use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use openshield_core::{Event, EventKind, MAX_RULES};
use openshield_protocol::{
    ErrorCode, FrameError, MAX_RULES_PER_PAGE, ProtocolError, ReadRequest, Request, Response,
    read_request, write_response,
};
use tracing::{debug, error, warn};

use crate::engine::{Engine, EventBus, SharedEngine, SubscribeError};
use crate::socket::{SocketSet, authorize_control_peer, authorize_observe_peer};

const MAX_CONTROL_CLIENTS: usize = 16;
// Observation uses a fixed worker pool: unprivileged connection churn can no
// longer create an unbounded number of kernel threads. Subscribers may occupy
// only part of the pool, reserving workers for status and paginated reads.
const OBSERVE_WORKER_COUNT: usize = 32;
const OBSERVE_QUEUE_CAPACITY: usize = 64;
const MAX_OBSERVE_IN_FLIGHT: usize = OBSERVE_WORKER_COUNT + OBSERVE_QUEUE_CAPACITY;
const MAX_OBSERVE_CONNECTIONS_PER_UID: usize = 4;
const MAX_OBSERVE_SUBSCRIBERS: usize = 24;
const MAX_OBSERVE_SUBSCRIBERS_PER_UID: usize = 2;
const OBSERVE_RATE_BURST: u32 = 256;
const OBSERVE_RATE_PER_SECOND: u32 = 64;
const OBSERVE_GLOBAL_RATE_BURST: u32 = 512;
const OBSERVE_GLOBAL_RATE_PER_SECOND: u32 = 64;
const MAX_OBSERVE_RULE_PAGE_BUILDS: usize = 4;
const MAX_OBSERVE_RULE_PAGE_BUILDS_PER_UID: usize = 1;
const MAX_TRACKED_OBSERVER_UIDS: usize = 1_024;
const OBSERVER_RATE_ENTRY_IDLE: Duration = Duration::from_secs(60);
const ACCEPT_BATCH: usize = 8;
const ACCEPT_IDLE: Duration = Duration::from_millis(20);
const CONTROL_ACCEPT_THROTTLE: Duration = Duration::from_millis(2);
const OBSERVE_ACCEPT_THROTTLE: Duration = Duration::from_millis(10);
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(2);
const OBSERVE_QUEUE_POLL: Duration = Duration::from_millis(25);
const SUBSCRIPTION_POLL: Duration = Duration::from_millis(200);
const CLIENT_DRAIN_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_OBSERVE_REQUESTS_PER_CONNECTION: usize = MAX_RULES + 2;

pub fn serve(
    sockets: &SocketSet,
    engine: &SharedEngine,
    events: &EventBus,
    shutdown: &Arc<AtomicBool>,
) -> Result<()> {
    let control_listener = sockets
        .control
        .try_clone()
        .context("cannot clone control listener")?;
    let observe_listener = sockets
        .observe
        .try_clone()
        .context("cannot clone observation listener")?;
    control_listener
        .set_nonblocking(true)
        .context("cannot make control listener nonblocking")?;
    observe_listener
        .set_nonblocking(true)
        .context("cannot make observation listener nonblocking")?;

    let control_clients = ClientLimiter::new(MAX_CONTROL_CLIENTS);
    let observe_admission = ObserverAdmission::production();
    let observer_gid = sockets.observer_gid();
    let (observe_sender, observe_workers) = spawn_observe_workers(engine, events, shutdown)?;

    let control_thread = {
        let engine = Arc::clone(engine);
        let control_shutdown = Arc::clone(shutdown);
        let clients = control_clients.clone();
        match thread::Builder::new()
            .name("openshield-control-accept".to_owned())
            .spawn(move || {
                control_accept_loop(&control_listener, &engine, &control_shutdown, &clients);
            }) {
            Ok(handle) => handle,
            Err(error) => {
                shutdown.store(true, Ordering::Release);
                drop(observe_sender);
                join_observe_workers(observe_workers)?;
                return Err(error).context("cannot spawn control accept loop");
            }
        }
    };
    let observe_thread = {
        let accept_shutdown = Arc::clone(shutdown);
        let admission = observe_admission.clone();
        match thread::Builder::new()
            .name("openshield-observe-accept".to_owned())
            .spawn(move || {
                observe_accept_loop(
                    &observe_listener,
                    &accept_shutdown,
                    &observe_sender,
                    &admission,
                    observer_gid,
                );
            }) {
            Ok(handle) => handle,
            Err(error) => {
                shutdown.store(true, Ordering::Release);
                let _ignored = control_thread.join();
                join_observe_workers(observe_workers)?;
                return Err(error).context("cannot spawn observation accept loop");
            }
        }
    };

    let control_result = control_thread
        .join()
        .map_err(|_| anyhow!("control accept loop terminated unexpectedly"));
    let observe_result = observe_thread
        .join()
        .map_err(|_| anyhow!("observation accept loop terminated unexpectedly"));
    let worker_result = join_observe_workers(observe_workers);

    let deadline = Instant::now() + CLIENT_DRAIN_TIMEOUT;
    while control_clients.active() != 0 || observe_admission.active() != 0 {
        if Instant::now() >= deadline {
            warn!(
                control_clients = control_clients.active(),
                observe_clients = observe_admission.active(),
                "client drain deadline reached during shutdown"
            );
            break;
        }
        thread::sleep(ACCEPT_IDLE);
    }
    control_result?;
    observe_result?;
    worker_result?;
    Ok(())
}

fn control_accept_loop(
    listener: &UnixListener,
    engine: &SharedEngine,
    shutdown: &Arc<AtomicBool>,
    clients: &ClientLimiter,
) {
    accept_loop(listener, shutdown, CONTROL_ACCEPT_THROTTLE, |stream| {
        let Some(permit) = clients.try_acquire() else {
            return;
        };
        let engine = Arc::clone(engine);
        let shutdown = Arc::clone(shutdown);
        let spawn = thread::Builder::new()
            .name("openshield-control-client".to_owned())
            .spawn(move || {
                let _permit = permit;
                if let Err(error) = handle_control_client(stream, &engine, &shutdown) {
                    debug!(error = %format_args!("{error:#}"), "control client disconnected");
                }
            });
        if let Err(error) = spawn {
            error!(%error, "cannot spawn bounded control client handler");
        }
    });
}

fn observe_accept_loop(
    listener: &UnixListener,
    shutdown: &Arc<AtomicBool>,
    sender: &SyncSender<ObserveJob>,
    admission: &ObserverAdmission,
    observer_gid: u32,
) {
    accept_loop(listener, shutdown, OBSERVE_ACCEPT_THROTTLE, |stream| {
        let uid = match authorize_observe_peer(&stream, observer_gid) {
            Ok(uid) => uid,
            Err(error) => {
                debug!(error = %format_args!("{error:#}"), "observation peer is not authorized");
                return;
            }
        };
        let Some(permit) = admission.try_acquire(uid) else {
            return;
        };
        let job = ObserveJob { stream, permit };
        match sender.try_send(job) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => {
                error!("observation worker queue disconnected");
                shutdown.store(true, Ordering::Release);
            }
        }
    });
}

fn accept_loop(
    listener: &UnixListener,
    shutdown: &AtomicBool,
    batch_throttle: Duration,
    mut accepted: impl FnMut(UnixStream),
) {
    while !shutdown.load(Ordering::Acquire) {
        let mut batch = 0;
        loop {
            match listener.accept() {
                Ok((stream, _address)) => {
                    accepted(stream);
                    batch += 1;
                    if batch >= ACCEPT_BATCH {
                        thread::sleep(batch_throttle);
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    warn!(%error, "Unix listener accept failed");
                    thread::sleep(ACCEPT_IDLE);
                    break;
                }
            }
        }
        if batch == 0 {
            thread::sleep(ACCEPT_IDLE);
        }
    }
}

#[derive(Debug)]
struct ObserveJob {
    stream: UnixStream,
    permit: ObserverPermit,
}

fn spawn_observe_workers(
    engine: &SharedEngine,
    events: &EventBus,
    shutdown: &Arc<AtomicBool>,
) -> Result<(SyncSender<ObserveJob>, Vec<JoinHandle<()>>)> {
    let (sender, receiver) = mpsc::sync_channel(OBSERVE_QUEUE_CAPACITY);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut workers = Vec::with_capacity(OBSERVE_WORKER_COUNT);

    for index in 0..OBSERVE_WORKER_COUNT {
        let worker_engine = Arc::clone(engine);
        let worker_events = events.clone();
        let worker_shutdown = Arc::clone(shutdown);
        let worker_receiver = Arc::clone(&receiver);
        let spawn = thread::Builder::new()
            .name(format!("openshield-observe-{index}"))
            .spawn(move || {
                observe_worker_loop(
                    &worker_receiver,
                    &worker_engine,
                    &worker_events,
                    &worker_shutdown,
                );
            });
        match spawn {
            Ok(handle) => workers.push(handle),
            Err(error) => {
                shutdown.store(true, Ordering::Release);
                drop(sender);
                let _ignored = join_observe_workers(workers);
                return Err(error).context("cannot spawn fixed observation worker pool");
            }
        }
    }

    Ok((sender, workers))
}

fn observe_worker_loop(
    receiver: &Mutex<Receiver<ObserveJob>>,
    engine: &SharedEngine,
    events: &EventBus,
    shutdown: &AtomicBool,
) {
    while !shutdown.load(Ordering::Acquire) {
        let job_result = if let Ok(queue) = receiver.lock() {
            // Other workers may have passed the loop condition before waiting
            // for this receiver mutex. Recheck after acquiring it so shutdown
            // does not serialize one queue timeout per worker.
            if shutdown.load(Ordering::Acquire) {
                return;
            }
            queue.recv_timeout(OBSERVE_QUEUE_POLL)
        } else {
            error!("observation worker queue mutex is poisoned");
            return;
        };
        match job_result {
            Ok(job) => {
                let ObserveJob { stream, permit } = job;
                if let Err(error) = handle_observe_client(stream, engine, events, shutdown, &permit)
                {
                    debug!(error = %format_args!("{error:#}"), "observation client disconnected");
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn join_observe_workers(workers: Vec<JoinHandle<()>>) -> Result<()> {
    let mut worker_panicked = false;
    for worker in workers {
        if worker.join().is_err() {
            worker_panicked = true;
        }
    }
    if worker_panicked {
        Err(anyhow!("observation worker terminated unexpectedly"))
    } else {
        Ok(())
    }
}

fn handle_control_client(
    mut stream: UnixStream,
    engine: &SharedEngine,
    shutdown: &AtomicBool,
) -> Result<()> {
    configure_client(&stream)?;
    if authorize_control_peer(&stream).is_err() {
        write_error(
            &mut stream,
            ErrorCode::Unauthorized,
            "control operations require uid 0",
        )?;
        return Ok(());
    }

    let request = match read_request_with_deadline(&mut stream) {
        Ok(Request::Control(request)) => request,
        Ok(Request::Read(_)) => {
            write_error(
                &mut stream,
                ErrorCode::InvalidRequest,
                "read requests must use the observation socket",
            )?;
            return Ok(());
        }
        Err(error) => {
            write_error(
                &mut stream,
                ErrorCode::InvalidRequest,
                "malformed or oversized control request",
            )?;
            return Err(error).context("invalid control frame");
        }
    };

    let (response, fatal) = match lock_engine(engine) {
        Ok(mut engine) => {
            let response = match engine.handle_control(request) {
                Ok(ack) => Response::Ack(ack),
                Err(error) => Response::Error(error),
            };
            (response, engine.restart_required())
        }
        Err(error) => (Response::Error(error), true),
    };
    if fatal {
        shutdown.store(true, Ordering::Release);
    }
    write_response_with_deadline(&mut stream, &response)
        .context("cannot write control response")?;
    Ok(())
}

fn handle_observe_client(
    mut stream: UnixStream,
    engine: &SharedEngine,
    events: &EventBus,
    shutdown: &AtomicBool,
    permit: &ObserverPermit,
) -> Result<()> {
    configure_client(&stream)?;
    let mut status_requests = 0_u8;
    let mut pages_started = false;
    let mut expected_after = None;
    let mut pages_finished = false;
    for _request_count in 0..MAX_OBSERVE_REQUESTS_PER_CONNECTION {
        let Some(request) = read_observer_request(&mut stream, permit)? else {
            return Ok(());
        };

        match request {
            request @ (ReadRequest::Status | ReadRequest::StatusV2 | ReadRequest::StatusV3) => {
                if pages_started || status_requests >= 2 {
                    write_error(
                        &mut stream,
                        ErrorCode::InvalidRequest,
                        "observation session permits at most two status reads before pagination",
                    )?;
                    return Ok(());
                }
                status_requests += 1;
                let response = lock_engine(engine).map_or_else(Response::Error, |engine| {
                    if matches!(request, ReadRequest::StatusV3) {
                        engine.status_v3_response()
                    } else if matches!(request, ReadRequest::StatusV2) {
                        engine.status_v2_response()
                    } else {
                        engine.status_response()
                    }
                });
                write_response_with_deadline(&mut stream, &response)
                    .context("cannot write status")?;
            }
            ReadRequest::RulesPage {
                after,
                limit: _requested_limit,
            } => {
                let cursor_is_valid = if pages_started {
                    !pages_finished && after == expected_after
                } else {
                    status_requests != 0 && after.is_none()
                };
                if !cursor_is_valid {
                    write_error(
                        &mut stream,
                        ErrorCode::InvalidRequest,
                        "rule pages require status followed by one strictly advancing cursor",
                    )?;
                    return Ok(());
                }
                let RulePageOutcome::Sent { next_after } =
                    write_rule_page(&mut stream, engine, permit, after, permit.uid != 0)?
                else {
                    return Ok(());
                };
                pages_started = true;
                expected_after = next_after;
                pages_finished = next_after.is_none();
            }
            ReadRequest::Subscribe { after_revision } => {
                if status_requests != 0 || pages_started {
                    write_error(
                        &mut stream,
                        ErrorCode::InvalidRequest,
                        "event subscription must be the first request on its connection",
                    )?;
                    return Ok(());
                }
                let Some(_subscription_permit) = permit.try_acquire_subscription() else {
                    write_error(
                        &mut stream,
                        ErrorCode::Conflict,
                        "observation subscription quota reached; retry later",
                    )?;
                    return Ok(());
                };
                stream_events(
                    &mut stream,
                    engine,
                    events,
                    shutdown,
                    after_revision,
                    permit.uid != 0,
                )?;
                return Ok(());
            }
        }
    }
    write_error(
        &mut stream,
        ErrorCode::Conflict,
        "observation connection request limit reached",
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RulePageOutcome {
    Sent { next_after: Option<uuid::Uuid> },
    SessionFinished,
}

fn write_rule_page(
    stream: &mut UnixStream,
    engine: &SharedEngine,
    observer: &ObserverPermit,
    after: Option<uuid::Uuid>,
    redact_sensitive: bool,
) -> Result<RulePageOutcome> {
    let Some(page_build_permit) = observer.try_acquire_rule_page_build() else {
        write_error(
            stream,
            ErrorCode::Conflict,
            "observation rule-page service is busy; retry later",
        )?;
        return Ok(RulePageOutcome::SessionFinished);
    };
    let response = {
        let response = lock_engine(engine).map_or_else(Response::Error, |engine| {
            // Ignore tiny client hints so a caller cannot amplify lock and
            // serialization work into one request per rule.
            engine.rules_page_response(after, MAX_RULES_PER_PAGE)
        });
        let response = redact_rule_page(response, redact_sensitive);
        fit_rule_page(response)
    };
    // Slow readers must not occupy a page-build slot. RAII also releases the
    // permit on every error or early-return path during response construction.
    drop(page_build_permit);

    let next_after = match &response {
        Response::RulesPage { next_after, .. } => *next_after,
        Response::Error(_) => {
            write_response_with_deadline(stream, &response)
                .context("cannot write rule-page error")?;
            return Ok(RulePageOutcome::SessionFinished);
        }
        _ => return Err(anyhow!("rule-page fitting changed the response variant")),
    };
    write_response_with_deadline(stream, &response).context("cannot write rule page")?;
    Ok(RulePageOutcome::Sent { next_after })
}

fn read_observer_request(
    stream: &mut UnixStream,
    permit: &ObserverPermit,
) -> Result<Option<ReadRequest>> {
    let request = match read_request_with_deadline(stream) {
        Ok(Request::Read(request)) => request,
        Ok(Request::Control(_)) => {
            write_error(
                stream,
                ErrorCode::Unauthorized,
                "mutations are forbidden on the observation socket",
            )?;
            return Ok(None);
        }
        Err(error) if is_clean_observer_disconnect(&error) => return Ok(None),
        Err(error) => {
            write_error(
                stream,
                ErrorCode::InvalidRequest,
                "malformed or oversized observation request",
            )?;
            return Err(error).context("invalid observation frame");
        }
    };
    if !permit.try_consume_request() {
        write_error(
            stream,
            ErrorCode::Conflict,
            "observation request rate exceeded",
        )?;
        return Ok(None);
    }
    Ok(Some(request))
}

fn is_clean_observer_disconnect(error: &FrameError) -> bool {
    matches!(
        error,
        FrameError::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
            )
    )
}

fn stream_events(
    stream: &mut UnixStream,
    engine: &SharedEngine,
    events: &EventBus,
    shutdown: &AtomicBool,
    after_revision: Option<u64>,
    redact_sensitive: bool,
) -> Result<()> {
    // Register first, then read the revision.  Events racing with this setup
    // are either represented by the revision check or already in this queue.
    let subscription = match events.subscribe() {
        Ok(subscription) => subscription,
        Err(SubscribeError::LimitReached) => {
            write_error(
                stream,
                ErrorCode::Conflict,
                "observation subscriber limit reached",
            )?;
            return Ok(());
        }
        Err(SubscribeError::Unavailable) => {
            write_error(
                stream,
                ErrorCode::Internal,
                "observation event service is unavailable",
            )?;
            return Ok(());
        }
    };
    let baseline = match lock_engine(engine) {
        Ok(engine) => match engine.subscription_revision() {
            Ok(revision) => revision,
            Err(error) => {
                write_response_with_deadline(stream, &Response::Error(error))?;
                return Ok(());
            }
        },
        Err(error) => {
            write_response_with_deadline(stream, &Response::Error(error))?;
            return Ok(());
        }
    };
    if after_revision.is_some_and(|revision| revision != baseline) {
        write_error(
            stream,
            ErrorCode::Conflict,
            "event revision is no longer current; reload status and rule pages",
        )?;
        return Ok(());
    }

    while !shutdown.load(Ordering::Acquire) {
        match subscription.recv_timeout(SUBSCRIPTION_POLL) {
            Ok(event) if event_reflected_by_revision(&event, baseline) => {}
            Ok(event) => {
                let event = if redact_sensitive {
                    event.redacted_for_observer()
                } else {
                    event
                };
                write_response_with_deadline(stream, &Response::Event(event))
                    .context("cannot stream firewall event")?;
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
    let _ignored = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn redact_rule_page(response: Response, redact_sensitive: bool) -> Response {
    if !redact_sensitive {
        return response;
    }
    match response {
        Response::RulesPage {
            revision,
            rules,
            next_after,
        } => Response::RulesPage {
            revision,
            rules: rules
                .into_iter()
                .map(|rule| rule.redacted_for_observer())
                .collect(),
            next_after,
        },
        other => other,
    }
}

fn fit_rule_page(response: Response) -> Response {
    fit_rule_page_with(response, |candidate| {
        write_response(&mut io::sink(), candidate).is_ok()
    })
}

fn fit_rule_page_with(
    response: Response,
    mut fits_bounded_frame: impl FnMut(&Response) -> bool,
) -> Response {
    let Response::RulesPage {
        revision,
        rules,
        next_after,
    } = response
    else {
        return response;
    };
    let original_count = rules.len();
    let upstream_has_more = next_after.is_some();
    if original_count == 0 {
        let candidate = Response::RulesPage {
            revision,
            rules,
            next_after: None,
        };
        return if fits_bounded_frame(&candidate) {
            candidate
        } else {
            Response::Error(ProtocolError::new(
                ErrorCode::Internal,
                "an empty rule page does not fit the bounded observation frame",
            ))
        };
    }

    // Frame size is monotonic with the prefix length. Binary search caps
    // serialization work at O(log(page size)) attempts instead of repeatedly
    // cloning and serializing n, n-1, ... prefixes for an untrusted observer.
    let mut lower = 1_usize;
    let mut upper = original_count;
    let mut best = None;
    while lower <= upper {
        let count = lower + (upper - lower) / 2;
        let truncated = count < original_count;
        let candidate_next = if upstream_has_more || truncated {
            rules.get(count - 1).map(|rule| rule.id)
        } else {
            None
        };
        let candidate = Response::RulesPage {
            revision,
            rules: rules[..count].to_vec(),
            next_after: candidate_next,
        };
        if fits_bounded_frame(&candidate) {
            best = Some(candidate);
            lower = count + 1;
        } else {
            upper = count - 1;
        }
    }
    best.unwrap_or_else(|| {
        Response::Error(ProtocolError::new(
            ErrorCode::Internal,
            "one validated rule does not fit the bounded observation frame",
        ))
    })
}

fn event_reflected_by_revision(event: &Event, baseline: u64) -> bool {
    match &event.kind {
        EventKind::CountersUpdated { .. } => event.revision < baseline,
        kind => {
            event.revision <= baseline
                && matches!(
                    kind,
                    EventKind::ModeChanged { .. }
                        | EventKind::RuleCreated { .. }
                        | EventKind::RuleUpdated { .. }
                        | EventKind::RuleDeleted { .. }
                        | EventKind::RuleEnabledChanged { .. }
                )
        }
    }
}

fn configure_client(stream: &UnixStream) -> Result<()> {
    stream
        .set_read_timeout(Some(CLIENT_IO_TIMEOUT))
        .context("cannot set client read timeout")?;
    stream
        .set_write_timeout(Some(CLIENT_IO_TIMEOUT))
        .context("cannot set client write timeout")?;
    Ok(())
}

fn read_request_with_deadline(stream: &mut UnixStream) -> std::result::Result<Request, FrameError> {
    read_request_before(stream, Instant::now() + CLIENT_IO_TIMEOUT)
}

fn read_request_before(
    stream: &mut UnixStream,
    deadline: Instant,
) -> std::result::Result<Request, FrameError> {
    let mut reader = DeadlineReader { stream, deadline };
    read_request(&mut reader)
}

/// Recomputes the socket timeout before every read against one monotonic
/// deadline.  `SO_RCVTIMEO` alone is only an idle timeout and can otherwise be
/// kept alive forever by sending a frame one byte at a time.
struct DeadlineReader<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl Read for DeadlineReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let Some(remaining) = self.deadline.checked_duration_since(Instant::now()) else {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute IPC request deadline exceeded",
            ));
        };
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "absolute IPC request deadline exceeded",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}

fn lock_engine(engine: &SharedEngine) -> Result<MutexGuard<'_, Engine>, ProtocolError> {
    engine.lock().map_err(|_| {
        ProtocolError::new(
            ErrorCode::Internal,
            "policy engine is temporarily unavailable",
        )
    })
}

fn write_error(stream: &mut UnixStream, code: ErrorCode, message: &str) -> Result<()> {
    write_response_with_deadline(stream, &Response::Error(ProtocolError::new(code, message)))
        .context("cannot write protocol error")
}

fn write_response_with_deadline(
    stream: &mut UnixStream,
    response: &Response,
) -> std::result::Result<(), FrameError> {
    let mut writer = DeadlineWriter {
        stream,
        deadline: Instant::now() + CLIENT_IO_TIMEOUT,
    };
    write_response(&mut writer, response)
}

/// Recomputes the socket timeout before every write against one monotonic
/// deadline. A peer that reads a frame one byte at a time therefore cannot
/// retain a bounded client slot indefinitely.
struct DeadlineWriter<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}

impl DeadlineWriter<'_> {
    fn remaining(&self) -> io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "absolute IPC response deadline exceeded",
                )
            })
    }
}

impl Write for DeadlineWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        let remaining = self.remaining()?;
        self.stream.set_write_timeout(Some(remaining))?;
        self.stream.flush()
    }
}

#[derive(Clone, Copy, Debug)]
struct ObserverLimits {
    maximum_connections: usize,
    maximum_connections_per_uid: usize,
    maximum_subscriptions: usize,
    maximum_subscriptions_per_uid: usize,
    rate_burst: u32,
    rate_per_second: u32,
    global_rate_burst: u32,
    global_rate_per_second: u32,
    maximum_rule_page_builds: usize,
    maximum_rule_page_builds_per_uid: usize,
    maximum_tracked_uids: usize,
    rate_entry_idle: Duration,
}

impl ObserverLimits {
    const PRODUCTION: Self = Self {
        maximum_connections: MAX_OBSERVE_IN_FLIGHT,
        maximum_connections_per_uid: MAX_OBSERVE_CONNECTIONS_PER_UID,
        maximum_subscriptions: MAX_OBSERVE_SUBSCRIBERS,
        maximum_subscriptions_per_uid: MAX_OBSERVE_SUBSCRIBERS_PER_UID,
        rate_burst: OBSERVE_RATE_BURST,
        rate_per_second: OBSERVE_RATE_PER_SECOND,
        global_rate_burst: OBSERVE_GLOBAL_RATE_BURST,
        global_rate_per_second: OBSERVE_GLOBAL_RATE_PER_SECOND,
        maximum_rule_page_builds: MAX_OBSERVE_RULE_PAGE_BUILDS,
        maximum_rule_page_builds_per_uid: MAX_OBSERVE_RULE_PAGE_BUILDS_PER_UID,
        maximum_tracked_uids: MAX_TRACKED_OBSERVER_UIDS,
        rate_entry_idle: OBSERVER_RATE_ENTRY_IDLE,
    };
}

#[derive(Debug)]
struct ObserverTokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl ObserverTokenBucket {
    fn new(now: Instant, burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            last_refill: now,
        }
    }

    fn try_consume(&mut self, now: Instant, burst: u32, rate_per_second: u32) -> bool {
        let elapsed = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed * f64::from(rate_per_second)).min(f64::from(burst));
        self.last_refill = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

#[derive(Debug)]
struct ObserverUidState {
    active_connections: usize,
    active_subscriptions: usize,
    active_rule_page_builds: usize,
    rate: ObserverTokenBucket,
    last_seen: Instant,
}

impl ObserverUidState {
    fn new(now: Instant, burst: u32) -> Self {
        Self {
            active_connections: 0,
            active_subscriptions: 0,
            active_rule_page_builds: 0,
            rate: ObserverTokenBucket::new(now, burst),
            last_seen: now,
        }
    }

    fn try_consume_token(&mut self, now: Instant, burst: u32, rate_per_second: u32) -> bool {
        self.last_seen = now;
        self.rate.try_consume(now, burst, rate_per_second)
    }
}

#[derive(Debug, Default)]
struct ObserverAdmissionState {
    active_connections: usize,
    active_subscriptions: usize,
    active_rule_page_builds: usize,
    global_rate: Option<ObserverTokenBucket>,
    users: BTreeMap<u32, ObserverUidState>,
}

/// Admission control for the group-restricted observation socket.
///
/// Credentials come from `SO_PEERCRED`; callers cannot choose the UID carried
/// by an accepted Unix socket. Per-UID limits prevent one account from taking
/// every slot, while aggregate page and rate limits bound the whole group.
#[derive(Clone, Debug)]
struct ObserverAdmission {
    inner: Arc<Mutex<ObserverAdmissionState>>,
    limits: ObserverLimits,
}

impl ObserverAdmission {
    fn production() -> Self {
        Self::with_limits(ObserverLimits::PRODUCTION)
    }

    fn with_limits(limits: ObserverLimits) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ObserverAdmissionState::default())),
            limits,
        }
    }

    fn try_acquire(&self, uid: u32) -> Option<ObserverPermit> {
        self.try_acquire_at(uid, Instant::now())
    }

    fn try_acquire_at(&self, uid: u32, now: Instant) -> Option<ObserverPermit> {
        let mut state = self.inner.lock().ok()?;
        if state.active_connections >= self.limits.maximum_connections {
            return None;
        }

        if !state.users.contains_key(&uid) && state.users.len() >= self.limits.maximum_tracked_uids
        {
            let idle = self.limits.rate_entry_idle;
            state.users.retain(|_tracked_uid, user| {
                user.active_connections != 0
                    || user.active_subscriptions != 0
                    || user.active_rule_page_builds != 0
                    || now.saturating_duration_since(user.last_seen) < idle
            });
            if state.users.len() >= self.limits.maximum_tracked_uids {
                return None;
            }
        }

        {
            let user = state
                .users
                .entry(uid)
                .or_insert_with(|| ObserverUidState::new(now, self.limits.rate_burst));
            if !user.try_consume_token(now, self.limits.rate_burst, self.limits.rate_per_second) {
                return None;
            }
            // Consume a per-UID token even if this UID already holds its
            // concurrency quota. Overflow attempts cannot preserve a fresh
            // private burst, but they also cannot drain the shared bucket.
            if user.active_connections >= self.limits.maximum_connections_per_uid {
                return None;
            }
        }
        if !Self::try_consume_global_token(&mut state, now, self.limits) {
            return None;
        }
        let user = state.users.get_mut(&uid)?;
        user.active_connections += 1;
        state.active_connections += 1;
        Some(ObserverPermit {
            admission: self.clone(),
            uid,
        })
    }

    fn try_acquire_subscription(&self, uid: u32) -> Option<ObserverSubscriptionPermit> {
        let mut state = self.inner.lock().ok()?;
        if state.active_subscriptions >= self.limits.maximum_subscriptions {
            return None;
        }
        let user = state.users.get_mut(&uid)?;
        if user.active_connections == 0
            || user.active_subscriptions >= self.limits.maximum_subscriptions_per_uid
        {
            return None;
        }
        user.active_subscriptions += 1;
        state.active_subscriptions += 1;
        Some(ObserverSubscriptionPermit {
            admission: self.clone(),
            uid,
        })
    }

    fn try_consume_request_at(&self, uid: u32, now: Instant) -> bool {
        let Ok(mut state) = self.inner.lock() else {
            return false;
        };
        {
            let Some(user) = state.users.get_mut(&uid) else {
                return false;
            };
            if user.active_connections == 0
                || !user.try_consume_token(now, self.limits.rate_burst, self.limits.rate_per_second)
            {
                return false;
            }
        }
        Self::try_consume_global_token(&mut state, now, self.limits)
    }

    fn try_consume_global_token(
        state: &mut ObserverAdmissionState,
        now: Instant,
        limits: ObserverLimits,
    ) -> bool {
        state
            .global_rate
            .get_or_insert_with(|| ObserverTokenBucket::new(now, limits.global_rate_burst))
            .try_consume(now, limits.global_rate_burst, limits.global_rate_per_second)
    }

    fn try_acquire_rule_page_build(&self, uid: u32) -> Option<ObserverRulePagePermit> {
        let mut state = self.inner.lock().ok()?;
        if state.active_rule_page_builds >= self.limits.maximum_rule_page_builds {
            return None;
        }
        let user = state.users.get_mut(&uid)?;
        if user.active_connections == 0
            || user.active_rule_page_builds >= self.limits.maximum_rule_page_builds_per_uid
        {
            return None;
        }
        user.active_rule_page_builds += 1;
        state.active_rule_page_builds += 1;
        Some(ObserverRulePagePermit {
            admission: self.clone(),
            uid,
        })
    }

    fn release_connection(&self, uid: u32) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let Some(user) = state.users.get_mut(&uid) else {
            return;
        };
        user.active_connections = user.active_connections.saturating_sub(1);
        state.active_connections = state.active_connections.saturating_sub(1);
    }

    fn release_subscription(&self, uid: u32) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let Some(user) = state.users.get_mut(&uid) else {
            return;
        };
        user.active_subscriptions = user.active_subscriptions.saturating_sub(1);
        state.active_subscriptions = state.active_subscriptions.saturating_sub(1);
    }

    fn release_rule_page_build(&self, uid: u32) {
        let Ok(mut state) = self.inner.lock() else {
            return;
        };
        let Some(user) = state.users.get_mut(&uid) else {
            return;
        };
        user.active_rule_page_builds = user.active_rule_page_builds.saturating_sub(1);
        state.active_rule_page_builds = state.active_rule_page_builds.saturating_sub(1);
    }

    fn active(&self) -> usize {
        self.inner
            .lock()
            .map_or(self.limits.maximum_connections, |state| {
                state.active_connections
            })
    }

    #[cfg(test)]
    fn active_rule_page_builds(&self) -> usize {
        self.inner
            .lock()
            .map_or(self.limits.maximum_rule_page_builds, |state| {
                state.active_rule_page_builds
            })
    }
}

#[derive(Debug)]
struct ObserverPermit {
    admission: ObserverAdmission,
    uid: u32,
}

impl ObserverPermit {
    fn try_consume_request(&self) -> bool {
        self.admission
            .try_consume_request_at(self.uid, Instant::now())
    }

    #[cfg(test)]
    fn try_consume_request_at(&self, now: Instant) -> bool {
        self.admission.try_consume_request_at(self.uid, now)
    }

    fn try_acquire_subscription(&self) -> Option<ObserverSubscriptionPermit> {
        self.admission.try_acquire_subscription(self.uid)
    }

    fn try_acquire_rule_page_build(&self) -> Option<ObserverRulePagePermit> {
        self.admission.try_acquire_rule_page_build(self.uid)
    }
}

impl Drop for ObserverPermit {
    fn drop(&mut self) {
        self.admission.release_connection(self.uid);
    }
}

#[derive(Debug)]
struct ObserverSubscriptionPermit {
    admission: ObserverAdmission,
    uid: u32,
}

impl Drop for ObserverSubscriptionPermit {
    fn drop(&mut self) {
        self.admission.release_subscription(self.uid);
    }
}

#[derive(Debug)]
struct ObserverRulePagePermit {
    admission: ObserverAdmission,
    uid: u32,
}

impl Drop for ObserverRulePagePermit {
    fn drop(&mut self) {
        self.admission.release_rule_page_build(self.uid);
    }
}

#[derive(Clone, Debug)]
struct ClientLimiter {
    active: Arc<AtomicUsize>,
    maximum: usize,
}

impl ClientLimiter {
    fn new(maximum: usize) -> Self {
        Self {
            active: Arc::new(AtomicUsize::new(0)),
            maximum,
        }
    }

    fn try_acquire(&self) -> Option<ClientPermit> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.maximum {
                return None;
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ClientPermit {
                        active: Arc::clone(&self.active),
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    fn active(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
struct ClientPermit {
    active: Arc<AtomicUsize>,
}

impl Drop for ClientPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use chrono::Utc;
    use nix::unistd::geteuid;
    use openshield_core::{
        ApplicationPath, ApplicationSelector, AtomicStateStore, CgroupPath, CommandArgument,
        CommandLineMatch, CommandLineSelector, Direction, ExecutableFileId, FirewallCounters,
        MAX_APPLICATION_PATH_BYTES, Rule, RuleName, RuleOrigin, RuleSpec, State, TransportProtocol,
    };
    use openshield_protocol::{read_response, write_request};
    use tempfile::tempdir;

    use super::*;
    use crate::backend::MemoryBackend;

    fn test_observer_limits() -> ObserverLimits {
        ObserverLimits {
            maximum_connections: 8,
            maximum_connections_per_uid: 2,
            maximum_subscriptions: 3,
            maximum_subscriptions_per_uid: 1,
            rate_burst: 8,
            rate_per_second: 2,
            global_rate_burst: 64,
            global_rate_per_second: 16,
            maximum_rule_page_builds: 4,
            maximum_rule_page_builds_per_uid: 1,
            maximum_tracked_uids: 8,
            rate_entry_idle: Duration::from_secs(10),
        }
    }

    #[test]
    fn non_root_observer_pages_remove_all_learned_application_metadata() -> Result<()> {
        let mut specification = RuleSpec::new(
            RuleName::new("secret curl rule")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            None,
            None,
            RuleOrigin::Learned,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/secret/bin/curl")?),
            Some(ExecutableFileId {
                device: 123_456,
                inode: 654_321,
                size: 777_333,
                ctime_seconds: 1_654_321_987,
                ctime_nanoseconds: 987_654_321,
            }),
            Some(CommandLineSelector::new(
                CommandLineMatch::Exact,
                vec![CommandArgument::new("secret-argument")?],
            )?),
            Some(42_424),
            Some(CgroupPath::new("/secret.slice")?),
        )?);
        let response = Response::RulesPage {
            revision: 1,
            rules: vec![Rule::new(specification)?],
            next_after: None,
        };

        let redacted = redact_rule_page(response, true);
        let encoded = serde_json::to_string(&redacted)?;
        for secret in [
            "secret curl rule",
            "/secret/bin/curl",
            "secret-argument",
            "/secret.slice",
            "42424",
            "123456",
            "654321",
            "777333",
            "1654321987",
            "987654321",
        ] {
            assert!(!encoded.contains(secret));
        }
        assert!(encoded.contains("metadata_redacted"));
        Ok(())
    }

    #[test]
    fn oversized_rule_page_is_shrunk_with_a_resumable_cursor() -> Result<()> {
        let executable = format!("/{}", "x".repeat(MAX_APPLICATION_PATH_BYTES - 1));
        let mut specification = RuleSpec::new(
            RuleName::new("large application rule")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            None,
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(executable)?),
            Some(ExecutableFileId {
                device: 1,
                inode: 2,
                size: 3,
                ctime_seconds: 4,
                ctime_nanoseconds: 5,
            }),
            None,
            Some(1_000),
            None,
        )?);
        let base = Rule::new(specification)?;
        let rules = (0..usize::from(MAX_RULES_PER_PAGE))
            .map(|_| {
                let mut rule = base.clone();
                rule.id = uuid::Uuid::new_v4();
                rule
            })
            .collect::<Vec<_>>();
        let original_count = rules.len();
        let fitted = fit_rule_page(Response::RulesPage {
            revision: 9,
            rules,
            next_after: Some(uuid::Uuid::new_v4()),
        });
        let Response::RulesPage {
            rules, next_after, ..
        } = &fitted
        else {
            return Err(anyhow!("valid rule page could not be fitted"));
        };
        assert!(!rules.is_empty());
        assert!(rules.len() < original_count);
        assert_eq!(*next_after, rules.last().map(|rule| rule.id));
        write_response(&mut io::sink(), &fitted)?;
        Ok(())
    }

    #[test]
    fn rule_page_fitting_uses_logarithmically_bounded_attempts() -> Result<()> {
        let rule = Rule::new(RuleSpec::new(
            RuleName::new("bounded fitting")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            None,
            None,
            None,
            RuleOrigin::Manual,
            true,
        )?)?;
        let mut attempts = 0_usize;
        let fitted = fit_rule_page_with(
            Response::RulesPage {
                revision: 1,
                rules: vec![rule; usize::from(MAX_RULES_PER_PAGE)],
                next_after: Some(uuid::Uuid::new_v4()),
            },
            |candidate| {
                attempts += 1;
                matches!(candidate, Response::RulesPage { rules, .. } if rules.len() <= 7)
            },
        );
        assert!(matches!(
            fitted,
            Response::RulesPage { rules, .. } if rules.len() == 7
        ));
        assert!(attempts <= 8, "binary search used {attempts} attempts");
        Ok(())
    }

    #[test]
    fn observation_session_reuses_one_connection_and_rejects_request_floods() -> Result<()> {
        for status_request in [
            ReadRequest::Status,
            ReadRequest::StatusV2,
            ReadRequest::StatusV3,
        ] {
            let temporary = tempdir()?;
            let store = AtomicStateStore::for_owner(
                temporary.path().join("persistent-observer.json"),
                geteuid().as_raw(),
            );
            let events = EventBus::new();
            let engine = Arc::new(Mutex::new(Engine::load(
                Box::new(MemoryBackend::default()),
                Box::new(store),
                events.clone(),
            )?));
            let shutdown = Arc::new(AtomicBool::new(false));
            let admission = ObserverAdmission::production();
            let permit = admission
                .try_acquire_at(1_000, Instant::now())
                .ok_or_else(|| anyhow!("observer admission unexpectedly denied"))?;
            let (server_stream, mut client_stream) = UnixStream::pair()?;
            let server_engine = Arc::clone(&engine);
            let server_events = events.clone();
            let server_shutdown = Arc::clone(&shutdown);
            let server = thread::spawn(move || {
                handle_observe_client(
                    server_stream,
                    &server_engine,
                    &server_events,
                    &server_shutdown,
                    &permit,
                )
            });

            write_request(&mut client_stream, &Request::Read(ReadRequest::Status))?;
            assert!(matches!(
                read_response(&mut client_stream)?,
                Response::Status { rule_count: 0, .. }
            ));
            write_request(&mut client_stream, &Request::Read(status_request.clone()))?;
            let response = read_response(&mut client_stream)?;
            match (&status_request, &response) {
                (ReadRequest::Status, Response::Status { .. })
                | (ReadRequest::StatusV2, Response::StatusV2 { .. }) => {}
                (ReadRequest::StatusV3, Response::StatusV3 { learning, .. }) => {
                    assert_eq!(learning.automatic_rules, 0);
                    assert_eq!(learning.quota_skipped_observations, 0);
                    assert!(learning.per_uid_limit > 512);
                }
                _ => return Err(anyhow!("status response version mismatch")),
            }
            assert!(matches!(
                response,
                Response::Status { rule_count: 0, .. }
                    | Response::StatusV2 { rule_count: 0, .. }
                    | Response::StatusV3 { rule_count: 0, .. }
            ));
            write_request(
                &mut client_stream,
                &Request::Read(ReadRequest::RulesPage {
                    after: None,
                    limit: MAX_RULES_PER_PAGE,
                }),
            )?;
            assert!(matches!(
                read_response(&mut client_stream)?,
                Response::RulesPage {
                    rules,
                    next_after: None,
                    ..
                } if rules.is_empty()
            ));

            // A status flood after pagination violates the bounded session FSM.
            write_request(&mut client_stream, &Request::Read(ReadRequest::StatusV3))?;
            assert!(matches!(
                read_response(&mut client_stream)?,
                Response::Error(ProtocolError {
                    code: ErrorCode::InvalidRequest,
                    ..
                })
            ));
            let _ignored = client_stream.shutdown(Shutdown::Both);
            server
                .join()
                .map_err(|_| anyhow!("observation session thread panicked"))??;
            assert_eq!(admission.active(), 0);
        }
        Ok(())
    }

    #[test]
    fn exhausted_rule_page_build_quota_returns_busy_conflict() -> Result<()> {
        let temporary = tempdir()?;
        let store = AtomicStateStore::for_owner(
            temporary.path().join("busy-observer.json"),
            geteuid().as_raw(),
        );
        let events = EventBus::new();
        let engine = Arc::new(Mutex::new(Engine::load(
            Box::new(MemoryBackend::default()),
            Box::new(store),
            events.clone(),
        )?));
        let shutdown = Arc::new(AtomicBool::new(false));
        let limits = ObserverLimits {
            maximum_rule_page_builds: 1,
            ..test_observer_limits()
        };
        let admission = ObserverAdmission::with_limits(limits);
        let now = Instant::now();
        let holder = admission
            .try_acquire_at(1_000, now)
            .ok_or_else(|| anyhow!("page-slot holder was unexpectedly denied"))?;
        let held_page = holder
            .try_acquire_rule_page_build()
            .ok_or_else(|| anyhow!("page slot could not be reserved"))?;
        let client_permit = admission
            .try_acquire_at(1_001, now)
            .ok_or_else(|| anyhow!("test client was unexpectedly denied"))?;
        let (server_stream, mut client_stream) = UnixStream::pair()?;
        let server_engine = Arc::clone(&engine);
        let server_events = events.clone();
        let server_shutdown = Arc::clone(&shutdown);
        let server = thread::spawn(move || {
            handle_observe_client(
                server_stream,
                &server_engine,
                &server_events,
                &server_shutdown,
                &client_permit,
            )
        });

        write_request(&mut client_stream, &Request::Read(ReadRequest::Status))?;
        assert!(matches!(
            read_response(&mut client_stream)?,
            Response::Status { .. }
        ));
        write_request(
            &mut client_stream,
            &Request::Read(ReadRequest::RulesPage {
                after: None,
                limit: MAX_RULES_PER_PAGE,
            }),
        )?;
        assert!(matches!(
            read_response(&mut client_stream)?,
            Response::Error(ProtocolError {
                code: ErrorCode::Conflict,
                message,
            }) if message.contains("busy")
        ));
        server
            .join()
            .map_err(|_| anyhow!("busy observation session thread panicked"))??;
        assert_eq!(admission.active_rule_page_builds(), 1);
        drop((held_page, holder));
        assert_eq!(admission.active_rule_page_builds(), 0);
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn client_limit_is_atomic_and_releases_on_drop() {
        let limiter = ClientLimiter::new(1);
        let permit = limiter.try_acquire();
        assert!(permit.is_some());
        assert!(limiter.try_acquire().is_none());
        drop(permit);
        assert!(limiter.try_acquire().is_some());
    }

    #[test]
    fn one_uid_cannot_monopolize_observation_connections() -> Result<()> {
        let admission = ObserverAdmission::with_limits(test_observer_limits());
        let now = Instant::now();
        let first = admission
            .try_acquire_at(1_000, now)
            .ok_or_else(|| anyhow!("first connection was unexpectedly denied"))?;
        let second = admission
            .try_acquire_at(1_000, now)
            .ok_or_else(|| anyhow!("second connection was unexpectedly denied"))?;
        assert!(admission.try_acquire_at(1_000, now).is_none());

        // A different unprivileged UID still receives service while the first
        // UID is holding its complete per-user quota.
        let other = admission
            .try_acquire_at(1_001, now)
            .ok_or_else(|| anyhow!("another UID was unfairly denied"))?;
        assert_eq!(admission.active(), 3);
        drop((first, second, other));
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn rule_page_build_admission_is_global_per_uid_and_raii_released() -> Result<()> {
        let admission = ObserverAdmission::with_limits(test_observer_limits());
        let now = Instant::now();
        let connections = (1_000..=1_004)
            .map(|uid| {
                admission
                    .try_acquire_at(uid, now)
                    .ok_or_else(|| anyhow!("connection for uid {uid} was unexpectedly denied"))
            })
            .collect::<Result<Vec<_>>>()?;

        let first = connections[0]
            .try_acquire_rule_page_build()
            .ok_or_else(|| anyhow!("first page build was unexpectedly denied"))?;
        assert!(connections[0].try_acquire_rule_page_build().is_none());
        let second = connections[1]
            .try_acquire_rule_page_build()
            .ok_or_else(|| anyhow!("second page build was unexpectedly denied"))?;
        let third = connections[2]
            .try_acquire_rule_page_build()
            .ok_or_else(|| anyhow!("third page build was unexpectedly denied"))?;
        let fourth = connections[3]
            .try_acquire_rule_page_build()
            .ok_or_else(|| anyhow!("fourth page build was unexpectedly denied"))?;
        assert_eq!(admission.active_rule_page_builds(), 4);
        assert!(connections[4].try_acquire_rule_page_build().is_none());

        drop(second);
        let replacement = connections[4]
            .try_acquire_rule_page_build()
            .ok_or_else(|| anyhow!("released global page slot was not reusable"))?;
        assert_eq!(admission.active_rule_page_builds(), 4);
        drop((first, third, fourth, replacement));
        assert_eq!(admission.active_rule_page_builds(), 0);
        drop(connections);
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn rule_page_build_permit_releases_on_early_error_return() -> Result<()> {
        let admission = ObserverAdmission::with_limits(test_observer_limits());
        let connection = admission
            .try_acquire_at(1_000, Instant::now())
            .ok_or_else(|| anyhow!("connection was unexpectedly denied"))?;

        let simulated_build: Result<()> = (|| {
            let _page = connection
                .try_acquire_rule_page_build()
                .ok_or_else(|| anyhow!("page build was unexpectedly denied"))?;
            Err(anyhow!("simulated page-build failure"))
        })();
        assert!(simulated_build.is_err());
        assert_eq!(admission.active_rule_page_builds(), 0);
        assert!(connection.try_acquire_rule_page_build().is_some());
        Ok(())
    }

    #[test]
    fn production_per_uid_quotas_are_enforced_exactly() -> Result<()> {
        let admission = ObserverAdmission::production();
        let now = Instant::now();
        let mut connections = Vec::new();
        for _index in 0..MAX_OBSERVE_CONNECTIONS_PER_UID {
            connections.push(
                admission
                    .try_acquire_at(1_000, now)
                    .ok_or_else(|| anyhow!("production connection quota was too small"))?,
            );
        }
        assert!(admission.try_acquire_at(1_000, now).is_none());

        let mut subscriptions = Vec::new();
        for connection in connections.iter().take(MAX_OBSERVE_SUBSCRIBERS_PER_UID) {
            subscriptions.push(
                connection
                    .try_acquire_subscription()
                    .ok_or_else(|| anyhow!("production subscription quota was too small"))?,
            );
        }
        assert!(
            connections[MAX_OBSERVE_SUBSCRIBERS_PER_UID]
                .try_acquire_subscription()
                .is_none()
        );

        let other_uid = admission
            .try_acquire_at(1_001, now)
            .ok_or_else(|| anyhow!("first UID monopolized observation admission"))?;
        drop((subscriptions, connections, other_uid));
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn one_uid_cannot_monopolize_subscriptions() -> Result<()> {
        let admission = ObserverAdmission::with_limits(test_observer_limits());
        let now = Instant::now();
        let first_connection = admission
            .try_acquire_at(1_000, now)
            .ok_or_else(|| anyhow!("first connection was unexpectedly denied"))?;
        let second_connection = admission
            .try_acquire_at(1_000, now)
            .ok_or_else(|| anyhow!("second connection was unexpectedly denied"))?;
        let first_subscription = first_connection
            .try_acquire_subscription()
            .ok_or_else(|| anyhow!("first subscription was unexpectedly denied"))?;
        assert!(second_connection.try_acquire_subscription().is_none());

        // Per-UID limiting leaves global subscription capacity for other
        // observers, while the worker reservation leaves read capacity even
        // when the global subscription limit is reached.
        let other_connection = admission
            .try_acquire_at(1_001, now)
            .ok_or_else(|| anyhow!("second UID connection was unexpectedly denied"))?;
        let other_subscription = other_connection
            .try_acquire_subscription()
            .ok_or_else(|| anyhow!("second UID subscription was unexpectedly denied"))?;
        let third_connection = admission
            .try_acquire_at(1_002, now)
            .ok_or_else(|| anyhow!("third UID connection was unexpectedly denied"))?;
        let third_subscription = third_connection
            .try_acquire_subscription()
            .ok_or_else(|| anyhow!("third UID subscription was unexpectedly denied"))?;
        let read_only_connection = admission
            .try_acquire_at(1_003, now)
            .ok_or_else(|| anyhow!("one-shot observation capacity was not reserved"))?;
        assert!(read_only_connection.try_acquire_subscription().is_none());
        assert_eq!(OBSERVE_WORKER_COUNT - MAX_OBSERVE_SUBSCRIBERS, 8);

        drop((
            first_subscription,
            other_subscription,
            third_subscription,
            first_connection,
            second_connection,
            other_connection,
            third_connection,
            read_only_connection,
        ));
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn observer_token_bucket_bounds_sustained_request_rate() -> Result<()> {
        let limits = ObserverLimits {
            maximum_connections_per_uid: 1,
            rate_burst: 2,
            rate_per_second: 1,
            ..test_observer_limits()
        };
        let admission = ObserverAdmission::with_limits(limits);
        let started = Instant::now();

        let first = admission
            .try_acquire_at(1_000, started)
            .ok_or_else(|| anyhow!("first burst token was unexpectedly denied"))?;
        drop(first);
        let second = admission
            .try_acquire_at(1_000, started)
            .ok_or_else(|| anyhow!("second burst token was unexpectedly denied"))?;
        drop(second);
        assert!(
            admission
                .try_acquire_at(1_000, started + Duration::from_millis(999))
                .is_none()
        );
        let refilled = admission
            .try_acquire_at(1_000, started + Duration::from_secs(1))
            .ok_or_else(|| anyhow!("token bucket did not refill deterministically"))?;
        drop(refilled);
        Ok(())
    }

    #[test]
    fn global_observer_token_bucket_bounds_distinct_uids() -> Result<()> {
        let limits = ObserverLimits {
            maximum_connections_per_uid: 1,
            rate_burst: 8,
            rate_per_second: 8,
            global_rate_burst: 2,
            global_rate_per_second: 1,
            ..test_observer_limits()
        };
        let admission = ObserverAdmission::with_limits(limits);
        let started = Instant::now();

        let first = admission
            .try_acquire_at(1_000, started)
            .ok_or_else(|| anyhow!("first global burst token was unexpectedly denied"))?;
        let second = admission
            .try_acquire_at(1_001, started)
            .ok_or_else(|| anyhow!("second global burst token was unexpectedly denied"))?;
        drop((first, second));
        assert!(
            admission
                .try_acquire_at(1_002, started + Duration::from_millis(999))
                .is_none()
        );
        let refilled = admission
            .try_acquire_at(1_002, started + Duration::from_secs(1))
            .ok_or_else(|| anyhow!("global token bucket did not refill deterministically"))?;
        drop(refilled);
        Ok(())
    }

    #[test]
    fn production_bursts_allow_a_complete_ten_thousand_rule_snapshot() {
        let page_size = usize::from(MAX_RULES_PER_PAGE);
        let page_requests = MAX_RULES.saturating_add(page_size - 1) / page_size;
        // One connection admission, one Status request, then every rule page.
        let initial_snapshot_work = page_requests + 2;
        assert!(
            usize::try_from(OBSERVE_RATE_BURST)
                .is_ok_and(|burst| { burst >= initial_snapshot_work })
        );
        assert!(
            usize::try_from(OBSERVE_GLOBAL_RATE_BURST)
                .is_ok_and(|burst| { burst >= initial_snapshot_work })
        );
    }

    #[test]
    fn observer_requests_consume_the_same_per_uid_work_budget() -> Result<()> {
        let limits = ObserverLimits {
            maximum_connections_per_uid: 1,
            rate_burst: 2,
            rate_per_second: 1,
            ..test_observer_limits()
        };
        let admission = ObserverAdmission::with_limits(limits);
        let started = Instant::now();
        let permit = admission
            .try_acquire_at(1_000, started)
            .ok_or_else(|| anyhow!("connection token was unexpectedly denied"))?;
        assert!(permit.try_consume_request_at(started));
        assert!(!permit.try_consume_request_at(started));
        assert!(permit.try_consume_request_at(started + Duration::from_secs(1)));
        Ok(())
    }

    #[test]
    fn observer_rate_state_has_a_bounded_uid_cardinality() -> Result<()> {
        let limits = ObserverLimits {
            maximum_tracked_uids: 2,
            ..test_observer_limits()
        };
        let admission = ObserverAdmission::with_limits(limits);
        let started = Instant::now();
        for uid in [1_000, 1_001] {
            let permit = admission
                .try_acquire_at(uid, started)
                .ok_or_else(|| anyhow!("tracked UID was unexpectedly denied"))?;
            drop(permit);
        }
        assert!(admission.try_acquire_at(1_002, started).is_none());

        let after_idle = started + limits.rate_entry_idle;
        let replacement = admission
            .try_acquire_at(1_002, after_idle)
            .ok_or_else(|| anyhow!("idle UID entries were not reclaimed"))?;
        drop(replacement);
        Ok(())
    }

    #[test]
    fn production_subscription_cap_reserves_eight_read_workers() -> Result<()> {
        let admission = ObserverAdmission::production();
        let now = Instant::now();
        let mut connections = Vec::new();
        let mut subscriptions = Vec::new();
        for index in 0..MAX_OBSERVE_SUBSCRIBERS {
            let uid_offset = u32::try_from(index / MAX_OBSERVE_SUBSCRIBERS_PER_UID)?;
            let connection = admission
                .try_acquire_at(2_000 + uid_offset, now)
                .ok_or_else(|| anyhow!("global subscription setup was unexpectedly denied"))?;
            let subscription = connection
                .try_acquire_subscription()
                .ok_or_else(|| anyhow!("global subscription cap was too small"))?;
            connections.push(connection);
            subscriptions.push(subscription);
        }

        let read_connection = admission
            .try_acquire_at(9_000, now)
            .ok_or_else(|| anyhow!("subscription cap consumed one-shot read capacity"))?;
        assert!(read_connection.try_acquire_subscription().is_none());
        assert_eq!(OBSERVE_WORKER_COUNT - MAX_OBSERVE_SUBSCRIBERS, 8);
        drop((subscriptions, connections, read_connection));
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn observation_flood_uses_only_fixed_workers_and_shutdown_releases_queue() -> Result<()> {
        let temporary = tempdir()?;
        let store =
            AtomicStateStore::for_owner(temporary.path().join("state.json"), geteuid().as_raw());
        let events = EventBus::new();
        let engine = Arc::new(Mutex::new(Engine::load(
            Box::new(MemoryBackend::default()),
            Box::new(store),
            events.clone(),
        )?));
        let shutdown = Arc::new(AtomicBool::new(false));
        let admission = ObserverAdmission::production();
        let (sender, workers) = spawn_observe_workers(&engine, &events, &shutdown)?;
        let worker_ids: HashSet<_> = workers.iter().map(|worker| worker.thread().id()).collect();
        assert_eq!(workers.len(), OBSERVE_WORKER_COUNT);
        assert_eq!(worker_ids.len(), OBSERVE_WORKER_COUNT);

        for index in 0..(OBSERVE_QUEUE_CAPACITY * 4) {
            let uid = 10_000_u32.saturating_add(u32::try_from(index)?);
            let Some(permit) = admission.try_acquire_at(uid, Instant::now()) else {
                // Rejection at the global in-flight bound is expected under a
                // flood and is itself part of the property being tested.
                continue;
            };
            let (stream, peer) = UnixStream::pair()?;
            drop(peer);
            match sender.try_send(ObserveJob { stream, permit }) {
                Ok(()) | Err(TrySendError::Full(_)) => {}
                Err(TrySendError::Disconnected(_)) => {
                    return Err(anyhow!("fixed worker queue disconnected during flood"));
                }
            }
        }

        // No request path contains a thread spawn; the same startup handles
        // remain the complete worker set after the flood.
        assert_eq!(workers.len(), OBSERVE_WORKER_COUNT);
        shutdown.store(true, Ordering::Release);
        drop(sender);
        join_observe_workers(workers)?;
        assert_eq!(admission.active(), 0);
        Ok(())
    }

    #[test]
    fn empty_observation_pool_shutdown_is_not_serialized_per_worker() -> Result<()> {
        let temporary = tempdir()?;
        let store = AtomicStateStore::for_owner(
            temporary.path().join("shutdown-state.json"),
            geteuid().as_raw(),
        );
        let events = EventBus::new();
        let engine = Arc::new(Mutex::new(Engine::load(
            Box::new(MemoryBackend::default()),
            Box::new(store),
            events.clone(),
        )?));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (sender, workers) = spawn_observe_workers(&engine, &events, &shutdown)?;
        thread::sleep(Duration::from_millis(50));

        let started = Instant::now();
        shutdown.store(true, Ordering::Release);
        join_observe_workers(workers)?;
        drop(sender);
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn counter_events_are_not_hidden_by_policy_revision() {
        let state = State::new();
        let event = state.counters_event(FirewallCounters::default(), Utc::now());
        assert!(!event_reflected_by_revision(&event, state.revision()));
    }

    #[test]
    fn structural_events_at_baseline_are_skipped() -> Result<()> {
        let mut state = State::new();
        let event = state.set_mode(openshield_core::Mode::Enforcing)?;
        assert!(event_reflected_by_revision(&event, state.revision()));
        Ok(())
    }

    #[test]
    fn request_reader_has_an_absolute_deadline_against_slow_dribble() -> Result<()> {
        let (mut reader, mut writer) = UnixStream::pair()?;
        configure_client(&reader)?;
        let mut deliberately_slow_frame = vec![0_u8, 0, 0, 100];
        deliberately_slow_frame.extend(std::iter::repeat_n(b' ', 100));
        let writer_thread = thread::spawn(move || {
            for byte in deliberately_slow_frame {
                if writer.write_all(&[byte]).is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        });

        let started = Instant::now();
        let result = read_request_before(&mut reader, started + Duration::from_millis(40));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
        let _ignored = reader.shutdown(Shutdown::Both);
        writer_thread
            .join()
            .map_err(|_| anyhow!("slow writer thread terminated unexpectedly"))?;
        Ok(())
    }

    #[test]
    fn response_writer_has_an_absolute_deadline_against_slow_reader() -> Result<()> {
        let (mut writer, mut reader) = UnixStream::pair()?;
        reader.set_read_timeout(Some(Duration::from_millis(10)))?;
        let stop = Arc::new(AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        let reader_thread = thread::spawn(move || {
            let mut byte = [0_u8; 1];
            while !reader_stop.load(Ordering::Acquire) {
                match reader.read(&mut byte) {
                    Ok(0) => break,
                    Ok(_) => thread::sleep(Duration::from_millis(5)),
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => break,
                }
            }
        });

        let started = Instant::now();
        let mut deadline_writer = DeadlineWriter {
            stream: &mut writer,
            deadline: started + Duration::from_millis(40),
        };
        let result = deadline_writer.write_all(&vec![0_u8; 8 * 1024 * 1024]);
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_millis(250));
        stop.store(true, Ordering::Release);
        let _ignored = writer.shutdown(Shutdown::Both);
        reader_thread
            .join()
            .map_err(|_| anyhow!("slow reader thread terminated unexpectedly"))?;
        Ok(())
    }
}
