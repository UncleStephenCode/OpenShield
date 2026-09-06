#![forbid(unsafe_code)]

mod application;
mod application_diagnostics;
mod backend;
mod compatibility;
mod engine;
mod learning;
mod nfqueue;
mod server;
mod socket;

use std::ffi::OsString;
use std::fs::{self, DirBuilder};
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result, ensure};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, pthread_sigmask};
use nix::unistd::geteuid;
use openshield_core::{AtomicStateStore, StateStore};
use tracing::{error, info};

use crate::backend::{AutoBackend, FirewallBackend, FirewallObserver, QueueVerdictStrategy};
use crate::engine::{Engine, EventBus, SharedEngine};
use crate::socket::{DaemonInstance, SocketSet, required_observer_gid};

const STATE_DIRECTORY: &str = "/var/lib/openshield";
const STATE_FILE: &str = "/var/lib/openshield/state.json";
const STATE_DIRECTORY_MODE: u32 = 0o700;
const MAX_NOTIFY_SOCKET_BYTES: usize = 107;
const NOTIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const READY_MESSAGE: &[u8] = b"READY=1";

#[derive(Debug)]
struct ActiveRuntime {
    sockets: SocketSet,
    queue: nfqueue::QueueRuntime,
    monitor: thread::JoinHandle<()>,
    _signal: thread::JoinHandle<()>,
}

fn main() -> ExitCode {
    match dispatch() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openshield-daemon: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartupAction {
    Run,
    Help,
    Version,
    InstallFailClosed,
}

fn dispatch() -> Result<()> {
    match parse_startup_action(std::env::args_os().skip(1))? {
        StartupAction::Run => run(),
        StartupAction::Help => write_stdout(
            "Usage: openshield-daemon [--help | --version | --install-fail-closed]\n\n\
             With no arguments, starts the privileged local firewall service.\n\
             --install-fail-closed installs only BlockAll for service startup ordering.\n",
        ),
        StartupAction::Version => write_stdout(concat!(
            env!("CARGO_PKG_NAME"),
            " ",
            env!("CARGO_PKG_VERSION"),
            "\n"
        )),
        StartupAction::InstallFailClosed => install_fail_closed(),
    }
}

fn parse_startup_action(arguments: impl IntoIterator<Item = OsString>) -> Result<StartupAction> {
    let mut arguments = arguments.into_iter();
    let Some(argument) = arguments.next() else {
        return Ok(StartupAction::Run);
    };
    ensure!(
        arguments.next().is_none(),
        "unsupported daemon arguments; use --help for usage"
    );
    match argument.to_str() {
        Some("-h" | "--help") => Ok(StartupAction::Help),
        Some("-V" | "--version") => Ok(StartupAction::Version),
        Some("--install-fail-closed") => Ok(StartupAction::InstallFailClosed),
        _ => anyhow::bail!("unsupported daemon argument; use --help for usage"),
    }
}

fn install_fail_closed() -> Result<()> {
    ensure!(
        geteuid().is_root(),
        "--install-fail-closed requires effective uid 0"
    );
    let _instance = DaemonInstance::acquire_fixed()
        .context("another daemon operation is active; refusing to replace its live policy")?;
    let mut backend = AutoBackend::discover().context(
        "cannot initialize a trusted firewall backend; fail-closed enforcement is unavailable",
    )?;
    info!(
        firewall_backend = backend.name(),
        "selected firewall backend"
    );
    install_fail_closed_with(&mut backend)
}

fn install_fail_closed_with<B: FirewallBackend>(backend: &mut B) -> Result<()> {
    backend
        .fail_closed()
        .context("cannot install the explicit fail-closed startup policy")
}

#[cfg(test)]
fn install_fail_closed_at<B: FirewallBackend>(
    backend: &mut B,
    runtime_directory: &Path,
    lock_path: &Path,
    expected_uid: u32,
) -> Result<()> {
    let _instance = DaemonInstance::acquire_at(runtime_directory, lock_path, expected_uid)
        .context("another daemon operation is active; refusing to replace its live policy")?;
    install_fail_closed_with(backend)
}

fn write_stdout(message: &str) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    output
        .write_all(message.as_bytes())
        .context("cannot write command output")?;
    output.flush().context("cannot flush command output")
}

fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .try_init()
        .map_err(|error| anyhow::anyhow!("cannot initialize structured logging: {error}"))?;

    ensure!(
        geteuid().is_root(),
        "openshield-daemon must run with effective uid 0"
    );
    let instance =
        DaemonInstance::acquire_fixed().context("cannot acquire the singleton daemon lock")?;
    let termination_signals = block_termination_signals()?;

    let mut backend = AutoBackend::discover().context(
        "cannot initialize a trusted firewall backend; fail-closed enforcement is unavailable",
    )?;
    info!(
        firewall_backend = backend.name(),
        "selected firewall backend"
    );
    // Do not rely solely on service-manager preflight. A direct invocation
    // must close the network before it inspects storage or constructs any
    // fallible userspace runtime component. Engine::load repeats this
    // quarantine deliberately; only start_firewall_runtime may later replace
    // it after the authenticated NFQUEUE consumer is ready.
    install_fail_closed_with(&mut backend)
        .context("cannot install the bootstrap BlockAll policy before state inspection")?;
    ensure_state_storage_or_fail_closed(&mut backend, Path::new(STATE_DIRECTORY), 0)?;
    let queue_verdict_strategy = backend.queue_verdict_strategy();
    let observer = backend.clone();
    let store: Box<dyn StateStore> = Box::new(AtomicStateStore::root_owned(STATE_FILE));
    let events = EventBus::new();
    let engine = Engine::load(Box::new(backend), store, events.clone())
        .context("cannot initialize fail-closed policy engine")?;
    // Engine loading has already installed the bootstrap BlockAll quarantine.
    // A missing NSS/group prerequisite must therefore fail closed before any
    // desired persisted policy is activated.
    let observer_gid = required_observer_gid().context(
        "observation is unavailable without the required system group; refusing partial startup",
    )?;

    let engine = Arc::new(Mutex::new(engine));
    let shutdown = Arc::new(AtomicBool::new(false));
    let ActiveRuntime {
        sockets,
        queue: queue_runtime,
        monitor,
        _signal: _signal_thread,
    } = start_firewall_runtime(
        instance,
        observer,
        observer_gid,
        termination_signals,
        &engine,
        &shutdown,
        queue_verdict_strategy,
    )?;

    info!("OpenShield firewall policy and local IPC are active");
    let server_result = server::serve(&sockets, &engine, &events, &shutdown);
    shutdown.store(true, Ordering::Release);
    let shutdown_quarantine = install_runtime_shutdown_quarantine(&engine);
    let queue_result = queue_runtime.join();
    let monitor_result = monitor
        .join()
        .map_err(|_| anyhow::anyhow!("firewall monitor terminated unexpectedly"));
    // Repeat after all policy-mutating workers have exited. The first call
    // closes the shutdown window; this final call makes BlockAll authoritative
    // even if a worker was already completing an observation when shutdown
    // began.
    let final_shutdown_quarantine = install_runtime_shutdown_quarantine(&engine);
    server_result?;
    shutdown_quarantine?;
    queue_result?;
    monitor_result?;
    final_shutdown_quarantine?;
    let engine = engine
        .lock()
        .map_err(|_| anyhow::anyhow!("policy engine mutex is poisoned during shutdown"))?;
    if engine.restart_required() {
        if engine.is_fatal() {
            anyhow::bail!("kernel policy is unknown; requesting service-manager restart");
        }
        anyhow::bail!("firewall integrity recovery requires a service-manager restart");
    }
    drop(engine);
    info!("OpenShield daemon stopped; kernel-resident policy remains active");
    Ok(())
}

fn start_firewall_runtime<O>(
    instance: DaemonInstance,
    observer: O,
    observer_gid: u32,
    termination_signals: SigSet,
    engine: &SharedEngine,
    shutdown: &Arc<AtomicBool>,
    queue_verdict_strategy: QueueVerdictStrategy,
) -> Result<ActiveRuntime>
where
    O: FirewallObserver + 'static,
{
    let queue_runtime = match nfqueue::spawn(engine, shutdown, queue_verdict_strategy) {
        Ok(runtime) => runtime,
        Err(error) => {
            if let Ok(mut engine) = engine.lock() {
                engine.quarantine_after_runtime_failure();
            }
            return Err(error).context(
                "application quarantine is unavailable; emergency BlockAll was requested",
            );
        }
    };

    let startup_activation = engine
        .lock()
        .map_err(|_| anyhow::anyhow!("policy engine mutex is poisoned during startup"))
        .and_then(|mut engine| {
            engine.activate_startup_policy()?;
            let compatibility = engine.runtime_compatibility();
            info!(
                compatibility_level = ?compatibility.level,
                compatibility_reason = ?compatibility.reason,
                "selected runtime compatibility"
            );
            Ok(())
        });
    if let Err(error) = startup_activation {
        return Err(clean_up_failed_startup(
            error.context(
                "cannot leave the bootstrap BlockAll quarantine for the selected startup policy",
            ),
            engine,
            shutdown,
            queue_runtime,
            None,
        ));
    }

    // Bind management sockets only after the complete kernel policy and its
    // fail-closed application-verdict consumer are active.
    let sockets = match instance.bind_sockets(observer_gid) {
        Ok(sockets) => sockets,
        Err(error) => {
            return Err(clean_up_failed_startup(
                error.context("cannot create local management sockets"),
                engine,
                shutdown,
                queue_runtime,
                None,
            ));
        }
    };
    let signal = match spawn_signal_waiter(termination_signals, Arc::clone(shutdown)) {
        Ok(signal_thread) => signal_thread,
        Err(error) => {
            return Err(clean_up_failed_startup(
                error,
                engine,
                shutdown,
                queue_runtime,
                None,
            ));
        }
    };
    let monitor = match learning::spawn_monitor(observer, Arc::clone(engine), Arc::clone(shutdown))
    {
        Ok(monitor) => monitor,
        Err(error) => {
            return Err(clean_up_failed_startup(
                error,
                engine,
                shutdown,
                queue_runtime,
                None,
            ));
        }
    };
    if let Err(error) = notify_systemd_ready() {
        return Err(clean_up_failed_startup(
            error,
            engine,
            shutdown,
            queue_runtime,
            Some(monitor),
        ));
    }

    Ok(ActiveRuntime {
        sockets,
        queue: queue_runtime,
        monitor,
        _signal: signal,
    })
}

fn install_runtime_shutdown_quarantine(engine: &SharedEngine) -> Result<()> {
    engine
        .lock()
        .map_err(|_| anyhow::anyhow!("policy engine mutex is poisoned during shutdown"))?
        .install_shutdown_quarantine()
}

fn clean_up_failed_startup(
    startup_error: anyhow::Error,
    engine: &SharedEngine,
    shutdown: &Arc<AtomicBool>,
    queue_runtime: nfqueue::QueueRuntime,
    monitor: Option<thread::JoinHandle<()>>,
) -> anyhow::Error {
    shutdown.store(true, Ordering::Release);
    let mut cleanup_errors = Vec::new();
    if let Err(error) = install_runtime_shutdown_quarantine(engine) {
        cleanup_errors.push(format!("shutdown quarantine failed: {error:#}"));
    }
    if let Err(error) = queue_runtime.join() {
        cleanup_errors.push(format!("NFQUEUE shutdown failed: {error:#}"));
    }
    if let Some(monitor) = monitor
        && monitor.join().is_err()
    {
        cleanup_errors.push("firewall monitor panicked during shutdown".to_owned());
    }
    if cleanup_errors.is_empty() {
        startup_error
    } else {
        anyhow::anyhow!(
            "{startup_error:#}; fail-closed startup cleanup also reported: {}",
            cleanup_errors.join("; ")
        )
    }
}

fn notify_systemd_ready() -> Result<()> {
    let Some(destination) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    send_ready_notification(&destination)
        .context("cannot notify the service manager after fail-closed startup")
}

fn send_ready_notification(destination: &std::ffi::OsStr) -> Result<()> {
    use std::os::linux::net::SocketAddrExt;

    let bytes = destination.as_bytes();
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_NOTIFY_SOCKET_BYTES,
        "NOTIFY_SOCKET has an invalid bounded length"
    );
    ensure!(
        !bytes.contains(&0),
        "NOTIFY_SOCKET contains an embedded NUL"
    );

    let address = match bytes.first() {
        Some(b'@') => {
            ensure!(bytes.len() > 1, "abstract NOTIFY_SOCKET has no name");
            SocketAddr::from_abstract_name(&bytes[1..]).context("invalid abstract NOTIFY_SOCKET")?
        }
        Some(b'/') => SocketAddr::from_pathname(Path::new(destination))
            .context("invalid filesystem NOTIFY_SOCKET")?,
        _ => anyhow::bail!("NOTIFY_SOCKET must be absolute or abstract"),
    };
    let socket = UnixDatagram::unbound().context("cannot create readiness datagram socket")?;
    socket
        .set_write_timeout(Some(NOTIFY_TIMEOUT))
        .context("cannot bound readiness notification write")?;
    let sent = socket
        .send_to_addr(READY_MESSAGE, &address)
        .context("cannot send READY=1")?;
    ensure!(
        sent == READY_MESSAGE.len(),
        "readiness notification was truncated"
    );
    Ok(())
}

fn ensure_state_storage_or_fail_closed<B>(
    backend: &mut B,
    path: &Path,
    required_owner: u32,
) -> Result<()>
where
    B: FirewallBackend,
{
    let Err(storage_error) = ensure_private_directory(path, required_owner) else {
        return Ok(());
    };
    match backend.fail_closed() {
        Ok(()) => Err(storage_error)
            .context("state storage is unsafe; fail-closed policy was installed before exit"),
        Err(firewall_error) => Err(anyhow::anyhow!(
            "state storage validation failed ({storage_error:#}); fail-closed installation also failed ({firewall_error:#})"
        )),
    }
}

fn block_termination_signals() -> Result<SigSet> {
    let mut signals = SigSet::empty();
    signals.add(Signal::SIGINT);
    signals.add(Signal::SIGTERM);
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&signals), None)
        .context("cannot block termination signals for graceful handling")?;
    Ok(signals)
}

fn spawn_signal_waiter(
    signals: SigSet,
    shutdown: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("openshield-signal-waiter".to_owned())
        .spawn(move || match signals.wait() {
            Ok(signal) => {
                info!(?signal, "termination signal received");
                shutdown.store(true, Ordering::Release);
            }
            Err(error) => {
                error!(%error, "signal waiter failed; initiating safe shutdown");
                shutdown.store(true, Ordering::Release);
            }
        })
        .context("cannot spawn termination signal waiter")
}

fn ensure_private_directory(path: &Path, required_owner: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("state directory has no parent"))?;
    validate_directory(parent, required_owner, false)?;

    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(STATE_DIRECTORY_MODE)
                .create(path)
                .with_context(|| format!("cannot create state directory {}", path.display()))?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect state directory {}", path.display()));
        }
    }
    validate_directory(path, required_owner, true)
}

fn validate_directory(path: &Path, required_owner: u32, require_private: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect directory {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "{} is a symlink",
        path.display()
    );
    ensure!(metadata.is_dir(), "{} is not a directory", path.display());
    ensure!(
        metadata.uid() == required_owner,
        "{} has an untrusted owner",
        path.display()
    );
    let mode = metadata.permissions().mode() & 0o777;
    if require_private {
        ensure!(
            mode == STATE_DIRECTORY_MODE,
            "{} must have mode {STATE_DIRECTORY_MODE:#o}, not {mode:#o}",
            path.display()
        );
    } else {
        ensure!(
            mode & 0o022 == 0,
            "{} is writable by group or other users",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use openshield_core::{FirewallCounters, Snapshot};
    use std::ffi::{OsStr, OsString};
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    use nix::unistd::geteuid;
    use tempfile::tempdir;

    use super::*;
    use crate::backend::FirewallObserver;

    #[derive(Debug, Default)]
    struct StartupBackendProbe {
        fail_closed_calls: usize,
    }

    impl FirewallObserver for StartupBackendProbe {
        fn policy_observation(&mut self) -> Result<FirewallCounters> {
            Ok(FirewallCounters::default())
        }
    }

    impl FirewallBackend for StartupBackendProbe {
        fn apply(&mut self, _snapshot: &Snapshot) -> Result<()> {
            Ok(())
        }

        fn fail_closed(&mut self) -> Result<()> {
            self.fail_closed_calls += 1;
            Ok(())
        }
    }

    #[test]
    fn creates_private_state_directory() -> Result<()> {
        let temporary = tempdir()?;
        let state = temporary.path().join("state");
        ensure_private_directory(&state, geteuid().as_raw())?;
        assert_eq!(
            fs::symlink_metadata(state)?.permissions().mode() & 0o777,
            STATE_DIRECTORY_MODE
        );
        Ok(())
    }

    #[test]
    fn rejects_state_directory_symlink() -> Result<()> {
        let temporary = tempdir()?;
        let target = temporary.path().join("target");
        fs::create_dir(&target)?;
        let state = temporary.path().join("state");
        symlink(target, &state)?;
        assert!(ensure_private_directory(&state, geteuid().as_raw()).is_err());
        Ok(())
    }

    #[test]
    fn rejects_group_access_to_state_directory() -> Result<()> {
        let temporary = tempdir()?;
        let state = temporary.path().join("state");
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750))?;
        assert!(ensure_private_directory(&state, geteuid().as_raw()).is_err());
        Ok(())
    }

    #[test]
    fn unsafe_state_storage_installs_block_all_before_startup_fails() -> Result<()> {
        let temporary = tempdir()?;
        let state = temporary.path().join("state");
        fs::create_dir(&state)?;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o750))?;
        let mut backend = StartupBackendProbe::default();

        assert!(
            ensure_state_storage_or_fail_closed(&mut backend, &state, geteuid().as_raw()).is_err()
        );
        assert_eq!(backend.fail_closed_calls, 1);
        Ok(())
    }

    #[test]
    fn daemon_arguments_are_decided_before_privileged_startup() -> Result<()> {
        assert_eq!(
            parse_startup_action(Vec::<OsString>::new())?,
            StartupAction::Run
        );
        assert_eq!(
            parse_startup_action([OsString::from("--help")])?,
            StartupAction::Help
        );
        assert_eq!(
            parse_startup_action([OsString::from("--version")])?,
            StartupAction::Version
        );
        assert_eq!(
            parse_startup_action([OsString::from("--install-fail-closed")])?,
            StartupAction::InstallFailClosed
        );
        assert!(parse_startup_action([OsString::from("--unknown")]).is_err());
        assert!(parse_startup_action([OsString::from("--help"), OsString::from("extra")]).is_err());
        Ok(())
    }

    #[test]
    fn explicit_startup_action_installs_only_fail_closed_policy() -> Result<()> {
        let mut backend = StartupBackendProbe::default();
        install_fail_closed_with(&mut backend)?;
        assert_eq!(backend.fail_closed_calls, 1);
        Ok(())
    }

    #[test]
    fn manual_fail_closed_refuses_to_touch_a_running_daemon_policy() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        let lock = runtime.join("daemon.lock");
        let uid = geteuid().as_raw();
        let _running = DaemonInstance::acquire_at(&runtime, &lock, uid)?;
        let mut backend = StartupBackendProbe::default();

        assert!(install_fail_closed_at(&mut backend, &runtime, &lock, uid).is_err());
        assert_eq!(backend.fail_closed_calls, 0);
        Ok(())
    }

    #[test]
    fn readiness_notification_reaches_filesystem_datagram() -> Result<()> {
        let temporary = tempdir()?;
        let path = temporary.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&path)?;
        receiver.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;

        send_ready_notification(path.as_os_str())?;
        let mut message = [0_u8; 32];
        let message_len = receiver.recv(&mut message)?;
        assert_eq!(&message[..message_len], READY_MESSAGE);
        Ok(())
    }

    #[test]
    fn readiness_notification_supports_linux_abstract_datagram() -> Result<()> {
        let name = format!("openshield-test-{}", uuid::Uuid::new_v4());
        let address = SocketAddr::from_abstract_name(name.as_bytes())?;
        let receiver = UnixDatagram::bind_addr(&address)?;
        receiver.set_read_timeout(Some(std::time::Duration::from_secs(1)))?;
        let destination = OsString::from(format!("@{name}"));

        send_ready_notification(&destination)?;
        let mut message = [0_u8; 32];
        let message_len = receiver.recv(&mut message)?;
        assert_eq!(&message[..message_len], READY_MESSAGE);
        Ok(())
    }

    #[test]
    fn readiness_notification_rejects_untrusted_address_shapes() {
        assert!(send_ready_notification(OsStr::new("relative.sock")).is_err());
        assert!(send_ready_notification(OsStr::new("@")).is_err());
        assert!(send_ready_notification(OsStr::from_bytes(b"/tmp/bad\0socket")).is_err());
        let oversized = OsString::from(format!("/{}", "x".repeat(MAX_NOTIFY_SOCKET_BYTES)));
        assert!(send_ready_notification(&oversized).is_err());
    }
}
