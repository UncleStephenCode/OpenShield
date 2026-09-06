#![forbid(unsafe_code)]

mod app;
mod i18n;
mod terminal;
mod transport;
mod ui;

use std::io::{self, IsTerminal};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;
use crossterm::event::{
    self, Event as TerminalEvent, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
};
use nix::unistd::geteuid;
use openshield_core::Mode;
use openshield_protocol::{Ack, ControlRequest, ErrorCode, OutboundGroupAction};

use crate::app::{App, FormField, GROUP_ACTIONS, Overlay, View};
use crate::i18n::{I18n, Locale};
use crate::terminal::TerminalSession;
use crate::transport::{Observer, ObserverUpdate, SocketPaths};

const INPUT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const STATUS_AGE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const MAX_FATAL_ERROR_CHARS: usize = 4_096;

#[derive(Debug, Parser)]
#[command(name = "openshield-tui", version)]
struct Cli {
    #[arg(long, value_name = "LOCALE")]
    locale: Option<Locale>,
}

fn main() -> ExitCode {
    terminal::install_panic_hook();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openshield-tui: {}", terminal_safe(&format!("{error:#}")));
            ExitCode::FAILURE
        }
    }
}

fn terminal_safe(value: &str) -> String {
    value
        .chars()
        .take(MAX_FATAL_ERROR_CHARS)
        .map(|character| {
            if i18n::is_unsafe_dynamic_character(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let i18n = cli.locale.map_or_else(I18n::detect, I18n::load)?;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        bail!(i18n.tr("main.terminal_required").to_owned());
    }

    let paths = SocketPaths::fixed();

    let read_only = !geteuid().is_root();
    let observer = Observer::start(&paths, &i18n);
    let mut app = App::new(read_only, i18n.clone());
    let mut terminal = TerminalSession::enter()
        .with_context(|| i18n.tr("main.terminal_init_failed").to_owned())?;
    let mut needs_draw = true;
    let mut last_status_draw = Instant::now();

    while !app.should_quit {
        needs_draw |= drain_observer_updates(&observer, &mut app);
        if app.view == View::Status
            && Instant::now().saturating_duration_since(last_status_draw)
                >= STATUS_AGE_REFRESH_INTERVAL
        {
            needs_draw = true;
        }
        if needs_draw {
            terminal
                .terminal_mut()
                .draw(|frame| ui::draw(frame, &app, &paths.observe, &paths.control))
                .with_context(|| i18n.tr("main.draw_failed").to_owned())?;
            if app.view == View::Status {
                last_status_draw = Instant::now();
            }
            needs_draw = false;
        }

        if event::poll(INPUT_POLL_INTERVAL)
            .with_context(|| i18n.tr("main.input_poll_failed").to_owned())?
        {
            match event::read().with_context(|| i18n.tr("main.input_read_failed").to_owned())? {
                TerminalEvent::Key(key) if key.kind == KeyEventKind::Press => {
                    app.notice = None;
                    if let Some(request) = handle_key(&mut app, key) {
                        execute_control(&paths, &observer, &mut app, request);
                    }
                    needs_draw = true;
                }
                TerminalEvent::Resize(_, _) => needs_draw = true,
                _ => {}
            }
        }
    }
    Ok(())
}

fn drain_observer_updates(observer: &Observer, app: &mut App) -> bool {
    let mut updated = false;
    let mut reconcile_rules = false;
    while let Ok(update) = observer.try_recv() {
        updated = true;
        match update {
            ObserverUpdate::Connected => app.connection = app::ConnectionState::Connected,
            ObserverUpdate::Disconnected(reason) => app.set_disconnected(reason),
            ObserverUpdate::TelemetryConnected => app.set_telemetry_connected(),
            ObserverUpdate::TelemetryDisconnected(reason) => {
                app.set_telemetry_disconnected(reason);
            }
            ObserverUpdate::Snapshot {
                snapshot,
                backend,
                runtime_compatibility,
            } => {
                app.connection = app::ConnectionState::Connected;
                app.set_observed_snapshot(snapshot, backend, runtime_compatibility);
            }
            ObserverUpdate::Restarted {
                snapshot,
                backend,
                runtime_compatibility,
            } => {
                app.connection = app::ConnectionState::Connected;
                app.set_restarted_observed_snapshot(snapshot, backend, runtime_compatibility);
            }
            ObserverUpdate::Event(event) => {
                let policy_changed = app.push_observer_event(*event);
                reconcile_rules |= policy_changed;
                if policy_changed && let Err(error) = observer.request_resync() {
                    app.notice = Some(error.localized(&app.i18n));
                }
            }
            ObserverUpdate::Dropped(count) => {
                app.dropped_events = app.dropped_events.saturating_add(count);
            }
        }
    }
    if reconcile_rules {
        app.reconcile_rule_selection();
    }
    updated
}

fn execute_control(
    paths: &SocketPaths,
    observer: &Observer,
    app: &mut App,
    request: ControlRequest,
) {
    let action = ControlAction::from_request(&request);
    match transport::send_control(paths, request) {
        Ok(ack) => {
            let message = ack_message(&ack, action, &app.i18n);
            let resync = request_resync_notice(observer, &app.i18n);
            app.notice = Some(format!("{message}{resync}"));
        }
        Err(error) => {
            let presentation = control_failure_presentation(&error, &app.i18n);
            let resync_status = if presentation.request_resync {
                request_resync_notice(observer, &app.i18n)
            } else {
                String::new()
            };
            app.overlay = Overlay::Message {
                title: presentation.title,
                body: format!("{}{resync_status}", presentation.body),
            };
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ControlFailurePresentation {
    title: String,
    body: String,
    request_resync: bool,
}

fn control_failure_presentation(
    error: &transport::IpcError,
    i18n: &I18n,
) -> ControlFailurePresentation {
    match error {
        transport::IpcError::Rejected {
            code: ErrorCode::Conflict,
            message,
        } => ControlFailurePresentation {
            title: i18n.tr("control.policy_changed_title").to_owned(),
            body: i18n.format("control.policy_changed_body", &[("message", message)]),
            request_resync: true,
        },
        transport::IpcError::Rejected { code, message } => ControlFailurePresentation {
            title: i18n.tr("control.rejected_title").to_owned(),
            body: {
                let code = format!("{code:?}");
                i18n.format(
                    "control.rejected_body",
                    &[("code", code.as_str()), ("message", message)],
                )
            },
            request_resync: true,
        },
        _ => ControlFailurePresentation {
            title: i18n.tr("control.unconfirmed_title").to_owned(),
            body: {
                let error = error.localized(i18n);
                i18n.format("control.unconfirmed_body", &[("error", error.as_str())])
            },
            request_resync: true,
        },
    }
}

fn request_resync_notice(observer: &Observer, i18n: &I18n) -> String {
    observer.request_resync().map_or_else(
        |error| {
            i18n.format(
                "control.resync_failed",
                &[("error", error.localized(i18n).as_str())],
            )
        },
        |()| i18n.tr("control.resync_scheduled").to_owned(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlAction {
    SetMode(Mode),
    CreateRule,
    UpdateRule,
    DeleteRule,
    SetRuleEnabled(bool),
    ManageOutboundGroup(OutboundGroupAction),
}

impl ControlAction {
    const fn from_request(request: &ControlRequest) -> Self {
        match request {
            ControlRequest::SetMode { mode, .. } => Self::SetMode(*mode),
            ControlRequest::CreateRule { .. } => Self::CreateRule,
            ControlRequest::UpdateRule { .. } => Self::UpdateRule,
            ControlRequest::DeleteRule { .. } => Self::DeleteRule,
            ControlRequest::SetRuleEnabled { enabled, .. } => Self::SetRuleEnabled(*enabled),
            ControlRequest::ManageOutboundGroup { action, .. } => {
                Self::ManageOutboundGroup(*action)
            }
        }
    }
}

fn ack_message(ack: &Ack, action: ControlAction, i18n: &I18n) -> String {
    let revision = ack.revision.to_string();
    if let ControlAction::SetMode(mode) = action {
        let mode = match mode {
            Mode::BlockAll => i18n.tr("mode.block_all"),
            Mode::Learning => i18n.tr("mode.learning"),
            Mode::Enforcing => i18n.tr("mode.enforcing"),
        };
        return i18n.format(
            "control.mode_changed",
            &[("mode", mode), ("revision", revision.as_str())],
        );
    }
    if let ControlAction::ManageOutboundGroup(action) = action {
        return i18n.format(
            "control.group_updated",
            &[
                ("action", ui::group_action_label(action, i18n)),
                ("revision", revision.as_str()),
            ],
        );
    }
    let name = ack.affected_rule.as_ref().map_or_else(
        || i18n.tr("common.unknown").to_owned(),
        |rule| rule.spec.name.to_string(),
    );
    let key = match action {
        ControlAction::CreateRule => "control.rule_created",
        ControlAction::UpdateRule => "control.rule_updated",
        ControlAction::DeleteRule => "control.rule_deleted",
        ControlAction::SetRuleEnabled(true) => "control.rule_enabled",
        ControlAction::SetRuleEnabled(false) => "control.rule_disabled",
        ControlAction::SetMode(_) | ControlAction::ManageOutboundGroup(_) => {
            unreachable!("non-rule action returned above")
        }
    };
    i18n.format(
        key,
        &[("rule", name.as_str()), ("revision", revision.as_str())],
    )
}

fn handle_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c' | 'C'))
    {
        app.should_quit = true;
        return None;
    }

    match &app.overlay {
        Overlay::None => handle_normal_key(app, key),
        Overlay::ModePicker { .. } => handle_mode_picker_key(app, key),
        Overlay::ConfirmBlockAll => handle_block_confirmation_key(app, key),
        Overlay::ConfirmDelete { .. } => handle_delete_confirmation_key(app, key),
        Overlay::GroupMenu { .. } => handle_group_menu_key(app, key),
        Overlay::ConfirmGroup { .. } => handle_group_confirmation_key(app, key),
        Overlay::Editor(_) => handle_editor_key(app, key),
        Overlay::Message { .. } => {
            if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                app.close_overlay();
            }
            None
        }
    }
}

fn handle_normal_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    match key.code {
        KeyCode::Char('q' | 'Q') => app.should_quit = true,
        KeyCode::Char('?' | '5') => app.view = View::Help,
        KeyCode::Char('1') => app.view = View::Status,
        KeyCode::Char('2') => app.view = View::Outbound,
        KeyCode::Char('3') => app.view = View::Inbound,
        KeyCode::Char('4') => app.view = View::Events,
        KeyCode::Tab => app.view = app.view.next(),
        KeyCode::Up if matches!(app.view, View::Outbound | View::Inbound) => {
            app.select_previous_rule();
        }
        KeyCode::Down if matches!(app.view, View::Outbound | View::Inbound) => {
            app.select_next_rule();
        }
        KeyCode::Left if app.view == View::Outbound => app.select_previous_group_member(),
        KeyCode::Right if app.view == View::Outbound => app.select_next_group_member(),
        KeyCode::PageUp if matches!(app.view, View::Outbound | View::Inbound) => {
            app.scroll_rule_details(true);
        }
        KeyCode::PageDown if matches!(app.view, View::Outbound | View::Inbound) => {
            app.scroll_rule_details(false);
        }
        KeyCode::Char('m' | 'M') => app.open_mode_picker(),
        KeyCode::Char('g' | 'G') if app.view == View::Outbound => app.open_group_menu(),
        KeyCode::Char('n' | 'N') if matches!(app.view, View::Outbound | View::Inbound) => {
            app.open_create_rule();
        }
        KeyCode::Char('e' | 'E') if matches!(app.view, View::Outbound | View::Inbound) => {
            app.open_edit_rule();
        }
        KeyCode::Char('d' | 'D') if matches!(app.view, View::Outbound | View::Inbound) => {
            app.open_delete_confirmation();
        }
        KeyCode::Char(' ') if matches!(app.view, View::Outbound | View::Inbound) => {
            return app.toggle_selected_rule();
        }
        _ => {}
    }
    None
}

fn handle_mode_picker_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    let Overlay::ModePicker { selected } = &app.overlay else {
        return None;
    };
    let selected = *selected;
    let choice = match key.code {
        KeyCode::Esc => {
            app.close_overlay();
            return None;
        }
        KeyCode::Char('1') => Some(Mode::BlockAll),
        KeyCode::Char('2') => Some(Mode::Learning),
        KeyCode::Char('3') => Some(Mode::Enforcing),
        KeyCode::Enter => Some(selected),
        KeyCode::Up | KeyCode::Left => {
            let previous = match selected {
                Mode::BlockAll => Mode::Enforcing,
                Mode::Learning => Mode::BlockAll,
                Mode::Enforcing => Mode::Learning,
            };
            app.overlay = Overlay::ModePicker { selected: previous };
            None
        }
        KeyCode::Down | KeyCode::Right => {
            let next = match selected {
                Mode::BlockAll => Mode::Learning,
                Mode::Learning => Mode::Enforcing,
                Mode::Enforcing => Mode::BlockAll,
            };
            app.overlay = Overlay::ModePicker { selected: next };
            None
        }
        _ => None,
    };
    choice.and_then(|mode| app.request_mode(mode))
}

fn handle_block_confirmation_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    match key.code {
        KeyCode::Char('y' | 'Y' | 'д' | 'Д') => app.confirm_block_all(true),
        KeyCode::Char('n' | 'N' | 'н' | 'Н') | KeyCode::Esc | KeyCode::Enter => {
            app.confirm_block_all(false)
        }
        _ => None,
    }
}

fn handle_delete_confirmation_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    match key.code {
        KeyCode::Char('y' | 'Y' | 'д' | 'Д') => app.confirm_delete(true),
        KeyCode::Char('n' | 'N' | 'н' | 'Н') | KeyCode::Esc | KeyCode::Enter => {
            app.confirm_delete(false)
        }
        _ => None,
    }
}

fn handle_group_menu_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    let Overlay::GroupMenu { selected, .. } = &app.overlay else {
        return None;
    };
    let selected = *selected;
    match key.code {
        KeyCode::Esc => app.close_overlay(),
        KeyCode::Up => app.move_group_action(true),
        KeyCode::Down => app.move_group_action(false),
        KeyCode::Enter => app.request_group_action(selected),
        KeyCode::Char(character @ '1'..='6') => {
            app.request_group_action(GROUP_ACTIONS[character as usize - '1' as usize]);
        }
        _ => {}
    }
    None
}

fn handle_group_confirmation_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    match key.code {
        KeyCode::Char('y' | 'Y' | 'д' | 'Д') => app.confirm_group_action(true),
        KeyCode::Char('n' | 'N' | 'н' | 'Н') | KeyCode::Esc | KeyCode::Enter => {
            app.confirm_group_action(false)
        }
        _ => None,
    }
}

fn handle_editor_key(app: &mut App, key: KeyEvent) -> Option<ControlRequest> {
    match key.code {
        KeyCode::Esc => {
            app.close_overlay();
            return None;
        }
        KeyCode::Enter => return app.submit_editor(),
        _ => {}
    }

    let Overlay::Editor(form) = &mut app.overlay else {
        return None;
    };
    match key.code {
        KeyCode::Tab => form.move_next(),
        KeyCode::BackTab => form.move_previous(),
        KeyCode::Left => form.cycle_choice(true),
        KeyCode::Right | KeyCode::Char(' ')
            if matches!(
                form.active_field,
                FormField::Action
                    | FormField::Protocol
                    | FormField::Application
                    | FormField::CommandMode
                    | FormField::Enabled
            ) =>
        {
            form.cycle_choice(false);
        }
        KeyCode::Backspace => form.backspace(),
        KeyCode::Char(character)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            form.insert_char(character);
        }
        _ => {}
    }
    None
}

#[cfg(test)]
mod tests {
    use std::io;

    use crossterm::event::KeyEvent;
    use openshield_core::{Direction, Rule, RuleName, RuleOrigin, RuleSpec, TransportProtocol};

    use super::*;

    #[test]
    fn read_only_keyboard_shortcut_does_not_open_editor() {
        let mut app = App::new(true, I18n::test_english());
        app.view = View::Outbound;
        let request = handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
        );
        assert!(request.is_none());
        assert_eq!(app.overlay, Overlay::None);
    }

    #[test]
    fn block_all_keyboard_path_still_requires_confirmation() {
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(openshield_core::Snapshot {
            revision: 4,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: Vec::new(),
        });
        app.open_mode_picker();
        let request = handle_key(
            &mut app,
            KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE),
        );
        assert!(request.is_none());
        assert_eq!(app.overlay, Overlay::ConfirmBlockAll);
    }

    #[test]
    fn group_keyboard_actions_require_confirmation_and_are_outbound_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let rule = Rule::new(RuleSpec::new(
            RuleName::new("outbound")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("192.0.2.1/32".parse()?),
            None,
            None,
            RuleOrigin::Manual,
            true,
        )?)?;
        let press = |app: &mut App, code| handle_key(app, KeyEvent::new(code, KeyModifiers::NONE));
        for (index, action) in GROUP_ACTIONS.into_iter().enumerate() {
            let mut app = App::new(false, I18n::test_english());
            app.set_snapshot(openshield_core::Snapshot {
                revision: 4,
                flow_generation: 1,
                mode: Mode::Enforcing,
                rules: vec![rule.clone()],
            });
            assert!(press(&mut app, KeyCode::Char('g')).is_none());
            assert_eq!(app.overlay, Overlay::None);
            app.view = View::Outbound;
            assert!(press(&mut app, KeyCode::Char('g')).is_none());
            assert!(matches!(app.overlay, Overlay::GroupMenu { .. }));
            for _ in 0..index {
                assert!(press(&mut app, KeyCode::Down).is_none());
            }
            assert!(press(&mut app, KeyCode::Enter).is_none());
            assert!(
                matches!(app.overlay, Overlay::ConfirmGroup { action: selected, .. } if selected == action)
            );
            assert!(press(&mut app, KeyCode::Enter).is_none());
            assert_eq!(app.overlay, Overlay::None);
            assert!(press(&mut app, KeyCode::Char('G')).is_none());
            let number = char::from(b'1' + u8::try_from(index)?);
            assert!(press(&mut app, KeyCode::Char(number)).is_none());
            assert!(
                matches!(press(&mut app, KeyCode::Char('д')), Some(ControlRequest::ManageOutboundGroup { expected_revision: 4, action: selected, .. }) if selected == action)
            );
            assert_eq!(app.overlay, Overlay::None);
            app.read_only = true;
            assert!(press(&mut app, KeyCode::Char('g')).is_none());
            assert_eq!(app.overlay, Overlay::None);
        }
        Ok(())
    }

    #[test]
    fn group_ack_uses_group_action_without_unknown_rule_name()
    -> Result<(), Box<dyn std::error::Error>> {
        let i18n = I18n::load(Locale::Ru)?;
        for action in GROUP_ACTIONS {
            let message = ack_message(
                &Ack::new(25, None),
                ControlAction::ManageOutboundGroup(action),
                &i18n,
            );
            assert!(
                message.contains(ui::group_action_label(action, &i18n)),
                "{message}"
            );
            assert!(message.contains("25"), "{message}");
            assert!(!message.contains(i18n.tr("common.unknown")), "{message}");
        }
        Ok(())
    }

    #[test]
    fn lost_ack_is_presented_as_ambiguous_and_forces_resync() {
        let error = transport::IpcError::Timeout(io::Error::new(
            io::ErrorKind::TimedOut,
            "response was lost after request write",
        ));
        let presentation = control_failure_presentation(&error, &I18n::test_english());

        assert!(presentation.request_resync);
        assert!(presentation.body.contains("may have been applied"));
        assert!(presentation.body.contains("Do not retry"));
        assert_eq!(presentation.title, " Result not confirmed ");
    }

    #[test]
    fn fatal_stderr_text_removes_terminal_and_bidi_controls() {
        assert_eq!(
            terminal_safe("safe\u{1b}[31m\u{202e}tail"),
            "safe [31m tail"
        );
    }

    #[test]
    fn russian_ack_message_names_the_completed_operation() -> Result<(), Box<dyn std::error::Error>>
    {
        let rule = Rule::new(RuleSpec::new(
            RuleName::new("Веб-сервер")?,
            Direction::Inbound,
            TransportProtocol::Tcp,
            Some("192.0.2.0/24".parse()?),
            None,
            None,
            RuleOrigin::Manual,
            true,
        )?)?;
        let ack = Ack::new(12, Some(rule));
        let i18n = I18n::load(Locale::Ru)?;

        assert_eq!(
            ack_message(&ack, ControlAction::CreateRule, &i18n),
            "Правило «Веб-сервер» успешно создано; ревизия политики 12"
        );
        assert_eq!(
            ack_message(&ack, ControlAction::DeleteRule, &i18n),
            "Правило «Веб-сервер» успешно удалено; ревизия политики 12"
        );
        Ok(())
    }
}
