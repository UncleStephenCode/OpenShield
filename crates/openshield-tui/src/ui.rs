use std::path::Path;
use std::time::{Duration, Instant};

use openshield_core::{
    CounterValue, Direction, Event, EventKind, Mode, Rule, RuleAction, RuleOrigin,
    TransportProtocol,
};
use openshield_protocol::{CompatibilityLevel, CompatibilityReason, OutboundGroupAction};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction as LayoutDirection, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Table, TableState, Tabs, Wrap,
    },
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::app::{
    App, CommandMode, ConnectionState, FormField, GROUP_ACTIONS, GroupTarget, OutboundGroupKey,
    Overlay, RuleForm, View, peer_label,
};
use crate::i18n::I18n;

const MAX_SINGLE_LINE_CHARS: usize = 1_024;
const MAX_MESSAGE_CHARS: usize = 4_096;
const COUNTERS_STALE_AFTER: Duration = Duration::from_secs(3);

pub fn draw(frame: &mut Frame<'_>, app: &App, observe_path: &Path, control_path: &Path) {
    let areas = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(frame.area());

    draw_tabs(frame, app, areas[0]);
    match app.view {
        View::Status => draw_status(frame, app, observe_path, control_path, areas[1]),
        View::Outbound => draw_outbound_rules(frame, app, areas[1]),
        View::Inbound => draw_inbound_rules(frame, app, areas[1]),
        View::Events => draw_events(frame, app, areas[1]),
        View::Help => draw_help(frame, app, areas[1]),
    }
    draw_footer(frame, app, areas[2]);
    draw_overlay(frame, app);
}

fn draw_tabs(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let titles = [
        View::Status,
        View::Outbound,
        View::Inbound,
        View::Events,
        View::Help,
    ]
    .into_iter()
    .map(|view| Line::from(view.title(&app.i18n)))
    .collect::<Vec<_>>();
    let selected = match app.view {
        View::Status => 0,
        View::Outbound => 1,
        View::Inbound => 2,
        View::Events => 3,
        View::Help => 4,
    };
    let tabs = Tabs::new(titles)
        .select(selected)
        .block(Block::default().borders(Borders::ALL).title(" OpenShield "))
        .highlight_style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .divider(" | ");
    frame.render_widget(tabs, area);
}

#[allow(clippy::too_many_lines)]
fn draw_status(
    frame: &mut Frame<'_>,
    app: &App,
    observe_path: &Path,
    control_path: &Path,
    area: Rect,
) {
    let i18n = &app.i18n;
    let now = Instant::now();
    let counters_age = app.counters_age(now);
    let connection = policy_health_span(&app.connection, i18n);
    let telemetry = telemetry_health_span(app, now, counters_age, i18n);
    let access = access_span(app.read_only, i18n);
    let backend = match app.backend {
        Some(openshield_protocol::FirewallBackendKind::Nftables) => "nftables",
        Some(openshield_protocol::FirewallBackendKind::Iptables) => "iptables/ip6tables",
        Some(openshield_protocol::FirewallBackendKind::Unknown) | None => i18n.tr("common.unknown"),
    };
    let (mode, revision, rule_count, inbound_count) = app.snapshot.as_ref().map_or_else(
        || (i18n.tr("common.unknown").to_owned(), 0, 0, 0),
        |snapshot| {
            (
                mode_label(snapshot.mode, i18n).to_owned(),
                snapshot.revision,
                snapshot.rules.len(),
                snapshot
                    .rules
                    .iter()
                    .filter(|rule| rule.spec.enabled && rule.spec.direction == Direction::Inbound)
                    .count(),
            )
        },
    );
    let mode_style = app
        .snapshot
        .as_ref()
        .map_or_else(Style::default, |snapshot| mode_style(snapshot.mode));
    let learning = app
        .snapshot
        .as_ref()
        .is_some_and(|snapshot| snapshot.mode == Mode::Learning);
    let revision = revision.to_string();
    let rule_count = rule_count.to_string();
    let inbound_count = inbound_count.to_string();
    let mut lines = vec![
        Line::from(vec![Span::raw(i18n.tr("status.policy")), connection]),
        Line::from(vec![
            Span::raw(i18n.tr("status.backend")),
            Span::styled(backend.to_owned(), Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::raw(i18n.tr("status.mode")),
            Span::styled(mode, mode_style.add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(
                i18n.tr("status.compatibility_level"),
                compatibility_reason_style(app.runtime_compatibility.reason),
            ),
            Span::styled(
                compatibility_level_label(app.runtime_compatibility.level, i18n),
                compatibility_level_style(
                    app.runtime_compatibility.level,
                    app.runtime_compatibility.reason,
                )
                .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled(
                i18n.tr("status.compatibility_reason"),
                compatibility_reason_style(app.runtime_compatibility.reason),
            ),
            Span::styled(
                compatibility_reason_label(app.runtime_compatibility.reason, i18n),
                compatibility_reason_style(app.runtime_compatibility.reason),
            ),
        ]),
    ];
    if learning {
        lines.push(Line::from(Span::styled(
            i18n.tr("status.learning_policy"),
            Style::default().fg(Color::Green),
        )));
    }
    // The compact 80x24 layout keeps the attested backend, mode, level and
    // reason ahead of all optional detail. The explanatory scope is omitted
    // there because it can wrap to several rows in translated interfaces.
    if area.height >= 24 {
        lines.push(Line::from(Span::styled(
            i18n.tr("status.compatibility_scope"),
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines.extend([
        Line::from(vec![Span::raw(i18n.tr("status.telemetry")), telemetry]),
        Line::from(vec![Span::raw(i18n.tr("status.access")), access]),
        Line::from(i18n.format("status.revision", &[("revision", revision.as_str())])),
        Line::from(i18n.format(
            "status.rule_counts",
            &[
                ("rules", rule_count.as_str()),
                ("inbound", inbound_count.as_str()),
            ],
        )),
        Line::from(""),
        Line::from(Span::styled(
            i18n.tr("status.inbound_policy"),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(""),
    ]);
    if let Some(counters) = &app.counters {
        let age = counters_age.map_or_else(
            || i18n.tr("status.age_unknown").to_owned(),
            |age| {
                let duration = duration_label(age, i18n);
                i18n.format("status.age", &[("duration", duration.as_str())])
            },
        );
        lines.push(Line::from(Span::styled(
            i18n.format("status.counters_title", &[("age", age.as_str())]),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.extend(counter_lines(
            &[
                (i18n.tr("status.counter_accepted_in"), counters.accepted_in),
                (
                    i18n.tr("status.counter_accepted_out"),
                    counters.accepted_out,
                ),
                (i18n.tr("status.counter_dropped_in"), counters.dropped_in),
                (i18n.tr("status.counter_dropped_out"), counters.dropped_out),
                (i18n.tr("status.counter_learned_out"), counters.learned_out),
            ],
            usize::from(area.width.saturating_sub(2)),
        ));
        lines.push(Line::from(""));
    } else {
        lines.push(Line::from(i18n.tr("status.counters_waiting")));
        lines.push(Line::from(""));
    }
    lines.extend([
        Line::from(i18n.format(
            "status.observe_socket",
            &[(
                "path",
                one_line(&observe_path.display().to_string()).as_str(),
            )],
        )),
        Line::from(i18n.format(
            "status.control_socket",
            &[(
                "path",
                one_line(&control_path.display().to_string()).as_str(),
            )],
        )),
    ]);
    let text = Text::from(lines);
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(i18n.tr("status.title")),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn policy_health_span(state: &ConnectionState, i18n: &I18n) -> Span<'static> {
    match state {
        ConnectionState::Connecting => Span::styled(
            i18n.tr("health.connecting").to_owned(),
            Style::default().fg(Color::Yellow),
        ),
        ConnectionState::Connected => Span::styled(
            i18n.tr("health.connected").to_owned(),
            Style::default().fg(Color::Green),
        ),
        ConnectionState::Disconnected(reason) => Span::styled(
            i18n.format(
                "health.disconnected",
                &[("reason", one_line(reason).as_str())],
            ),
            Style::default().fg(Color::Red),
        ),
    }
}

fn telemetry_health_span(
    app: &App,
    now: Instant,
    counters_age: Option<Duration>,
    i18n: &I18n,
) -> Span<'static> {
    match &app.telemetry {
        ConnectionState::Connecting => Span::styled(
            i18n.tr("health.connecting").to_owned(),
            Style::default().fg(Color::Yellow),
        ),
        ConnectionState::Connected => {
            let stale_age = counters_age.or_else(|| app.telemetry_connection_age(now));
            match stale_age {
                Some(age) if age >= COUNTERS_STALE_AFTER => Span::styled(
                    i18n.format(
                        "health.telemetry_stale",
                        &[("duration", duration_label(age, i18n).as_str())],
                    ),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Some(_) if counters_age.is_some() => Span::styled(
                    i18n.tr("health.connected").to_owned(),
                    Style::default().fg(Color::Green),
                ),
                _ => Span::styled(
                    i18n.tr("health.connected").to_owned(),
                    Style::default().fg(Color::Yellow),
                ),
            }
        }
        ConnectionState::Disconnected(reason) => Span::styled(
            i18n.format(
                "health.telemetry_disconnected",
                &[("reason", one_line(reason).as_str())],
            ),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    }
}

fn access_span(read_only: bool, i18n: &I18n) -> Span<'static> {
    if read_only {
        Span::styled(
            i18n.tr("access.read_only").to_owned(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            i18n.tr("access.privileged").to_owned(),
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    }
}

fn draw_outbound_rules(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let areas = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(area);
    let nodes = app.outbound_nodes();
    let selected_node = app.selected_outbound_node_index(&nodes);
    let group_rows = nodes
        .iter()
        .map(|node| {
            let active = node.rules.iter().filter(|rule| rule.spec.enabled).count();
            let state = if active == node.rules.len() {
                "●"
            } else if active == 0 {
                "○"
            } else {
                "◐"
            };
            let label = node.executable.map_or_else(
                || {
                    format!(
                        "{} {}",
                        group_kind_label(&node.key, i18n),
                        group_value_label(&node.key, i18n)
                    )
                },
                |path| {
                    format!(
                        "  {} {}",
                        if node.last_child { "└" } else { "├" },
                        one_line(path)
                    )
                },
            );
            Row::new([
                Cell::from(state),
                Cell::from(label),
                Cell::from(node.rules.len().to_string()),
            ])
        })
        .collect::<Vec<_>>();
    let group_header = styled_header([
        i18n.tr("rules.column_enabled"),
        i18n.tr("rules.column_group"),
        i18n.tr("rules.column_count"),
    ]);
    let group_table = Table::new(
        group_rows,
        [
            Constraint::Length(3),
            Constraint::Min(12),
            Constraint::Length(5),
        ],
    )
    .header(group_header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(i18n.tr("rules.outbound_groups_title")),
    )
    .row_highlight_style(selected_style())
    .highlight_symbol("▶ ");
    let mut group_state = TableState::default().with_selected(selected_node);
    frame.render_stateful_widget(group_table, areas[0], &mut group_state);

    let right = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(areas[1]);
    let members = selected_node.map_or(&[][..], |index| nodes[index].rules.as_slice());
    draw_rule_table(
        frame,
        members,
        (!members.is_empty()).then_some(app.selected_outbound_member_index()),
        i18n.tr("rules.outbound_members_title"),
        right[0],
        i18n,
        true,
    );
    let selected = members.get(app.selected_outbound_member_index()).copied();
    draw_rule_details(
        frame,
        app,
        selected,
        i18n.tr("rules.empty_outbound"),
        right[1],
    );
}

fn draw_inbound_rules(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let areas = Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);
    let rules = app.inbound_rules();
    draw_rule_table(
        frame,
        &rules,
        (!rules.is_empty()).then_some(app.selected_inbound_rule_index()),
        i18n.tr("rules.inbound_title"),
        areas[0],
        i18n,
        false,
    );
    draw_rule_details(
        frame,
        app,
        rules.get(app.selected_inbound_rule_index()).copied(),
        i18n.tr("rules.empty_inbound"),
        areas[1],
    );
}

fn draw_rule_table(
    frame: &mut Frame<'_>,
    rules: &[&Rule],
    selected: Option<usize>,
    title: &str,
    area: Rect,
    i18n: &I18n,
    show_action: bool,
) {
    let rows = rules
        .iter()
        .map(|rule| rule_row(rule, i18n, show_action))
        .collect::<Vec<_>>();
    let mut header = vec![i18n.tr("rules.column_enabled")];
    let mut widths = vec![Constraint::Length(4)];
    if show_action {
        header.push(i18n.tr("rule_action.label"));
        widths.push(Constraint::Length(9));
    }
    let peer_header = i18n.tr(if show_action {
        "editor.field_destination"
    } else {
        "editor.field_source"
    });
    header.extend([
        i18n.tr("rules.column_protocol"),
        peer_header,
        i18n.tr("rules.column_port"),
        i18n.tr("rules.column_interface"),
        i18n.tr("rules.column_name"),
    ]);
    widths.extend([
        Constraint::Length(7),
        Constraint::Min(15),
        Constraint::Length(11),
        Constraint::Length(12),
        Constraint::Min(14),
    ]);
    let header = Row::new(header).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title))
        .row_highlight_style(selected_style())
        .highlight_symbol("▶ ");
    let mut state = TableState::default().with_selected(selected);
    frame.render_stateful_widget(table, area, &mut state);
}

fn rule_row(rule: &Rule, i18n: &I18n, show_action: bool) -> Row<'static> {
    let style = if rule.spec.enabled {
        Style::default()
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let mut cells = vec![Cell::from(if rule.spec.enabled { "●" } else { "○" })];
    if show_action {
        cells.push(Cell::from(action_label(rule.spec.action, i18n).to_owned()));
    }
    cells.extend([
        Cell::from(protocol_label(rule.spec.protocol, i18n).to_owned()),
        Cell::from(peer_label(rule, i18n)),
        Cell::from(port_label(rule)),
        Cell::from(
            rule.spec
                .interface
                .as_ref()
                .map_or_else(|| "—".to_owned(), ToString::to_string),
        ),
        Cell::from(rule.spec.name.to_string()),
    ]);
    Row::new(cells).style(style)
}

fn draw_rule_details(
    frame: &mut Frame<'_>,
    app: &App,
    rule: Option<&Rule>,
    empty_message: &str,
    area: Rect,
) {
    let i18n = &app.i18n;
    let lines = rule.map_or_else(
        || vec![Line::from(empty_message.to_owned())],
        |rule| rule_detail_lines(rule, i18n),
    );
    let content_width = area.width.saturating_sub(2).max(1);
    let lines = hard_wrap_lines(lines, content_width);
    let content_height = lines.len();
    let visible_height = usize::from(area.height.saturating_sub(2));
    let maximum = content_height.saturating_sub(visible_height);
    let scroll = app.clamp_rule_details_scroll(maximum);
    let title = if maximum == 0 {
        i18n.tr("rules.details_rule_title").to_owned()
    } else {
        format!(
            "{} [{}/{}]",
            i18n.tr("rules.details_rule_title").trim(),
            usize::from(scroll).saturating_add(1),
            maximum.saturating_add(1)
        )
    };
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .scroll((scroll, 0)),
        area,
    );
}

#[allow(clippy::too_many_lines)]
fn rule_detail_lines(rule: &Rule, i18n: &I18n) -> Vec<Line<'static>> {
    let origin = match rule.spec.origin {
        RuleOrigin::Manual => i18n.tr("common.manual"),
        RuleOrigin::Learned => i18n.tr("common.learned"),
        RuleOrigin::Template => i18n.tr("common.template"),
    };
    let mut lines = vec![
        detail_line(i18n.tr("rules.details_uuid"), rule.id.to_string()),
        detail_line(i18n.tr("rules.details_name"), rule.spec.name.as_str()),
        detail_parts(&[
            (
                i18n.tr("rules.details_enabled"),
                i18n.tr(if rule.spec.enabled {
                    "common.yes"
                } else {
                    "common.no"
                }),
            ),
            (
                i18n.tr("rule_action.label"),
                action_label(rule.spec.action, i18n),
            ),
            (i18n.tr("rules.details_origin"), origin),
            (
                i18n.tr("rules.details_direction"),
                direction_label(rule.spec.direction, i18n),
            ),
        ]),
        detail_parts(&[
            (
                i18n.tr("rules.details_protocol"),
                protocol_label(rule.spec.protocol, i18n),
            ),
            (
                i18n.tr(if rule.spec.direction == Direction::Inbound {
                    "editor.field_source"
                } else {
                    "editor.field_destination"
                }),
                peer_label(rule, i18n).as_str(),
            ),
            (i18n.tr("rules.details_port"), port_label(rule).as_str()),
            (
                i18n.tr("rules.details_interface"),
                rule.spec
                    .interface
                    .as_ref()
                    .map_or(i18n.tr("common.any"), |interface| interface.as_str()),
            ),
        ]),
        detail_parts(&[
            (
                i18n.tr("rules.details_created"),
                rule.created_at.to_rfc3339().as_str(),
            ),
            (
                i18n.tr("rules.details_updated"),
                rule.updated_at.to_rfc3339().as_str(),
            ),
        ]),
    ];
    let Some(application) = &rule.spec.application else {
        lines.push(detail_line(
            i18n.tr("rules.column_application"),
            i18n.tr("rules.network_only"),
        ));
        return lines;
    };
    if application.metadata_redacted {
        lines.push(detail_line(
            i18n.tr("rules.details_metadata_redacted"),
            i18n.tr("common.yes"),
        ));
        return lines;
    }
    lines.push(detail_line(
        i18n.tr("rules.details_cgroup"),
        application
            .cgroup
            .as_ref()
            .map_or("—", |cgroup| cgroup.as_str()),
    ));
    lines.push(detail_line(
        i18n.tr("rules.details_executable"),
        application
            .executable
            .as_ref()
            .map_or("—", |executable| executable.as_str()),
    ));
    let file_identity = application.executable_file.map_or_else(
        || "—".to_owned(),
        |file| {
            let device = file.device.to_string();
            let inode = file.inode.to_string();
            let size = file.size.to_string();
            let ctime = format!("{}.{:09}", file.ctime_seconds, file.ctime_nanoseconds);
            i18n.format(
                "rules.details_file_id",
                &[
                    ("device", device.as_str()),
                    ("inode", inode.as_str()),
                    ("size", size.as_str()),
                    ("ctime", ctime.as_str()),
                ],
            )
        },
    );
    lines.push(detail_line(
        i18n.tr("rules.details_file_identity"),
        file_identity,
    ));
    let (command_mode, arguments) = application.command_line.as_ref().map_or_else(
        || (i18n.tr("editor.command_any").to_owned(), "—".to_owned()),
        |command| {
            let mode = match command.kind {
                openshield_core::CommandLineMatch::Exact => i18n.tr("editor.command_exact"),
                openshield_core::CommandLineMatch::Prefix => i18n.tr("editor.command_prefix"),
            };
            (
                mode.to_owned(),
                crate::app::command_arguments_json(&command.arguments),
            )
        },
    );
    lines.push(detail_parts(&[
        (i18n.tr("rules.details_command_mode"), command_mode.as_str()),
        (i18n.tr("rules.details_arguments"), arguments.as_str()),
    ]));
    let uid = application
        .uid
        .map_or_else(|| "—".to_owned(), |uid| uid.to_string());
    lines.push(detail_line(i18n.tr("rules.details_uid"), uid));
    lines
}

fn detail_line(label: &str, value: impl AsRef<str>) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{}: ", one_line(label)),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw(safe_rule_detail(value.as_ref())),
    ])
}

fn detail_parts(parts: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::with_capacity(parts.len().saturating_mul(3));
    for (index, (label, value)) in parts.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("; "));
        }
        spans.push(Span::styled(
            format!("{}: ", one_line(label)),
            Style::default().fg(Color::Cyan),
        ));
        spans.push(Span::raw(safe_rule_detail(value)));
    }
    Line::from(spans)
}

fn hard_wrap_lines(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let width = usize::from(width.max(1));
    let mut wrapped = Vec::new();
    for line in lines {
        let mut current_spans = Vec::new();
        let mut current_width = 0_usize;
        for span in line.spans {
            let style = span.style;
            let mut current_text = String::new();
            for character in span.content.chars() {
                let character_width = character.width().unwrap_or(0);
                if current_width > 0 && current_width.saturating_add(character_width) > width {
                    if !current_text.is_empty() {
                        current_spans.push(Span::styled(std::mem::take(&mut current_text), style));
                    }
                    wrapped.push(Line::from(std::mem::take(&mut current_spans)));
                    current_width = 0;
                }
                current_text.push(character);
                current_width = current_width.saturating_add(character_width);
            }
            if !current_text.is_empty() {
                current_spans.push(Span::styled(current_text, style));
            }
        }
        if current_spans.is_empty() {
            wrapped.push(Line::default());
        } else {
            wrapped.push(Line::from(current_spans));
        }
    }
    wrapped
}

fn group_kind_label(key: &OutboundGroupKey<'_>, i18n: &I18n) -> String {
    i18n.tr(match key {
        OutboundGroupKey::Cgroup(_) => "rules.group_cgroup",
        OutboundGroupKey::Executable(_) => "rules.group_executable",
        OutboundGroupKey::Destination(_) => "rules.group_destination",
    })
    .to_owned()
}

fn group_value_label(key: &OutboundGroupKey<'_>, i18n: &I18n) -> String {
    match key {
        OutboundGroupKey::Cgroup(value) | OutboundGroupKey::Executable(value) => value.to_string(),
        OutboundGroupKey::Destination(Some(value)) => value.to_string(),
        OutboundGroupKey::Destination(None) => i18n.tr("rules.group_any_destination").to_owned(),
    }
}

fn port_label(rule: &Rule) -> String {
    rule.spec.port.map_or_else(
        || "—".to_owned(),
        |range| {
            if range.start() == range.end() {
                range.start().to_string()
            } else {
                format!("{}-{}", range.start(), range.end())
            }
        },
    )
}

fn styled_header<const N: usize>(values: [&str; N]) -> Row<'_> {
    Row::new(values).style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )
}

fn selected_style() -> Style {
    Style::default()
        .bg(Color::DarkGray)
        .add_modifier(Modifier::BOLD)
}

fn draw_events(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let items = app
        .events
        .iter()
        .rev()
        .map(|event| ListItem::new(format_event(event, i18n)))
        .collect::<Vec<_>>();
    let title = if app.dropped_events == 0 {
        i18n.tr("events.title").to_owned()
    } else {
        let count = app.dropped_events.to_string();
        i18n.format("events.title_dropped", &[("count", count.as_str())])
    };
    frame.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(title)),
        area,
    );
}

fn draw_help(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let mut lines = vec![
        Line::from(i18n.tr("help.navigation")),
        Line::from(i18n.tr("help.next_tab")),
        Line::from(i18n.tr("help.select_rule")),
        Line::from(i18n.tr("help.quit")),
        Line::from(i18n.tr("help.open_help")),
        Line::from(""),
        Line::from(Span::styled(
            i18n.tr("help.control_title"),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(i18n.tr("help.select_mode")),
        Line::from(i18n.tr("help.rule_actions")),
        Line::from(i18n.tr("help.toggle_rule")),
        Line::from(""),
        Line::from(i18n.tr("help.editor")),
    ];
    if app.read_only {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            i18n.tr("help.unprivileged"),
            Style::default().fg(Color::Yellow),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(i18n.tr("help.title")),
            )
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let i18n = &app.i18n;
    let message = app.notice.as_deref().map_or_else(
        || match app.view {
            View::Status => i18n.tr("footer.status"),
            View::Outbound if app.read_only => i18n.tr("footer.rules_read_only"),
            View::Outbound => i18n.tr("footer.rules"),
            View::Inbound if app.read_only => i18n.tr("footer.inbound_read_only"),
            View::Inbound => i18n.tr("footer.inbound"),
            View::Events if matches!(app.telemetry, ConnectionState::Connected) => {
                i18n.tr("footer.events_live")
            }
            View::Events => i18n.tr("footer.events_offline"),
            View::Help => i18n.tr("footer.help"),
        },
        str::trim,
    );
    frame.render_widget(
        Paragraph::new(one_line(message))
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

fn draw_overlay(frame: &mut Frame<'_>, app: &App) {
    let i18n = &app.i18n;
    match &app.overlay {
        Overlay::None => {}
        Overlay::ModePicker { selected } => {
            let area = centered_rect(54, 11, frame.area());
            frame.render_widget(Clear, area);
            let modes = [Mode::BlockAll, Mode::Learning, Mode::Enforcing];
            let lines = modes.into_iter().enumerate().map(|(index, mode)| {
                let style = if mode == *selected {
                    mode_style(mode).add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(
                    format!("{}. {}", index + 1, mode_label(mode, i18n)),
                    style,
                ))
            });
            let text = Text::from(lines.collect::<Vec<_>>());
            frame.render_widget(
                Paragraph::new(text)
                    .block(
                        Block::default()
                            .borders(Borders::ALL)
                            .title(i18n.tr("overlay.mode_picker")),
                    )
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
        Overlay::ConfirmBlockAll => draw_confirmation(
            frame,
            i18n.tr("overlay.block_all_title"),
            i18n.tr("overlay.block_all_body"),
            Color::Red,
        ),
        Overlay::ConfirmDelete { name, .. } => draw_confirmation(
            frame,
            i18n.tr("overlay.delete_title"),
            &i18n.format("overlay.delete_body", &[("name", one_line(name).as_str())]),
            Color::Yellow,
        ),
        Overlay::GroupMenu { target, selected } => draw_group_menu(frame, target, *selected, i18n),
        Overlay::ConfirmGroup { target, action } => {
            let body = i18n.format(
                "group.confirm_body",
                &[
                    ("action", group_action_label(*action, i18n)),
                    ("group", group_dialog_label(target, frame.area()).as_str()),
                    ("count", target.count.to_string().as_str()),
                ],
            );
            let body = format!("{body}\n\n{}", i18n.tr("group.semantics"));
            draw_group_dialog(
                frame,
                i18n.tr("group.confirm_title"),
                Text::from(body),
                Color::Yellow,
            );
        }
        Overlay::Editor(form) => draw_editor(frame, form, i18n),
        Overlay::Message { title, body } => {
            let area = centered_rect(70, 9, frame.area());
            frame.render_widget(Clear, area);
            frame.render_widget(
                Paragraph::new(safe_multiline(body))
                    .block(Block::default().borders(Borders::ALL).title(title.as_str()))
                    .wrap(Wrap { trim: false }),
                area,
            );
        }
    }
}

pub fn group_action_label(action: OutboundGroupAction, i18n: &I18n) -> &str {
    i18n.tr(match action {
        OutboundGroupAction::Delete => "group.delete",
        OutboundGroupAction::Accept => "rule_action.accept",
        OutboundGroupAction::Reject => "rule_action.reject",
        OutboundGroupAction::Drop => "rule_action.drop",
        OutboundGroupAction::Disable => "group.disable",
        OutboundGroupAction::Enable => "group.enable",
    })
}

fn draw_group_menu(
    frame: &mut Frame<'_>,
    target: &GroupTarget,
    selected: OutboundGroupAction,
    i18n: &I18n,
) {
    let scope = i18n.format(
        "group.scope",
        &[
            ("group", group_dialog_label(target, frame.area()).as_str()),
            ("count", target.count.to_string().as_str()),
        ],
    );
    let mut text = Text::from(scope);
    text.push_line("");
    for (index, action) in GROUP_ACTIONS.into_iter().enumerate() {
        let marker = if action == selected { "▶" } else { " " };
        let style = if action == selected {
            selected_style()
        } else {
            Style::default()
        };
        text.push_line(Line::styled(
            format!(
                "{marker} {}. {}",
                index + 1,
                group_action_label(action, i18n)
            ),
            style,
        ));
    }
    text.push_line("");
    text.push_line(i18n.tr("group.hint").to_owned());
    text.push_line("");
    text.lines
        .extend(Text::from(i18n.tr("group.semantics").to_owned()).lines);
    draw_group_dialog(frame, i18n.tr("group.title"), text, Color::Cyan);
}

fn group_dialog_label(target: &GroupTarget, terminal: Rect) -> String {
    let area = centered_rect(90, 23, terminal);
    // A very long cgroup/path must not push actions and the broad-template
    // warning out of the dialog. Only the displayed label is abbreviated.
    clipped_counter_label(
        &one_line(&target.label),
        usize::from(area.width.saturating_sub(2)) * 2,
    )
}

fn draw_group_dialog(frame: &mut Frame<'_>, title: &str, text: Text<'static>, color: Color) {
    let area = centered_rect(90, 23, frame.area());
    let lines = hard_wrap_lines(text.lines, area.width.saturating_sub(2).max(1));
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(color))
                .title(title),
        ),
        area,
    );
}

#[allow(clippy::too_many_lines)]
fn draw_editor(frame: &mut Frame<'_>, form: &RuleForm, i18n: &I18n) {
    let area = centered_rect(86, 29, frame.area());
    frame.render_widget(Clear, area);
    let mut fields = vec![(
        FormField::Name,
        i18n.tr("editor.field_name"),
        form.name.clone(),
    )];
    if form.direction() == Direction::Outbound {
        fields.push((
            FormField::Action,
            i18n.tr("rule_action.label"),
            action_label(form.action, i18n).to_owned(),
        ));
    }
    fields.extend([
        (
            FormField::Protocol,
            i18n.tr("editor.field_protocol"),
            protocol_label(form.protocol, i18n).to_owned(),
        ),
        (
            FormField::PeerNetwork,
            i18n.tr(if form.direction() == Direction::Inbound {
                "editor.field_source"
            } else {
                "editor.field_destination"
            }),
            form.peer_network.clone(),
        ),
        (
            FormField::Port,
            i18n.tr("editor.field_port"),
            form.port.clone(),
        ),
        (
            FormField::Interface,
            i18n.tr("editor.field_interface"),
            form.interface.clone(),
        ),
    ]);
    if form.direction() == Direction::Outbound {
        fields.extend([
            (
                FormField::Application,
                i18n.tr("editor.field_application"),
                if form.bind_application {
                    i18n.tr("common.yes")
                } else {
                    i18n.tr("common.no")
                }
                .to_owned(),
            ),
            (
                FormField::Executable,
                i18n.tr("editor.field_executable"),
                form.executable.clone(),
            ),
            (
                FormField::CommandMode,
                i18n.tr("editor.field_command_mode"),
                command_mode_label(form.command_mode, i18n).to_owned(),
            ),
            (
                FormField::Arguments,
                i18n.tr("editor.field_arguments"),
                form.arguments.clone(),
            ),
            (
                FormField::Uid,
                i18n.tr("editor.field_uid"),
                form.uid.clone(),
            ),
            (
                FormField::Cgroup,
                i18n.tr("editor.field_cgroup"),
                form.cgroup.clone(),
            ),
        ]);
    }
    fields.push((
        FormField::Enabled,
        i18n.tr("editor.field_enabled"),
        if form.enabled {
            i18n.tr("common.yes")
        } else {
            i18n.tr("common.no")
        }
        .to_owned(),
    ));
    let mut lines = Vec::with_capacity(fields.len() + 6);
    lines.push(Line::from(vec![
        Span::raw(format!("{:>20}: ", i18n.tr("editor.field_origin"))),
        Span::styled(
            match form.origin {
                RuleOrigin::Manual => i18n.tr("common.manual"),
                RuleOrigin::Learned => i18n.tr("common.learned_immutable"),
                RuleOrigin::Template => i18n.tr("common.template"),
            },
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw(format!("{:>20}: ", i18n.tr("editor.field_direction"))),
        Span::styled(
            direction_label(form.direction(), i18n),
            Style::default().fg(Color::DarkGray),
        ),
    ]));
    let value_width = usize::from(area.width.saturating_sub(25).max(4));
    let mut focus_line = 0;
    for (field, label, value) in fields {
        let is_active = form.active_field == field;
        let style = if is_active {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{label:>20}: "), style),
            Span::styled(
                if value.is_empty() {
                    "—".to_owned()
                } else {
                    editor_value(&value, is_active, value_width)
                },
                style,
            ),
        ]));
        if is_active {
            focus_line = lines.len().saturating_sub(1);
            if let Some(error) = &form.error {
                lines.push(Line::from(Span::styled(
                    safe_rule_detail(error),
                    Style::default().fg(Color::Red),
                )));
                focus_line = lines.len().saturating_sub(1);
            }
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        i18n.tr(if form.direction() == Direction::Inbound {
            "editor.inbound_help"
        } else {
            "editor.outbound_help"
        }),
        Style::default().fg(Color::DarkGray),
    )));
    if form.direction() == Direction::Outbound {
        lines.push(Line::from(Span::styled(
            i18n.tr("editor.application_help"),
            Style::default().fg(Color::DarkGray),
        )));
    }
    let visible_height = usize::from(area.height.saturating_sub(2));
    let scroll = focus_line.saturating_add(1).saturating_sub(visible_height);
    let scroll = u16::try_from(scroll).unwrap_or(u16::MAX);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if form.id.is_some() {
                        i18n.tr("editor.edit_title")
                    } else if form.direction() == Direction::Inbound {
                        i18n.tr("editor.new_inbound_title")
                    } else {
                        i18n.tr("editor.new_outbound_title")
                    }),
            )
            .scroll((scroll, 0)),
        area,
    );
}

fn editor_value(value: &str, show_tail: bool, maximum_chars: usize) -> String {
    let value = safe_rule_detail(value);
    if !show_tail || value.width() <= maximum_chars {
        return value;
    }
    let tail_width = maximum_chars.saturating_sub(1);
    let mut used_width = 0_usize;
    let mut tail = Vec::new();
    for character in value.chars().rev() {
        let character_width = character.width().unwrap_or(0);
        if used_width.saturating_add(character_width) > tail_width {
            break;
        }
        used_width = used_width.saturating_add(character_width);
        tail.push(character);
    }
    tail.reverse();
    format!("…{}", tail.into_iter().collect::<String>())
}

fn draw_confirmation(frame: &mut Frame<'_>, title: &str, body: &str, color: Color) {
    let area = centered_rect(68, 8, frame.area());
    frame.render_widget(Clear, area);
    frame.render_widget(
        Paragraph::new(body)
            .alignment(Alignment::Center)
            .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn centered_rect(width_percent: u16, height: u16, area: Rect) -> Rect {
    let vertical_margin = area.height.saturating_sub(height) / 2;
    let vertical = Layout::default()
        .direction(LayoutDirection::Vertical)
        .constraints([
            Constraint::Length(vertical_margin),
            Constraint::Min(height.min(area.height)),
            Constraint::Length(vertical_margin),
        ])
        .split(area);
    let horizontal_margin = 100_u16.saturating_sub(width_percent) / 2;
    Layout::default()
        .direction(LayoutDirection::Horizontal)
        .constraints([
            Constraint::Percentage(horizontal_margin),
            Constraint::Percentage(width_percent),
            Constraint::Percentage(horizontal_margin),
        ])
        .split(vertical[1])[1]
}

fn format_event(event: &Event, i18n: &I18n) -> Line<'static> {
    let timestamp = event.occurred_at.format("%H:%M:%S");
    let (text, color) = match &event.kind {
        EventKind::ModeChanged { previous, current } => (
            i18n.format(
                "event.mode_changed",
                &[
                    ("previous", mode_label(*previous, i18n)),
                    ("current", mode_label(*current, i18n)),
                ],
            ),
            mode_color(*current),
        ),
        EventKind::RuleCreated { rule } => (
            i18n.format("event.rule_created", &[("rule", rule.spec.name.as_str())]),
            Color::Green,
        ),
        EventKind::RuleUpdated { rule } => (
            i18n.format("event.rule_updated", &[("rule", rule.spec.name.as_str())]),
            Color::Cyan,
        ),
        EventKind::RuleDeleted { rule } => (
            i18n.format("event.rule_deleted", &[("rule", rule.spec.name.as_str())]),
            Color::Yellow,
        ),
        EventKind::RuleEnabledChanged { rule } => (
            i18n.format(
                "event.rule_enabled",
                &[
                    ("rule", rule.spec.name.as_str()),
                    (
                        "state",
                        if rule.spec.enabled {
                            i18n.tr("event.enabled")
                        } else {
                            i18n.tr("event.disabled")
                        },
                    ),
                ],
            ),
            Color::Cyan,
        ),
        EventKind::CountersUpdated { counters } => {
            (format_counters_event(counters, i18n), Color::DarkGray)
        }
    };
    Line::from(vec![
        Span::styled(
            format!("{timestamp} r{} ", event.revision),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(text, Style::default().fg(color)),
    ])
}

fn format_counters_event(counters: &openshield_core::FirewallCounters, i18n: &I18n) -> String {
    let accepted_in_packets = counters.accepted_in.packets.to_string();
    let accepted_in_bytes = counters.accepted_in.bytes.to_string();
    let dropped_in_packets = counters.dropped_in.packets.to_string();
    let dropped_in_bytes = counters.dropped_in.bytes.to_string();
    let accepted_out_packets = counters.accepted_out.packets.to_string();
    let accepted_out_bytes = counters.accepted_out.bytes.to_string();
    let dropped_out_packets = counters.dropped_out.packets.to_string();
    let dropped_out_bytes = counters.dropped_out.bytes.to_string();
    let learned_packets = counters.learned_out.packets.to_string();
    let learned_bytes = counters.learned_out.bytes.to_string();
    i18n.format(
        "event.counters",
        &[
            ("accepted_in_packets", accepted_in_packets.as_str()),
            ("accepted_in_bytes", accepted_in_bytes.as_str()),
            ("dropped_in_packets", dropped_in_packets.as_str()),
            ("dropped_in_bytes", dropped_in_bytes.as_str()),
            ("accepted_out_packets", accepted_out_packets.as_str()),
            ("accepted_out_bytes", accepted_out_bytes.as_str()),
            ("dropped_out_packets", dropped_out_packets.as_str()),
            ("dropped_out_bytes", dropped_out_bytes.as_str()),
            ("learned_packets", learned_packets.as_str()),
            ("learned_bytes", learned_bytes.as_str()),
        ],
    )
}

pub fn mode_label(mode: Mode, i18n: &I18n) -> &str {
    match mode {
        Mode::BlockAll => i18n.tr("mode.block_all"),
        Mode::Learning => i18n.tr("mode.learning"),
        Mode::Enforcing => i18n.tr("mode.enforcing"),
    }
}

fn compatibility_level_label(level: CompatibilityLevel, i18n: &I18n) -> &str {
    match level {
        CompatibilityLevel::Unknown => i18n.tr("compatibility.level_unknown"),
        CompatibilityLevel::KernelNative => i18n.tr("compatibility.level_kernel_native"),
        CompatibilityLevel::ConntrackHybrid => i18n.tr("compatibility.level_conntrack_hybrid"),
        CompatibilityLevel::Nfqueue => i18n.tr("compatibility.level_nfqueue"),
    }
}

fn compatibility_reason_label(reason: CompatibilityReason, i18n: &I18n) -> &str {
    match reason {
        CompatibilityReason::Unknown => i18n.tr("compatibility.reason_unknown"),
        CompatibilityReason::BlockAll => i18n.tr("compatibility.reason_block_all"),
        CompatibilityReason::EmergencyBlockAll => {
            i18n.tr("compatibility.reason_emergency_block_all")
        }
        CompatibilityReason::NetworkOnly => i18n.tr("compatibility.reason_network_only"),
        CompatibilityReason::Learning => i18n.tr("compatibility.reason_learning"),
        CompatibilityReason::ApplicationTcp => i18n.tr("compatibility.reason_application_tcp"),
        CompatibilityReason::ApplicationPerPacket => {
            i18n.tr("compatibility.reason_application_per_packet")
        }
    }
}

const fn compatibility_level_style(
    level: CompatibilityLevel,
    reason: CompatibilityReason,
) -> Style {
    let color = if matches!(reason, CompatibilityReason::EmergencyBlockAll) {
        Color::Red
    } else {
        match level {
            CompatibilityLevel::Unknown => Color::DarkGray,
            CompatibilityLevel::KernelNative => Color::Green,
            CompatibilityLevel::ConntrackHybrid => Color::Yellow,
            CompatibilityLevel::Nfqueue => Color::Cyan,
        }
    };
    Style::new().fg(color)
}

fn compatibility_reason_style(reason: CompatibilityReason) -> Style {
    if matches!(reason, CompatibilityReason::EmergencyBlockAll) {
        Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    }
}

const fn mode_style(mode: Mode) -> Style {
    Style::new().fg(mode_color(mode))
}

const fn mode_color(mode: Mode) -> Color {
    match mode {
        Mode::BlockAll => Color::Red,
        Mode::Learning => Color::Yellow,
        Mode::Enforcing => Color::Green,
    }
}

pub fn direction_label(direction: Direction, i18n: &I18n) -> &str {
    match direction {
        Direction::Inbound => i18n.tr("direction.inbound"),
        Direction::Outbound => i18n.tr("direction.outbound"),
    }
}

pub fn protocol_label(protocol: TransportProtocol, i18n: &I18n) -> &str {
    match protocol {
        TransportProtocol::Any => i18n.tr("common.any"),
        TransportProtocol::Tcp => "TCP",
        TransportProtocol::Udp => "UDP",
        TransportProtocol::Icmp => "ICMP",
        TransportProtocol::IcmpV6 => "ICMPv6",
    }
}

fn action_label(action: RuleAction, i18n: &I18n) -> &str {
    match action {
        RuleAction::Accept => i18n.tr("rule_action.accept"),
        RuleAction::Drop => i18n.tr("rule_action.drop"),
        RuleAction::Reject => i18n.tr("rule_action.reject"),
    }
}

fn command_mode_label(mode: CommandMode, i18n: &I18n) -> &str {
    match mode {
        CommandMode::Any => i18n.tr("editor.command_any"),
        CommandMode::Exact => i18n.tr("editor.command_exact"),
        CommandMode::Prefix => i18n.tr("editor.command_prefix"),
    }
}

fn duration_label(duration: Duration, i18n: &I18n) -> String {
    let seconds = duration.as_secs();
    if seconds == 0 {
        i18n.tr("duration.subsecond").to_owned()
    } else if seconds < 60 {
        let value = seconds.to_string();
        i18n.format("duration.seconds", &[("value", value.as_str())])
    } else if seconds < 3_600 {
        let value = (seconds / 60).to_string();
        i18n.format("duration.minutes", &[("value", value.as_str())])
    } else {
        let value = (seconds / 3_600).to_string();
        i18n.format("duration.hours", &[("value", value.as_str())])
    }
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .take(MAX_SINGLE_LINE_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Rule fields are already bounded by the core model, so preserve the whole
/// value for the scrollable details pane while neutralizing terminal-control
/// and bidirectional-format characters defensively.
fn safe_rule_detail(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if crate::i18n::is_unsafe_dynamic_character(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn safe_multiline(value: &str) -> String {
    value
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .map(|character| match character {
            '\n' => '\n',
            character if character.is_control() => ' ',
            character => character,
        })
        .collect()
}

fn counter_lines(rows: &[(&str, CounterValue)], width: usize) -> Vec<Line<'static>> {
    let rows = rows
        .iter()
        .map(|(label, value)| (*label, value.packets.to_string(), value.bytes.to_string()))
        .collect::<Vec<_>>();
    let label_width = rows
        .iter()
        .map(|(label, _, _)| label.width())
        .max()
        .unwrap_or(0);
    let packet_width = rows
        .iter()
        .map(|(_, packets, _)| packets.len())
        .max()
        .unwrap_or(0);
    let byte_width = rows
        .iter()
        .map(|(_, _, bytes)| bytes.len())
        .max()
        .unwrap_or(0);

    // Reserve the indentation, column gap and separator. Prefer complete
    // numbers, while retaining enough of a clipped label to identify its row.
    let available = width.saturating_sub(6);
    let numeric_space = available.saturating_sub(label_width.min(8));
    let packet_space = packet_width.min(numeric_space / 2);
    let byte_space = byte_width.min(numeric_space - packet_space);
    let packet_space = packet_width.min(numeric_space - byte_space);
    let label_space = label_width.min(available - packet_space - byte_space);
    let spare = available - label_space - packet_space - byte_space;
    let packet_padding = 12_usize.saturating_sub(packet_space).min(spare);
    let packet_space = packet_space + packet_padding;
    let byte_space = byte_space
        + 16_usize
            .saturating_sub(byte_space)
            .min(spare - packet_padding);

    rows.into_iter()
        .map(|(label, packets, bytes)| {
            let label = clipped_counter_label(label, label_space);
            let padding = " ".repeat(label_space.saturating_sub(label.width()));
            // Never present a partial integer as though it were the full count.
            let packets = if packets.len() <= packet_space {
                packets.as_str()
            } else if packet_space == 0 {
                ""
            } else {
                "…"
            };
            let bytes = if bytes.len() <= byte_space {
                bytes.as_str()
            } else if byte_space == 0 {
                ""
            } else {
                "…"
            };
            let line =
                format!("  {label}{padding} {packets:>packet_space$} / {bytes:>byte_space$}");
            Line::from(clipped_counter_label(&line, width))
        })
        .collect()
}

fn clipped_counter_label(label: &str, width: usize) -> String {
    if label.width() <= width {
        return label.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let end = label
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|&index| label[..index].width() < width)
        .last()
        .unwrap_or(0);
    format!("{}…", &label[..end])
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use openshield_core::{ExecutableFileId, Snapshot};
    use openshield_protocol::{
        CompatibilityLevel, CompatibilityReason, FirewallBackendKind, RuntimeCompatibility,
    };
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::i18n::Locale;

    #[test]
    fn counter_columns_align_in_every_locale() -> Result<(), Box<dyn std::error::Error>> {
        for &locale in Locale::SUPPORTED {
            let i18n = I18n::load(locale)?;
            let rows = [
                "status.counter_accepted_in",
                "status.counter_accepted_out",
                "status.counter_dropped_in",
                "status.counter_dropped_out",
                "status.counter_learned_out",
            ]
            .map(|key| {
                (
                    i18n.tr(key),
                    CounterValue {
                        packets: 123,
                        bytes: 456,
                    },
                )
            });
            let lines = counter_lines(&rows, 118);
            let mut terminal = Terminal::new(TestBackend::new(118, 5))?;
            terminal.draw(|frame| {
                frame.render_widget(Paragraph::new(lines.clone()), frame.area());
            })?;
            let buffer = terminal.backend().buffer();
            let expected = (0..118)
                .filter(|&x| matches!(buffer[(x, 0)].symbol(), "1" | "/" | "4"))
                .collect::<Vec<_>>();
            assert_eq!(expected.len(), 3, "locale {locale}");
            for y in 1..5 {
                let actual = (0..118)
                    .filter(|&x| matches!(buffer[(x, y)].symbol(), "1" | "/" | "4"))
                    .collect::<Vec<_>>();
                assert_eq!(actual, expected, "locale {locale}, row {y}");
            }
            for ((label, _), line) in rows.iter().zip(&lines) {
                assert!(line.to_string().contains(*label), "locale {locale}: {line}");
            }
        }
        Ok(())
    }

    #[test]
    fn counter_columns_share_width_for_large_values_and_unicode_labels()
    -> Result<(), Box<dyn std::error::Error>> {
        let rows = [
            (
                "in",
                CounterValue {
                    packets: 1,
                    bytes: 2,
                },
            ),
            (
                "принято исходящих",
                CounterValue {
                    packets: u64::MAX,
                    bytes: 3,
                },
            ),
            (
                "已丢弃入站",
                CounterValue {
                    packets: 4,
                    bytes: u64::MAX,
                },
            ),
            (
                "e\u{301}",
                CounterValue {
                    packets: 5,
                    bytes: 6,
                },
            ),
        ];
        let lines = counter_lines(&rows, 118);
        let mut separator_columns = Vec::new();
        let mut byte_ends = Vec::new();
        for ((label, value), line) in rows.iter().zip(&lines) {
            let text = line.to_string();
            let (packets, bytes) = text.split_once(" / ").ok_or("missing counter separator")?;
            assert!(text.contains(*label), "{text}");
            assert!(packets.ends_with(&value.packets.to_string()), "{text}");
            assert_eq!(bytes.trim(), value.bytes.to_string());
            separator_columns.push(packets.width());
            byte_ends.push(text.width());
        }
        assert!(separator_columns.windows(2).all(|pair| pair[0] == pair[1]));
        assert!(byte_ends.windows(2).all(|pair| pair[0] == pair[1]));
        Ok(())
    }

    #[test]
    fn narrow_counter_rows_fit_without_wrapping_or_partial_numbers()
    -> Result<(), Box<dyn std::error::Error>> {
        let rows = [
            (
                "принято входящих",
                CounterValue {
                    packets: 7,
                    bytes: 8,
                },
            ),
            (
                "принято исходящих",
                CounterValue {
                    packets: 9,
                    bytes: u64::MAX,
                },
            ),
            (
                "заблокировано входящих",
                CounterValue {
                    packets: u64::MAX,
                    bytes: 0,
                },
            ),
            (
                "已丢弃出站",
                CounterValue {
                    packets: 1,
                    bytes: 2,
                },
            ),
            (
                "e\u{301} learned outbound",
                CounterValue {
                    packets: 3,
                    bytes: 4,
                },
            ),
        ];
        assert!(counter_lines(&rows, 0).iter().all(|line| line.width() == 0));
        for width in [1_u16, 5, 10, 20, 38, 60, 80] {
            let mut lines = counter_lines(&rows, usize::from(width));
            for line in &lines {
                assert!(line.width() <= usize::from(width), "width {width}: {line}");
                let text = line.to_string();
                if let Some((label_and_packets, bytes)) = text.split_once(" / ") {
                    let packet = label_and_packets
                        .rsplit_once(' ')
                        .map_or("", |(_, number)| number);
                    for number in [packet, bytes.trim()] {
                        assert!(
                            number.len() <= 1 || number == "…" || number == u64::MAX.to_string(),
                            "partial number at width {width}: {text}"
                        );
                    }
                }
            }
            lines.push(Line::from("X"));
            let mut terminal = Terminal::new(TestBackend::new(width, 6))?;
            terminal.draw(|frame| {
                frame.render_widget(
                    Paragraph::new(lines.clone()).wrap(Wrap { trim: false }),
                    frame.area(),
                );
            })?;
            assert_eq!(
                terminal.backend().buffer()[(0, 5)].symbol(),
                "X",
                "width {width}"
            );
        }
        Ok(())
    }

    #[test]
    fn status_renders_verified_backend_instead_of_subscription_wording()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = App::new(true, I18n::test_english());
        app.set_observed_snapshot(
            Snapshot {
                revision: 4,
                flow_generation: 1,
                mode: Mode::Learning,
                rules: Vec::new(),
            },
            FirewallBackendKind::Nftables,
            RuntimeCompatibility {
                level: CompatibilityLevel::ConntrackHybrid,
                reason: CompatibilityReason::ApplicationTcp,
            },
        );
        app.connection = ConnectionState::Connected;
        app.set_telemetry_connected();
        let mut terminal = Terminal::new(TestBackend::new(110, 32))?;
        terminal.draw(|frame| {
            draw(
                frame,
                &app,
                Path::new("/run/openshield/observe.sock"),
                Path::new("/run/openshield/control.sock"),
            );
        })?;
        let screen = buffer_text(terminal.backend());
        assert!(screen.contains("Firewall backend: nftables"), "{screen}");
        assert!(
            screen.contains("Active policy path: L2 — conntrack/NFQUEUE hybrid"),
            "{screen}"
        );
        assert!(
            screen.contains("Selection reason: application-bound TCP attributes new flows"),
            "{screen}"
        );
        assert!(
            screen.contains("network-only packets always stay in the kernel"),
            "{screen}"
        );
        assert!(
            screen.contains("Learning allows outbound traffic by default"),
            "{screen}"
        );
        assert!(screen.contains("enabled Drop and Reject"), "{screen}");
        assert!(!screen.contains("Compatibility level:"), "{screen}");
        assert!(!screen.to_ascii_lowercase().contains("ebpf"), "{screen}");
        assert!(!screen.to_ascii_lowercase().contains("subscription"));
        Ok(())
    }

    #[test]
    fn group_dialogs_show_actions_scope_and_template_warning_in_every_locale()
    -> Result<(), Box<dyn std::error::Error>> {
        let target = GroupTarget {
            selector: openshield_protocol::OutboundGroupSelector::Destination {
                peer_network: None,
            },
            label: format!("/system.slice/{}.service", "long-name-".repeat(100)),
            count: 321,
        };
        let compact = |text: &str| {
            text.chars()
                .filter(|ch| !ch.is_whitespace() && *ch != '│')
                .collect::<String>()
        };
        for &locale in Locale::SUPPORTED {
            let mut app = App::new(false, I18n::load(locale)?);
            for (width, height) in [(80, 24), (120, 30)] {
                let mut terminal = Terminal::new(TestBackend::new(width, height))?;
                for confirmation in [false, true] {
                    app.overlay = if confirmation {
                        Overlay::ConfirmGroup {
                            target: target.clone(),
                            action: OutboundGroupAction::Enable,
                        }
                    } else {
                        Overlay::GroupMenu {
                            target: target.clone(),
                            selected: OutboundGroupAction::Enable,
                        }
                    };
                    terminal.draw(|frame| draw_overlay(frame, &app))?;
                    let screen = buffer_text(terminal.backend());
                    assert!(screen.contains("321"), "{locale}: {screen}");
                    assert!(screen.contains('…'), "{locale}: {screen}");
                    assert!(
                        compact(&screen).contains(&compact(app.i18n.tr("group.semantics"))),
                        "warning hidden in {locale} at {width}x{height}: {screen}"
                    );
                    if !confirmation {
                        for action in GROUP_ACTIONS {
                            assert!(
                                compact(&screen)
                                    .contains(&compact(group_action_label(action, &app.i18n))),
                                "action hidden in {locale}: {screen}"
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }

    #[test]
    fn emergency_quarantine_renders_level_and_reason_in_red()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut app = App::new(true, I18n::test_english());
        app.set_observed_snapshot(
            Snapshot {
                revision: 9,
                flow_generation: 1,
                mode: Mode::BlockAll,
                rules: Vec::new(),
            },
            FirewallBackendKind::Nftables,
            RuntimeCompatibility {
                level: CompatibilityLevel::KernelNative,
                reason: CompatibilityReason::EmergencyBlockAll,
            },
        );
        app.connection = ConnectionState::Connected;
        let mut terminal = Terminal::new(TestBackend::new(110, 32))?;
        terminal.draw(|frame| {
            draw(
                frame,
                &app,
                Path::new("/run/openshield/observe.sock"),
                Path::new("/run/openshield/control.sock"),
            );
        })?;

        let red_text = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .filter(|cell| cell.fg == Color::Red)
            .map(ratatui::buffer::Cell::symbol)
            .collect::<String>();
        assert!(red_text.contains("L3 — kernel native"), "{red_text}");
        assert!(red_text.contains("Active policy path:"), "{red_text}");
        assert!(red_text.contains("Selection reason:"), "{red_text}");
        assert!(
            red_text.contains("emergency fail-closed quarantine is active"),
            "{red_text}"
        );
        Ok(())
    }

    #[test]
    fn compact_status_keeps_runtime_evidence_visible_in_every_locale()
    -> Result<(), Box<dyn std::error::Error>> {
        for &locale in Locale::SUPPORTED {
            let i18n = I18n::load(locale)?;
            let expected_mode = i18n.tr("mode.enforcing").to_owned();
            let expected_level = i18n.tr("compatibility.level_kernel_native").to_owned();
            let reason_prefix = i18n
                .tr("compatibility.reason_network_only")
                .chars()
                .take(12)
                .collect::<String>();
            let scope = i18n.tr("status.compatibility_scope").to_owned();
            let mut app = App::new(true, i18n);
            app.set_observed_snapshot(
                Snapshot {
                    revision: 7,
                    flow_generation: 1,
                    mode: Mode::Enforcing,
                    rules: Vec::new(),
                },
                FirewallBackendKind::Nftables,
                RuntimeCompatibility {
                    level: CompatibilityLevel::KernelNative,
                    reason: CompatibilityReason::NetworkOnly,
                },
            );
            app.connection = ConnectionState::Connected;
            app.set_telemetry_connected();

            let mut terminal = Terminal::new(TestBackend::new(80, 24))?;
            terminal.draw(|frame| {
                draw(
                    frame,
                    &app,
                    Path::new("/run/openshield/observe.sock"),
                    Path::new("/run/openshield/control.sock"),
                );
            })?;
            let screen = buffer_text(terminal.backend());
            let compact = |value: &str| {
                value
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect::<String>()
            };
            let compact_screen = compact(&screen);
            for expected in [
                "nftables",
                expected_mode.as_str(),
                expected_level.as_str(),
                app.i18n.tr("status.compatibility_reason"),
                reason_prefix.as_str(),
            ] {
                let compact_expected = compact(expected);
                assert!(
                    compact_screen.contains(&compact_expected),
                    "missing {expected:?} in {} compact status: {screen}",
                    locale.code(),
                );
            }
            assert!(
                !compact_screen.contains(&compact(&scope)),
                "scope must be omitted from {} compact status: {screen}",
                locale.code(),
            );
        }
        Ok(())
    }

    #[test]
    fn outbound_and_inbound_views_render_grouping_and_complete_selectors()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut outbound_form = RuleForm::default();
        outbound_form.name = "package updater".to_owned();
        outbound_form.action = RuleAction::Reject;
        outbound_form.protocol = TransportProtocol::Tcp;
        outbound_form.peer_network = "203.0.113.0/24".to_owned();
        outbound_form.port = "443".to_owned();
        outbound_form.interface = "eth0".to_owned();
        outbound_form.bind_application = true;
        outbound_form.executable = "/usr/bin/updater".to_owned();
        outbound_form.command_mode = CommandMode::Exact;
        outbound_form.arguments = r#"["updater","--channel=stable"]"#.to_owned();
        outbound_form.uid = "1000".to_owned();
        outbound_form.cgroup = "/system.slice/updater.service".to_owned();
        let mut outbound_spec = outbound_form
            .to_rule_spec(&I18n::test_english())
            .map_err(std::io::Error::other)?;
        outbound_spec
            .application
            .as_mut()
            .ok_or("missing application selector")?
            .executable_file = Some(ExecutableFileId {
            device: 8,
            inode: 42,
            size: 12_345,
            ctime_seconds: 1_700_000_000,
            ctime_nanoseconds: 123,
        });
        outbound_spec.validate()?;
        let outbound = Rule::new(outbound_spec)?;
        let mut inbound_form = RuleForm::for_direction(Direction::Inbound);
        inbound_form.name = "https ingress".to_owned();
        inbound_form.protocol = TransportProtocol::Tcp;
        inbound_form.peer_network = "198.51.100.0/24".to_owned();
        inbound_form.port = "8443".to_owned();
        inbound_form.interface = "ens3".to_owned();
        let inbound = Rule::new(
            inbound_form
                .to_rule_spec(&I18n::test_english())
                .map_err(std::io::Error::other)?,
        )?;
        let mut app = App::new(false, I18n::test_english());
        app.set_snapshot(Snapshot {
            revision: 2,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![inbound, outbound],
        });
        app.view = View::Outbound;
        let mut terminal = Terminal::new(TestBackend::new(180, 45))?;
        terminal.draw(|frame| {
            draw(frame, &app, Path::new("/observe"), Path::new("/control"));
        })?;
        let outbound_screen = buffer_text(terminal.backend());
        for expected in [
            "/system.slice/updater.service",
            "203.0.113.0/24",
            "443",
            "/usr/bin/updater",
            "--channel=stable",
            "12345 B",
            "1000",
            "Reject",
        ] {
            assert!(
                outbound_screen.contains(expected),
                "missing {expected}: {outbound_screen}"
            );
        }

        app.view = View::Inbound;
        terminal.draw(|frame| {
            draw(frame, &app, Path::new("/observe"), Path::new("/control"));
        })?;
        let inbound_screen = buffer_text(terminal.backend());
        for expected in ["https ingress", "198.51.100.0/24", "8443", "ens3"] {
            assert!(
                inbound_screen.contains(expected),
                "missing {expected}: {inbound_screen}"
            );
        }
        assert!(!inbound_screen.contains("/usr/bin/updater"));
        Ok(())
    }

    #[test]
    #[allow(clippy::too_many_lines)] // Exercise root and both children in two locales.
    fn outbound_tree_renders_branches_and_filters_both_right_panes()
    -> Result<(), Box<dyn std::error::Error>> {
        for locale in [Locale::En, Locale::Ru] {
            let mut rules = Vec::new();
            for (path, peer, name) in [
                (
                    "/usr/libexec/nm-daemon-helper",
                    "203.0.113.11",
                    "helper-one",
                ),
                (
                    "/usr/libexec/nm-daemon-helper",
                    "203.0.113.12",
                    "helper-two",
                ),
                ("/usr/sbin/NetworkManager", "198.51.100.9", "manager-only"),
            ] {
                let mut form = RuleForm::default();
                form.name = name.to_owned();
                form.protocol = TransportProtocol::Tcp;
                form.port = "443".to_owned();
                form.peer_network = peer.to_owned();
                form.bind_application = true;
                form.executable = path.to_owned();
                form.cgroup = "/system.slice/NetworkManager.service".to_owned();
                rules.push(Rule::new(
                    form.to_rule_spec(&I18n::test_english())
                        .map_err(std::io::Error::other)?,
                )?);
            }
            let mut app = App::new(false, I18n::load(locale)?);
            app.view = View::Outbound;
            app.set_snapshot(Snapshot {
                revision: 1,
                flow_generation: 1,
                mode: Mode::Learning,
                rules,
            });
            let mut terminal = Terminal::new(TestBackend::new(220, 44))?;
            for row in 0..3 {
                terminal.draw(|frame| draw_outbound_rules(frame, &app, frame.area()))?;
                let screen = buffer_text(terminal.backend());
                assert!(
                    screen.contains("/system.slice/NetworkManager.service"),
                    "{screen}"
                );
                assert!(
                    screen.contains("├ /usr/libexec/nm-daemon-helper"),
                    "{screen}"
                );
                assert!(screen.contains("└ /usr/sbin/NetworkManager"), "{screen}");
                // Inspect the actual right-hand cells: both paths deliberately
                // remain visible in the left tree even when filtered out here.
                let right = Layout::default()
                    .direction(LayoutDirection::Horizontal)
                    .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
                    .split(Rect::new(0, 0, 220, 44))[1];
                let buffer = terminal.backend().buffer();
                let right_text = (right.y..right.bottom())
                    .map(|y| {
                        (right.x..right.right())
                            .map(|x| buffer[(x, y)].symbol())
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                assert_eq!(
                    right_text.contains("203.0.113.11"),
                    row != 2,
                    "{right_text}"
                );
                assert_eq!(
                    right_text.contains("203.0.113.12"),
                    row != 2,
                    "{right_text}"
                );
                assert_eq!(
                    right_text.contains("198.51.100.9"),
                    row != 1,
                    "{right_text}"
                );
                if row == 1 {
                    assert!(
                        right_text.contains("/usr/libexec/nm-daemon-helper"),
                        "{right_text}"
                    );
                    assert!(
                        !right_text.contains("/usr/sbin/NetworkManager"),
                        "{right_text}"
                    );
                } else if row == 2 {
                    assert!(
                        right_text.contains("/usr/sbin/NetworkManager"),
                        "{right_text}"
                    );
                    assert!(
                        !right_text.contains("/usr/libexec/nm-daemon-helper"),
                        "{right_text}"
                    );
                }
                app.select_next_rule();
            }
            app.select_previous_rule();
            app.select_previous_rule();
            terminal.draw(|frame| draw_outbound_rules(frame, &app, frame.area()))?;
            let screen = buffer_text(terminal.backend());
            for peer in ["203.0.113.11", "203.0.113.12", "198.51.100.9"] {
                assert!(screen.contains(peer), "{screen}");
            }
        }
        Ok(())
    }

    #[test]
    fn disabled_application_template_is_visible_in_its_application_group()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut form = RuleForm::default();
        form.name = "application access template".to_owned();
        form.origin = RuleOrigin::Template;
        form.enabled = false;
        form.bind_application = true;
        form.executable = "/usr/bin/example-client".to_owned();
        form.cgroup = "/system.slice/example.service".to_owned();
        let template = Rule::new(
            form.to_rule_spec(&I18n::test_english())
                .map_err(std::io::Error::other)?,
        )?;

        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Learning,
            rules: vec![template],
        });
        let groups = app.outbound_groups();
        assert_eq!(groups.len(), 1);
        assert!(matches!(groups[0].key, OutboundGroupKey::Cgroup(_)));

        let mut terminal = Terminal::new(TestBackend::new(160, 36))?;
        terminal.draw(|frame| {
            draw(frame, &app, Path::new("/observe"), Path::new("/control"));
        })?;
        let screen = buffer_text(terminal.backend());
        for expected in [
            "application access template",
            "application template",
            "Accept",
            "/usr/bin/example-client",
            "/system.slice/example.service",
        ] {
            assert!(screen.contains(expected), "missing {expected}: {screen}");
        }
        Ok(())
    }

    #[test]
    fn long_rule_details_are_preserved_and_scroll_to_the_end()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut form = RuleForm::default();
        form.name = "long command".to_owned();
        form.protocol = TransportProtocol::Tcp;
        form.peer_network = "203.0.113.7".to_owned();
        form.bind_application = true;
        form.executable = "/usr/bin/long-command".to_owned();
        form.command_mode = CommandMode::Exact;
        let mut arguments = (0..7)
            .map(|index| format!("{index}-{}", "x".repeat(900)))
            .collect::<Vec<_>>();
        arguments.push(format!("7-{}ARGTAIL", "y".repeat(880)));
        form.arguments = serde_json::to_string(&arguments)?;
        let rule = Rule::new(
            form.to_rule_spec(&I18n::test_english())
                .map_err(std::io::Error::other)?,
        )?;
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.set_snapshot(Snapshot {
            revision: 1,
            flow_generation: 1,
            mode: Mode::Enforcing,
            rules: vec![rule],
        });
        for _ in 0..1_000 {
            app.scroll_rule_details(false);
        }

        let mut terminal = Terminal::new(TestBackend::new(80, 24))?;
        terminal.draw(|frame| {
            draw(frame, &app, Path::new("/observe"), Path::new("/control"));
        })?;
        let screen = buffer_text(terminal.backend());
        assert!(screen.contains("ARGTAIL"), "{screen}");
        Ok(())
    }

    #[test]
    fn rule_details_escape_arguments_without_replacing_or_conflating_them()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut form = RuleForm::default();
        form.name = "command control characters".to_owned();
        form.protocol = TransportProtocol::Tcp;
        form.bind_application = true;
        form.executable = "/usr/bin/client".to_owned();
        form.command_mode = CommandMode::Exact;
        form.arguments =
            r#"["client","line\nnext","line\\nnext","\u001b[31m\u202eSECRET"]"#.to_owned();
        let i18n = I18n::test_english();
        let rule = Rule::new(form.to_rule_spec(&i18n).map_err(std::io::Error::other)?)?;
        let lines = rule_detail_lines(&rule, &i18n);
        let text = lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .map(|span| span.content.as_ref())
            .collect::<String>();
        assert!(!text.chars().any(crate::i18n::is_unsafe_dynamic_character));
        assert!(text.contains(r#""line\nnext","line\\nnext""#));
        assert!(text.contains(r#""\u001b[31m\u202eSECRET""#));
        Ok(())
    }

    #[test]
    fn common_terminal_sizes_render_every_view_without_panicking()
    -> Result<(), Box<dyn std::error::Error>> {
        for (width, height) in [(80, 24), (40, 10)] {
            let mut app = App::new(true, I18n::test_english());
            for view in [
                View::Status,
                View::Outbound,
                View::Inbound,
                View::Events,
                View::Help,
            ] {
                app.view = view;
                let mut terminal = Terminal::new(TestBackend::new(width, height))?;
                terminal.draw(|frame| {
                    draw(frame, &app, Path::new("/observe"), Path::new("/control"));
                })?;
            }
        }
        Ok(())
    }

    #[test]
    fn editor_keeps_active_value_tail_and_error_visible_in_small_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut form = RuleForm::default();
        form.active_field = FormField::Executable;
        form.bind_application = true;
        form.executable = "/very/long/executable/path/whose/end/is/important/TAIL".to_owned();
        form.error = Some("VALIDATION ERROR".to_owned());
        let mut app = App::new(false, I18n::test_english());
        app.view = View::Outbound;
        app.overlay = Overlay::Editor(Box::new(form));
        let mut terminal = Terminal::new(TestBackend::new(40, 10))?;
        terminal.draw(|frame| {
            draw(frame, &app, Path::new("/observe"), Path::new("/control"));
        })?;
        let screen = buffer_text(terminal.backend());
        assert!(screen.contains("TAIL"), "{screen}");
        assert!(screen.contains("VALIDATION ERROR"), "{screen}");
        Ok(())
    }

    fn buffer_text(backend: &TestBackend) -> String {
        let buffer = backend.buffer();
        let mut text = String::new();
        for y in buffer.area.y..buffer.area.bottom() {
            let mut x = buffer.area.x;
            while x < buffer.area.right() {
                let symbol = buffer[(x, y)].symbol();
                text.push_str(symbol);
                // TestBackend can retain old symbols under the trailing cell
                // of a wide glyph. A real terminal does not display those cells.
                x = x.saturating_add(u16::try_from(symbol.width()).unwrap_or(u16::MAX).max(1));
            }
            text.push('\n');
        }
        text
    }
}
