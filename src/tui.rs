use crate::config::Config;
use crate::export;
use crate::models::*;
use crate::parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};
use std::path::PathBuf;

fn ioc_color(t: &IocType) -> Color {
    match t {
        IocType::IPv4 | IocType::IPv6 => Color::Cyan,
        IocType::Domain => Color::Magenta,
        IocType::URL => Color::LightBlue,
        IocType::MD5 | IocType::SHA1 | IocType::SHA256 => Color::Red,
        IocType::Email => Color::Green,
        IocType::CVE => Color::Yellow,
        IocType::BitcoinWallet => Color::DarkGray,
        IocType::Unknown => Color::Gray,
    }
}

fn priority_color(p: &Priority) -> Color {
    match p {
        Priority::High => Color::Red,
        Priority::Medium => Color::Yellow,
        Priority::Low => Color::Green,
        Priority::Unknown => Color::Gray,
    }
}

fn tag_style(t: &Tag) -> Style {
    match t {
        Tag::Malicious => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Tag::Suspicious => Style::default().fg(Color::Yellow),
        Tag::Clean => Style::default().fg(Color::Green),
        Tag::FalsePositive => Style::default().fg(Color::DarkGray),
        Tag::Untagged => Style::default().fg(Color::White),
    }
}

fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        s.to_string()
    } else {
        format!(
            "{}...",
            chars[..max.saturating_sub(3)].iter().collect::<String>()
        )
    }
}

fn toggle_type_filter(state: &mut AppState, t: IocType) {
    if state.type_filters.is_empty() {
        state.type_filters.insert(t);
    } else {
        if state.type_filters.contains(&t) {
            state.type_filters.remove(&t);
        } else {
            state.type_filters.insert(t);
        }
    }
}

fn centered_rect(w: u16, h: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect::new(x, y, w.min(area.width), h.min(area.height))
}

pub fn draw(f: &mut Frame, state: &AppState, _config: &Config) {
    let size = f.size();
    if size.height < 12 || size.width < 60 {
        let p = Paragraph::new("Terminal window too small.\nPlease resize to at least 60x12.")
            .alignment(ratatui::layout::Alignment::Center)
            .style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD));
        f.render_widget(p, size);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Top Navigation tabs
            Constraint::Min(5),    // Main workspace
            Constraint::Length(1), // Bottom Status bar / Prompt
        ])
        .split(size);

    draw_tabs_bar(f, chunks[0], state);

    match state.active_view {
        AppView::Dashboard => draw_dashboard_view(f, chunks[1], state),
        AppView::TriageList => {
            let filtered = state.get_filtered_entries();
            let show_panel =
                state.show_side_panel && size.width >= 100 && !state.entries.is_empty();
            if show_panel {
                let mid = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .split(chunks[1]);
                draw_table(f, mid[0], state, &filtered);
                draw_side_panel(f, mid[1], state);
            } else {
                draw_table(f, chunks[1], state, &filtered);
            }
        }
        AppView::LookupManager => draw_lookup_manager_view(f, chunks[1], state),
        AppView::Settings => draw_settings_view(f, chunks[1], state),
    }

    if state.mode == AppMode::CommandInput {
        draw_command_prompt(f, chunks[2], state);
    } else {
        draw_status_bar(f, chunks[2], state);
    }

    match state.mode {
        AppMode::InputPaste => draw_input_modal(f, size, state),
        AppMode::Help => draw_help_overlay(f, size),
        AppMode::NoteEditing => draw_note_editor(f, size, state),
        AppMode::ExportConfirm => draw_export_confirm(f, size),
        AppMode::DeleteConfirm => draw_delete_confirm(f, size, state),
        AppMode::SearchEditing => draw_search_editor(f, size, state),
        AppMode::SortSelect => draw_sort_select(f, size, state),
        AppMode::TypeFilterSelect => draw_type_filter_select(f, size, state),
        AppMode::Normal | AppMode::CommandInput => {}
    }
}

fn draw_tabs_bar(f: &mut Frame, area: Rect, state: &AppState) {
    let tabs = [
        (AppView::Dashboard, " [F1] Dashboard "),
        (AppView::TriageList, " [F2] Triage Grid "),
        (AppView::LookupManager, " [F3] Lookup Manager "),
        (AppView::Settings, " [F4] Settings "),
    ];

    let mut spans = Vec::new();
    for (view, label) in &tabs {
        let is_active = state.active_view == *view;
        let style = if is_active {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        spans.push(Span::styled(*label, style));
        spans.push(Span::raw(" "));
    }

    let mut filter_spans = Vec::new();
    if !state.search_query.is_empty() {
        filter_spans.push(Span::styled(
            " 🔍 Search Active",
            Style::default().fg(Color::Yellow),
        ));
    }
    if state.tag_filter != TagFilter::All {
        filter_spans.push(Span::styled(
            " 🏷️ Tag Filtered",
            Style::default().fg(Color::Green),
        ));
    }
    if !state.type_filters.is_empty() {
        filter_spans.push(Span::styled(
            " ⚙️ Type Filtered",
            Style::default().fg(Color::Cyan),
        ));
    }

    let left_paragraph = Paragraph::new(Line::from(spans));
    let right_paragraph =
        Paragraph::new(Line::from(filter_spans)).alignment(ratatui::layout::Alignment::Right);

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(area);

    f.render_widget(left_paragraph, chunks[0]);
    f.render_widget(right_paragraph, chunks[1]);
}

fn draw_dashboard_view(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    let left_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7), // Key Metrics
            Constraint::Length(9), // Tag Breakdown
            Constraint::Min(5),    // Type Breakdown
        ])
        .split(chunks[0]);

    let total = state.entries.len();
    let tagged = state.tagged_count();
    let dupes = state.duplicate_count;

    let metrics_text = vec![
        Line::from(vec![
            Span::styled("  Total Parsed:  ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{:<6}", state.total_input_count),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Duplicates:  ", Style::default().fg(Color::White)),
            Span::styled(format!("{:<6}", dupes), Style::default().fg(Color::Red)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("  Unique IOCs:   ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{:<6}", total),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  Tagged Items: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{:<6}", tagged),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    ];
    let metrics_block = Paragraph::new(metrics_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Session Metrics ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(metrics_block, left_chunks[0]);

    let mut mal = 0;
    let mut sus = 0;
    let mut cln = 0;
    let mut fp = 0;
    let mut unt = 0;
    for e in &state.entries {
        match e.tag {
            Tag::Malicious => mal += 1,
            Tag::Suspicious => sus += 1,
            Tag::Clean => cln += 1,
            Tag::FalsePositive => fp += 1,
            Tag::Untagged => unt += 1,
        }
    }
    let total_tags = total;

    let draw_bar = |count: usize, total: usize, width: usize| -> String {
        if total == 0 {
            return "░".repeat(width);
        }
        let filled = (count * width) / total;
        format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
    };

    let bar_width = (left_chunks[1].width as usize)
        .saturating_sub(25)
        .max(10)
        .min(30);
    let mut tag_lines = Vec::new();

    let tags_stats = [
        ("MALICIOUS       ", mal, Color::Red),
        ("SUSPICIOUS      ", sus, Color::Yellow),
        ("CLEAN           ", cln, Color::Green),
        ("FALSE POSITIVE  ", fp, Color::DarkGray),
        ("UNTAGGED        ", unt, Color::White),
    ];

    for (label, count, color) in tags_stats {
        let pct = if total_tags > 0 {
            (count * 100) / total_tags
        } else {
            0
        };
        tag_lines.push(Line::from(vec![
            Span::styled(label, Style::default().fg(color)),
            Span::styled(
                draw_bar(count, total_tags, bar_width),
                Style::default().fg(color),
            ),
            Span::styled(
                format!(" {:>3}% ({})", pct, count),
                Style::default().fg(Color::Gray),
            ),
        ]));
    }
    let tag_block = Paragraph::new(tag_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Tag Verdict Distribution ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(tag_block, left_chunks[1]);

    let mut ipv4 = 0;
    let mut ipv6 = 0;
    let mut domain = 0;
    let mut url = 0;
    let mut md5 = 0;
    let mut sha1 = 0;
    let mut sha256 = 0;
    let mut email = 0;
    let mut cve = 0;
    let mut btc = 0;

    for e in &state.entries {
        match e.ioc_type {
            IocType::IPv4 => ipv4 += 1,
            IocType::IPv6 => ipv6 += 1,
            IocType::Domain => domain += 1,
            IocType::URL => url += 1,
            IocType::MD5 => md5 += 1,
            IocType::SHA1 => sha1 += 1,
            IocType::SHA256 => sha256 += 1,
            IocType::Email => email += 1,
            IocType::CVE => cve += 1,
            IocType::BitcoinWallet => btc += 1,
            _ => {}
        }
    }

    let type_stats = [
        ("IPv4   ", ipv4, Color::Cyan),
        ("IPv6   ", ipv6, Color::Cyan),
        ("Domain ", domain, Color::Magenta),
        ("URL    ", url, Color::LightBlue),
        ("MD5    ", md5, Color::Red),
        ("SHA1   ", sha1, Color::Red),
        ("SHA256 ", sha256, Color::Red),
        ("Email  ", email, Color::Green),
        ("CVE    ", cve, Color::Yellow),
        ("Crypto ", btc, Color::Gray),
    ];

    let mut type_lines = Vec::new();
    let max_count = type_stats
        .iter()
        .map(|(_, count, _)| *count)
        .max()
        .unwrap_or(0)
        .max(1);
    let type_bar_width = (left_chunks[2].width as usize)
        .saturating_sub(18)
        .max(10)
        .min(25);

    for (label, count, color) in type_stats {
        if count == 0 {
            continue;
        }
        type_lines.push(Line::from(vec![
            Span::styled(format!("  {} ", label), Style::default().fg(color)),
            Span::styled(
                draw_bar(count, max_count, type_bar_width),
                Style::default().fg(color),
            ),
            Span::styled(format!(" ({})", count), Style::default().fg(Color::White)),
        ]));
    }
    if type_lines.is_empty() {
        type_lines.push(Line::from(Span::styled(
            "  No indicators parsed yet. Press I to paste raw text.",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }
    let type_block = Paragraph::new(type_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" IOC Type Breakdown ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(type_block, left_chunks[2]);

    let mut log_lines = Vec::new();
    let log_count = state.session_logs.len();
    let max_logs = (chunks[1].height as usize).saturating_sub(4);
    let start_idx = log_count.saturating_sub(max_logs);
    for log in &state.session_logs[start_idx..] {
        log_lines.push(Line::from(Span::styled(
            log,
            Style::default().fg(Color::Cyan),
        )));
    }
    if log_lines.is_empty() {
        log_lines.push(Line::from(Span::styled(
            "  No activity recorded in this session.",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }
    let log_block = Paragraph::new(log_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Live Activity Logs ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(log_block, chunks[1]);
}

fn draw_lookup_manager_view(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let entry_opt = state.selected_entry();
    let mut details_lines = Vec::new();
    if let Some(entry) = entry_opt {
        details_lines.push(Line::from(vec![Span::styled(
            "Selected Indicator details",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )]));
        details_lines.push(Line::from(""));
        details_lines.push(Line::from(vec![
            Span::styled("Value:    ", Style::default().fg(Color::Cyan)),
            Span::styled(&entry.value, Style::default().fg(Color::White)),
        ]));
        details_lines.push(Line::from(vec![
            Span::styled("Type:     ", Style::default().fg(Color::Cyan)),
            Span::styled(
                entry.ioc_type.to_string(),
                Style::default().fg(ioc_color(&entry.ioc_type)),
            ),
        ]));
        details_lines.push(Line::from(vec![
            Span::styled("Priority: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                entry.priority.to_string(),
                Style::default().fg(priority_color(&entry.priority)),
            ),
        ]));
        details_lines.push(Line::from(vec![
            Span::styled("Tag:      ", Style::default().fg(Color::Cyan)),
            Span::styled(entry.tag.to_string(), tag_style(&entry.tag)),
        ]));
        details_lines.push(Line::from(""));
        details_lines.push(Line::from(vec![
            Span::styled("Notes:    ", Style::default().fg(Color::Cyan)),
            Span::styled(
                if entry.note.is_empty() {
                    "[None]"
                } else {
                    &entry.note
                },
                Style::default().fg(Color::White),
            ),
        ]));
        details_lines.push(Line::from(""));
        details_lines.push(Line::from(vec![
            Span::styled("Created:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                entry.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    } else {
        details_lines.push(Line::from(Span::styled(
            "No indicators loaded in triage list.",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }
    let details_block = Paragraph::new(details_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Target Metadata ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(details_block, chunks[0]);

    let mut lookup_lines = Vec::new();
    if let Some(entry) = entry_opt {
        lookup_lines.push(Line::from(Span::styled(
            "Select platforms to look up or copy:",
            Style::default().fg(Color::White),
        )));
        lookup_lines.push(Line::from(""));

        for (i, lu) in entry.lookup_urls.iter().enumerate() {
            let is_sel = i == state.lookup_selected_index;
            let is_chk = state.lookup_checked_platforms.contains(&lu.platform);

            let chk_str = if is_chk { " ☑ " } else { " ☐ " };
            let cursor = if is_sel { "➤ " } else { "  " };

            let style = if is_sel {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if is_chk {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::White)
            };

            lookup_lines.push(Line::from(vec![
                Span::raw(cursor),
                Span::styled(
                    chk_str,
                    if is_chk {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
                Span::styled(format!("{:<15}", lu.platform), style),
                Span::styled(
                    truncate(&lu.url, (chunks[1].width as usize).saturating_sub(25)),
                    Style::default().fg(Color::DarkGray),
                ),
            ]));
        }

        lookup_lines.push(Line::from(""));
        lookup_lines.push(Line::from(Span::styled(
            "Controls:",
            Style::default().fg(Color::Cyan),
        )));
        lookup_lines.push(Line::from(
            "  [Space] Toggle checkbox  [A] Select All  [U] Unselect All",
        ));
        lookup_lines.push(Line::from(
            "  [O] Open checked URLs    [C] Copy checked URLs to clipboard",
        ));
    } else {
        lookup_lines.push(Line::from(Span::styled(
            "Select an indicator in Triage List first.",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }
    let lookup_block = Paragraph::new(lookup_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Threat Intelligence Lookups ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(lookup_block, chunks[1]);
}

fn draw_settings_view(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(5)])
        .split(area);

    let fields = [
        ("EXPORT_DIR", state.export_dir.to_string_lossy().to_string()),
        ("MAX_IOC_LIMIT", state.max_ioc_limit.to_string()),
    ];

    let mut fields_lines = Vec::new();
    fields_lines.push(Line::from(Span::styled(
        "Console Configurations (Use ↑/↓, Enter to Edit)",
        Style::default().fg(Color::White),
    )));
    fields_lines.push(Line::from(""));

    for (i, (name, val)) in fields.iter().enumerate() {
        let is_sel = i == state.settings_selected_index;
        let prefix = if is_sel { "➤ " } else { "  " };
        let mut spans = vec![
            Span::raw(prefix),
            Span::styled(format!("{:<18}: ", name), Style::default().fg(Color::Cyan)),
        ];

        if is_sel && state.settings_active_edit {
            spans.push(Span::styled(
                format!("{}█", state.settings_text_buffer),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::UNDERLINED),
            ));
        } else {
            spans.push(Span::styled(
                val,
                if is_sel {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::White)
                },
            ));
        }

        fields_lines.push(Line::from(spans));
    }

    let fields_block = Paragraph::new(fields_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Configurations ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(fields_block, chunks[0]);

    let mut info_lines = Vec::new();
    info_lines.push(Line::from(Span::styled(
        "Export Actions:",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )));
    info_lines.push(Line::from(
        "  Press [J] to trigger instant JSON session export",
    ));
    info_lines.push(Line::from(
        "  Press [C] to trigger instant CSV session export",
    ));
    info_lines.push(Line::from(""));
    info_lines.push(Line::from(Span::styled(
        "Environment variables default fallbacks:",
        Style::default().fg(Color::Cyan),
    )));
    info_lines.push(Line::from("  EXPORT_DIR    - sets output folder path"));
    info_lines.push(Line::from(
        "  MAX_IOC_LIMIT - restricts maximum indicators loaded",
    ));
    info_lines.push(Line::from(""));
    info_lines.push(Line::from(Span::styled(
        "Command Palette:",
        Style::default().fg(Color::Cyan),
    )));
    info_lines.push(Line::from(
        "  Press [:] in Normal mode to type commands directly (e.g. :tag mal, :clear)",
    ));

    let info_block = Paragraph::new(info_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Session Operations ")
            .border_style(Style::default().fg(Color::Blue)),
    );
    f.render_widget(info_block, chunks[1]);
}

fn draw_command_prompt(f: &mut Frame, area: Rect, state: &AppState) {
    let text = format!(":{}█", state.command_buffer);
    let prompt =
        Paragraph::new(text).style(Style::default().fg(Color::Cyan).bg(Color::Indexed(236)));
    f.render_widget(prompt, area);
}

fn draw_table(f: &mut Frame, area: Rect, state: &AppState, filtered: &[&IocEntry]) {
    let visible = (area.height as usize).saturating_sub(3).max(5);
    let selected = state.selected_index;
    let offset = if selected < state.scroll_offset {
        selected
    } else if selected >= state.scroll_offset + visible {
        selected.saturating_sub(visible - 1)
    } else {
        state.scroll_offset
    };

    let mut header_cells = vec![Cell::from(" Sel").style(
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    )];
    if area.width >= 70 {
        header_cells.push(
            Cell::from(" # ").style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        );
    }
    header_cells.push(
        Cell::from("Indicator").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    );
    header_cells.push(
        Cell::from("Type").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    );
    if area.width >= 70 {
        header_cells.push(
            Cell::from("Pri").style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        );
    }
    header_cells.push(
        Cell::from("Tag").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    );
    if area.width >= 90 {
        header_cells.push(
            Cell::from("Note").style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        );
    }
    let header = Row::new(header_cells).height(1).bottom_margin(1);

    let rows: Vec<Row> = filtered
        .iter()
        .skip(offset)
        .take(visible)
        .map(|e| {
            let is_sel = e.id == filtered.get(selected).map_or(0, |s| s.id);
            let is_chk = state.selected_ids.contains(&e.id);
            let chk_str = if is_chk { " ☑ " } else { " ☐ " };

            let base = if is_sel {
                Style::default()
                    .fg(Color::Yellow)
                    .bg(Color::Indexed(238))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let marker = if is_sel { "➤ " } else { "  " };

            let mut cells = vec![Cell::from(format!("{}{}", marker, chk_str)).style(base)];
            if area.width >= 70 {
                cells.push(Cell::from(format!("{:>3}", e.id)).style(base));
            }
            cells.push(Cell::from(truncate(&e.value, 40)).style(base.fg(if is_sel {
                Color::Yellow
            } else {
                ioc_color(&e.ioc_type)
            })));
            cells.push(Cell::from(e.ioc_type.to_string()).style(base.fg(ioc_color(&e.ioc_type))));
            if area.width >= 70 {
                cells.push(
                    Cell::from(e.priority.to_string()).style(base.fg(priority_color(&e.priority))),
                );
            }
            cells.push(Cell::from(e.tag.to_string()).style(if is_sel {
                base
            } else {
                tag_style(&e.tag)
            }));
            if area.width >= 90 {
                let note_display = if e.note.is_empty() {
                    String::new()
                } else {
                    truncate(&e.note, 20)
                };
                cells.push(Cell::from(note_display).style(base));
            }

            Row::new(cells)
        })
        .collect();

    let widths = if area.width >= 90 {
        vec![
            Constraint::Length(6),  // Sel
            Constraint::Length(5),  // ID
            Constraint::Min(30),    // Indicator
            Constraint::Length(8),  // Type
            Constraint::Length(5),  // Pri
            Constraint::Length(5),  // Tag
            Constraint::Length(25), // Note
        ]
    } else if area.width >= 70 {
        vec![
            Constraint::Length(6), // Sel
            Constraint::Length(5), // ID
            Constraint::Min(20),   // Indicator
            Constraint::Length(8), // Type
            Constraint::Length(5), // Pri
            Constraint::Length(5), // Tag
        ]
    } else {
        vec![
            Constraint::Length(6), // Sel
            Constraint::Min(15),   // Indicator
            Constraint::Length(8), // Type
            Constraint::Length(5), // Tag
        ]
    };

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Indicators ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(table, area);
}

fn draw_side_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let mut lines: Vec<Line> = Vec::new();

    let entry_opt = state.selected_entry();
    if let Some(entry) = entry_opt {
        lines.push(Line::from(vec![
            Span::styled(
                "Value: ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&entry.value, Style::default().fg(Color::White)),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Type:  ", Style::default().fg(Color::Cyan)),
            Span::styled(
                entry.ioc_type.to_string(),
                Style::default().fg(ioc_color(&entry.ioc_type)),
            ),
            Span::raw("  "),
            Span::styled("Priority: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                entry.priority.to_string(),
                Style::default().fg(priority_color(&entry.priority)),
            ),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Tag:   ", Style::default().fg(Color::Cyan)),
            Span::styled(entry.tag.to_string(), tag_style(&entry.tag)),
        ]));
        lines.push(Line::from(""));

        if !entry.note.is_empty() {
            lines.push(Line::from(vec![
                Span::styled(
                    "Note: ",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&entry.note, Style::default().fg(Color::White)),
            ]));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled(
            "─ Lookup URLs ─",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));
        for (i, lu) in entry.lookup_urls.iter().take(4).enumerate() {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" [{}] ", i + 1),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(&lu.platform, Style::default().fg(Color::Green)),
            ]));
            let display_url = truncate(&lu.url, (area.width as usize).saturating_sub(6));
            lines.push(Line::from(vec![
                Span::raw("     "),
                Span::styled(display_url, Style::default().fg(Color::DarkGray)),
            ]));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "No indicator selected",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::ITALIC),
        )));
    }

    if !state.entries.is_empty() {
        let mut mal = 0;
        let mut sus = 0;
        let mut cln = 0;
        let mut fp = 0;
        let mut unt = 0;
        for e in &state.entries {
            match e.tag {
                Tag::Malicious => mal += 1,
                Tag::Suspicious => sus += 1,
                Tag::Clean => cln += 1,
                Tag::FalsePositive => fp += 1,
                Tag::Untagged => unt += 1,
            }
        }
        let total_tags = state.entries.len();

        let draw_bar = |count: usize, total: usize, width: usize| -> String {
            if total == 0 {
                return "░".repeat(width);
            }
            let filled = (count * width) / total;
            format!("{}{}", "█".repeat(filled), "░".repeat(width - filled))
        };

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "─ Tag Breakdown ─",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));

        let bar_width = (area.width as usize).saturating_sub(15).max(6).min(20);

        let tags_stats = [
            ("MAL", mal, Color::Red),
            ("SUS", sus, Color::Yellow),
            ("CLN", cln, Color::Green),
            ("FP ", fp, Color::DarkGray),
            ("UNT", unt, Color::White),
        ];

        for (label, count, color) in tags_stats {
            let pct = if total_tags > 0 {
                (count * 100) / total_tags
            } else {
                0
            };
            lines.push(Line::from(vec![
                Span::styled(format!(" {}: ", label), Style::default().fg(color)),
                Span::styled(
                    draw_bar(count, total_tags, bar_width),
                    Style::default().fg(color),
                ),
                Span::styled(
                    format!(" {:>3}% ({})", pct, count),
                    Style::default().fg(Color::Gray),
                ),
            ]));
        }
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Details ")
                .border_style(Style::default().fg(Color::White)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(panel, area);
}

fn draw_status_bar(f: &mut Frame, area: Rect, state: &AppState) {
    let mut keys = vec![
        Span::styled(" [Tab]", Style::default().fg(Color::Cyan)),
        Span::raw(" Tab "),
        Span::styled(" [F1-F4]", Style::default().fg(Color::Cyan)),
        Span::raw(" Go "),
    ];

    if area.width >= 75 {
        keys.push(Span::styled(" [:]", Style::default().fg(Color::Cyan)));
        keys.push(Span::raw(" Cmd "));
    }
    if area.width >= 85 {
        keys.push(Span::styled(" [?]", Style::default().fg(Color::Cyan)));
        keys.push(Span::raw(" Help "));
    }

    keys.push(Span::raw("| "));

    match state.active_view {
        AppView::Dashboard => {
            keys.push(Span::styled(" [I]", Style::default().fg(Color::Cyan)));
            keys.push(Span::raw(" Paste "));
        }
        AppView::TriageList => {
            if area.width >= 80 {
                keys.push(Span::styled(" [Spc]", Style::default().fg(Color::Cyan)));
                keys.push(Span::raw(" Check "));
            }
            keys.push(Span::styled(" [/]", Style::default().fg(Color::Cyan)));
            keys.push(Span::raw(" Find "));
            if area.width >= 90 {
                keys.push(Span::styled(" [F/S]", Style::default().fg(Color::Cyan)));
                keys.push(Span::raw(" Flt/Sort "));
            }
            keys.push(Span::styled(" [T/N/C/D]", Style::default().fg(Color::Cyan)));
            keys.push(Span::raw(" Act "));
        }
        AppView::LookupManager => {
            keys.push(Span::styled(" [Spc]", Style::default().fg(Color::Cyan)));
            keys.push(Span::raw(" Check "));
            keys.push(Span::styled(" [O/C]", Style::default().fg(Color::Cyan)));
            keys.push(Span::raw(" Open/Copy "));
        }
        AppView::Settings => {
            keys.push(Span::styled(" [Enter]", Style::default().fg(Color::Cyan)));
            keys.push(Span::raw(" Edit "));
            keys.push(Span::styled(" [J/C]", Style::default().fg(Color::Cyan)));
            keys.push(Span::raw(" Export "));
        }
    }

    keys.push(Span::raw("| "));
    keys.push(Span::styled(
        &state.status_message,
        Style::default().fg(Color::Green),
    ));

    let bar = Paragraph::new(Line::from(keys))
        .style(Style::default().bg(Color::Indexed(236)).fg(Color::White));
    f.render_widget(bar, area);
}

fn draw_input_modal(f: &mut Frame, area: Rect, state: &AppState) {
    let modal = centered_rect(
        70.min(area.width.saturating_sub(4)),
        20.min(area.height.saturating_sub(4)),
        area,
    );
    f.render_widget(Clear, modal);
    let char_count = state.input_buffer.chars().count();
    let title = format!(
        " Paste IOCs ({} chars) — Enter×2 to confirm, Esc to cancel ",
        char_count
    );
    let display_text = if state.input_buffer.is_empty() {
        "Paste your IOC data here...\n\nSupported: IPv4, IPv6, Domains, URLs, MD5, SHA1, SHA256,\nEmails, CVEs, Bitcoin addresses\n\nAccepts defanged formats: hxxp, [.], (.) etc.".to_string()
    } else {
        let lines: Vec<&str> = state.input_buffer.lines().collect();
        let max_lines = (modal.height as usize).saturating_sub(4);
        if lines.len() > max_lines {
            format!(
                "{}...\n[{} more lines]",
                lines[..max_lines].join("\n"),
                lines.len() - max_lines
            )
        } else {
            state.input_buffer.clone()
        }
    };
    let input = Paragraph::new(display_text)
        .style(Style::default().fg(if state.input_buffer.is_empty() {
            Color::DarkGray
        } else {
            Color::White
        }))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Black)),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(input, modal);
}

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let modal = centered_rect(65, 24, area);
    f.render_widget(Clear, modal);
    let help_text = vec![
        Line::from(Span::styled(
            "  Keybindings & Controls",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  F1 / F2 / F3 / F4  Switch between views directly"),
        Line::from("  Tab / Shift+Tab    Cycle views forward / backward"),
        Line::from("  :                  Open command palette prompt"),
        Line::from(""),
        Line::from("  Triage Grid Tab:"),
        Line::from("  ↑/↓ / Space        Navigate rows / Toggle checkbox selection"),
        Line::from("  A / U              Select all / Unselect all filtered items"),
        Line::from("  /                  Enter search query filter"),
        Line::from("  F / Shift+F        Cycle tag filter forward / backward"),
        Line::from("  Y / S / x          Type filter / Sort options / Clear filters"),
        Line::from("  T / Shift+T        Cycle tag verdict forward / backward (bulk)"),
        Line::from("  N / C / D          Add notes / Copy values (bulk) / Delete (bulk)"),
        Line::from("  O / 1-9            Open all lookups (bulk) / Open lookup index"),
        Line::from(""),
        Line::from("  Lookup Manager Tab:"),
        Line::from("  ↑/↓ / Space        Navigate threat intel list / Toggle checkbox"),
        Line::from("  O / C              Open checked lookup URLs / Copy checked links"),
        Line::from(""),
        Line::from("  Settings Tab:"),
        Line::from("  ↑/↓ / Enter        Select settings field / Start editing"),
        Line::from("  J / C              Export session to JSON / CSV"),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close help overlay",
            Style::default().fg(Color::DarkGray),
        )),
    ];
    let help = Paragraph::new(help_text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Help ")
            .border_style(Style::default().fg(Color::Yellow))
            .style(Style::default().bg(Color::Black)),
    );
    f.render_widget(help, modal);
}

fn draw_note_editor(f: &mut Frame, area: Rect, state: &AppState) {
    let editor_area = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(3),
        area.width,
        3,
    );
    f.render_widget(Clear, editor_area);
    let text = format!("{}█", state.note_buffer);
    let editor = Paragraph::new(text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Edit Note — Enter to save, Esc to cancel ")
                .border_style(Style::default().fg(Color::Yellow))
                .style(Style::default().bg(Color::Black)),
        );
    f.render_widget(editor, editor_area);
}

fn draw_search_editor(f: &mut Frame, area: Rect, state: &AppState) {
    let editor_area = Rect::new(
        area.x,
        area.y + area.height.saturating_sub(3),
        area.width,
        3,
    );
    f.render_widget(Clear, editor_area);
    let text = format!("{}█", state.search_query);
    let editor = Paragraph::new(text)
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Search Query — Enter to apply, Esc to cancel/clear ")
                .border_style(Style::default().fg(Color::Yellow))
                .style(Style::default().bg(Color::Black)),
        );
    f.render_widget(editor, editor_area);
}

fn draw_sort_select(f: &mut Frame, area: Rect, state: &AppState) {
    let modal = centered_rect(45, 12, area);
    f.render_widget(Clear, modal);

    let keys = [
        ("1", "ID", SortBy::Id),
        ("2", "Value", SortBy::Value),
        ("3", "Type", SortBy::Type),
        ("4", "Priority", SortBy::Priority),
        ("5", "Tag", SortBy::Tag),
    ];

    let mut lines = vec![
        Line::from(Span::styled(
            "  Sort Settings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
    ];

    for (key, name, variant) in &keys {
        let is_selected = state.sort_by == *variant;
        let prefix = if is_selected { " ➤ " } else { "   " };
        let style = if is_selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };

        lines.push(Line::from(vec![
            Span::raw(prefix),
            Span::styled(format!("[{}]", key), Style::default().fg(Color::Cyan)),
            Span::styled(format!(" {}", name), style),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::raw("  Current Order: "),
        Span::styled(
            format!(
                "{} {}",
                state.sort_order,
                if state.sort_order == SortOrder::Ascending {
                    "Ascending"
                } else {
                    "Descending"
                }
            ),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::raw("  Press "),
        Span::styled("[O]", Style::default().fg(Color::Cyan)),
        Span::raw(" to toggle direction, "),
        Span::styled("[Esc]", Style::default().fg(Color::Cyan)),
        Span::raw(" to close"),
    ]));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Sort Options ")
            .border_style(Style::default().fg(Color::Yellow))
            .style(Style::default().bg(Color::Black)),
    );
    f.render_widget(p, modal);
}

fn draw_type_filter_select(f: &mut Frame, area: Rect, state: &AppState) {
    let modal = centered_rect(50, 16, area);
    f.render_widget(Clear, modal);

    let types = [
        ("1", "IPv4", IocType::IPv4),
        ("2", "IPv6", IocType::IPv6),
        ("3", "Domain", IocType::Domain),
        ("4", "URL", IocType::URL),
        ("5", "MD5", IocType::MD5),
        ("6", "SHA1", IocType::SHA1),
        ("7", "SHA256", IocType::SHA256),
        ("8", "Email", IocType::Email),
        ("9", "CVE", IocType::CVE),
        ("0", "Crypto", IocType::BitcoinWallet),
    ];

    let mut lines = vec![
        Line::from(Span::styled(
            "  Filter by IOC Type",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  (Empty = Show All)",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
    ];

    for (key, name, variant) in &types {
        let is_active = state.type_filters.is_empty() || state.type_filters.contains(variant);
        let chk = if is_active { " ☑ " } else { " ☐ " };
        let style = if is_active {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        lines.push(Line::from(vec![
            Span::styled(chk, style),
            Span::styled(format!("[{}]", key), Style::default().fg(Color::Cyan)),
            Span::styled(format!(" {}", name), Style::default().fg(Color::White)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("  [A]", Style::default().fg(Color::Cyan)),
        Span::raw(" Enable All  "),
        Span::styled("[C]", Style::default().fg(Color::Cyan)),
        Span::raw(" Clear All  "),
        Span::styled("[Esc]", Style::default().fg(Color::Cyan)),
        Span::raw(" Close"),
    ]));

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" IOC Type Filter ")
            .border_style(Style::default().fg(Color::Yellow))
            .style(Style::default().bg(Color::Black)),
    );
    f.render_widget(p, modal);
}

fn draw_export_confirm(f: &mut Frame, area: Rect) {
    let modal = centered_rect(45, 7, area);
    f.render_widget(Clear, modal);
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Export session?",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled("  [J]", Style::default().fg(Color::Cyan)),
            Span::raw(" JSON  "),
            Span::styled("[C]", Style::default().fg(Color::Cyan)),
            Span::raw(" CSV  "),
            Span::styled("[Esc]", Style::default().fg(Color::Cyan)),
            Span::raw(" Cancel"),
        ]),
    ];
    let p = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Export ")
            .border_style(Style::default().fg(Color::Green))
            .style(Style::default().bg(Color::Black)),
    );
    f.render_widget(p, modal);
}

fn draw_delete_confirm(f: &mut Frame, area: Rect, state: &AppState) {
    let modal = centered_rect(50, 7, area);
    f.render_widget(Clear, modal);

    let text = if state.selected_ids.is_empty() {
        let val = state.selected_entry().map_or("", |e| &e.value);
        vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  Delete {}?", truncate(val, 30)),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  [Y]", Style::default().fg(Color::Cyan)),
                Span::raw(" Yes  "),
                Span::styled("[N/Esc]", Style::default().fg(Color::Cyan)),
                Span::raw(" Cancel"),
            ]),
        ]
    } else {
        let count = state.selected_ids.len();
        vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  Delete all {} selected indicators?", count),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(vec![
                Span::styled("  [Y]", Style::default().fg(Color::Cyan)),
                Span::raw(" Yes  "),
                Span::styled("[N/Esc]", Style::default().fg(Color::Cyan)),
                Span::raw(" Cancel"),
            ]),
        ]
    };

    let p = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Confirm Delete ")
            .border_style(Style::default().fg(Color::Red))
            .style(Style::default().bg(Color::Black)),
    );
    f.render_widget(p, modal);
}

pub fn handle_event(state: &mut AppState, config: &Config) -> Result<bool, anyhow::Error> {
    if event::poll(std::time::Duration::from_millis(16))? {
        if let Event::Key(key) = event::read()? {
            match state.mode {
                AppMode::Normal => return handle_normal_key(state, key, config),
                AppMode::InputPaste => handle_input_key(state, key, config),
                AppMode::NoteEditing => handle_note_key(state, key),
                AppMode::Help => {
                    state.mode = AppMode::Normal;
                }
                AppMode::ExportConfirm => handle_export_key(state, key, config),
                AppMode::DeleteConfirm => handle_delete_key(state, key),
                AppMode::SearchEditing => handle_search_key(state, key),
                AppMode::SortSelect => handle_sort_key(state, key),
                AppMode::TypeFilterSelect => handle_type_filter_key(state, key),
                AppMode::CommandInput => handle_command_key(state, key),
            }
        }
    }
    Ok(false)
}

fn handle_normal_key(
    state: &mut AppState,
    key: KeyEvent,
    _config: &Config,
) -> Result<bool, anyhow::Error> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Ok(true);
    }

    // Tab switching
    match key.code {
        KeyCode::F(1) => {
            state.active_view = AppView::Dashboard;
            state.status_message = "Dashboard view".to_string();
            return Ok(false);
        }
        KeyCode::F(2) => {
            state.active_view = AppView::TriageList;
            state.status_message = "Triage Grid view".to_string();
            return Ok(false);
        }
        KeyCode::F(3) => {
            state.active_view = AppView::LookupManager;
            state.status_message = "Lookup Manager view".to_string();

            let platforms: Vec<String> = state
                .selected_entry()
                .map(|e| e.lookup_urls.iter().map(|lu| lu.platform.clone()).collect())
                .unwrap_or_default();
            if !platforms.is_empty() {
                state.lookup_checked_platforms.clear();
                for p in platforms {
                    state.lookup_checked_platforms.insert(p);
                }
            }
            state.lookup_selected_index = 0;
            return Ok(false);
        }
        KeyCode::F(4) => {
            state.active_view = AppView::Settings;
            state.status_message = "Settings view".to_string();
            return Ok(false);
        }
        KeyCode::Tab => {
            state.active_view = match state.active_view {
                AppView::Dashboard => AppView::TriageList,
                AppView::TriageList => AppView::LookupManager,
                AppView::LookupManager => AppView::Settings,
                AppView::Settings => AppView::Dashboard,
            };
            state.status_message = format!("Switched view to {}", state.active_view);
            if state.active_view == AppView::LookupManager {
                let platforms: Vec<String> = state
                    .selected_entry()
                    .map(|e| e.lookup_urls.iter().map(|lu| lu.platform.clone()).collect())
                    .unwrap_or_default();
                if !platforms.is_empty() {
                    state.lookup_checked_platforms.clear();
                    for p in platforms {
                        state.lookup_checked_platforms.insert(p);
                    }
                }
                state.lookup_selected_index = 0;
            }
            return Ok(false);
        }
        KeyCode::Char(':') => {
            state.mode = AppMode::CommandInput;
            state.command_buffer.clear();
            return Ok(false);
        }
        KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(true),
        KeyCode::Char('?') => {
            state.mode = AppMode::Help;
            return Ok(false);
        }
        _ => {}
    }

    match state.active_view {
        AppView::Dashboard => handle_dashboard_keys(state, key),
        AppView::TriageList => handle_triage_list_keys(state, key),
        AppView::LookupManager => handle_lookup_manager_keys(state, key),
        AppView::Settings => handle_settings_keys(state, key),
    }

    Ok(false)
}

fn handle_dashboard_keys(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Char('i') | KeyCode::Char('I') => {
            state.input_buffer.clear();
            state.mode = AppMode::InputPaste;
        }
        _ => {}
    }
}

fn handle_triage_list_keys(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Up => state.move_up(1),
        KeyCode::Down => state.move_down(1),
        KeyCode::PageUp => state.move_up(10),
        KeyCode::PageDown => state.move_down(10),
        KeyCode::Home => state.jump_home(),
        KeyCode::End => state.jump_end(),
        KeyCode::Char('o') | KeyCode::Char('O') => open_all_urls(state),

        KeyCode::Char('t') => {
            state.cycle_tags_for_selected(true);
            state.status_message = "Tags cycled forward".to_string();
        }
        KeyCode::Char('T') => {
            state.cycle_tags_for_selected(false);
            state.status_message = "Tags cycled backward".to_string();
        }

        KeyCode::Char('n') => {
            state.note_buffer = state
                .selected_entry()
                .map_or(String::new(), |e| e.note.clone());
            state.mode = AppMode::NoteEditing;
        }
        KeyCode::Char('e') => {
            if !state.entries.is_empty() {
                state.mode = AppMode::ExportConfirm;
            }
        }
        KeyCode::Char('c') | KeyCode::Char('C') => copy_to_clipboard(state),
        KeyCode::Char('d') => {
            if !state.entries.is_empty() {
                state.mode = AppMode::DeleteConfirm;
            }
        }
        KeyCode::Char('i') | KeyCode::Char('I') => {
            state.input_buffer.clear();
            state.mode = AppMode::InputPaste;
        }

        KeyCode::Char('/') => {
            state.mode = AppMode::SearchEditing;
        }
        KeyCode::Char('f') => {
            state.tag_filter = match state.tag_filter {
                TagFilter::All => TagFilter::Tag(Tag::Untagged),
                TagFilter::Tag(Tag::Untagged) => TagFilter::Tag(Tag::Clean),
                TagFilter::Tag(Tag::Clean) => TagFilter::Tag(Tag::Suspicious),
                TagFilter::Tag(Tag::Suspicious) => TagFilter::Tag(Tag::Malicious),
                TagFilter::Tag(Tag::Malicious) => TagFilter::Tag(Tag::FalsePositive),
                TagFilter::Tag(Tag::FalsePositive) => TagFilter::All,
            };
            state.status_message = format!("Tag filter: {}", state.tag_filter);
            state.selected_index = 0;
        }
        KeyCode::Char('F') => {
            state.tag_filter = match state.tag_filter {
                TagFilter::All => TagFilter::Tag(Tag::FalsePositive),
                TagFilter::Tag(Tag::FalsePositive) => TagFilter::Tag(Tag::Malicious),
                TagFilter::Tag(Tag::Malicious) => TagFilter::Tag(Tag::Suspicious),
                TagFilter::Tag(Tag::Suspicious) => TagFilter::Tag(Tag::Clean),
                TagFilter::Tag(Tag::Clean) => TagFilter::Tag(Tag::Untagged),
                TagFilter::Tag(Tag::Untagged) => TagFilter::All,
            };
            state.status_message = format!("Tag filter: {}", state.tag_filter);
            state.selected_index = 0;
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            state.mode = AppMode::SortSelect;
        }
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            state.mode = AppMode::TypeFilterSelect;
        }
        KeyCode::Char('x') => {
            state.search_query.clear();
            state.tag_filter = TagFilter::All;
            state.type_filters.clear();
            state.status_message = "Filters cleared".to_string();
            state.selected_index = 0;
        }
        KeyCode::Char(' ') => {
            state.toggle_select_selected();
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            state.select_all_filtered();
            state.status_message = format!(
                "Selected all {} filtered entries",
                state.get_filtered_entries().len()
            );
        }
        KeyCode::Char('u') | KeyCode::Char('U') => {
            state.clear_all_selection();
            state.status_message = "Selection cleared".to_string();
        }

        KeyCode::Char(c) if c.is_ascii_digit() && c != '0' => {
            let idx = (c as u8 - b'1') as usize;
            open_url_by_index(state, idx);
        }
        _ => {}
    }
}

fn handle_lookup_manager_keys(state: &mut AppState, key: KeyEvent) {
    let (val, lookup_urls) = match state.selected_entry() {
        Some(e) => (e.value.clone(), e.lookup_urls.clone()),
        None => return,
    };

    let count = lookup_urls.len();
    if count == 0 {
        return;
    }

    match key.code {
        KeyCode::Up => {
            state.lookup_selected_index = state.lookup_selected_index.saturating_sub(1);
        }
        KeyCode::Down => {
            if state.lookup_selected_index < count - 1 {
                state.lookup_selected_index += 1;
            }
        }
        KeyCode::Char(' ') => {
            if let Some(lu) = lookup_urls.get(state.lookup_selected_index) {
                let name = lu.platform.clone();
                if state.lookup_checked_platforms.contains(&name) {
                    state.lookup_checked_platforms.remove(&name);
                } else {
                    state.lookup_checked_platforms.insert(name);
                }
            }
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            let platforms: Vec<String> = lookup_urls.iter().map(|lu| lu.platform.clone()).collect();
            for p in platforms {
                state.lookup_checked_platforms.insert(p);
            }
            state.status_message = "All lookups checked".to_string();
        }
        KeyCode::Char('u') | KeyCode::Char('U') => {
            state.lookup_checked_platforms.clear();
            state.status_message = "All lookups unchecked".to_string();
        }
        KeyCode::Char('o') | KeyCode::Char('O') => {
            let mut opened = 0;
            for lu in &lookup_urls {
                if state.lookup_checked_platforms.contains(&lu.platform) {
                    let _ = open::that(&lu.url);
                    opened += 1;
                }
            }
            state.status_message = format!("Opened {} checked lookup URLs", opened);
            state.add_log(&format!("Opened {} lookup links for {}", opened, val));
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            let mut urls = Vec::new();
            for lu in &lookup_urls {
                if state.lookup_checked_platforms.contains(&lu.platform) {
                    urls.push(lu.url.clone());
                }
            }
            if !urls.is_empty() {
                let joined = urls.join("\n");
                match arboard::Clipboard::new() {
                    Ok(mut clip) => {
                        if clip.set_text(&joined).is_ok() {
                            state.status_message = format!("Copied {} checked URLs", urls.len());
                        }
                    }
                    Err(_) => state.status_message = "Clipboard error".to_string(),
                }
            }
        }
        _ => {}
    }
}

fn handle_settings_keys(state: &mut AppState, key: KeyEvent) {
    if state.settings_active_edit {
        match key.code {
            KeyCode::Esc => {
                state.settings_active_edit = false;
                state.settings_text_buffer.clear();
                state.status_message = "Edit cancelled".to_string();
            }
            KeyCode::Enter => {
                let buffer = state.settings_text_buffer.trim().to_string();
                if state.settings_selected_index == 0 {
                    let path = PathBuf::from(&buffer);
                    state.export_dir = path;
                    state.add_log(&format!("Export directory updated to: {}", buffer));
                    state.status_message = format!("Saved export directory: {}", buffer);
                } else if state.settings_selected_index == 1 {
                    if let Ok(limit) = buffer.parse::<usize>() {
                        state.max_ioc_limit = limit;
                        state.add_log(&format!("Max IOC limit updated to: {}", limit));
                        state.status_message = format!("Saved max limit: {}", limit);
                    } else {
                        state.status_message = "Error: Invalid number format".to_string();
                        return;
                    }
                }
                state.settings_active_edit = false;
                state.settings_text_buffer.clear();
            }
            KeyCode::Char(c) => {
                state.settings_text_buffer.push(c);
            }
            KeyCode::Backspace => {
                state.settings_text_buffer.pop();
            }
            _ => {}
        }
    } else {
        match key.code {
            KeyCode::Up => {
                state.settings_selected_index = state.settings_selected_index.saturating_sub(1);
            }
            KeyCode::Down => {
                if state.settings_selected_index < 1 {
                    state.settings_selected_index += 1;
                }
            }
            KeyCode::Enter => {
                state.settings_active_edit = true;
                state.settings_text_buffer = if state.settings_selected_index == 0 {
                    state.export_dir.to_string_lossy().to_string()
                } else {
                    state.max_ioc_limit.to_string()
                };
                state.status_message = "Enter value, then press Enter to save".to_string();
            }
            KeyCode::Char('j') | KeyCode::Char('J') => {
                if !state.entries.is_empty() {
                    state.mode = AppMode::ExportConfirm;
                }
            }
            KeyCode::Char('c') | KeyCode::Char('C') => {
                if !state.entries.is_empty() {
                    state.mode = AppMode::ExportConfirm;
                }
            }
            _ => {}
        }
    }
}

fn handle_command_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.command_buffer.clear();
            state.mode = AppMode::Normal;
            state.status_message = "Command mode exited".to_string();
        }
        KeyCode::Enter => {
            let cmd = state.command_buffer.clone();
            state.command_buffer.clear();
            state.mode = AppMode::Normal;
            execute_command(state, &cmd);
        }
        KeyCode::Char(c) => {
            state.command_buffer.push(c);
        }
        KeyCode::Backspace => {
            state.command_buffer.pop();
        }
        _ => {}
    }
}

fn execute_command(state: &mut AppState, cmd_str: &str) {
    let parts: Vec<&str> = cmd_str.trim().split_whitespace().collect();
    if parts.is_empty() {
        return;
    }
    let cmd = parts[0].to_lowercase();
    match cmd.as_str() {
        "help" | "?" => {
            state.active_view = AppView::Dashboard;
            state.mode = AppMode::Help;
        }
        "clear" => {
            state.entries.clear();
            state.selected_ids.clear();
            state.selected_index = 0;
            state.add_log("Cleared all indicators");
            state.status_message = "Cleared all indicators".to_string();
        }
        "search" => {
            let query = parts[1..].join(" ");
            state.search_query = query.clone();
            state.selected_index = 0;
            state.add_log(&format!("Search query set to '{}'", query));
            state.status_message = format!("Searching for '{}'", query);
        }
        "tag" => {
            if parts.len() < 2 {
                state.status_message =
                    "Usage: :tag <clean|suspicious|malicious|fp|untagged>".to_string();
                return;
            }
            let tag_val = match parts[1].to_lowercase().as_str() {
                "clean" | "cln" => Tag::Clean,
                "suspicious" | "sus" => Tag::Suspicious,
                "malicious" | "mal" => Tag::Malicious,
                "fp" | "falsepositive" => Tag::FalsePositive,
                "untagged" | "-" => Tag::Untagged,
                _ => {
                    state.status_message =
                        "Invalid tag. Choose clean, suspicious, malicious, fp, untagged"
                            .to_string();
                    return;
                }
            };

            let mut tagged_val = None;
            if state.selected_ids.is_empty() {
                if let Some(entry) = state.selected_entry_mut() {
                    entry.tag = tag_val;
                    tagged_val = Some(entry.value.clone());
                    state.has_unsaved_changes = true;
                }
                if let Some(val) = tagged_val {
                    state.add_log(&format!("Tagged {} as {}", val, tag_val));
                    state.status_message = format!("Tagged as {}", tag_val);
                }
            } else {
                let ids = state.selected_ids.clone();
                for entry in &mut state.entries {
                    if ids.contains(&entry.id) {
                        entry.tag = tag_val;
                    }
                }
                state.add_log(&format!(
                    "Tagged {} selected indicators as {}",
                    ids.len(),
                    tag_val
                ));
                state.status_message = format!("Tagged {} items as {}", ids.len(), tag_val);
                state.has_unsaved_changes = true;
            }
        }
        "filter" => {
            if parts.len() < 2 {
                state.status_message = "Usage: :filter <tag|type|clear> [value]".to_string();
                return;
            }
            match parts[1].to_lowercase().as_str() {
                "clear" | "none" => {
                    state.tag_filter = TagFilter::All;
                    state.type_filters.clear();
                    state.status_message = "Filters cleared".to_string();
                }
                "tag" => {
                    if parts.len() < 3 {
                        state.status_message =
                            "Usage: :filter tag <cln|sus|mal|fp|untagged>".to_string();
                        return;
                    }
                    let tag_filter = match parts[2].to_lowercase().as_str() {
                        "cln" | "clean" => TagFilter::Tag(Tag::Clean),
                        "sus" | "suspicious" => TagFilter::Tag(Tag::Suspicious),
                        "mal" | "malicious" => TagFilter::Tag(Tag::Malicious),
                        "fp" | "falsepositive" => TagFilter::Tag(Tag::FalsePositive),
                        "untagged" | "-" => TagFilter::Tag(Tag::Untagged),
                        _ => {
                            state.status_message = "Invalid tag filter".to_string();
                            return;
                        }
                    };
                    state.tag_filter = tag_filter;
                    state.selected_index = 0;
                    state.status_message = format!("Filtering by tag: {}", state.tag_filter);
                }
                "type" => {
                    if parts.len() < 3 {
                        state.status_message =
                            "Usage: :filter type <ipv4|ipv6|domain|url|hash|email|cve|bitcoin>"
                                .to_string();
                        return;
                    }
                    let t = match parts[2].to_lowercase().as_str() {
                        "ipv4" => IocType::IPv4,
                        "ipv6" => IocType::IPv6,
                        "domain" => IocType::Domain,
                        "url" => IocType::URL,
                        "md5" => IocType::MD5,
                        "sha1" => IocType::SHA1,
                        "sha256" => IocType::SHA256,
                        "email" => IocType::Email,
                        "cve" => IocType::CVE,
                        "bitcoin" | "btc" | "crypto" | "wallet" => IocType::BitcoinWallet,
                        _ => {
                            state.status_message = "Invalid IOC type".to_string();
                            return;
                        }
                    };
                    state.type_filters.clear();
                    state.type_filters.insert(t.clone());
                    state.selected_index = 0;
                    state.status_message = format!("Filtering by type: {}", t);
                }
                _ => {
                    state.status_message =
                        "Invalid filter command. Use tag, type, clear".to_string();
                }
            }
        }
        "sort" => {
            if parts.len() < 2 {
                state.status_message =
                    "Usage: :sort <id|value|type|priority|tag> [asc|desc]".to_string();
                return;
            }
            let key = match parts[1].to_lowercase().as_str() {
                "id" => SortBy::Id,
                "value" | "val" => SortBy::Value,
                "type" => SortBy::Type,
                "priority" | "pri" => SortBy::Priority,
                "tag" => SortBy::Tag,
                _ => {
                    state.status_message = "Invalid sort key".to_string();
                    return;
                }
            };
            state.sort_by = key;
            if parts.len() >= 3 {
                state.sort_order = match parts[2].to_lowercase().as_str() {
                    "desc" | "descending" => SortOrder::Descending,
                    _ => SortOrder::Ascending,
                };
            }
            state.status_message = format!("Sorted by {} {}", state.sort_by, state.sort_order);
        }
        "limit" => {
            if parts.len() < 2 {
                state.status_message = format!("Current limit: {}", state.max_ioc_limit);
                return;
            }
            if let Ok(limit) = parts[1].parse::<usize>() {
                state.max_ioc_limit = limit;
                state.status_message = format!("Set maximum IOC limit to {}", limit);
                state.add_log(&format!("Max IOC limit set to {}", limit));
            } else {
                state.status_message = "Invalid limit number".to_string();
            }
        }
        "dir" => {
            if parts.len() < 2 {
                state.status_message =
                    format!("Current export dir: {}", state.export_dir.display());
                return;
            }
            let path = PathBuf::from(parts[1]);
            state.export_dir = path;
            state.status_message =
                format!("Set export directory to {}", state.export_dir.display());
            state.add_log(&format!(
                "Export directory set to {}",
                state.export_dir.display()
            ));
        }
        _ => {
            state.status_message = format!("Unknown command: {}", cmd);
        }
    }
}

fn handle_input_key(state: &mut AppState, key: KeyEvent, _config: &Config) {
    match key.code {
        KeyCode::Esc => {
            state.input_buffer.clear();
            if state.entries.is_empty() {
                state.status_message = "No IOCs loaded. Press I to paste.".to_string();
            }
            state.mode = AppMode::Normal;
        }
        KeyCode::Enter => {
            if state.input_buffer.ends_with('\n') || state.input_buffer.is_empty() {
                if !state.input_buffer.trim().is_empty() {
                    let (entries, total, dupes) = parser::parse_iocs(&state.input_buffer);
                    let count = entries.len();
                    let max = state.max_ioc_limit;
                    let mut new_entries = entries;
                    if state.entries.len() + new_entries.len() > max {
                        let allowed = max.saturating_sub(state.entries.len());
                        new_entries.truncate(allowed);
                        state.status_message = format!(
                            "Limit reached! Added {} of {} (max {})",
                            allowed, count, max
                        );
                        state.add_log(&format!(
                            "Pasted {} items, added {} of {} due to max limit",
                            total, allowed, count
                        ));
                    } else {
                        state.status_message = format!(
                            "Parsed {} unique IOCs ({} total, {} duplicates)",
                            count, total, dupes
                        );
                        state.add_log(&format!(
                            "Pasted & parsed {} unique IOCs ({} duplicates)",
                            count, dupes
                        ));
                    }
                    let start_id = state.entries.last().map_or(1, |e| e.id + 1);
                    for (i, e) in new_entries.iter_mut().enumerate() {
                        e.id = start_id + i;
                    }
                    state.total_input_count += total;
                    state.duplicate_count += dupes;
                    state.entries.extend(new_entries);
                    state.has_unsaved_changes = true;
                }
                state.input_buffer.clear();
                state.mode = AppMode::Normal;
            } else {
                state.input_buffer.push('\n');
            }
        }
        KeyCode::Char(c) => state.input_buffer.push(c),
        KeyCode::Backspace => {
            state.input_buffer.pop();
        }
        _ => {}
    }
}

fn handle_note_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.note_buffer.clear();
            state.mode = AppMode::Normal;
        }
        KeyCode::Enter => {
            let note = state.note_buffer.clone();
            let mut note_saved = None;
            if let Some(e) = state.selected_entry_mut() {
                e.note = note.clone();
                note_saved = Some(e.value.clone());
                state.has_unsaved_changes = true;
            }
            if let Some(val) = note_saved {
                state.add_log(&format!("Updated note for {}: '{}'", val, note));
                state.status_message = "Note saved".to_string();
            }
            state.note_buffer.clear();
            state.mode = AppMode::Normal;
        }
        KeyCode::Char(c) => state.note_buffer.push(c),
        KeyCode::Backspace => {
            state.note_buffer.pop();
        }
        _ => {}
    }
}

fn handle_search_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            state.search_query.clear();
            state.mode = AppMode::Normal;
            state.status_message = "Search cleared".to_string();
        }
        KeyCode::Enter => {
            state.mode = AppMode::Normal;
            let count = state.get_filtered_entries().len();
            state.status_message = format!("Search applied: {} matching entries", count);
            state.add_log(&format!(
                "Search filter applied for '{}'",
                state.search_query
            ));
            state.selected_index = 0;
        }
        KeyCode::Char(c) => {
            state.search_query.push(c);
        }
        KeyCode::Backspace => {
            state.search_query.pop();
        }
        _ => {}
    }
}

fn handle_sort_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => {
            state.mode = AppMode::Normal;
        }
        KeyCode::Char('1') => {
            state.sort_by = SortBy::Id;
            state.status_message = "Sorted by ID".to_string();
            state.add_log("Sorted by ID");
        }
        KeyCode::Char('2') => {
            state.sort_by = SortBy::Value;
            state.status_message = "Sorted by Value".to_string();
            state.add_log("Sorted by Value");
        }
        KeyCode::Char('3') => {
            state.sort_by = SortBy::Type;
            state.status_message = "Sorted by Type".to_string();
            state.add_log("Sorted by Type");
        }
        KeyCode::Char('4') => {
            state.sort_by = SortBy::Priority;
            state.status_message = "Sorted by Priority".to_string();
            state.add_log("Sorted by Priority");
        }
        KeyCode::Char('5') => {
            state.sort_by = SortBy::Tag;
            state.status_message = "Sorted by Tag".to_string();
            state.add_log("Sorted by Tag");
        }
        KeyCode::Char('o') | KeyCode::Char('O') => {
            state.sort_order = match state.sort_order {
                SortOrder::Ascending => SortOrder::Descending,
                SortOrder::Descending => SortOrder::Ascending,
            };
            state.status_message = format!("Sort order toggled to {}", state.sort_order);
        }
        _ => {}
    }
}

fn handle_type_filter_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => {
            state.mode = AppMode::Normal;
            state.selected_index = 0;
        }
        KeyCode::Char('1') => toggle_type_filter(state, IocType::IPv4),
        KeyCode::Char('2') => toggle_type_filter(state, IocType::IPv6),
        KeyCode::Char('3') => toggle_type_filter(state, IocType::Domain),
        KeyCode::Char('4') => toggle_type_filter(state, IocType::URL),
        KeyCode::Char('5') => toggle_type_filter(state, IocType::MD5),
        KeyCode::Char('6') => toggle_type_filter(state, IocType::SHA1),
        KeyCode::Char('7') => toggle_type_filter(state, IocType::SHA256),
        KeyCode::Char('8') => toggle_type_filter(state, IocType::Email),
        KeyCode::Char('9') => toggle_type_filter(state, IocType::CVE),
        KeyCode::Char('0') => toggle_type_filter(state, IocType::BitcoinWallet),
        KeyCode::Char('a') | KeyCode::Char('A') => {
            state.type_filters.clear();
            state.status_message = "All types enabled".to_string();
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            state.type_filters.clear();
            state.status_message = "Type filter cleared".to_string();
        }
        _ => {}
    }
}

fn handle_export_key(state: &mut AppState, key: KeyEvent, config: &Config) {
    match key.code {
        KeyCode::Char('j') | KeyCode::Char('J') => {
            let mut state_config = config.clone();
            state_config.export_dir = state.export_dir.clone();
            state_config.max_ioc_limit = state.max_ioc_limit;

            match export::export_json(state, &state_config) {
                Ok(path) => {
                    state.status_message = format!("Exported JSON: {}", path);
                    state.add_log(&format!("Exported JSON to {}", path));
                }
                Err(e) => state.status_message = format!("Export error: {}", e),
            }
            state.mode = AppMode::Normal;
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            let mut state_config = config.clone();
            state_config.export_dir = state.export_dir.clone();
            state_config.max_ioc_limit = state.max_ioc_limit;

            match export::export_csv(state, &state_config) {
                Ok(path) => {
                    state.status_message = format!("Exported CSV: {}", path);
                    state.add_log(&format!("Exported CSV to {}", path));
                }
                Err(e) => state.status_message = format!("Export error: {}", e),
            }
            state.mode = AppMode::Normal;
        }
        KeyCode::Esc => state.mode = AppMode::Normal,
        _ => {}
    }
}

fn handle_delete_key(state: &mut AppState, key: KeyEvent) {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => {
            if state.selected_ids.is_empty() {
                let val = state
                    .selected_entry()
                    .map(|e| e.value.clone())
                    .unwrap_or_default();
                state.delete_selected();
                state.status_message = format!("Deleted: {}", truncate(&val, 30));
            } else {
                let count = state.selected_ids.len();
                state.delete_selected_bulk();
                state.status_message = format!("Deleted {} indicators", count);
            }
            state.mode = AppMode::Normal;
        }
        _ => state.mode = AppMode::Normal,
    }
}

fn open_all_urls(state: &mut AppState) {
    let info = state
        .selected_entry()
        .map(|e| (e.value.clone(), e.lookup_urls.clone()));
    if let Some((val, urls)) = info {
        let count = urls.len();
        for url in urls {
            let _ = open::that(&url.url);
        }
        state.status_message = format!("Opened {} URLs in browser", count);
        state.add_log(&format!("Batch opened {} lookup links for {}", count, val));
    }
}

fn open_url_by_index(state: &mut AppState, idx: usize) {
    let info = state
        .selected_entry()
        .map(|e| (e.value.clone(), e.lookup_urls.clone()));
    if let Some((val, urls)) = info {
        if let Some(lu) = urls.get(idx) {
            let url = lu.url.clone();
            let platform = lu.platform.clone();
            let _ = open::that(&url);
            state.status_message = format!("Opened {} in browser", platform);
            state.add_log(&format!("Opened {} lookup for {}", platform, val));
        }
    }
}

fn copy_to_clipboard(state: &mut AppState) {
    let text_to_copy = if state.selected_ids.is_empty() {
        state
            .selected_entry()
            .map(|e| e.value.clone())
            .unwrap_or_default()
    } else {
        let selected_set = &state.selected_ids;
        let mut values = Vec::new();
        for e in &state.entries {
            if selected_set.contains(&e.id) {
                values.push(e.value.clone());
            }
        }
        values.join("\n")
    };

    if text_to_copy.is_empty() {
        return;
    }

    match arboard::Clipboard::new() {
        Ok(mut clip) => match clip.set_text(&text_to_copy) {
            Ok(_) => {
                if state.selected_ids.is_empty() {
                    state.status_message = format!("Copied: {}", truncate(&text_to_copy, 30));
                } else {
                    state.status_message =
                        format!("Copied {} selected values", state.selected_ids.len());
                }
            }
            Err(e) => state.status_message = format!("Clipboard error: {}", e),
        },
        Err(e) => state.status_message = format!("Clipboard error: {}", e),
    }
}
