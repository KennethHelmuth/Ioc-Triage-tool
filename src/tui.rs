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

fn ioc_color(t: &IocType) -> Color {
    match t {
        IocType::IPv4 | IocType::IPv6 => Color::Cyan,
        IocType::Domain => Color::Magenta,
        IocType::URL => Color::Blue,
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

pub fn draw(f: &mut Frame, state: &AppState, _config: &Config) {
    let size = f.size();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(size);

    draw_header(f, chunks[0], state);
    let show_panel = state.show_side_panel && size.width >= 100 && !state.entries.is_empty();
    if show_panel {
        let mid = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(chunks[1]);
        draw_table(f, mid[0], state);
        draw_side_panel(f, mid[1], state);
    } else {
        draw_table(f, chunks[1], state);
    }
    draw_status_bar(f, chunks[2], state);

    match state.mode {
        AppMode::InputPaste => draw_input_modal(f, size, state),
        AppMode::Help => draw_help_overlay(f, size),
        AppMode::NoteEditing => draw_note_editor(f, size, state),
        AppMode::ExportConfirm => draw_export_confirm(f, size),
        AppMode::DeleteConfirm => draw_delete_confirm(f, size, state),
        AppMode::Normal => {}
    }
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState) {
    let tagged = state.tagged_count();
    let total = state.entries.len();
    let text = format!(
        "  IOC TRIAGE CONSOLE   [{} indicators | {} tagged]",
        total, tagged
    );
    let p = Paragraph::new(text)
        .style(
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(p, area);
}

fn draw_table(f: &mut Frame, area: Rect, state: &AppState) {
    let visible = (area.height as usize).saturating_sub(3).max(5);
    let selected = state.selected_index;
    let offset = if selected < state.scroll_offset {
        selected
    } else if selected >= state.scroll_offset + visible {
        selected.saturating_sub(visible - 1)
    } else {
        state.scroll_offset
    };

    let header = Row::new(vec![
        Cell::from(" # ").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Indicator").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Type").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Pri").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Tag").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("Note").style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1)
    .bottom_margin(1);

    let rows: Vec<Row> = state
        .entries
        .iter()
        .skip(offset)
        .take(visible)
        .map(|e| {
            let is_sel = e.id == state.entries.get(selected).map_or(0, |s| s.id);
            let base = if is_sel {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let note_display = if e.note.is_empty() {
                String::new()
            } else {
                truncate(&e.note, 15)
            };
            Row::new(vec![
                Cell::from(format!("{:>3}", e.id)).style(base),
                Cell::from(truncate(&e.value, 40)).style(base.fg(if is_sel {
                    Color::Yellow
                } else {
                    ioc_color(&e.ioc_type)
                })),
                Cell::from(e.ioc_type.to_string()).style(base.fg(ioc_color(&e.ioc_type))),
                Cell::from(e.priority.to_string()).style(base.fg(priority_color(&e.priority))),
                Cell::from(e.tag.to_string()).style(if is_sel { base } else { tag_style(&e.tag) }),
                Cell::from(note_display).style(base),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(5),
        Constraint::Min(20),
        Constraint::Length(8),
        Constraint::Length(5),
        Constraint::Length(5),
        Constraint::Length(17),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Indicators ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(table, area);
}

fn draw_side_panel(f: &mut Frame, area: Rect, state: &AppState) {
    let entry = match state.selected_entry() {
        Some(e) => e,
        None => return,
    };

    let mut lines: Vec<Line> = Vec::new();
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
    for (i, lu) in entry.lookup_urls.iter().enumerate() {
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

    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("Created: ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            entry.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            Style::default().fg(Color::DarkGray),
        ),
    ]));

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
    let keys = vec![
        Span::styled(" [↑↓]", Style::default().fg(Color::Cyan)),
        Span::raw(" Nav "),
        Span::styled("[O]", Style::default().fg(Color::Cyan)),
        Span::raw(" Open "),
        Span::styled("[T]", Style::default().fg(Color::Cyan)),
        Span::raw(" Tag "),
        Span::styled("[N]", Style::default().fg(Color::Cyan)),
        Span::raw(" Note "),
        Span::styled("[E]", Style::default().fg(Color::Cyan)),
        Span::raw(" Export "),
        Span::styled("[C]", Style::default().fg(Color::Cyan)),
        Span::raw(" Copy "),
        Span::styled("[D]", Style::default().fg(Color::Cyan)),
        Span::raw(" Del "),
        Span::styled("[?]", Style::default().fg(Color::Cyan)),
        Span::raw(" Help "),
        Span::styled("[Q]", Style::default().fg(Color::Cyan)),
        Span::raw(" Quit  "),
        Span::styled(&state.status_message, Style::default().fg(Color::Green)),
    ];
    let bar = Paragraph::new(Line::from(keys))
        .style(Style::default().bg(Color::DarkGray).fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::TOP)
                .border_style(Style::default().fg(Color::DarkGray)),
        );
    f.render_widget(bar, area);
}

fn centered_rect(w: u16, h: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect::new(x, y, w.min(area.width), h.min(area.height))
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
    let modal = centered_rect(60, 22, area);
    f.render_widget(Clear, modal);
    let help_text = vec![
        Line::from(Span::styled(
            "  Keybindings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from("  ↑/↓         Navigate rows"),
        Line::from("  PgUp/PgDn   Jump 10 rows"),
        Line::from("  Home/End    Jump to first/last"),
        Line::from("  O           Open all lookup URLs"),
        Line::from("  1-9         Open specific lookup URL"),
        Line::from("  T           Cycle tag forward"),
        Line::from("  Shift+T     Cycle tag backward"),
        Line::from("  N           Edit note"),
        Line::from("  E           Export session"),
        Line::from("  C           Copy indicator to clipboard"),
        Line::from("  D           Delete selected indicator"),
        Line::from("  I           Paste new IOCs"),
        Line::from("  ?           Toggle this help"),
        Line::from("  Q / Ctrl+C  Quit"),
        Line::from(""),
        Line::from(Span::styled(
            "  Press any key to close",
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
    let val = state.selected_entry().map_or("", |e| &e.value);
    let text = vec![
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
    ];
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
    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => return Ok(true),
        KeyCode::Up => state.move_up(1),
        KeyCode::Down => state.move_down(1),
        KeyCode::PageUp => state.move_up(10),
        KeyCode::PageDown => state.move_down(10),
        KeyCode::Home => state.jump_home(),
        KeyCode::End => state.jump_end(),
        KeyCode::Char('o') | KeyCode::Char('O') => open_all_urls(state),
        KeyCode::Char('t') => {
            if let Some(idx) = state
                .entries
                .get(state.selected_index)
                .map(|_| state.selected_index)
            {
                state.entries[idx].tag = state.entries[idx].tag.cycle_forward();
                state.has_unsaved_changes = true;
                state.status_message = format!("Tag set to {}", state.entries[idx].tag);
            }
        }
        KeyCode::Char('T') => {
            if let Some(idx) = state
                .entries
                .get(state.selected_index)
                .map(|_| state.selected_index)
            {
                state.entries[idx].tag = state.entries[idx].tag.cycle_backward();
                state.has_unsaved_changes = true;
                state.status_message = format!("Tag set to {}", state.entries[idx].tag);
            }
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
        KeyCode::Char('c') => copy_to_clipboard(state),
        KeyCode::Char('d') => {
            if !state.entries.is_empty() {
                state.mode = AppMode::DeleteConfirm;
            }
        }
        KeyCode::Char('i') | KeyCode::Char('I') => {
            state.input_buffer.clear();
            state.mode = AppMode::InputPaste;
        }
        KeyCode::Char('?') => state.mode = AppMode::Help,
        KeyCode::Char(c) if c.is_ascii_digit() && c != '0' => {
            let idx = (c as u8 - b'1') as usize;
            open_url_by_index(state, idx);
        }
        _ => {}
    }
    Ok(false)
}

fn handle_input_key(state: &mut AppState, key: KeyEvent, config: &Config) {
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
                    let max = config.max_ioc_limit;
                    let mut new_entries = entries;
                    if state.entries.len() + new_entries.len() > max {
                        let allowed = max.saturating_sub(state.entries.len());
                        new_entries.truncate(allowed);
                        state.status_message = format!(
                            "Limit reached! Added {} of {} (max {})",
                            allowed, count, max
                        );
                    } else {
                        state.status_message = format!(
                            "Parsed {} unique IOCs ({} total, {} duplicates)",
                            count, total, dupes
                        );
                    }
                    // Re-ID entries to continue from existing
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
            if let Some(e) = state.selected_entry_mut() {
                e.note = note;
                state.has_unsaved_changes = true;
            }
            state.status_message = "Note saved".to_string();
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

fn handle_export_key(state: &mut AppState, key: KeyEvent, config: &Config) {
    match key.code {
        KeyCode::Char('j') | KeyCode::Char('J') => {
            match export::export_json(state, config) {
                Ok(path) => state.status_message = format!("Exported JSON: {}", path),
                Err(e) => state.status_message = format!("Export error: {}", e),
            }
            state.mode = AppMode::Normal;
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            match export::export_csv(state, config) {
                Ok(path) => state.status_message = format!("Exported CSV: {}", path),
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
            let val = state
                .selected_entry()
                .map(|e| e.value.clone())
                .unwrap_or_default();
            state.delete_selected();
            state.status_message = format!("Deleted: {}", truncate(&val, 30));
            state.mode = AppMode::Normal;
        }
        _ => state.mode = AppMode::Normal,
    }
}

fn open_all_urls(state: &mut AppState) {
    if let Some(entry) = state.selected_entry() {
        let urls: Vec<String> = entry.lookup_urls.iter().map(|l| l.url.clone()).collect();
        let count = urls.len();
        for url in urls {
            let _ = open::that(&url);
        }
        state.status_message = format!("Opened {} URLs in browser", count);
    }
}

fn open_url_by_index(state: &mut AppState, idx: usize) {
    if let Some(entry) = state.selected_entry() {
        if let Some(lu) = entry.lookup_urls.get(idx) {
            let url = lu.url.clone();
            let platform = lu.platform.clone();
            let _ = open::that(&url);
            state.status_message = format!("Opened {} in browser", platform);
        }
    }
}

fn copy_to_clipboard(state: &mut AppState) {
    if let Some(entry) = state.selected_entry() {
        let val = entry.value.clone();
        match arboard::Clipboard::new() {
            Ok(mut clip) => match clip.set_text(&val) {
                Ok(_) => state.status_message = format!("Copied: {}", truncate(&val, 30)),
                Err(e) => state.status_message = format!("Clipboard error: {}", e),
            },
            Err(e) => state.status_message = format!("Clipboard error: {}", e),
        }
    }
}
