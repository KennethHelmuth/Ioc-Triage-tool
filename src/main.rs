mod config;
mod export;
mod lookup;
mod models;
mod parser;
mod tui;

use config::Config;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use models::{AppState, AppMode};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Read, IsTerminal};
use std::panic;

fn main() -> anyhow::Result<()> {
    let config = Config::from_env();

    // Check for piped stdin or command-line file arguments first
    let initial_input = read_initial_input()?;

    // Set panic hook to restore terminal before printing panic info
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut state = AppState::new();
    state.export_dir = config.export_dir.clone();
    state.max_ioc_limit = config.max_ioc_limit;
    state.add_log("Console session initialized");

    // Populate with initial input if present
    if let Some(input) = initial_input {
        let (entries, total, dupes) = parser::parse_iocs(&input);
        let count = entries.len();
        state.entries = entries;
        state.mode = AppMode::Normal;
        state.total_input_count = total;
        state.duplicate_count = dupes;
        state.status_message = format!(
            "Loaded {} unique IOCs from input ({} total, {} duplicates)",
            count, total, dupes
        );
        state.add_log(&format!("Imported {} unique indicators ({} total)", count, total));
    }

    // Main event loop
    let result = run_loop(&mut terminal, &mut state, &config);

    // Always restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn read_initial_input() -> anyhow::Result<Option<String>> {
    // 1. Check stdin if not a terminal (piped input)
    if !io::stdin().is_terminal() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        if !input.trim().is_empty() {
            return Ok(Some(input));
        }
    }

    // 2. Check command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 {
        let path = &args[1];
        if path == "-h" || path == "--help" {
            println!("🛡️  IOC Triage Console — Help");
            println!("\nUsage:");
            println!("  ioc-triage                  Interactive mode (starts with paste modal)");
            println!("  ioc-triage <file>           Parse IOCs from <file> and start triage console");
            println!("  cat logs.txt | ioc-triage   Parse IOCs from stdin pipe and start triage console");
            std::process::exit(0);
        }
        let content = std::fs::read_to_string(path)?;
        return Ok(Some(content));
    }

    Ok(None)
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    state: &mut AppState,
    config: &Config,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| tui::draw(f, state, config))?;

        match tui::handle_event(state, config) {
            Ok(should_quit) => {
                if should_quit {
                    break;
                }
            }
            Err(e) => {
                state.status_message = format!("Error: {}", e);
            }
        }
    }
    Ok(())
}
