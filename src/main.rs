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
use models::AppState;
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;
use std::panic;

fn main() -> anyhow::Result<()> {
    let config = Config::from_env();

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

    // Main event loop
    let result = run_loop(&mut terminal, &mut state, &config);

    // Always restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
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
