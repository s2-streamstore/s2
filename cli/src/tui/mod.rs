mod app;
mod event;
mod ui;

use std::io;

use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::config::{load_cli_config, sdk_config};
use crate::error::CliError;
use app::App;

pub async fn run() -> Result<(), CliError> {
    // Load config and try to create SDK client
    // If access token is missing, we'll start with Setup screen instead of failing
    let cli_config = load_cli_config()?;
    let s2 = match sdk_config(&cli_config) {
        Ok(sdk_cfg) => Some(s2_sdk::S2::new(sdk_cfg).map_err(CliError::SdkInit)?),
        Err(_) => None, // No access token - will show setup screen
    };

    // Setup terminal
    enable_raw_mode().map_err(|e| CliError::RecordReaderInit(format!("terminal setup: {e}")))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)
        .map_err(|e| CliError::RecordReaderInit(format!("terminal setup: {e}")))?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)
        .map_err(|e| CliError::RecordReaderInit(format!("terminal setup: {e}")))?;

    // Create and run app
    let app = App::new(s2);
    let result = app.run(&mut terminal).await;

    // Restore terminal - attempt all cleanup steps even if some fail
    // This is critical: a partially restored terminal leaves the user's shell broken
    let mut cleanup_errors = Vec::new();

    if let Err(e) = disable_raw_mode() {
        cleanup_errors.push(format!("disable_raw_mode: {e}"));
    }

    if let Err(e) = execute!(terminal.backend_mut(), LeaveAlternateScreen) {
        cleanup_errors.push(format!("leave_alternate_screen: {e}"));
    }

    if let Err(e) = terminal.show_cursor() {
        cleanup_errors.push(format!("show_cursor: {e}"));
    }

    // Log cleanup errors to stderr (won't be visible in alternate screen anyway)
    if !cleanup_errors.is_empty() {
        eprintln!(
            "Warning: terminal cleanup errors: {}",
            cleanup_errors.join(", ")
        );
    }

    result
}
