mod app;
mod event;
mod text_input;
mod ui;
use std::io;

use app::App;
use crossterm::{
    cursor::Show,
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, prelude::CrosstermBackend};

use crate::{
    config::{load_cli_config, sdk_config},
    error::CliError,
};

pub fn user_agent() -> String {
    format!("s2-tui/{}", env!("CARGO_PKG_VERSION"))
}

/// RAII guard that restores the terminal on drop, including on panic.
struct TerminalGuard;

impl TerminalGuard {
    fn acquire() -> Result<Self, CliError> {
        enable_raw_mode()
            .map_err(|e| CliError::RecordReaderInit(format!("terminal setup: {e}")))?;
        let mut stdout = io::stdout();
        if let Err(e) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(CliError::RecordReaderInit(format!("terminal setup: {e}")));
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

pub async fn run() -> Result<(), CliError> {
    // Load config and try to create SDK client
    // If access token is missing, we'll start with Setup screen instead of failing
    let cli_config = load_cli_config()?;
    let s2 = match sdk_config(&cli_config, &user_agent()) {
        Ok(sdk_cfg) => Some(s2_sdk::S2::new(sdk_cfg).map_err(CliError::SdkInit)?),
        Err(_) => None, // No access token - will show setup screen
    };

    let _guard = TerminalGuard::acquire()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)
        .map_err(|e| CliError::RecordReaderInit(format!("terminal setup: {e}")))?;

    // Create and run app
    let app = App::new(s2);
    app.run(&mut terminal).await
}
