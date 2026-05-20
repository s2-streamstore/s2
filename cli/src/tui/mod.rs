mod app;
mod event;
mod text_input;
mod ui;
use std::{
    io, panic,
    sync::atomic::{AtomicBool, Ordering},
};

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

static TERMINAL_ACTIVE: AtomicBool = AtomicBool::new(false);
static PANIC_HOOK_INSTALLED: AtomicBool = AtomicBool::new(false);

pub fn user_agent() -> String {
    format!("s2-tui/{}", env!("CARGO_PKG_VERSION"))
}

fn restore_terminal() {
    let _ = execute!(io::stdout(), Show, LeaveAlternateScreen);
    let _ = disable_raw_mode();
}

fn restore_terminal_if_active() {
    if TERMINAL_ACTIVE.swap(false, Ordering::SeqCst) {
        restore_terminal();
    }
}

fn install_terminal_panic_hook() {
    if PANIC_HOOK_INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }

    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        restore_terminal_if_active();
        previous_hook(info);
    }));
}

/// Guard that restores the terminal on normal exit.
///
/// The panic hook handles panic cleanup because this workspace uses
/// `panic = "abort"`, which skips destructors.
struct TerminalGuard;

impl TerminalGuard {
    fn acquire() -> Result<Self, CliError> {
        install_terminal_panic_hook();
        enable_raw_mode()
            .map_err(|e| CliError::RecordReaderInit(format!("terminal setup: {e}")))?;
        TERMINAL_ACTIVE.store(true, Ordering::SeqCst);
        let mut stdout = io::stdout();
        if let Err(e) = execute!(stdout, EnterAlternateScreen) {
            restore_terminal_if_active();
            return Err(CliError::RecordReaderInit(format!("terminal setup: {e}")));
        }
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal_if_active();
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
