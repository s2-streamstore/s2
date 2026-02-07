use std::collections::VecDeque;

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Padding, Paragraph},
};

use super::app::{
    AccessTokensState, AgoUnit, App, AppendViewState, BasinsState, BenchViewState,
    CompressionOption, ExpiryOption, InputMode, MessageLevel, MetricCategory, MetricsType,
    MetricsViewState, PipState, ReadStartFrom, ReadViewState, RetentionPolicyOption, Screen,
    SettingsState, SetupState, StreamDetailState, StreamsState, Tab,
};
use crate::types::{StorageClass, TimestampingMode};

const GREEN: Color = Color::Rgb(34, 197, 94);
const YELLOW: Color = Color::Rgb(250, 204, 21);
const RED: Color = Color::Rgb(239, 68, 68);
const CYAN: Color = Color::Rgb(34, 211, 238);
const BLUE: Color = Color::Rgb(59, 130, 246);
const PURPLE: Color = Color::Rgb(167, 139, 250);
const ORANGE: Color = Color::Rgb(251, 146, 60);
const WHITE: Color = Color::Rgb(255, 255, 255);

const GRAY_100: Color = Color::Rgb(243, 244, 246);
const GRAY_200: Color = Color::Rgb(180, 180, 180);
const GRAY_300: Color = Color::Rgb(150, 150, 150);
const GRAY_400: Color = Color::Rgb(120, 120, 120);
const GRAY_500: Color = Color::Rgb(107, 114, 128);
const GRAY_600: Color = Color::Rgb(100, 100, 100);
const GRAY_700: Color = Color::Rgb(80, 80, 80);
const GRAY_750: Color = Color::Rgb(63, 63, 70);
const GRAY_800: Color = Color::Rgb(60, 60, 60);
const GRAY_850: Color = Color::Rgb(50, 50, 50);
const GRAY_900: Color = Color::Rgb(40, 40, 40);

const BG_DARK: Color = Color::Rgb(17, 17, 17);
const BG_PANEL: Color = Color::Rgb(24, 24, 27);
const BG_SELECTED: Color = Color::Rgb(39, 39, 42);

const ACCENT: Color = WHITE;
const SUCCESS: Color = GREEN;
const WARNING: Color = YELLOW;
const ERROR: Color = RED;
const TEXT_PRIMARY: Color = WHITE;
const TEXT_SECONDARY: Color = GRAY_100;
const TEXT_MUTED: Color = GRAY_500;
const BORDER: Color = GRAY_750;
const BORDER_DIM: Color = GRAY_850;
const BORDER_TITLE: Color = GRAY_900;

const BADGE_ACTIVE: Color = Color::Rgb(22, 101, 52);
const BADGE_PENDING: Color = Color::Rgb(113, 63, 18);
const BADGE_DANGER: Color = Color::Rgb(127, 29, 29);

const STAT_MIN: Color = Color::Rgb(96, 165, 250);
const STAT_MAX: Color = Color::Rgb(251, 191, 36);
const STAT_AVG: Color = PURPLE;

const GREEN_BRIGHT: Color = Color::Rgb(34, 197, 94);
const GREEN_LIGHT: Color = Color::Rgb(74, 222, 128);
const GREEN_LIGHTER: Color = Color::Rgb(134, 239, 172);
const GREEN_PALE: Color = Color::Rgb(187, 247, 208);
const GREEN_PALEST: Color = Color::Rgb(220, 252, 231);

const CHART_PURPLE: Color = Color::Rgb(139, 92, 246);
const CHART_VIOLET: Color = Color::Rgb(124, 58, 237);
const CHART_INDIGO: Color = Color::Rgb(99, 102, 241);
const CHART_DEEP_INDIGO: Color = Color::Rgb(79, 70, 229);
const CHART_BLUE: Color = Color::Rgb(59, 130, 246);
const CHART_ROYAL_BLUE: Color = Color::Rgb(37, 99, 235);
const CHART_LIGHT_BLUE: Color = Color::Rgb(96, 165, 250);
const CHART_PALE_BLUE: Color = Color::Rgb(147, 197, 253);
const CHART_YELLOW: Color = Color::Rgb(250, 204, 21);
const CHART_ORANGE: Color = Color::Rgb(251, 146, 60);

const STORAGE_EXPRESS: Color = ORANGE;
const STORAGE_STANDARD: Color = Color::Rgb(147, 197, 253);

const TIME_RECENT: Color = GREEN_LIGHT;
const TIME_MODERATE: Color = YELLOW;
const TIME_OLD: Color = GRAY_200;

const CURSOR: &str = "▎";
const SELECTED_INDICATOR: &str = " ▸ ";
const UNSELECTED_INDICATOR: &str = "   ";

/// Minimum dialog dimensions to ensure readability
const MIN_DIALOG_WIDTH: u16 = 60;
const MIN_DIALOG_HEIGHT: u16 = 20;

/// Help descriptions for TUI options.
/// Source: https://github.com/s2-streamstore/s2-specs/blob/main/s2/v1/openapi.json
mod help_text {
    // Record format (s2-format header) - exact from spec
    pub const FORMAT_TEXT: &str = "Plain text, one record per line. No headers.";
    pub const FORMAT_JSON: &str = "Efficient transmission and storage of Unicode data (UTF-8)."; // "raw" format
    pub const FORMAT_JSON_BASE64: &str = "Safe transmission with efficient storage of binary data."; // "base64" format

    // Storage class - spec has no descriptions, these are functional
    pub const STORAGE_DEFAULT: &str = "Use basin's default storage class.";
    pub const STORAGE_STANDARD: &str = "Standard storage class for recent writes.";
    pub const STORAGE_EXPRESS: &str = "Express storage class, optimized for performance.";

    // Timestamping mode - spec has no descriptions, these are functional
    pub const TS_DEFAULT: &str = "Use basin's default timestamping mode.";
    pub const TS_CLIENT_PREFER: &str = "Use client timestamp if provided, else arrival time.";
    pub const TS_CLIENT_REQUIRE: &str = "Require client timestamp, reject if missing.";
    pub const TS_ARRIVAL: &str = "Always use server arrival time.";

    // Uncapped - exact from spec
    pub const TS_UNCAPPED: &str = "Allow client timestamps to exceed arrival time.";
    pub const TS_CAPPED: &str = "Client timestamps capped at arrival time.";

    // Retention - exact from spec
    pub const RETENTION_INFINITE: &str = "Retain records unless explicitly trimmed.";
    pub const RETENTION_AGE: &str = "Auto-trim records older than threshold (seconds).";

    // Delete on empty - exact from spec
    pub const DELETE_NEVER: &str = "Set to 0 to disable delete-on-empty.";
    pub const DELETE_THRESHOLD: &str = "Minimum age (seconds) before empty stream can be deleted.";

    // Clamp - functional description
    pub const CLAMP_ON: &str = "Clamp start position to stream bounds.";
    pub const CLAMP_OFF: &str = "Error if start position out of bounds.";

    // Auto-create streams - exact from spec
    pub const AUTO_CREATE_APPEND: &str = "Create stream on append if it doesn't exist.";
    pub const AUTO_CREATE_READ: &str = "Create stream on read if it doesn't exist.";

    // Fencing - exact from spec
    pub const FENCE_TOKEN: &str = "Fencing token which can be overridden by a fence command.";
    pub const FENCE_CURRENT: &str = "Current fencing token (empty string if unfenced).";

    // Trim - functional description
    pub const TRIM_SEQ_NUM: &str = "Remove all records before this sequence number.";

    // Match seq_num - exact from spec
    pub const MATCH_SEQ_NUM: &str = "Enforce that the first record's sequence number matches.";

    // Access tokens
    pub const TOKEN_EXPIRY: &str = "When the token becomes invalid.";

    // Append fencing - exact from spec
    pub const APPEND_FENCING: &str = "Enforce fencing token match for this operation.";
}

/// Safely truncate a string to max_len characters, adding suffix if truncated.
/// Returns the original string if it fits, otherwise truncates and adds suffix.
fn truncate_str(s: &str, max_len: usize, suffix: &str) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let truncate_at = max_len.saturating_sub(suffix.len());
        // Find a valid char boundary
        let mut end = truncate_at.min(s.len());
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}{}", &s[..end], suffix)
    }
}

// S2 Logo (shared between splash and setup screens)
const S2_LOGO: &[&str] = &[
    "   █████████████████████████    ",
    "  ██████████████████████████████ ",
    " ███████████████████████████████ ",
    "█████████████████████████████████",
    "█████████████████████████████████  ",
    "███████████████                  ",
    "███████████████                  ",
    "██████████████   ████████████████",
    "██████████████   ████████████████",
    "██████████████   ████████████████",
    "███████████████           ███████",
    "██████████████████          █████",
    "█████████████████████████    ████",
    "█████████████████████████   █████",
    "██████                     ██████",
    "█████                    ████████",
    " ███    ██████████████████████ ",
    "  ██    ██████████████████████ ",
    "         ████████████████████    ",
];

/// Render the S2 logo as styled lines
fn render_logo() -> Vec<Line<'static>> {
    S2_LOGO
        .iter()
        .map(|&line| Line::from(Span::styled(line, Style::default().fg(WHITE))))
        .collect()
}

/// Render a toggle switch with consistent styling
fn render_toggle(on: bool, is_selected: bool) -> Vec<Span<'static>> {
    if on {
        vec![
            Span::styled(
                "",
                Style::default().fg(if is_selected { CYAN } else { GRAY_800 }),
            ),
            Span::styled(" ON ", Style::default().fg(BG_DARK).bg(CYAN).bold()),
            Span::styled("", Style::default().fg(CYAN)),
        ]
    } else {
        vec![
            Span::styled(
                "",
                Style::default().fg(if is_selected { TEXT_MUTED } else { GRAY_800 }),
            ),
            Span::styled(" OFF ", Style::default().fg(TEXT_MUTED).bg(GRAY_800)),
            Span::styled("", Style::default().fg(GRAY_800)),
        ]
    }
}

/// Render a pill-style option selector
fn render_pill(label: &str, is_row_selected: bool, is_active: bool) -> Span<'static> {
    let label = label.to_string();
    if is_active {
        Span::styled(
            format!(" {} ", label),
            Style::default().fg(BG_DARK).bg(CYAN).bold(),
        )
    } else if is_row_selected {
        Span::styled(
            format!(" {} ", label),
            Style::default().fg(TEXT_PRIMARY).bg(GRAY_750),
        )
    } else {
        Span::styled(format!(" {} ", label), Style::default().fg(TEXT_MUTED))
    }
}

/// Render a form field row with selection indicator and label
fn render_field_row(
    field_idx: usize,
    label: &str,
    current_selected: usize,
) -> (Span<'static>, Span<'static>) {
    let is_selected = field_idx == current_selected;
    let indicator = if is_selected {
        Span::styled(SELECTED_INDICATOR, Style::default().fg(CYAN).bold())
    } else {
        Span::raw(UNSELECTED_INDICATOR)
    };
    let label_span = Span::styled(
        format!("{:<15}", label),
        Style::default().fg(if is_selected {
            TEXT_PRIMARY
        } else {
            TEXT_MUTED
        }),
    );
    (indicator, label_span)
}

/// Render a form field row with bold label when selected
fn render_field_row_bold(
    field_idx: usize,
    label: &str,
    current_selected: usize,
) -> (Span<'static>, Span<'static>) {
    let is_selected = field_idx == current_selected;
    let indicator = if is_selected {
        Span::styled(SELECTED_INDICATOR, Style::default().fg(CYAN).bold())
    } else {
        Span::raw(UNSELECTED_INDICATOR)
    };
    let label_style = if is_selected {
        Style::default().fg(TEXT_PRIMARY).bold()
    } else {
        Style::default().fg(TEXT_MUTED)
    };
    (indicator, Span::styled(label.to_string(), label_style))
}

/// Render a primary action button
fn render_button(label: &str, is_selected: bool, is_enabled: bool, color: Color) -> Line<'static> {
    let (btn_fg, btn_bg) = if is_selected && is_enabled {
        (BG_DARK, color)
    } else if is_enabled {
        (color, BG_PANEL)
    } else {
        (GRAY_600, BG_PANEL)
    };

    let indicator = if is_selected {
        Span::styled(SELECTED_INDICATOR, Style::default().fg(CYAN).bold())
    } else {
        Span::raw(UNSELECTED_INDICATOR)
    };

    Line::from(vec![
        indicator,
        Span::styled(
            format!(" ▶ {} ", label),
            Style::default().fg(btn_fg).bg(btn_bg).bold(),
        ),
    ])
}

/// Render a section header with divider line
fn render_section_header(title: &str, width: usize) -> Line<'static> {
    let title_with_spaces = format!("   {} ", title);
    let divider_len = width.saturating_sub(title_with_spaces.len());
    Line::from(vec![
        Span::styled(title_with_spaces, Style::default().fg(CYAN).bold()),
        Span::styled("─".repeat(divider_len), Style::default().fg(GRAY_750)),
    ])
}

/// Render text input with cursor
fn render_text_input_with_cursor(
    value: &str,
    is_editing: bool,
    placeholder: &str,
    color: Color,
    cursor: usize,
) -> Vec<Span<'static>> {
    if value.is_empty() && !is_editing {
        vec![Span::styled(
            placeholder.to_string(),
            Style::default().fg(GRAY_600).italic(),
        )]
    } else if is_editing {
        let cursor = cursor.min(value.len());
        let before = &value[..cursor];
        let after = &value[cursor..];
        vec![
            Span::styled(before.to_string(), Style::default().fg(color)),
            Span::styled(CURSOR, Style::default().fg(CYAN)),
            Span::styled(after.to_string(), Style::default().fg(color)),
        ]
    } else {
        vec![Span::styled(value.to_string(), Style::default().fg(color))]
    }
}

/// Render a search/filter bar with consistent styling
fn render_search_bar(
    filter: &str,
    filter_active: bool,
    placeholder: &str,
) -> (Block<'static>, Line<'static>) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if filter_active { CYAN } else { BORDER }))
        .style(Style::default().bg(BG_PANEL));

    let line = if filter_active {
        Line::from(vec![
            Span::styled(" [/] ", Style::default().fg(CYAN)),
            Span::styled(filter.to_string(), Style::default().fg(TEXT_PRIMARY)),
            Span::styled(CURSOR, Style::default().fg(CYAN)),
        ])
    } else if filter.is_empty() {
        Line::from(vec![Span::styled(
            format!(" [/] {}...", placeholder),
            Style::default().fg(TEXT_MUTED),
        )])
    } else {
        Line::from(vec![
            Span::styled(" [/] ", Style::default().fg(TEXT_MUTED)),
            Span::styled(filter.to_string(), Style::default().fg(TEXT_PRIMARY)),
        ])
    };

    (block, line)
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    f.render_widget(Block::default().style(Style::default().bg(BG_DARK)), area);
    if matches!(app.screen, Screen::Splash) {
        draw_splash(f, area);
        return;
    }
    if matches!(app.screen, Screen::Setup(_)) {
        if let Screen::Setup(state) = &app.screen {
            draw_setup(f, area, state);
        }
        return;
    }
    let show_tabs = matches!(
        app.screen,
        Screen::Basins(_) | Screen::AccessTokens(_) | Screen::Settings(_)
    );

    let chunks = if show_tabs {
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(1), // Tab bar
                Constraint::Min(3),
                Constraint::Length(1), // Status bar
            ])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(0), // No tab bar
                Constraint::Min(3),
                Constraint::Length(1), // Status bar
            ])
            .split(area)
    };
    if show_tabs {
        draw_tab_bar(f, chunks[0], app.tab);
    }
    match &app.screen {
        Screen::Splash => unreachable!(),
        Screen::Setup(_) => unreachable!(), // Handled above
        Screen::Basins(state) => draw_basins(f, chunks[1], state),
        Screen::Streams(state) => draw_streams(f, chunks[1], state),
        Screen::StreamDetail(state) => draw_stream_detail(f, chunks[1], state),
        Screen::ReadView(state) => draw_read_view(f, chunks[1], state),
        Screen::AppendView(state) => draw_append_view(f, chunks[1], state),
        Screen::AccessTokens(state) => draw_access_tokens(f, chunks[1], state),
        Screen::MetricsView(state) => draw_metrics_view(f, chunks[1], state),
        Screen::Settings(state) => draw_settings(f, chunks[1], state),
        Screen::BenchView(state) => draw_bench_view(f, chunks[1], state),
    }
    if let Screen::MetricsView(state) = &app.screen {
        if state.time_picker_open {
            draw_time_picker(f, state);
        }
        if state.calendar_open {
            draw_calendar_picker(f, state);
        }
    }
    draw_status_bar(f, chunks[2], app);
    if app.show_help {
        draw_help_overlay(f, &app.screen);
    }
    if !matches!(app.input_mode, InputMode::Normal) {
        draw_input_dialog(f, &app.input_mode);
    }
    // Draw PiP overlay last so it's on top
    if let Some(ref pip) = app.pip {
        if !pip.minimized {
            draw_pip(f, pip);
        } else {
            draw_pip_minimized(f, pip);
        }
    }
}

fn draw_splash(f: &mut Frame, area: Rect) {
    draw_aurora_background(f, area);

    let mut lines = render_logo();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Streams as a cloud",
        Style::default().fg(WHITE).bold(),
    )));
    lines.push(Line::from(Span::styled(
        "storage primitive",
        Style::default().fg(WHITE).bold(),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "The serverless API for unlimited, durable, real-time streams.",
        Style::default().fg(TEXT_MUTED),
    )));

    let content_height = lines.len() as u16;
    let y = area.y + area.height.saturating_sub(content_height) / 2;

    let centered_area = Rect::new(area.x, y, area.width, content_height.min(area.height));
    let logo_widget = Paragraph::new(lines).alignment(Alignment::Center);
    f.render_widget(logo_widget, centered_area);
}

/// Draw the setup screen (first-time token entry)
fn draw_setup(f: &mut Frame, area: Rect, state: &SetupState) {
    draw_aurora_background(f, area);

    let mut lines = render_logo();
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Streams as a cloud storage primitive",
        Style::default().fg(WHITE).bold(),
    )));
    lines.push(Line::from(Span::styled(
        "The serverless API for unlimited, durable, real-time streams.",
        Style::default().fg(TEXT_MUTED),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(""));
    let token_display = if state.access_token.is_empty() {
        vec![
            Span::styled("Token ", Style::default().fg(TEXT_MUTED)),
            Span::styled("› ", Style::default().fg(BORDER)),
            Span::styled(CURSOR, Style::default().fg(CYAN)),
        ]
    } else {
        let max_width = 40;
        let cursor = state.cursor.min(state.access_token.len());
        let (display, cursor_in_display) = if state.access_token.len() <= max_width {
            (state.access_token.clone(), cursor)
        } else {
            // Show a window around the cursor
            let half = max_width / 2;
            let start = cursor.saturating_sub(half);
            let end = (start + max_width).min(state.access_token.len());
            let start = if end == state.access_token.len() {
                end.saturating_sub(max_width)
            } else {
                start
            };
            (state.access_token[start..end].to_string(), cursor - start)
        };
        let before = &display[..cursor_in_display];
        let after = &display[cursor_in_display..];
        vec![
            Span::styled("Token ", Style::default().fg(TEXT_MUTED)),
            Span::styled("› ", Style::default().fg(CYAN)),
            Span::styled(before.to_string(), Style::default().fg(WHITE)),
            Span::styled(CURSOR, Style::default().fg(CYAN)),
            Span::styled(after.to_string(), Style::default().fg(WHITE)),
        ]
    };
    lines.push(Line::from(token_display));
    lines.push(Line::from(""));
    if let Some(error) = &state.error {
        lines.push(Line::from(Span::styled(
            error.as_str(),
            Style::default().fg(ERROR),
        )));
    } else if state.validating {
        lines.push(Line::from(Span::styled(
            "Validating...",
            Style::default().fg(YELLOW),
        )));
    } else {
        lines.push(Line::from(vec![
            Span::styled("Sign up: ", Style::default().fg(TEXT_MUTED)),
            Span::styled(
                "https://s2.dev/sign-up",
                Style::default().fg(CYAN).underlined(),
            ),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Enter to continue · Esc to quit",
        Style::default().fg(BORDER),
    )));

    let content_height = lines.len() as u16;
    let y = area.y + area.height.saturating_sub(content_height) / 2;
    let centered_area = Rect::new(area.x, y, area.width, content_height.min(area.height));

    let content = Paragraph::new(lines).alignment(Alignment::Center);
    f.render_widget(content, centered_area);
}

/// Draw the settings screen
fn draw_settings(f: &mut Frame, area: Rect, state: &SettingsState) {
    use ratatui::widgets::BorderType;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title bar (consistent height)
            Constraint::Min(1),    // Content
        ])
        .split(area);
    let title_block = Block::default()
        .borders(Borders::BOTTOM)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));
    let title_content = Paragraph::new(Line::from(vec![
        Span::styled(" ⚙ ", Style::default().fg(CYAN)),
        Span::styled("Settings", Style::default().fg(TEXT_PRIMARY).bold()),
    ]))
    .block(title_block);
    f.render_widget(title_content, chunks[0]);
    let content_area = chunks[1];
    let panel_width = 70.min(content_area.width.saturating_sub(4));
    let panel_x = content_area.x + (content_area.width.saturating_sub(panel_width)) / 2;
    let panel_area = Rect::new(
        panel_x,
        content_area.y + 1,
        panel_width,
        content_area.height.saturating_sub(2),
    );

    let settings_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL))
        .padding(Padding::new(2, 2, 1, 1));
    let inner = settings_block.inner(panel_area);
    f.render_widget(settings_block, panel_area);
    let field_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4), // Access Token (label + 3-line bordered input)
            Constraint::Length(4), // Account Endpoint
            Constraint::Length(4), // Basin Endpoint
            Constraint::Length(3), // Compression (label + pills, no border)
            Constraint::Length(1), // Spacer
            Constraint::Length(3), // Save button
            Constraint::Min(1),    // Message/footer
        ])
        .split(inner);

    let is_editing_token = state.editing && state.selected == 0;
    let token_display = if is_editing_token {
        state.access_token.clone()
    } else if state.access_token_masked && !state.access_token.is_empty() {
        format!("{}...", "*".repeat(20.min(state.access_token.len())))
    } else if state.access_token.is_empty() {
        "(not set)".to_string()
    } else {
        state.access_token.clone()
    };

    draw_settings_field(
        f,
        field_chunks[0],
        "Access Token",
        token_display,
        state.selected == 0,
        if is_editing_token {
            Some(state.cursor)
        } else {
            None
        },
        Some("Space to toggle visibility"),
    );
    draw_settings_field(
        f,
        field_chunks[1],
        "Account Endpoint",
        if state.account_endpoint.is_empty() {
            "(default)".to_string()
        } else {
            state.account_endpoint.clone()
        },
        state.selected == 1,
        if state.editing && state.selected == 1 {
            Some(state.cursor)
        } else {
            None
        },
        None,
    );
    draw_settings_field(
        f,
        field_chunks[2],
        "Basin Endpoint",
        if state.basin_endpoint.is_empty() {
            "(default)".to_string()
        } else {
            state.basin_endpoint.clone()
        },
        state.selected == 2,
        if state.editing && state.selected == 2 {
            Some(state.cursor)
        } else {
            None
        },
        None,
    );
    let compression_label = Line::from(vec![Span::styled(
        "Compression",
        Style::default().fg(TEXT_SECONDARY),
    )]);
    f.render_widget(
        Paragraph::new(compression_label),
        Rect::new(
            field_chunks[3].x,
            field_chunks[3].y,
            field_chunks[3].width,
            1,
        ),
    );

    let options = [
        CompressionOption::None,
        CompressionOption::Gzip,
        CompressionOption::Zstd,
    ];
    let pills: Vec<Span> = options
        .iter()
        .map(|opt| {
            let is_selected = *opt == state.compression;
            let style = if is_selected {
                Style::default().fg(BG_DARK).bg(CYAN).bold()
            } else {
                Style::default().fg(TEXT_MUTED).bg(BG_DARK)
            };
            Span::styled(format!(" {} ", opt.as_str()), style)
        })
        .collect();

    let mut pill_line = vec![Span::styled("  ", Style::default())];
    for (i, pill) in pills.into_iter().enumerate() {
        if i > 0 {
            pill_line.push(Span::styled(" ", Style::default()));
        }
        pill_line.push(pill);
    }
    if state.selected == 3 {
        pill_line.push(Span::styled("  ← h/l →", Style::default().fg(TEXT_MUTED)));
    }

    let compression_row = Rect::new(
        field_chunks[3].x,
        field_chunks[3].y + 1,
        field_chunks[3].width,
        1,
    );
    f.render_widget(
        Paragraph::new(Line::from(pill_line)).style(Style::default().bg(BG_DARK)),
        compression_row,
    );
    let save_style = if state.selected == 4 {
        Style::default().fg(BG_DARK).bg(CYAN).bold()
    } else if state.has_changes {
        Style::default().fg(CYAN)
    } else {
        Style::default().fg(TEXT_MUTED)
    };
    let save_text = if state.has_changes {
        " ● Save Changes "
    } else {
        "   Save Changes "
    };
    let save_button = Paragraph::new(Line::from(Span::styled(save_text, save_style)))
        .alignment(Alignment::Center);
    f.render_widget(save_button, field_chunks[5]);
    if let Some(msg) = &state.message {
        let msg_lower = msg.to_lowercase();
        let is_error = msg_lower.contains("error")
            || msg_lower.contains("fail")
            || msg_lower.contains("invalid");
        let msg_style = if is_error {
            Style::default().fg(ERROR)
        } else {
            Style::default().fg(SUCCESS)
        };
        let msg_para = Paragraph::new(Line::from(Span::styled(msg.as_str(), msg_style)))
            .alignment(Alignment::Center);
        f.render_widget(msg_para, field_chunks[6]);
    } else {
        let footer = Paragraph::new(Line::from(Span::styled(
            "j/k navigate • e/Enter edit • r reload",
            Style::default().fg(TEXT_MUTED),
        )))
        .alignment(Alignment::Center);
        f.render_widget(footer, field_chunks[6]);
    }
}

/// Helper to draw a settings field
fn draw_settings_field(
    f: &mut Frame,
    area: Rect,
    label: &str,
    value: String,
    selected: bool,
    cursor: Option<usize>,
    hint: Option<&str>,
) {
    let label_line = Line::from(vec![
        Span::styled(label, Style::default().fg(TEXT_SECONDARY)),
        if let Some(h) = hint {
            Span::styled(format!("  ({})", h), Style::default().fg(TEXT_MUTED))
        } else {
            Span::raw("")
        },
    ]);
    f.render_widget(
        Paragraph::new(label_line),
        Rect::new(area.x, area.y, area.width, 1),
    );

    let border_style = if selected {
        Style::default().fg(CYAN)
    } else {
        Style::default().fg(BORDER)
    };

    let value_display = if let Some(cursor_pos) = cursor {
        let cursor_pos = cursor_pos.min(value.len());
        let before = &value[..cursor_pos];
        let after = &value[cursor_pos..];
        format!("{}█{}", before, after)
    } else {
        value
    };

    let value_style = if value_display.starts_with('(') {
        Style::default().fg(TEXT_MUTED)
    } else {
        Style::default().fg(TEXT_PRIMARY)
    };

    let value_block = Block::default()
        .borders(Borders::ALL)
        .border_style(border_style)
        .style(Style::default().bg(BG_DARK));
    let value_para = Paragraph::new(Span::styled(value_display, value_style))
        .block(value_block)
        .wrap(ratatui::widgets::Wrap { trim: false });

    f.render_widget(value_para, Rect::new(area.x, area.y + 1, area.width, 3));
}

/// Draw a subtle aurora/gradient background effect
/// Optimized to compute one color per row (at center) rather than per-cell
fn draw_aurora_background(f: &mut Frame, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }

    let height = area.height as f64;

    for row in 0..area.height {
        let y = row as f64 / height;

        // Build the row string efficiently - all same character
        let row_str: String = " ".repeat(area.width as usize);

        // Use the row's center color for performance
        // This reduces allocations from O(width) to O(1) per row
        let color = aurora_color_at(0.5, y);

        let line = Line::from(Span::styled(row_str, Style::default().bg(color)));
        let row_area = Rect::new(area.x, area.y + row, area.width, 1);
        f.render_widget(Paragraph::new(line), row_area);
    }
}

/// Compute aurora color at normalized coordinates (0.0-1.0)
fn aurora_color_at(x: f64, y: f64) -> Color {
    // Distance from bottom-right corner
    let dist_br = ((x - 0.8).powi(2) + (y - 0.9).powi(2)).sqrt();
    // Distance from center-bottom
    let dist_cb = ((x - 0.5).powi(2) + (y - 0.85).powi(2)).sqrt();

    // Aurora intensity (stronger near bottom)
    let intensity_br = (1.0 - dist_br * 1.5).max(0.0) * 0.4;
    let intensity_cb = (1.0 - dist_cb * 1.8).max(0.0) * 0.3;
    let intensity = (intensity_br + intensity_cb).min(1.0);

    // Base dark color with subtle blue/teal tint
    let base_r: i32 = 8;
    let base_g: i32 = 12;
    let base_b: i32 = 18;

    // Aurora colors (teal/cyan)
    let aurora_r: i32 = 0;
    let aurora_g: i32 = 40;
    let aurora_b: i32 = 60;

    let r = (base_r as f64 + (aurora_r - base_r) as f64 * intensity) as u8;
    let g = (base_g as f64 + (aurora_g - base_g) as f64 * intensity) as u8;
    let b = (base_b as f64 + (aurora_b - base_b) as f64 * intensity) as u8;

    Color::Rgb(r, g, b)
}

fn draw_tab_bar(f: &mut Frame, area: Rect, current_tab: Tab) {
    let basins_style = if current_tab == Tab::Basins {
        Style::default().fg(CYAN).bold()
    } else {
        Style::default().fg(TEXT_MUTED)
    };

    let tokens_style = if current_tab == Tab::AccessTokens {
        Style::default().fg(CYAN).bold()
    } else {
        Style::default().fg(TEXT_MUTED)
    };

    let settings_style = if current_tab == Tab::Settings {
        Style::default().fg(CYAN).bold()
    } else {
        Style::default().fg(TEXT_MUTED)
    };

    let line = Line::from(vec![
        Span::styled("Basins", basins_style),
        Span::styled("  │  ", Style::default().fg(BORDER)),
        Span::styled("Access Tokens", tokens_style),
        Span::styled("  │  ", Style::default().fg(BORDER)),
        Span::styled("Settings", settings_style),
        Span::styled("  (Tab to switch)", Style::default().fg(TEXT_MUTED)),
    ]);

    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}

fn draw_access_tokens(f: &mut Frame, area: Rect, state: &AccessTokensState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title bar (consistent height)
            Constraint::Length(3), // Search bar
            Constraint::Length(2), // Header
            Constraint::Min(1),    // Table rows
        ])
        .split(area);
    let count_text = if state.loading {
        " loading...".to_string()
    } else {
        let filtered_count = state
            .tokens
            .iter()
            .filter(|t| {
                state.filter.is_empty()
                    || t.id.to_lowercase().contains(&state.filter.to_lowercase())
            })
            .count();
        if filtered_count != state.tokens.len() {
            format!("  {}/{} tokens", filtered_count, state.tokens.len())
        } else {
            format!("  {} tokens", state.tokens.len())
        }
    };
    let title_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Access Tokens", Style::default().fg(CYAN).bold()),
            Span::styled(&count_text, Style::default().fg(GRAY_700)),
        ]),
    ];
    let title_block = Paragraph::new(title_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(GRAY_800)),
    );
    f.render_widget(title_block, chunks[0]);

    let (search_block, search_text) =
        render_search_bar(&state.filter, state.filter_active, "Filter by token ID");
    f.render_widget(Paragraph::new(search_text).block(search_block), chunks[1]);

    let header = Line::from(vec![
        Span::styled("  ", Style::default()), // Space for selection prefix
        Span::styled(
            format!("{:<30}", "TOKEN ID"),
            Style::default().fg(TEXT_MUTED).bold(),
        ),
        Span::styled(
            format!("{:<28}", "EXPIRES AT"),
            Style::default().fg(TEXT_MUTED).bold(),
        ),
        Span::styled("SCOPE", Style::default().fg(TEXT_MUTED).bold()),
    ]);
    let header_para = Paragraph::new(header);
    f.render_widget(header_para, chunks[2]);

    let filtered_tokens: Vec<_> = state
        .tokens
        .iter()
        .filter(|t| {
            state.filter.is_empty()
                || t.id
                    .to_string()
                    .to_lowercase()
                    .contains(&state.filter.to_lowercase())
        })
        .collect();

    if state.loading {
        let loading = Paragraph::new(Line::from(Span::styled(
            "Loading access tokens...",
            Style::default().fg(TEXT_MUTED),
        )));
        f.render_widget(loading, chunks[3]);
    } else if filtered_tokens.is_empty() {
        let empty_msg = if state.tokens.is_empty() {
            "No access tokens yet. Press  c  to issue your first token."
        } else {
            "No tokens match the filter. Press  Esc  to clear."
        };
        let empty = Paragraph::new(Line::from(Span::styled(
            empty_msg,
            Style::default().fg(TEXT_MUTED),
        )));
        f.render_widget(empty, chunks[3]);
    } else {
        let table_area = chunks[3];
        let visible_height = table_area.height as usize;
        let total = filtered_tokens.len();
        let selected = state.selected.min(total.saturating_sub(1));

        let scroll_offset = if selected >= visible_height {
            selected - visible_height + 1
        } else {
            0
        };

        for (view_idx, token) in filtered_tokens
            .iter()
            .enumerate()
            .skip(scroll_offset)
            .take(visible_height)
        {
            let y = table_area.y + (view_idx - scroll_offset) as u16;
            if y >= table_area.y + table_area.height {
                break;
            }

            let is_selected = view_idx == selected;
            let row_area = Rect::new(table_area.x, y, table_area.width, 1);

            if is_selected {
                f.render_widget(
                    Block::default().style(Style::default().bg(BG_SELECTED)),
                    row_area,
                );
            }

            let scope_summary = format_scope_summary(token);
            let prefix = if is_selected { "▸ " } else { "  " };
            let token_id_str = token.id.to_string();
            let token_id_display = truncate_str(&token_id_str, 28, "…");
            let expires_str = token.expires_at.to_string();
            let expires_display = truncate_str(&expires_str, 26, "…");

            let name_style = if is_selected {
                Style::default().fg(TEXT_PRIMARY).bold()
            } else {
                Style::default().fg(TEXT_PRIMARY)
            };

            let line = Line::from(vec![
                Span::styled(
                    prefix,
                    Style::default().fg(if is_selected { CYAN } else { TEXT_PRIMARY }),
                ),
                Span::styled(format!("{:<30}", token_id_display), name_style),
                Span::styled(
                    format!("{:<28}", expires_display),
                    Style::default().fg(TEXT_MUTED),
                ),
                Span::styled(scope_summary, Style::default().fg(TEXT_MUTED)),
            ]);

            f.render_widget(Paragraph::new(line), row_area);
        }
    }
}

/// Format a summary of the token scope
fn format_scope_summary(token: &s2_sdk::types::AccessTokenInfo) -> String {
    let ops_count = token.scope.ops.len();
    let has_basins = token.scope.basins.is_some();
    let has_streams = token.scope.streams.is_some();

    let mut parts = vec![format!("{} ops", ops_count)];
    if has_basins {
        parts.push("basins".to_string());
    }
    if has_streams {
        parts.push("streams".to_string());
    }
    parts.join(", ")
}

/// Format a basin matcher for display
fn format_basin_matcher(matcher: &Option<s2_sdk::types::BasinMatcher>) -> String {
    use s2_sdk::types::BasinMatcher;
    match matcher {
        None => "All".to_string(),
        Some(BasinMatcher::None) => "None".to_string(),
        Some(BasinMatcher::Prefix(p)) => format!("Prefix: {}", p),
        Some(BasinMatcher::Exact(e)) => format!("Exact: {}", e),
    }
}

/// Format a stream matcher for display
fn format_stream_matcher(matcher: &Option<s2_sdk::types::StreamMatcher>) -> String {
    use s2_sdk::types::StreamMatcher;
    match matcher {
        None => "All".to_string(),
        Some(StreamMatcher::None) => "None".to_string(),
        Some(StreamMatcher::Prefix(p)) => format!("Prefix: {}", p),
        Some(StreamMatcher::Exact(e)) => format!("Exact: {}", e),
    }
}

/// Format an access token matcher for display
fn format_token_matcher(matcher: &Option<s2_sdk::types::AccessTokenMatcher>) -> String {
    use s2_sdk::types::AccessTokenMatcher;
    match matcher {
        None => "All".to_string(),
        Some(AccessTokenMatcher::None) => "None".to_string(),
        Some(AccessTokenMatcher::Prefix(p)) => format!("Prefix: {}", p),
        Some(AccessTokenMatcher::Exact(e)) => format!("Exact: {}", e),
    }
}

/// Format an operation for display
fn format_operation(op: &s2_sdk::types::Operation) -> String {
    use s2_sdk::types::Operation as SdkOp;
    match op {
        SdkOp::ListBasins => "list_basins",
        SdkOp::CreateBasin => "create_basin",
        SdkOp::DeleteBasin => "delete_basin",
        SdkOp::GetBasinConfig => "get_basin_config",
        SdkOp::ReconfigureBasin => "reconfigure_basin",
        SdkOp::GetBasinMetrics => "get_basin_metrics",
        SdkOp::ListStreams => "list_streams",
        SdkOp::CreateStream => "create_stream",
        SdkOp::DeleteStream => "delete_stream",
        SdkOp::GetStreamConfig => "get_stream_config",
        SdkOp::ReconfigureStream => "reconfigure_stream",
        SdkOp::GetStreamMetrics => "get_stream_metrics",
        SdkOp::CheckTail => "check_tail",
        SdkOp::Read => "read",
        SdkOp::Append => "append",
        SdkOp::Fence => "fence",
        SdkOp::Trim => "trim",
        SdkOp::GetAccountMetrics => "get_account_metrics",
        SdkOp::ListAccessTokens => "list_access_tokens",
        SdkOp::IssueAccessToken => "issue_access_token",
        SdkOp::RevokeAccessToken => "revoke_access_token",
    }
    .to_string()
}

/// Check if operation is account-level
fn is_account_op(op: &s2_sdk::types::Operation) -> bool {
    use s2_sdk::types::Operation as SdkOp;
    matches!(op, SdkOp::ListBasins | SdkOp::GetAccountMetrics)
}

/// Check if operation is basin-level
fn is_basin_op(op: &s2_sdk::types::Operation) -> bool {
    use s2_sdk::types::Operation as SdkOp;
    matches!(
        op,
        SdkOp::CreateBasin
            | SdkOp::DeleteBasin
            | SdkOp::GetBasinConfig
            | SdkOp::ReconfigureBasin
            | SdkOp::ListStreams
            | SdkOp::GetBasinMetrics
    )
}

/// Check if operation is stream-level
fn is_stream_op(op: &s2_sdk::types::Operation) -> bool {
    use s2_sdk::types::Operation as SdkOp;
    matches!(
        op,
        SdkOp::CreateStream
            | SdkOp::DeleteStream
            | SdkOp::GetStreamConfig
            | SdkOp::ReconfigureStream
            | SdkOp::Read
            | SdkOp::Append
            | SdkOp::CheckTail
            | SdkOp::Fence
            | SdkOp::Trim
            | SdkOp::GetStreamMetrics
    )
}

/// Check if operation is token-related
fn is_token_op(op: &s2_sdk::types::Operation) -> bool {
    use s2_sdk::types::Operation as SdkOp;
    matches!(
        op,
        SdkOp::ListAccessTokens | SdkOp::IssueAccessToken | SdkOp::RevokeAccessToken
    )
}

fn draw_metrics_view(f: &mut Frame, area: Rect, state: &MetricsViewState) {
    use s2_sdk::types::Metric;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title with tabs
            Constraint::Length(3), // Stats header row
            Constraint::Min(12),
            Constraint::Length(6), // Timeline (scrollable)
        ])
        .split(area);
    let title = match &state.metrics_type {
        MetricsType::Account => "Account".to_string(),
        MetricsType::Basin { basin_name } => basin_name.to_string(),
        MetricsType::Stream {
            basin_name,
            stream_name,
        } => format!("{}/{}", basin_name, stream_name),
    };

    if matches!(state.metrics_type, MetricsType::Account) {
        let categories = [MetricCategory::ActiveBasins, MetricCategory::AccountOps];

        let mut title_spans: Vec<Span> = vec![
            Span::styled(" [ ", Style::default().fg(BORDER)),
            Span::styled(&title, Style::default().fg(CYAN).bold()),
            Span::styled(" ]  ", Style::default().fg(BORDER)),
        ];

        for (i, cat) in categories.iter().enumerate() {
            if i > 0 {
                title_spans.push(Span::styled(" | ", Style::default().fg(BORDER)));
            }
            let style = if *cat == state.selected_category {
                Style::default().fg(BG_DARK).bg(CYAN).bold()
            } else {
                Style::default().fg(TEXT_MUTED)
            };
            title_spans.push(Span::styled(format!(" {} ", cat.as_str()), style));
        }
        title_spans.push(Span::styled("  ", Style::default()));
        title_spans.push(Span::styled(
            format!("[{}]", state.time_range.as_str()),
            Style::default().fg(CYAN),
        ));

        let title_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CYAN))
            .title_bottom(Line::from(Span::styled(
                " ←/→ category  t time picker ",
                Style::default().fg(TEXT_MUTED),
            )))
            .style(Style::default().bg(BG_PANEL));

        let title_para = Paragraph::new(Line::from(title_spans))
            .block(title_block)
            .alignment(Alignment::Center);
        f.render_widget(title_para, chunks[0]);
    } else if matches!(state.metrics_type, MetricsType::Basin { .. }) {
        let categories = [
            MetricCategory::Storage,
            MetricCategory::AppendOps,
            MetricCategory::ReadOps,
            MetricCategory::AppendThroughput,
            MetricCategory::ReadThroughput,
            MetricCategory::BasinOps,
        ];

        let mut title_spans: Vec<Span> = vec![
            Span::styled(" [ ", Style::default().fg(BORDER)),
            Span::styled(&title, Style::default().fg(CYAN).bold()),
            Span::styled(" ]  ", Style::default().fg(BORDER)),
        ];

        for (i, cat) in categories.iter().enumerate() {
            if i > 0 {
                title_spans.push(Span::styled(" | ", Style::default().fg(BORDER)));
            }
            let style = if *cat == state.selected_category {
                Style::default().fg(BG_DARK).bg(CYAN).bold()
            } else {
                Style::default().fg(TEXT_MUTED)
            };
            title_spans.push(Span::styled(format!(" {} ", cat.as_str()), style));
        }
        title_spans.push(Span::styled("  ", Style::default()));
        title_spans.push(Span::styled(
            format!("[{}]", state.time_range.as_str()),
            Style::default().fg(CYAN),
        ));

        let title_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CYAN))
            .title_bottom(Line::from(Span::styled(
                " ←/→ category  t time picker ",
                Style::default().fg(TEXT_MUTED),
            )))
            .style(Style::default().bg(BG_PANEL));

        let title_para = Paragraph::new(Line::from(title_spans))
            .block(title_block)
            .alignment(Alignment::Center);
        f.render_widget(title_para, chunks[0]);
    } else {
        let title_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CYAN))
            .title_bottom(Line::from(Span::styled(
                " t time picker ",
                Style::default().fg(TEXT_MUTED),
            )))
            .style(Style::default().bg(BG_PANEL));

        let title_para = Paragraph::new(Line::from(vec![
            Span::styled(" [ ", Style::default().fg(BORDER)),
            Span::styled(&title, Style::default().fg(CYAN).bold()),
            Span::styled(" ]  ", Style::default().fg(BORDER)),
            Span::styled(" Storage ", Style::default().fg(BG_DARK).bg(CYAN).bold()),
            Span::styled("  ", Style::default()),
            Span::styled(
                format!("[{}]", state.time_range.as_str()),
                Style::default().fg(CYAN),
            ),
        ]))
        .block(title_block)
        .alignment(Alignment::Center);
        f.render_widget(title_para, chunks[0]);
    }
    if state.loading {
        let loading_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER))
            .style(Style::default().bg(BG_DARK));
        let loading = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "Loading metrics...",
                Style::default().fg(TEXT_MUTED),
            )),
        ])
        .block(loading_block)
        .alignment(Alignment::Center);

        let remaining = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1)])
            .split(chunks[1]);
        f.render_widget(loading, remaining[0]);
        return;
    }

    if state.metrics.is_empty() {
        let empty_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER))
            .style(Style::default().bg(BG_DARK));
        let empty = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "No data in the last 24 hours",
                Style::default().fg(TEXT_MUTED),
            )),
        ])
        .block(empty_block)
        .alignment(Alignment::Center);

        let remaining = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1)])
            .split(chunks[1]);
        f.render_widget(empty, remaining[0]);
        return;
    }
    let mut label_values: Vec<String> = Vec::new();
    let mut label_name = String::new();

    for metric in &state.metrics {
        if let Metric::Label(m) = metric {
            label_name = m.name.clone();
            label_values.extend(m.values.iter().cloned());
        }
    }
    if !label_values.is_empty() {
        render_label_metric(f, chunks, &label_name, &label_values, state);
        return;
    }
    let accumulation_metrics: Vec<_> = state
        .metrics
        .iter()
        .filter_map(|m| {
            if let Metric::Accumulation(a) = m {
                Some(a)
            } else {
                None
            }
        })
        .collect();

    if accumulation_metrics.len() > 1 {
        render_multi_metric(f, chunks, &accumulation_metrics, state);
        return;
    }
    let mut all_values: Vec<(u32, f64)> = Vec::new();
    let mut metric_name = String::new();
    let mut metric_unit = s2_sdk::types::MetricUnit::Bytes;

    for metric in &state.metrics {
        match metric {
            Metric::Gauge(m) => {
                metric_name = m.name.clone();
                metric_unit = m.unit;
                all_values.extend(m.values.iter().cloned());
            }
            Metric::Accumulation(m) => {
                metric_name = m.name.clone();
                metric_unit = m.unit;
                all_values.extend(m.values.iter().cloned());
            }
            Metric::Scalar(m) => {
                metric_name = m.name.clone();
                metric_unit = m.unit;
                all_values.push((0, m.value));
            }
            Metric::Label(_) => {} // Handled above
        }
    }

    if all_values.is_empty() {
        return;
    }
    all_values.sort_by_key(|(ts, _)| *ts);
    let values_only: Vec<f64> = all_values.iter().map(|(_, v)| *v).collect();
    let min_val = values_only.iter().cloned().fold(f64::MAX, f64::min);
    let max_val = values_only.iter().cloned().fold(f64::MIN, f64::max);
    let avg_val = if !values_only.is_empty() {
        values_only.iter().sum::<f64>() / values_only.len() as f64
    } else {
        0.0
    };
    let latest_val = values_only.last().cloned().unwrap_or(0.0);
    let first_val = values_only.first().cloned().unwrap_or(0.0);
    let change = if first_val > 0.0 {
        ((latest_val - first_val) / first_val) * 100.0
    } else if latest_val > 0.0 {
        100.0
    } else {
        0.0
    };
    let first_ts = all_values.first().map(|(ts, _)| *ts).unwrap_or(0);
    let last_ts = all_values.last().map(|(ts, _)| *ts).unwrap_or(0);
    let stats_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));

    let stats_inner = stats_block.inner(chunks[1]);
    f.render_widget(stats_block, chunks[1]);
    let (trend_arrow, trend_color) = if change > 1.0 {
        ("↑", CYAN)
    } else if change < -1.0 {
        ("↓", ERROR)
    } else {
        ("→", TEXT_MUTED)
    };
    let trend_text = if change.abs() > 0.1 {
        format!("{:+.1}%", change)
    } else {
        "stable".to_string()
    };

    let stats_line = Line::from(vec![
        Span::styled(" NOW ", Style::default().fg(BG_DARK).bg(CYAN).bold()),
        Span::styled(
            format!(" {} ", format_metric_value_f64(latest_val, metric_unit)),
            Style::default().fg(CYAN).bold(),
        ),
        Span::styled(trend_arrow, Style::default().fg(trend_color).bold()),
        Span::styled(format!("{} ", trend_text), Style::default().fg(trend_color)),
        Span::styled("  |  ", Style::default().fg(BORDER)),
        Span::styled("min ", Style::default().fg(TEXT_MUTED)),
        Span::styled(
            format_metric_value_f64(min_val, metric_unit),
            Style::default().fg(STAT_MIN),
        ),
        Span::styled("  max ", Style::default().fg(TEXT_MUTED)),
        Span::styled(
            format_metric_value_f64(max_val, metric_unit),
            Style::default().fg(STAT_MAX),
        ),
        Span::styled("  avg ", Style::default().fg(TEXT_MUTED)),
        Span::styled(
            format_metric_value_f64(avg_val, metric_unit),
            Style::default().fg(STAT_AVG),
        ),
        Span::styled(
            format!("  |  {} pts", all_values.len()),
            Style::default().fg(TEXT_MUTED),
        ),
    ]);
    let stats_para = Paragraph::new(stats_line).alignment(Alignment::Center);
    f.render_widget(stats_para, stats_inner);
    let chart_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title(Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(&metric_name, Style::default().fg(CYAN).bold()),
            Span::styled(" ", Style::default()),
        ]))
        .style(Style::default().bg(BG_DARK));

    let chart_inner = chart_block.inner(chunks[2]);
    f.render_widget(chart_block, chunks[2]);
    render_area_chart(
        f,
        chart_inner,
        &all_values,
        min_val,
        max_val,
        metric_unit,
        first_ts,
        last_ts,
    );
    let timeline_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(" Data Points ", Style::default().fg(TEXT_PRIMARY)),
            Span::styled(
                format!("[{}/{}]", state.scroll + 1, all_values.len()),
                Style::default().fg(TEXT_MUTED),
            ),
        ]))
        .title_bottom(Line::from(Span::styled(
            " j/k scroll ",
            Style::default().fg(TEXT_MUTED),
        )))
        .style(Style::default().bg(BG_DARK));

    let timeline_inner = timeline_block.inner(chunks[3]);
    f.render_widget(timeline_block, chunks[3]);
    let bar_width = timeline_inner.width.saturating_sub(26) as usize;
    let visible_rows = timeline_inner.height as usize;

    let bars: Vec<Line> = all_values
        .iter()
        .skip(state.scroll)
        .take(visible_rows)
        .map(|(ts, value)| {
            let bar_len = if max_val > 0.0 {
                ((*value / max_val) * bar_width as f64) as usize
            } else {
                0
            };
            let intensity = if max_val > 0.0 { *value / max_val } else { 0.0 };
            let bar_color = intensity_to_color(intensity);

            let bar: String = (0..bar_len)
                .map(|i| {
                    let pos = i as f64 / bar_len.max(1) as f64;
                    if pos > 0.9 {
                        '█'
                    } else if pos > 0.7 {
                        '▓'
                    } else if pos > 0.4 {
                        '▒'
                    } else {
                        '░'
                    }
                })
                .collect();

            let time_str = format_metric_timestamp_short(*ts);

            Line::from(vec![
                Span::styled(
                    format!(" {:>8} ", time_str),
                    Style::default().fg(TEXT_MUTED),
                ),
                Span::styled(bar, Style::default().fg(bar_color)),
                Span::styled(
                    format!(" {:>10}", format_metric_value_f64(*value, metric_unit)),
                    Style::default().fg(TEXT_SECONDARY),
                ),
            ])
        })
        .collect();

    let bars_para = Paragraph::new(bars);
    f.render_widget(bars_para, timeline_inner);
}

/// Convert intensity (0.0-1.0) to a green gradient color
fn intensity_to_color(intensity: f64) -> Color {
    if intensity > 0.8 {
        GREEN_BRIGHT
    } else if intensity > 0.6 {
        GREEN_LIGHT
    } else if intensity > 0.4 {
        GREEN_LIGHTER
    } else if intensity > 0.2 {
        GREEN_PALE
    } else {
        GREEN_PALEST
    }
}

/// Render multiple accumulation metrics (like Account Ops breakdown)
fn render_multi_metric(
    f: &mut Frame,
    chunks: std::rc::Rc<[Rect]>,
    metrics: &[&s2_sdk::types::AccumulationMetric],
    state: &MetricsViewState,
) {
    use std::collections::BTreeMap;
    let colors = [
        CHART_PURPLE,
        CHART_VIOLET,
        CHART_INDIGO,
        CHART_DEEP_INDIGO,
        CHART_BLUE,
        CHART_ROYAL_BLUE,
        CHART_LIGHT_BLUE,
        CHART_PALE_BLUE,
        CHART_YELLOW,
        CHART_ORANGE,
    ];
    let mut metric_totals: Vec<(String, f64, usize)> = metrics
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let total: f64 = m.values.iter().map(|(_, v)| v).sum();
            (m.name.clone(), total, i)
        })
        .collect();
    metric_totals.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let mut time_buckets: BTreeMap<u32, f64> = BTreeMap::new();
    for metric in metrics.iter() {
        for (ts, val) in &metric.values {
            *time_buckets.entry(*ts).or_default() += val;
        }
    }

    let all_values: Vec<(u32, f64)> = time_buckets.into_iter().collect();
    let values_only: Vec<f64> = all_values.iter().map(|(_, v)| *v).collect();

    let grand_total: f64 = values_only.iter().sum();
    let min_val = values_only.iter().cloned().fold(f64::MAX, f64::min);
    let max_val = values_only.iter().cloned().fold(f64::MIN, f64::max);
    let avg_val = if !values_only.is_empty() {
        grand_total / values_only.len() as f64
    } else {
        0.0
    };
    let latest_val = values_only.last().cloned().unwrap_or(0.0);
    let first_val = values_only.first().cloned().unwrap_or(0.0);
    let first_ts = all_values.first().map(|(ts, _)| *ts).unwrap_or(0);
    let last_ts = all_values.last().map(|(ts, _)| *ts).unwrap_or(0);
    let change = if first_val > 0.0 {
        ((latest_val - first_val) / first_val) * 100.0
    } else if latest_val > 0.0 {
        100.0
    } else {
        0.0
    };
    let stats_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));

    let stats_inner = stats_block.inner(chunks[1]);
    f.render_widget(stats_block, chunks[1]);

    let (trend_arrow, trend_color) = if change > 1.0 {
        ("↑", CYAN)
    } else if change < -1.0 {
        ("↓", ERROR)
    } else {
        ("→", TEXT_MUTED)
    };
    let trend_text = if change.abs() > 0.1 {
        format!("{:+.1}%", change)
    } else {
        "stable".to_string()
    };

    let stats_line = Line::from(vec![
        Span::styled(" NOW ", Style::default().fg(BG_DARK).bg(CYAN).bold()),
        Span::styled(
            format!(" {} ", format_count(latest_val as u64)),
            Style::default().fg(CYAN).bold(),
        ),
        Span::styled(trend_arrow, Style::default().fg(trend_color).bold()),
        Span::styled(format!("{} ", trend_text), Style::default().fg(trend_color)),
        Span::styled("  |  ", Style::default().fg(BORDER)),
        Span::styled("min ", Style::default().fg(TEXT_MUTED)),
        Span::styled(format_count(min_val as u64), Style::default().fg(STAT_MIN)),
        Span::styled("  max ", Style::default().fg(TEXT_MUTED)),
        Span::styled(format_count(max_val as u64), Style::default().fg(STAT_MAX)),
        Span::styled("  avg ", Style::default().fg(TEXT_MUTED)),
        Span::styled(format_count(avg_val as u64), Style::default().fg(STAT_AVG)),
        Span::styled(
            format!("  |  {} pts", all_values.len()),
            Style::default().fg(TEXT_MUTED),
        ),
    ]);
    let stats_para = Paragraph::new(stats_line).alignment(Alignment::Center);
    f.render_widget(stats_para, stats_inner);
    let chart_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title(Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled("Total Operations", Style::default().fg(CYAN).bold()),
            Span::styled(" ", Style::default()),
        ]))
        .style(Style::default().bg(BG_DARK));

    let chart_inner = chart_block.inner(chunks[2]);
    f.render_widget(chart_block, chunks[2]);

    if !all_values.is_empty() {
        render_area_chart(
            f,
            chart_inner,
            &all_values,
            min_val,
            max_val,
            s2_sdk::types::MetricUnit::Operations,
            first_ts,
            last_ts,
        );
    }
    let timeline_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(" Breakdown ", Style::default().fg(TEXT_PRIMARY)),
            Span::styled(
                format!("({} operation types)", metrics.len()),
                Style::default().fg(TEXT_MUTED),
            ),
        ]))
        .title_bottom(Line::from(Span::styled(
            " j/k scroll ",
            Style::default().fg(TEXT_MUTED),
        )))
        .style(Style::default().bg(BG_DARK));

    let timeline_inner = timeline_block.inner(chunks[3]);
    f.render_widget(timeline_block, chunks[3]);
    let visible_rows = timeline_inner.height as usize;
    let bar_width = timeline_inner.width.saturating_sub(28) as usize;
    let max_total = metric_totals.iter().map(|(_, t, _)| *t).fold(0.0, f64::max);

    let lines: Vec<Line> = metric_totals
        .iter()
        .enumerate()
        .skip(state.scroll)
        .take(visible_rows)
        .map(|(_i, (name, total, orig_idx))| {
            let color = colors[*orig_idx % colors.len()];
            let bar_len = if max_total > 0.0 {
                ((total / max_total) * bar_width as f64) as usize
            } else {
                0
            };

            let bar: String = "█".repeat(bar_len);
            let percentage = if grand_total > 0.0 {
                (total / grand_total) * 100.0
            } else {
                0.0
            };

            let display_name = name.replace('_', " ");
            let display_name = if display_name.len() > 14 {
                format!("{}…", &display_name[..13])
            } else {
                display_name
            };

            Line::from(vec![
                Span::styled(
                    format!(" {:>14} ", display_name),
                    Style::default().fg(TEXT_PRIMARY),
                ),
                Span::styled(bar, Style::default().fg(color)),
                Span::styled(
                    format!(" {:>6} ({:>4.1}%)", format_count(*total as u64), percentage),
                    Style::default().fg(TEXT_SECONDARY),
                ),
            ])
        })
        .collect();

    let bars_para = Paragraph::new(lines);
    f.render_widget(bars_para, timeline_inner);
}

/// Render a label metric (list of string values, like Active Basins)
fn render_label_metric(
    f: &mut Frame,
    chunks: std::rc::Rc<[Rect]>,
    metric_name: &str,
    values: &[String],
    state: &MetricsViewState,
) {
    let stats_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));

    let stats_inner = stats_block.inner(chunks[1]);
    f.render_widget(stats_block, chunks[1]);

    let stats_line = Line::from(vec![
        Span::styled(" TOTAL ", Style::default().fg(BG_DARK).bg(CYAN).bold()),
        Span::styled(
            format!(" {} ", values.len()),
            Style::default().fg(CYAN).bold(),
        ),
        Span::styled(
            format!(" {} in selected time range", metric_name.to_lowercase()),
            Style::default().fg(TEXT_MUTED),
        ),
    ]);
    let stats_para = Paragraph::new(stats_line).alignment(Alignment::Center);
    f.render_widget(stats_para, stats_inner);
    let list_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title(Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(metric_name, Style::default().fg(CYAN).bold()),
            Span::styled(" ", Style::default()),
        ]))
        .style(Style::default().bg(BG_DARK));

    let list_inner = list_block.inner(chunks[2]);
    f.render_widget(list_block, chunks[2]);

    if values.is_empty() {
        let empty = Paragraph::new(Span::styled("No data", Style::default().fg(TEXT_MUTED)))
            .alignment(Alignment::Center);
        f.render_widget(empty, list_inner);
    } else {
        let visible_rows = list_inner.height as usize;
        let total_items = values.len();

        let items: Vec<Line> = values
            .iter()
            .enumerate()
            .skip(state.scroll)
            .take(visible_rows)
            .map(|(i, value)| {
                Line::from(vec![
                    Span::styled(format!(" {:>3}. ", i + 1), Style::default().fg(TEXT_MUTED)),
                    Span::styled(value, Style::default().fg(CYAN)),
                ])
            })
            .collect();

        let list_para = Paragraph::new(items);
        f.render_widget(list_para, list_inner);
        let scroll_block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER))
            .title(Line::from(vec![Span::styled(
                format!(
                    " Showing {}-{} of {} ",
                    state.scroll + 1,
                    (state.scroll + visible_rows).min(total_items),
                    total_items
                ),
                Style::default().fg(TEXT_MUTED),
            )]))
            .title_bottom(Line::from(Span::styled(
                " j/k scroll ",
                Style::default().fg(TEXT_MUTED),
            )))
            .style(Style::default().bg(BG_DARK));

        f.render_widget(scroll_block, chunks[3]);
    }
}

/// Render a beautiful area chart with Y-axis, filled area, and X-axis
#[allow(clippy::too_many_arguments)]
fn render_area_chart(
    f: &mut Frame,
    area: Rect,
    values: &[(u32, f64)],
    min_val: f64,
    max_val: f64,
    unit: s2_sdk::types::MetricUnit,
    first_ts: u32,
    last_ts: u32,
) {
    let height = area.height.saturating_sub(1) as usize; // Leave room for X-axis
    let y_axis_width = 10u16;
    let width = area.width.saturating_sub(y_axis_width + 1) as usize;

    if height < 2 || width < 10 {
        return;
    }
    let chart_min = if min_val > 0.0 { 0.0 } else { min_val };
    let chart_max = max_val * 1.1; // 10% headroom
    let chart_range = chart_max - chart_min;
    let values_only: Vec<f64> = values.iter().map(|(_, v)| *v).collect();
    let step = values_only.len() as f64 / width as f64;

    // Build the chart row by row (top to bottom)
    let mut lines: Vec<Line> = Vec::new();

    // Block characters for smooth area fill
    // Using vertical eighths: ' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'
    let fill_chars = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    for row in 0..height {
        let y_frac_top = 1.0 - (row as f64 / height as f64);
        let y_frac_bot = 1.0 - ((row + 1) as f64 / height as f64);

        // Y-axis label (only on certain rows)
        let y_label: String = if row == 0 {
            format!("{:>9} ", format_metric_value_f64(chart_max, unit))
        } else if row == height / 2 {
            format!(
                "{:>9} ",
                format_metric_value_f64((chart_max + chart_min) / 2.0, unit)
            )
        } else if row == height - 1 {
            format!("{:>9} ", format_metric_value_f64(chart_min, unit))
        } else {
            "          ".to_string()
        };

        let mut spans: Vec<Span> = vec![Span::styled(y_label, Style::default().fg(TEXT_MUTED))];

        // Draw each column
        for col in 0..width {
            let idx = ((col as f64) * step) as usize;
            let val = values_only.get(idx).cloned().unwrap_or(0.0);

            // Normalize value to chart coordinates
            let val_norm = (val - chart_min) / chart_range;
            let val_y = val_norm; // 0.0 = bottom, 1.0 = top

            // Determine what character to draw
            let char_and_color = if val_y >= y_frac_top {
                // Value is above this row - full fill
                ('█', intensity_to_color(val_norm))
            } else if val_y > y_frac_bot {
                // Value is within this row - partial fill
                let fill_frac = (val_y - y_frac_bot) / (y_frac_top - y_frac_bot);
                let char_idx = (fill_frac * 8.0) as usize;
                (fill_chars[char_idx.min(8)], intensity_to_color(val_norm))
            } else {
                // Value is below this row - empty or grid
                if col % 10 == 0 {
                    ('·', GRAY_750)
                } else {
                    (' ', BG_DARK)
                }
            };

            spans.push(Span::styled(
                char_and_color.0.to_string(),
                Style::default().fg(char_and_color.1),
            ));
        }

        lines.push(Line::from(spans));
    }

    // X-axis with time labels
    let first_time = format_metric_timestamp_short(first_ts);
    let last_time = format_metric_timestamp_short(last_ts);
    let mid_ts = first_ts + (last_ts - first_ts) / 2;
    let mid_time = format_metric_timestamp_short(mid_ts);

    let x_axis_padding = " ".repeat(y_axis_width as usize);

    let mut x_axis_spans = vec![
        Span::styled(&x_axis_padding, Style::default()),
        Span::styled(&first_time, Style::default().fg(TEXT_MUTED)),
    ];

    let remaining_after_first = width.saturating_sub(first_time.len() + mid_time.len() / 2);
    let padding_to_mid = remaining_after_first / 2;
    x_axis_spans.push(Span::styled(" ".repeat(padding_to_mid), Style::default()));
    x_axis_spans.push(Span::styled(&mid_time, Style::default().fg(TEXT_MUTED)));

    let remaining_after_mid =
        width.saturating_sub(first_time.len() + padding_to_mid + mid_time.len() + last_time.len());
    x_axis_spans.push(Span::styled(
        " ".repeat(remaining_after_mid),
        Style::default(),
    ));
    x_axis_spans.push(Span::styled(&last_time, Style::default().fg(TEXT_MUTED)));

    lines.push(Line::from(x_axis_spans));

    let chart_para = Paragraph::new(lines);
    f.render_widget(chart_para, area);
}

/// Render a sparkline with gradient coloring (unused but kept for reference)
#[allow(dead_code)]
fn render_sparkline_gradient(values: &[(u32, f64)], width: usize) -> String {
    if values.is_empty() {
        return "-".repeat(width);
    }
    let spark_chars = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    let values_only: Vec<f64> = values.iter().map(|(_, v)| *v).collect();
    let min_val = values_only.iter().cloned().fold(f64::MAX, f64::min);
    let max_val = values_only.iter().cloned().fold(f64::MIN, f64::max);
    let range = max_val - min_val;
    let step = values_only.len() as f64 / width as f64;
    let mut sparkline = String::new();

    for i in 0..width {
        let idx = (i as f64 * step) as usize;
        let val = values_only.get(idx).cloned().unwrap_or(0.0);

        let normalized = if range > 0.0 {
            ((val - min_val) / range).clamp(0.0, 1.0)
        } else {
            0.5
        };

        let char_idx = (normalized * (spark_chars.len() - 1) as f64) as usize;
        sparkline.push(spark_chars[char_idx]);
    }

    sparkline
}
/// Format timestamp in short form for bar chart
fn format_metric_timestamp_short(ts: u32) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let time = UNIX_EPOCH + Duration::from_secs(ts as u64);

    humantime::format_rfc3339_seconds(time)
        .to_string()
        .chars()
        .skip(11) // Skip date portion
        .take(8) // Take HH:MM:SS
        .collect()
}

/// Format a metric value (f64) with appropriate unit
fn format_metric_value_f64(value: f64, unit: s2_sdk::types::MetricUnit) -> String {
    use s2_sdk::types::MetricUnit;
    match unit {
        MetricUnit::Bytes => format_bytes(value as u64),
        MetricUnit::Operations => format_count(value as u64),
    }
}

/// Format bytes with appropriate unit
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Format count with K/M suffixes
fn format_count(count: u64) -> String {
    if count >= 1_000_000 {
        format!("{:.1}M", count as f64 / 1_000_000.0)
    } else if count >= 1_000 {
        format!("{:.1}K", count as f64 / 1_000.0)
    } else {
        count.to_string()
    }
}

/// Draw time range picker popup
fn draw_time_picker(f: &mut Frame, state: &MetricsViewState) {
    use super::app::TimeRangeOption;

    let area = f.area();

    let item_count = TimeRangeOption::PRESETS.len() + 1;

    let popup_width = 30u16;
    let popup_height = (item_count as u16) + 4; // Items + borders + title

    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    let mut items: Vec<ListItem> = TimeRangeOption::PRESETS
        .iter()
        .enumerate()
        .map(|(i, option)| {
            let is_selected = i == state.time_picker_selected;
            let is_current =
                std::mem::discriminant(option) == std::mem::discriminant(&state.time_range);

            let style = if is_selected {
                Style::default().fg(BG_DARK).bg(CYAN).bold()
            } else if is_current {
                Style::default().fg(CYAN)
            } else {
                Style::default().fg(TEXT_PRIMARY)
            };

            let marker = if is_current { " ✓" } else { "" };
            ListItem::new(format!(" {}{} ", option.as_label(), marker)).style(style)
        })
        .collect();

    let custom_index = TimeRangeOption::PRESETS.len();
    let is_custom_selected = state.time_picker_selected == custom_index;
    let is_custom_current = matches!(state.time_range, TimeRangeOption::Custom { .. });
    let custom_style = if is_custom_selected {
        Style::default().fg(BG_DARK).bg(CYAN).bold()
    } else {
        Style::default().fg(CYAN)
    };
    let custom_marker = if is_custom_current { " ✓" } else { "" };
    items.push(ListItem::new(format!(" Custom range...{} ", custom_marker)).style(custom_style));

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(CYAN))
            .title(Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled("Time Range", Style::default().fg(CYAN).bold()),
                Span::styled(" ", Style::default()),
            ]))
            .title_bottom(Line::from(Span::styled(
                " Enter select  Esc close ",
                Style::default().fg(TEXT_MUTED),
            )))
            .style(Style::default().bg(BG_PANEL)),
    );

    f.render_widget(list, popup_area);
}

/// Draw calendar date picker
fn draw_calendar_picker(f: &mut Frame, state: &MetricsViewState) {
    use chrono::{Datelike, Local, NaiveDate};

    let area = f.area();

    let popup_width = 36u16;
    let popup_height = 14u16;

    let popup_x = (area.width.saturating_sub(popup_width)) / 2;
    let popup_y = (area.height.saturating_sub(popup_height)) / 2;

    let popup_area = Rect::new(popup_x, popup_y, popup_width, popup_height);

    f.render_widget(Clear, popup_area);

    // Month names
    let month_names = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let month_name = month_names
        .get(state.calendar_month.saturating_sub(1) as usize)
        .unwrap_or(&"???");

    // Calculate first day of month and days in month (with safe fallbacks)
    let today = Local::now().date_naive();
    let first_of_month = NaiveDate::from_ymd_opt(state.calendar_year, state.calendar_month, 1)
        .unwrap_or(today.with_day(1).unwrap_or(today));
    let first_weekday = first_of_month.weekday().num_days_from_sunday() as usize;
    let days_in_month = {
        let next_month = if state.calendar_month == 12 {
            NaiveDate::from_ymd_opt(state.calendar_year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(state.calendar_year, state.calendar_month + 1, 1)
        };
        next_month
            .and_then(|d| d.pred_opt())
            .map(|d| d.day())
            .unwrap_or(28) // Safe fallback - February minimum
    };

    // Build calendar lines
    let mut lines: Vec<Line> = Vec::new();

    // Month/Year header with navigation hints
    lines.push(Line::from(vec![
        Span::styled(" [", Style::default().fg(TEXT_MUTED)),
        Span::styled(
            format!("{} {}", month_name, state.calendar_year),
            Style::default().fg(CYAN).bold(),
        ),
        Span::styled("] ", Style::default().fg(TEXT_MUTED)),
    ]));

    // Day headers
    lines.push(Line::from(vec![
        Span::styled(" Su ", Style::default().fg(TEXT_MUTED)),
        Span::styled(" Mo ", Style::default().fg(TEXT_MUTED)),
        Span::styled(" Tu ", Style::default().fg(TEXT_MUTED)),
        Span::styled(" We ", Style::default().fg(TEXT_MUTED)),
        Span::styled(" Th ", Style::default().fg(TEXT_MUTED)),
        Span::styled(" Fr ", Style::default().fg(TEXT_MUTED)),
        Span::styled(" Sa ", Style::default().fg(TEXT_MUTED)),
    ]));

    // Calendar grid
    let mut day = 1u32;
    for week in 0..6 {
        let mut spans: Vec<Span> = Vec::new();
        for weekday in 0..7 {
            let cell_idx = week * 7 + weekday;
            if cell_idx < first_weekday || day > days_in_month {
                spans.push(Span::styled("    ", Style::default()));
            } else {
                let is_selected = day == state.calendar_day;
                let current_date = (state.calendar_year, state.calendar_month, day);

                // Check if this day is the start or end of selection
                let is_start = state.calendar_start == Some(current_date);
                let is_end = state.calendar_end == Some(current_date);

                // Check if this day is in the selected range
                let in_range = match (state.calendar_start, state.calendar_end) {
                    (Some(start), Some(end)) => {
                        let (s, e) = if start <= end {
                            (start, end)
                        } else {
                            (end, start)
                        };
                        current_date >= s && current_date <= e
                    }
                    (Some(start), None) if state.calendar_selecting_end => {
                        // Show range preview while selecting end
                        let (s, e) = if start <= current_date {
                            (start, current_date)
                        } else {
                            (current_date, start)
                        };
                        current_date >= s && current_date <= e && is_selected
                    }
                    _ => false,
                };

                let style = if is_selected || is_start || is_end {
                    Style::default().fg(BG_DARK).bg(CYAN).bold()
                } else if in_range {
                    Style::default().fg(CYAN).bg(BG_PANEL)
                } else {
                    Style::default().fg(TEXT_PRIMARY)
                };

                spans.push(Span::styled(format!("{:>3} ", day), style));
                day += 1;
            }
        }
        lines.push(Line::from(spans));
        if day > days_in_month {
            break;
        }
    }

    // Selection status
    let status = match (state.calendar_start, state.calendar_end) {
        (Some((sy, sm, sd)), Some((ey, em, ed))) => {
            format!("{:02}/{:02}/{} - {:02}/{:02}/{}", sm, sd, sy, em, ed, ey)
        }
        (Some((sy, sm, sd)), None) => {
            if state.calendar_selecting_end {
                format!("{:02}/{:02}/{} - select end", sm, sd, sy)
            } else {
                "Select start date".to_string()
            }
        }
        _ => "Select start date".to_string(),
    };
    lines.push(Line::from(Span::styled(
        format!(" {} ", status),
        Style::default().fg(CYAN),
    )));

    let calendar_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .title(Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled("Select Date Range", Style::default().fg(CYAN).bold()),
            Span::styled(" ", Style::default()),
        ]))
        .title_bottom(Line::from(Span::styled(
            " ←→↑↓ nav  [/] month  Enter select  Esc cancel ",
            Style::default().fg(TEXT_MUTED),
        )))
        .style(Style::default().bg(BG_PANEL));

    let calendar_para = Paragraph::new(lines)
        .block(calendar_block)
        .alignment(Alignment::Center);

    f.render_widget(calendar_para, popup_area);
}

fn draw_basins(f: &mut Frame, area: Rect, state: &BasinsState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title bar (consistent height)
            Constraint::Length(3), // Search bar
            Constraint::Length(2), // Header
            Constraint::Min(1),    // Table rows
        ])
        .split(area);
    let count_text = if state.loading {
        " loading...".to_string()
    } else {
        let filtered_count = state
            .basins
            .iter()
            .filter(|b| {
                state.filter.is_empty()
                    || b.name
                        .to_string()
                        .to_lowercase()
                        .contains(&state.filter.to_lowercase())
            })
            .count();
        if filtered_count != state.basins.len() {
            format!("  {}/{} basins", filtered_count, state.basins.len())
        } else {
            format!("  {} basins", state.basins.len())
        }
    };
    let title_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Basins", Style::default().fg(CYAN).bold()),
            Span::styled(&count_text, Style::default().fg(GRAY_700)),
        ]),
    ];
    let title_block = Paragraph::new(title_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(GRAY_800)),
    );
    f.render_widget(title_block, chunks[0]);

    let (search_block, search_text) =
        render_search_bar(&state.filter, state.filter_active, "Filter by prefix");
    f.render_widget(Paragraph::new(search_text).block(search_block), chunks[1]);

    let header_area = chunks[2];
    let total_width = header_area.width as usize;
    let state_col = 12;
    let scope_col = 16;
    let name_col = total_width.saturating_sub(state_col + scope_col + 4);

    let header = Line::from(vec![
        Span::styled(
            format!("  {:<width$}", "Name", width = name_col),
            Style::default().fg(TEXT_MUTED),
        ),
        Span::styled(
            format!("{:<width$}", "State", width = state_col),
            Style::default().fg(TEXT_MUTED),
        ),
        Span::styled("Scope", Style::default().fg(TEXT_MUTED)),
    ]);
    f.render_widget(
        Paragraph::new(header),
        Rect::new(header_area.x, header_area.y, header_area.width, 1),
    );
    let sep = "─".repeat(total_width);
    f.render_widget(
        Paragraph::new(Span::styled(sep, Style::default().fg(BORDER))),
        Rect::new(header_area.x, header_area.y + 1, header_area.width, 1),
    );

    let filtered: Vec<_> = state
        .basins
        .iter()
        .filter(|b| {
            state.filter.is_empty()
                || b.name
                    .to_string()
                    .to_lowercase()
                    .contains(&state.filter.to_lowercase())
        })
        .collect();

    let table_area = chunks[3];

    if filtered.is_empty() && !state.loading {
        let msg = if state.filter.is_empty() {
            "No basins yet. Press  c  to create your first basin."
        } else {
            "No basins match the filter. Press  Esc  to clear."
        };
        let text = Paragraph::new(Span::styled(msg, Style::default().fg(TEXT_MUTED)))
            .alignment(Alignment::Center);
        f.render_widget(
            text,
            Rect::new(table_area.x, table_area.y + 2, table_area.width, 1),
        );
        return;
    }

    if state.loading {
        let text = Paragraph::new(Span::styled(
            "Loading basins...",
            Style::default().fg(TEXT_MUTED),
        ))
        .alignment(Alignment::Center);
        f.render_widget(
            text,
            Rect::new(table_area.x, table_area.y + 2, table_area.width, 1),
        );
        return;
    }

    let visible_height = table_area.height as usize;
    let total = filtered.len();
    let selected = state.selected.min(total.saturating_sub(1));

    let scroll_offset = if selected >= visible_height {
        selected - visible_height + 1
    } else {
        0
    };

    for (view_idx, basin) in filtered
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_height)
    {
        let y = table_area.y + (view_idx - scroll_offset) as u16;
        if y >= table_area.y + table_area.height {
            break;
        }

        let is_selected = view_idx == selected;
        let row_area = Rect::new(table_area.x, y, table_area.width, 1);

        if is_selected {
            f.render_widget(
                Block::default().style(Style::default().bg(BG_SELECTED)),
                row_area,
            );
        }

        let name = basin.name.to_string();
        let max_name_len = name_col.saturating_sub(2);
        let display_name = truncate_str(&name, max_name_len, "…");

        let (state_text, state_bg) = match basin.state {
            s2_sdk::types::BasinState::Active => ("Active", BADGE_ACTIVE),
            s2_sdk::types::BasinState::Creating => ("Creating", BADGE_PENDING),
            s2_sdk::types::BasinState::Deleting => ("Deleting", BADGE_DANGER),
        };

        let scope = basin
            .scope
            .as_ref()
            .map(|s| match s {
                s2_sdk::types::BasinScope::AwsUsEast1 => "aws:us-east-1",
            })
            .unwrap_or("—");

        let prefix = if is_selected { "▸ " } else { "  " };
        let name_style = if is_selected {
            Style::default().fg(TEXT_PRIMARY).bold()
        } else {
            Style::default().fg(TEXT_SECONDARY)
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    prefix,
                    Style::default().fg(if is_selected { CYAN } else { TEXT_SECONDARY }),
                ),
                Span::styled(display_name, name_style),
            ])),
            Rect::new(row_area.x, y, name_col as u16, 1),
        );

        let badge_x = row_area.x + name_col as u16;
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" {} ", state_text),
                Style::default().fg(WHITE).bg(state_bg),
            )),
            Rect::new(badge_x, y, state_col as u16, 1),
        );

        let scope_x = badge_x + state_col as u16;
        f.render_widget(
            Paragraph::new(Span::styled(scope, Style::default().fg(TEXT_MUTED))),
            Rect::new(scope_x, y, scope_col as u16, 1),
        );
    }
}

fn draw_streams(f: &mut Frame, area: Rect, state: &StreamsState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title bar with basin name (consistent height)
            Constraint::Length(3), // Search bar
            Constraint::Length(2), // Header
            Constraint::Min(1),    // Table rows
        ])
        .split(area);
    let count_text = if state.loading {
        " loading...".to_string()
    } else {
        let filtered_count = state
            .streams
            .iter()
            .filter(|s| {
                state.filter.is_empty()
                    || s.name
                        .to_string()
                        .to_lowercase()
                        .contains(&state.filter.to_lowercase())
            })
            .count();
        if filtered_count != state.streams.len() {
            format!("  {}/{} streams", filtered_count, state.streams.len())
        } else {
            format!("  {} streams", state.streams.len())
        }
    };

    let basin_name_str = state.basin_name.to_string();
    let title_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ← ", Style::default().fg(GRAY_700)),
            Span::styled(&basin_name_str, Style::default().fg(CYAN).bold()),
            Span::styled(&count_text, Style::default().fg(GRAY_700)),
        ]),
    ];
    let title_block = Paragraph::new(title_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(GRAY_800)),
    );
    f.render_widget(title_block, chunks[0]);

    let (search_block, search_text) =
        render_search_bar(&state.filter, state.filter_active, "Filter by prefix");
    f.render_widget(Paragraph::new(search_text).block(search_block), chunks[1]);

    let header_area = chunks[2];
    let total_width = header_area.width as usize;
    let created_col = 24;
    let status_col = 12;
    let name_col = total_width.saturating_sub(created_col + status_col + 4);

    let header = Line::from(vec![
        Span::styled(
            format!("  {:<width$}", "Name", width = name_col),
            Style::default().fg(TEXT_MUTED),
        ),
        Span::styled(
            format!("{:<width$}", "Status", width = status_col),
            Style::default().fg(TEXT_MUTED),
        ),
        Span::styled("Created", Style::default().fg(TEXT_MUTED)),
    ]);
    f.render_widget(
        Paragraph::new(header),
        Rect::new(header_area.x, header_area.y, header_area.width, 1),
    );
    let sep = "─".repeat(total_width);
    f.render_widget(
        Paragraph::new(Span::styled(sep, Style::default().fg(BORDER))),
        Rect::new(header_area.x, header_area.y + 1, header_area.width, 1),
    );

    let filtered: Vec<_> = state
        .streams
        .iter()
        .filter(|s| {
            state.filter.is_empty()
                || s.name
                    .to_string()
                    .to_lowercase()
                    .contains(&state.filter.to_lowercase())
        })
        .collect();

    let table_area = chunks[3];

    if filtered.is_empty() && !state.loading {
        let msg = if state.filter.is_empty() {
            "No streams in this basin. Press  c  to create your first stream."
        } else {
            "No streams match the filter. Press  Esc  to clear."
        };
        let text = Paragraph::new(Span::styled(msg, Style::default().fg(TEXT_MUTED)))
            .alignment(Alignment::Center);
        f.render_widget(
            text,
            Rect::new(table_area.x, table_area.y + 2, table_area.width, 1),
        );
        return;
    }

    if state.loading {
        let text = Paragraph::new(Span::styled(
            "Loading streams...",
            Style::default().fg(TEXT_MUTED),
        ))
        .alignment(Alignment::Center);
        f.render_widget(
            text,
            Rect::new(table_area.x, table_area.y + 2, table_area.width, 1),
        );
        return;
    }

    let visible_height = table_area.height as usize;
    let total = filtered.len();
    let selected = state.selected.min(total.saturating_sub(1));

    let scroll_offset = if selected >= visible_height {
        selected - visible_height + 1
    } else {
        0
    };

    for (view_idx, stream) in filtered
        .iter()
        .enumerate()
        .skip(scroll_offset)
        .take(visible_height)
    {
        let y = table_area.y + (view_idx - scroll_offset) as u16;
        if y >= table_area.y + table_area.height {
            break;
        }

        let is_selected = view_idx == selected;
        let row_area = Rect::new(table_area.x, y, table_area.width, 1);

        if is_selected {
            f.render_widget(
                Block::default().style(Style::default().bg(BG_SELECTED)),
                row_area,
            );
        }

        let name = stream.name.to_string();
        let max_name_len = name_col.saturating_sub(2);
        let display_name = truncate_str(&name, max_name_len, "…");

        let created = stream.created_at.to_string();

        let prefix = if is_selected { "▸ " } else { "  " };
        let name_style = if is_selected {
            Style::default().fg(TEXT_PRIMARY).bold()
        } else {
            Style::default().fg(TEXT_SECONDARY)
        };
        f.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    prefix,
                    Style::default().fg(if is_selected { CYAN } else { TEXT_SECONDARY }),
                ),
                Span::styled(display_name, name_style),
            ])),
            Rect::new(row_area.x, y, name_col as u16, 1),
        );

        let status_x = row_area.x + name_col as u16;
        let (status_text, status_bg) = if stream.deleted_at.is_some() {
            ("Deleting", BADGE_DANGER)
        } else {
            ("Active", BADGE_ACTIVE)
        };
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" {} ", status_text),
                Style::default().fg(WHITE).bg(status_bg),
            )),
            Rect::new(status_x, y, status_col as u16, 1),
        );

        let created_x = status_x + status_col as u16;
        f.render_widget(
            Paragraph::new(Span::styled(created, Style::default().fg(TEXT_MUTED))),
            Rect::new(created_x, y, created_col as u16, 1),
        );
    }
}

fn draw_stream_detail(f: &mut Frame, area: Rect, state: &StreamDetailState) {
    // Vertical layout: Header, Stats row, Actions
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(5), // Stats cards
            Constraint::Min(12),
        ])
        .split(area);

    let basin_str = state.basin_name.to_string();
    let stream_str = state.stream_name.to_string();
    let header_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ← ", Style::default().fg(GRAY_600)),
            Span::styled(&basin_str, Style::default().fg(GRAY_300)),
            Span::styled(" / ", Style::default().fg(GRAY_700)),
            Span::styled(&stream_str, Style::default().fg(CYAN).bold()),
        ]),
    ];
    let header = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(BORDER_TITLE)),
    );
    f.render_widget(header, chunks[0]);

    let stats_area = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(20), // Stats content
            Constraint::Length(2),
        ])
        .split(chunks[1])[1];

    let stats_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(stats_area);

    fn render_stat_card_v2(
        f: &mut Frame,
        area: Rect,
        icon: &str,
        label: &str,
        value: &str,
        value_color: Color,
    ) {
        let lines = vec![
            Line::from(vec![
                Span::styled(icon, Style::default().fg(value_color)),
                Span::styled(format!(" {}", label), Style::default().fg(GRAY_400)),
            ]),
            Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(value, Style::default().fg(value_color).bold()),
            ]),
        ];
        let widget = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(BORDER_DIM))
                .border_type(ratatui::widgets::BorderType::Rounded),
        );
        f.render_widget(widget, area);
    }

    // Tail Position
    let (tail_val, tail_color) = if let Some(pos) = &state.tail_position {
        if pos.seq_num > 0 {
            (format!("{}", pos.seq_num), CYAN)
        } else {
            ("0".to_string(), GRAY_600)
        }
    } else if state.loading {
        ("...".to_string(), GRAY_600)
    } else {
        ("--".to_string(), GRAY_600)
    };
    render_stat_card_v2(f, stats_chunks[0], "▌", "Records", &tail_val, tail_color);

    // Last Write
    let (ts_val, ts_color) = if let Some(pos) = &state.tail_position {
        if pos.timestamp > 0 {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0);
            let age_secs = now_ms.saturating_sub(pos.timestamp) / 1000;
            let val = if age_secs < 60 {
                format!("{}s ago", age_secs)
            } else if age_secs < 3600 {
                format!("{}m ago", age_secs / 60)
            } else if age_secs < 86400 {
                format!("{}h ago", age_secs / 3600)
            } else {
                format!("{}d ago", age_secs / 86400)
            };
            let color = if age_secs < 60 {
                TIME_RECENT
            } else if age_secs < 3600 {
                TIME_MODERATE
            } else {
                TIME_OLD
            };
            (val, color)
        } else {
            ("never".to_string(), GRAY_600)
        }
    } else {
        ("--".to_string(), GRAY_600)
    };
    render_stat_card_v2(f, stats_chunks[1], "◷", "Last Write", &ts_val, ts_color);

    // Storage Class
    let (storage_val, storage_color) = if let Some(config) = &state.config {
        let val = config
            .storage_class
            .as_ref()
            .map(|s| format!("{:?}", s).to_lowercase())
            .unwrap_or_else(|| "default".to_string());
        let color = match val.as_str() {
            "express" => STORAGE_EXPRESS,
            "standard" => STORAGE_STANDARD,
            _ => GRAY_200,
        };
        (val, color)
    } else {
        ("--".to_string(), GRAY_600)
    };
    render_stat_card_v2(
        f,
        stats_chunks[2],
        "◈",
        "Storage",
        &storage_val,
        storage_color,
    );
    let (retention_val, retention_color) = if let Some(config) = &state.config {
        let val = config
            .retention_policy
            .as_ref()
            .map(|p| match p {
                crate::types::RetentionPolicy::Age(dur) => {
                    let secs = dur.as_secs();
                    if secs >= 86400 * 365 {
                        format!("{}y", secs / (86400 * 365))
                    } else if secs >= 86400 {
                        format!("{}d", secs / 86400)
                    } else if secs >= 3600 {
                        format!("{}h", secs / 3600)
                    } else {
                        format!("{}s", secs)
                    }
                }
                crate::types::RetentionPolicy::Infinite => "∞".to_string(),
            })
            .unwrap_or_else(|| "∞".to_string());
        let color = if val == "∞" { PURPLE } else { GRAY_200 };
        (val, color)
    } else {
        ("--".to_string(), GRAY_600)
    };
    render_stat_card_v2(
        f,
        stats_chunks[3],
        "◔",
        "Retention",
        &retention_val,
        retention_color,
    );

    let actions_outer = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(20),
            Constraint::Length(2),
        ])
        .split(chunks[2])[1];

    let action_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 2), Constraint::Ratio(1, 2)])
        .split(actions_outer);
    let data_ops: Vec<(&str, &str, &str, &str)> = vec![
        ("t", "Tail", "Live stream, see records as they arrive", "◉"),
        ("r", "Read", "Read with custom start position & limits", "◎"),
        ("a", "Append", "Write new records to stream", "◆"),
    ];

    // Stream management (right column)
    let mgmt_ops: Vec<(&str, &str, &str, &str)> = vec![
        ("f", "Fence", "Set token for exclusive writes", "⊘"),
        ("m", "Trim", "Delete records before seq number", "✂"),
    ];

    fn render_action_column(
        f: &mut Frame,
        area: Rect,
        title: &str,
        actions: &[(&str, &str, &str, &str)],
        selected: usize,
        offset: usize,
    ) {
        let title_width = title.len() + 4;
        let line_width = area.width.saturating_sub(title_width as u16 + 2) as usize;

        let mut lines = vec![
            Line::from(vec![
                Span::styled(format!("  {} ", title), Style::default().fg(CYAN).bold()),
                Span::styled("─".repeat(line_width), Style::default().fg(BORDER_TITLE)),
            ]),
            Line::from(""),
        ];

        for (i, (key, name, desc, icon)) in actions.iter().enumerate() {
            let actual_idx = i + offset;
            let is_selected = actual_idx == selected;

            if is_selected {
                // Selected action - highlighted card style
                lines.push(Line::from(vec![
                    Span::styled("  ▶ ", Style::default().fg(CYAN)),
                    Span::styled(*icon, Style::default().fg(CYAN)),
                    Span::styled(
                        format!(" {} ", name),
                        Style::default().fg(Color::White).bold(),
                    ),
                    Span::styled(format!("[{}]", key), Style::default().fg(CYAN).bold()),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("      ", Style::default()),
                    Span::styled(*desc, Style::default().fg(GRAY_200).italic()),
                ]));
            } else {
                // Unselected action - dimmed
                lines.push(Line::from(vec![
                    Span::styled("    ", Style::default()),
                    Span::styled(*icon, Style::default().fg(GRAY_700)),
                    Span::styled(format!(" {} ", name), Style::default().fg(GRAY_400)),
                    Span::styled(format!("[{}]", key), Style::default().fg(GRAY_700)),
                ]));
            }
            lines.push(Line::from(""));
        }

        let widget = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(GRAY_750))
                .border_type(ratatui::widgets::BorderType::Rounded),
        );
        f.render_widget(widget, area);
    }

    render_action_column(
        f,
        action_cols[0],
        "Data Operations",
        &data_ops,
        state.selected_action,
        0,
    );
    render_action_column(
        f,
        action_cols[1],
        "Stream Management",
        &mgmt_ops,
        state.selected_action,
        3,
    );
}

fn draw_read_view(f: &mut Frame, area: Rect, state: &ReadViewState) {
    let (mode_text, mode_color) = if state.is_tailing {
        if state.paused {
            ("PAUSED", WARNING)
        } else {
            ("LIVE", SUCCESS)
        }
    } else {
        ("READING", ACCENT)
    };

    // Show sparklines when tailing with throughput data
    let show_sparklines = state.is_tailing && !state.throughput_history.is_empty();
    let sparkline_height = if show_sparklines { 4 } else { 0 };
    let timeline_height = if state.show_timeline { 3 } else { 0 };

    // Split into header, optional sparklines, content, and optional timeline
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(sparkline_height),
            Constraint::Min(1), // Content
            Constraint::Length(timeline_height),
        ])
        .split(area);

    let basin_str = state.basin_name.to_string();
    let stream_str = state.stream_name.to_string();
    let record_count = format!("  {} records", state.records.len());

    let mut header_spans = vec![
        Span::styled("  ← ", Style::default().fg(GRAY_600)),
        Span::styled(&basin_str, Style::default().fg(GRAY_300)),
        Span::styled(" / ", Style::default().fg(GRAY_700)),
        Span::styled(&stream_str, Style::default().fg(GRAY_200)),
        Span::styled("  ", Style::default()),
        Span::styled(
            format!(" {} ", mode_text),
            Style::default().fg(BG_DARK).bg(mode_color).bold(),
        ),
        Span::styled(&record_count, Style::default().fg(GRAY_700)),
    ];

    if state.is_tailing && state.current_mibps > 0.0 {
        header_spans.push(Span::styled("  ", Style::default()));
        header_spans.push(Span::styled(
            format!("{:.1} MiB/s", state.current_mibps),
            Style::default().fg(CYAN).bold(),
        ));
        header_spans.push(Span::styled(
            format!("  {:.0} rec/s", state.current_recps),
            Style::default().fg(TEXT_MUTED),
        ));
    }

    if let Some(ref output) = state.output_file {
        header_spans.push(Span::styled("  → ", Style::default().fg(GRAY_700)));
        header_spans.push(Span::styled(output, Style::default().fg(YELLOW)));
    }

    let header_lines = vec![Line::from(""), Line::from(header_spans)];
    let header = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(GRAY_800)),
    );
    f.render_widget(header, main_chunks[0]);

    if show_sparklines {
        draw_tail_sparklines(
            f,
            main_chunks[1],
            &state.throughput_history,
            &state.records_per_sec_history,
        );
    }

    let content_area = main_chunks[2];
    let outer_block = Block::default().borders(Borders::NONE);

    let inner_area = outer_block.inner(content_area);
    f.render_widget(outer_block, content_area);

    if state.records.is_empty() {
        let text = if state.loading {
            "Waiting for records..."
        } else {
            "No records"
        };
        let para = Paragraph::new(Span::styled(text, Style::default().fg(TEXT_MUTED)))
            .alignment(Alignment::Center);
        f.render_widget(
            para,
            Rect::new(inner_area.x, inner_area.y + 2, inner_area.width, 1),
        );
        return;
    }

    let total_records = state.records.len();
    let selected = state.selected.min(total_records.saturating_sub(1));

    // Layout depends on whether list is hidden
    let body_area = if state.hide_list {
        // Full width for body when list hidden
        inner_area
    } else {
        // Split into left (record list) and right (body preview) panes
        let panes = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(28),
                Constraint::Min(20), // Body preview - takes remaining space
            ])
            .split(inner_area);

        let list_area = panes[0];
        let visible_height = list_area.height as usize;

        // Keep selected record in view
        let scroll_offset = if state.is_tailing && !state.paused {
            // Auto-scroll to show latest
            total_records.saturating_sub(visible_height)
        } else if selected >= visible_height {
            selected - visible_height + 1
        } else {
            0
        };

        for (view_idx, record) in state
            .records
            .iter()
            .enumerate()
            .skip(scroll_offset)
            .take(visible_height)
        {
            let y = list_area.y + (view_idx - scroll_offset) as u16;
            if y >= list_area.y + list_area.height {
                break;
            }

            let is_selected = view_idx == selected;
            let has_headers = !record.headers.is_empty();
            let row_area = Rect::new(list_area.x, y, list_area.width, 1);

            if is_selected {
                f.render_widget(
                    Block::default().style(Style::default().bg(BG_SELECTED)),
                    row_area,
                );
            }

            let sel_indicator = if is_selected { "▸" } else { " " };
            let header_indicator = if has_headers { "⌘" } else { " " };

            let line = Line::from(vec![
                Span::styled(sel_indicator, Style::default().fg(CYAN)),
                Span::styled(
                    format!("#{:<8}", record.seq_num),
                    Style::default()
                        .fg(if is_selected { CYAN } else { TEXT_SECONDARY })
                        .bold(),
                ),
                Span::styled(
                    format!("{:>13}", record.timestamp),
                    Style::default().fg(TEXT_MUTED),
                ),
                Span::styled(
                    format!(" {}", header_indicator),
                    Style::default().fg(if has_headers { YELLOW } else { BORDER }),
                ),
            ]);
            f.render_widget(Paragraph::new(line), row_area);
        }

        // Vertical separator - single widget instead of per-row loop
        let sep_x = panes[1].x.saturating_sub(1);
        let sep_lines: Vec<Line> = (0..inner_area.height)
            .map(|_| Line::from(Span::styled("│", Style::default().fg(BORDER))))
            .collect();
        f.render_widget(
            Paragraph::new(sep_lines),
            Rect::new(sep_x, inner_area.y, 1, inner_area.height),
        );

        panes[1]
    };

    if let Some(record) = state.records.get(selected) {
        let body = String::from_utf8_lossy(&record.body);
        let body_width = body_area.width.saturating_sub(2) as usize;
        let body_height = body_area.height as usize;

        // Cinema mode: when list is hidden and tailing, show raw body without chrome
        let cinema_mode = state.hide_list && state.is_tailing && !state.paused;

        let (content_start_y, content_height) = if cinema_mode {
            (body_area.y, body_height)
        } else {
            let header_line = Line::from(vec![
                Span::styled(
                    format!(" #{}", record.seq_num),
                    Style::default().fg(CYAN).bold(),
                ),
                Span::styled(
                    format!("  {}ms", record.timestamp),
                    Style::default().fg(TEXT_MUTED),
                ),
                Span::styled(
                    format!("  {} bytes", record.body.len()),
                    Style::default().fg(TEXT_MUTED),
                ),
                if !record.headers.is_empty() {
                    Span::styled(
                        format!("  ⌘{}", record.headers.len()),
                        Style::default().fg(YELLOW),
                    )
                } else {
                    Span::styled("", Style::default())
                },
            ]);
            f.render_widget(
                Paragraph::new(header_line),
                Rect::new(body_area.x, body_area.y, body_area.width, 1),
            );

            let sep = "─".repeat(body_width);
            f.render_widget(
                Paragraph::new(Span::styled(
                    format!(" {}", sep),
                    Style::default().fg(BORDER),
                )),
                Rect::new(body_area.x, body_area.y + 1, body_area.width, 1),
            );

            (body_area.y + 2, body_height.saturating_sub(2))
        };

        if body.is_empty() {
            f.render_widget(
                Paragraph::new(Span::styled(
                    " (empty body)",
                    Style::default().fg(TEXT_MUTED).italic(),
                )),
                Rect::new(body_area.x, content_start_y, body_area.width, 1),
            );
        } else {
            let mut display_lines: Vec<Line> = Vec::new();

            for line in body.lines().take(content_height) {
                if cinema_mode {
                    display_lines.push(Line::from(Span::styled(
                        line.to_string(),
                        Style::default().fg(TEXT_PRIMARY),
                    )));
                } else {
                    let chars: Vec<char> = line.chars().collect();
                    if chars.is_empty() {
                        display_lines.push(Line::from(""));
                    } else {
                        for chunk in chars.chunks(body_width.max(1)) {
                            let text: String = chunk.iter().collect();
                            display_lines.push(Line::from(Span::styled(
                                text,
                                Style::default().fg(TEXT_PRIMARY),
                            )));
                            if display_lines.len() >= content_height {
                                break;
                            }
                        }
                    }
                }
                if display_lines.len() >= content_height {
                    break;
                }
            }

            let body_para = Paragraph::new(display_lines).block(
                Block::default().padding(Padding::horizontal(if cinema_mode { 0 } else { 1 })),
            );
            f.render_widget(
                body_para,
                Rect::new(
                    body_area.x,
                    content_start_y,
                    body_area.width,
                    content_height as u16,
                ),
            );
        }
    }

    // Draw timeline scrubber if enabled
    if state.show_timeline && !state.records.is_empty() {
        draw_timeline_scrubber(f, main_chunks[3], state);
    }

    // Draw headers popup if showing
    if state.show_detail
        && let Some(record) = state.records.get(selected)
    {
        draw_headers_popup(f, record);
    }
}

fn draw_timeline_scrubber(f: &mut Frame, area: Rect, state: &ReadViewState) {
    let total = state.records.len();
    if total == 0 {
        return;
    }

    let selected = state.selected.min(total.saturating_sub(1));
    let width = area.width.saturating_sub(4) as usize;

    // Calculate record density histogram
    let bucket_count = width.max(1);
    let mut buckets = vec![0u64; bucket_count];

    for (i, _record) in state.records.iter().enumerate() {
        let bucket = (i * bucket_count) / total.max(1);
        let bucket = bucket.min(bucket_count - 1);
        buckets[bucket] += 1;
    }

    // Normalize buckets for display
    let max_bucket = buckets.iter().copied().max().unwrap_or(1).max(1);

    // Build histogram line
    let bar_chars = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let mut histogram_spans = Vec::new();

    let current_bucket = (selected * bucket_count) / total.max(1);
    let current_bucket = current_bucket.min(bucket_count - 1);

    for (i, &count) in buckets.iter().enumerate() {
        let level = ((count as f64 / max_bucket as f64) * 7.0).round() as usize;
        let level = level.min(7);
        let ch = bar_chars[level];

        let color = if i == current_bucket || count > 0 {
            CYAN
        } else {
            BORDER
        };

        histogram_spans.push(Span::styled(ch.to_string(), Style::default().fg(color)));
    }

    // Position indicator
    let position_pct = (selected as f64 / (total - 1).max(1) as f64) * 100.0;

    // Time info from records
    let (first_ts, last_ts) =
        if let (Some(first), Some(last)) = (state.records.front(), state.records.back()) {
            (first.timestamp, last.timestamp)
        } else {
            (0, 0)
        };

    let time_span = if last_ts > first_ts {
        let span_ms = last_ts - first_ts;
        if span_ms >= 3600000 {
            format!("{:.1}h span", span_ms as f64 / 3600000.0)
        } else if span_ms >= 60000 {
            format!("{:.1}m span", span_ms as f64 / 60000.0)
        } else {
            format!("{:.1}s span", span_ms as f64 / 1000.0)
        }
    } else {
        "".to_string()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .title(Line::from(vec![
            Span::styled(" Timeline ", Style::default().fg(TEXT_MUTED)),
            Span::styled(
                format!(
                    "#{}",
                    state.records.get(selected).map(|r| r.seq_num).unwrap_or(0)
                ),
                Style::default().fg(CYAN).bold(),
            ),
            Span::styled(
                format!(" ({:.0}%) ", position_pct),
                Style::default().fg(TEXT_MUTED),
            ),
            Span::styled(time_span, Style::default().fg(CYAN)),
        ]))
        .title_bottom(Line::from(Span::styled(
            " [ ] seek  T toggle ",
            Style::default().fg(TEXT_MUTED),
        )));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Draw histogram
    f.render_widget(
        Paragraph::new(Line::from(histogram_spans)).alignment(Alignment::Center),
        inner,
    );
}

fn draw_headers_popup(f: &mut Frame, record: &s2_sdk::types::SequencedRecord) {
    // Size popup based on number of headers (min height for "no headers" message)
    let content_lines = if record.headers.is_empty() {
        1
    } else {
        record.headers.len()
    };
    // Compact sizing: 5 lines overhead (title, record#, spacing, border) + content
    let height = ((content_lines + 5) as u16).min(20).min(f.area().height);
    let width = 45_u16.min(f.area().width);
    let x = f.area().x + f.area().width.saturating_sub(width) / 2;
    let y = f.area().y + f.area().height.saturating_sub(height) / 2;
    let area = Rect::new(x, y, width, height);

    let mut lines = vec![
        Line::from(""),
        Line::from(vec![Span::styled(
            format!("  Record #{}", record.seq_num),
            Style::default().fg(CYAN).bold(),
        )]),
        Line::from(""),
    ];

    if record.headers.is_empty() {
        lines.push(Line::from(vec![Span::styled(
            "  No headers",
            Style::default().fg(TEXT_MUTED).italic(),
        )]));
    } else {
        for header in &record.headers {
            let name = String::from_utf8_lossy(&header.name);
            let value = String::from_utf8_lossy(&header.value);
            lines.push(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(format!("{}", name), Style::default().fg(YELLOW)),
                Span::styled(" = ", Style::default().fg(BORDER)),
                Span::styled(format!("{}", value), Style::default().fg(TEXT_PRIMARY)),
            ]));
        }
    }

    let (title, border_color) = if record.headers.is_empty() {
        (" Headers ", BORDER)
    } else {
        (" Headers ", YELLOW)
    };

    let block = Block::default()
        .title(Line::from(Span::styled(
            title,
            Style::default().fg(border_color).bold(),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_DARK));

    f.render_widget(Clear, area);
    let para = Paragraph::new(lines)
        .block(block)
        .wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(para, area);
}

fn draw_append_view(f: &mut Frame, area: Rect, state: &AppendViewState) {
    // Split into header and content
    let outer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(1)])
        .split(area);

    let basin_str = state.basin_name.to_string();
    let stream_str = state.stream_name.to_string();
    let header_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  ← ", Style::default().fg(GRAY_600)),
            Span::styled(&basin_str, Style::default().fg(GRAY_300)),
            Span::styled(" / ", Style::default().fg(GRAY_700)),
            Span::styled(&stream_str, Style::default().fg(GRAY_200)),
            Span::styled("  ", Style::default()),
            Span::styled(" APPEND ", Style::default().fg(BG_DARK).bg(CYAN).bold()),
        ]),
    ];
    let header = Paragraph::new(header_lines).block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(BORDER_TITLE)),
    );
    f.render_widget(header, outer_chunks[0]);

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(outer_chunks[1]);

    let form_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(GRAY_750))
        .border_type(ratatui::widgets::BorderType::Rounded)
        .padding(Padding::new(2, 2, 1, 1));

    let form_inner = form_block.inner(main_chunks[0]);
    f.render_widget(form_block, main_chunks[0]);

    let cursor = |editing: bool| if editing { "▎" } else { "" };
    let selected_marker = |sel: bool| if sel { "▸ " } else { "  " };

    let mut lines: Vec<Line> = Vec::new();

    let body_selected = state.selected == 0;
    let body_editing = body_selected && state.editing;
    lines.push(Line::from(vec![
        Span::styled(selected_marker(body_selected), Style::default().fg(CYAN)),
        Span::styled(
            "Body",
            Style::default().fg(if body_selected {
                TEXT_PRIMARY
            } else {
                TEXT_MUTED
            }),
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  ", Style::default()),
        Span::styled(
            if state.body.is_empty() && !body_editing {
                "(empty)".to_string()
            } else {
                format!("{}{}", &state.body, cursor(body_editing))
            },
            Style::default().fg(if body_editing {
                CYAN
            } else if state.body.is_empty() {
                TEXT_MUTED
            } else {
                TEXT_SECONDARY
            }),
        ),
    ]));
    lines.push(Line::from(""));

    let headers_selected = state.selected == 1;
    let headers_editing = headers_selected && state.editing;
    lines.push(Line::from(vec![
        Span::styled(selected_marker(headers_selected), Style::default().fg(CYAN)),
        Span::styled(
            "Headers",
            Style::default().fg(if headers_selected {
                TEXT_PRIMARY
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled(
            format!("  ({} added)", state.headers.len()),
            Style::default().fg(TEXT_MUTED),
        ),
        if headers_selected && !headers_editing {
            Span::styled("  d=del", Style::default().fg(BORDER))
        } else {
            Span::raw("")
        },
    ]));

    for (key, value) in &state.headers {
        lines.push(Line::from(vec![
            Span::styled("    ", Style::default()),
            Span::styled(key, Style::default().fg(YELLOW)),
            Span::styled(": ", Style::default().fg(TEXT_MUTED)),
            Span::styled(value, Style::default().fg(TEXT_SECONDARY)),
        ]));
    }

    if headers_editing {
        lines.push(Line::from(vec![
            Span::styled("  + ", Style::default().fg(CYAN)),
            Span::styled(
                format!(
                    "{}{}",
                    &state.header_key_input,
                    if state.editing_header_key { "▎" } else { "" }
                ),
                Style::default().fg(if state.editing_header_key {
                    CYAN
                } else {
                    YELLOW
                }),
            ),
            Span::styled(": ", Style::default().fg(TEXT_MUTED)),
            Span::styled(
                format!(
                    "{}{}",
                    &state.header_value_input,
                    if !state.editing_header_key { "▎" } else { "" }
                ),
                Style::default().fg(if !state.editing_header_key {
                    CYAN
                } else {
                    TEXT_SECONDARY
                }),
            ),
            Span::styled("  ⇥=switch", Style::default().fg(BORDER)),
        ]));
    } else if headers_selected {
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                "Press Enter to add header",
                Style::default().fg(TEXT_MUTED).italic(),
            ),
        ]));
    }
    lines.push(Line::from(""));

    let match_selected = state.selected == 2;
    let match_editing = match_selected && state.editing;
    lines.push(Line::from(vec![
        Span::styled(selected_marker(match_selected), Style::default().fg(CYAN)),
        Span::styled(
            "Match Seq#",
            Style::default().fg(if match_selected {
                TEXT_PRIMARY
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            if state.match_seq_num.is_empty() && !match_editing {
                "(none)".to_string()
            } else {
                format!("{}{}", &state.match_seq_num, cursor(match_editing))
            },
            Style::default().fg(if match_editing {
                CYAN
            } else if state.match_seq_num.is_empty() {
                TEXT_MUTED
            } else {
                TEXT_SECONDARY
            }),
        ),
    ]));
    if match_selected {
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                help_text::MATCH_SEQ_NUM,
                Style::default().fg(GRAY_600).italic(),
            ),
        ]));
    }
    lines.push(Line::from(""));

    let fence_selected = state.selected == 3;
    let fence_editing = fence_selected && state.editing;
    lines.push(Line::from(vec![
        Span::styled(selected_marker(fence_selected), Style::default().fg(CYAN)),
        Span::styled(
            "Fencing Token",
            Style::default().fg(if fence_selected {
                TEXT_PRIMARY
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            if state.fencing_token.is_empty() && !fence_editing {
                "(none)".to_string()
            } else {
                format!("{}{}", &state.fencing_token, cursor(fence_editing))
            },
            Style::default().fg(if fence_editing {
                CYAN
            } else if state.fencing_token.is_empty() {
                TEXT_MUTED
            } else {
                TEXT_SECONDARY
            }),
        ),
    ]));
    if fence_selected {
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(
                help_text::APPEND_FENCING,
                Style::default().fg(GRAY_600).italic(),
            ),
        ]));
    }
    lines.push(Line::from(""));

    // Separator between single record and batch mode
    lines.push(Line::from(vec![
        Span::styled("  ─── ", Style::default().fg(GRAY_800)),
        Span::styled("or batch from file", Style::default().fg(TEXT_MUTED)),
        Span::styled(" ───────────────", Style::default().fg(GRAY_800)),
    ]));
    lines.push(Line::from(""));

    // Input file field
    let file_selected = state.selected == 4;
    let file_editing = file_selected && state.editing;
    lines.push(Line::from(vec![
        Span::styled(selected_marker(file_selected), Style::default().fg(CYAN)),
        Span::styled(
            "Input File",
            Style::default().fg(if file_selected {
                TEXT_PRIMARY
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled("  ", Style::default()),
        Span::styled(
            if state.input_file.is_empty() && !file_editing {
                "(none)".to_string()
            } else {
                format!("{}{}", &state.input_file, cursor(file_editing))
            },
            Style::default().fg(if file_editing {
                CYAN
            } else if state.input_file.is_empty() {
                TEXT_MUTED
            } else {
                CYAN
            }),
        ),
    ]));

    // Format selector (only shown when file is set)
    let format_selected = state.selected == 5;
    let format_opts = [
        ("Text", state.input_format == super::app::InputFormat::Text),
        ("JSON", state.input_format == super::app::InputFormat::Json),
        (
            "JSON+Base64",
            state.input_format == super::app::InputFormat::JsonBase64,
        ),
    ];
    lines.push(Line::from(vec![
        Span::styled(selected_marker(format_selected), Style::default().fg(CYAN)),
        Span::styled(
            "Format",
            Style::default().fg(if format_selected {
                TEXT_PRIMARY
            } else {
                TEXT_MUTED
            }),
        ),
        Span::styled("      ", Style::default()),
        render_pill(format_opts[0].0, format_selected, format_opts[0].1),
        Span::raw(" "),
        render_pill(format_opts[1].0, format_selected, format_opts[1].1),
        Span::raw(" "),
        render_pill(format_opts[2].0, format_selected, format_opts[2].1),
    ]));
    if format_selected {
        let format_help = match state.input_format {
            super::app::InputFormat::Text => help_text::FORMAT_TEXT,
            super::app::InputFormat::Json => help_text::FORMAT_JSON,
            super::app::InputFormat::JsonBase64 => help_text::FORMAT_JSON_BASE64,
        };
        lines.push(Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(format_help, Style::default().fg(GRAY_600).italic()),
        ]));
    }

    // Show progress if appending from file
    if let Some((done, total)) = state.file_append_progress {
        let pct = if total > 0 { (done * 100) / total } else { 0 };
        lines.push(Line::from(vec![
            Span::styled("    ", Style::default()),
            Span::styled(
                format!("Progress: {}/{} records ({}%)", done, total, pct),
                Style::default().fg(YELLOW),
            ),
        ]));
    }
    lines.push(Line::from(""));

    let send_selected = state.selected == 6;
    let can_send = (!state.body.is_empty() || !state.input_file.is_empty()) && !state.appending;
    let (btn_fg, btn_bg) = if state.appending {
        (BG_DARK, YELLOW)
    } else if send_selected && can_send {
        (BG_DARK, CYAN)
    } else {
        (if can_send { CYAN } else { TEXT_MUTED }, BG_PANEL)
    };
    let btn_text = if state.appending {
        if state.file_append_progress.is_some() {
            " ◌ APPENDING FILE... "
        } else {
            " ◌ SENDING... "
        }
    } else if !state.input_file.is_empty() {
        " ▶ APPEND FILE "
    } else {
        " ▶ SEND "
    };
    lines.push(Line::from(vec![
        Span::styled(selected_marker(send_selected), Style::default().fg(CYAN)),
        Span::styled(btn_text, Style::default().fg(btn_fg).bg(btn_bg).bold()),
    ]));

    let form_para = Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(form_para, form_inner);

    let history_block = Block::default()
        .title(Line::from(vec![
            Span::styled(" History ", Style::default().fg(TEXT_PRIMARY)),
            Span::styled(
                format!(" {} appended", state.history.len()),
                Style::default().fg(TEXT_MUTED),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER));

    if state.history.is_empty() {
        let text = Paragraph::new(Span::styled(
            "No records appended yet",
            Style::default().fg(TEXT_MUTED).italic(),
        ))
        .alignment(Alignment::Center)
        .block(history_block);
        f.render_widget(text, main_chunks[1]);
    } else {
        let history_inner = history_block.inner(main_chunks[1]);
        f.render_widget(history_block, main_chunks[1]);

        let visible_height = history_inner.height as usize;
        let start = state.history.len().saturating_sub(visible_height);

        let mut history_lines: Vec<Line> = Vec::new();
        for result in state.history.iter().skip(start) {
            let mut spans = vec![Span::styled(
                format!("#{:<8}", result.seq_num),
                Style::default().fg(CYAN),
            )];
            if result.header_count > 0 {
                spans.push(Span::styled(
                    format!(" ⌘{}", result.header_count),
                    Style::default().fg(YELLOW),
                ));
            }
            spans.push(Span::styled(
                format!(" {}", &result.body_preview),
                Style::default().fg(TEXT_SECONDARY),
            ));
            history_lines.push(Line::from(spans));
        }

        let history_para =
            Paragraph::new(history_lines).wrap(ratatui::widgets::Wrap { trim: false });
        f.render_widget(history_para, history_inner);
    }
}

fn draw_status_bar(f: &mut Frame, area: Rect, app: &App) {
    let width = area.width as usize;

    // Get hints based on available width - full, medium, or compact
    let hints = get_responsive_hints(&app.screen, width);

    // Create message spans with accessible text prefixes (not just colors)
    let message_spans: Option<Vec<Span>> = app.message.as_ref().map(|m| {
        let (prefix, prefix_color, text_color) = match m.level {
            MessageLevel::Info => ("ℹ ", CYAN, ACCENT),
            MessageLevel::Success => ("✓ ", SUCCESS, SUCCESS),
            MessageLevel::Error => ("✗ ", ERROR, ERROR),
        };
        vec![
            Span::styled(prefix, Style::default().fg(prefix_color).bold()),
            Span::styled(&m.text, Style::default().fg(text_color)),
        ]
    });

    // PiP indicator
    let pip_indicator: Option<Vec<Span>> = app.pip.as_ref().map(|pip| {
        vec![
            Span::styled(" PiP:", Style::default().fg(TEXT_MUTED)),
            Span::styled(format!("{}", pip.stream_name), Style::default().fg(CYAN)),
            Span::styled(" ", Style::default()),
        ]
    });

    // Calculate available width for hints after message and PiP indicator
    let msg_len = app.message.as_ref().map(|m| m.text.len() + 2).unwrap_or(0);
    let pip_len = app
        .pip
        .as_ref()
        .map(|p| p.stream_name.to_string().len() + 7)
        .unwrap_or(0);
    let available = width.saturating_sub(msg_len + pip_len);

    // Truncate hints if needed
    let display_hints: String = if hints.len() > available && available > 3 {
        format!("{}...", &hints[..available.saturating_sub(3)])
    } else {
        hints
    };

    let mut spans = Vec::new();

    if let Some(msg_spans) = message_spans {
        spans.extend(msg_spans);
        spans.push(Span::styled("  ", Style::default()));
    }

    if let Some(pip_spans) = pip_indicator {
        spans.extend(pip_spans);
    }

    spans.push(Span::styled(display_hints, Style::default().fg(TEXT_MUTED)));

    // Add persistent help hint indicator (always visible, stands out)
    let show_help_hint = !matches!(app.screen, Screen::Splash | Screen::Setup(_));
    if show_help_hint {
        // Calculate padding to right-align the help hint
        let current_len: usize = spans.iter().map(|s| s.content.len()).sum();
        let help_hint = " ? help";
        let padding_needed = width.saturating_sub(current_len + help_hint.len());
        if padding_needed > 0 {
            spans.push(Span::styled(" ".repeat(padding_needed), Style::default()));
        }
        spans.push(Span::styled("?", Style::default().fg(CYAN).bold()));
        spans.push(Span::styled(" help", Style::default().fg(TEXT_MUTED)));
    }

    let line = Line::from(spans);
    let status = Paragraph::new(line);
    f.render_widget(status, area);
}

/// Get responsive hints based on screen width
fn get_responsive_hints(screen: &Screen, width: usize) -> String {
    // Width thresholds
    let wide = width >= 100;
    let medium = width >= 60;

    match screen {
        Screen::Splash | Screen::Setup(_) => String::new(),
        Screen::Settings(_) => {
            if wide {
                "jk nav | e edit | hl compression | space toggle | ⏎ save | r reload | ⇥ switch | q"
                    .to_string()
            } else if medium {
                "jk e hl space ⏎ r ⇥ q".to_string()
            } else {
                "jk e ⏎ r ⇥ q".to_string()
            }
        }
        Screen::Basins(_) => {
            if wide {
                "/ filter | jk nav | ⏎ open | B bench | M metrics | A acct | c new | e cfg | d del | r ref | ?".to_string()
            } else if medium {
                "/ | jk ⏎ | B bench | M A | c d e r ?".to_string()
            } else {
                "jk ⏎ B M A c d ?".to_string()
            }
        }
        Screen::Streams(_) => {
            if wide {
                "/ filter | jk nav | ⏎ open | M metrics | c new | e cfg | d del | esc".to_string()
            } else if medium {
                "/ filter | jk nav | ⏎ open | M c e d | esc".to_string()
            } else {
                "jk ⏎ M c d esc".to_string()
            }
        }
        Screen::StreamDetail(_) => {
            if wide {
                "t tail | r read | a append | f fence | m trim | p pip | M metrics | e cfg | esc"
                    .to_string()
            } else if medium {
                "t tail | r read | a append | p pip | f m M e | esc".to_string()
            } else {
                "t r a p f m M esc".to_string()
            }
        }
        Screen::ReadView(s) => {
            if s.show_detail {
                "esc/⏎ close".to_string()
            } else if s.is_tailing {
                if wide {
                    "jk nav | [] seek | h headers | T timeline | ⇥ list | space pause | esc"
                        .to_string()
                } else if medium {
                    "jk [] nav | h | T time | ⇥ | space | esc".to_string()
                } else {
                    "jk [] h T ⇥ space esc".to_string()
                }
            } else if wide {
                "jk nav | [] seek | h headers | T timeline | ⇥ list | esc".to_string()
            } else if medium {
                "jk [] nav | h | T time | ⇥ | esc".to_string()
            } else {
                "jk [] h T ⇥ esc".to_string()
            }
        }
        Screen::AppendView(s) => {
            if s.editing {
                if s.selected == 1 {
                    "type | ⇥ key/val | ⏎ add | esc done".to_string()
                } else {
                    "type | ⏎ done | esc cancel".to_string()
                }
            } else if wide {
                "jk nav | ⏎ edit/send | d del header | esc back".to_string()
            } else {
                "jk ⏎ edit | d del | esc".to_string()
            }
        }
        Screen::AccessTokens(_) => {
            if wide {
                "/ filter | jk nav | c issue | d revoke | r ref | ⇥ switch | ? | q".to_string()
            } else if medium {
                "/ | jk | c issue | d rev | r | ⇥ | ? q".to_string()
            } else {
                "jk c d r ⇥ ? q".to_string()
            }
        }
        Screen::MetricsView(state) => {
            if matches!(
                state.metrics_type,
                MetricsType::Basin { .. } | MetricsType::Account
            ) {
                if wide {
                    "←→ category | jk scroll | t time range | r refresh | esc back | q quit"
                        .to_string()
                } else {
                    "←→ cat | jk | t time | r | esc q".to_string()
                }
            } else if wide {
                "jk scroll | t time range | r refresh | esc back | q quit".to_string()
            } else {
                "jk | t time | r | esc q".to_string()
            }
        }
        Screen::BenchView(state) => {
            if state.config_phase {
                if wide {
                    "jk nav | ←→ adjust | ⏎ edit/start | esc back | q quit".to_string()
                } else {
                    "jk ←→ ⏎ esc q".to_string()
                }
            } else if state.running {
                if wide {
                    "space pause | q stop".to_string()
                } else {
                    "space q".to_string()
                }
            } else if wide {
                "r restart | esc back | q quit".to_string()
            } else {
                "r esc q".to_string()
            }
        }
    }
}

fn draw_help_overlay(f: &mut Frame, screen: &Screen) {
    let area = centered_rect(60, 70, f.area());

    // Helper to create a section header
    fn section(title: &str) -> Line<'static> {
        Line::from(vec![
            Span::styled("  ", Style::default()),
            Span::styled(format!("─── {} ", title), Style::default().fg(CYAN).bold()),
            Span::styled("─".repeat(20), Style::default().fg(GRAY_800)),
        ])
    }

    // Helper to create a key binding line with description
    fn key(keys: &str, action: &str, desc: &str) -> Line<'static> {
        let mut spans = vec![
            Span::styled(format!("{:>6} ", keys), Style::default().fg(CYAN).bold()),
            Span::styled(
                format!("{:<20}", action),
                Style::default().fg(TEXT_SECONDARY),
            ),
        ];
        if !desc.is_empty() {
            spans.push(Span::styled(
                format!("  {}", desc),
                Style::default().fg(TEXT_MUTED).italic(),
            ));
        }
        Line::from(spans)
    }

    // Get the screen title for the help header
    let screen_title = match screen {
        Screen::Splash | Screen::Setup(_) => "",
        Screen::Settings(_) => "Settings",
        Screen::Basins(_) => "Basins",
        Screen::Streams(_) => "Streams",
        Screen::StreamDetail(_) => "Stream Detail",
        Screen::ReadView(_) => "Read View",
        Screen::AppendView(_) => "Append Records",
        Screen::AccessTokens(_) => "Access Tokens",
        Screen::MetricsView(_) => "Metrics",
        Screen::BenchView(_) => "Benchmark",
    };

    let mut help_text = match screen {
        Screen::Splash | Screen::Setup(_) => vec![],
        Screen::Settings(_) => vec![
            Line::from(""),
            section("Navigation"),
            key("j / k", "Move down / up", "Navigate between settings"),
            key("g / G", "Jump to top / bottom", ""),
            Line::from(""),
            section("Editing"),
            key("e", "Edit field", "Modify the selected setting"),
            key(
                "h / l",
                "Cycle option left / right",
                "Change compression level",
            ),
            key("space", "Toggle visibility", "Show/hide auth token"),
            key("enter", "Save changes", "Write settings to config file"),
            key("r", "Reload", "Discard changes, reload from file"),
            Line::from(""),
            section("Application"),
            key(
                "tab",
                "Switch tab",
                "Navigate between Basins/Tokens/Settings",
            ),
            key("q", "Quit", "Exit the application"),
            Line::from(""),
        ],
        Screen::Basins(_) => vec![
            Line::from(""),
            section("Navigation"),
            key("j / k", "Move down / up", "Navigate basin list"),
            key("g / G", "Jump to top / bottom", ""),
            key("/", "Filter", "Search basins by name"),
            key("enter", "Open basin", "View streams in selected basin"),
            Line::from(""),
            section("Basin Actions"),
            key("c", "Create basin", "Create a new basin"),
            key("e", "Configure", "Modify basin settings"),
            key("d", "Delete", "Remove selected basin (requires confirm)"),
            key("r", "Refresh", "Reload basin list from server"),
            Line::from(""),
            section("Analytics"),
            key("B", "Benchmark", "Run performance benchmark on basin"),
            key("M", "Basin metrics", "View metrics for selected basin"),
            key("A", "Account metrics", "View account-level metrics"),
            Line::from(""),
            section("Application"),
            key("tab", "Switch tab", "Go to Access Tokens or Settings"),
            key("q", "Quit", "Exit the application"),
            Line::from(""),
        ],
        Screen::Streams(_) => vec![
            Line::from(""),
            section("Navigation"),
            key("j / k", "Move down / up", "Navigate stream list"),
            key("g / G", "Jump to top / bottom", ""),
            key("/", "Filter", "Search streams by name"),
            key("enter", "Open stream", "View stream details and actions"),
            Line::from(""),
            section("Stream Actions"),
            key("c", "Create stream", "Create a new stream in this basin"),
            key("e", "Configure", "Modify stream settings"),
            key("d", "Delete", "Remove selected stream (requires confirm)"),
            key("r", "Refresh", "Reload stream list from server"),
            key("M", "Metrics", "View metrics for selected stream"),
            Line::from(""),
            section("Navigation"),
            key("esc", "Back", "Return to basins list"),
            Line::from(""),
        ],
        Screen::StreamDetail(_) => vec![
            Line::from(""),
            section("Navigation"),
            key("j / k", "Move down / up", "Navigate action menu"),
            key("enter", "Execute", "Run the selected action"),
            Line::from(""),
            section("Data Operations"),
            key("t", "Tail", "Follow stream in real-time (live updates)"),
            key("r", "Read", "Read records from a specific position"),
            key("a", "Append", "Add new records to the stream"),
            Line::from(""),
            section("Stream Management"),
            key("f", "Fence", "Create a fencing token for coordination"),
            key("m", "Trim", "Remove old records up to a sequence"),
            key("e", "Configure", "Modify stream settings"),
            key("M", "Metrics", "View stream performance metrics"),
            Line::from(""),
            section("Multi-tasking"),
            key("p", "Pin to PiP", "Monitor stream in picture-in-picture"),
            key("P", "Toggle PiP", "Show/hide the PiP window"),
            Line::from(""),
            section("Navigation"),
            key("esc", "Back", "Return to streams list"),
            Line::from(""),
        ],
        Screen::ReadView(state) => {
            let mut lines = vec![
                Line::from(""),
                section("Scrolling"),
                key("j / k", "Scroll down / up", "Move through records"),
                key("g / G", "Jump to top / bottom", ""),
                key(
                    "[ / ]",
                    "Seek backward / forward",
                    "Jump by larger increments",
                ),
            ];
            if state.is_tailing {
                lines.push(Line::from(""));
                lines.push(section("Live Tailing"));
                lines.push(key(
                    "space",
                    "Pause / Resume",
                    "Temporarily stop live updates",
                ));
            }
            lines.extend(vec![
                Line::from(""),
                section("Display"),
                key("h", "Toggle headers", "Show/hide record headers"),
                key("T", "Timeline", "Open timeline scrubber"),
                key("tab", "Toggle record list", "Switch focus to record list"),
                key("enter", "Record detail", "View full record content"),
                Line::from(""),
                section("Multi-tasking"),
                key("p", "Pin to PiP", "Continue monitoring in background"),
                Line::from(""),
                section("Navigation"),
                key("esc", "Back", "Return to stream detail"),
                Line::from(""),
            ]);
            lines
        }
        Screen::AppendView(state) => {
            if state.editing {
                vec![
                    Line::from(""),
                    section("Text Input"),
                    key("type", "Enter text", "Type your content"),
                    key("enter", "Confirm", "Save the current field"),
                    key("esc", "Cancel", "Discard changes to field"),
                    Line::from(""),
                    section("Header Fields"),
                    key(
                        "tab",
                        "Switch key/value",
                        "Toggle between header key and value",
                    ),
                    Line::from(""),
                ]
            } else {
                vec![
                    Line::from(""),
                    section("Navigation"),
                    key("j / k", "Move down / up", "Navigate between fields"),
                    Line::from(""),
                    section("Single Record"),
                    key("enter", "Edit / Send", "Edit field or send the record"),
                    key("d", "Delete header", "Remove the last header entry"),
                    Line::from(""),
                    section("Batch from File"),
                    key("enter", "Edit file path", "Enter path to file with records"),
                    key(
                        "",
                        "(one record per line)",
                        "Each line becomes a record body",
                    ),
                    Line::from(""),
                    section("Navigation"),
                    key("esc", "Back", "Return to stream detail"),
                    Line::from(""),
                ]
            }
        }
        Screen::AccessTokens(_) => vec![
            Line::from(""),
            section("Navigation"),
            key("j / k", "Move down / up", "Navigate token list"),
            key("g / G", "Jump to top / bottom", ""),
            key("/", "Filter", "Search tokens by ID"),
            Line::from(""),
            section("Token Actions"),
            key("c", "Issue token", "Create a new access token"),
            key("d", "Revoke", "Invalidate the selected token"),
            key("r", "Refresh", "Reload token list from server"),
            Line::from(""),
            section("Application"),
            key("tab", "Switch tab", "Go to Basins or Settings"),
            key("q", "Quit", "Exit the application"),
            Line::from(""),
        ],
        Screen::MetricsView(state) => {
            let mut lines = vec![
                Line::from(""),
                section("Navigation"),
                key("j / k", "Scroll down / up", "Navigate metrics display"),
            ];
            if matches!(
                state.metrics_type,
                MetricsType::Basin { .. } | MetricsType::Account
            ) {
                lines.push(key(
                    "← / →",
                    "Change category",
                    "Switch between metric types",
                ));
            }
            lines.extend(vec![
                Line::from(""),
                section("Actions"),
                key("r", "Refresh", "Reload metrics from server"),
                key("t", "Time range", "Open time range picker"),
                Line::from(""),
                section("Navigation"),
                key("esc", "Back", "Return to previous screen"),
                key("q", "Quit", "Exit the application"),
                Line::from(""),
            ]);
            lines
        }
        Screen::BenchView(state) => {
            if state.config_phase {
                vec![
                    Line::from(""),
                    section("Configuration"),
                    key("j / k", "Move down / up", "Navigate benchmark settings"),
                    key("h / l", "Decrease / Increase", "Adjust numeric values"),
                    key("enter", "Edit / Start", "Edit field or start benchmark"),
                    Line::from(""),
                    section("Navigation"),
                    key("esc", "Back", "Return to basin view"),
                    key("q", "Quit", "Exit the application"),
                    Line::from(""),
                ]
            } else if state.running {
                vec![
                    Line::from(""),
                    section("Benchmark Control"),
                    key(
                        "space",
                        "Pause / Resume",
                        "Temporarily stop/continue benchmark",
                    ),
                    key("q", "Stop", "End benchmark and show results"),
                    Line::from(""),
                ]
            } else {
                vec![
                    Line::from(""),
                    section("Results"),
                    key("r", "Restart", "Run the benchmark again"),
                    Line::from(""),
                    section("Navigation"),
                    key("esc", "Back", "Return to basin view"),
                    key("q", "Quit", "Exit the application"),
                    Line::from(""),
                ]
            }
        }
    };

    // Add dismiss hint at the bottom
    if !help_text.is_empty() {
        help_text.push(Line::from(vec![
            Span::styled("  Press ", Style::default().fg(TEXT_MUTED)),
            Span::styled("?", Style::default().fg(CYAN).bold()),
            Span::styled(" or ", Style::default().fg(TEXT_MUTED)),
            Span::styled("Esc", Style::default().fg(CYAN).bold()),
            Span::styled(" to close this help", Style::default().fg(TEXT_MUTED)),
        ]));
    }

    let title = format!(" {} · Keyboard Shortcuts ", screen_title);
    let block = Block::default()
        .title(Line::from(Span::styled(
            title,
            Style::default().fg(TEXT_PRIMARY).bold(),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(ACCENT))
        .style(Style::default().bg(BG_DARK))
        .padding(Padding::horizontal(1));

    let help = Paragraph::new(help_text).block(block);

    f.render_widget(Clear, area);
    f.render_widget(help, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    // Calculate target size from percentage
    let target_width = (area.width as u32 * percent_x as u32 / 100) as u16;
    let target_height = (area.height as u32 * percent_y as u32 / 100) as u16;

    // Apply minimum sizes to ensure readability on small terminals
    let width = target_width.max(MIN_DIALOG_WIDTH).min(area.width);
    let height = target_height.max(MIN_DIALOG_HEIGHT).min(area.height);

    // Center the rectangle
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;

    Rect::new(x, y, width, height)
}

fn get_selected_line_hint(mode: &InputMode) -> usize {
    match mode {
        InputMode::Normal => 0,
        InputMode::CreateBasin { selected, .. } => match selected {
            0 => 3,   // Name
            1 => 7,   // Region
            2 => 12,  // Storage
            3 => 16,  // Retention
            4 => 19,  // Duration
            5 => 22,  // Timestamps
            6 => 26,  // Uncapped
            7 => 30,  // Delete on empty
            8 => 34,  // Threshold
            9 => 40,  // On append
            10 => 44, // On read
            _ => 48,  // Button
        },
        InputMode::CreateStream { selected, .. } => match selected {
            0 => 5,  // Name
            1 => 12, // Storage
            2 => 16, // Retention
            3 => 19, // Duration
            4 => 22, // Timestamps
            5 => 26, // Uncapped
            6 => 30, // Delete on empty
            7 => 34, // Threshold
            _ => 38, // Button
        },
        InputMode::ReconfigureBasin { selected, .. } => match selected {
            0 => 6,  // Storage
            1 => 10, // Retention
            2 => 14, // Duration
            3 => 18, // Timestamps
            4 => 22, // Uncapped
            5 => 28, // On append
            6 => 32, // On read
            _ => 36,
        },
        InputMode::ReconfigureStream { selected, .. } => match selected {
            0 => 6,  // Storage
            1 => 10, // Retention
            2 => 14, // Duration
            3 => 18, // Timestamps
            4 => 22, // Uncapped
            5 => 26, // Delete on empty
            6 => 30, // Threshold
            _ => 34,
        },
        InputMode::CustomRead { selected, .. } => match selected {
            0 => 6,  // Seq num
            1 => 9,  // Timestamp
            2 => 12, // Time ago
            3 => 15, // Tail offset
            4 => 20, // Max records
            5 => 23, // Max bytes
            6 => 26, // Until
            7 => 31, // Clamp
            8 => 35, // Format
            9 => 40, // Output file
            _ => 45, // Button
        },
        InputMode::IssueAccessToken { selected, .. } => match selected {
            0 => 2,   // Token ID
            1 => 5,   // Expiration
            2 => 9,   // Custom duration
            3 => 14,  // Basins scope
            4 => 17,  // Basins pattern
            5 => 20,  // Streams scope
            6 => 23,  // Streams pattern
            7 => 26,  // Tokens scope
            8 => 29,  // Tokens pattern
            9 => 34,  // Account read
            10 => 36, // Account write
            11 => 38, // Basin read
            12 => 40, // Basin write
            13 => 42, // Stream read
            14 => 44, // Stream write
            15 => 48, // Auto prefix
            _ => 52,  // Button
        },
        InputMode::Fence { selected, .. } => *selected * 4 + 5,
        InputMode::Trim { selected, .. } => *selected * 4 + 5,
        InputMode::ConfirmDeleteBasin { .. }
        | InputMode::ConfirmDeleteStream { .. }
        | InputMode::ConfirmRevokeToken { .. }
        | InputMode::ShowIssuedToken { .. }
        | InputMode::ViewTokenDetail { .. } => 0,
    }
}

fn draw_input_dialog(f: &mut Frame, mode: &InputMode) {
    let (title, content, hint) = match mode {
        InputMode::Normal => return,

        InputMode::CreateBasin {
            name,
            scope,
            create_stream_on_append,
            create_stream_on_read,
            storage_class,
            retention_policy,
            retention_age_input,
            timestamping_mode,
            timestamping_uncapped,
            delete_on_empty_enabled,
            delete_on_empty_min_age,
            selected,
            editing,
            cursor,
        } => {
            use crate::tui::app::BasinScopeOption;

            let name_valid = name.len() >= 8 && name.len() <= 48;

            // Scope options
            let scope_opts = [("AWS us-east-1", *scope == BasinScopeOption::AwsUsEast1)];

            // Storage class options
            let storage_opts = [
                ("Default", storage_class.is_none()),
                (
                    "Standard",
                    matches!(storage_class, Some(StorageClass::Standard)),
                ),
                (
                    "Express",
                    matches!(storage_class, Some(StorageClass::Express)),
                ),
            ];

            // Timestamping mode options
            let ts_opts = [
                ("Default", timestamping_mode.is_none()),
                (
                    "ClientPrefer",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientPrefer)),
                ),
                (
                    "ClientRequire",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientRequire)),
                ),
                (
                    "Arrival",
                    matches!(timestamping_mode, Some(TimestampingMode::Arrival)),
                ),
            ];
            let ret_opts = [
                (
                    "Infinite",
                    *retention_policy == RetentionPolicyOption::Infinite,
                ),
                ("Age-based", *retention_policy == RetentionPolicyOption::Age),
            ];

            let mut lines = vec![];

            // Basin name section
            lines.push(Line::from(""));
            lines.push(render_section_header("Basin name", 48));
            lines.push(Line::from(""));

            // Basin Name field
            let (ind, lbl) = render_field_row_bold(0, "Name", *selected);
            let name_color = if name.is_empty() {
                GRAY_600
            } else if name_valid {
                CYAN
            } else {
                YELLOW
            };
            let mut name_spans = vec![ind, lbl, Span::raw("  ")];
            name_spans.extend(render_text_input_with_cursor(
                name,
                *selected == 0 && *editing,
                "enter name...",
                name_color,
                *cursor,
            ));
            lines.push(Line::from(name_spans));

            // Validation hint
            let hint_text = if name.is_empty() {
                "lowercase, numbers, hyphens (8-48 chars)".to_string()
            } else if name.len() < 8 {
                format!("{} more chars needed", 8 - name.len())
            } else if name.len() > 48 {
                "name too long".to_string()
            } else {
                format!("{}/48 chars", name.len())
            };
            let hint_color = if name_valid || name.is_empty() {
                GRAY_600
            } else {
                YELLOW
            };
            lines.push(Line::from(vec![
                Span::raw("              "),
                Span::styled(hint_text, Style::default().fg(hint_color).italic()),
            ]));

            // Basin Scope (Cloud Provider/Region)
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(1, "Region", *selected);
            let mut scope_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &scope_opts {
                scope_spans.push(render_pill(label, *selected == 1, *active));
                scope_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(scope_spans));

            // Default stream configuration section
            lines.push(Line::from(""));
            lines.push(render_section_header("Default stream configuration", 48));
            lines.push(Line::from(""));

            // Storage Class
            let (ind, lbl) = render_field_row_bold(2, "Storage", *selected);
            let mut storage_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &storage_opts {
                storage_spans.push(render_pill(label, *selected == 2, *active));
                storage_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(storage_spans));

            // Storage class help text
            if *selected == 2 {
                let storage_help = match storage_class {
                    None => help_text::STORAGE_DEFAULT,
                    Some(StorageClass::Standard) => help_text::STORAGE_STANDARD,
                    Some(StorageClass::Express) => help_text::STORAGE_EXPRESS,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(storage_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(3, "Retention", *selected);
            let mut ret_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ret_opts {
                ret_spans.push(render_pill(label, *selected == 3, *active));
                ret_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ret_spans));

            // Retention help text
            if *selected == 3 {
                let ret_help = match retention_policy {
                    RetentionPolicyOption::Infinite => help_text::RETENTION_INFINITE,
                    RetentionPolicyOption::Age => help_text::RETENTION_AGE,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ret_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            if *retention_policy == RetentionPolicyOption::Age {
                let (ind, lbl) = render_field_row_bold(4, "  Duration", *selected);
                let mut duration_spans = vec![ind, lbl, Span::raw("  ")];
                duration_spans.extend(render_text_input_with_cursor(
                    retention_age_input,
                    *selected == 4 && *editing,
                    "",
                    YELLOW,
                    *cursor,
                ));
                duration_spans.push(Span::styled(
                    "  e.g. 7d, 30d, 1y",
                    Style::default().fg(GRAY_600).italic(),
                ));
                lines.push(Line::from(duration_spans));
            }

            // Timestamping Mode
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(5, "Timestamps", *selected);
            let mut ts_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ts_opts {
                ts_spans.push(render_pill(label, *selected == 5, *active));
                ts_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ts_spans));

            // Timestamping mode help text
            if *selected == 5 {
                let ts_help = match timestamping_mode {
                    None => help_text::TS_DEFAULT,
                    Some(TimestampingMode::ClientPrefer) => help_text::TS_CLIENT_PREFER,
                    Some(TimestampingMode::ClientRequire) => help_text::TS_CLIENT_REQUIRE,
                    Some(TimestampingMode::Arrival) => help_text::TS_ARRIVAL,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ts_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Uncapped Timestamps
            let (ind, lbl) = render_field_row_bold(6, "  Uncapped", *selected);
            let mut uncapped_spans = vec![ind, lbl, Span::raw("  ")];
            uncapped_spans.extend(render_toggle(*timestamping_uncapped, *selected == 6));
            lines.push(Line::from(uncapped_spans));

            // Uncapped help text
            if *selected == 6 {
                let uncapped_help = if *timestamping_uncapped {
                    help_text::TS_UNCAPPED
                } else {
                    help_text::TS_CAPPED
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(uncapped_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Delete on Empty
            let delete_opts = [
                ("Never", !*delete_on_empty_enabled),
                ("After threshold", *delete_on_empty_enabled),
            ];
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(7, "Delete on empty", *selected);
            let mut del_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &delete_opts {
                del_spans.push(render_pill(label, *selected == 7, *active));
                del_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(del_spans));

            // Delete on empty help text
            if *selected == 7 {
                let del_help = if *delete_on_empty_enabled {
                    help_text::DELETE_THRESHOLD
                } else {
                    help_text::DELETE_NEVER
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(del_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Delete on Empty Threshold (conditional)
            if *delete_on_empty_enabled {
                let (ind, lbl) = render_field_row_bold(8, "  Threshold", *selected);
                let mut threshold_spans = vec![ind, lbl, Span::raw("  ")];
                threshold_spans.extend(render_text_input_with_cursor(
                    delete_on_empty_min_age,
                    *selected == 8 && *editing,
                    "",
                    YELLOW,
                    *cursor,
                ));
                threshold_spans.push(Span::styled(
                    "  e.g. 1h, 7d",
                    Style::default().fg(GRAY_600).italic(),
                ));
                lines.push(Line::from(threshold_spans));
            }

            // Create streams automatically section
            lines.push(Line::from(""));
            lines.push(render_section_header("Create streams automatically", 48));
            lines.push(Line::from(""));

            // On Append
            let (ind, lbl) = render_field_row_bold(9, "On append", *selected);
            let mut append_spans = vec![ind, lbl, Span::raw("  ")];
            append_spans.extend(render_toggle(*create_stream_on_append, *selected == 9));
            lines.push(Line::from(append_spans));

            // On append help text
            if *selected == 9 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::AUTO_CREATE_APPEND,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // On Read
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(10, "On read", *selected);
            let mut read_spans = vec![ind, lbl, Span::raw("  ")];
            read_spans.extend(render_toggle(*create_stream_on_read, *selected == 10));
            lines.push(Line::from(read_spans));

            // On read help text
            if *selected == 10 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::AUTO_CREATE_READ,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // Create button section
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "─".repeat(52),
                Style::default().fg(GRAY_750),
            )]));
            lines.push(Line::from(""));

            let can_create = name_valid;
            lines.push(render_button(
                "CREATE BASIN",
                *selected == 11,
                can_create,
                CYAN,
            ));
            if !can_create {
                lines.push(Line::from(vec![
                    Span::raw("      "),
                    Span::styled("(enter valid name)", Style::default().fg(GRAY_600).italic()),
                ]));
            }

            lines.push(Line::from(""));

            (
                " Create Basin ",
                lines,
                "j/k navigate · h/l cycle · Space toggle · Enter edit · Esc cancel",
            )
        }

        InputMode::CreateStream {
            basin,
            name,
            storage_class,
            retention_policy,
            retention_age_input,
            timestamping_mode,
            timestamping_uncapped,
            delete_on_empty_enabled,
            delete_on_empty_min_age,
            selected,
            editing,
            cursor,
        } => {
            // Storage options
            let storage_opts = [
                ("Default", storage_class.is_none()),
                (
                    "Standard",
                    matches!(storage_class, Some(StorageClass::Standard)),
                ),
                (
                    "Express",
                    matches!(storage_class, Some(StorageClass::Express)),
                ),
            ];

            // Timestamping mode options
            let ts_opts = [
                ("Default", timestamping_mode.is_none()),
                (
                    "ClientPrefer",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientPrefer)),
                ),
                (
                    "ClientRequire",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientRequire)),
                ),
                (
                    "Arrival",
                    matches!(timestamping_mode, Some(TimestampingMode::Arrival)),
                ),
            ];
            let ret_opts = [
                (
                    "Infinite",
                    *retention_policy == RetentionPolicyOption::Infinite,
                ),
                ("Age-based", *retention_policy == RetentionPolicyOption::Age),
            ];

            let mut lines = vec![
                Line::from(""),
                render_section_header("Stream name", 48),
                Line::from(""),
            ];

            // Show which basin this stream will be created in
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled("in basin: ", Style::default().fg(GRAY_600)),
                Span::styled(basin.to_string(), Style::default().fg(TEXT_SECONDARY)),
            ]));
            lines.push(Line::from(""));

            // Stream Name field
            let (ind, lbl) = render_field_row(0, "Name", *selected);
            let name_color = if name.is_empty() { GRAY_600 } else { CYAN };
            let mut name_spans = vec![ind, lbl, Span::raw("  ")];
            name_spans.extend(render_text_input_with_cursor(
                name,
                *selected == 0 && *editing,
                "enter name...",
                name_color,
                *cursor,
            ));
            lines.push(Line::from(name_spans));

            // Stream configuration section
            lines.push(Line::from(""));
            lines.push(render_section_header("Stream configuration", 48));
            lines.push(Line::from(""));

            // Storage Class
            let (ind, lbl) = render_field_row(1, "Storage", *selected);
            let mut storage_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &storage_opts {
                storage_spans.push(render_pill(label, *selected == 1, *active));
                storage_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(storage_spans));

            // Storage class help text
            if *selected == 1 {
                let storage_help = match storage_class {
                    None => help_text::STORAGE_DEFAULT,
                    Some(StorageClass::Standard) => help_text::STORAGE_STANDARD,
                    Some(StorageClass::Express) => help_text::STORAGE_EXPRESS,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(storage_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row(2, "Retention", *selected);
            let mut ret_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ret_opts {
                ret_spans.push(render_pill(label, *selected == 2, *active));
                ret_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ret_spans));

            // Retention help text
            if *selected == 2 {
                let ret_help = match retention_policy {
                    RetentionPolicyOption::Infinite => help_text::RETENTION_INFINITE,
                    RetentionPolicyOption::Age => help_text::RETENTION_AGE,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ret_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            if *retention_policy == RetentionPolicyOption::Age {
                let (ind, lbl) = render_field_row(3, "  Duration", *selected);
                let mut duration_spans = vec![ind, lbl, Span::raw("  ")];
                duration_spans.extend(render_text_input_with_cursor(
                    retention_age_input,
                    *selected == 3 && *editing,
                    "",
                    YELLOW,
                    *cursor,
                ));
                duration_spans.push(Span::styled(
                    "  e.g. 7d, 30d, 1y",
                    Style::default().fg(GRAY_600).italic(),
                ));
                lines.push(Line::from(duration_spans));
            }

            // Timestamping Mode
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row(4, "Timestamps", *selected);
            let mut ts_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ts_opts {
                ts_spans.push(render_pill(label, *selected == 4, *active));
                ts_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ts_spans));

            // Timestamping mode help text
            if *selected == 4 {
                let ts_help = match timestamping_mode {
                    None => help_text::TS_DEFAULT,
                    Some(TimestampingMode::ClientPrefer) => help_text::TS_CLIENT_PREFER,
                    Some(TimestampingMode::ClientRequire) => help_text::TS_CLIENT_REQUIRE,
                    Some(TimestampingMode::Arrival) => help_text::TS_ARRIVAL,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ts_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Uncapped Timestamps
            let (ind, lbl) = render_field_row(5, "  Uncapped", *selected);
            let mut uncapped_spans = vec![ind, lbl, Span::raw("  ")];
            uncapped_spans.extend(render_toggle(*timestamping_uncapped, *selected == 5));
            lines.push(Line::from(uncapped_spans));

            // Uncapped help text
            if *selected == 5 {
                let uncapped_help = if *timestamping_uncapped {
                    help_text::TS_UNCAPPED
                } else {
                    help_text::TS_CAPPED
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(uncapped_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Delete on Empty
            let delete_opts = [
                ("Never", !*delete_on_empty_enabled),
                ("After threshold", *delete_on_empty_enabled),
            ];
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row(6, "Delete on empty", *selected);
            let mut del_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &delete_opts {
                del_spans.push(render_pill(label, *selected == 6, *active));
                del_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(del_spans));

            // Delete on empty help text
            if *selected == 6 {
                let del_help = if *delete_on_empty_enabled {
                    help_text::DELETE_THRESHOLD
                } else {
                    help_text::DELETE_NEVER
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(del_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Delete on Empty Threshold (conditional)
            if *delete_on_empty_enabled {
                let (ind, lbl) = render_field_row(7, "  Threshold", *selected);
                let mut threshold_spans = vec![ind, lbl, Span::raw("  ")];
                threshold_spans.extend(render_text_input_with_cursor(
                    delete_on_empty_min_age,
                    *selected == 7 && *editing,
                    "",
                    YELLOW,
                    *cursor,
                ));
                threshold_spans.push(Span::styled(
                    "  e.g. 1h, 7d",
                    Style::default().fg(GRAY_600).italic(),
                ));
                lines.push(Line::from(threshold_spans));
            }

            // Create button section
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "─".repeat(52),
                Style::default().fg(GRAY_750),
            )]));
            lines.push(Line::from(""));

            let can_create = !name.is_empty();
            lines.push(render_button(
                "CREATE STREAM",
                *selected == 8,
                can_create,
                CYAN,
            ));
            if !can_create {
                lines.push(Line::from(vec![
                    Span::raw("      "),
                    Span::styled(
                        "(enter stream name)",
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            lines.push(Line::from(""));

            (
                " Create Stream ",
                lines,
                "j/k navigate · h/l cycle · Space toggle · Enter edit · Esc cancel",
            )
        }

        InputMode::ConfirmDeleteBasin { basin } => (
            " ⚠ Delete Basin ",
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Are you sure you want to delete ",
                    Style::default().fg(TEXT_SECONDARY),
                )]),
                Line::from(vec![
                    Span::styled(basin.to_string(), Style::default().fg(WHITE).bold()),
                    Span::styled("?", Style::default().fg(TEXT_SECONDARY)),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "All streams in this basin will be deleted.",
                    Style::default().fg(TEXT_MUTED),
                )]),
                Line::from(vec![Span::styled(
                    "This action cannot be undone.",
                    Style::default().fg(ERROR),
                )]),
            ],
            "y confirm  n/esc cancel",
        ),

        InputMode::ConfirmDeleteStream { basin, stream } => (
            " ⚠ Delete Stream ",
            vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Are you sure you want to delete ",
                    Style::default().fg(TEXT_SECONDARY),
                )]),
                Line::from(vec![Span::styled(
                    stream.to_string(),
                    Style::default().fg(WHITE).bold(),
                )]),
                Line::from(vec![
                    Span::styled("from ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(basin.to_string(), Style::default().fg(TEXT_SECONDARY)),
                    Span::styled("?", Style::default().fg(TEXT_MUTED)),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "This action cannot be undone.",
                    Style::default().fg(ERROR),
                )]),
            ],
            "y confirm  n/esc cancel",
        ),

        InputMode::ReconfigureBasin {
            basin,
            create_stream_on_append,
            create_stream_on_read,
            storage_class,
            retention_policy,
            retention_age_secs,
            timestamping_mode,
            timestamping_uncapped,
            selected,
            editing_age,
            age_input,
            cursor,
        } => {
            // Options
            let storage_opts = [
                ("Default", storage_class.is_none()),
                (
                    "Standard",
                    matches!(storage_class, Some(StorageClass::Standard)),
                ),
                (
                    "Express",
                    matches!(storage_class, Some(StorageClass::Express)),
                ),
            ];
            let ret_opts = [
                (
                    "Infinite",
                    *retention_policy == RetentionPolicyOption::Infinite,
                ),
                ("Age-based", *retention_policy == RetentionPolicyOption::Age),
            ];
            let ts_opts = [
                ("Default", timestamping_mode.is_none()),
                (
                    "ClientPrefer",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientPrefer)),
                ),
                (
                    "ClientRequire",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientRequire)),
                ),
                (
                    "Arrival",
                    matches!(timestamping_mode, Some(TimestampingMode::Arrival)),
                ),
            ];

            let mut lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("   ", Style::default()),
                    Span::styled(basin.to_string(), Style::default().fg(CYAN).bold()),
                ]),
                Line::from(""),
                render_section_header("Default stream configuration", 48),
                Line::from(""),
            ];

            // Storage Class
            let (ind, lbl) = render_field_row_bold(0, "Storage", *selected);
            let mut storage_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &storage_opts {
                storage_spans.push(render_pill(label, *selected == 0, *active));
                storage_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(storage_spans));

            // Storage class help text
            if *selected == 0 {
                let storage_help = match storage_class {
                    None => help_text::STORAGE_DEFAULT,
                    Some(StorageClass::Standard) => help_text::STORAGE_STANDARD,
                    Some(StorageClass::Express) => help_text::STORAGE_EXPRESS,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(storage_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(1, "Retention", *selected);
            let mut ret_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ret_opts {
                ret_spans.push(render_pill(label, *selected == 1, *active));
                ret_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ret_spans));

            // Retention help text
            if *selected == 1 {
                let ret_help = match retention_policy {
                    RetentionPolicyOption::Infinite => help_text::RETENTION_INFINITE,
                    RetentionPolicyOption::Age => help_text::RETENTION_AGE,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ret_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            if *retention_policy == RetentionPolicyOption::Age {
                let (ind, lbl) = render_field_row_bold(2, "  Duration", *selected);
                let age_display = if *editing_age {
                    age_input.clone()
                } else {
                    format!("{}s", retention_age_secs)
                };
                let mut duration_spans = vec![ind, lbl, Span::raw("  ")];
                duration_spans.extend(render_text_input_with_cursor(
                    &age_display,
                    *selected == 2 && *editing_age,
                    "",
                    YELLOW,
                    *cursor,
                ));
                duration_spans.push(Span::styled(
                    "  e.g. 604800 (7 days)",
                    Style::default().fg(GRAY_600).italic(),
                ));
                lines.push(Line::from(duration_spans));
            }

            // Timestamping Mode
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(3, "Timestamps", *selected);
            let mut ts_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ts_opts {
                ts_spans.push(render_pill(label, *selected == 3, *active));
                ts_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ts_spans));

            // Timestamping mode help text
            if *selected == 3 {
                let ts_help = match timestamping_mode {
                    None => help_text::TS_DEFAULT,
                    Some(TimestampingMode::ClientPrefer) => help_text::TS_CLIENT_PREFER,
                    Some(TimestampingMode::ClientRequire) => help_text::TS_CLIENT_REQUIRE,
                    Some(TimestampingMode::Arrival) => help_text::TS_ARRIVAL,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ts_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Uncapped Timestamps
            let (ind, lbl) = render_field_row_bold(4, "  Uncapped", *selected);
            let mut uncapped_spans = vec![ind, lbl, Span::raw("  ")];
            uncapped_spans.extend(render_toggle(
                timestamping_uncapped.unwrap_or(false),
                *selected == 4,
            ));
            lines.push(Line::from(uncapped_spans));

            // Uncapped help text
            if *selected == 4 {
                let uncapped_help = if timestamping_uncapped.unwrap_or(false) {
                    help_text::TS_UNCAPPED
                } else {
                    help_text::TS_CAPPED
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(uncapped_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Create streams automatically section
            lines.push(Line::from(""));
            lines.push(render_section_header("Create streams automatically", 48));
            lines.push(Line::from(""));

            // On Append
            let (ind, lbl) = render_field_row_bold(5, "On append", *selected);
            let mut append_spans = vec![ind, lbl, Span::raw("  ")];
            append_spans.extend(render_toggle(
                create_stream_on_append.unwrap_or(false),
                *selected == 5,
            ));
            lines.push(Line::from(append_spans));

            // On append help text
            if *selected == 5 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::AUTO_CREATE_APPEND,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // On Read
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(6, "On read", *selected);
            let mut read_spans = vec![ind, lbl, Span::raw("  ")];
            read_spans.extend(render_toggle(
                create_stream_on_read.unwrap_or(false),
                *selected == 6,
            ));
            lines.push(Line::from(read_spans));

            // On read help text
            if *selected == 6 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::AUTO_CREATE_READ,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            lines.push(Line::from(""));

            (
                " Reconfigure Basin ",
                lines,
                "j/k navigate · h/l cycle · Space toggle · Enter edit · s save · Esc cancel",
            )
        }

        InputMode::ReconfigureStream {
            basin,
            stream,
            storage_class,
            retention_policy,
            retention_age_secs,
            timestamping_mode,
            timestamping_uncapped,
            delete_on_empty_enabled,
            delete_on_empty_min_age,
            selected,
            editing_age,
            age_input,
            cursor,
            ..
        } => {
            // Options
            let storage_opts = [
                ("Default", storage_class.is_none()),
                (
                    "Standard",
                    matches!(storage_class, Some(StorageClass::Standard)),
                ),
                (
                    "Express",
                    matches!(storage_class, Some(StorageClass::Express)),
                ),
            ];
            let ret_opts = [
                (
                    "Infinite",
                    *retention_policy == RetentionPolicyOption::Infinite,
                ),
                ("Age-based", *retention_policy == RetentionPolicyOption::Age),
            ];
            let ts_opts = [
                ("Default", timestamping_mode.is_none()),
                (
                    "ClientPrefer",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientPrefer)),
                ),
                (
                    "ClientRequire",
                    matches!(timestamping_mode, Some(TimestampingMode::ClientRequire)),
                ),
                (
                    "Arrival",
                    matches!(timestamping_mode, Some(TimestampingMode::Arrival)),
                ),
            ];

            let mut lines = vec![];

            // Stream name header
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("   ", Style::default()),
                Span::styled(
                    format!("{}/{}", basin, stream),
                    Style::default().fg(CYAN).bold(),
                ),
            ]));

            // Stream configuration section
            lines.push(Line::from(""));
            lines.push(render_section_header("Stream configuration", 48));
            lines.push(Line::from(""));

            // Storage Class
            let (ind, lbl) = render_field_row(0, "Storage", *selected);
            let mut storage_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &storage_opts {
                storage_spans.push(render_pill(label, *selected == 0, *active));
                storage_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(storage_spans));

            // Storage class help text
            if *selected == 0 {
                let storage_help = match storage_class {
                    None => help_text::STORAGE_DEFAULT,
                    Some(StorageClass::Standard) => help_text::STORAGE_STANDARD,
                    Some(StorageClass::Express) => help_text::STORAGE_EXPRESS,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(storage_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row(1, "Retention", *selected);
            let mut ret_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ret_opts {
                ret_spans.push(render_pill(label, *selected == 1, *active));
                ret_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ret_spans));

            // Retention help text
            if *selected == 1 {
                let ret_help = match retention_policy {
                    RetentionPolicyOption::Infinite => help_text::RETENTION_INFINITE,
                    RetentionPolicyOption::Age => help_text::RETENTION_AGE,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ret_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            if *retention_policy == RetentionPolicyOption::Age {
                let (ind, lbl) = render_field_row(2, "  Duration", *selected);
                let age_display = if *selected == 2 && *editing_age {
                    age_input.clone()
                } else {
                    format!("{}s", retention_age_secs)
                };
                let mut duration_spans = vec![ind, lbl, Span::raw("  ")];
                duration_spans.extend(render_text_input_with_cursor(
                    &age_display,
                    *selected == 2 && *editing_age,
                    "",
                    YELLOW,
                    *cursor,
                ));
                duration_spans.push(Span::styled(
                    "  e.g. 604800 (7 days)",
                    Style::default().fg(GRAY_600).italic(),
                ));
                lines.push(Line::from(duration_spans));
            }

            // Timestamping Mode
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row(3, "Timestamps", *selected);
            let mut ts_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &ts_opts {
                ts_spans.push(render_pill(label, *selected == 3, *active));
                ts_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(ts_spans));

            // Timestamping mode help text
            if *selected == 3 {
                let ts_help = match timestamping_mode {
                    None => help_text::TS_DEFAULT,
                    Some(TimestampingMode::ClientPrefer) => help_text::TS_CLIENT_PREFER,
                    Some(TimestampingMode::ClientRequire) => help_text::TS_CLIENT_REQUIRE,
                    Some(TimestampingMode::Arrival) => help_text::TS_ARRIVAL,
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(ts_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Uncapped Timestamps
            let (ind, lbl) = render_field_row(4, "  Uncapped", *selected);
            let mut uncapped_spans = vec![ind, lbl, Span::raw("  ")];
            uncapped_spans.extend(render_toggle(
                timestamping_uncapped.unwrap_or(false),
                *selected == 4,
            ));
            lines.push(Line::from(uncapped_spans));

            // Uncapped help text
            if *selected == 4 {
                let uncapped_help = if timestamping_uncapped.unwrap_or(false) {
                    help_text::TS_UNCAPPED
                } else {
                    help_text::TS_CAPPED
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(uncapped_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Delete on Empty
            let delete_opts = [
                ("Never", !*delete_on_empty_enabled),
                ("After threshold", *delete_on_empty_enabled),
            ];
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row(5, "Delete on empty", *selected);
            let mut del_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &delete_opts {
                del_spans.push(render_pill(label, *selected == 5, *active));
                del_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(del_spans));

            // Delete on empty help text
            if *selected == 5 {
                let del_help = if *delete_on_empty_enabled {
                    help_text::DELETE_THRESHOLD
                } else {
                    help_text::DELETE_NEVER
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(del_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Delete on Empty Threshold (conditional)
            if *delete_on_empty_enabled {
                let (ind, lbl) = render_field_row(6, "  Threshold", *selected);
                let mut threshold_spans = vec![ind, lbl, Span::raw("  ")];
                threshold_spans.extend(render_text_input_with_cursor(
                    delete_on_empty_min_age,
                    *selected == 6 && *editing_age,
                    "",
                    YELLOW,
                    *cursor,
                ));
                threshold_spans.push(Span::styled(
                    "  e.g. 1h, 7d",
                    Style::default().fg(GRAY_600).italic(),
                ));
                lines.push(Line::from(threshold_spans));
            }

            lines.push(Line::from(""));

            (
                " Reconfigure Stream ",
                lines,
                "j/k navigate · h/l cycle · Space toggle · Enter edit · s save · Esc cancel",
            )
        }

        InputMode::CustomRead {
            basin,
            stream,
            start_from,
            seq_num_value,
            timestamp_value,
            ago_value,
            ago_unit,
            tail_offset_value,
            count_limit,
            byte_limit,
            until_timestamp,
            clamp,
            format,
            output_file,
            selected,
            editing,
            cursor,
        } => {
            // Unit options for "time ago"
            let unit_str = match ago_unit {
                AgoUnit::Seconds => "sec",
                AgoUnit::Minutes => "min",
                AgoUnit::Hours => "hr",
                AgoUnit::Days => "day",
            };

            // Format options
            let format_opts = [
                ("Text", format.as_str() == "text"),
                ("JSON", format.as_str() == "json"),
                ("JSON+Base64", format.as_str() == "json-base64"),
            ];

            let mut lines = vec![];

            // Stream info header
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("   Reading from: ", Style::default().fg(TEXT_MUTED)),
                Span::styled(
                    format!("s2://{}/{}", basin, stream),
                    Style::default().fg(CYAN).bold(),
                ),
            ]));

            // Start position section
            lines.push(Line::from(""));
            lines.push(render_section_header("Start position", 48));
            lines.push(Line::from(""));

            // Row 0: Sequence number option
            let is_seq = *start_from == ReadStartFrom::SeqNum;
            let (ind, lbl) = render_field_row(0, "Sequence #", *selected);
            let mut seq_spans = vec![ind];
            seq_spans.push(Span::styled(
                if is_seq { "● " } else { "○ " },
                Style::default().fg(if is_seq { CYAN } else { GRAY_800 }),
            ));
            seq_spans.push(lbl);
            seq_spans.push(Span::raw("  "));
            seq_spans.extend(render_text_input_with_cursor(
                seq_num_value,
                *selected == 0 && *editing,
                "0",
                if is_seq { CYAN } else { TEXT_MUTED },
                *cursor,
            ));
            lines.push(Line::from(seq_spans));

            // Row 1: Timestamp option
            let is_ts = *start_from == ReadStartFrom::Timestamp;
            let (ind, lbl) = render_field_row(1, "Timestamp", *selected);
            let mut ts_spans = vec![ind];
            ts_spans.push(Span::styled(
                if is_ts { "● " } else { "○ " },
                Style::default().fg(if is_ts { CYAN } else { GRAY_800 }),
            ));
            ts_spans.push(lbl);
            ts_spans.push(Span::raw("  "));
            ts_spans.extend(render_text_input_with_cursor(
                timestamp_value,
                *selected == 1 && *editing,
                "0",
                if is_ts { CYAN } else { TEXT_MUTED },
                *cursor,
            ));
            ts_spans.push(Span::styled("  ms", Style::default().fg(TEXT_MUTED)));
            lines.push(Line::from(ts_spans));

            // Row 2: Time ago option
            let is_ago = *start_from == ReadStartFrom::Ago;
            let (ind, lbl) = render_field_row(2, "Time ago", *selected);
            let mut ago_spans = vec![ind];
            ago_spans.push(Span::styled(
                if is_ago { "● " } else { "○ " },
                Style::default().fg(if is_ago { CYAN } else { GRAY_800 }),
            ));
            ago_spans.push(lbl);
            ago_spans.push(Span::raw("  "));
            ago_spans.extend(render_text_input_with_cursor(
                ago_value,
                *selected == 2 && *editing,
                "5",
                if is_ago { CYAN } else { TEXT_MUTED },
                *cursor,
            ));
            ago_spans.push(Span::styled(
                format!(" {}", unit_str),
                Style::default().fg(if is_ago { TEXT_SECONDARY } else { TEXT_MUTED }),
            ));
            ago_spans.push(Span::styled(
                "  ‹tab› cycle",
                Style::default().fg(GRAY_600).italic(),
            ));
            lines.push(Line::from(ago_spans));

            // Row 3: Tail offset option
            let is_off = *start_from == ReadStartFrom::TailOffset;
            let (ind, lbl) = render_field_row(3, "Tail offset", *selected);
            let mut off_spans = vec![ind];
            off_spans.push(Span::styled(
                if is_off { "● " } else { "○ " },
                Style::default().fg(if is_off { CYAN } else { GRAY_800 }),
            ));
            off_spans.push(lbl);
            off_spans.push(Span::raw("  "));
            off_spans.extend(render_text_input_with_cursor(
                tail_offset_value,
                *selected == 3 && *editing,
                "10",
                if is_off { CYAN } else { TEXT_MUTED },
                *cursor,
            ));
            off_spans.push(Span::styled("  back", Style::default().fg(TEXT_MUTED)));
            lines.push(Line::from(off_spans));

            // Limits section
            lines.push(Line::from(""));
            lines.push(render_section_header("Limits", 48));
            lines.push(Line::from(""));

            // Row 4: Max records
            let (ind, lbl) = render_field_row(4, "Max records", *selected);
            let mut count_spans = vec![ind, lbl, Span::raw("  ")];
            count_spans.extend(render_text_input_with_cursor(
                count_limit,
                *selected == 4 && *editing,
                "∞ unlimited",
                YELLOW,
                *cursor,
            ));
            lines.push(Line::from(count_spans));

            // Row 5: Max bytes
            let (ind, lbl) = render_field_row(5, "Max bytes", *selected);
            let mut bytes_spans = vec![ind, lbl, Span::raw("  ")];
            bytes_spans.extend(render_text_input_with_cursor(
                byte_limit,
                *selected == 5 && *editing,
                "∞ unlimited",
                YELLOW,
                *cursor,
            ));
            lines.push(Line::from(bytes_spans));

            // Row 6: Until timestamp
            let (ind, lbl) = render_field_row(6, "Until", *selected);
            let mut until_spans = vec![ind, lbl, Span::raw("  ")];
            until_spans.extend(render_text_input_with_cursor(
                until_timestamp,
                *selected == 6 && *editing,
                "∞ unlimited",
                YELLOW,
                *cursor,
            ));
            until_spans.push(Span::styled("  ms", Style::default().fg(TEXT_MUTED)));
            lines.push(Line::from(until_spans));

            // Options section
            lines.push(Line::from(""));
            lines.push(render_section_header("Options", 48));
            lines.push(Line::from(""));

            // Row 7: Clamp toggle
            let (ind, lbl) = render_field_row(7, "Clamp to tail", *selected);
            let mut clamp_spans = vec![ind, lbl, Span::raw("  ")];
            clamp_spans.extend(render_toggle(*clamp, *selected == 7));
            lines.push(Line::from(clamp_spans));

            // Clamp help text
            if *selected == 7 {
                let clamp_help = if *clamp {
                    help_text::CLAMP_ON
                } else {
                    help_text::CLAMP_OFF
                };
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(clamp_help, Style::default().fg(GRAY_600).italic()),
                ]));
            }

            // Row 8: Format
            let (ind, lbl) = render_field_row(8, "Format", *selected);
            let mut format_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &format_opts {
                format_spans.push(render_pill(label, *selected == 8, *active));
                format_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(format_spans));

            // Format help text - shows description of currently selected format
            let format_help = match format.as_str() {
                "text" => help_text::FORMAT_TEXT,
                "json" => help_text::FORMAT_JSON,
                _ => help_text::FORMAT_JSON_BASE64,
            };
            lines.push(Line::from(vec![
                Span::raw("                  "),
                Span::styled(format_help, Style::default().fg(GRAY_600).italic()),
            ]));

            // Row 9: Output file
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row(9, "Output file", *selected);
            let mut output_spans = vec![ind, lbl, Span::raw("  ")];
            output_spans.extend(render_text_input_with_cursor(
                output_file,
                *selected == 9 && *editing,
                "display only",
                TEXT_SECONDARY,
                *cursor,
            ));
            lines.push(Line::from(output_spans));

            // Divider and button
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "─".repeat(52),
                Style::default().fg(GRAY_750),
            )]));
            lines.push(Line::from(""));

            // Row 10: Start button
            lines.push(render_button("START READING", *selected == 10, true, CYAN));

            lines.push(Line::from(""));

            (
                " Read Stream ",
                lines,
                "j/k navigate · Enter edit/select · Space toggle · Tab unit · Esc cancel",
            )
        }

        InputMode::Fence {
            basin,
            stream,
            new_token,
            current_token,
            selected,
            editing,
            cursor,
        } => {
            let mut lines = vec![
                Line::from(vec![
                    Span::raw("   "),
                    Span::styled(
                        format!("s2://{}/{}", basin, stream),
                        Style::default().fg(CYAN).bold(),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "   Set a new fencing token to block other writers.",
                    Style::default().fg(TEXT_MUTED),
                )),
                Line::from(""),
            ];

            // Row 0: New token
            let (ind, lbl) = render_field_row_bold(0, "New Token", *selected);
            let new_color = if new_token.is_empty() { WARNING } else { CYAN };
            let mut new_spans = vec![ind, lbl, Span::raw("  ")];
            new_spans.extend(render_text_input_with_cursor(
                new_token,
                *selected == 0 && *editing,
                "(required)",
                new_color,
                *cursor,
            ));
            lines.push(Line::from(new_spans));

            // New token help text
            if *selected == 0 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::FENCE_TOKEN,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // Row 1: Current token
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(1, "Current", *selected);
            let mut cur_spans = vec![ind, lbl, Span::raw("  ")];
            cur_spans.extend(render_text_input_with_cursor(
                current_token,
                *selected == 1 && *editing,
                "(none)",
                TEXT_SECONDARY,
                *cursor,
            ));
            lines.push(Line::from(cur_spans));

            // Current token help text
            if *selected == 1 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::FENCE_CURRENT,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // Divider and button
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "─".repeat(44),
                Style::default().fg(GRAY_750),
            )]));
            lines.push(Line::from(""));

            // Row 2: Submit button
            let can_submit = !new_token.is_empty();
            lines.push(render_button("FENCE", *selected == 2, can_submit, CYAN));

            lines.push(Line::from(""));

            (
                " Fence Stream ",
                lines,
                "j/k navigate · Enter edit · Esc cancel",
            )
        }

        InputMode::Trim {
            basin,
            stream,
            trim_point,
            fencing_token,
            selected,
            editing,
            cursor,
        } => {
            let mut lines = vec![
                Line::from(vec![
                    Span::raw("   "),
                    Span::styled(
                        format!("s2://{}/{}", basin, stream),
                        Style::default().fg(CYAN).bold(),
                    ),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    "   Delete all records before the trim point.",
                    Style::default().fg(TEXT_MUTED),
                )),
                Line::from(Span::styled(
                    "   This is eventually consistent.",
                    Style::default().fg(TEXT_MUTED),
                )),
                Line::from(""),
            ];

            // Row 0: Trim point
            let (ind, lbl) = render_field_row_bold(0, "Trim Point", *selected);
            let trim_color = if trim_point.is_empty() {
                WARNING
            } else {
                YELLOW
            };
            let mut trim_spans = vec![ind, lbl, Span::raw("  ")];
            trim_spans.extend(render_text_input_with_cursor(
                trim_point,
                *selected == 0 && *editing,
                "(seq num)",
                trim_color,
                *cursor,
            ));
            lines.push(Line::from(trim_spans));

            // Trim point help text
            if *selected == 0 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::TRIM_SEQ_NUM,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // Row 1: Fencing token
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(1, "Fence Token", *selected);
            let mut fence_spans = vec![ind, lbl, Span::raw("  ")];
            fence_spans.extend(render_text_input_with_cursor(
                fencing_token,
                *selected == 1 && *editing,
                "(none)",
                TEXT_SECONDARY,
                *cursor,
            ));
            lines.push(Line::from(fence_spans));

            // Fence token help text
            if *selected == 1 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::APPEND_FENCING,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // Divider and button
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "─".repeat(44),
                Style::default().fg(GRAY_750),
            )]));
            lines.push(Line::from(""));

            // Row 2: Submit button
            let can_submit = !trim_point.is_empty() && trim_point.parse::<u64>().is_ok();
            lines.push(render_button("TRIM", *selected == 2, can_submit, WARNING));

            lines.push(Line::from(""));

            (
                " Trim Stream ",
                lines,
                "j/k navigate · Enter edit · Esc cancel",
            )
        }

        InputMode::IssueAccessToken {
            id,
            expiry,
            expiry_custom,
            basins_scope,
            basins_value,
            streams_scope,
            streams_value,
            tokens_scope,
            tokens_value,
            account_read,
            account_write,
            basin_read,
            basin_write,
            stream_read,
            stream_write,
            auto_prefix_streams,
            selected,
            editing,
            cursor,
        } => {
            use crate::tui::app::ScopeOption;

            let expiry_opts = [
                ("Never", *expiry == ExpiryOption::Never),
                ("1d", *expiry == ExpiryOption::OneDay),
                ("7d", *expiry == ExpiryOption::SevenDays),
                ("30d", *expiry == ExpiryOption::ThirtyDays),
                ("90d", *expiry == ExpiryOption::NinetyDays),
                ("1y", *expiry == ExpiryOption::OneYear),
                ("Custom", *expiry == ExpiryOption::Custom),
            ];

            let scope_opts = |scope: &ScopeOption| {
                [
                    ("All", *scope == ScopeOption::All),
                    ("Prefix", *scope == ScopeOption::Prefix),
                    ("Exact", *scope == ScopeOption::Exact),
                ]
            };

            let mut lines = vec![];
            lines.push(Line::from(""));

            // Row 0: Token ID
            let (ind, lbl) = render_field_row_bold(0, "Token ID", *selected);
            let id_color = if id.is_empty() { WARNING } else { CYAN };
            let mut id_spans = vec![ind, lbl, Span::raw("  ")];
            id_spans.extend(render_text_input_with_cursor(
                id,
                *selected == 0 && *editing,
                "(required)",
                id_color,
                *cursor,
            ));
            lines.push(Line::from(id_spans));

            // Row 1: Expiration
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(1, "Expiration", *selected);
            let mut expiry_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in &expiry_opts {
                expiry_spans.push(render_pill(label, *selected == 1, *active));
                expiry_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(expiry_spans));

            // Expiration help text
            if *selected == 1 {
                lines.push(Line::from(vec![
                    Span::raw("                  "),
                    Span::styled(
                        help_text::TOKEN_EXPIRY,
                        Style::default().fg(GRAY_600).italic(),
                    ),
                ]));
            }

            // Row 2: Custom expiration (only if Custom selected)
            if *expiry == ExpiryOption::Custom {
                let (ind, lbl) = render_field_row_bold(2, "  Duration", *selected);
                let mut custom_spans = vec![ind, lbl, Span::raw("  ")];
                custom_spans.extend(render_text_input_with_cursor(
                    expiry_custom,
                    *selected == 2 && *editing,
                    "e.g. 30d, 1w",
                    YELLOW,
                    *cursor,
                ));
                lines.push(Line::from(custom_spans));
            }

            // Resources section
            lines.push(Line::from(""));
            lines.push(render_section_header("Resources", 48));
            lines.push(Line::from(""));

            // Row 3: Basins scope
            let (ind, lbl) = render_field_row_bold(3, "Basins", *selected);
            let mut basins_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in scope_opts(basins_scope) {
                basins_spans.push(render_pill(label, *selected == 3, active));
                basins_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(basins_spans));

            // Row 4: Basins value (only if Prefix/Exact)
            if matches!(basins_scope, ScopeOption::Prefix | ScopeOption::Exact) {
                let (ind, lbl) = render_field_row_bold(4, "  Pattern", *selected);
                let mut pattern_spans = vec![ind, lbl, Span::raw("  ")];
                pattern_spans.extend(render_text_input_with_cursor(
                    basins_value,
                    *selected == 4 && *editing,
                    "enter pattern",
                    TEXT_SECONDARY,
                    *cursor,
                ));
                lines.push(Line::from(pattern_spans));
            }

            // Row 5: Streams scope
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(5, "Streams", *selected);
            let mut streams_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in scope_opts(streams_scope) {
                streams_spans.push(render_pill(label, *selected == 5, active));
                streams_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(streams_spans));

            // Row 6: Streams value (only if Prefix/Exact)
            if matches!(streams_scope, ScopeOption::Prefix | ScopeOption::Exact) {
                let (ind, lbl) = render_field_row_bold(6, "  Pattern", *selected);
                let mut pattern_spans = vec![ind, lbl, Span::raw("  ")];
                pattern_spans.extend(render_text_input_with_cursor(
                    streams_value,
                    *selected == 6 && *editing,
                    "enter pattern",
                    TEXT_SECONDARY,
                    *cursor,
                ));
                lines.push(Line::from(pattern_spans));
            }

            // Row 7: Access Tokens scope
            lines.push(Line::from(""));
            let (ind, lbl) = render_field_row_bold(7, "Tokens", *selected);
            let mut tokens_spans = vec![ind, lbl, Span::raw("  ")];
            for (label, active) in scope_opts(tokens_scope) {
                tokens_spans.push(render_pill(label, *selected == 7, active));
                tokens_spans.push(Span::raw(" "));
            }
            lines.push(Line::from(tokens_spans));

            // Row 8: Tokens value (only if Prefix/Exact)
            if matches!(tokens_scope, ScopeOption::Prefix | ScopeOption::Exact) {
                let (ind, lbl) = render_field_row_bold(8, "  Pattern", *selected);
                let mut pattern_spans = vec![ind, lbl, Span::raw("  ")];
                pattern_spans.extend(render_text_input_with_cursor(
                    tokens_value,
                    *selected == 8 && *editing,
                    "enter pattern",
                    TEXT_SECONDARY,
                    *cursor,
                ));
                lines.push(Line::from(pattern_spans));
            }

            // Operations section
            lines.push(Line::from(""));
            lines.push(render_section_header("Operations", 48));
            lines.push(Line::from(""));

            // Row 9: Account Read
            let (ind, lbl) = render_field_row_bold(9, "Account Read", *selected);
            let mut acc_read_spans = vec![ind, lbl, Span::raw("  ")];
            acc_read_spans.extend(render_toggle(*account_read, *selected == 9));
            lines.push(Line::from(acc_read_spans));

            // Row 10: Account Write
            let (ind, lbl) = render_field_row_bold(10, "Account Write", *selected);
            let mut acc_write_spans = vec![ind, lbl, Span::raw("  ")];
            acc_write_spans.extend(render_toggle(*account_write, *selected == 10));
            lines.push(Line::from(acc_write_spans));

            lines.push(Line::from(""));

            // Row 11: Basin Read
            let (ind, lbl) = render_field_row_bold(11, "Basin Read", *selected);
            let mut basin_read_spans = vec![ind, lbl, Span::raw("  ")];
            basin_read_spans.extend(render_toggle(*basin_read, *selected == 11));
            lines.push(Line::from(basin_read_spans));

            // Row 12: Basin Write
            let (ind, lbl) = render_field_row_bold(12, "Basin Write", *selected);
            let mut basin_write_spans = vec![ind, lbl, Span::raw("  ")];
            basin_write_spans.extend(render_toggle(*basin_write, *selected == 12));
            lines.push(Line::from(basin_write_spans));

            lines.push(Line::from(""));

            // Row 13: Stream Read
            let (ind, lbl) = render_field_row_bold(13, "Stream Read", *selected);
            let mut stream_read_spans = vec![ind, lbl, Span::raw("  ")];
            stream_read_spans.extend(render_toggle(*stream_read, *selected == 13));
            lines.push(Line::from(stream_read_spans));

            // Row 14: Stream Write
            let (ind, lbl) = render_field_row_bold(14, "Stream Write", *selected);
            let mut stream_write_spans = vec![ind, lbl, Span::raw("  ")];
            stream_write_spans.extend(render_toggle(*stream_write, *selected == 14));
            lines.push(Line::from(stream_write_spans));

            // Options section
            lines.push(Line::from(""));
            lines.push(render_section_header("Options", 48));
            lines.push(Line::from(""));

            // Row 15: Auto-prefix streams
            let (ind, lbl) = render_field_row_bold(15, "Auto-prefix", *selected);
            let mut prefix_spans = vec![ind, lbl, Span::raw("  ")];
            prefix_spans.extend(render_toggle(*auto_prefix_streams, *selected == 15));
            lines.push(Line::from(prefix_spans));

            // Divider and button
            lines.push(Line::from(""));
            lines.push(Line::from(vec![Span::styled(
                "─".repeat(52),
                Style::default().fg(GRAY_750),
            )]));
            lines.push(Line::from(""));

            // Row 16: Submit button
            let can_submit = !id.is_empty();
            lines.push(render_button(
                "ISSUE TOKEN",
                *selected == 16,
                can_submit,
                SUCCESS,
            ));

            lines.push(Line::from(""));

            (
                " Issue Access Token ",
                lines,
                "j/k navigate · h/l cycle · Space toggle · Enter edit · Esc cancel",
            )
        }

        InputMode::ConfirmRevokeToken { token_id } => (
            " Revoke Access Token ",
            vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("Revoke token ", Style::default().fg(TEXT_SECONDARY)),
                    Span::styled(token_id, Style::default().fg(ERROR).bold()),
                    Span::styled("?", Style::default().fg(TEXT_SECONDARY)),
                ]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "The token will be immediately invalidated.",
                    Style::default().fg(TEXT_MUTED),
                )]),
                Line::from(vec![Span::styled(
                    "This action cannot be undone.",
                    Style::default().fg(ERROR),
                )]),
            ],
            "y confirm  n/esc cancel",
        ),

        InputMode::ShowIssuedToken { token } => (
            " Access Token Issued ",
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "Copy this token now - it won't be shown again!",
                    Style::default().fg(WARNING).bold(),
                )),
                Line::from(""),
                Line::from(Span::styled(token, Style::default().fg(CYAN))),
                Line::from(""),
            ],
            "press any key to dismiss",
        ),

        InputMode::ViewTokenDetail { token } => {
            let mut lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("   Token ID:    ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(
                        token.id.to_string(),
                        Style::default().fg(TEXT_PRIMARY).bold(),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("   Expires At:  ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(
                        token.expires_at.to_string(),
                        Style::default().fg(TEXT_PRIMARY),
                    ),
                ]),
                Line::from(vec![
                    Span::styled("   Auto-prefix: ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(
                        if token.auto_prefix_streams {
                            "Yes"
                        } else {
                            "No"
                        },
                        Style::default().fg(if token.auto_prefix_streams {
                            CYAN
                        } else {
                            TEXT_MUTED
                        }),
                    ),
                ]),
                Line::from(""),
                render_section_header("Resource Scope", 44),
            ];

            // Basins scope
            let basins_str = format_basin_matcher(&token.scope.basins);
            lines.push(Line::from(vec![
                Span::styled("   Basins:   ", Style::default().fg(TEXT_MUTED)),
                Span::styled(basins_str, Style::default().fg(TEXT_PRIMARY)),
            ]));

            // Streams scope
            let streams_str = format_stream_matcher(&token.scope.streams);
            lines.push(Line::from(vec![
                Span::styled("   Streams:  ", Style::default().fg(TEXT_MUTED)),
                Span::styled(streams_str, Style::default().fg(TEXT_PRIMARY)),
            ]));

            // Access tokens scope
            let tokens_str = format_token_matcher(&token.scope.access_tokens);
            lines.push(Line::from(vec![
                Span::styled("   Tokens:   ", Style::default().fg(TEXT_MUTED)),
                Span::styled(tokens_str, Style::default().fg(TEXT_PRIMARY)),
            ]));

            lines.push(Line::from(""));
            lines.push(render_section_header("Operations", 44));

            // Group operations by category
            let ops = &token.scope.ops;

            // Account operations
            let account_ops: Vec<_> = ops
                .iter()
                .filter(|o| is_account_op(o))
                .map(format_operation)
                .collect();
            if !account_ops.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("   Account:  ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(account_ops.join(", "), Style::default().fg(TEXT_PRIMARY)),
                ]));
            }

            // Basin operations
            let basin_ops: Vec<_> = ops
                .iter()
                .filter(|o| is_basin_op(o))
                .map(format_operation)
                .collect();
            if !basin_ops.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("   Basin:    ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(basin_ops.join(", "), Style::default().fg(TEXT_PRIMARY)),
                ]));
            }

            // Stream operations
            let stream_ops: Vec<_> = ops
                .iter()
                .filter(|o| is_stream_op(o))
                .map(format_operation)
                .collect();
            if !stream_ops.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("   Stream:   ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(stream_ops.join(", "), Style::default().fg(TEXT_PRIMARY)),
                ]));
            }

            // Token operations
            let token_ops: Vec<_> = ops
                .iter()
                .filter(|o| is_token_op(o))
                .map(format_operation)
                .collect();
            if !token_ops.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("   Tokens:   ", Style::default().fg(TEXT_MUTED)),
                    Span::styled(token_ops.join(", "), Style::default().fg(TEXT_PRIMARY)),
                ]));
            }

            lines.push(Line::from(""));

            (" Access Token Details ", lines, "esc/enter close")
        }
    };

    // Use smaller area for simple confirmation dialogs
    let is_delete_dialog = matches!(
        mode,
        InputMode::ConfirmDeleteBasin { .. } | InputMode::ConfirmDeleteStream { .. }
    );
    let is_simple_dialog = is_delete_dialog || matches!(mode, InputMode::ConfirmRevokeToken { .. });
    let area = if is_simple_dialog {
        // Content-based sizing: content lines + borders (2) + hint (1) + padding (2)
        let height = (content.len() as u16 + 5).min(f.area().height);
        let width = 50.min(f.area().width);
        let x = f.area().x + f.area().width.saturating_sub(width) / 2;
        let y = f.area().y + f.area().height.saturating_sub(height) / 2;
        Rect::new(x, y, width, height)
    } else {
        centered_rect(60, 85, f.area())
    };

    let (border_color, title_style) = if is_delete_dialog {
        (ERROR, Style::default().fg(ERROR).bold())
    } else {
        (CYAN, Style::default().fg(TEXT_PRIMARY).bold())
    };

    let block = Block::default()
        .title(Line::from(Span::styled(title, title_style)))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .style(Style::default().bg(BG_DARK))
        .padding(Padding::horizontal(2));

    // Split area for content and hint
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(area);

    f.render_widget(Clear, area);

    // Calculate scroll offset to keep selected item visible
    // Inner height = area height - borders (2) - padding (0) - hint line (1)
    let inner_height = chunks[0].height.saturating_sub(4) as usize;
    let content_height = content.len();
    let scroll_offset = if content_height > inner_height {
        // Find the selected field's approximate line position
        let selected_line = get_selected_line_hint(mode);
        // Scroll so selected item is in the middle-ish of visible area
        let half_visible = inner_height / 2;
        if selected_line > half_visible {
            (selected_line - half_visible).min(content_height.saturating_sub(inner_height))
        } else {
            0
        }
    } else {
        0
    };

    let dialog = Paragraph::new(content.clone())
        .block(block)
        .wrap(ratatui::widgets::Wrap { trim: false })
        .scroll((scroll_offset as u16, 0));
    f.render_widget(dialog, chunks[0]);

    if content_height > inner_height {
        let inner_area = chunks[0].inner(Margin::new(1, 1));
        if scroll_offset > 0 {
            let up_indicator = Paragraph::new("▲")
                .style(Style::default().fg(GRAY_600))
                .alignment(Alignment::Right);
            let up_area = Rect::new(inner_area.x, inner_area.y, inner_area.width, 1);
            f.render_widget(up_indicator, up_area);
        }
        if scroll_offset + inner_height < content_height {
            let down_indicator = Paragraph::new("▼")
                .style(Style::default().fg(GRAY_600))
                .alignment(Alignment::Right);
            let down_area = Rect::new(
                inner_area.x,
                inner_area.y + inner_area.height.saturating_sub(1),
                inner_area.width,
                1,
            );
            f.render_widget(down_indicator, down_area);
        }
    }

    // Parse and render hint with highlighted keys for better accessibility
    let hint_spans = render_hint_with_keys(hint);
    let hint_line = Line::from(hint_spans);
    let hint_para = Paragraph::new(hint_line).alignment(Alignment::Center);
    f.render_widget(hint_para, chunks[1]);
}

/// Parse a hint string and render keys (before descriptions) with highlighting.
/// Format expected: "key1 desc1 · key2 desc2 · ..."
fn render_hint_with_keys(hint: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let parts: Vec<&str> = hint.split(" · ").collect();

    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::default().fg(GRAY_800)));
        }

        // Split into key and description (first word is the key)
        if let Some(space_idx) = part.find(' ') {
            let key = &part[..space_idx];
            let desc = &part[space_idx..];
            spans.push(Span::styled(
                key.to_string(),
                Style::default().fg(CYAN).bold(),
            ));
            spans.push(Span::styled(
                desc.to_string(),
                Style::default().fg(TEXT_MUTED),
            ));
        } else {
            // No space, treat whole thing as key
            spans.push(Span::styled(
                part.to_string(),
                Style::default().fg(CYAN).bold(),
            ));
        }
    }

    spans
}

fn draw_bench_view(f: &mut Frame, area: Rect, state: &BenchViewState) {
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Benchmark ", Style::default().fg(TEXT_PRIMARY).bold()),
            Span::styled(
                format!("• {} ", state.basin_name),
                Style::default().fg(ACCENT),
            ),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_DARK));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if state.config_phase {
        draw_bench_config(f, inner, state);
    } else {
        draw_bench_running(f, inner, state);
    }
}

fn draw_bench_config(f: &mut Frame, area: Rect, state: &BenchViewState) {
    use crate::tui::app::BenchConfigField;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Title
            Constraint::Length(3),
            Constraint::Length(3), // Target MiB/s
            Constraint::Length(3), // Duration
            Constraint::Length(3), // Catchup delay
            Constraint::Length(3), // Start button
            Constraint::Min(1),    // Spacer
        ])
        .margin(1)
        .split(area);

    // Title
    let title = Paragraph::new(Line::from(vec![Span::styled(
        "Configure Benchmark",
        Style::default().fg(TEXT_PRIMARY).bold(),
    )]))
    .alignment(Alignment::Center);
    f.render_widget(title, chunks[0]);

    // Helper to draw a config field
    let draw_field =
        |f: &mut Frame, area: Rect, label: &str, value: &str, selected: bool, editing: bool| {
            let style = if selected {
                Style::default()
                    .fg(if editing { YELLOW } else { CYAN })
                    .bold()
            } else {
                Style::default().fg(TEXT_SECONDARY)
            };

            let prefix = if selected { "▸ " } else { "  " };
            let suffix = if selected && !editing { " ◂" } else { "" };

            let line = Line::from(vec![
                Span::styled(prefix, style),
                Span::styled(format!("{}: ", label), Style::default().fg(TEXT_MUTED)),
                Span::styled(value, style),
                Span::styled(suffix, style),
            ]);
            f.render_widget(Paragraph::new(line), area);
        };
    let record_size_str = if state.editing && state.config_field == BenchConfigField::RecordSize {
        format!("{}_", state.edit_buffer)
    } else {
        format_bytes(state.record_size as u64)
    };
    draw_field(
        f,
        chunks[1],
        "Record Size",
        &record_size_str,
        state.config_field == BenchConfigField::RecordSize,
        state.editing,
    );

    // Target MiB/s
    let target_str = if state.editing && state.config_field == BenchConfigField::TargetMibps {
        format!("{}_", state.edit_buffer)
    } else {
        format!("{} MiB/s", state.target_mibps)
    };
    draw_field(
        f,
        chunks[2],
        "Target Throughput",
        &target_str,
        state.config_field == BenchConfigField::TargetMibps,
        state.editing,
    );

    // Duration
    let duration_str = if state.editing && state.config_field == BenchConfigField::Duration {
        format!("{}_", state.edit_buffer)
    } else {
        format!("{}s", state.duration_secs)
    };
    draw_field(
        f,
        chunks[3],
        "Duration",
        &duration_str,
        state.config_field == BenchConfigField::Duration,
        state.editing,
    );

    // Catchup delay
    let catchup_str = if state.editing && state.config_field == BenchConfigField::CatchupDelay {
        format!("{}_", state.edit_buffer)
    } else {
        format!("{}s", state.catchup_delay_secs)
    };
    draw_field(
        f,
        chunks[4],
        "Catchup Delay",
        &catchup_str,
        state.config_field == BenchConfigField::CatchupDelay,
        state.editing,
    );

    // Start button
    let start_style = if state.config_field == BenchConfigField::Start {
        Style::default().fg(BG_DARK).bg(CYAN).bold()
    } else {
        Style::default().fg(CYAN)
    };
    let start = Paragraph::new(Line::from(Span::styled(" ▶ Start Benchmark ", start_style)))
        .alignment(Alignment::Center);
    f.render_widget(start, chunks[5]);
}

fn draw_bench_running(f: &mut Frame, area: Rect, state: &BenchViewState) {
    use crate::tui::event::BenchPhase;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Progress bar
            Constraint::Length(5), // Write stats
            Constraint::Length(5),
            Constraint::Length(5), // Catchup stats (or waiting)
            Constraint::Min(3),    // Latency stats or chart
        ])
        .margin(1)
        .split(area);

    // Progress bar
    let progress_pct = state.progress_pct.min(100.0);
    let phase_text = match state.phase {
        BenchPhase::Write => "Writing",
        BenchPhase::Read => "Reading",
        BenchPhase::CatchupWait => "Waiting for catchup",
        BenchPhase::Catchup => "Catchup read",
    };

    let progress_block = Block::default()
        .title(Line::from(vec![
            Span::styled(" Progress ", Style::default().fg(TEXT_PRIMARY).bold()),
            Span::styled(format!("• {} ", phase_text), Style::default().fg(YELLOW)),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER));

    let progress_inner = progress_block.inner(chunks[0]);
    f.render_widget(progress_block, chunks[0]);

    // Progress bar using block characters
    let bar_width = progress_inner.width.saturating_sub(20) as usize;
    let filled = ((progress_pct / 100.0) * bar_width as f64) as usize;
    let empty = bar_width.saturating_sub(filled);

    let time_display = if state.phase == BenchPhase::Write {
        format!(
            " {:.1}s / {}s",
            state.elapsed_secs.min(state.duration_secs as f64),
            state.duration_secs
        )
    } else {
        format!(" {:.1}s", state.elapsed_secs)
    };
    let progress_line = Line::from(vec![
        Span::styled(
            format!("{:>5.1}% ", progress_pct),
            Style::default().fg(TEXT_PRIMARY),
        ),
        Span::styled("█".repeat(filled), Style::default().fg(CYAN)),
        Span::styled("░".repeat(empty), Style::default().fg(TEXT_MUTED)),
        Span::styled(time_display, Style::default().fg(TEXT_SECONDARY)),
    ]);
    f.render_widget(Paragraph::new(progress_line), progress_inner);

    // Write stats
    draw_bench_stat_box(
        f,
        chunks[1],
        "Write",
        BLUE,
        state.write_mibps,
        state.write_recps,
        state.write_bytes,
        state.write_records,
        &state.write_history,
    );
    draw_bench_stat_box(
        f,
        chunks[2],
        "Read",
        CYAN,
        state.read_mibps,
        state.read_recps,
        state.read_bytes,
        state.read_records,
        &state.read_history,
    );

    // Catchup stats or waiting message
    if matches!(state.phase, BenchPhase::CatchupWait) {
        let wait_block = Block::default()
            .title(Line::from(Span::styled(
                " Catchup ",
                Style::default().fg(TEXT_PRIMARY).bold(),
            )))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER));
        let wait_inner = wait_block.inner(chunks[3]);
        f.render_widget(wait_block, chunks[3]);

        let wait_text = Paragraph::new(Line::from(vec![
            Span::styled("Waiting ", Style::default().fg(TEXT_MUTED)),
            Span::styled(
                format!("{}s", state.catchup_delay_secs),
                Style::default().fg(CYAN),
            ),
            Span::styled(" before catchup read...", Style::default().fg(TEXT_MUTED)),
        ]))
        .alignment(Alignment::Center);
        f.render_widget(wait_text, wait_inner);
    } else {
        let empty_history = VecDeque::new();
        draw_bench_stat_box(
            f,
            chunks[3],
            "Catchup",
            CYAN,
            state.catchup_mibps,
            state.catchup_recps,
            state.catchup_bytes,
            state.catchup_records,
            &empty_history,
        );
    }

    // Latency stats (only show after completion)
    if !state.running && (state.ack_latency.is_some() || state.e2e_latency.is_some()) {
        draw_latency_stats(f, chunks[4], &state.ack_latency, &state.e2e_latency);
    } else if let Some(error) = &state.error {
        let error_block = Block::default()
            .title(Line::from(Span::styled(
                " Error ",
                Style::default().fg(RED).bold(),
            )))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(RED));
        let error_inner = error_block.inner(chunks[4]);
        f.render_widget(error_block, chunks[4]);

        let error_text = Paragraph::new(error.as_str())
            .style(Style::default().fg(RED))
            .wrap(ratatui::widgets::Wrap { trim: true });
        f.render_widget(error_text, error_inner);
    } else {
        // Show sparkline area for throughput history
        draw_throughput_sparklines(f, chunks[4], &state.write_history, &state.read_history);
    }
}

#[allow(clippy::too_many_arguments)]
fn draw_bench_stat_box(
    f: &mut Frame,
    area: Rect,
    label: &str,
    color: Color,
    mibps: f64,
    recps: f64,
    bytes: u64,
    records: u64,
    history: &VecDeque<f64>,
) {
    let block = Block::default()
        .title(Line::from(Span::styled(
            format!(" {} ", label),
            Style::default().fg(color).bold(),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    // Layout: stats on left, sparkline on right
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(30), Constraint::Length(25)])
        .split(inner);

    // Stats
    let stats = vec![
        Line::from(vec![
            Span::styled(format!("{:>8.2}", mibps), Style::default().fg(color).bold()),
            Span::styled(" MiB/s  ", Style::default().fg(TEXT_MUTED)),
            Span::styled(format!("{:>8.0}", recps), Style::default().fg(color).bold()),
            Span::styled(" rec/s", Style::default().fg(TEXT_MUTED)),
        ]),
        Line::from(vec![
            Span::styled(
                format!("{:>8}", format_bytes(bytes)),
                Style::default().fg(TEXT_SECONDARY),
            ),
            Span::styled(" total  ", Style::default().fg(TEXT_MUTED)),
            Span::styled(
                format!("{:>8}", format_number(records)),
                Style::default().fg(TEXT_SECONDARY),
            ),
            Span::styled(" records", Style::default().fg(TEXT_MUTED)),
        ]),
    ];
    f.render_widget(Paragraph::new(stats), chunks[0]);

    // Sparkline
    if !history.is_empty() {
        let sparkline_data: Vec<u64> = history.iter().map(|v| (*v * 100.0) as u64).collect();
        let sparkline = ratatui::widgets::Sparkline::default()
            .data(&sparkline_data)
            .style(Style::default().fg(color));
        f.render_widget(sparkline, chunks[1]);
    }
}

fn draw_throughput_sparklines(
    f: &mut Frame,
    area: Rect,
    write_history: &VecDeque<f64>,
    read_history: &VecDeque<f64>,
) {
    let block = Block::default()
        .title(Line::from(Span::styled(
            " Throughput ",
            Style::default().fg(TEXT_PRIMARY).bold(),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    if write_history.is_empty() && read_history.is_empty() {
        let waiting = Paragraph::new("Collecting data...")
            .style(Style::default().fg(TEXT_MUTED))
            .alignment(Alignment::Center);
        f.render_widget(waiting, inner);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);

    // Write sparkline
    if !write_history.is_empty() {
        let write_data: Vec<u64> = write_history.iter().map(|v| (*v * 100.0) as u64).collect();
        let write_spark = ratatui::widgets::Sparkline::default()
            .block(Block::default().title(Span::styled("Write", Style::default().fg(BLUE))))
            .data(&write_data)
            .style(Style::default().fg(BLUE));
        f.render_widget(write_spark, chunks[0]);
    }
    if !read_history.is_empty() {
        let read_data: Vec<u64> = read_history.iter().map(|v| (*v * 100.0) as u64).collect();
        let read_spark = ratatui::widgets::Sparkline::default()
            .block(Block::default().title(Span::styled("Read", Style::default().fg(CYAN))))
            .data(&read_data)
            .style(Style::default().fg(CYAN));
        f.render_widget(read_spark, chunks[1]);
    }
}

fn draw_latency_stats(
    f: &mut Frame,
    area: Rect,
    ack_latency: &Option<crate::types::LatencyStats>,
    e2e_latency: &Option<crate::types::LatencyStats>,
) {
    let block = Block::default()
        .title(Line::from(Span::styled(
            " Latency Statistics ",
            Style::default().fg(TEXT_PRIMARY).bold(),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);

    // Ack latency
    if let Some(stats) = ack_latency {
        draw_latency_box(f, chunks[0], "Ack Latency", BLUE, stats);
    }

    // E2E latency
    if let Some(stats) = e2e_latency {
        draw_latency_box(f, chunks[1], "E2E Latency", CYAN, stats);
    }
}

fn draw_latency_box(
    f: &mut Frame,
    area: Rect,
    title: &str,
    color: Color,
    stats: &crate::types::LatencyStats,
) {
    let block = Block::default()
        .title(Line::from(Span::styled(
            title,
            Style::default().fg(color).bold(),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER));

    let inner = block.inner(area);
    f.render_widget(block, area);

    let stats_vec = stats.clone().into_vec();
    let max_val = stats_vec
        .iter()
        .map(|(_, d)| d.as_millis())
        .max()
        .unwrap_or(1) as f64;

    let bar_width = inner.width.saturating_sub(20) as f64;

    let lines: Vec<Line> = stats_vec
        .iter()
        .map(|(name, duration)| {
            let ms = duration.as_millis();
            let bar_len = ((ms as f64 / max_val) * bar_width).round() as usize;
            Line::from(vec![
                Span::styled(format!("{:>5}: ", name), Style::default().fg(TEXT_MUTED)),
                Span::styled(format!("{:>4}ms ", ms), Style::default().fg(color).bold()),
                Span::styled("█".repeat(bar_len), Style::default().fg(color)),
            ])
        })
        .collect();

    f.render_widget(Paragraph::new(lines), inner);
}

fn draw_tail_sparklines(
    f: &mut Frame,
    area: Rect,
    throughput_history: &VecDeque<f64>,
    records_history: &VecDeque<f64>,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(2),
            Constraint::Percentage(50),
            Constraint::Percentage(50),
            Constraint::Length(2),
        ])
        .split(area);

    // Throughput sparkline (MiB/s)
    if !throughput_history.is_empty() {
        let max_val = throughput_history.iter().cloned().fold(0.1_f64, f64::max);
        let data: Vec<u64> = throughput_history
            .iter()
            .map(|v| ((v / max_val) * 100.0) as u64)
            .collect();

        let current = throughput_history.back().copied().unwrap_or(0.0);
        let block = Block::default()
            .title(Line::from(vec![
                Span::styled(" ▲ ", Style::default().fg(CYAN)),
                Span::styled(
                    format!("{:.2} MiB/s ", current),
                    Style::default().fg(CYAN).bold(),
                ),
            ]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER));

        let inner = block.inner(chunks[1]);
        f.render_widget(block, chunks[1]);

        let sparkline = ratatui::widgets::Sparkline::default()
            .data(&data)
            .style(Style::default().fg(CYAN));
        f.render_widget(sparkline, inner);
    }

    // Records/s sparkline
    if !records_history.is_empty() {
        let max_val = records_history.iter().cloned().fold(1.0_f64, f64::max);
        let data: Vec<u64> = records_history
            .iter()
            .map(|v| ((v / max_val) * 100.0) as u64)
            .collect();

        let current = records_history.back().copied().unwrap_or(0.0);
        let block = Block::default()
            .title(Line::from(vec![
                Span::styled(" ◆ ", Style::default().fg(CYAN)),
                Span::styled(
                    format!("{:.0} rec/s ", current),
                    Style::default().fg(CYAN).bold(),
                ),
            ]))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(BORDER));

        let inner = block.inner(chunks[2]);
        f.render_widget(block, chunks[2]);

        let sparkline = ratatui::widgets::Sparkline::default()
            .data(&data)
            .style(Style::default().fg(CYAN));
        f.render_widget(sparkline, inner);
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Draw Picture-in-Picture overlay in bottom-right corner
fn draw_pip(f: &mut Frame, pip: &PipState) {
    let area = f.area();

    // PiP window size: 40 chars wide, 12 lines tall
    let pip_width = 44.min(area.width.saturating_sub(4));
    let pip_height = 14.min(area.height.saturating_sub(4));

    // Position in bottom-right corner with some margin
    let pip_area = Rect::new(
        area.width.saturating_sub(pip_width + 2),
        area.height.saturating_sub(pip_height + 2),
        pip_width,
        pip_height,
    );

    // Clear background
    f.render_widget(Clear, pip_area);

    // Create title with stream info
    let title = format!(" {}/{} ", pip.basin_name, pip.stream_name);
    let status = if pip.paused { " PAUSED " } else { " LIVE " };
    let status_color = if pip.paused { WARNING } else { SUCCESS };

    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(&title, Style::default().fg(CYAN).bold()),
            Span::styled(status, Style::default().fg(BG_DARK).bg(status_color).bold()),
        ]))
        .title_bottom(Line::from(vec![
            Span::styled(" P", Style::default().fg(TEXT_MUTED)),
            Span::styled("=close ", Style::default().fg(TEXT_MUTED)),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(CYAN))
        .style(Style::default().bg(BG_PANEL));

    let inner = block.inner(pip_area);
    f.render_widget(block, pip_area);

    // Split inner area: header line + records list
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Stats line
            Constraint::Min(1),    // Records
        ])
        .split(inner);

    // Stats line
    let stats = if pip.current_mibps > 0.0 {
        format!(
            "{:.1} MiB/s  {:.0} rec/s  {} records",
            pip.current_mibps,
            pip.current_recps,
            pip.records.len()
        )
    } else {
        format!("{} records", pip.records.len())
    };
    let stats_para = Paragraph::new(Span::styled(&stats, Style::default().fg(TEXT_MUTED)));
    f.render_widget(stats_para, chunks[0]);

    // Records list (show last N that fit)
    let visible_height = chunks[1].height as usize;
    let records_to_show: Vec<_> = pip
        .records
        .iter()
        .rev()
        .take(visible_height)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    if records_to_show.is_empty() {
        let waiting = Paragraph::new(Span::styled(
            "Waiting for records...",
            Style::default().fg(TEXT_MUTED).italic(),
        ))
        .alignment(Alignment::Center);
        f.render_widget(waiting, chunks[1]);
    } else {
        let items: Vec<ListItem> = records_to_show
            .iter()
            .map(|record| {
                let seq = format!("#{:<6}", record.seq_num);
                let body_preview: String = String::from_utf8_lossy(&record.body)
                    .chars()
                    .take(28)
                    .filter(|c| !c.is_control())
                    .collect();

                ListItem::new(Line::from(vec![
                    Span::styled(seq, Style::default().fg(TEXT_MUTED)),
                    Span::styled(" ", Style::default()),
                    Span::styled(body_preview, Style::default().fg(TEXT_PRIMARY)),
                ]))
            })
            .collect();

        let list = List::new(items);
        f.render_widget(list, chunks[1]);
    }
}

/// Draw minimized PiP indicator in bottom-right corner
fn draw_pip_minimized(f: &mut Frame, pip: &PipState) {
    let area = f.area();

    // Small indicator: just shows stream name and record count
    let indicator_width = 24.min(area.width.saturating_sub(4));
    let indicator_height = 3;

    let indicator_area = Rect::new(
        area.width.saturating_sub(indicator_width + 2),
        area.height.saturating_sub(indicator_height + 2),
        indicator_width,
        indicator_height,
    );

    f.render_widget(Clear, indicator_area);

    let status_char = if pip.paused { "⏸" } else { "●" };
    let status_color = if pip.paused { WARNING } else { SUCCESS };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(BORDER))
        .style(Style::default().bg(BG_PANEL));

    let para = Paragraph::new(Line::from(vec![
        Span::styled(status_char, Style::default().fg(status_color)),
        Span::styled(" ", Style::default()),
        Span::styled(
            format!("{} ({})", pip.stream_name, pip.records.len()),
            Style::default().fg(TEXT_SECONDARY),
        ),
    ]))
    .block(block);

    f.render_widget(para, indicator_area);
}
