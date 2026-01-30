use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use base64ct::Encoding;
use chrono::{Datelike, NaiveDate};
use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, prelude::Backend};
use s2_sdk::types::{
    AccessTokenId, AccessTokenInfo, BasinInfo, BasinMetricSet, BasinName, BasinState, StreamInfo,
    StreamMetricSet, StreamName, StreamPosition, TimeRange,
};
use tokio::sync::mpsc;

use super::{
    event::{BasinConfigInfo, BenchFinalStats, BenchPhase, BenchSample, Event, StreamConfigInfo},
    ui,
};
use crate::{
    cli::{
        CreateStreamArgs, IssueAccessTokenArgs, ListAccessTokensArgs, ListBasinsArgs,
        ListStreamsArgs, ReadArgs, ReconfigureBasinArgs, ReconfigureStreamArgs,
    },
    config::{self, Compression, ConfigKey},
    error::CliError,
    ops,
    record_format::{RecordFormat, RecordsOut},
    types::{
        BasinConfig, DeleteOnEmptyConfig, Operation, RetentionPolicy, S2BasinAndMaybeStreamUri,
        S2BasinAndStreamUri, S2BasinUri, StorageClass, StreamConfig, TimestampingConfig,
        TimestampingMode,
    },
};

/// Maximum records to keep in read view buffer
const MAX_RECORDS_BUFFER: usize = 1000;

/// Maximum throughput history samples to keep (60 seconds at 1 sample/sec)
const MAX_THROUGHPUT_HISTORY: usize = 60;

/// Splash screen display duration in milliseconds
const SPLASH_DURATION_MS: u64 = 1200;

/// Target frame interval in milliseconds (~60fps)
const FRAME_INTERVAL_MS: u64 = 16;

/// Calculate throughput rates from accumulated bytes/records over elapsed time.
/// Returns (MiB/s, records/s).
#[inline]
fn calculate_throughput(bytes: u64, records: u64, elapsed_secs: f64) -> (f64, f64) {
    let mibps = (bytes as f64) / (1024.0 * 1024.0) / elapsed_secs;
    let recps = (records as f64) / elapsed_secs;
    (mibps, recps)
}

/// Top-level navigation tabs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tab {
    #[default]
    Basins,
    AccessTokens,
    Settings,
}

/// Current screen being displayed
#[derive(Debug, Clone)]
pub enum Screen {
    Splash,
    Setup(SetupState),
    Basins(BasinsState),
    Streams(StreamsState),
    StreamDetail(StreamDetailState),
    ReadView(ReadViewState),
    AppendView(AppendViewState),
    AccessTokens(AccessTokensState),
    MetricsView(MetricsViewState),
    Settings(SettingsState),
    BenchView(BenchViewState),
}

/// State for the setup screen (first-time token entry)
#[derive(Debug, Clone, Default)]
pub struct SetupState {
    pub access_token: String,
    pub cursor: usize,
    pub error: Option<String>,
    pub validating: bool,
}

/// State for the basins list screen
#[derive(Debug, Clone, Default)]
pub struct BasinsState {
    pub basins: Vec<BasinInfo>,
    pub selected: usize,
    pub loading: bool,
    pub filter: String,
    pub filter_active: bool,
    pub has_more: bool,
    pub loading_more: bool,
}

/// State for the streams list screen
#[derive(Debug, Clone)]
pub struct StreamsState {
    pub basin_name: BasinName,
    pub streams: Vec<StreamInfo>,
    pub selected: usize,
    pub loading: bool,
    pub filter: String,
    pub filter_active: bool,
    pub has_more: bool,
    pub loading_more: bool,
}

/// State for the stream detail screen
#[derive(Debug, Clone)]
pub struct StreamDetailState {
    pub basin_name: BasinName,
    pub stream_name: StreamName,
    pub config: Option<StreamConfig>,
    pub tail_position: Option<StreamPosition>,
    pub selected_action: usize,
    pub loading: bool,
}

/// State for the read/tail view
#[derive(Debug, Clone)]
pub struct ReadViewState {
    pub basin_name: BasinName,
    pub stream_name: StreamName,
    pub records: VecDeque<s2_sdk::types::SequencedRecord>,
    pub is_tailing: bool,
    pub selected: usize,
    pub paused: bool,
    pub loading: bool,
    pub show_detail: bool,
    pub hide_list: bool,
    pub output_file: Option<String>,
    // Throughput tracking for live sparklines
    pub throughput_history: VecDeque<f64>,      // MiB/s samples
    pub records_per_sec_history: VecDeque<f64>, // records/s samples
    pub current_mibps: f64,
    pub current_recps: f64,
    pub bytes_this_second: u64,
    pub records_this_second: u64,
    pub last_tick: Option<std::time::Instant>,
    // Timeline scrubber
    pub show_timeline: bool,
}

/// Maximum records to keep in PiP buffer (smaller than main view)
const MAX_PIP_RECORDS: usize = 50;

/// Picture-in-Picture state for watching a stream while navigating elsewhere
#[derive(Debug, Clone)]
pub struct PipState {
    pub basin_name: BasinName,
    pub stream_name: StreamName,
    pub records: VecDeque<s2_sdk::types::SequencedRecord>,
    pub paused: bool,
    pub minimized: bool,
    // Throughput tracking
    pub current_mibps: f64,
    pub current_recps: f64,
    pub bytes_this_second: u64,
    pub records_this_second: u64,
    pub last_tick: Option<std::time::Instant>,
}

/// State for the append view
#[derive(Debug, Clone)]
pub struct AppendViewState {
    pub basin_name: BasinName,
    pub stream_name: StreamName,
    pub body: String,
    pub headers: Vec<(String, String)>, // List of (key, value) pairs
    pub match_seq_num: String,          // Empty = none
    pub fencing_token: String,
    pub selected: usize,
    pub editing: bool,
    pub header_key_input: String, // For adding new header
    pub header_value_input: String,
    pub editing_header_key: bool,
    pub history: Vec<AppendResult>,
    pub appending: bool,
    // File append support
    pub input_file: String,        // Path to file to append from
    pub input_format: InputFormat, // Format for file records (text, json, json-base64)
    pub file_append_progress: Option<(usize, usize)>, // (done, total) during file append
}

/// Input format for file append (mirrors CLI's RecordFormat)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputFormat {
    #[default]
    Text,
    Json,
    JsonBase64,
}

impl InputFormat {
    pub fn next(self) -> Self {
        match self {
            Self::Text => Self::Json,
            Self::Json => Self::JsonBase64,
            Self::JsonBase64 => Self::Text,
        }
    }
}

/// Result of an append operation
#[derive(Debug, Clone)]
pub struct AppendResult {
    pub seq_num: u64,
    pub body_preview: String,
    pub header_count: usize,
}

/// State for the access tokens list screen
#[derive(Debug, Clone, Default)]
pub struct AccessTokensState {
    pub tokens: Vec<AccessTokenInfo>,
    pub selected: usize,
    pub loading: bool,
    pub filter: String,
    pub filter_active: bool,
}

/// Compression option for settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionOption {
    #[default]
    None,
    Gzip,
    Zstd,
}

impl CompressionOption {
    pub fn as_str(&self) -> &'static str {
        match self {
            CompressionOption::None => "None",
            CompressionOption::Gzip => "Gzip",
            CompressionOption::Zstd => "Zstd",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            CompressionOption::None => CompressionOption::Gzip,
            CompressionOption::Gzip => CompressionOption::Zstd,
            CompressionOption::Zstd => CompressionOption::None,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            CompressionOption::None => CompressionOption::Zstd,
            CompressionOption::Gzip => CompressionOption::None,
            CompressionOption::Zstd => CompressionOption::Gzip,
        }
    }
}

/// State for the settings screen
#[derive(Debug, Clone)]
pub struct SettingsState {
    pub access_token: String,
    pub access_token_masked: bool, // Whether to show masked or plaintext
    pub account_endpoint: String,
    pub basin_endpoint: String,
    pub compression: CompressionOption,
    pub selected: usize, // 0=token, 1=account_endpoint, 2=basin_endpoint, 3=compression
    pub editing: bool,
    pub cursor: usize,
    pub has_changes: bool,
    pub message: Option<String>,
}

impl Default for SettingsState {
    fn default() -> Self {
        Self {
            access_token: String::new(),
            access_token_masked: true,
            account_endpoint: String::new(),
            basin_endpoint: String::new(),
            compression: CompressionOption::None,
            selected: 0,
            editing: false,
            cursor: 0,
            has_changes: false,
            message: None,
        }
    }
}

/// Type of metrics being viewed
#[derive(Debug, Clone)]
pub enum MetricsType {
    Account,
    Basin {
        basin_name: BasinName,
    },
    Stream {
        basin_name: BasinName,
        stream_name: StreamName,
    },
}

/// Which metric is currently selected (for basin/stream)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MetricCategory {
    #[default]
    Storage,
    AppendOps,
    ReadOps,
    AppendThroughput,
    ReadThroughput,
    BasinOps,
    ActiveBasins,
    AccountOps,
}

impl MetricCategory {
    pub fn next(&self) -> Self {
        match self {
            Self::Storage => Self::AppendOps,
            Self::AppendOps => Self::ReadOps,
            Self::ReadOps => Self::AppendThroughput,
            Self::AppendThroughput => Self::ReadThroughput,
            Self::ReadThroughput => Self::BasinOps,
            Self::BasinOps => Self::Storage,
            Self::ActiveBasins => Self::AccountOps,
            Self::AccountOps => Self::ActiveBasins,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Self::Storage => Self::BasinOps,
            Self::AppendOps => Self::Storage,
            Self::ReadOps => Self::AppendOps,
            Self::AppendThroughput => Self::ReadOps,
            Self::ReadThroughput => Self::AppendThroughput,
            Self::BasinOps => Self::ReadThroughput,
            Self::ActiveBasins => Self::AccountOps,
            Self::AccountOps => Self::ActiveBasins,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Storage => "Storage",
            Self::AppendOps => "Append Ops",
            Self::ReadOps => "Read Ops",
            Self::AppendThroughput => "Append Throughput",
            Self::ReadThroughput => "Read Throughput",
            Self::BasinOps => "Basin Ops",
            Self::ActiveBasins => "Active Basins",
            Self::AccountOps => "Account Ops",
        }
    }
}

/// Time range options for metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeRangeOption {
    OneHour,
    SixHours,
    TwelveHours,
    #[default]
    TwentyFourHours,
    ThreeDays,
    SevenDays,
    ThirtyDays,
    Custom {
        start: u32,
        end: u32,
    }, // Unix timestamps
}

impl TimeRangeOption {
    pub const PRESETS: &'static [TimeRangeOption] = &[
        TimeRangeOption::OneHour,
        TimeRangeOption::SixHours,
        TimeRangeOption::TwelveHours,
        TimeRangeOption::TwentyFourHours,
        TimeRangeOption::ThreeDays,
        TimeRangeOption::SevenDays,
        TimeRangeOption::ThirtyDays,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            TimeRangeOption::OneHour => "1h",
            TimeRangeOption::SixHours => "6h",
            TimeRangeOption::TwelveHours => "12h",
            TimeRangeOption::TwentyFourHours => "24h",
            TimeRangeOption::ThreeDays => "3d",
            TimeRangeOption::SevenDays => "7d",
            TimeRangeOption::ThirtyDays => "30d",
            TimeRangeOption::Custom { .. } => "Custom",
        }
    }

    pub fn as_label(&self) -> &'static str {
        match self {
            TimeRangeOption::OneHour => "Last hour",
            TimeRangeOption::SixHours => "Last 6 hours",
            TimeRangeOption::TwelveHours => "Last 12 hours",
            TimeRangeOption::TwentyFourHours => "Last 24 hours",
            TimeRangeOption::ThreeDays => "Last 3 days",
            TimeRangeOption::SevenDays => "Last 7 days",
            TimeRangeOption::ThirtyDays => "Last 30 days",
            TimeRangeOption::Custom { .. } => "Custom range",
        }
    }

    pub fn as_duration(&self) -> Duration {
        match self {
            TimeRangeOption::OneHour => Duration::from_secs(60 * 60),
            TimeRangeOption::SixHours => Duration::from_secs(6 * 60 * 60),
            TimeRangeOption::TwelveHours => Duration::from_secs(12 * 60 * 60),
            TimeRangeOption::TwentyFourHours => Duration::from_secs(24 * 60 * 60),
            TimeRangeOption::ThreeDays => Duration::from_secs(3 * 24 * 60 * 60),
            TimeRangeOption::SevenDays => Duration::from_secs(7 * 24 * 60 * 60),
            TimeRangeOption::ThirtyDays => Duration::from_secs(30 * 24 * 60 * 60),
            TimeRangeOption::Custom { start, end } => Duration::from_secs((end - start) as u64),
        }
    }

    pub fn get_range(&self) -> (u32, u32) {
        match self {
            TimeRangeOption::Custom { start, end } => (*start, *end),
            _ => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                let range_secs = self.as_duration().as_secs() as u32;
                (now.saturating_sub(range_secs), now)
            }
        }
    }

    pub fn next(&self) -> Self {
        match self {
            TimeRangeOption::OneHour => TimeRangeOption::SixHours,
            TimeRangeOption::SixHours => TimeRangeOption::TwelveHours,
            TimeRangeOption::TwelveHours => TimeRangeOption::TwentyFourHours,
            TimeRangeOption::TwentyFourHours => TimeRangeOption::ThreeDays,
            TimeRangeOption::ThreeDays => TimeRangeOption::SevenDays,
            TimeRangeOption::SevenDays => TimeRangeOption::ThirtyDays,
            TimeRangeOption::ThirtyDays => TimeRangeOption::OneHour,
            TimeRangeOption::Custom { .. } => TimeRangeOption::OneHour,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            TimeRangeOption::OneHour => TimeRangeOption::ThirtyDays,
            TimeRangeOption::SixHours => TimeRangeOption::OneHour,
            TimeRangeOption::TwelveHours => TimeRangeOption::SixHours,
            TimeRangeOption::TwentyFourHours => TimeRangeOption::TwelveHours,
            TimeRangeOption::ThreeDays => TimeRangeOption::TwentyFourHours,
            TimeRangeOption::SevenDays => TimeRangeOption::ThreeDays,
            TimeRangeOption::ThirtyDays => TimeRangeOption::SevenDays,
            TimeRangeOption::Custom { .. } => TimeRangeOption::ThirtyDays,
        }
    }
}

/// State for the metrics view
#[derive(Debug, Clone)]
pub struct MetricsViewState {
    pub metrics_type: MetricsType,
    pub metrics: Vec<s2_sdk::types::Metric>,
    pub selected_category: MetricCategory,
    pub time_range: TimeRangeOption,
    pub loading: bool,
    pub scroll: usize,
    pub time_picker_open: bool,
    pub time_picker_selected: usize,
    pub calendar_open: bool,
    pub calendar_year: i32,
    pub calendar_month: u32,
    pub calendar_day: u32,                       // Currently highlighted day
    pub calendar_start: Option<(i32, u32, u32)>, // Selected start date (year, month, day)
    pub calendar_end: Option<(i32, u32, u32)>,   // Selected end date
    pub calendar_selecting_end: bool,            // true if selecting end date
}

/// Benchmark configuration phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BenchConfigField {
    #[default]
    RecordSize,
    TargetMibps,
    Duration,
    CatchupDelay,
    Start,
}

impl BenchConfigField {
    pub fn next(&self) -> Self {
        match self {
            Self::RecordSize => Self::TargetMibps,
            Self::TargetMibps => Self::Duration,
            Self::Duration => Self::CatchupDelay,
            Self::CatchupDelay => Self::Start,
            Self::Start => Self::RecordSize,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            Self::RecordSize => Self::Start,
            Self::TargetMibps => Self::RecordSize,
            Self::Duration => Self::TargetMibps,
            Self::CatchupDelay => Self::Duration,
            Self::Start => Self::CatchupDelay,
        }
    }
}

/// State for the benchmark view
#[derive(Debug, Clone)]
pub struct BenchViewState {
    pub basin_name: BasinName,
    pub config_phase: bool,
    pub config_field: BenchConfigField,
    pub record_size: u32,        // bytes (default 8KB)
    pub target_mibps: u64,       // MiB/s (default 1)
    pub duration_secs: u64,      // seconds (default 60)
    pub catchup_delay_secs: u64, // seconds (default 20)
    pub editing: bool,
    pub edit_buffer: String,
    pub stream_name: Option<String>,
    pub phase: BenchPhase,
    pub running: bool,
    pub stopping: bool,
    pub elapsed_secs: f64,
    pub progress_pct: f64,
    pub write_mibps: f64,
    pub write_recps: f64,
    pub write_bytes: u64,
    pub write_records: u64,
    pub write_history: VecDeque<f64>,
    pub read_mibps: f64,
    pub read_recps: f64,
    pub read_bytes: u64,
    pub read_records: u64,
    pub read_history: VecDeque<f64>,
    pub catchup_mibps: f64,
    pub catchup_recps: f64,
    pub catchup_bytes: u64,
    pub catchup_records: u64,
    pub ack_latency: Option<crate::types::LatencyStats>,
    pub e2e_latency: Option<crate::types::LatencyStats>,
    pub error: Option<String>,
}

impl BenchViewState {
    pub fn new(basin_name: BasinName) -> Self {
        Self {
            basin_name,
            config_phase: true,
            config_field: BenchConfigField::default(),
            record_size: 8 * 1024, // 8 KB
            target_mibps: 1,
            duration_secs: 60,
            catchup_delay_secs: 20,
            editing: false,
            edit_buffer: String::new(),
            stream_name: None,
            phase: BenchPhase::Write,
            running: false,
            stopping: false,
            elapsed_secs: 0.0,
            progress_pct: 0.0,
            write_mibps: 0.0,
            write_recps: 0.0,
            write_bytes: 0,
            write_records: 0,
            write_history: VecDeque::new(),
            read_mibps: 0.0,
            read_recps: 0.0,
            read_bytes: 0,
            read_records: 0,
            read_history: VecDeque::new(),
            catchup_mibps: 0.0,
            catchup_recps: 0.0,
            catchup_bytes: 0,
            catchup_records: 0,
            ack_latency: None,
            e2e_latency: None,
            error: None,
        }
    }
}

/// Status message level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageLevel {
    Info,
    Success,
    Error,
}

/// Status message to display
#[derive(Debug, Clone)]
pub struct StatusMessage {
    pub text: String,
    pub level: MessageLevel,
}

/// Input mode for text input dialogs
#[derive(Debug, Clone, Default)]
pub enum InputMode {
    /// Not in input mode
    #[default]
    Normal,
    /// Creating a new basin
    CreateBasin {
        name: String,
        scope: BasinScopeOption,
        create_stream_on_append: bool,
        create_stream_on_read: bool,
        storage_class: Option<StorageClass>,
        retention_policy: RetentionPolicyOption,
        retention_age_input: String,
        timestamping_mode: Option<TimestampingMode>,
        timestamping_uncapped: bool,
        delete_on_empty_enabled: bool,
        delete_on_empty_min_age: String,
        selected: usize,
        editing: bool,
        cursor: usize,
    },
    /// Creating a new stream
    CreateStream {
        basin: BasinName,
        name: String,
        storage_class: Option<StorageClass>,
        retention_policy: RetentionPolicyOption,
        retention_age_input: String,
        timestamping_mode: Option<TimestampingMode>,
        timestamping_uncapped: bool,
        delete_on_empty_enabled: bool,
        delete_on_empty_min_age: String,
        selected: usize,
        editing: bool,
        cursor: usize,
    },
    /// Confirming basin deletion
    ConfirmDeleteBasin { basin: BasinName },
    /// Confirming stream deletion
    ConfirmDeleteStream {
        basin: BasinName,
        stream: StreamName,
    },
    /// Reconfiguring a basin
    ReconfigureBasin {
        basin: BasinName,
        create_stream_on_append: Option<bool>,
        create_stream_on_read: Option<bool>,
        storage_class: Option<StorageClass>,
        retention_policy: RetentionPolicyOption,
        retention_age_secs: u64,
        timestamping_mode: Option<TimestampingMode>,
        timestamping_uncapped: Option<bool>,
        selected: usize,
        editing_age: bool,
        age_input: String,
        cursor: usize,
    },
    /// Reconfiguring a stream
    ReconfigureStream {
        basin: BasinName,
        stream: StreamName,
        storage_class: Option<StorageClass>,
        retention_policy: RetentionPolicyOption,
        retention_age_secs: u64,
        timestamping_mode: Option<TimestampingMode>,
        timestamping_uncapped: Option<bool>,
        delete_on_empty_enabled: bool,
        delete_on_empty_min_age: String,
        selected: usize,
        editing_age: bool,
        age_input: String,
        cursor: usize,
    },
    /// Custom read configuration
    CustomRead {
        basin: BasinName,
        stream: StreamName,
        start_from: ReadStartFrom,
        seq_num_value: String,
        timestamp_value: String,
        ago_value: String,
        ago_unit: AgoUnit,
        tail_offset_value: String,
        count_limit: String,
        byte_limit: String,
        until_timestamp: String,
        clamp: bool,
        format: ReadFormat,
        output_file: String,
        selected: usize,
        editing: bool,
        cursor: usize,
    },
    /// Fence a stream (set new fencing token)
    Fence {
        basin: BasinName,
        stream: StreamName,
        new_token: String,
        current_token: String, // Empty = no current token
        selected: usize,       // 0=new_token, 1=current_token, 2=submit
        editing: bool,
        cursor: usize,
    },
    /// Trim a stream (delete records before seq num)
    Trim {
        basin: BasinName,
        stream: StreamName,
        trim_point: String,
        fencing_token: String, // Empty = no fencing token
        selected: usize,       // 0=trim_point, 1=fencing_token, 2=submit
        editing: bool,
        cursor: usize,
    },
    /// Issue a new access token
    IssueAccessToken {
        id: String,
        expiry: ExpiryOption,
        expiry_custom: String,
        basins_scope: ScopeOption,
        basins_value: String,
        streams_scope: ScopeOption,
        streams_value: String,
        tokens_scope: ScopeOption,
        tokens_value: String,
        account_read: bool,
        account_write: bool,
        basin_read: bool,
        basin_write: bool,
        stream_read: bool,
        stream_write: bool,
        auto_prefix_streams: bool,
        selected: usize,
        editing: bool,
        cursor: usize,
    },
    /// Confirming access token revocation
    ConfirmRevokeToken { token_id: String },
    /// Show issued token (one-time display)
    ShowIssuedToken { token: String },
    /// View access token details
    ViewTokenDetail { token: AccessTokenInfo },
}

/// Retention policy option for UI
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum RetentionPolicyOption {
    #[default]
    Infinite,
    Age,
}

impl RetentionPolicyOption {
    pub fn toggle(&self) -> Self {
        match self {
            Self::Infinite => Self::Age,
            Self::Age => Self::Infinite,
        }
    }
}

/// Cycle storage class forward: None -> Standard -> Express -> None
fn storage_class_next(sc: &Option<StorageClass>) -> Option<StorageClass> {
    match sc {
        None => Some(StorageClass::Standard),
        Some(StorageClass::Standard) => Some(StorageClass::Express),
        Some(StorageClass::Express) => None,
    }
}

/// Cycle storage class backward: None -> Express -> Standard -> None
fn storage_class_prev(sc: &Option<StorageClass>) -> Option<StorageClass> {
    match sc {
        None => Some(StorageClass::Express),
        Some(StorageClass::Standard) => None,
        Some(StorageClass::Express) => Some(StorageClass::Standard),
    }
}

/// Cycle timestamping mode forward: None -> ClientPrefer -> ClientRequire -> Arrival -> None
fn timestamping_mode_next(tm: &Option<TimestampingMode>) -> Option<TimestampingMode> {
    match tm {
        None => Some(TimestampingMode::ClientPrefer),
        Some(TimestampingMode::ClientPrefer) => Some(TimestampingMode::ClientRequire),
        Some(TimestampingMode::ClientRequire) => Some(TimestampingMode::Arrival),
        Some(TimestampingMode::Arrival) => None,
    }
}

/// Cycle timestamping mode backward: None -> Arrival -> ClientRequire -> ClientPrefer -> None
fn timestamping_mode_prev(tm: &Option<TimestampingMode>) -> Option<TimestampingMode> {
    match tm {
        None => Some(TimestampingMode::Arrival),
        Some(TimestampingMode::ClientPrefer) => None,
        Some(TimestampingMode::ClientRequire) => Some(TimestampingMode::ClientPrefer),
        Some(TimestampingMode::Arrival) => Some(TimestampingMode::ClientRequire),
    }
}

/// Basin scope option for UI (cloud provider/region)
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum BasinScopeOption {
    #[default]
    AwsUsEast1,
}

/// Expiry options for access tokens
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ExpiryOption {
    #[default]
    Never,
    OneDay,
    SevenDays,
    ThirtyDays,
    NinetyDays,
    OneYear,
    Custom,
}

impl ExpiryOption {
    pub fn next(&self) -> Self {
        match self {
            ExpiryOption::Never => ExpiryOption::OneDay,
            ExpiryOption::OneDay => ExpiryOption::SevenDays,
            ExpiryOption::SevenDays => ExpiryOption::ThirtyDays,
            ExpiryOption::ThirtyDays => ExpiryOption::NinetyDays,
            ExpiryOption::NinetyDays => ExpiryOption::OneYear,
            ExpiryOption::OneYear => ExpiryOption::Custom,
            ExpiryOption::Custom => ExpiryOption::Never,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ExpiryOption::Never => ExpiryOption::Custom,
            ExpiryOption::OneDay => ExpiryOption::Never,
            ExpiryOption::SevenDays => ExpiryOption::OneDay,
            ExpiryOption::ThirtyDays => ExpiryOption::SevenDays,
            ExpiryOption::NinetyDays => ExpiryOption::ThirtyDays,
            ExpiryOption::OneYear => ExpiryOption::NinetyDays,
            ExpiryOption::Custom => ExpiryOption::OneYear,
        }
    }

    pub fn duration_str(self) -> Option<&'static str> {
        match self {
            ExpiryOption::Never => None,
            ExpiryOption::OneDay => Some("1d"),
            ExpiryOption::SevenDays => Some("7d"),
            ExpiryOption::ThirtyDays => Some("30d"),
            ExpiryOption::NinetyDays => Some("90d"),
            ExpiryOption::OneYear => Some("365d"),
            ExpiryOption::Custom => None,
        }
    }
}

/// Scope options for resource access
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ScopeOption {
    #[default]
    All,
    Prefix,
    Exact,
    None,
}

impl ScopeOption {
    pub fn next(&self) -> Self {
        match self {
            ScopeOption::All => ScopeOption::Prefix,
            ScopeOption::Prefix => ScopeOption::Exact,
            ScopeOption::Exact => ScopeOption::None,
            ScopeOption::None => ScopeOption::All,
        }
    }

    pub fn prev(&self) -> Self {
        match self {
            ScopeOption::All => ScopeOption::None,
            ScopeOption::Prefix => ScopeOption::All,
            ScopeOption::Exact => ScopeOption::Prefix,
            ScopeOption::None => ScopeOption::Exact,
        }
    }
}

/// Start position for read operation
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ReadStartFrom {
    /// From current tail (live follow, no historical)
    #[default]
    Tail,
    /// From specific sequence number
    SeqNum,
    /// From specific timestamp (ms)
    Timestamp,
    /// From N time ago
    Ago,
    /// From N records before tail
    TailOffset,
}

/// Time unit for "ago" option
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum AgoUnit {
    Seconds,
    #[default]
    Minutes,
    Hours,
    Days,
}

impl AgoUnit {
    pub fn as_seconds(self, value: u64) -> u64 {
        match self {
            AgoUnit::Seconds => value,
            AgoUnit::Minutes => value * 60,
            AgoUnit::Hours => value * 3600,
            AgoUnit::Days => value * 86400,
        }
    }

    pub fn next(self) -> Self {
        match self {
            AgoUnit::Seconds => AgoUnit::Minutes,
            AgoUnit::Minutes => AgoUnit::Hours,
            AgoUnit::Hours => AgoUnit::Days,
            AgoUnit::Days => AgoUnit::Seconds,
        }
    }
}

/// Output format for read operation
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ReadFormat {
    #[default]
    Text,
    Json,
    JsonBase64,
}

impl ReadFormat {
    pub fn next(&self) -> Self {
        match self {
            ReadFormat::Text => ReadFormat::Json,
            ReadFormat::Json => ReadFormat::JsonBase64,
            ReadFormat::JsonBase64 => ReadFormat::Text,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ReadFormat::Text => "text",
            ReadFormat::Json => "json",
            ReadFormat::JsonBase64 => "json-base64",
        }
    }
}
/// Config for basin reconfiguration
#[derive(Debug, Clone)]
pub struct BasinReconfigureConfig {
    pub create_stream_on_append: Option<bool>,
    pub create_stream_on_read: Option<bool>,
    pub storage_class: Option<StorageClass>,
    pub retention_policy: RetentionPolicyOption,
    pub retention_age_secs: u64,
    pub timestamping_mode: Option<TimestampingMode>,
    pub timestamping_uncapped: Option<bool>,
}

/// Config for stream reconfiguration
#[derive(Debug, Clone)]
pub struct StreamReconfigureConfig {
    pub storage_class: Option<StorageClass>,
    pub retention_policy: RetentionPolicyOption,
    pub retention_age_secs: u64,
    pub timestamping_mode: Option<TimestampingMode>,
    pub timestamping_uncapped: Option<bool>,
    pub delete_on_empty_enabled: bool,
    pub delete_on_empty_min_age: String,
}

/// Main application state
pub struct App {
    pub screen: Screen,
    pub tab: Tab,
    pub s2: Option<s2_sdk::S2>,
    pub message: Option<StatusMessage>,
    pub show_help: bool,
    pub input_mode: InputMode,
    pub pip: Option<PipState>,
    should_quit: bool,
    /// Stop signal for the benchmark task
    bench_stop_signal: Option<Arc<AtomicBool>>,
}

/// Build a basin config from form values
#[allow(clippy::too_many_arguments)]
fn build_basin_config(
    create_stream_on_append: bool,
    create_stream_on_read: bool,
    storage_class: Option<StorageClass>,
    retention_policy: RetentionPolicyOption,
    retention_age_input: String,
    timestamping_mode: Option<TimestampingMode>,
    timestamping_uncapped: bool,
    delete_on_empty_enabled: bool,
    delete_on_empty_min_age: String,
) -> BasinConfig {
    let retention = match retention_policy {
        RetentionPolicyOption::Infinite => None,
        RetentionPolicyOption::Age => humantime::parse_duration(&retention_age_input)
            .ok()
            .map(RetentionPolicy::Age),
    };
    let timestamping = if timestamping_mode.is_some() || timestamping_uncapped {
        Some(TimestampingConfig {
            timestamping_mode,
            timestamping_uncapped: if timestamping_uncapped {
                Some(true)
            } else {
                None
            },
        })
    } else {
        None
    };
    let delete_on_empty = if delete_on_empty_enabled {
        humantime::parse_duration(&delete_on_empty_min_age)
            .ok()
            .map(|d| DeleteOnEmptyConfig {
                delete_on_empty_min_age: d,
            })
    } else {
        None
    };

    BasinConfig {
        default_stream_config: StreamConfig {
            storage_class,
            retention_policy: retention,
            timestamping,
            delete_on_empty,
        },
        create_stream_on_append,
        create_stream_on_read,
    }
}

fn build_stream_config(
    storage_class: Option<StorageClass>,
    retention_policy: RetentionPolicyOption,
    retention_age_input: String,
    timestamping_mode: Option<TimestampingMode>,
    timestamping_uncapped: bool,
    delete_on_empty_enabled: bool,
    delete_on_empty_min_age: String,
) -> StreamConfig {
    let retention = match retention_policy {
        RetentionPolicyOption::Infinite => None,
        RetentionPolicyOption::Age => humantime::parse_duration(&retention_age_input)
            .ok()
            .map(RetentionPolicy::Age),
    };
    let timestamping = if timestamping_mode.is_some() || timestamping_uncapped {
        Some(TimestampingConfig {
            timestamping_mode,
            timestamping_uncapped: if timestamping_uncapped {
                Some(true)
            } else {
                None
            },
        })
    } else {
        None
    };
    let delete_on_empty = if delete_on_empty_enabled {
        humantime::parse_duration(&delete_on_empty_min_age)
            .ok()
            .map(|d| DeleteOnEmptyConfig {
                delete_on_empty_min_age: d,
            })
    } else {
        None
    };

    StreamConfig {
        storage_class,
        retention_policy: retention,
        timestamping,
        delete_on_empty,
    }
}

impl App {
    pub fn new(s2: Option<s2_sdk::S2>) -> Self {
        let screen = if s2.is_some() {
            Screen::Splash
        } else {
            Screen::Setup(SetupState::default())
        };
        Self {
            screen,
            tab: Tab::Basins,
            s2,
            message: None,
            show_help: false,
            input_mode: InputMode::Normal,
            pip: None,
            should_quit: false,
            bench_stop_signal: None,
        }
    }

    /// Create an S2 client from the given access token
    fn create_s2_client(access_token: &str) -> Result<s2_sdk::S2, CliError> {
        let sdk_config = s2_sdk::types::S2Config::new(access_token)
            .with_user_agent("s2-cli")
            .map_err(|e| CliError::EndpointsFromEnv(e.to_string()))?
            .with_request_timeout(Duration::from_secs(30));
        s2_sdk::S2::new(sdk_config).map_err(CliError::SdkInit)
    }

    /// Load settings from config file
    fn load_settings_state() -> SettingsState {
        let file_config = config::load_config_file().unwrap_or_default();

        let env_config = config::load_cli_config().unwrap_or_default();
        let access_token = file_config
            .access_token
            .clone()
            .or_else(|| env_config.access_token.clone())
            .unwrap_or_default();
        let token_from_env =
            file_config.access_token.is_none() && env_config.access_token.is_some();

        SettingsState {
            access_token,
            access_token_masked: true,
            account_endpoint: file_config.account_endpoint.unwrap_or_default(),
            basin_endpoint: file_config.basin_endpoint.unwrap_or_default(),
            compression: match file_config.compression {
                Some(Compression::Gzip) => CompressionOption::Gzip,
                Some(Compression::Zstd) => CompressionOption::Zstd,
                None => CompressionOption::None,
            },
            selected: 0,
            editing: false,
            cursor: 0,
            has_changes: false,
            message: if token_from_env {
                Some("Token loaded from S2_ACCESS_TOKEN env var".to_string())
            } else {
                None
            },
        }
    }

    /// Save settings to config file
    fn save_settings_static(state: &SettingsState) -> Result<(), CliError> {
        let mut cli_config = config::load_config_file().unwrap_or_default();
        if state.access_token.is_empty() {
            cli_config.unset(ConfigKey::AccessToken);
        } else {
            cli_config
                .set(ConfigKey::AccessToken, state.access_token.clone())
                .map_err(CliError::Config)?;
        }
        if state.account_endpoint.is_empty() {
            cli_config.unset(ConfigKey::AccountEndpoint);
        } else {
            cli_config
                .set(ConfigKey::AccountEndpoint, state.account_endpoint.clone())
                .map_err(CliError::Config)?;
        }
        if state.basin_endpoint.is_empty() {
            cli_config.unset(ConfigKey::BasinEndpoint);
        } else {
            cli_config
                .set(ConfigKey::BasinEndpoint, state.basin_endpoint.clone())
                .map_err(CliError::Config)?;
        }
        match state.compression {
            CompressionOption::None => cli_config.unset(ConfigKey::Compression),
            CompressionOption::Gzip => {
                cli_config
                    .set(ConfigKey::Compression, "gzip".to_string())
                    .map_err(CliError::Config)?;
            }
            CompressionOption::Zstd => {
                cli_config
                    .set(ConfigKey::Compression, "zstd".to_string())
                    .map_err(CliError::Config)?;
            }
        }

        config::save_cli_config(&cli_config).map_err(CliError::Config)?;
        Ok(())
    }

    pub async fn run<B: Backend>(mut self, terminal: &mut Terminal<B>) -> Result<(), CliError> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let splash_start = std::time::Instant::now();
        let splash_duration = Duration::from_millis(SPLASH_DURATION_MS);
        if self.s2.is_some() {
            self.load_basins(tx.clone());
        }
        let mut pending_basins: Option<Result<(Vec<BasinInfo>, bool), CliError>> = None;

        loop {
            terminal
                .draw(|f| ui::draw(f, &self))
                .map_err(|e| CliError::RecordWrite(format!("Failed to draw: {e}")))?;
            if matches!(self.screen, Screen::Splash) && splash_start.elapsed() >= splash_duration {
                let mut basins_state = BasinsState {
                    loading: pending_basins.is_none(),
                    ..Default::default()
                };
                if let Some(result) = pending_basins.take() {
                    match result {
                        Ok((basins, has_more)) => {
                            basins_state.basins = basins;
                            basins_state.has_more = has_more;
                            basins_state.loading = false;
                        }
                        Err(e) => {
                            basins_state.loading = false;
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load basins: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
                self.screen = Screen::Basins(basins_state);
            }

            // Always check keyboard input first (non-blocking) to ensure responsiveness
            // even when async events are flooding in
            if event::poll(Duration::from_millis(0))
                .map_err(|e| CliError::RecordWrite(format!("Failed to poll events: {e}")))?
                && let CrosstermEvent::Key(key) = event::read()
                    .map_err(|e| CliError::RecordWrite(format!("Failed to read event: {e}")))?
            {
                if matches!(self.screen, Screen::Splash) {
                    let mut basins_state = BasinsState {
                        loading: pending_basins.is_none(),
                        ..Default::default()
                    };
                    if let Some(result) = pending_basins.take() {
                        match result {
                            Ok((basins, has_more)) => {
                                basins_state.basins = basins;
                                basins_state.has_more = has_more;
                                basins_state.loading = false;
                            }
                            Err(e) => {
                                basins_state.loading = false;
                                self.message = Some(StatusMessage {
                                    text: format!("Failed to load basins: {e}"),
                                    level: MessageLevel::Error,
                                });
                            }
                        }
                    }
                    self.screen = Screen::Basins(basins_state);
                    continue;
                }
                self.handle_key(key, tx.clone());
            }
            if self.should_quit {
                break;
            }

            // Handle async events from background tasks with a short timeout
            tokio::select! {
                Some(event) = rx.recv() => {

                    if matches!(self.screen, Screen::Splash)
                        && let Event::BasinsLoaded(result) = event {
                            pending_basins = Some(result);
                            continue;
                        }
                    self.handle_event(event);
                }
                _ = tokio::time::sleep(Duration::from_millis(FRAME_INTERVAL_MS)) => {}
            }

            if self.should_quit {
                break;
            }
        }

        Ok(())
    }

    fn handle_event(&mut self, event: Event) {
        match event {
            Event::BasinsLoaded(result) => {
                if let Screen::Basins(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok((basins, has_more)) => {
                            state.has_more = has_more;
                            state.basins = basins;
                            self.message = Some(StatusMessage {
                                text: format!("Loaded {} basins", state.basins.len()),
                                level: MessageLevel::Success,
                            });
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load basins: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::MoreBasinsLoaded(result) => {
                if let Screen::Basins(state) = &mut self.screen {
                    state.loading_more = false;
                    match result {
                        Ok((basins, has_more)) => {
                            state.has_more = has_more;
                            state.basins.extend(basins);
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load more: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::StreamsLoaded(result) => {
                if let Screen::Streams(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok((streams, has_more)) => {
                            state.has_more = has_more;
                            state.streams = streams;
                            self.message = Some(StatusMessage {
                                text: format!("Loaded {} streams", state.streams.len()),
                                level: MessageLevel::Success,
                            });
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load streams: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::MoreStreamsLoaded(result) => {
                if let Screen::Streams(state) = &mut self.screen {
                    state.loading_more = false;
                    match result {
                        Ok((streams, has_more)) => {
                            state.has_more = has_more;
                            state.streams.extend(streams);
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load more: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::StreamConfigLoaded(result) => {
                if let Screen::StreamDetail(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok(config) => {
                            state.config = Some(config);
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load config: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::TailPositionLoaded(result) => {
                if let Screen::StreamDetail(state) = &mut self.screen {
                    match result {
                        Ok(pos) => {
                            state.tail_position = Some(pos);
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load tail position: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::RecordReceived(result) => {
                if let Screen::ReadView(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok(record) => {
                            if !state.paused {
                                // Deduplicate by seq_num - skip if we already have this or a later
                                // record
                                let dominated = state
                                    .records
                                    .back()
                                    .map(|last| record.seq_num <= last.seq_num)
                                    .unwrap_or(false);
                                if dominated {
                                    return;
                                }

                                // Track throughput
                                let record_bytes = record.body.len() as u64;
                                state.bytes_this_second += record_bytes;
                                state.records_this_second += 1;

                                // Check if a second has passed
                                if let Some(last_tick) = state.last_tick {
                                    let elapsed = last_tick.elapsed();
                                    if elapsed >= std::time::Duration::from_secs(1) {
                                        let (mibps, recps) = calculate_throughput(
                                            state.bytes_this_second,
                                            state.records_this_second,
                                            elapsed.as_secs_f64(),
                                        );

                                        state.current_mibps = mibps;
                                        state.current_recps = recps;
                                        state.throughput_history.push_back(mibps);
                                        state.records_per_sec_history.push_back(recps);

                                        if state.throughput_history.len() > MAX_THROUGHPUT_HISTORY {
                                            state.throughput_history.pop_front();
                                        }
                                        if state.records_per_sec_history.len()
                                            > MAX_THROUGHPUT_HISTORY
                                        {
                                            state.records_per_sec_history.pop_front();
                                        }

                                        state.bytes_this_second = 0;
                                        state.records_this_second = 0;
                                        state.last_tick = Some(std::time::Instant::now());
                                    }
                                }

                                state.records.push_back(record);

                                while state.records.len() > MAX_RECORDS_BUFFER {
                                    state.records.pop_front();

                                    if state.selected > 0 {
                                        state.selected = state.selected.saturating_sub(1);
                                    }
                                }

                                if state.is_tailing {
                                    state.selected = state.records.len().saturating_sub(1);
                                }
                            }
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Read error: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::ReadEnded => {
                if let Screen::ReadView(state) = &mut self.screen {
                    state.loading = false;
                    if !state.is_tailing {
                        self.message = Some(StatusMessage {
                            text: "Read complete".to_string(),
                            level: MessageLevel::Info,
                        });
                    }
                }
            }

            Event::PipRecordReceived(result) => {
                if let Some(ref mut pip) = self.pip
                    && !pip.paused
                {
                    match result {
                        Ok(record) => {
                            // Deduplicate by seq_num
                            let dominated = pip
                                .records
                                .back()
                                .map(|last| record.seq_num <= last.seq_num)
                                .unwrap_or(false);
                            if dominated {
                                return;
                            }

                            // Track throughput
                            let record_bytes = record.body.len() as u64;
                            pip.bytes_this_second += record_bytes;
                            pip.records_this_second += 1;

                            // Check if a second has passed
                            if let Some(last_tick) = pip.last_tick {
                                let elapsed = last_tick.elapsed();
                                if elapsed >= std::time::Duration::from_secs(1) {
                                    let (mibps, recps) = calculate_throughput(
                                        pip.bytes_this_second,
                                        pip.records_this_second,
                                        elapsed.as_secs_f64(),
                                    );
                                    pip.current_mibps = mibps;
                                    pip.current_recps = recps;
                                    pip.bytes_this_second = 0;
                                    pip.records_this_second = 0;
                                    pip.last_tick = Some(std::time::Instant::now());
                                }
                            }

                            pip.records.push_back(record);

                            // Keep PiP buffer small
                            while pip.records.len() > MAX_PIP_RECORDS {
                                pip.records.pop_front();
                            }
                        }
                        Err(_) => {
                            // Silently ignore errors in PiP to not disrupt main workflow
                        }
                    }
                }
            }

            Event::PipReadEnded => {
                // PiP stream ended - could happen if stream is deleted
                if self.pip.is_some() {
                    self.pip = None;
                    self.message = Some(StatusMessage {
                        text: "PiP stream ended".to_string(),
                        level: MessageLevel::Info,
                    });
                }
            }

            Event::BasinCreated(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(basin) => {
                        self.message = Some(StatusMessage {
                            text: format!("Created basin '{}'", basin.name),
                            level: MessageLevel::Success,
                        });

                        if let Screen::Basins(state) = &mut self.screen {
                            state.loading = true;
                        }
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to create basin: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::BasinDeleted(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(name) => {
                        self.message = Some(StatusMessage {
                            text: format!("Deleted basin '{}'", name),
                            level: MessageLevel::Success,
                        });

                        if let Screen::Basins(state) = &mut self.screen {
                            state.loading = true;
                        }
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to delete basin: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::StreamCreated(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(stream) => {
                        self.message = Some(StatusMessage {
                            text: format!("Created stream '{}'", stream.name),
                            level: MessageLevel::Success,
                        });

                        if let Screen::Streams(state) = &mut self.screen {
                            state.loading = true;
                        }
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to create stream: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::StreamDeleted(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(name) => {
                        self.message = Some(StatusMessage {
                            text: format!("Deleted stream '{}'", name),
                            level: MessageLevel::Success,
                        });

                        if let Screen::Streams(state) = &mut self.screen {
                            state.loading = true;
                        }
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to delete stream: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::BasinConfigLoaded(result) => {
                if let InputMode::ReconfigureBasin {
                    create_stream_on_append,
                    create_stream_on_read,
                    storage_class,
                    retention_policy,
                    retention_age_secs,
                    timestamping_mode,
                    timestamping_uncapped,
                    age_input,
                    ..
                } = &mut self.input_mode
                {
                    match result {
                        Ok(info) => {
                            *create_stream_on_append = Some(info.create_stream_on_append);
                            *create_stream_on_read = Some(info.create_stream_on_read);
                            *storage_class = info.storage_class;
                            if let Some(age) = info.retention_age_secs {
                                *retention_policy = RetentionPolicyOption::Age;
                                *retention_age_secs = age;
                                *age_input = age.to_string();
                            } else {
                                *retention_policy = RetentionPolicyOption::Infinite;
                            }
                            *timestamping_mode = info.timestamping_mode;
                            *timestamping_uncapped = Some(info.timestamping_uncapped);
                        }
                        Err(e) => {
                            self.input_mode = InputMode::Normal;
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load basin config: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::StreamConfigForReconfigLoaded(result) => {
                if let InputMode::ReconfigureStream {
                    storage_class,
                    retention_policy,
                    retention_age_secs,
                    timestamping_mode,
                    timestamping_uncapped,
                    delete_on_empty_enabled,
                    delete_on_empty_min_age,
                    age_input,
                    ..
                } = &mut self.input_mode
                {
                    match result {
                        Ok(info) => {
                            *storage_class = info.storage_class;
                            if let Some(age) = info.retention_age_secs {
                                *retention_policy = RetentionPolicyOption::Age;
                                *retention_age_secs = age;
                                *age_input = age.to_string();
                            } else {
                                *retention_policy = RetentionPolicyOption::Infinite;
                            }
                            *timestamping_mode = info.timestamping_mode;
                            *timestamping_uncapped = Some(info.timestamping_uncapped);

                            if let Some(min_age_secs) = info.delete_on_empty_min_age_secs {
                                *delete_on_empty_enabled = true;
                                *delete_on_empty_min_age = format!("{}s", min_age_secs);
                            } else {
                                *delete_on_empty_enabled = false;
                            }
                        }
                        Err(e) => {
                            self.input_mode = InputMode::Normal;
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load stream config: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::BasinReconfigured(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(()) => {
                        self.message = Some(StatusMessage {
                            text: "Basin reconfigured".to_string(),
                            level: MessageLevel::Success,
                        });
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to reconfigure basin: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::StreamReconfigured(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(()) => {
                        self.message = Some(StatusMessage {
                            text: "Stream reconfigured".to_string(),
                            level: MessageLevel::Success,
                        });
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to reconfigure stream: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::StreamFenced(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(token) => {
                        self.message = Some(StatusMessage {
                            text: format!("Stream fenced with token: {}", token),
                            level: MessageLevel::Success,
                        });
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to fence stream: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::StreamTrimmed(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok((trim_point, new_tail)) => {
                        self.message = Some(StatusMessage {
                            text: format!("Trimmed to {} (tail: {})", trim_point, new_tail),
                            level: MessageLevel::Success,
                        });
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to trim stream: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::RecordAppended(result) => {
                if let Screen::AppendView(state) = &mut self.screen {
                    state.appending = false;
                    match result {
                        Ok((seq_num, body_preview, header_count)) => {
                            state.history.push(AppendResult {
                                seq_num,
                                body_preview,
                                header_count,
                            });
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to append: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::FileAppendProgress {
                appended,
                total,
                last_seq,
            } => {
                if let Screen::AppendView(state) = &mut self.screen {
                    state.file_append_progress = Some((appended, total));
                    if let Some(seq) = last_seq {
                        // Add to history as we go
                        state.history.push(AppendResult {
                            seq_num: seq,
                            body_preview: format!("batch #{}", appended),
                            header_count: 0,
                        });
                    }
                }
            }

            Event::FileAppendComplete(result) => {
                if let Screen::AppendView(state) = &mut self.screen {
                    state.appending = false;
                    state.file_append_progress = None;
                    match result {
                        Ok((total, first_seq, last_seq)) => {
                            self.message = Some(StatusMessage {
                                text: format!(
                                    "Appended {} records (seq {}..{})",
                                    total, first_seq, last_seq
                                ),
                                level: MessageLevel::Success,
                            });
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to append from file: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::AccessTokensLoaded(result) => {
                if let Screen::AccessTokens(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok(tokens) => {
                            state.tokens = tokens;
                            self.message = Some(StatusMessage {
                                text: format!("Loaded {} access tokens", state.tokens.len()),
                                level: MessageLevel::Success,
                            });
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load access tokens: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::AccessTokenIssued(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(token) => {
                        self.input_mode = InputMode::ShowIssuedToken {
                            token: token.clone(),
                        };
                        self.message = Some(StatusMessage {
                            text: "Access token issued - copy it now, it won't be shown again!"
                                .to_string(),
                            level: MessageLevel::Success,
                        });

                        if let Screen::AccessTokens(state) = &mut self.screen {
                            state.loading = true;
                        }
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to issue access token: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::AccessTokenRevoked(result) => {
                self.input_mode = InputMode::Normal;
                match result {
                    Ok(id) => {
                        self.message = Some(StatusMessage {
                            text: format!("Revoked access token '{}'", id),
                            level: MessageLevel::Success,
                        });

                        if let Screen::AccessTokens(state) = &mut self.screen {
                            state.loading = true;
                        }
                    }
                    Err(e) => {
                        self.message = Some(StatusMessage {
                            text: format!("Failed to revoke access token: {e}"),
                            level: MessageLevel::Error,
                        });
                    }
                }
            }

            Event::AccountMetricsLoaded(result) => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok(metrics) => {
                            state.metrics = metrics;
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load account metrics: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::BasinMetricsLoaded(result) => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok(metrics) => {
                            state.metrics = metrics;
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load basin metrics: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::StreamMetricsLoaded(result) => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.loading = false;
                    match result {
                        Ok(metrics) => {
                            state.metrics = metrics;
                        }
                        Err(e) => {
                            self.message = Some(StatusMessage {
                                text: format!("Failed to load stream metrics: {e}"),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
            }

            Event::Error(e) => {
                self.message = Some(StatusMessage {
                    text: e.to_string(),
                    level: MessageLevel::Error,
                });
            }

            Event::BenchStreamCreated(result) => {
                if let Screen::BenchView(state) = &mut self.screen {
                    match result {
                        Ok(stream_name) => {
                            state.stream_name = Some(stream_name);
                            state.running = true;
                            self.message = Some(StatusMessage {
                                text: "Benchmark started".to_string(),
                                level: MessageLevel::Info,
                            });
                        }
                        Err(e) => {
                            state.error = Some(e.to_string());
                            state.running = false;
                        }
                    }
                }
            }

            Event::BenchWriteSample(sample) => {
                if let Screen::BenchView(state) = &mut self.screen {
                    state.write_mibps = sample.mib_per_sec;
                    state.write_recps = sample.records_per_sec;
                    state.write_bytes = sample.bytes;
                    state.write_records = sample.records;
                    state.elapsed_secs = sample.elapsed.as_secs_f64();
                    state.progress_pct =
                        ((state.elapsed_secs / state.duration_secs as f64) * 100.0).min(100.0);

                    state.write_history.push_back(sample.mib_per_sec);
                    if state.write_history.len() > 60 {
                        state.write_history.pop_front();
                    }
                }
            }

            Event::BenchReadSample(sample) => {
                if let Screen::BenchView(state) = &mut self.screen {
                    state.read_mibps = sample.mib_per_sec;
                    state.read_recps = sample.records_per_sec;
                    state.read_bytes = sample.bytes;
                    state.read_records = sample.records;
                    state.elapsed_secs = sample.elapsed.as_secs_f64();

                    state.read_history.push_back(sample.mib_per_sec);
                    if state.read_history.len() > 60 {
                        state.read_history.pop_front();
                    }
                }
            }

            Event::BenchCatchupSample(sample) => {
                if let Screen::BenchView(state) = &mut self.screen {
                    state.catchup_mibps = sample.mib_per_sec;
                    state.catchup_recps = sample.records_per_sec;
                    state.catchup_bytes = sample.bytes;
                    state.catchup_records = sample.records;
                    state.elapsed_secs = sample.elapsed.as_secs_f64();
                }
            }

            Event::BenchPhaseComplete(phase) => {
                if let Screen::BenchView(state) = &mut self.screen {
                    state.phase = match phase {
                        BenchPhase::Write => BenchPhase::Read,
                        BenchPhase::Read => BenchPhase::CatchupWait,
                        BenchPhase::CatchupWait => BenchPhase::Catchup,
                        BenchPhase::Catchup => BenchPhase::Catchup, // Final
                    };
                }
            }

            Event::BenchComplete(result) => {
                if let Screen::BenchView(state) = &mut self.screen {
                    state.running = false;
                    match result {
                        Ok(stats) => {
                            state.ack_latency = stats.ack_latency;
                            state.e2e_latency = stats.e2e_latency;
                            self.message = Some(StatusMessage {
                                text: "Benchmark complete!".to_string(),
                                level: MessageLevel::Success,
                            });
                        }
                        Err(e) => {
                            state.error = Some(e.to_string());
                        }
                    }
                }
            }
        }
    }

    fn is_text_input_active(&self) -> bool {
        if !matches!(self.input_mode, InputMode::Normal) {
            return true;
        }
        match &self.screen {
            Screen::Setup(_) => true,
            Screen::Settings(s) => s.editing,
            Screen::BenchView(s) => s.editing,
            Screen::Basins(s) => s.filter_active,
            Screen::Streams(s) => s.filter_active,
            Screen::AccessTokens(s) => s.filter_active,
            Screen::AppendView(s) => s.editing,
            _ => false,
        }
    }

    fn handle_text_input(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        if !matches!(self.input_mode, InputMode::Normal) {
            self.handle_input_key(key, tx);
            return;
        }
        match &self.screen {
            Screen::Setup(_) => self.handle_setup_key(key, tx),
            Screen::Settings(_) => self.handle_settings_key(key, tx),
            Screen::BenchView(_) => self.handle_bench_view_key(key, tx),
            Screen::Basins(_) => self.handle_basins_key(key, tx),
            Screen::Streams(_) => self.handle_streams_key(key, tx),
            Screen::AccessTokens(_) => self.handle_access_tokens_key(key, tx),
            Screen::AppendView(_) => self.handle_append_view_key(key, tx),
            _ => {}
        }
    }

    fn handle_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        self.message = None;

        // Text input modes bypass global keybindings
        if self.is_text_input_active() {
            self.handle_text_input(key, tx);
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc if self.show_help => {
                self.show_help = false;
                return;
            }
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
                return;
            }
            KeyCode::Char('P') => {
                // Toggle PiP visibility or close it
                if let Some(ref mut pip) = self.pip {
                    if pip.minimized {
                        // Restore minimized PiP
                        pip.minimized = false;
                    } else {
                        // Close PiP entirely
                        self.pip = None;
                        self.message = Some(StatusMessage {
                            text: "PiP closed".to_string(),
                            level: MessageLevel::Info,
                        });
                    }
                }
                return;
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                return;
            }
            KeyCode::Char('q') if !matches!(self.screen, Screen::Basins(_)) => {}
            KeyCode::Char('q') => {
                self.should_quit = true;
                return;
            }
            _ => {}
        }

        if self.show_help {
            return;
        }
        if key.code == KeyCode::Tab {
            match &self.screen {
                Screen::Basins(_) | Screen::AccessTokens(_) | Screen::Settings(_) => {
                    self.switch_tab(tx.clone());
                    return;
                }
                _ => {}
            }
        }
        match &self.screen {
            Screen::Splash | Screen::Setup(_) => {}
            Screen::Basins(_) => self.handle_basins_key(key, tx),
            Screen::Streams(_) => self.handle_streams_key(key, tx),
            Screen::StreamDetail(_) => self.handle_stream_detail_key(key, tx),
            Screen::ReadView(_) => self.handle_read_view_key(key, tx),
            Screen::AppendView(_) => self.handle_append_view_key(key, tx),
            Screen::AccessTokens(_) => self.handle_access_tokens_key(key, tx),
            Screen::MetricsView(_) => self.handle_metrics_view_key(key, tx),
            Screen::Settings(_) => self.handle_settings_key(key, tx),
            Screen::BenchView(_) => self.handle_bench_view_key(key, tx),
        }
    }

    fn handle_input_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        // Handle IssueAccessToken submit separately to avoid borrow issues.
        // We need to extract values before calling the method since the match arm
        // holds borrows that conflict with the method call.
        if matches!(key.code, KeyCode::Char(' ') | KeyCode::Enter)
            && let InputMode::IssueAccessToken {
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
                ..
            } = &self.input_mode
            && *selected == 16
            && !*editing
            && !id.is_empty()
        {
            let id = id.clone();
            let expiry = *expiry;
            let expiry_custom = expiry_custom.clone();
            let basins_scope = *basins_scope;
            let basins_value = basins_value.clone();
            let streams_scope = *streams_scope;
            let streams_value = streams_value.clone();
            let tokens_scope = *tokens_scope;
            let tokens_value = tokens_value.clone();
            let account_read = *account_read;
            let account_write = *account_write;
            let basin_read = *basin_read;
            let basin_write = *basin_write;
            let stream_read = *stream_read;
            let stream_write = *stream_write;
            let auto_prefix_streams = *auto_prefix_streams;
            self.issue_access_token_v2(
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
                tx,
            );
            return;
        }

        match &mut self.input_mode {
            InputMode::Normal => {}

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
                const FIELD_COUNT: usize = 12;

                if *editing {
                    let field: Option<&mut String> = match *selected {
                        0 => Some(name),
                        4 => Some(retention_age_input),
                        8 => Some(delete_on_empty_min_age),
                        _ => None,
                    };
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            *editing = false;
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            if let Some(f) = field {
                                *cursor = (*cursor + 1).min(f.len());
                            }
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            if let Some(f) = field {
                                *cursor = f.len();
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(f) = field
                                && *cursor > 0
                            {
                                f.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if let Some(f) = field
                                && *cursor < f.len()
                            {
                                f.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) => {
                            if *selected == 0 {
                                if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
                                    name.insert(*cursor, c);
                                    *cursor += 1;
                                }
                            } else if *selected == 4 && c.is_ascii_alphanumeric() {
                                retention_age_input.insert(*cursor, c);
                                *cursor += 1;
                            } else if *selected == 8 && c.is_ascii_alphanumeric() {
                                delete_on_empty_min_age.insert(*cursor, c);
                                *cursor += 1;
                            }
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => {
                            self.input_mode = InputMode::Normal;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if *selected > 0 {
                                *selected -= 1;

                                if *selected == 8 && !*delete_on_empty_enabled {
                                    *selected = 7;
                                }

                                if *selected == 4 && *retention_policy != RetentionPolicyOption::Age
                                {
                                    *selected = 3;
                                }
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if *selected < FIELD_COUNT - 1 {
                                *selected += 1;

                                if *selected == 4 && *retention_policy != RetentionPolicyOption::Age
                                {
                                    *selected = 5;
                                }

                                if *selected == 8 && !*delete_on_empty_enabled {
                                    *selected = 9;
                                }
                            }
                        }
                        KeyCode::Enter => match *selected {
                            0 => {
                                *cursor = name.len();
                                *editing = true;
                            }
                            4 => {
                                if *retention_policy == RetentionPolicyOption::Age {
                                    *cursor = retention_age_input.len();
                                    *editing = true;
                                }
                            }
                            8 => {
                                if *delete_on_empty_enabled {
                                    *cursor = delete_on_empty_min_age.len();
                                    *editing = true;
                                }
                            }
                            11 => {
                                if name.len() >= 8 {
                                    let basin_name = name.clone();
                                    let basin_scope = *scope;
                                    let csoa = *create_stream_on_append;
                                    let csor = *create_stream_on_read;
                                    let sc = storage_class.clone();
                                    let rp = *retention_policy;
                                    let rai = retention_age_input.clone();
                                    let tm = timestamping_mode.clone();
                                    let tu = *timestamping_uncapped;
                                    let doe = *delete_on_empty_enabled;
                                    let doema = delete_on_empty_min_age.clone();

                                    let config = build_basin_config(
                                        csoa, csor, sc, rp, rai, tm, tu, doe, doema,
                                    );
                                    self.create_basin_with_config(
                                        basin_name,
                                        basin_scope,
                                        config,
                                        tx.clone(),
                                    );
                                }
                            }
                            _ => {}
                        },
                        KeyCode::Char(' ') => match *selected {
                            6 => *timestamping_uncapped = !*timestamping_uncapped,
                            9 => *create_stream_on_append = !*create_stream_on_append,
                            10 => *create_stream_on_read = !*create_stream_on_read,
                            _ => {}
                        },
                        KeyCode::Left | KeyCode::Char('h') => match *selected {
                            2 => *storage_class = storage_class_prev(storage_class),
                            3 => *retention_policy = retention_policy.toggle(),
                            5 => *timestamping_mode = timestamping_mode_prev(timestamping_mode),
                            7 => *delete_on_empty_enabled = !*delete_on_empty_enabled,
                            _ => {}
                        },
                        KeyCode::Right | KeyCode::Char('l') => match *selected {
                            2 => *storage_class = storage_class_next(storage_class),
                            3 => *retention_policy = retention_policy.toggle(),
                            5 => *timestamping_mode = timestamping_mode_next(timestamping_mode),
                            7 => *delete_on_empty_enabled = !*delete_on_empty_enabled,
                            _ => {}
                        },
                        _ => {}
                    }
                }
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
                const FIELD_COUNT: usize = 9;

                if *editing {
                    let field: Option<&mut String> = match *selected {
                        0 => Some(name),
                        3 => Some(retention_age_input),
                        7 => Some(delete_on_empty_min_age),
                        _ => None,
                    };
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            *editing = false;
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            if let Some(f) = field {
                                *cursor = (*cursor + 1).min(f.len());
                            }
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            if let Some(f) = field {
                                *cursor = f.len();
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(f) = field
                                && *cursor > 0
                            {
                                f.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if let Some(f) = field
                                && *cursor < f.len()
                            {
                                f.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) => {
                            if *selected == 0 {
                                name.insert(*cursor, c);
                                *cursor += 1;
                            } else if *selected == 3 && c.is_ascii_alphanumeric() {
                                retention_age_input.insert(*cursor, c);
                                *cursor += 1;
                            } else if *selected == 7 && c.is_ascii_alphanumeric() {
                                delete_on_empty_min_age.insert(*cursor, c);
                                *cursor += 1;
                            }
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => {
                            self.input_mode = InputMode::Normal;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if *selected > 0 {
                                *selected -= 1;

                                if *selected == 7 && !*delete_on_empty_enabled {
                                    *selected = 6;
                                }

                                if *selected == 3 && *retention_policy != RetentionPolicyOption::Age
                                {
                                    *selected = 2;
                                }
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if *selected < FIELD_COUNT - 1 {
                                *selected += 1;

                                if *selected == 3 && *retention_policy != RetentionPolicyOption::Age
                                {
                                    *selected = 4;
                                }

                                if *selected == 7 && !*delete_on_empty_enabled {
                                    *selected = 8;
                                }
                            }
                        }
                        KeyCode::Enter => match *selected {
                            0 => {
                                *cursor = name.len();
                                *editing = true;
                            }
                            3 => {
                                if *retention_policy == RetentionPolicyOption::Age {
                                    *cursor = retention_age_input.len();
                                    *editing = true;
                                }
                            }
                            7 => {
                                if *delete_on_empty_enabled {
                                    *cursor = delete_on_empty_min_age.len();
                                    *editing = true;
                                }
                            }
                            8 => {
                                if !name.is_empty() {
                                    let basin_name = basin.clone();
                                    let stream_name = name.clone();
                                    let sc = storage_class.clone();
                                    let rp = *retention_policy;
                                    let rai = retention_age_input.clone();
                                    let tm = timestamping_mode.clone();
                                    let tu = *timestamping_uncapped;
                                    let doe = *delete_on_empty_enabled;
                                    let doema = delete_on_empty_min_age.clone();

                                    let config =
                                        build_stream_config(sc, rp, rai, tm, tu, doe, doema);
                                    self.create_stream_with_config(
                                        basin_name,
                                        stream_name,
                                        config,
                                        tx.clone(),
                                    );
                                }
                            }
                            _ => {}
                        },
                        KeyCode::Char(' ') => {
                            if *selected == 5 {
                                *timestamping_uncapped = !*timestamping_uncapped;
                            }
                        }
                        KeyCode::Left | KeyCode::Char('h') => match *selected {
                            1 => *storage_class = storage_class_prev(storage_class),
                            2 => *retention_policy = retention_policy.toggle(),
                            4 => *timestamping_mode = timestamping_mode_prev(timestamping_mode),
                            6 => *delete_on_empty_enabled = !*delete_on_empty_enabled,
                            _ => {}
                        },
                        KeyCode::Right | KeyCode::Char('l') => match *selected {
                            1 => *storage_class = storage_class_next(storage_class),
                            2 => *retention_policy = retention_policy.toggle(),
                            4 => *timestamping_mode = timestamping_mode_next(timestamping_mode),
                            6 => *delete_on_empty_enabled = !*delete_on_empty_enabled,
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }

            InputMode::ConfirmDeleteBasin { basin } => match key.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.input_mode = InputMode::Normal;
                }
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let basin = basin.clone();
                    self.delete_basin(basin, tx.clone());
                }
                _ => {}
            },

            InputMode::ConfirmDeleteStream { basin, stream } => match key.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.input_mode = InputMode::Normal;
                }
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let basin = basin.clone();
                    let stream = stream.clone();
                    self.delete_stream(basin, stream, tx.clone());
                }
                _ => {}
            },

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
                const BASIN_MAX_ROW: usize = 6;
                if *editing_age {
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            if let Ok(secs) = age_input.parse::<u64>() {
                                *retention_age_secs = secs;
                            }
                            *editing_age = false;
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            *cursor = (*cursor + 1).min(age_input.len());
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            *cursor = age_input.len();
                        }
                        KeyCode::Backspace => {
                            if *cursor > 0 {
                                age_input.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if *cursor < age_input.len() {
                                age_input.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) if c.is_ascii_digit() => {
                            age_input.insert(*cursor, c);
                            *cursor += 1;
                        }
                        _ => {}
                    }
                    return;
                }

                match key.code {
                    KeyCode::Esc => {
                        self.input_mode = InputMode::Normal;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if *selected > 0 {
                            *selected -= 1;

                            if *selected == 2 && *retention_policy != RetentionPolicyOption::Age {
                                *selected = 1;
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if *selected < BASIN_MAX_ROW {
                            *selected += 1;

                            if *selected == 2 && *retention_policy != RetentionPolicyOption::Age {
                                *selected = 3;
                            }
                        }
                    }
                    KeyCode::Char(' ') => match *selected {
                        4 => *timestamping_uncapped = Some(!timestamping_uncapped.unwrap_or(false)),
                        5 => {
                            *create_stream_on_append =
                                Some(!create_stream_on_append.unwrap_or(false))
                        }
                        6 => *create_stream_on_read = Some(!create_stream_on_read.unwrap_or(false)),
                        _ => {}
                    },
                    KeyCode::Enter => {
                        if *selected == 2 && *retention_policy == RetentionPolicyOption::Age {
                            *age_input = retention_age_secs.to_string();
                            *cursor = age_input.len();
                            *editing_age = true;
                        }
                    }
                    KeyCode::Left | KeyCode::Char('h') => match *selected {
                        0 => *storage_class = storage_class_prev(storage_class),
                        1 => *retention_policy = retention_policy.toggle(),
                        3 => *timestamping_mode = timestamping_mode_prev(timestamping_mode),
                        _ => {}
                    },
                    KeyCode::Right | KeyCode::Char('l') => match *selected {
                        0 => *storage_class = storage_class_next(storage_class),
                        1 => *retention_policy = retention_policy.toggle(),
                        3 => *timestamping_mode = timestamping_mode_next(timestamping_mode),
                        _ => {}
                    },
                    KeyCode::Char('s') => {
                        let b = basin.clone();
                        let config = BasinReconfigureConfig {
                            create_stream_on_append: *create_stream_on_append,
                            create_stream_on_read: *create_stream_on_read,
                            storage_class: storage_class.clone(),
                            retention_policy: *retention_policy,
                            retention_age_secs: *retention_age_secs,
                            timestamping_mode: timestamping_mode.clone(),
                            timestamping_uncapped: *timestamping_uncapped,
                        };
                        self.reconfigure_basin(b, config, tx.clone());
                    }
                    _ => {}
                }
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
            } => {
                if *editing_age {
                    let (field, digits_only): (&mut String, bool) = if *selected == 2 {
                        (age_input, true)
                    } else {
                        (delete_on_empty_min_age, false)
                    };
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            if *selected == 2
                                && let Ok(secs) = age_input.parse::<u64>()
                            {
                                *retention_age_secs = secs;
                            }
                            *editing_age = false;
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            *cursor = (*cursor + 1).min(field.len());
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            *cursor = field.len();
                        }
                        KeyCode::Backspace => {
                            if *cursor > 0 {
                                field.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if *cursor < field.len() {
                                field.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) => {
                            if !digits_only || c.is_ascii_digit() {
                                if *selected == 6 && !c.is_ascii_alphanumeric() {
                                    // delete_on_empty_min_age only accepts alphanumeric
                                } else {
                                    field.insert(*cursor, c);
                                    *cursor += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                    return;
                }
                const STREAM_MAX_ROW: usize = 6;

                match key.code {
                    KeyCode::Esc => {
                        self.input_mode = InputMode::Normal;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if *selected > 0 {
                            *selected -= 1;

                            if *selected == 6 && !*delete_on_empty_enabled {
                                *selected = 5;
                            }

                            if *selected == 2 && *retention_policy != RetentionPolicyOption::Age {
                                *selected = 1;
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if *selected < STREAM_MAX_ROW {
                            *selected += 1;

                            if *selected == 2 && *retention_policy != RetentionPolicyOption::Age {
                                *selected = 3;
                            }

                            if *selected == 6 && !*delete_on_empty_enabled {
                                *selected = 5;
                            }
                        }
                    }
                    KeyCode::Char(' ') => {
                        if *selected == 4 {
                            *timestamping_uncapped = Some(!timestamping_uncapped.unwrap_or(false));
                        }
                    }
                    KeyCode::Enter => {
                        if *selected == 2 && *retention_policy == RetentionPolicyOption::Age {
                            *age_input = retention_age_secs.to_string();
                            *cursor = age_input.len();
                            *editing_age = true;
                        } else if *selected == 6 && *delete_on_empty_enabled {
                            *cursor = delete_on_empty_min_age.len();
                            *editing_age = true;
                        }
                    }
                    KeyCode::Left | KeyCode::Char('h') => match *selected {
                        0 => *storage_class = storage_class_prev(storage_class),
                        1 => *retention_policy = retention_policy.toggle(),
                        3 => *timestamping_mode = timestamping_mode_prev(timestamping_mode),
                        5 => *delete_on_empty_enabled = !*delete_on_empty_enabled,
                        _ => {}
                    },
                    KeyCode::Right | KeyCode::Char('l') => match *selected {
                        0 => *storage_class = storage_class_next(storage_class),
                        1 => *retention_policy = retention_policy.toggle(),
                        3 => *timestamping_mode = timestamping_mode_next(timestamping_mode),
                        5 => *delete_on_empty_enabled = !*delete_on_empty_enabled,
                        _ => {}
                    },
                    KeyCode::Char('s') => {
                        let b = basin.clone();
                        let s = stream.clone();
                        let config = StreamReconfigureConfig {
                            storage_class: storage_class.clone(),
                            retention_policy: *retention_policy,
                            retention_age_secs: *retention_age_secs,
                            timestamping_mode: timestamping_mode.clone(),
                            timestamping_uncapped: *timestamping_uncapped,
                            delete_on_empty_enabled: *delete_on_empty_enabled,
                            delete_on_empty_min_age: delete_on_empty_min_age.clone(),
                        };
                        self.reconfigure_stream(b, s, config, tx.clone());
                    }
                    _ => {}
                }
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
                if *editing {
                    let field: Option<&mut String> = match *selected {
                        0 => Some(seq_num_value),
                        1 => Some(timestamp_value),
                        2 => Some(ago_value),
                        3 => Some(tail_offset_value),
                        4 => Some(count_limit),
                        5 => Some(byte_limit),
                        6 => Some(until_timestamp),
                        9 => Some(output_file),
                        _ => None,
                    };
                    let digits_only = *selected != 9;

                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            *editing = false;
                        }
                        KeyCode::Tab if *selected == 2 => {
                            *ago_unit = ago_unit.next();
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            if let Some(f) = field {
                                *cursor = (*cursor + 1).min(f.len());
                            }
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            if let Some(f) = field {
                                *cursor = f.len();
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(f) = field
                                && *cursor > 0
                            {
                                f.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if let Some(f) = field
                                && *cursor < f.len()
                            {
                                f.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) => {
                            if let Some(f) = field
                                && (!digits_only || c.is_ascii_digit())
                            {
                                f.insert(*cursor, c);
                                *cursor += 1;
                            }
                        }
                        _ => {}
                    }
                    return;
                }

                // Navigation layout:
                const MAX_ROW: usize = 10;

                match key.code {
                    KeyCode::Esc => {
                        self.input_mode = InputMode::Normal;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if *selected > 0 {
                            *selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if *selected < MAX_ROW {
                            *selected += 1;
                        }
                    }
                    KeyCode::Tab if *selected == 2 => {
                        // Cycle time unit for ago
                        *ago_unit = ago_unit.next();
                    }
                    KeyCode::Char(' ') => {
                        // Space = select/toggle
                        match *selected {
                            0 => *start_from = ReadStartFrom::SeqNum,
                            1 => *start_from = ReadStartFrom::Timestamp,
                            2 => *start_from = ReadStartFrom::Ago,
                            3 => *start_from = ReadStartFrom::TailOffset,
                            7 => *clamp = !*clamp,
                            8 => *format = format.next(),
                            _ => {}
                        }
                    }
                    KeyCode::Enter => {
                        // Enter = select + edit value, toggle, or run
                        match *selected {
                            0 => {
                                *start_from = ReadStartFrom::SeqNum;
                                *cursor = seq_num_value.len();
                                *editing = true;
                            }
                            1 => {
                                *start_from = ReadStartFrom::Timestamp;
                                *cursor = timestamp_value.len();
                                *editing = true;
                            }
                            2 => {
                                *start_from = ReadStartFrom::Ago;
                                *cursor = ago_value.len();
                                *editing = true;
                            }
                            3 => {
                                *start_from = ReadStartFrom::TailOffset;
                                *cursor = tail_offset_value.len();
                                *editing = true;
                            }
                            4 => {
                                *cursor = count_limit.len();
                                *editing = true;
                            }
                            5 => {
                                *cursor = byte_limit.len();
                                *editing = true;
                            }
                            6 => {
                                *cursor = until_timestamp.len();
                                *editing = true;
                            }
                            7 => *clamp = !*clamp,
                            8 => *format = format.next(),
                            9 => {
                                *cursor = output_file.len();
                                *editing = true;
                            }
                            10 => {
                                // Start reading - clone all values first
                                let b = basin.clone();
                                let s = stream.clone();
                                let sf = *start_from;
                                let snv = seq_num_value.clone();
                                let tsv = timestamp_value.clone();
                                let agv = ago_value.clone();
                                let agu = *ago_unit;
                                let tov = tail_offset_value.clone();
                                let cl = count_limit.clone();
                                let bl = byte_limit.clone();
                                let ut = until_timestamp.clone();
                                let clp = *clamp;
                                let fmt = *format;
                                let of = output_file.clone();
                                self.input_mode = InputMode::Normal;

                                if !of.is_empty() {
                                    self.message = Some(StatusMessage {
                                        text: format!("Writing to {}", of),
                                        level: MessageLevel::Info,
                                    });
                                }
                                self.start_custom_read(
                                    b,
                                    s,
                                    sf,
                                    snv,
                                    tsv,
                                    agv,
                                    agu,
                                    tov,
                                    cl,
                                    bl,
                                    ut,
                                    clp,
                                    fmt,
                                    of,
                                    tx.clone(),
                                );
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
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
                if *editing {
                    let field: &mut String = if *selected == 0 {
                        new_token
                    } else {
                        current_token
                    };
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            *editing = false;
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            *cursor = (*cursor + 1).min(field.len());
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            *cursor = field.len();
                        }
                        KeyCode::Backspace => {
                            if *cursor > 0 {
                                field.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if *cursor < field.len() {
                                field.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) => {
                            field.insert(*cursor, c);
                            *cursor += 1;
                        }
                        _ => {}
                    }
                    return;
                }

                // Navigation: 0=new_token, 1=current_token, 2=submit
                match key.code {
                    KeyCode::Esc => {
                        self.input_mode = InputMode::Normal;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if *selected > 0 {
                            *selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if *selected < 2 {
                            *selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        match *selected {
                            0 => {
                                *cursor = new_token.len();
                                *editing = true;
                            }
                            1 => {
                                *cursor = current_token.len();
                                *editing = true;
                            }
                            2 => {
                                // Submit fence
                                if !new_token.is_empty() {
                                    let b = basin.clone();
                                    let s = stream.clone();
                                    let nt = new_token.clone();
                                    let ct = if current_token.is_empty() {
                                        None
                                    } else {
                                        Some(current_token.clone())
                                    };
                                    self.fence_stream(b, s, nt, ct, tx.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
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
                if *editing {
                    let (field, digits_only): (&mut String, bool) = if *selected == 0 {
                        (trim_point, true)
                    } else {
                        (fencing_token, false)
                    };
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            *editing = false;
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            *cursor = (*cursor + 1).min(field.len());
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            *cursor = field.len();
                        }
                        KeyCode::Backspace => {
                            if *cursor > 0 {
                                field.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if *cursor < field.len() {
                                field.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) => {
                            if !digits_only || c.is_ascii_digit() {
                                field.insert(*cursor, c);
                                *cursor += 1;
                            }
                        }
                        _ => {}
                    }
                    return;
                }

                // Navigation: 0=trim_point, 1=fencing_token, 2=submit
                match key.code {
                    KeyCode::Esc => {
                        self.input_mode = InputMode::Normal;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if *selected > 0 {
                            *selected -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if *selected < 2 {
                            *selected += 1;
                        }
                    }
                    KeyCode::Enter => {
                        match *selected {
                            0 => {
                                *cursor = trim_point.len();
                                *editing = true;
                            }
                            1 => {
                                *cursor = fencing_token.len();
                                *editing = true;
                            }
                            2 => {
                                // Submit trim
                                if let Ok(tp) = trim_point.parse::<u64>() {
                                    let b = basin.clone();
                                    let s = stream.clone();
                                    let ft = if fencing_token.is_empty() {
                                        None
                                    } else {
                                        Some(fencing_token.clone())
                                    };
                                    self.trim_stream(b, s, tp, ft, tx.clone());
                                }
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
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
                // Fields: 0=id, 1=expiry, 2=expiry_custom, 3=basins_scope, 4=basins_value,
                //         5=streams_scope, 6=streams_value, 7=tokens_scope, 8=tokens_value,
                //         9=account_read, 10=account_write, 11=basin_read, 12=basin_write,
                //         13=stream_read, 14=stream_write, 15=auto_prefix, 16=submit
                const MAX_FIELD: usize = 16;

                if *editing {
                    let field: Option<&mut String> = match *selected {
                        0 => Some(id),
                        2 => Some(expiry_custom),
                        4 => Some(basins_value),
                        6 => Some(streams_value),
                        8 => Some(tokens_value),
                        _ => None,
                    };
                    match key.code {
                        KeyCode::Esc | KeyCode::Enter => {
                            *editing = false;
                        }
                        KeyCode::Left => {
                            *cursor = cursor.saturating_sub(1);
                        }
                        KeyCode::Right => {
                            if let Some(f) = field {
                                *cursor = (*cursor + 1).min(f.len());
                            }
                        }
                        KeyCode::Home => {
                            *cursor = 0;
                        }
                        KeyCode::End => {
                            if let Some(f) = field {
                                *cursor = f.len();
                            }
                        }
                        KeyCode::Backspace => {
                            if let Some(f) = field
                                && *cursor > 0
                            {
                                f.remove(*cursor - 1);
                                *cursor -= 1;
                            }
                        }
                        KeyCode::Delete => {
                            if let Some(f) = field
                                && *cursor < f.len()
                            {
                                f.remove(*cursor);
                            }
                        }
                        KeyCode::Char(c) => {
                            match *selected {
                                0 => {
                                    // Token ID: letters, numbers, hyphens, underscores
                                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                                        id.insert(*cursor, c);
                                        *cursor += 1;
                                    }
                                }
                                2 => {
                                    // Custom expiry: e.g., "30d", "1w", "24h"
                                    if c.is_ascii_alphanumeric() {
                                        expiry_custom.insert(*cursor, c);
                                        *cursor += 1;
                                    }
                                }
                                4 => {
                                    basins_value.insert(*cursor, c);
                                    *cursor += 1;
                                }
                                6 => {
                                    streams_value.insert(*cursor, c);
                                    *cursor += 1;
                                }
                                8 => {
                                    tokens_value.insert(*cursor, c);
                                    *cursor += 1;
                                }
                                _ => {}
                            }
                        }
                        _ => {}
                    }
                    return;
                }

                match key.code {
                    KeyCode::Esc => {
                        self.input_mode = InputMode::Normal;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        if *selected > 0 {
                            *selected -= 1;
                            // Skip value fields if scope doesn't need them
                            if *selected == 2 && *expiry != ExpiryOption::Custom {
                                *selected = 1;
                            }
                            if *selected == 4
                                && !matches!(basins_scope, ScopeOption::Prefix | ScopeOption::Exact)
                            {
                                *selected = 3;
                            }
                            if *selected == 6
                                && !matches!(
                                    streams_scope,
                                    ScopeOption::Prefix | ScopeOption::Exact
                                )
                            {
                                *selected = 5;
                            }
                            if *selected == 8
                                && !matches!(tokens_scope, ScopeOption::Prefix | ScopeOption::Exact)
                            {
                                *selected = 7;
                            }
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if *selected < MAX_FIELD {
                            *selected += 1;
                            // Skip value fields if scope doesn't need them
                            if *selected == 2 && *expiry != ExpiryOption::Custom {
                                *selected = 3;
                            }
                            if *selected == 4
                                && !matches!(basins_scope, ScopeOption::Prefix | ScopeOption::Exact)
                            {
                                *selected = 5;
                            }
                            if *selected == 6
                                && !matches!(
                                    streams_scope,
                                    ScopeOption::Prefix | ScopeOption::Exact
                                )
                            {
                                *selected = 7;
                            }
                            if *selected == 8
                                && !matches!(tokens_scope, ScopeOption::Prefix | ScopeOption::Exact)
                            {
                                *selected = 9;
                            }
                        }
                    }
                    KeyCode::Left | KeyCode::Right => {
                        let forward = key.code == KeyCode::Right;
                        match *selected {
                            1 => {
                                *expiry = if forward {
                                    expiry.next()
                                } else {
                                    expiry.prev()
                                }
                            }
                            3 => {
                                *basins_scope = if forward {
                                    basins_scope.next()
                                } else {
                                    basins_scope.prev()
                                }
                            }
                            5 => {
                                *streams_scope = if forward {
                                    streams_scope.next()
                                } else {
                                    streams_scope.prev()
                                }
                            }
                            7 => {
                                *tokens_scope = if forward {
                                    tokens_scope.next()
                                } else {
                                    tokens_scope.prev()
                                }
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Char(' ') | KeyCode::Enter => {
                        match *selected {
                            // Text inputs
                            0 => {
                                *cursor = id.len();
                                *editing = true;
                            }
                            2 => {
                                *cursor = expiry_custom.len();
                                *editing = true;
                            }
                            4 => {
                                *cursor = basins_value.len();
                                *editing = true;
                            }
                            6 => {
                                *cursor = streams_value.len();
                                *editing = true;
                            }
                            8 => {
                                *cursor = tokens_value.len();
                                *editing = true;
                            }
                            // Cycle options
                            1 => *expiry = expiry.next(),
                            3 => *basins_scope = basins_scope.next(),
                            5 => *streams_scope = streams_scope.next(),
                            7 => *tokens_scope = tokens_scope.next(),
                            // Toggle checkboxes
                            9 => *account_read = !*account_read,
                            10 => *account_write = !*account_write,
                            11 => *basin_read = !*basin_read,
                            12 => *basin_write = !*basin_write,
                            13 => *stream_read = !*stream_read,
                            14 => *stream_write = !*stream_write,
                            15 => *auto_prefix_streams = !*auto_prefix_streams,
                            // Submit case (16) is handled before the match to avoid borrow issues
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }

            InputMode::ConfirmRevokeToken { token_id } => match key.code {
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    self.input_mode = InputMode::Normal;
                }
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    let id = token_id.clone();
                    self.revoke_access_token(id, tx.clone());
                }
                _ => {}
            },

            InputMode::ShowIssuedToken { .. } => {
                // Any key dismisses the token display
                match key.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char(_) => {
                        self.input_mode = InputMode::Normal;
                    }
                    _ => {}
                }
            }

            InputMode::ViewTokenDetail { .. } => {
                // Esc or Enter to close detail view
                match key.code {
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                        self.input_mode = InputMode::Normal;
                    }
                    _ => {}
                }
            }
        }
    }

    fn handle_basins_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::Basins(state) = &mut self.screen else {
            return;
        };

        // Handle filter mode
        if state.filter_active {
            match key.code {
                KeyCode::Esc => {
                    state.filter_active = false;
                    state.filter.clear();
                    state.selected = 0;
                }
                KeyCode::Enter => {
                    state.filter_active = false;
                }
                KeyCode::Backspace => {
                    state.filter.pop();
                    state.selected = 0;
                }
                KeyCode::Char(c) => {
                    state.filter.push(c);
                    state.selected = 0;
                }
                _ => {}
            }
            return;
        }

        // Get filtered list info for bounds checking
        let filtered_len = state
            .basins
            .iter()
            .filter(|b| state.filter.is_empty() || b.name.to_string().contains(&state.filter))
            .count();
        let has_more = state.has_more;
        let loading_more = state.loading_more;
        let no_filter = state.filter.is_empty();
        let total_len = state.basins.len();
        let last_basin = state.basins.last().map(|b| b.name.clone());

        match key.code {
            KeyCode::Char('/') => {
                state.filter_active = true;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if state.selected > 0 {
                    state.selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if filtered_len > 0 && state.selected < filtered_len - 1 {
                    state.selected += 1;
                } else if no_filter
                    && has_more
                    && !loading_more
                    && state.selected == total_len.saturating_sub(1)
                    && let Some(last) = last_basin
                {
                    state.loading_more = true;
                    self.load_more_basins(last, tx);
                }
            }
            KeyCode::Char('g') => {
                state.selected = 0;
            }
            KeyCode::Char('G') => {
                if filtered_len > 0 {
                    state.selected = filtered_len - 1;
                }
                // Also trigger load more if at end
                if no_filter
                    && has_more
                    && !loading_more
                    && let Some(last) = last_basin
                {
                    state.loading_more = true;
                    self.load_more_basins(last, tx);
                }
            }
            KeyCode::Enter => {
                let filtered: Vec<_> = state
                    .basins
                    .iter()
                    .filter(|b| {
                        state.filter.is_empty() || b.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(basin) = filtered.get(state.selected) {
                    let basin_name = basin.name.clone();
                    self.screen = Screen::Streams(StreamsState {
                        basin_name: basin_name.clone(),
                        streams: Vec::new(),
                        selected: 0,
                        loading: true,
                        filter: String::new(),
                        filter_active: false,
                        has_more: false,
                        loading_more: false,
                    });
                    self.load_streams(basin_name, tx);
                }
            }
            KeyCode::Char('r') => {
                state.loading = true;
                state.filter.clear();
                state.selected = 0;
                self.load_basins(tx);
            }
            KeyCode::Char('c') => {
                self.input_mode = InputMode::CreateBasin {
                    name: String::new(),
                    scope: BasinScopeOption::AwsUsEast1,
                    create_stream_on_append: false,
                    create_stream_on_read: false,
                    storage_class: None,
                    retention_policy: RetentionPolicyOption::Infinite,
                    retention_age_input: "7d".to_string(),
                    timestamping_mode: None,
                    timestamping_uncapped: false,
                    delete_on_empty_enabled: false,
                    delete_on_empty_min_age: "7d".to_string(),
                    selected: 0,
                    editing: false,
                    cursor: 0,
                };
            }
            KeyCode::Char('d') => {
                let filtered: Vec<_> = state
                    .basins
                    .iter()
                    .filter(|b| {
                        state.filter.is_empty() || b.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(basin) = filtered.get(state.selected) {
                    if basin.state == BasinState::Deleting {
                        self.message = Some(StatusMessage {
                            text: "Basin is already being deleted".to_string(),
                            level: MessageLevel::Info,
                        });
                    } else {
                        self.input_mode = InputMode::ConfirmDeleteBasin {
                            basin: basin.name.clone(),
                        };
                    }
                }
            }
            KeyCode::Char('e') => {
                let filtered: Vec<_> = state
                    .basins
                    .iter()
                    .filter(|b| {
                        state.filter.is_empty() || b.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(basin) = filtered.get(state.selected) {
                    let basin_name = basin.name.clone();
                    self.input_mode = InputMode::ReconfigureBasin {
                        basin: basin_name.clone(),
                        create_stream_on_append: None,
                        create_stream_on_read: None,
                        storage_class: None,
                        retention_policy: RetentionPolicyOption::Infinite,
                        retention_age_secs: 604800, // 1 week default
                        timestamping_mode: None,
                        timestamping_uncapped: None,
                        selected: 0,
                        editing_age: false,
                        age_input: String::new(),
                        cursor: 0,
                    };
                    // Load current config
                    self.load_basin_config(basin_name, tx);
                }
            }
            KeyCode::Char('M') => {
                // Basin Metrics for selected basin
                let filtered: Vec<_> = state
                    .basins
                    .iter()
                    .filter(|b| {
                        state.filter.is_empty() || b.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(basin) = filtered.get(state.selected) {
                    let basin_name = basin.name.clone();
                    self.open_basin_metrics(basin_name, tx);
                }
            }
            KeyCode::Char('A') => {
                // Account Metrics
                self.open_account_metrics(tx);
            }
            KeyCode::Char('B') => {
                // Benchmark on selected basin
                let filtered: Vec<_> = state
                    .basins
                    .iter()
                    .filter(|b| {
                        state.filter.is_empty() || b.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(basin) = filtered.get(state.selected) {
                    let basin_name = basin.name.clone();
                    self.screen = Screen::BenchView(BenchViewState::new(basin_name));
                }
            }
            KeyCode::Esc => {
                if !state.filter.is_empty() {
                    state.filter.clear();
                    state.selected = 0;
                }
            }
            _ => {}
        }
    }

    fn handle_streams_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::Streams(state) = &mut self.screen else {
            return;
        };

        // Handle filter mode
        if state.filter_active {
            match key.code {
                KeyCode::Esc => {
                    state.filter_active = false;
                    state.filter.clear();
                    state.selected = 0;
                }
                KeyCode::Enter => {
                    state.filter_active = false;
                }
                KeyCode::Backspace => {
                    state.filter.pop();
                    state.selected = 0;
                }
                KeyCode::Char(c) => {
                    state.filter.push(c);
                    state.selected = 0;
                }
                _ => {}
            }
            return;
        }

        // Get filtered list info for bounds checking
        let filtered_len = state
            .streams
            .iter()
            .filter(|s| state.filter.is_empty() || s.name.to_string().contains(&state.filter))
            .count();
        let has_more = state.has_more;
        let loading_more = state.loading_more;
        let no_filter = state.filter.is_empty();
        let total_len = state.streams.len();
        let last_stream = state.streams.last().map(|s| s.name.clone());
        let basin_name = state.basin_name.clone();

        match key.code {
            KeyCode::Char('/') => {
                state.filter_active = true;
            }
            KeyCode::Esc => {
                if !state.filter.is_empty() {
                    state.filter.clear();
                    state.selected = 0;
                } else {
                    self.screen = Screen::Basins(BasinsState {
                        loading: true,
                        ..Default::default()
                    });
                    self.load_basins(tx);
                }
            }
            KeyCode::Char('q') => {
                self.screen = Screen::Basins(BasinsState {
                    loading: true,
                    ..Default::default()
                });
                self.load_basins(tx);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if state.selected > 0 {
                    state.selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if filtered_len > 0 && state.selected < filtered_len - 1 {
                    state.selected += 1;
                } else if no_filter
                    && has_more
                    && !loading_more
                    && state.selected == total_len.saturating_sub(1)
                    && let Some(last) = last_stream
                {
                    state.loading_more = true;
                    self.load_more_streams(basin_name, last, tx);
                }
            }
            KeyCode::Char('g') => {
                state.selected = 0;
            }
            KeyCode::Char('G') => {
                if filtered_len > 0 {
                    state.selected = filtered_len - 1;
                }
                if no_filter
                    && has_more
                    && !loading_more
                    && let Some(last) = last_stream
                {
                    state.loading_more = true;
                    self.load_more_streams(basin_name, last, tx);
                }
            }
            KeyCode::Enter => {
                let filtered: Vec<_> = state
                    .streams
                    .iter()
                    .filter(|s| {
                        state.filter.is_empty() || s.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(stream) = filtered.get(state.selected) {
                    let stream_name = stream.name.clone();
                    let basin_name = state.basin_name.clone();
                    self.screen = Screen::StreamDetail(StreamDetailState {
                        basin_name: basin_name.clone(),
                        stream_name: stream_name.clone(),
                        config: None,
                        tail_position: None,
                        selected_action: 0,
                        loading: true,
                    });
                    self.load_stream_detail(basin_name, stream_name, tx);
                }
            }
            KeyCode::Char('r') => {
                let basin_name = state.basin_name.clone();
                state.loading = true;
                state.filter.clear();
                state.selected = 0;
                self.load_streams(basin_name, tx);
            }
            KeyCode::Char('c') => {
                self.input_mode = InputMode::CreateStream {
                    basin: state.basin_name.clone(),
                    name: String::new(),
                    storage_class: None,
                    retention_policy: RetentionPolicyOption::Infinite,
                    retention_age_input: "7d".to_string(),
                    timestamping_mode: None,
                    timestamping_uncapped: false,
                    delete_on_empty_enabled: false,
                    delete_on_empty_min_age: "7d".to_string(),
                    selected: 0,
                    editing: false,
                    cursor: 0,
                };
            }
            KeyCode::Char('d') => {
                let filtered: Vec<_> = state
                    .streams
                    .iter()
                    .filter(|s| {
                        state.filter.is_empty() || s.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(stream) = filtered.get(state.selected) {
                    if stream.deleted_at.is_some() {
                        self.message = Some(StatusMessage {
                            text: "Stream is already being deleted".to_string(),
                            level: MessageLevel::Info,
                        });
                    } else {
                        self.input_mode = InputMode::ConfirmDeleteStream {
                            basin: state.basin_name.clone(),
                            stream: stream.name.clone(),
                        };
                    }
                }
            }
            KeyCode::Char('e') => {
                let filtered: Vec<_> = state
                    .streams
                    .iter()
                    .filter(|s| {
                        state.filter.is_empty() || s.name.to_string().contains(&state.filter)
                    })
                    .collect();
                if let Some(stream) = filtered.get(state.selected) {
                    let basin_name = state.basin_name.clone();
                    let stream_name = stream.name.clone();
                    self.input_mode = InputMode::ReconfigureStream {
                        basin: basin_name.clone(),
                        stream: stream_name.clone(),
                        storage_class: None,
                        retention_policy: RetentionPolicyOption::Infinite,
                        retention_age_secs: 604800,
                        timestamping_mode: None,
                        timestamping_uncapped: None,
                        delete_on_empty_enabled: false,
                        delete_on_empty_min_age: "7d".to_string(),
                        selected: 0,
                        editing_age: false,
                        age_input: String::new(),
                        cursor: 0,
                    };
                    // Load current config
                    self.load_stream_config_for_reconfig(basin_name, stream_name, tx);
                }
            }
            KeyCode::Char('M') => {
                // Basin Metrics
                let basin_name = state.basin_name.clone();
                self.open_basin_metrics(basin_name, tx);
            }
            _ => {}
        }
    }

    fn handle_stream_detail_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::StreamDetail(state) = &mut self.screen else {
            return;
        };

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                let basin_name = state.basin_name.clone();
                self.screen = Screen::Streams(StreamsState {
                    basin_name: basin_name.clone(),
                    streams: Vec::new(),
                    selected: 0,
                    loading: true,
                    filter: String::new(),
                    filter_active: false,
                    has_more: false,
                    loading_more: false,
                });
                self.load_streams(basin_name, tx);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if state.selected_action > 0 {
                    state.selected_action -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if state.selected_action < 4 {
                    // 5 actions: tail, custom read, append, fence, trim
                    state.selected_action += 1;
                }
            }
            KeyCode::Enter => {
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                match state.selected_action {
                    0 => self.start_tail(basin_name, stream_name, tx), // Tail
                    1 => self.open_custom_read_dialog(basin_name, stream_name), // Custom read
                    2 => self.open_append_view(basin_name, stream_name), // Append
                    3 => self.open_fence_dialog(basin_name, stream_name), // Fence
                    4 => self.open_trim_dialog(basin_name, stream_name), // Trim
                    _ => {}
                }
            }
            KeyCode::Char('t') => {
                // Simple tail - s2 read with no flags (live follow from current position)
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.start_tail(basin_name, stream_name, tx);
            }
            KeyCode::Char('r') => {
                // Custom read - open configuration dialog
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.open_custom_read_dialog(basin_name, stream_name);
            }
            KeyCode::Char('a') => {
                // Append records
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.open_append_view(basin_name, stream_name);
            }
            KeyCode::Char('e') => {
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.input_mode = InputMode::ReconfigureStream {
                    basin: basin_name.clone(),
                    stream: stream_name.clone(),
                    storage_class: None,
                    retention_policy: RetentionPolicyOption::Infinite,
                    retention_age_secs: 604800,
                    timestamping_mode: None,
                    timestamping_uncapped: None,
                    delete_on_empty_enabled: false,
                    delete_on_empty_min_age: "7d".to_string(),
                    selected: 0,
                    editing_age: false,
                    age_input: String::new(),
                    cursor: 0,
                };
                self.load_stream_config_for_reconfig(basin_name, stream_name, tx);
            }
            KeyCode::Char('f') => {
                // Fence stream
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.open_fence_dialog(basin_name, stream_name);
            }
            KeyCode::Char('m') => {
                // Trim stream
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.open_trim_dialog(basin_name, stream_name);
            }
            KeyCode::Char('M') => {
                // Stream Metrics
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.open_stream_metrics(basin_name, stream_name, tx);
            }
            KeyCode::Char('p') => {
                // Pin stream to PiP (picture-in-picture) - start tailing in background
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.start_pip(basin_name, stream_name, tx);
                self.message = Some(StatusMessage {
                    text: "Stream pinned to PiP".to_string(),
                    level: MessageLevel::Success,
                });
            }
            _ => {}
        }
    }

    fn handle_read_view_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::ReadView(state) = &mut self.screen else {
            return;
        };

        // If showing detail panel, handle differently
        if state.show_detail {
            match key.code {
                KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') => {
                    state.show_detail = false;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                // Go back to stream detail and reload data
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.screen = Screen::StreamDetail(StreamDetailState {
                    basin_name: basin_name.clone(),
                    stream_name: stream_name.clone(),
                    config: None,
                    tail_position: None,
                    selected_action: 0,
                    loading: true,
                });
                self.load_stream_detail(basin_name, stream_name, tx);
            }
            KeyCode::Char(' ') => {
                state.paused = !state.paused;
                self.message = Some(StatusMessage {
                    text: if state.paused {
                        "Paused".to_string()
                    } else {
                        "Resumed".to_string()
                    },
                    level: MessageLevel::Info,
                });
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if state.selected > 0 {
                    state.selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let max_idx = state.records.len().saturating_sub(1);
                if state.selected < max_idx {
                    state.selected += 1;
                }
            }
            KeyCode::Char('g') => {
                state.selected = 0;
            }
            KeyCode::Char('G') => {
                state.selected = state.records.len().saturating_sub(1);
            }
            KeyCode::Tab | KeyCode::Char('l') => {
                // Toggle list pane visibility
                state.hide_list = !state.hide_list;
            }
            KeyCode::Enter | KeyCode::Char('h') => {
                if !state.records.is_empty() {
                    state.show_detail = true;
                }
            }
            KeyCode::Char('T') => {
                // Toggle timeline scrubber
                state.show_timeline = !state.show_timeline;
            }
            KeyCode::Char('[') => {
                // Jump backward by 10% of records
                let jump = (state.records.len() / 10).max(1);
                state.selected = state.selected.saturating_sub(jump);
            }
            KeyCode::Char(']') => {
                // Jump forward by 10% of records
                let jump = (state.records.len() / 10).max(1);
                let max_idx = state.records.len().saturating_sub(1);
                state.selected = (state.selected + jump).min(max_idx);
            }
            KeyCode::Char('p') => {
                // Pin current stream to PiP (picture-in-picture)
                if state.is_tailing {
                    let basin_name = state.basin_name.clone();
                    let stream_name = state.stream_name.clone();
                    self.start_pip(basin_name, stream_name, tx);
                    self.message = Some(StatusMessage {
                        text: "Stream pinned to PiP".to_string(),
                        level: MessageLevel::Info,
                    });
                } else {
                    self.message = Some(StatusMessage {
                        text: "PiP only available when tailing".to_string(),
                        level: MessageLevel::Info,
                    });
                }
            }
            _ => {}
        }
    }

    fn load_basins(&self, tx: mpsc::UnboundedSender<Event>) {
        Self::load_basins_page(self.s2.clone(), None, tx, false);
    }

    fn load_more_basins(&self, start_after: BasinName, tx: mpsc::UnboundedSender<Event>) {
        Self::load_basins_page(self.s2.clone(), Some(start_after), tx, true);
    }

    fn load_basins_page(
        s2: Option<s2_sdk::S2>,
        start_after: Option<BasinName>,
        tx: mpsc::UnboundedSender<Event>,
        is_more: bool,
    ) {
        let Some(s2) = s2 else {
            let _ = tx.send(Event::BasinsLoaded(Err(CliError::Config(
                crate::error::CliConfigError::MissingAccessToken,
            ))));
            return;
        };
        tokio::spawn(async move {
            let args = ListBasinsArgs {
                prefix: None,
                start_after: start_after.map(|n| n.to_string().parse().unwrap()),
                limit: Some(100),
                no_auto_paginate: true,
            };
            let event = match ops::list_basins(&s2, args).await {
                Ok((basins, has_more)) => {
                    if is_more {
                        Event::MoreBasinsLoaded(Ok((basins, has_more)))
                    } else {
                        Event::BasinsLoaded(Ok((basins, has_more)))
                    }
                }
                Err(e) => {
                    if is_more {
                        Event::MoreBasinsLoaded(Err(e))
                    } else {
                        Event::BasinsLoaded(Err(e))
                    }
                }
            };
            let _ = tx.send(event);
        });
    }

    fn load_streams(&self, basin_name: BasinName, tx: mpsc::UnboundedSender<Event>) {
        Self::load_streams_page(self.s2.clone(), basin_name, None, tx, false);
    }

    fn load_more_streams(
        &self,
        basin_name: BasinName,
        start_after: StreamName,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        Self::load_streams_page(self.s2.clone(), basin_name, Some(start_after), tx, true);
    }

    fn load_streams_page(
        s2: Option<s2_sdk::S2>,
        basin_name: BasinName,
        start_after: Option<StreamName>,
        tx: mpsc::UnboundedSender<Event>,
        is_more: bool,
    ) {
        let Some(s2) = s2 else {
            let _ = tx.send(Event::StreamsLoaded(Err(CliError::Config(
                crate::error::CliConfigError::MissingAccessToken,
            ))));
            return;
        };
        tokio::spawn(async move {
            let args = ListStreamsArgs {
                uri: S2BasinAndMaybeStreamUri {
                    basin: basin_name,
                    stream: None,
                },
                prefix: None,
                start_after: start_after.map(|n| n.to_string().parse().unwrap()),
                limit: Some(100),
                no_auto_paginate: true,
            };
            let event = match ops::list_streams(&s2, args).await {
                Ok((streams, has_more)) => {
                    if is_more {
                        Event::MoreStreamsLoaded(Ok((streams, has_more)))
                    } else {
                        Event::StreamsLoaded(Ok((streams, has_more)))
                    }
                }
                Err(e) => {
                    if is_more {
                        Event::MoreStreamsLoaded(Err(e))
                    } else {
                        Event::StreamsLoaded(Err(e))
                    }
                }
            };
            let _ = tx.send(event);
        });
    }

    fn load_stream_detail(
        &self,
        basin_name: BasinName,
        stream_name: StreamName,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let uri = S2BasinAndStreamUri {
            basin: basin_name.clone(),
            stream: stream_name.clone(),
        };

        // Load config
        let tx_config = tx.clone();
        let uri_config = uri.clone();
        let s2_config = s2.clone();
        tokio::spawn(async move {
            match ops::get_stream_config(&s2_config, uri_config).await {
                Ok(config) => {
                    let _ = tx_config.send(Event::StreamConfigLoaded(Ok(config.into())));
                }
                Err(e) => {
                    let _ = tx_config.send(Event::StreamConfigLoaded(Err(e)));
                }
            }
        });

        // Load tail position
        let tx_tail = tx;
        tokio::spawn(async move {
            match ops::check_tail(&s2, uri).await {
                Ok(pos) => {
                    let _ = tx_tail.send(Event::TailPositionLoaded(Ok(pos)));
                }
                Err(e) => {
                    let _ = tx_tail.send(Event::TailPositionLoaded(Err(e)));
                }
            }
        });
    }

    fn create_basin_with_config(
        &mut self,
        name: String,
        scope: BasinScopeOption,
        config: BasinConfig,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        self.input_mode = InputMode::Normal;
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let tx_refresh = tx.clone();
        tokio::spawn(async move {
            let basin_name: BasinName = match name.parse() {
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.send(Event::BasinCreated(Err(CliError::RecordWrite(format!(
                        "Invalid basin name: {e}"
                    )))));
                    return;
                }
            };
            let sdk_scope = match scope {
                BasinScopeOption::AwsUsEast1 => s2_sdk::types::BasinScope::AwsUsEast1,
            };
            let input = s2_sdk::types::CreateBasinInput::new(basin_name)
                .with_config(config.into())
                .with_scope(sdk_scope);

            match s2
                .create_basin(input)
                .await
                .map_err(|e| CliError::op(crate::error::OpKind::CreateBasin, e))
            {
                Ok(info) => {
                    let _ = tx.send(Event::BasinCreated(Ok(info)));
                    // Trigger refresh
                    let args = ListBasinsArgs {
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: true,
                    };
                    if let Ok((basins, has_more)) = ops::list_basins(&s2, args).await {
                        let _ = tx_refresh.send(Event::BasinsLoaded(Ok((basins, has_more))));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::BasinCreated(Err(e)));
                }
            }
        });
    }

    fn delete_basin(&mut self, basin: BasinName, tx: mpsc::UnboundedSender<Event>) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let tx_refresh = tx.clone();
        let name = basin.to_string();
        tokio::spawn(async move {
            match ops::delete_basin(&s2, &basin).await {
                Ok(()) => {
                    let _ = tx.send(Event::BasinDeleted(Ok(name)));
                    // Trigger refresh
                    let args = ListBasinsArgs {
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: true,
                    };
                    if let Ok((basins, has_more)) = ops::list_basins(&s2, args).await {
                        let _ = tx_refresh.send(Event::BasinsLoaded(Ok((basins, has_more))));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::BasinDeleted(Err(e)));
                }
            }
        });
    }

    fn create_stream_with_config(
        &mut self,
        basin: BasinName,
        name: String,
        config: StreamConfig,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        self.input_mode = InputMode::Normal;
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let tx_refresh = tx.clone();
        let basin_clone = basin.clone();
        tokio::spawn(async move {
            let stream_name: StreamName = match name.parse() {
                Ok(n) => n,
                Err(e) => {
                    let _ = tx.send(Event::StreamCreated(Err(CliError::RecordWrite(format!(
                        "Invalid stream name: {e}"
                    )))));
                    return;
                }
            };
            let args = CreateStreamArgs {
                uri: S2BasinAndStreamUri {
                    basin: basin.clone(),
                    stream: stream_name,
                },
                config,
            };
            match ops::create_stream(&s2, args).await {
                Ok(info) => {
                    let _ = tx.send(Event::StreamCreated(Ok(info)));
                    // Trigger refresh
                    let args = ListStreamsArgs {
                        uri: S2BasinAndMaybeStreamUri {
                            basin: basin_clone,
                            stream: None,
                        },
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: true,
                    };
                    if let Ok((streams, has_more)) = ops::list_streams(&s2, args).await {
                        let _ = tx_refresh.send(Event::StreamsLoaded(Ok((streams, has_more))));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::StreamCreated(Err(e)));
                }
            }
        });
    }

    fn delete_stream(
        &mut self,
        basin: BasinName,
        stream: StreamName,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let tx_refresh = tx.clone();
        let name = stream.to_string();
        let basin_clone = basin.clone();
        tokio::spawn(async move {
            let uri = S2BasinAndStreamUri {
                basin: basin.clone(),
                stream,
            };
            match ops::delete_stream(&s2, uri).await {
                Ok(()) => {
                    let _ = tx.send(Event::StreamDeleted(Ok(name)));
                    // Trigger refresh
                    let args = ListStreamsArgs {
                        uri: S2BasinAndMaybeStreamUri {
                            basin: basin_clone,
                            stream: None,
                        },
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: true,
                    };
                    if let Ok((streams, has_more)) = ops::list_streams(&s2, args).await {
                        let _ = tx_refresh.send(Event::StreamsLoaded(Ok((streams, has_more))));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::StreamDeleted(Err(e)));
                }
            }
        });
    }

    /// Simple tail - like `s2 read` with no flags (live follow from current position)
    fn start_tail(
        &mut self,
        basin_name: BasinName,
        stream_name: StreamName,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        self.screen = Screen::ReadView(ReadViewState {
            basin_name: basin_name.clone(),
            stream_name: stream_name.clone(),
            records: VecDeque::new(),
            is_tailing: true,
            selected: 0,
            paused: false,
            loading: true,
            show_detail: false,
            hide_list: false,
            output_file: None,
            throughput_history: VecDeque::new(),
            records_per_sec_history: VecDeque::new(),
            current_mibps: 0.0,
            current_recps: 0.0,
            bytes_this_second: 0,
            records_this_second: 0,
            last_tick: Some(std::time::Instant::now()),
            show_timeline: false,
        });

        let s2 = self.s2.clone().expect("S2 client not initialized");
        let uri = S2BasinAndStreamUri {
            basin: basin_name,
            stream: stream_name,
        };

        tokio::spawn(async move {
            // Simple tail: no flags = TailOffset(0) = start at current tail, wait for new records
            let args = ReadArgs {
                uri,
                seq_num: None,
                timestamp: None,
                ago: None,
                tail_offset: None, // Defaults to TailOffset(0) in ops::read
                count: None,
                bytes: None,
                clamp: true,
                until: None,
                format: RecordFormat::default(),
                output: RecordsOut::Stdout,
            };

            match ops::read(&s2, &args).await {
                Ok(mut batch_stream) => {
                    use futures::StreamExt;
                    while let Some(batch_result) = batch_stream.next().await {
                        match batch_result {
                            Ok(batch) => {
                                for record in batch.records {
                                    if tx.send(Event::RecordReceived(Ok(record))).is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Event::RecordReceived(Err(
                                    crate::error::CliError::op(crate::error::OpKind::Read, e),
                                )));
                                return;
                            }
                        }
                    }
                    let _ = tx.send(Event::ReadEnded);
                }
                Err(e) => {
                    let _ = tx.send(Event::Error(e));
                }
            }
        });
    }

    /// Start a picture-in-picture tail for a stream
    fn start_pip(
        &mut self,
        basin_name: BasinName,
        stream_name: StreamName,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        // Initialize PiP state
        self.pip = Some(PipState {
            basin_name: basin_name.clone(),
            stream_name: stream_name.clone(),
            records: VecDeque::new(),
            paused: false,
            minimized: false,
            current_mibps: 0.0,
            current_recps: 0.0,
            bytes_this_second: 0,
            records_this_second: 0,
            last_tick: Some(std::time::Instant::now()),
        });

        let s2 = self.s2.clone().expect("S2 client not initialized");
        let uri = S2BasinAndStreamUri {
            basin: basin_name,
            stream: stream_name,
        };

        tokio::spawn(async move {
            // Simple tail for PiP: start at current tail, wait for new records
            let args = ReadArgs {
                uri,
                seq_num: None,
                timestamp: None,
                ago: None,
                tail_offset: None,
                count: None,
                bytes: None,
                clamp: true,
                until: None,
                format: RecordFormat::default(),
                output: RecordsOut::Stdout,
            };

            match ops::read(&s2, &args).await {
                Ok(mut batch_stream) => {
                    use futures::StreamExt;
                    while let Some(batch_result) = batch_stream.next().await {
                        match batch_result {
                            Ok(batch) => {
                                for record in batch.records {
                                    if tx.send(Event::PipRecordReceived(Ok(record))).is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Event::PipRecordReceived(Err(
                                    crate::error::CliError::op(crate::error::OpKind::Read, e),
                                )));
                                return;
                            }
                        }
                    }
                    let _ = tx.send(Event::PipReadEnded);
                }
                Err(e) => {
                    let _ = tx.send(Event::Error(e));
                }
            }
        });
    }

    /// Open custom read configuration dialog
    fn open_custom_read_dialog(&mut self, basin: BasinName, stream: StreamName) {
        self.input_mode = InputMode::CustomRead {
            basin,
            stream,
            start_from: ReadStartFrom::SeqNum, // Default to reading from beginning
            seq_num_value: "0".to_string(),
            timestamp_value: String::new(),
            ago_value: "5".to_string(),
            ago_unit: AgoUnit::Minutes,
            tail_offset_value: "10".to_string(),
            count_limit: String::new(),
            byte_limit: String::new(),
            until_timestamp: String::new(),
            clamp: true,
            format: ReadFormat::Text,
            output_file: String::new(),
            selected: 0,
            editing: false,
            cursor: 0,
        };
    }

    /// Start reading with custom configuration
    #[allow(clippy::too_many_arguments)]
    fn start_custom_read(
        &mut self,
        basin_name: BasinName,
        stream_name: StreamName,
        start_from: ReadStartFrom,
        seq_num_value: String,
        timestamp_value: String,
        ago_value: String,
        ago_unit: AgoUnit,
        tail_offset_value: String,
        count_limit: String,
        byte_limit: String,
        until_timestamp: String,
        clamp: bool,
        format: ReadFormat,
        output_file: String,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let has_output = !output_file.is_empty();
        self.screen = Screen::ReadView(ReadViewState {
            basin_name: basin_name.clone(),
            stream_name: stream_name.clone(),
            records: VecDeque::new(),
            is_tailing: true,
            selected: 0,
            paused: false,
            loading: true,
            show_detail: false,
            hide_list: false,
            output_file: if has_output {
                Some(output_file.clone())
            } else {
                None
            },
            throughput_history: VecDeque::new(),
            records_per_sec_history: VecDeque::new(),
            current_mibps: 0.0,
            current_recps: 0.0,
            bytes_this_second: 0,
            records_this_second: 0,
            last_tick: Some(std::time::Instant::now()),
            show_timeline: false,
        });

        let s2 = self.s2.clone().expect("S2 client not initialized");
        let uri = S2BasinAndStreamUri {
            basin: basin_name,
            stream: stream_name,
        };

        tokio::spawn(async move {
            let seq_num = if start_from == ReadStartFrom::SeqNum {
                seq_num_value.parse().ok()
            } else {
                None
            };

            let timestamp = if start_from == ReadStartFrom::Timestamp {
                timestamp_value.parse().ok()
            } else {
                None
            };

            let ago = if start_from == ReadStartFrom::Ago {
                ago_value.parse::<u64>().ok().map(|v| {
                    let secs = ago_unit.as_seconds(v);
                    humantime::Duration::from(std::time::Duration::from_secs(secs))
                })
            } else {
                None
            };

            let tail_offset = if start_from == ReadStartFrom::TailOffset {
                tail_offset_value.parse().ok()
            } else {
                None
            };

            let count = count_limit.parse().ok().filter(|&v| v > 0);
            let bytes = byte_limit.parse().ok().filter(|&v| v > 0);
            let until = until_timestamp.parse().ok().filter(|&v| v > 0);

            let record_format = match format {
                ReadFormat::Text => RecordFormat::Text,
                ReadFormat::Json => RecordFormat::Json,
                ReadFormat::JsonBase64 => RecordFormat::JsonBase64,
            };

            // Set up output file if specified
            let output = if output_file.is_empty() {
                RecordsOut::Stdout
            } else {
                RecordsOut::File(std::path::PathBuf::from(&output_file))
            };

            let args = ReadArgs {
                uri,
                seq_num,
                timestamp,
                ago,
                tail_offset,
                count,
                bytes,
                clamp,
                until,
                format: record_format,
                output: output.clone(),
            };

            // Open file writer if output file is specified
            let mut file_writer: Option<tokio::fs::File> = if !output_file.is_empty() {
                match tokio::fs::File::create(&output_file).await {
                    Ok(f) => Some(f),
                    Err(e) => {
                        let _ = tx.send(Event::Error(crate::error::CliError::RecordWrite(
                            e.to_string(),
                        )));
                        return;
                    }
                }
            } else {
                None
            };

            match ops::read(&s2, &args).await {
                Ok(mut batch_stream) => {
                    use futures::StreamExt;
                    use tokio::io::AsyncWriteExt;
                    while let Some(batch_result) = batch_stream.next().await {
                        match batch_result {
                            Ok(batch) => {
                                for record in batch.records {
                                    // Write to file if specified
                                    if let Some(ref mut writer) = file_writer {
                                        let line = match record_format {
                                            RecordFormat::Text => {
                                                format!(
                                                    "{}\n",
                                                    String::from_utf8_lossy(&record.body)
                                                )
                                            }
                                            RecordFormat::Json => {
                                                format!(
                                                    "{}\n",
                                                    serde_json::json!({
                                                        "seq_num": record.seq_num,
                                                        "timestamp": record.timestamp,
                                                        "headers": record.headers.iter().map(|h| {
                                                            serde_json::json!({
                                                                "name": String::from_utf8_lossy(&h.name),
                                                                "value": String::from_utf8_lossy(&h.value)
                                                            })
                                                        }).collect::<Vec<_>>(),
                                                        "body": String::from_utf8_lossy(&record.body).to_string()
                                                    })
                                                )
                                            }
                                            RecordFormat::JsonBase64 => {
                                                format!(
                                                    "{}\n",
                                                    serde_json::json!({
                                                        "seq_num": record.seq_num,
                                                        "timestamp": record.timestamp,
                                                        "headers": record.headers.iter().map(|h| {
                                                            serde_json::json!({
                                                                "name": String::from_utf8_lossy(&h.name),
                                                                "value": String::from_utf8_lossy(&h.value)
                                                            })
                                                        }).collect::<Vec<_>>(),
                                                        "body": base64ct::Base64::encode_string(&record.body)
                                                    })
                                                )
                                            }
                                        };
                                        let _ = writer.write_all(line.as_bytes()).await;
                                    }

                                    if tx.send(Event::RecordReceived(Ok(record))).is_err() {
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Event::RecordReceived(Err(
                                    crate::error::CliError::op(crate::error::OpKind::Read, e),
                                )));
                                return;
                            }
                        }
                    }
                    let _ = tx.send(Event::ReadEnded);
                }
                Err(e) => {
                    let _ = tx.send(Event::Error(e));
                }
            }
        });
    }

    fn load_basin_config(&self, basin: BasinName, tx: mpsc::UnboundedSender<Event>) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        tokio::spawn(async move {
            match ops::get_basin_config(&s2, &basin).await {
                Ok(config) => {
                    // Extract default stream config info
                    let (
                        storage_class,
                        retention_age_secs,
                        timestamping_mode,
                        timestamping_uncapped,
                    ) = if let Some(default_config) = &config.default_stream_config {
                        let sc = default_config.storage_class.map(StorageClass::from);
                        let age = match default_config.retention_policy {
                            Some(s2_sdk::types::RetentionPolicy::Age(secs)) => Some(secs),
                            _ => None,
                        };
                        let ts_mode = default_config
                            .timestamping
                            .as_ref()
                            .and_then(|t| t.mode.map(TimestampingMode::from));
                        let ts_uncapped = default_config
                            .timestamping
                            .as_ref()
                            .map(|t| t.uncapped)
                            .unwrap_or(false);
                        (sc, age, ts_mode, ts_uncapped)
                    } else {
                        (None, None, None, false)
                    };

                    let info = BasinConfigInfo {
                        create_stream_on_append: config.create_stream_on_append,
                        create_stream_on_read: config.create_stream_on_read,
                        storage_class,
                        retention_age_secs,
                        timestamping_mode,
                        timestamping_uncapped,
                    };
                    let _ = tx.send(Event::BasinConfigLoaded(Ok(info)));
                }
                Err(e) => {
                    let _ = tx.send(Event::BasinConfigLoaded(Err(e)));
                }
            }
        });
    }

    fn load_stream_config_for_reconfig(
        &self,
        basin: BasinName,
        stream: StreamName,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let uri = S2BasinAndStreamUri { basin, stream };
        tokio::spawn(async move {
            match ops::get_stream_config(&s2, uri).await {
                Ok(config) => {
                    let storage_class = config.storage_class.map(StorageClass::from);
                    let retention_age_secs = match config.retention_policy {
                        Some(s2_sdk::types::RetentionPolicy::Age(secs)) => Some(secs),
                        _ => None,
                    };
                    let timestamping_mode = config
                        .timestamping
                        .as_ref()
                        .and_then(|t| t.mode.map(TimestampingMode::from));
                    let timestamping_uncapped = config
                        .timestamping
                        .as_ref()
                        .map(|t| t.uncapped)
                        .unwrap_or(false);
                    let delete_on_empty_min_age_secs =
                        config.delete_on_empty.map(|d| d.min_age_secs);

                    let info = StreamConfigInfo {
                        storage_class,
                        retention_age_secs,
                        timestamping_mode,
                        timestamping_uncapped,
                        delete_on_empty_min_age_secs,
                    };
                    let _ = tx.send(Event::StreamConfigForReconfigLoaded(Ok(info)));
                }
                Err(e) => {
                    let _ = tx.send(Event::StreamConfigForReconfigLoaded(Err(e)));
                }
            }
        });
    }

    fn reconfigure_basin(
        &mut self,
        basin: BasinName,
        config: BasinReconfigureConfig,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let tx_refresh = tx.clone();
        tokio::spawn(async move {
            let retention_policy = match config.retention_policy {
                RetentionPolicyOption::Infinite => Some(crate::types::RetentionPolicy::Infinite),
                RetentionPolicyOption::Age => Some(crate::types::RetentionPolicy::Age(
                    Duration::from_secs(config.retention_age_secs),
                )),
            };

            let timestamping =
                if config.timestamping_mode.is_some() || config.timestamping_uncapped.is_some() {
                    Some(crate::types::TimestampingConfig {
                        timestamping_mode: config.timestamping_mode,
                        timestamping_uncapped: config.timestamping_uncapped,
                    })
                } else {
                    None
                };

            let default_stream_config = StreamConfig {
                storage_class: config.storage_class,
                retention_policy,
                timestamping,
                delete_on_empty: None,
            };

            let args = ReconfigureBasinArgs {
                basin: S2BasinUri(basin),
                create_stream_on_append: config.create_stream_on_append,
                create_stream_on_read: config.create_stream_on_read,
                default_stream_config,
            };
            match ops::reconfigure_basin(&s2, args).await {
                Ok(_) => {
                    let _ = tx.send(Event::BasinReconfigured(Ok(())));
                    // Trigger refresh
                    let args = ListBasinsArgs {
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: true,
                    };
                    if let Ok((basins, has_more)) = ops::list_basins(&s2, args).await {
                        let _ = tx_refresh.send(Event::BasinsLoaded(Ok((basins, has_more))));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::BasinReconfigured(Err(e)));
                }
            }
        });
    }

    fn reconfigure_stream(
        &mut self,
        basin: BasinName,
        stream: StreamName,
        config: StreamReconfigureConfig,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let basin_clone = basin.clone();
        let tx_refresh = tx.clone();
        tokio::spawn(async move {
            let retention_policy = match config.retention_policy {
                RetentionPolicyOption::Infinite => Some(crate::types::RetentionPolicy::Infinite),
                RetentionPolicyOption::Age => Some(crate::types::RetentionPolicy::Age(
                    Duration::from_secs(config.retention_age_secs),
                )),
            };

            let timestamping =
                if config.timestamping_mode.is_some() || config.timestamping_uncapped.is_some() {
                    Some(crate::types::TimestampingConfig {
                        timestamping_mode: config.timestamping_mode,
                        timestamping_uncapped: config.timestamping_uncapped,
                    })
                } else {
                    None
                };

            let delete_on_empty = if config.delete_on_empty_enabled {
                humantime::parse_duration(&config.delete_on_empty_min_age)
                    .ok()
                    .map(|d| crate::types::DeleteOnEmptyConfig {
                        delete_on_empty_min_age: d,
                    })
            } else {
                None
            };

            let args = ReconfigureStreamArgs {
                uri: S2BasinAndStreamUri { basin, stream },
                config: StreamConfig {
                    storage_class: config.storage_class,
                    retention_policy,
                    timestamping,
                    delete_on_empty,
                },
            };
            match ops::reconfigure_stream(&s2, args).await {
                Ok(_) => {
                    let _ = tx.send(Event::StreamReconfigured(Ok(())));
                    // Trigger refresh
                    let args = ListStreamsArgs {
                        uri: S2BasinAndMaybeStreamUri {
                            basin: basin_clone,
                            stream: None,
                        },
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: true,
                    };
                    if let Ok((streams, has_more)) = ops::list_streams(&s2, args).await {
                        let _ = tx_refresh.send(Event::StreamsLoaded(Ok((streams, has_more))));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::StreamReconfigured(Err(e)));
                }
            }
        });
    }

    /// Open the append view
    fn open_append_view(&mut self, basin_name: BasinName, stream_name: StreamName) {
        self.screen = Screen::AppendView(AppendViewState {
            basin_name,
            stream_name,
            body: String::new(),
            headers: Vec::new(),
            match_seq_num: String::new(),
            fencing_token: String::new(),
            selected: 0,
            editing: false,
            header_key_input: String::new(),
            header_value_input: String::new(),
            editing_header_key: true,
            history: Vec::new(),
            appending: false,
            input_file: String::new(),
            input_format: InputFormat::Text,
            file_append_progress: None,
        });
    }

    /// Handle keys in append view
    /// Layout: 0=body, 1=headers, 2=match_seq, 3=fencing, 4=send
    fn handle_append_view_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::AppendView(state) = &mut self.screen else {
            return;
        };

        // Don't handle keys while appending
        if state.appending {
            return;
        }

        // If editing a field, handle text input
        if state.editing {
            match key.code {
                KeyCode::Esc => {
                    state.editing = false;
                }
                KeyCode::Enter => {
                    if state.selected == 1 {
                        // Headers: if editing key, move to value; if editing value, add header
                        if state.editing_header_key {
                            if !state.header_key_input.is_empty() {
                                state.editing_header_key = false;
                            }
                        } else {
                            if !state.header_key_input.is_empty() {
                                state.headers.push((
                                    state.header_key_input.clone(),
                                    state.header_value_input.clone(),
                                ));
                                state.header_key_input.clear();
                                state.header_value_input.clear();
                                state.editing_header_key = true;
                            }
                            state.editing = false;
                        }
                    } else {
                        state.editing = false;
                    }
                }
                KeyCode::Tab if state.selected == 1 => {
                    // Toggle between key and value in headers
                    state.editing_header_key = !state.editing_header_key;
                }
                KeyCode::Backspace => match state.selected {
                    0 => {
                        state.body.pop();
                    }
                    1 => {
                        if state.editing_header_key {
                            state.header_key_input.pop();
                        } else {
                            state.header_value_input.pop();
                        }
                    }
                    2 => {
                        state.match_seq_num.pop();
                    }
                    3 => {
                        state.fencing_token.pop();
                    }
                    4 => {
                        state.input_file.pop();
                    }
                    _ => {}
                },
                KeyCode::Char(c) => match state.selected {
                    0 => {
                        state.body.push(c);
                    }
                    1 => {
                        if state.editing_header_key {
                            state.header_key_input.push(c);
                        } else {
                            state.header_value_input.push(c);
                        }
                    }
                    2 => {
                        if c.is_ascii_digit() {
                            state.match_seq_num.push(c);
                        }
                    }
                    3 => {
                        state.fencing_token.push(c);
                    }
                    4 => {
                        state.input_file.push(c);
                    }
                    _ => {}
                },
                _ => {}
            }
            return;
        }

        // Not editing - handle navigation
        match key.code {
            KeyCode::Esc => {
                // Go back to stream detail
                let basin_name = state.basin_name.clone();
                let stream_name = state.stream_name.clone();
                self.screen = Screen::StreamDetail(StreamDetailState {
                    basin_name: basin_name.clone(),
                    stream_name: stream_name.clone(),
                    config: None,
                    tail_position: None,
                    selected_action: 2, // Append action
                    loading: true,
                });
                self.load_stream_detail(basin_name, stream_name, tx);
            }
            KeyCode::Char('j') | KeyCode::Down => {
                state.selected = (state.selected + 1).min(6);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                state.selected = state.selected.saturating_sub(1);
            }
            KeyCode::Char('d') if state.selected == 1 => {
                state.headers.pop();
            }
            // Cycle format with h/l or space when on format field
            KeyCode::Char('h') | KeyCode::Char('l') | KeyCode::Char(' ') if state.selected == 5 => {
                state.input_format = state.input_format.next();
            }
            KeyCode::Enter => {
                if state.selected == 6 {
                    // Send button - check if we have file input or body
                    if !state.input_file.is_empty() {
                        // Append from file
                        let basin_name = state.basin_name.clone();
                        let stream_name = state.stream_name.clone();
                        let file_path = state.input_file.clone();
                        let input_format = state.input_format;
                        let fencing_token = if state.fencing_token.is_empty() {
                            None
                        } else {
                            Some(state.fencing_token.clone())
                        };
                        state.input_file.clear();
                        state.appending = true;
                        state.file_append_progress = Some((0, 0));
                        self.append_from_file(
                            basin_name,
                            stream_name,
                            file_path,
                            input_format,
                            fencing_token,
                            tx,
                        );
                    } else if !state.body.is_empty() {
                        // Append single record
                        let basin_name = state.basin_name.clone();
                        let stream_name = state.stream_name.clone();
                        let body = state.body.clone();
                        let headers = state.headers.clone();
                        let match_seq_num = state.match_seq_num.parse::<u64>().ok();
                        let fencing_token = if state.fencing_token.is_empty() {
                            None
                        } else {
                            Some(state.fencing_token.clone())
                        };
                        state.body.clear();
                        state.appending = true;
                        self.append_record(
                            basin_name,
                            stream_name,
                            body,
                            headers,
                            match_seq_num,
                            fencing_token,
                            tx,
                        );
                    }
                } else {
                    // Start editing the selected field
                    state.editing = true;
                    if state.selected == 1 {
                        state.editing_header_key = true;
                    }
                }
            }
            _ => {}
        }
    }

    /// Append a single record to the stream
    #[allow(clippy::too_many_arguments)]
    fn append_record(
        &self,
        basin_name: BasinName,
        stream_name: StreamName,
        body: String,
        headers: Vec<(String, String)>,
        match_seq_num: Option<u64>,
        fencing_token: Option<String>,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let body_preview = if body.len() > 50 {
            format!("{}...", &body[..50])
        } else {
            body.clone()
        };
        let header_count = headers.len();

        tokio::spawn(async move {
            use s2_sdk::types::{
                AppendInput, AppendRecord, AppendRecordBatch, FencingToken, Header,
            };

            let stream = s2.basin(basin_name).stream(stream_name);

            let mut record = match AppendRecord::new(body.into_bytes()) {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx.send(Event::RecordAppended(Err(
                        crate::error::CliError::RecordWrite(e.to_string()),
                    )));
                    return;
                }
            };
            if !headers.is_empty() {
                let parsed_headers: Vec<Header> = headers
                    .into_iter()
                    .map(|(k, v)| Header::new(k.into_bytes(), v.into_bytes()))
                    .collect();
                record = match record.with_headers(parsed_headers) {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Event::RecordAppended(Err(
                            crate::error::CliError::RecordWrite(e.to_string()),
                        )));
                        return;
                    }
                };
            }

            let records = match AppendRecordBatch::try_from_iter([record]) {
                Ok(batch) => batch,
                Err(e) => {
                    let _ = tx.send(Event::RecordAppended(Err(
                        crate::error::CliError::RecordWrite(e.to_string()),
                    )));
                    return;
                }
            };

            let mut input = AppendInput::new(records);
            if let Some(seq) = match_seq_num {
                input = input.with_match_seq_num(seq);
            }
            if let Some(token_str) = fencing_token {
                match token_str.parse::<FencingToken>() {
                    Ok(token) => {
                        input = input.with_fencing_token(token);
                    }
                    Err(e) => {
                        let _ = tx.send(Event::RecordAppended(Err(
                            crate::error::CliError::RecordWrite(format!(
                                "Invalid fencing token: {}",
                                e
                            )),
                        )));
                        return;
                    }
                }
            }

            match stream.append(input).await {
                Ok(output) => {
                    let _ = tx.send(Event::RecordAppended(Ok((
                        output.start.seq_num,
                        body_preview,
                        header_count,
                    ))));
                }
                Err(e) => {
                    let _ = tx.send(Event::RecordAppended(Err(crate::error::CliError::op(
                        crate::error::OpKind::Append,
                        e,
                    ))));
                }
            }
        });
    }

    /// Append records from a file (one record per line)
    fn append_from_file(
        &self,
        basin_name: BasinName,
        stream_name: StreamName,
        file_path: String,
        input_format: InputFormat,
        fencing_token: Option<String>,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");

        tokio::spawn(async move {
            use base64ct::{Base64, Encoding};
            use s2_sdk::types::{
                AppendInput, AppendRecord, AppendRecordBatch, FencingToken, Header,
            };
            use tokio::io::{AsyncBufReadExt, BufReader};

            // Open and read the file
            let file = match tokio::fs::File::open(&file_path).await {
                Ok(f) => f,
                Err(e) => {
                    let _ = tx.send(Event::FileAppendComplete(Err(
                        crate::error::CliError::RecordReaderInit(format!(
                            "Failed to open file '{}': {}",
                            file_path, e
                        )),
                    )));
                    return;
                }
            };

            let reader = BufReader::new(file);
            let mut lines = reader.lines();

            // Collect all lines first to get total count
            let mut all_lines = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                if !line.is_empty() {
                    all_lines.push(line);
                }
            }

            let total = all_lines.len();
            if total == 0 {
                let _ = tx.send(Event::FileAppendComplete(Err(
                    crate::error::CliError::RecordReaderInit(
                        "File is empty or contains no valid records".to_string(),
                    ),
                )));
                return;
            }

            let stream = s2.basin(basin_name).stream(stream_name);

            // Helper to parse a line into an AppendRecord based on format
            let parse_line = |line: &str, format: InputFormat| -> Result<AppendRecord, String> {
                match format {
                    InputFormat::Text => {
                        AppendRecord::new(line.as_bytes().to_vec()).map_err(|e| e.to_string())
                    }
                    InputFormat::Json | InputFormat::JsonBase64 => {
                        // Parse JSON: {"body": "...", "headers": [["key", "value"], ...],
                        // "timestamp": ...}
                        #[derive(serde::Deserialize)]
                        struct JsonRecord {
                            #[serde(default)]
                            body: String,
                            #[serde(default)]
                            headers: Vec<(String, String)>,
                            #[serde(default)]
                            timestamp: Option<u64>,
                        }

                        let parsed: JsonRecord = serde_json::from_str(line)
                            .map_err(|e| format!("Invalid JSON: {}", e))?;

                        // Decode body (base64 if json-base64, otherwise UTF-8)
                        let body_bytes = if format == InputFormat::JsonBase64 {
                            Base64::decode_vec(&parsed.body)
                                .map_err(|_| format!("Invalid base64 in body: {}", parsed.body))?
                        } else {
                            parsed.body.into_bytes()
                        };

                        let mut record =
                            AppendRecord::new(body_bytes).map_err(|e| e.to_string())?;

                        // Add headers
                        if !parsed.headers.is_empty() {
                            let headers: Result<Vec<Header>, String> = parsed
                                .headers
                                .into_iter()
                                .map(|(k, v)| {
                                    let key_bytes = if format == InputFormat::JsonBase64 {
                                        Base64::decode_vec(&k).map_err(|_| {
                                            format!("Invalid base64 in header key: {}", k)
                                        })?
                                    } else {
                                        k.into_bytes()
                                    };
                                    let val_bytes = if format == InputFormat::JsonBase64 {
                                        Base64::decode_vec(&v).map_err(|_| {
                                            format!("Invalid base64 in header value: {}", v)
                                        })?
                                    } else {
                                        v.into_bytes()
                                    };
                                    Ok(Header::new(key_bytes, val_bytes))
                                })
                                .collect();
                            record = record.with_headers(headers?).map_err(|e| e.to_string())?;
                        }

                        // Add timestamp if provided
                        if let Some(ts) = parsed.timestamp {
                            record = record.with_timestamp(ts);
                        }

                        Ok(record)
                    }
                }
            };

            // Process in batches
            let batch_size = 100;
            let mut appended = 0;
            let mut first_seq: Option<u64> = None;
            let mut last_seq: u64 = 0;

            for chunk in all_lines.chunks(batch_size) {
                // Create records from lines
                let records: Result<Vec<AppendRecord>, String> = chunk
                    .iter()
                    .map(|line| parse_line(line, input_format))
                    .collect();

                let records = match records {
                    Ok(r) => r,
                    Err(e) => {
                        let _ = tx.send(Event::FileAppendComplete(Err(
                            crate::error::CliError::RecordWrite(format!("Invalid record: {}", e)),
                        )));
                        return;
                    }
                };

                let batch = match AppendRecordBatch::try_from_iter(records) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = tx.send(Event::FileAppendComplete(Err(
                            crate::error::CliError::RecordWrite(format!(
                                "Failed to create batch: {}",
                                e
                            )),
                        )));
                        return;
                    }
                };

                let mut input = AppendInput::new(batch);

                // Apply fencing token if provided
                if let Some(ref token_str) = fencing_token {
                    match token_str.parse::<FencingToken>() {
                        Ok(token) => {
                            input = input.with_fencing_token(token);
                        }
                        Err(e) => {
                            let _ = tx.send(Event::FileAppendComplete(Err(
                                crate::error::CliError::RecordWrite(format!(
                                    "Invalid fencing token: {}",
                                    e
                                )),
                            )));
                            return;
                        }
                    }
                }

                match stream.append(input).await {
                    Ok(output) => {
                        if first_seq.is_none() {
                            first_seq = Some(output.start.seq_num);
                        }
                        last_seq = output.end.seq_num;
                        appended += chunk.len();

                        // Send progress update
                        let _ = tx.send(Event::FileAppendProgress {
                            appended,
                            total,
                            last_seq: Some(last_seq),
                        });
                    }
                    Err(e) => {
                        let _ = tx.send(Event::FileAppendComplete(Err(
                            crate::error::CliError::op(crate::error::OpKind::Append, e),
                        )));
                        return;
                    }
                }
            }

            // Send completion
            let _ = tx.send(Event::FileAppendComplete(Ok((
                total,
                first_seq.unwrap_or(0),
                last_seq,
            ))));
        });
    }

    /// Open fence dialog
    fn open_fence_dialog(&mut self, basin: BasinName, stream: StreamName) {
        self.input_mode = InputMode::Fence {
            basin,
            stream,
            new_token: String::new(),
            current_token: String::new(),
            selected: 0,
            editing: false,
            cursor: 0,
        };
    }

    /// Open trim dialog
    fn open_trim_dialog(&mut self, basin: BasinName, stream: StreamName) {
        self.input_mode = InputMode::Trim {
            basin,
            stream,
            trim_point: String::new(),
            fencing_token: String::new(),
            selected: 0,
            editing: false,
            cursor: 0,
        };
    }

    /// Fence a stream
    fn fence_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        new_token: String,
        current_token: Option<String>,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let new_token_clone = new_token.clone();

        tokio::spawn(async move {
            use s2_sdk::types::{AppendInput, AppendRecordBatch, CommandRecord, FencingToken};

            let stream_client = s2.basin(basin).stream(stream);
            let new_fencing_token = match new_token.parse::<FencingToken>() {
                Ok(token) => token,
                Err(e) => {
                    let _ = tx.send(Event::StreamFenced(Err(
                        crate::error::CliError::RecordWrite(format!(
                            "Invalid new fencing token: {}",
                            e
                        )),
                    )));
                    return;
                }
            };
            let command = CommandRecord::fence(new_fencing_token);
            let record: s2_sdk::types::AppendRecord = command.into();
            let records = match AppendRecordBatch::try_from_iter([record]) {
                Ok(batch) => batch,
                Err(e) => {
                    let _ = tx.send(Event::StreamFenced(Err(
                        crate::error::CliError::RecordWrite(e.to_string()),
                    )));
                    return;
                }
            };

            let mut input = AppendInput::new(records);
            if let Some(token_str) = current_token
                && !token_str.is_empty()
            {
                match token_str.parse::<FencingToken>() {
                    Ok(token) => {
                        input = input.with_fencing_token(token);
                    }
                    Err(e) => {
                        let _ = tx.send(Event::StreamFenced(Err(
                            crate::error::CliError::RecordWrite(format!(
                                "Invalid current fencing token: {}",
                                e
                            )),
                        )));
                        return;
                    }
                }
            }

            match stream_client.append(input).await {
                Ok(_) => {
                    let _ = tx.send(Event::StreamFenced(Ok(new_token_clone)));
                }
                Err(e) => {
                    let _ = tx.send(Event::StreamFenced(Err(crate::error::CliError::op(
                        crate::error::OpKind::Fence,
                        e,
                    ))));
                }
            }
        });
    }

    /// Trim a stream
    fn trim_stream(
        &self,
        basin: BasinName,
        stream: StreamName,
        trim_point: u64,
        fencing_token: Option<String>,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");

        tokio::spawn(async move {
            use s2_sdk::types::{AppendInput, AppendRecordBatch, CommandRecord, FencingToken};

            let stream_client = s2.basin(basin).stream(stream);
            let command = CommandRecord::trim(trim_point);
            let record: s2_sdk::types::AppendRecord = command.into();
            let records = match AppendRecordBatch::try_from_iter([record]) {
                Ok(batch) => batch,
                Err(e) => {
                    let _ = tx.send(Event::StreamTrimmed(Err(
                        crate::error::CliError::RecordWrite(e.to_string()),
                    )));
                    return;
                }
            };

            let mut input = AppendInput::new(records);
            if let Some(token_str) = fencing_token
                && !token_str.is_empty()
            {
                match token_str.parse::<FencingToken>() {
                    Ok(token) => {
                        input = input.with_fencing_token(token);
                    }
                    Err(e) => {
                        let _ = tx.send(Event::StreamTrimmed(Err(
                            crate::error::CliError::RecordWrite(format!(
                                "Invalid fencing token: {}",
                                e
                            )),
                        )));
                        return;
                    }
                }
            }

            match stream_client.append(input).await {
                Ok(output) => {
                    let _ = tx.send(Event::StreamTrimmed(Ok((trim_point, output.tail.seq_num))));
                }
                Err(e) => {
                    let _ = tx.send(Event::StreamTrimmed(Err(crate::error::CliError::op(
                        crate::error::OpKind::Trim,
                        e,
                    ))));
                }
            }
        });
    }

    /// Switch between tabs
    fn switch_tab(&mut self, tx: mpsc::UnboundedSender<Event>) {
        match self.tab {
            Tab::Basins => {
                self.tab = Tab::AccessTokens;
                self.screen = Screen::AccessTokens(AccessTokensState {
                    loading: true,
                    ..Default::default()
                });
                self.load_access_tokens(tx);
            }
            Tab::AccessTokens => {
                self.tab = Tab::Settings;
                self.screen = Screen::Settings(Self::load_settings_state());
            }
            Tab::Settings => {
                self.tab = Tab::Basins;
                self.screen = Screen::Basins(BasinsState {
                    loading: true,
                    ..Default::default()
                });
                self.load_basins(tx);
            }
        }
    }

    /// Handle keys on access tokens screen
    fn handle_access_tokens_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::AccessTokens(state) = &mut self.screen else {
            return;
        };

        // Handle filter mode
        if state.filter_active {
            match key.code {
                KeyCode::Esc => {
                    state.filter_active = false;
                    state.filter.clear();
                    state.selected = 0;
                }
                KeyCode::Enter => {
                    state.filter_active = false;
                }
                KeyCode::Backspace => {
                    state.filter.pop();
                    state.selected = 0;
                }
                KeyCode::Char(c) => {
                    state.filter.push(c);
                    state.selected = 0;
                }
                _ => {}
            }
            return;
        }

        // Get filtered tokens for navigation
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

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if !filtered_tokens.is_empty() && state.selected < filtered_tokens.len() - 1 {
                    state.selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if state.selected > 0 {
                    state.selected -= 1;
                }
            }
            KeyCode::Char('g') | KeyCode::Home => {
                state.selected = 0;
            }
            KeyCode::Char('G') | KeyCode::End => {
                if !filtered_tokens.is_empty() {
                    state.selected = filtered_tokens.len() - 1;
                }
            }
            KeyCode::Char('/') => {
                state.filter_active = true;
            }
            KeyCode::Char('c') => {
                self.input_mode = InputMode::IssueAccessToken {
                    id: String::new(),
                    expiry: ExpiryOption::ThirtyDays,
                    expiry_custom: String::new(),
                    basins_scope: ScopeOption::All,
                    basins_value: String::new(),
                    streams_scope: ScopeOption::All,
                    streams_value: String::new(),
                    tokens_scope: ScopeOption::All,
                    tokens_value: String::new(),
                    account_read: true,
                    account_write: false,
                    basin_read: true,
                    basin_write: false,
                    stream_read: true,
                    stream_write: false,
                    auto_prefix_streams: false,
                    selected: 0,
                    editing: false,
                    cursor: 0,
                };
            }
            KeyCode::Char('d') => {
                if let Some(token) = filtered_tokens.get(state.selected) {
                    self.input_mode = InputMode::ConfirmRevokeToken {
                        token_id: token.id.to_string(),
                    };
                }
            }
            KeyCode::Char('r') => {
                state.loading = true;
                self.load_access_tokens(tx);
            }
            KeyCode::Char('i') | KeyCode::Enter => {
                // View token details
                if let Some(token) = filtered_tokens.get(state.selected) {
                    self.input_mode = InputMode::ViewTokenDetail {
                        token: (*token).clone(),
                    };
                }
            }
            _ => {}
        }
    }

    /// Handle keys on setup screen (first-time token entry)
    fn handle_setup_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::Setup(state) = &mut self.screen else {
            return;
        };

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Esc => {
                self.should_quit = true;
            }
            KeyCode::Enter => {
                if state.access_token.is_empty() {
                    state.error = Some("Access token is required".to_string());
                    return;
                }

                state.validating = true;
                state.error = None;

                match Self::create_s2_client(&state.access_token) {
                    Ok(s2) => {
                        if let Err(e) = config::set_config_value(
                            ConfigKey::AccessToken,
                            state.access_token.clone(),
                        ) {
                            state.error = Some(format!("Failed to save config: {}", e));
                            state.validating = false;
                            return;
                        }

                        self.s2 = Some(s2);
                        self.screen = Screen::Basins(BasinsState {
                            loading: true,
                            ..Default::default()
                        });
                        self.load_basins(tx);
                        self.message = Some(StatusMessage {
                            text: "Access token configured successfully".to_string(),
                            level: MessageLevel::Success,
                        });
                    }
                    Err(e) => {
                        state.error = Some(format!("Invalid token: {}", e));
                        state.validating = false;
                    }
                }
            }
            KeyCode::Left => {
                state.cursor = state.cursor.saturating_sub(1);
            }
            KeyCode::Right => {
                state.cursor = (state.cursor + 1).min(state.access_token.len());
            }
            KeyCode::Home => {
                state.cursor = 0;
            }
            KeyCode::End => {
                state.cursor = state.access_token.len();
            }
            KeyCode::Backspace => {
                if state.cursor > 0 {
                    state.access_token.remove(state.cursor - 1);
                    state.cursor -= 1;
                    state.error = None;
                }
            }
            KeyCode::Delete => {
                if state.cursor < state.access_token.len() {
                    state.access_token.remove(state.cursor);
                    state.error = None;
                }
            }
            KeyCode::Char(c) => {
                state.access_token.insert(state.cursor, c);
                state.cursor += 1;
                state.error = None;
            }
            _ => {}
        }
    }

    /// Handle keys on settings screen
    fn handle_settings_key(&mut self, key: KeyEvent, _tx: mpsc::UnboundedSender<Event>) {
        let Screen::Settings(state) = &mut self.screen else {
            return;
        };

        // Handle editing mode
        if state.editing {
            let field = match state.selected {
                0 => &mut state.access_token,
                1 => &mut state.account_endpoint,
                2 => &mut state.basin_endpoint,
                _ => return,
            };
            match key.code {
                KeyCode::Esc => {
                    state.editing = false;
                }
                KeyCode::Enter => {
                    state.editing = false;
                    state.has_changes = true;
                }
                KeyCode::Left => {
                    state.cursor = state.cursor.saturating_sub(1);
                }
                KeyCode::Right => {
                    state.cursor = (state.cursor + 1).min(field.len());
                }
                KeyCode::Home => {
                    state.cursor = 0;
                }
                KeyCode::End => {
                    state.cursor = field.len();
                }
                KeyCode::Backspace => {
                    if state.cursor > 0 {
                        field.remove(state.cursor - 1);
                        state.cursor -= 1;
                        state.has_changes = true;
                    }
                }
                KeyCode::Delete => {
                    if state.cursor < field.len() {
                        field.remove(state.cursor);
                        state.has_changes = true;
                    }
                }
                KeyCode::Char(c) => {
                    field.insert(state.cursor, c);
                    state.cursor += 1;
                    state.has_changes = true;
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Char('q') => {
                self.should_quit = true;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if state.selected < 4 {
                    // 0=token, 1=account, 2=basin, 3=compression, 4=save
                    state.selected += 1;
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if state.selected > 0 {
                    state.selected -= 1;
                }
            }
            KeyCode::Char('e') | KeyCode::Enter if state.selected < 3 => {
                state.editing = true;
                state.cursor = match state.selected {
                    0 => state.access_token.len(),
                    1 => state.account_endpoint.len(),
                    2 => state.basin_endpoint.len(),
                    _ => 0,
                };
            }
            KeyCode::Char('h') | KeyCode::Left if state.selected == 3 => {
                // Cycle compression option backwards
                state.compression = state.compression.prev();
                state.has_changes = true;
            }
            KeyCode::Char('l') | KeyCode::Right if state.selected == 3 => {
                // Cycle compression option forwards
                state.compression = state.compression.next();
                state.has_changes = true;
            }
            KeyCode::Char(' ') if state.selected == 0 => {
                // Toggle token visibility
                state.access_token_masked = !state.access_token_masked;
            }
            KeyCode::Enter if state.selected == 4 => {
                // Save settings - clone state to avoid borrow issues
                let state_clone = state.clone();
                match Self::save_settings_static(&state_clone) {
                    Err(e) => {
                        state.message = Some(format!("Failed to save: {}", e));
                    }
                    Ok(()) => {
                        state.has_changes = false;
                        state.message = Some("Settings saved successfully".to_string());

                        // If access token changed, recreate S2 client
                        if !state.access_token.is_empty() {
                            match Self::create_s2_client(&state.access_token) {
                                Ok(s2) => {
                                    self.s2 = Some(s2);
                                }
                                Err(e) => {
                                    state.message =
                                        Some(format!("Token saved but client error: {}", e));
                                }
                            }
                        }
                    }
                }
            }
            KeyCode::Char('r') => {
                // Reload settings from file
                *state = Self::load_settings_state();
                state.message = Some("Settings reloaded".to_string());
            }
            _ => {}
        }
    }

    /// Load access tokens
    fn load_access_tokens(&self, tx: mpsc::UnboundedSender<Event>) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        tokio::spawn(async move {
            let args = ListAccessTokensArgs {
                prefix: None,
                start_after: None,
                limit: Some(100),
                no_auto_paginate: false,
            };
            let event = match ops::list_access_tokens(&s2, args).await {
                Ok((tokens, _)) => Event::AccessTokensLoaded(Ok(tokens)),
                Err(e) => Event::AccessTokensLoaded(Err(e)),
            };
            let _ = tx.send(event);
        });
    }

    /// Issue a new access token (v2 with full options)
    #[allow(clippy::too_many_arguments)]
    fn issue_access_token_v2(
        &self,
        id: String,
        expiry: ExpiryOption,
        expiry_custom: String,
        basins_scope: ScopeOption,
        basins_value: String,
        streams_scope: ScopeOption,
        streams_value: String,
        tokens_scope: ScopeOption,
        tokens_value: String,
        account_read: bool,
        account_write: bool,
        basin_read: bool,
        basin_write: bool,
        stream_read: bool,
        stream_write: bool,
        auto_prefix_streams: bool,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let tx_refresh = tx.clone();

        tokio::spawn(async move {
            let token_id: AccessTokenId = match id.parse() {
                Ok(id) => id,
                Err(e) => {
                    let _ = tx.send(Event::AccessTokenIssued(Err(CliError::InvalidArgs(
                        miette::miette!("Invalid token ID: {}", e),
                    ))));
                    return;
                }
            };
            let mut operations: Vec<Operation> = Vec::new();

            // Account level operations
            if account_read {
                operations.push(Operation::ListBasins);
                operations.push(Operation::GetAccountMetrics);
            }
            // (No account-write ops at account level)

            // Basin level operations
            if basin_read {
                operations.push(Operation::GetBasinConfig);
                operations.push(Operation::GetBasinMetrics);
                operations.push(Operation::ListStreams);
            }
            if basin_write {
                operations.push(Operation::CreateBasin);
                operations.push(Operation::DeleteBasin);
                operations.push(Operation::ReconfigureBasin);
            }

            // Stream level operations
            if stream_read {
                operations.push(Operation::GetStreamConfig);
                operations.push(Operation::GetStreamMetrics);
                operations.push(Operation::Read);
                operations.push(Operation::CheckTail);
            }
            if stream_write {
                operations.push(Operation::CreateStream);
                operations.push(Operation::DeleteStream);
                operations.push(Operation::ReconfigureStream);
                operations.push(Operation::Append);
                operations.push(Operation::Fence);
                operations.push(Operation::Trim);
            }

            // Token operations (based on tokens scope)
            if !matches!(tokens_scope, ScopeOption::None) {
                if account_read {
                    operations.push(Operation::ListAccessTokens);
                }
                if account_write {
                    operations.push(Operation::IssueAccessToken);
                    operations.push(Operation::RevokeAccessToken);
                }
            }
            let expires_in_str = match expiry {
                ExpiryOption::Never => None,
                ExpiryOption::Custom => {
                    if expiry_custom.is_empty() {
                        None
                    } else {
                        Some(expiry_custom.clone())
                    }
                }
                _ => expiry.duration_str().map(|s| s.to_string()),
            };
            let basins_matcher = match basins_scope {
                ScopeOption::All => None,
                ScopeOption::None => Some("".to_string()), // Empty string = no basins
                ScopeOption::Prefix => Some(basins_value.clone()),
                ScopeOption::Exact => Some(format!("={}", basins_value)),
            };

            let streams_matcher = match streams_scope {
                ScopeOption::All => None,
                ScopeOption::None => Some("".to_string()),
                ScopeOption::Prefix => Some(streams_value.clone()),
                ScopeOption::Exact => Some(format!("={}", streams_value)),
            };

            let tokens_matcher = match tokens_scope {
                ScopeOption::All => None,
                ScopeOption::None => Some("".to_string()),
                ScopeOption::Prefix => Some(tokens_value.clone()),
                ScopeOption::Exact => Some(format!("={}", tokens_value)),
            };
            let args = IssueAccessTokenArgs {
                id: token_id,
                expires_in: expires_in_str.and_then(|s| s.parse().ok()),
                expires_at: None,
                auto_prefix_streams,
                basins: basins_matcher.and_then(|s| {
                    if s.is_empty() && matches!(basins_scope, ScopeOption::None) {
                        // For "None" scope, we don't pass anything (API default is all)
                        // Actually, to restrict to none, we need special handling
                        None
                    } else if s.is_empty() {
                        None
                    } else {
                        s.parse().ok()
                    }
                }),
                streams: streams_matcher
                    .and_then(|s| if s.is_empty() { None } else { s.parse().ok() }),
                access_tokens: tokens_matcher
                    .and_then(|s| if s.is_empty() { None } else { s.parse().ok() }),
                op_group_perms: None,
                ops: operations,
            };

            match ops::issue_access_token(&s2, args).await {
                Ok(token) => {
                    let _ = tx.send(Event::AccessTokenIssued(Ok(token)));
                    // Trigger refresh
                    let list_args = ListAccessTokensArgs {
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: false,
                    };
                    if let Ok((tokens, _)) = ops::list_access_tokens(&s2, list_args).await {
                        let _ = tx_refresh.send(Event::AccessTokensLoaded(Ok(tokens)));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::AccessTokenIssued(Err(e)));
                }
            }
        });
    }

    /// Revoke an access token
    fn revoke_access_token(&self, id: String, tx: mpsc::UnboundedSender<Event>) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let tx_refresh = tx.clone();

        tokio::spawn(async move {
            let token_id: AccessTokenId = match id.parse() {
                Ok(id) => id,
                Err(e) => {
                    let _ = tx.send(Event::AccessTokenRevoked(Err(CliError::InvalidArgs(
                        miette::miette!("Invalid token ID: {}", e),
                    ))));
                    return;
                }
            };

            match ops::revoke_access_token(&s2, token_id.clone()).await {
                Ok(()) => {
                    let _ = tx.send(Event::AccessTokenRevoked(Ok(id)));
                    // Trigger refresh
                    let list_args = ListAccessTokensArgs {
                        prefix: None,
                        start_after: None,
                        limit: Some(100),
                        no_auto_paginate: false,
                    };
                    if let Ok((tokens, _)) = ops::list_access_tokens(&s2, list_args).await {
                        let _ = tx_refresh.send(Event::AccessTokensLoaded(Ok(tokens)));
                    }
                }
                Err(e) => {
                    let _ = tx.send(Event::AccessTokenRevoked(Err(e)));
                }
            }
        });
    }

    /// Open basin metrics view
    /// Open account metrics view
    fn open_account_metrics(&mut self, tx: mpsc::UnboundedSender<Event>) {
        let (year, month, day) = Self::today();
        self.screen = Screen::MetricsView(MetricsViewState {
            metrics_type: MetricsType::Account,
            metrics: Vec::new(),
            selected_category: MetricCategory::ActiveBasins,
            time_range: TimeRangeOption::default(),
            loading: true,
            scroll: 0,
            time_picker_open: false,
            time_picker_selected: 3, // Default to 24h (index 3)
            calendar_open: false,
            calendar_year: year,
            calendar_month: month,
            calendar_day: day,
            calendar_start: None,
            calendar_end: None,
            calendar_selecting_end: false,
        });
        self.load_account_metrics(MetricCategory::ActiveBasins, TimeRangeOption::default(), tx);
    }

    fn open_basin_metrics(&mut self, basin_name: BasinName, tx: mpsc::UnboundedSender<Event>) {
        let (year, month, day) = Self::today();
        self.screen = Screen::MetricsView(MetricsViewState {
            metrics_type: MetricsType::Basin {
                basin_name: basin_name.clone(),
            },
            metrics: Vec::new(),
            selected_category: MetricCategory::Storage,
            time_range: TimeRangeOption::default(),
            loading: true,
            scroll: 0,
            time_picker_open: false,
            time_picker_selected: 3,
            calendar_open: false,
            calendar_year: year,
            calendar_month: month,
            calendar_day: day,
            calendar_start: None,
            calendar_end: None,
            calendar_selecting_end: false,
        });
        self.load_basin_metrics(
            basin_name,
            MetricCategory::Storage,
            TimeRangeOption::default(),
            tx,
        );
    }

    /// Open stream metrics view
    fn open_stream_metrics(
        &mut self,
        basin_name: BasinName,
        stream_name: StreamName,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let (year, month, day) = Self::today();
        self.screen = Screen::MetricsView(MetricsViewState {
            metrics_type: MetricsType::Stream {
                basin_name: basin_name.clone(),
                stream_name: stream_name.clone(),
            },
            metrics: Vec::new(),
            selected_category: MetricCategory::Storage,
            time_range: TimeRangeOption::default(),
            loading: true,
            scroll: 0,
            time_picker_open: false,
            time_picker_selected: 3,
            calendar_open: false,
            calendar_year: year,
            calendar_month: month,
            calendar_day: day,
            calendar_start: None,
            calendar_end: None,
            calendar_selecting_end: false,
        });
        self.load_stream_metrics(basin_name, stream_name, TimeRangeOption::default(), tx);
    }

    /// Get today's date as (year, month, day)
    fn today() -> (i32, u32, u32) {
        use chrono::{Datelike, Local};
        let today = Local::now();
        (today.year(), today.month(), today.day())
    }

    /// Load basin metrics
    /// Load account metrics
    fn load_account_metrics(
        &self,
        category: MetricCategory,
        time_range: TimeRangeOption,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        use s2_sdk::types::AccountMetricSet;

        let s2 = self.s2.clone().expect("S2 client not initialized");
        let (start, end) = time_range.get_range();

        tokio::spawn(async move {
            let set = match category {
                MetricCategory::ActiveBasins => {
                    AccountMetricSet::ActiveBasins(TimeRange::new(start, end))
                }
                MetricCategory::AccountOps => AccountMetricSet::AccountOps(
                    s2_sdk::types::TimeRangeAndInterval::new(start, end),
                ),
                _ => return, // Other categories not valid for account
            };

            let input = s2_sdk::types::GetAccountMetricsInput::new(set);
            match s2.get_account_metrics(input).await {
                Ok(metrics) => {
                    let _ = tx.send(Event::AccountMetricsLoaded(Ok(metrics)));
                }
                Err(e) => {
                    let _ = tx.send(Event::AccountMetricsLoaded(Err(CliError::op(
                        crate::error::OpKind::GetAccountMetrics,
                        e,
                    ))));
                }
            }
        });
    }

    fn load_basin_metrics(
        &self,
        basin_name: BasinName,
        category: MetricCategory,
        time_range: TimeRangeOption,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let (start, end) = time_range.get_range();

        tokio::spawn(async move {
            let set = match category {
                MetricCategory::Storage => BasinMetricSet::Storage(TimeRange::new(start, end)),
                MetricCategory::AppendOps => {
                    BasinMetricSet::AppendOps(s2_sdk::types::TimeRangeAndInterval::new(start, end))
                }
                MetricCategory::ReadOps => {
                    BasinMetricSet::ReadOps(s2_sdk::types::TimeRangeAndInterval::new(start, end))
                }
                MetricCategory::AppendThroughput => BasinMetricSet::AppendThroughput(
                    s2_sdk::types::TimeRangeAndInterval::new(start, end),
                ),
                MetricCategory::ReadThroughput => BasinMetricSet::ReadThroughput(
                    s2_sdk::types::TimeRangeAndInterval::new(start, end),
                ),
                MetricCategory::BasinOps => {
                    BasinMetricSet::BasinOps(s2_sdk::types::TimeRangeAndInterval::new(start, end))
                }
                _ => return,
            };

            let input = s2_sdk::types::GetBasinMetricsInput::new(basin_name, set);
            match s2.get_basin_metrics(input).await {
                Ok(metrics) => {
                    let _ = tx.send(Event::BasinMetricsLoaded(Ok(metrics)));
                }
                Err(e) => {
                    let _ = tx.send(Event::BasinMetricsLoaded(Err(CliError::op(
                        crate::error::OpKind::GetBasinMetrics,
                        e,
                    ))));
                }
            }
        });
    }

    /// Load stream metrics
    fn load_stream_metrics(
        &self,
        basin_name: BasinName,
        stream_name: StreamName,
        time_range: TimeRangeOption,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let s2 = self.s2.clone().expect("S2 client not initialized");
        let (start, end) = time_range.get_range();

        tokio::spawn(async move {
            let set = StreamMetricSet::Storage(TimeRange::new(start, end));

            let input = s2_sdk::types::GetStreamMetricsInput::new(basin_name, stream_name, set);
            match s2.get_stream_metrics(input).await {
                Ok(metrics) => {
                    let _ = tx.send(Event::StreamMetricsLoaded(Ok(metrics)));
                }
                Err(e) => {
                    let _ = tx.send(Event::StreamMetricsLoaded(Err(CliError::op(
                        crate::error::OpKind::GetStreamMetrics,
                        e,
                    ))));
                }
            }
        });
    }

    /// Handle keys in metrics view
    fn handle_metrics_view_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        // Check if time picker or calendar is open first
        let (time_picker_open, calendar_open) = {
            let Screen::MetricsView(state) = &self.screen else {
                return;
            };
            (state.time_picker_open, state.calendar_open)
        };

        if time_picker_open {
            self.handle_time_picker_key(key, tx);
            return;
        }

        if calendar_open {
            self.handle_calendar_key(key, tx);
            return;
        }

        // Extract data from state first to avoid borrow issues
        let (metrics_type, selected_category, time_range) = {
            let Screen::MetricsView(state) = &self.screen else {
                return;
            };
            (
                state.metrics_type.clone(),
                state.selected_category,
                state.time_range,
            )
        };

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                // Go back to previous screen
                match &metrics_type {
                    MetricsType::Account => {
                        // Go back to basins list
                        self.screen = Screen::Basins(BasinsState {
                            loading: true,
                            ..Default::default()
                        });
                        self.load_basins(tx);
                    }
                    MetricsType::Basin { basin_name } => {
                        let basin_name = basin_name.clone();
                        self.screen = Screen::Streams(StreamsState {
                            basin_name: basin_name.clone(),
                            streams: Vec::new(),
                            selected: 0,
                            loading: true,
                            filter: String::new(),
                            filter_active: false,
                            has_more: false,
                            loading_more: false,
                        });
                        self.load_streams(basin_name, tx);
                    }
                    MetricsType::Stream {
                        basin_name,
                        stream_name,
                    } => {
                        let basin_name = basin_name.clone();
                        let stream_name = stream_name.clone();
                        self.screen = Screen::StreamDetail(StreamDetailState {
                            basin_name: basin_name.clone(),
                            stream_name: stream_name.clone(),
                            config: None,
                            tail_position: None,
                            selected_action: 0,
                            loading: true,
                        });
                        self.load_stream_detail(basin_name, stream_name, tx);
                    }
                }
            }
            KeyCode::Char('t') => {
                // Open time picker
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.time_picker_open = true;
                    // Set picker selection to current time range
                    state.time_picker_selected = TimeRangeOption::PRESETS
                        .iter()
                        .position(|p| {
                            std::mem::discriminant(p) == std::mem::discriminant(&state.time_range)
                        })
                        .unwrap_or(3);
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                // Previous metric category (for basin or account metrics)
                match &metrics_type {
                    MetricsType::Account => {
                        let new_category = selected_category.prev();
                        if let Screen::MetricsView(state) = &mut self.screen {
                            state.selected_category = new_category;
                            state.loading = true;
                            state.metrics.clear();
                        }
                        self.load_account_metrics(new_category, time_range, tx);
                    }
                    MetricsType::Basin { basin_name } => {
                        let basin_name = basin_name.clone();
                        let new_category = selected_category.prev();
                        if let Screen::MetricsView(state) = &mut self.screen {
                            state.selected_category = new_category;
                            state.loading = true;
                            state.metrics.clear();
                        }
                        self.load_basin_metrics(basin_name, new_category, time_range, tx);
                    }
                    MetricsType::Stream { .. } => {} // No category switching for stream
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                // Next metric category (for basin or account metrics)
                match &metrics_type {
                    MetricsType::Account => {
                        let new_category = selected_category.next();
                        if let Screen::MetricsView(state) = &mut self.screen {
                            state.selected_category = new_category;
                            state.loading = true;
                            state.metrics.clear();
                        }
                        self.load_account_metrics(new_category, time_range, tx);
                    }
                    MetricsType::Basin { basin_name } => {
                        let basin_name = basin_name.clone();
                        let new_category = selected_category.next();
                        if let Screen::MetricsView(state) = &mut self.screen {
                            state.selected_category = new_category;
                            state.loading = true;
                            state.metrics.clear();
                        }
                        self.load_basin_metrics(basin_name, new_category, time_range, tx);
                    }
                    MetricsType::Stream { .. } => {} // No category switching for stream
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Screen::MetricsView(state) = &mut self.screen
                    && state.scroll > 0
                {
                    state.scroll -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.scroll += 1;
                }
            }
            KeyCode::Char('r') => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.loading = true;
                    state.metrics.clear();
                }
                match &metrics_type {
                    MetricsType::Account => {
                        self.load_account_metrics(selected_category, time_range, tx);
                    }
                    MetricsType::Basin { basin_name } => {
                        self.load_basin_metrics(
                            basin_name.clone(),
                            selected_category,
                            time_range,
                            tx,
                        );
                    }
                    MetricsType::Stream {
                        basin_name,
                        stream_name,
                    } => {
                        self.load_stream_metrics(
                            basin_name.clone(),
                            stream_name.clone(),
                            time_range,
                            tx,
                        );
                    }
                }
            }
            KeyCode::Char('[') => {
                // Previous time range
                let new_time_range = time_range.prev();
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.time_range = new_time_range;
                    state.loading = true;
                    state.metrics.clear();
                }
                match &metrics_type {
                    MetricsType::Account => {
                        self.load_account_metrics(selected_category, new_time_range, tx);
                    }
                    MetricsType::Basin { basin_name } => {
                        self.load_basin_metrics(
                            basin_name.clone(),
                            selected_category,
                            new_time_range,
                            tx,
                        );
                    }
                    MetricsType::Stream {
                        basin_name,
                        stream_name,
                    } => {
                        self.load_stream_metrics(
                            basin_name.clone(),
                            stream_name.clone(),
                            new_time_range,
                            tx,
                        );
                    }
                }
            }
            KeyCode::Char(']') => {
                // Next time range
                let new_time_range = time_range.next();
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.time_range = new_time_range;
                    state.loading = true;
                    state.metrics.clear();
                }
                match &metrics_type {
                    MetricsType::Account => {
                        self.load_account_metrics(selected_category, new_time_range, tx);
                    }
                    MetricsType::Basin { basin_name } => {
                        self.load_basin_metrics(
                            basin_name.clone(),
                            selected_category,
                            new_time_range,
                            tx,
                        );
                    }
                    MetricsType::Stream {
                        basin_name,
                        stream_name,
                    } => {
                        self.load_stream_metrics(
                            basin_name.clone(),
                            stream_name.clone(),
                            new_time_range,
                            tx,
                        );
                    }
                }
            }
            _ => {}
        }
    }

    /// Handle keys when time picker popup is open
    fn handle_time_picker_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        // PRESETS.len() is 7 (indices 0-6), index 7 is "Custom"
        const CUSTOM_INDEX: usize = 7;

        let (metrics_type, selected_category) = {
            let Screen::MetricsView(state) = &self.screen else {
                return;
            };
            (state.metrics_type.clone(), state.selected_category)
        };

        match key.code {
            KeyCode::Esc => {
                // Close picker without changing
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.time_picker_open = false;
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Screen::MetricsView(state) = &mut self.screen
                    && state.time_picker_selected > 0
                {
                    state.time_picker_selected -= 1;
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Screen::MetricsView(state) = &mut self.screen
                    && state.time_picker_selected < CUSTOM_INDEX
                {
                    state.time_picker_selected += 1;
                }
            }
            KeyCode::Enter => {
                let time_picker_selected = {
                    let Screen::MetricsView(state) = &self.screen else {
                        return;
                    };
                    state.time_picker_selected
                };

                if time_picker_selected == CUSTOM_INDEX {
                    // Open calendar picker
                    if let Screen::MetricsView(state) = &mut self.screen {
                        state.time_picker_open = false;
                        state.calendar_open = true;
                        state.calendar_start = None;
                        state.calendar_end = None;
                        state.calendar_selecting_end = false;
                    }
                } else {
                    // Select preset time range and close picker
                    let new_time_range = {
                        let Screen::MetricsView(state) = &mut self.screen else {
                            return;
                        };
                        let selected = TimeRangeOption::PRESETS
                            .get(state.time_picker_selected)
                            .cloned()
                            .unwrap_or_default();
                        state.time_range = selected;
                        state.time_picker_open = false;
                        state.loading = true;
                        state.metrics.clear();
                        selected
                    };

                    // Reload metrics with new time range
                    match &metrics_type {
                        MetricsType::Account => {
                            self.load_account_metrics(selected_category, new_time_range, tx);
                        }
                        MetricsType::Basin { basin_name } => {
                            self.load_basin_metrics(
                                basin_name.clone(),
                                selected_category,
                                new_time_range,
                                tx,
                            );
                        }
                        MetricsType::Stream {
                            basin_name,
                            stream_name,
                        } => {
                            self.load_stream_metrics(
                                basin_name.clone(),
                                stream_name.clone(),
                                new_time_range,
                                tx,
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Handle keys when calendar picker is open
    fn handle_calendar_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let (metrics_type, selected_category) = {
            let Screen::MetricsView(state) = &self.screen else {
                return;
            };
            (state.metrics_type.clone(), state.selected_category)
        };

        match key.code {
            KeyCode::Esc => {
                // Close calendar without changing
                if let Screen::MetricsView(state) = &mut self.screen {
                    state.calendar_open = false;
                    state.calendar_start = None;
                    state.calendar_end = None;
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    // Move to previous day
                    if state.calendar_day > 1 {
                        state.calendar_day -= 1;
                    } else {
                        // Go to previous month
                        if state.calendar_month > 1 {
                            state.calendar_month -= 1;
                        } else {
                            state.calendar_month = 12;
                            state.calendar_year -= 1;
                        }
                        state.calendar_day =
                            Self::days_in_month(state.calendar_year, state.calendar_month);
                    }
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    let max_day = Self::days_in_month(state.calendar_year, state.calendar_month);
                    if state.calendar_day < max_day {
                        state.calendar_day += 1;
                    } else {
                        // Go to next month
                        if state.calendar_month < 12 {
                            state.calendar_month += 1;
                        } else {
                            state.calendar_month = 1;
                            state.calendar_year += 1;
                        }
                        state.calendar_day = 1;
                    }
                }
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    // Move up one week (7 days)
                    if state.calendar_day > 7 {
                        state.calendar_day -= 7;
                    } else {
                        // Go to previous month
                        if state.calendar_month > 1 {
                            state.calendar_month -= 1;
                        } else {
                            state.calendar_month = 12;
                            state.calendar_year -= 1;
                        }
                        let prev_month_days =
                            Self::days_in_month(state.calendar_year, state.calendar_month);
                        state.calendar_day = prev_month_days.saturating_sub(7 - state.calendar_day);
                    }
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Screen::MetricsView(state) = &mut self.screen {
                    let max_day = Self::days_in_month(state.calendar_year, state.calendar_month);
                    if state.calendar_day + 7 <= max_day {
                        state.calendar_day += 7;
                    } else {
                        let overflow = state.calendar_day + 7 - max_day;
                        // Go to next month
                        if state.calendar_month < 12 {
                            state.calendar_month += 1;
                        } else {
                            state.calendar_month = 1;
                            state.calendar_year += 1;
                        }
                        state.calendar_day = overflow.min(Self::days_in_month(
                            state.calendar_year,
                            state.calendar_month,
                        ));
                    }
                }
            }
            KeyCode::Char('[') => {
                // Previous month
                if let Screen::MetricsView(state) = &mut self.screen {
                    if state.calendar_month > 1 {
                        state.calendar_month -= 1;
                    } else {
                        state.calendar_month = 12;
                        state.calendar_year -= 1;
                    }
                    let max_day = Self::days_in_month(state.calendar_year, state.calendar_month);
                    state.calendar_day = state.calendar_day.min(max_day);
                }
            }
            KeyCode::Char(']') => {
                // Next month
                if let Screen::MetricsView(state) = &mut self.screen {
                    if state.calendar_month < 12 {
                        state.calendar_month += 1;
                    } else {
                        state.calendar_month = 1;
                        state.calendar_year += 1;
                    }
                    let max_day = Self::days_in_month(state.calendar_year, state.calendar_month);
                    state.calendar_day = state.calendar_day.min(max_day);
                }
            }
            KeyCode::Enter => {
                // Select date
                let should_apply = {
                    let Screen::MetricsView(state) = &mut self.screen else {
                        return;
                    };
                    let selected_date = (
                        state.calendar_year,
                        state.calendar_month,
                        state.calendar_day,
                    );

                    if state.calendar_start.is_none() {
                        // First selection: set start date
                        state.calendar_start = Some(selected_date);
                        state.calendar_selecting_end = true;
                        false
                    } else if !state.calendar_selecting_end {
                        // Start date already set, selecting again resets
                        state.calendar_start = Some(selected_date);
                        state.calendar_selecting_end = true;
                        false
                    } else {
                        // Second selection: set end date and apply
                        state.calendar_end = Some(selected_date);
                        true
                    }
                };

                if should_apply {
                    // Apply custom date range
                    let new_time_range = {
                        let Screen::MetricsView(state) = &mut self.screen else {
                            return;
                        };

                        let start_date = state
                            .calendar_start
                            .expect("calendar_start set before should_apply");
                        let end_date = state
                            .calendar_end
                            .expect("calendar_end set before should_apply");

                        let (start, end) = if start_date <= end_date {
                            (start_date, end_date)
                        } else {
                            (end_date, start_date)
                        };

                        let start_ts = Self::date_to_timestamp(start.0, start.1, start.2, true);
                        let end_ts = Self::date_to_timestamp(end.0, end.1, end.2, false);

                        let Some((start_ts, end_ts)) = start_ts.zip(end_ts) else {
                            state.calendar_open = false;
                            return;
                        };

                        let time_range = TimeRangeOption::Custom {
                            start: start_ts,
                            end: end_ts,
                        };
                        state.time_range = time_range;
                        state.calendar_open = false;
                        state.loading = true;
                        state.metrics.clear();
                        time_range
                    };

                    // Reload metrics
                    match &metrics_type {
                        MetricsType::Account => {
                            self.load_account_metrics(selected_category, new_time_range, tx);
                        }
                        MetricsType::Basin { basin_name } => {
                            self.load_basin_metrics(
                                basin_name.clone(),
                                selected_category,
                                new_time_range,
                                tx,
                            );
                        }
                        MetricsType::Stream {
                            basin_name,
                            stream_name,
                        } => {
                            self.load_stream_metrics(
                                basin_name.clone(),
                                stream_name.clone(),
                                new_time_range,
                                tx,
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn days_in_month(year: i32, month: u32) -> u32 {
        let next_month_start = if month == 12 {
            NaiveDate::from_ymd_opt(year + 1, 1, 1)
        } else {
            NaiveDate::from_ymd_opt(year, month + 1, 1)
        };
        next_month_start
            .and_then(|d| d.pred_opt())
            .map(|d| d.day())
            .unwrap_or(28)
    }

    fn date_to_timestamp(year: i32, month: u32, day: u32, start_of_day: bool) -> Option<u32> {
        use chrono::{TimeZone, Utc};
        let (h, m, s) = if start_of_day {
            (0, 0, 0)
        } else {
            (23, 59, 59)
        };
        Utc.with_ymd_and_hms(year, month, day, h, m, s)
            .single()
            .map(|dt| dt.timestamp() as u32)
    }

    fn handle_bench_view_key(&mut self, key: KeyEvent, tx: mpsc::UnboundedSender<Event>) {
        let Screen::BenchView(state) = &mut self.screen else {
            return;
        };

        // If running, only allow stop
        if state.running {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    state.stopping = true;
                    // Signal the benchmark task to stop
                    if let Some(stop_signal) = &self.bench_stop_signal {
                        stop_signal.store(true, Ordering::Relaxed);
                    }
                    self.message = Some(StatusMessage {
                        text: "Stopping benchmark...".to_string(),
                        level: MessageLevel::Info,
                    });
                }
                _ => {}
            }
            return;
        }

        // If showing results, allow going back
        if !state.config_phase && !state.running {
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    // Go back to basins
                    self.screen = Screen::Basins(BasinsState::default());
                    self.load_basins(tx);
                }
                KeyCode::Char('r') => {
                    // Reset to config phase
                    let basin_name = state.basin_name.clone();
                    self.screen = Screen::BenchView(BenchViewState::new(basin_name));
                }
                _ => {}
            }
            return;
        }

        // Config phase
        if state.editing {
            match key.code {
                KeyCode::Esc => {
                    state.editing = false;
                    state.edit_buffer.clear();
                }
                KeyCode::Enter => {
                    // Apply the edit
                    match state.edit_buffer.parse::<u64>() {
                        Ok(val) if val > 0 => {
                            match state.config_field {
                                BenchConfigField::RecordSize => {
                                    let val = val.clamp(128, 1024 * 1024) as u32;
                                    state.record_size = val;
                                }
                                BenchConfigField::TargetMibps => {
                                    state.target_mibps = val.clamp(1, 100);
                                }
                                BenchConfigField::Duration => {
                                    state.duration_secs = val.clamp(10, 600);
                                }
                                BenchConfigField::CatchupDelay => {
                                    state.catchup_delay_secs = val.min(120);
                                }
                                BenchConfigField::Start => {}
                            }
                            state.editing = false;
                            state.edit_buffer.clear();
                        }
                        Ok(_) => {
                            // Value is 0, show error
                            self.message = Some(StatusMessage {
                                text: "Value must be greater than 0".to_string(),
                                level: MessageLevel::Error,
                            });
                        }
                        Err(_) => {
                            // Invalid number, show error
                            self.message = Some(StatusMessage {
                                text: "Invalid number".to_string(),
                                level: MessageLevel::Error,
                            });
                        }
                    }
                }
                KeyCode::Char(c) if c.is_ascii_digit() => {
                    state.edit_buffer.push(c);
                }
                KeyCode::Backspace => {
                    state.edit_buffer.pop();
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                // Go back to basins
                self.screen = Screen::Basins(BasinsState::default());
                self.load_basins(tx);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                state.config_field = state.config_field.prev();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                state.config_field = state.config_field.next();
            }
            KeyCode::Enter => {
                if state.config_field == BenchConfigField::Start {
                    // Start the benchmark
                    let basin_name = state.basin_name.clone();
                    let record_size = state.record_size;
                    let target_mibps = state.target_mibps;
                    let duration_secs = state.duration_secs;
                    let catchup_delay_secs = state.catchup_delay_secs;
                    state.config_phase = false;
                    self.start_benchmark(
                        basin_name,
                        record_size,
                        target_mibps,
                        duration_secs,
                        catchup_delay_secs,
                        tx,
                    );
                } else {
                    // Edit the field
                    state.editing = true;
                    state.edit_buffer = match state.config_field {
                        BenchConfigField::RecordSize => state.record_size.to_string(),
                        BenchConfigField::TargetMibps => state.target_mibps.to_string(),
                        BenchConfigField::Duration => state.duration_secs.to_string(),
                        BenchConfigField::CatchupDelay => state.catchup_delay_secs.to_string(),
                        BenchConfigField::Start => String::new(),
                    };
                }
            }
            KeyCode::Left | KeyCode::Char('h') => {
                // Decrease value
                match state.config_field {
                    BenchConfigField::RecordSize => {
                        state.record_size = (state.record_size / 2).max(128);
                    }
                    BenchConfigField::TargetMibps => {
                        state.target_mibps = (state.target_mibps.saturating_sub(1)).max(1);
                    }
                    BenchConfigField::Duration => {
                        state.duration_secs = (state.duration_secs.saturating_sub(10)).max(10);
                    }
                    BenchConfigField::CatchupDelay => {
                        state.catchup_delay_secs = state.catchup_delay_secs.saturating_sub(5);
                    }
                    BenchConfigField::Start => {}
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                // Increase value
                match state.config_field {
                    BenchConfigField::RecordSize => {
                        state.record_size = (state.record_size * 2).min(1024 * 1024);
                    }
                    BenchConfigField::TargetMibps => {
                        state.target_mibps = state.target_mibps.saturating_add(1).min(100);
                    }
                    BenchConfigField::Duration => {
                        state.duration_secs = state.duration_secs.saturating_add(10).min(600);
                    }
                    BenchConfigField::CatchupDelay => {
                        state.catchup_delay_secs =
                            state.catchup_delay_secs.saturating_add(5).min(120);
                    }
                    BenchConfigField::Start => {}
                }
            }
            _ => {}
        }
    }

    fn start_benchmark(
        &mut self,
        basin_name: BasinName,
        record_size: u32,
        target_mibps: u64,
        duration_secs: u64,
        catchup_delay_secs: u64,
        tx: mpsc::UnboundedSender<Event>,
    ) {
        let Some(s2) = self.s2.clone() else {
            let _ = tx.send(Event::BenchStreamCreated(Err(CliError::Config(
                crate::error::CliConfigError::MissingAccessToken,
            ))));
            return;
        };

        // Create a stop signal that can be triggered from the UI
        let user_stop = Arc::new(AtomicBool::new(false));
        self.bench_stop_signal = Some(user_stop.clone());

        tokio::spawn(async move {
            use std::{num::NonZeroU64, time::Duration};

            use s2_sdk::types::{
                CreateStreamInput, DeleteOnEmptyConfig, DeleteStreamInput, RetentionPolicy,
                StreamConfig as SdkStreamConfig, StreamName, TimestampingConfig, TimestampingMode,
            };
            let stream_name: StreamName = format!("_bench_{}", uuid::Uuid::new_v4())
                .parse()
                .expect("valid stream name");
            let stream_name_str = stream_name.to_string();

            let stream_config = SdkStreamConfig::new()
                .with_retention_policy(RetentionPolicy::Age(3600))
                .with_delete_on_empty(
                    DeleteOnEmptyConfig::new().with_min_age(Duration::from_secs(60)),
                )
                .with_timestamping(
                    TimestampingConfig::new()
                        .with_mode(TimestampingMode::ClientRequire)
                        .with_uncapped(true),
                );

            let basin = s2.basin(basin_name.clone());
            if let Err(e) = basin
                .create_stream(
                    CreateStreamInput::new(stream_name.clone()).with_config(stream_config),
                )
                .await
            {
                let _ = tx.send(Event::BenchStreamCreated(Err(CliError::op(
                    crate::error::OpKind::Bench,
                    e,
                ))));
                return;
            }

            let _ = tx.send(Event::BenchStreamCreated(Ok(stream_name_str)));

            // Get stream handle
            let stream = basin.stream(stream_name.clone());

            // Run the benchmark with events
            let result = run_bench_with_events(
                stream,
                record_size as usize,
                NonZeroU64::new(target_mibps).unwrap_or(NonZeroU64::MIN),
                Duration::from_secs(duration_secs),
                Duration::from_secs(catchup_delay_secs),
                user_stop,
                tx.clone(),
            )
            .await;

            // Clean up the stream
            let _ = basin
                .delete_stream(DeleteStreamInput::new(stream_name))
                .await;

            let _ = tx.send(Event::BenchComplete(result));
        });
    }
}

/// Run the benchmark and send events to the TUI
async fn run_bench_with_events(
    stream: s2_sdk::S2Stream,
    record_size: usize,
    target_mibps: std::num::NonZeroU64,
    duration: std::time::Duration,
    catchup_delay: std::time::Duration,
    user_stop: Arc<AtomicBool>,
    tx: mpsc::UnboundedSender<Event>,
) -> Result<BenchFinalStats, CliError> {
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };

    use futures::StreamExt;
    use tokio::time::Instant;

    use crate::{bench::*, types::LatencyStats};

    const WRITE_DONE_SENTINEL: u64 = u64::MAX;

    let bench_start = Instant::now();
    // Separate flags: user_stop is for user cancellation, write_stop is for duration expiry
    let write_stop = Arc::new(AtomicBool::new(false));
    let write_done_records = Arc::new(AtomicU64::new(WRITE_DONE_SENTINEL));

    // We need to re-implement the bench logic here to send events
    // For now, let's use a simplified version that calls into bench.rs
    // and extracts the stats

    let mut all_ack_latencies: Vec<Duration> = Vec::new();
    let mut all_e2e_latencies: Vec<Duration> = Vec::new();

    // Run write and read streams concurrently
    let write_stream = bench_write(
        stream.clone(),
        record_size,
        target_mibps,
        write_stop.clone(),
        write_done_records.clone(),
        bench_start,
    );

    let read_stream = bench_read(
        stream.clone(),
        record_size,
        write_done_records.clone(),
        bench_start,
    );

    enum BenchEvent {
        Write(Result<BenchWriteSample, CliError>),
        Read(Result<BenchReadSample, CliError>),
        WriteDone,
        ReadDone,
    }

    let (btx, mut brx) = tokio::sync::mpsc::unbounded_channel();
    let write_tx = btx.clone();
    let write_handle = tokio::spawn(async move {
        let mut write_stream = std::pin::pin!(write_stream);
        while let Some(sample) = write_stream.next().await {
            if write_tx.send(BenchEvent::Write(sample)).is_err() {
                return;
            }
        }
        let _ = write_tx.send(BenchEvent::WriteDone);
    });
    let read_tx = btx.clone();
    let read_handle = tokio::spawn(async move {
        let mut read_stream = std::pin::pin!(read_stream);
        while let Some(sample) = read_stream.next().await {
            if read_tx.send(BenchEvent::Read(sample)).is_err() {
                return;
            }
        }
        let _ = read_tx.send(BenchEvent::ReadDone);
    });
    drop(btx);

    let deadline = bench_start + duration;
    let mut write_done = false;
    let mut read_done = false;

    loop {
        if write_done && read_done {
            break;
        }
        // Check if user cancelled
        if user_stop.load(Ordering::Relaxed) {
            write_stop.store(true, Ordering::Relaxed);
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline), if !write_stop.load(Ordering::Relaxed) => {
                write_stop.store(true, Ordering::Relaxed);
                let _ = tx.send(Event::BenchPhaseComplete(BenchPhase::Write));
            }
            event = brx.recv() => {
                match event {
                    Some(BenchEvent::Write(Ok(sample))) => {
                        all_ack_latencies.extend(sample.ack_latencies.iter().copied());
                        let mibps = sample.bytes as f64 / (1024.0 * 1024.0) / sample.elapsed.as_secs_f64().max(0.001);
                        let recps = sample.records as f64 / sample.elapsed.as_secs_f64().max(0.001);
                        let _ = tx.send(Event::BenchWriteSample(BenchSample {
                            bytes: sample.bytes,
                            records: sample.records,
                            elapsed: sample.elapsed,
                            mib_per_sec: mibps,
                            records_per_sec: recps,
                        }));
                    }
                    Some(BenchEvent::Write(Err(e))) => {
                        write_stop.store(true, Ordering::Relaxed);
                        write_handle.abort();
                        read_handle.abort();
                        return Err(e);
                    }
                    Some(BenchEvent::WriteDone) => {
                        write_done = true;
                    }
                    Some(BenchEvent::Read(Ok(sample))) => {
                        all_e2e_latencies.extend(sample.e2e_latencies.iter().copied());
                        let mibps = sample.bytes as f64 / (1024.0 * 1024.0) / sample.elapsed.as_secs_f64().max(0.001);
                        let recps = sample.records as f64 / sample.elapsed.as_secs_f64().max(0.001);
                        let _ = tx.send(Event::BenchReadSample(BenchSample {
                            bytes: sample.bytes,
                            records: sample.records,
                            elapsed: sample.elapsed,
                            mib_per_sec: mibps,
                            records_per_sec: recps,
                        }));
                    }
                    Some(BenchEvent::Read(Err(e))) => {
                        write_stop.store(true, Ordering::Relaxed);
                        write_handle.abort();
                        read_handle.abort();
                        return Err(e);
                    }
                    Some(BenchEvent::ReadDone) => {
                        read_done = true;
                        let _ = tx.send(Event::BenchPhaseComplete(BenchPhase::Read));
                    }
                    None => {
                        write_done = true;
                        read_done = true;
                    }
                }
            }
        }
    }

    let _ = write_handle.await;
    let _ = read_handle.await;

    // Check if user stopped before starting catchup
    if user_stop.load(Ordering::Relaxed) {
        return Ok(BenchFinalStats {
            ack_latency: if all_ack_latencies.is_empty() {
                None
            } else {
                Some(LatencyStats::compute(all_ack_latencies))
            },
            e2e_latency: if all_e2e_latencies.is_empty() {
                None
            } else {
                Some(LatencyStats::compute(all_e2e_latencies))
            },
        });
    }

    let catchup_wait_start = Instant::now();
    while catchup_wait_start.elapsed() < catchup_delay {
        if user_stop.load(Ordering::Relaxed) {
            return Ok(BenchFinalStats {
                ack_latency: if all_ack_latencies.is_empty() {
                    None
                } else {
                    Some(LatencyStats::compute(all_ack_latencies))
                },
                e2e_latency: if all_e2e_latencies.is_empty() {
                    None
                } else {
                    Some(LatencyStats::compute(all_e2e_latencies))
                },
            });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let _ = tx.send(Event::BenchPhaseComplete(BenchPhase::CatchupWait));

    let catchup_stream = bench_read_catchup(stream.clone(), record_size, bench_start);
    let mut catchup_stream = std::pin::pin!(catchup_stream);
    let catchup_timeout = Duration::from_secs(300);
    let catchup_deadline = tokio::time::Instant::now() + catchup_timeout;
    loop {
        if user_stop.load(Ordering::Relaxed) {
            break;
        }
        match tokio::time::timeout_at(catchup_deadline, catchup_stream.next()).await {
            Ok(Some(Ok(sample))) => {
                let mibps = sample.bytes as f64
                    / (1024.0 * 1024.0)
                    / sample.elapsed.as_secs_f64().max(0.001);
                let recps = sample.records as f64 / sample.elapsed.as_secs_f64().max(0.001);
                let _ = tx.send(Event::BenchCatchupSample(BenchSample {
                    bytes: sample.bytes,
                    records: sample.records,
                    elapsed: sample.elapsed,
                    mib_per_sec: mibps,
                    records_per_sec: recps,
                }));
            }
            Ok(Some(Err(e))) => {
                return Err(e);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(CliError::BenchVerification(
                    "catchup read timed out after 5 minutes".to_string(),
                ));
            }
        }
    }
    let _ = tx.send(Event::BenchPhaseComplete(BenchPhase::Catchup));

    Ok(BenchFinalStats {
        ack_latency: if all_ack_latencies.is_empty() {
            None
        } else {
            Some(LatencyStats::compute(all_ack_latencies))
        },
        e2e_latency: if all_e2e_latencies.is_empty() {
            None
        } else {
            Some(LatencyStats::compute(all_e2e_latencies))
        },
    })
}
