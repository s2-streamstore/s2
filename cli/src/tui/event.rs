use std::time::Duration;

use s2_sdk::types::{
    AccessTokenInfo, BasinInfo, Metric, SequencedRecord, StreamInfo, StreamPosition,
};

use crate::{
    error::CliError,
    types::{LatencyStats, StorageClass, StreamConfig, TimestampingMode},
};

/// Basin config info for reconfiguration
#[derive(Debug, Clone)]
pub struct BasinConfigInfo {
    pub create_stream_on_append: bool,
    pub create_stream_on_read: bool,
    // Default stream config
    pub storage_class: Option<StorageClass>,
    pub retention_age_secs: Option<u64>, // None = infinite
    pub timestamping_mode: Option<TimestampingMode>,
    pub timestamping_uncapped: bool,
}

/// Stream config info for reconfiguration
#[derive(Debug, Clone)]
pub struct StreamConfigInfo {
    pub storage_class: Option<StorageClass>,
    pub retention_age_secs: Option<u64>, // None = infinite
    pub timestamping_mode: Option<TimestampingMode>,
    pub timestamping_uncapped: bool,
    pub delete_on_empty_min_age_secs: Option<u64>, // None = disabled
}

/// Events that can occur in the TUI
#[derive(Debug)]
pub enum Event {
    /// Basins have been loaded from the API
    BasinsLoaded(Result<Vec<BasinInfo>, CliError>),

    /// Streams have been loaded from the API
    StreamsLoaded(Result<Vec<StreamInfo>, CliError>),

    /// Stream configuration loaded
    StreamConfigLoaded(Result<StreamConfig, CliError>),

    /// Tail position loaded
    TailPositionLoaded(Result<StreamPosition, CliError>),

    /// A record was received during read/tail
    RecordReceived(Result<SequencedRecord, CliError>),

    /// Read stream ended
    ReadEnded,

    /// A record was received for the PiP (picture-in-picture) tail
    PipRecordReceived(Result<SequencedRecord, CliError>),

    /// PiP read stream ended
    PipReadEnded,

    /// Basin created successfully
    BasinCreated(Result<BasinInfo, CliError>),

    /// Basin deleted successfully
    BasinDeleted(Result<String, CliError>),

    /// Stream created successfully
    StreamCreated(Result<StreamInfo, CliError>),

    /// Stream deleted successfully
    StreamDeleted(Result<String, CliError>),

    /// Basin config loaded for reconfiguration
    BasinConfigLoaded(Result<BasinConfigInfo, CliError>),

    /// Stream config loaded for reconfiguration
    StreamConfigForReconfigLoaded(Result<StreamConfigInfo, CliError>),

    /// Basin reconfigured successfully
    BasinReconfigured(Result<(), CliError>),

    /// Stream reconfigured successfully
    StreamReconfigured(Result<(), CliError>),

    /// Record appended successfully (seq_num, body_preview, header_count)
    RecordAppended(Result<(u64, String, usize), CliError>),

    /// File append progress update (appended_count, total_lines, last_seq_num)
    FileAppendProgress {
        appended: usize,
        total: usize,
        last_seq: Option<u64>,
    },

    /// File append completed (total_records, first_seq, last_seq)
    FileAppendComplete(Result<(usize, u64, u64), CliError>),

    /// Stream fenced successfully (new token)
    StreamFenced(Result<String, CliError>),

    /// Stream trimmed successfully (trim_point, new_tail_seq_num)
    StreamTrimmed(Result<(u64, u64), CliError>),

    /// Access tokens have been loaded from the API
    AccessTokensLoaded(Result<Vec<AccessTokenInfo>, CliError>),

    /// Access token issued successfully (token string)
    AccessTokenIssued(Result<String, CliError>),

    /// Access token revoked successfully (token id)
    AccessTokenRevoked(Result<String, CliError>),

    /// Account metrics loaded
    AccountMetricsLoaded(Result<Vec<Metric>, CliError>),

    /// Basin metrics loaded
    BasinMetricsLoaded(Result<Vec<Metric>, CliError>),

    /// Stream metrics loaded
    StreamMetricsLoaded(Result<Vec<Metric>, CliError>),

    /// An error occurred in a background task
    Error(CliError),

    /// Benchmark stream created
    BenchStreamCreated(Result<String, CliError>),

    /// Benchmark write sample received
    BenchWriteSample(BenchSample),

    /// Benchmark read sample received
    BenchReadSample(BenchSample),

    /// Benchmark catchup sample received
    BenchCatchupSample(BenchSample),

    /// Benchmark phase completed
    BenchPhaseComplete(BenchPhase),

    /// Benchmark finished with final stats
    BenchComplete(Result<BenchFinalStats, CliError>),
}

/// A sample from the benchmark (write, read, or catchup)
#[derive(Debug, Clone)]
pub struct BenchSample {
    pub bytes: u64,
    pub records: u64,
    pub elapsed: Duration,
    pub mib_per_sec: f64,
    pub records_per_sec: f64,
}

/// Which phase of the benchmark
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenchPhase {
    Write,
    Read,
    CatchupWait,
    Catchup,
}

#[derive(Debug, Clone)]
pub struct BenchFinalStats {
    pub ack_latency: Option<LatencyStats>,
    pub e2e_latency: Option<LatencyStats>,
}
