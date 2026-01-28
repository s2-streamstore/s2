use std::num::NonZeroU64;

use clap::{Args, Parser, Subcommand, builder::styling};
use s2_sdk::types::{
    AccessTokenId, AccessTokenIdPrefix, AccessTokenIdStartAfter, BasinNamePrefix,
    BasinNameStartAfter, FencingToken, StreamNamePrefix, StreamNameStartAfter,
};

use crate::{
    record_format::{
        RecordFormat, RecordsIn, RecordsOut, parse_records_input_source,
        parse_records_output_source,
    },
    types::{
        AccessTokenMatcher, BasinConfig, BasinMatcher, Interval, Operation,
        PermittedOperationGroups, S2BasinAndMaybeStreamUri, S2BasinAndStreamUri, S2BasinUri,
        StorageClass, StreamConfig, StreamMatcher,
    },
};

const STYLES: styling::Styles = styling::Styles::styled()
    .header(styling::AnsiColor::Green.on_default().bold())
    .usage(styling::AnsiColor::Green.on_default().bold())
    .literal(styling::AnsiColor::Blue.on_default().bold())
    .placeholder(styling::AnsiColor::Cyan.on_default());

const GENERAL_USAGE: &str = color_print::cstr!(
    r#"
    <dim>$</dim> <bold>s2 config set access_token YOUR_ACCESS_TOKEN</bold>
    <dim>$</dim> <bold>s2 list-basins --prefix "foo" --limit 100</bold>
    "#
);

#[derive(Parser, Debug)]
#[command(name = "s2", version, override_usage = GENERAL_USAGE, styles = STYLES)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Manage CLI configuration.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// List basins or streams in a basin.
    ///
    /// List basins if basin name is not provided otherwise lists streams in
    /// the basin.
    Ls(LsArgs),

    /// List basins.
    ListBasins(ListBasinsArgs),

    /// Create a basin.
    CreateBasin(CreateBasinArgs),

    /// Delete a basin.
    DeleteBasin {
        /// Name of the basin to delete.
        basin: S2BasinUri,
    },

    /// Get basin config.
    GetBasinConfig {
        /// Basin name to get config for.
        basin: S2BasinUri,
    },

    /// Reconfigure a basin.
    ReconfigureBasin(ReconfigureBasinArgs),

    /// List access tokens.
    ListAccessTokens(ListAccessTokensArgs),

    /// Issue an access token.
    IssueAccessToken(IssueAccessTokenArgs),

    /// Revoke an access token.
    RevokeAccessToken {
        /// ID of the access token to revoke.
        #[arg(long)]
        id: AccessTokenId,
    },

    /// Get account metrics.
    GetAccountMetrics(GetAccountMetricsArgs),

    /// Get basin metrics.
    GetBasinMetrics(GetBasinMetricsArgs),

    /// Get stream metrics.
    GetStreamMetrics(GetStreamMetricsArgs),

    /// List streams.
    ListStreams(ListStreamsArgs),

    /// Create a stream.
    CreateStream(CreateStreamArgs),

    /// Delete a stream.
    DeleteStream {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Get stream config.
    GetStreamConfig {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Reconfigure a stream.
    ReconfigureStream(ReconfigureStreamArgs),

    /// Check the tail position of a stream.
    ///
    /// Returns the sequence number that will be assigned to the next record,
    /// and the timestamp of the last record.
    CheckTail {
        /// S2 URI of the format: s2://{basin}/{stream}
        #[arg(value_name = "S2_URI")]
        uri: S2BasinAndStreamUri,
    },

    /// Set a trim point for a stream.
    ///
    /// Trimming is eventually consistent, and trimmed records may be visible
    /// for a brief period.
    Trim(TrimArgs),

    /// Set a fencing token for a stream.
    ///
    /// Fencing is strongly consistent, and subsequent appends that specify a
    /// token will be rejected if it does not match.
    ///
    /// Note that fencing is a cooperative mechanism,
    /// and it is only enforced when a token is provided.
    Fence(FenceArgs),

    /// Append records to a stream.
    Append(AppendArgs),

    /// Read records from a stream.
    ///
    /// If a limit if specified, reading will stop when the limit is reached or there are no more
    /// records on the stream. If a limit is not specified, the reader will keep tailing and
    /// wait for new records.
    Read(ReadArgs),

    /// Tail a stream, showing the last N records.
    Tail(TailArgs),

    /// Benchmark a stream to measure throughput and latency.
    Bench(BenchArgs),

    /// Run S2 Lite server backed by object storage.
    ///
    /// Starts a lightweight S2-compatible server that can be backed by
    /// S3, local filesystem, or in-memory storage.
    Lite(crate::lite::LiteArgs),
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// List all configuration values.
    List,
    /// Get a configuration value.
    Get {
        /// Config key
        key: crate::config::ConfigKey,
    },
    /// Set a configuration value.
    Set {
        /// Config key
        key: crate::config::ConfigKey,
        /// Value to set
        value: String,
    },
    /// Unset a configuration value.
    Unset {
        /// Config key
        key: crate::config::ConfigKey,
    },
}

#[derive(Args, Debug)]
pub struct LsArgs {
    /// Name of the basin to manage or S2 URI with basin and optionally prefix.
    ///
    /// S2 URI is of the format: s2://{basin}/{prefix}
    #[arg(value_name = "BASIN|S2_URI")]
    pub uri: Option<S2BasinAndMaybeStreamUri>,

    /// Filter to names that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<String>,

    /// Filter to names that lexicographically start after this name.
    #[arg(short = 's', long)]
    pub start_after: Option<String>,

    /// Limit the number of items to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of items instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct ListBasinsArgs {
    /// Filter to basin names that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<BasinNamePrefix>,

    /// Filter to basin names that lexicographically start after this name.
    #[arg(short = 's', long)]
    pub start_after: Option<BasinNameStartAfter>,

    /// Limit the number of basins to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of basins instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct CreateBasinArgs {
    /// Name of the basin to create.
    pub basin: S2BasinUri,

    #[command(flatten)]
    pub config: BasinConfig,
}

#[derive(Args, Debug)]
pub struct ReconfigureBasinArgs {
    /// Name of the basin to reconfigure.
    pub basin: S2BasinUri,

    /// Create stream on append with basin defaults if it doesn't exist.
    #[arg(long)]
    pub create_stream_on_append: Option<bool>,

    /// Create stream on read with basin defaults if it doesn't exist.
    #[arg(long)]
    pub create_stream_on_read: Option<bool>,

    #[clap(flatten)]
    pub default_stream_config: StreamConfig,
}

#[derive(Args, Debug)]
pub struct ListAccessTokensArgs {
    /// List access tokens that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<AccessTokenIdPrefix>,

    /// Only return access tokens that lexicographically start after this token ID.
    #[arg(short = 's', long)]
    pub start_after: Option<AccessTokenIdStartAfter>,

    /// Limit the number of access tokens to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of access tokens instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct IssueAccessTokenArgs {
    /// Access token ID.
    #[arg(long)]
    pub id: AccessTokenId,

    /// Token validity duration (e.g., "30d", "1w", "24h"). Token expires after this duration from
    /// now.
    #[arg(long, conflicts_with = "expires_at")]
    pub expires_in: Option<humantime::Duration>,

    /// Absolute expiration time in RFC3339 format (e.g., "2024-12-31T23:59:59Z").
    #[arg(long, conflicts_with = "expires_in")]
    pub expires_at: Option<String>,

    /// Namespace streams based on the configured stream-level scope, which must be a prefix.
    /// Stream name arguments will be automatically prefixed, and the prefix will be stripped
    /// when listing streams.
    #[arg(long, default_value_t = false)]
    pub auto_prefix_streams: bool,

    /// Basin names allowed.
    /// Matches exact value if it starts with `=`, otherwise treats it as a prefix.
    #[arg(long)]
    pub basins: Option<BasinMatcher>,

    /// Stream names allowed.
    /// Matches exact value if it starts with `=`, otherwise treats it as a prefix.
    #[arg(long)]
    pub streams: Option<StreamMatcher>,

    /// Token IDs allowed.
    /// Matches exact value if it starts with `=`, otherwise treats it as a prefix.
    #[arg(long)]
    pub access_tokens: Option<AccessTokenMatcher>,

    /// Access permissions at the operation group level.
    /// The format is: "account=rw,basin=r,stream=w"
    /// where 'r' indicates read permission and 'w' indicates write permission.
    #[arg(long)]
    pub op_group_perms: Option<PermittedOperationGroups>,

    /// Operations allowed for the token.
    /// A union of allowed operations and groups is used as an effective set of allowed operations.
    #[arg(long, value_delimiter = ',')]
    pub ops: Vec<Operation>,
}

#[derive(Args, Debug)]
pub struct ListStreamsArgs {
    /// Name of the basin to manage or S2 URI with basin and optionally prefix.
    ///
    /// S2 URI is of the format: s2://{basin}/{prefix}
    #[arg(value_name = "BASIN|S2_URI")]
    pub uri: S2BasinAndMaybeStreamUri,

    /// Filter to stream names that begin with this prefix.
    #[arg(short = 'p', long)]
    pub prefix: Option<StreamNamePrefix>,

    /// Filter to stream names that lexicographically start after this name.
    #[arg(short = 's', long)]
    pub start_after: Option<StreamNameStartAfter>,

    /// Limit the number of streams to return. Acts as page size (max 1000) when using
    /// --no-auto-paginate.
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,

    /// Returns only a single page of streams instead of auto-paginating.
    #[arg(long, default_value_t = false)]
    pub no_auto_paginate: bool,
}

#[derive(Args, Debug)]
pub struct CreateStreamArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    #[command(flatten)]
    pub config: StreamConfig,
}

#[derive(Args, Debug)]
pub struct ReconfigureStreamArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    #[clap(flatten)]
    pub config: StreamConfig,
}

#[derive(Args, Debug)]
pub struct TrimArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Earliest sequence number that should be retained.
    /// This sequence number is only allowed to advance,
    /// and any regression will be ignored.
    pub trim_point: u64,

    /// Enforce fencing token.
    #[arg(short = 'f', long)]
    pub fencing_token: Option<FencingToken>,

    /// Enforce that the sequence number issued to the first record matches.
    #[arg(short = 'm', long)]
    pub match_seq_num: Option<u64>,
}

#[derive(Args, Debug)]
pub struct FenceArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// New fencing token.
    /// It may be upto 36 characters, and can be empty.
    pub new_fencing_token: FencingToken,

    /// Enforce existing fencing token.
    #[arg(short = 'f', long)]
    pub fencing_token: Option<FencingToken>,

    /// Enforce that the sequence number issued to this command matches.
    #[arg(short = 'm', long)]
    pub match_seq_num: Option<u64>,
}

#[derive(Args, Debug)]
pub struct AppendArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Enforce fencing token.
    #[arg(short = 'f', long)]
    pub fencing_token: Option<FencingToken>,

    /// Enforce that the sequence number issued to the first record matches.
    #[arg(short = 'm', long)]
    pub match_seq_num: Option<u64>,

    /// Input format.
    #[arg(long, value_enum, default_value_t)]
    pub format: RecordFormat,

    /// Input newline delimited records to append from a file or stdin.
    /// Use "-" to read from stdin.
    #[arg(short = 'i', long, value_parser = parse_records_input_source, default_value = "-")]
    pub input: RecordsIn,

    /// How long to wait for more records before flushing a batch.
    #[arg(long, default_value = "5ms")]
    pub linger: humantime::Duration,
}

#[derive(Args, Debug)]
pub struct ReadArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Starting sequence number (inclusive).
    #[arg(short = 's', long, group = "start")]
    pub seq_num: Option<u64>,

    /// Starting timestamp in milliseconds since Unix epoch (inclusive).
    #[arg(long, group = "start")]
    pub timestamp: Option<u64>,

    /// Starting timestamp as a human-friendly delta from current time e.g. "1h",
    /// which will be converted to milliseconds since Unix epoch.
    #[arg(long, group = "start")]
    pub ago: Option<humantime::Duration>,

    /// Start from N records before the tail of the stream.
    #[arg(long, group = "start")]
    pub tail_offset: Option<u64>,

    /// Limit the number of records returned.
    #[arg(short = 'n', long)]
    pub count: Option<u64>,

    /// Limit the number of bytes returned.
    #[arg(short = 'b', long)]
    pub bytes: Option<u64>,

    /// Clamp the start position at the tail position.
    #[arg(long, default_value_t = false)]
    pub clamp: bool,

    /// Exclusive end-timestamp in milliseconds since Unix epoch.
    /// If provided, results will be limited such that all records returned
    /// will have a timestamp < the one provided via `until`.
    #[arg(long)]
    pub until: Option<u64>,

    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    pub format: RecordFormat,

    /// Output records to a file or stdout.
    /// Use "-" to write to stdout.
    #[arg(short = 'o', long, value_parser = parse_records_output_source, default_value = "-")]
    pub output: RecordsOut,
}

#[derive(Args, Debug)]
pub struct TailArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    /// Output the last N records instead of the default (10).
    #[arg(short = 'n', long = "lines", default_value_t = 10)]
    pub lines: u64,

    /// Follow the stream, waiting for new records to be appended.
    #[arg(short = 'f', long, default_value_t = false)]
    pub follow: bool,

    /// Output format.
    #[arg(long, value_enum, default_value_t)]
    pub format: RecordFormat,

    /// Output records to a file or stdout.
    /// Use "-" to write to stdout.
    #[arg(short = 'o', long, value_parser = parse_records_output_source, default_value = "-")]
    pub output: RecordsOut,
}

#[derive(Args, Debug)]
pub struct BenchArgs {
    /// Name of the basin to use for the test.
    pub basin: S2BasinUri,

    /// Storage class for the test stream. Uses basin default if not specified.
    #[arg(short = 'c', long)]
    pub storage_class: Option<StorageClass>,

    /// Total metered record size in bytes (includes headers and overhead).
    #[arg(
        short = 'b',
        long,
        default_value_t = 8*1024,
        value_parser = clap::value_parser!(u32).range(128..1024*1024),
    )]
    pub record_size: u32,

    /// Target write throughput in MiB/s.
    #[arg(
        short = 't',
        long,
        value_parser = clap::value_parser!(NonZeroU64),
        default_value_t = NonZeroU64::new(1).expect("non-zero")
    )]
    pub target_mibps: NonZeroU64,

    /// Run test for this duration.
    #[arg(short = 'd', long, default_value = "60s")]
    pub duration: humantime::Duration,

    /// Delay before starting the catchup read.
    #[arg(short = 'w', long, default_value = "20s")]
    pub catchup_delay: humantime::Duration,
}

/// Time range args for gauge metrics (no interval).
#[derive(Args, Debug)]
#[command(group(clap::ArgGroup::new("start_time").required(true)))]
#[command(group(clap::ArgGroup::new("end_time").required(true)))]
pub struct TimeRangeArgs {
    /// Start time in seconds since Unix epoch.
    #[arg(long = "start-timestamp", group = "start_time")]
    pub start_timestamp: Option<u32>,

    /// Start time as human-friendly delta from current time (e.g., "2h", "1d", "0s").
    #[arg(long, group = "start_time")]
    pub start_ago: Option<humantime::Duration>,

    /// End time in seconds since Unix epoch.
    #[arg(long = "end-timestamp", group = "end_time")]
    pub end_timestamp: Option<u32>,

    /// End time as human-friendly delta from current time (e.g., "2h", "1d", "0s").
    #[arg(long, group = "end_time")]
    pub end_ago: Option<humantime::Duration>,
}

/// Time range args for accumulation metrics (with interval).
#[derive(Args, Debug)]
pub struct TimeRangeAndIntervalArgs {
    #[command(flatten)]
    pub time_range: TimeRangeArgs,

    /// Accumulation interval.
    #[arg(long)]
    pub interval: Option<Interval>,
}

/// Account metrics.
#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub enum AccountMetricCommand {
    /// Basins with at least one stream in the time range.
    ActiveBasins(TimeRangeArgs),
    /// Account operations by type.
    AccountOps(TimeRangeAndIntervalArgs),
}

/// Basin metrics.
#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub enum BasinMetricCommand {
    /// Total stored bytes across all streams (hourly).
    Storage(TimeRangeArgs),
    /// Append operations by storage class.
    AppendOps(TimeRangeAndIntervalArgs),
    /// Read operations by read type.
    ReadOps(TimeRangeAndIntervalArgs),
    /// Total bytes read across all streams.
    ReadThroughput(TimeRangeAndIntervalArgs),
    /// Total bytes appended across all streams.
    AppendThroughput(TimeRangeAndIntervalArgs),
    /// Basin operations by type.
    BasinOps(TimeRangeAndIntervalArgs),
}

/// Stream metrics.
#[derive(Subcommand, Debug)]
#[command(disable_help_subcommand = true)]
pub enum StreamMetricCommand {
    /// Total stored bytes for the stream (minutely).
    Storage(TimeRangeArgs),
}

#[derive(Args, Debug)]
#[command(subcommand_value_name = "METRIC", subcommand_help_heading = "Metrics")]
pub struct GetAccountMetricsArgs {
    #[command(subcommand)]
    pub metric: AccountMetricCommand,
}

#[derive(Args, Debug)]
#[command(subcommand_value_name = "METRIC", subcommand_help_heading = "Metrics")]
pub struct GetBasinMetricsArgs {
    /// Basin name.
    pub basin: S2BasinUri,

    #[command(subcommand)]
    pub metric: BasinMetricCommand,
}

#[derive(Args, Debug)]
#[command(subcommand_value_name = "METRIC", subcommand_help_heading = "Metrics")]
pub struct GetStreamMetricsArgs {
    /// S2 URI of the format: s2://{basin}/{stream}
    #[arg(value_name = "S2_URI")]
    pub uri: S2BasinAndStreamUri,

    #[command(subcommand)]
    pub metric: StreamMetricCommand,
}
