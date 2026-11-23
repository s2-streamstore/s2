use std::{collections::BTreeMap, fmt};

use jiff::Timestamp;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::access::AccessTokenId;

use super::{timestamp_from_epoch_secs, validate_metrics_timestamp};
use crate::error::ValidationError;

/// Interval to accumulate over for timeseries metric sets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TimeseriesInterval {
    /// Minute.
    Minute,
    /// Hour.
    Hour,
    /// Day.
    Day,
    /// An interval this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl TimeseriesInterval {
    /// Return the wire name of this timeseries interval.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Unknown(name) => name,
        }
    }

    pub(crate) fn from_api(value: MaybeKnown<api::metrics::TimeseriesInterval>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::metrics::TimeseriesInterval::Minute => Self::Minute,
            api::metrics::TimeseriesInterval::Hour => Self::Hour,
            api::metrics::TimeseriesInterval::Day => Self::Day,
        }
    }

    pub(crate) fn into_api(self) -> MaybeKnown<api::metrics::TimeseriesInterval> {
        let known = match self {
            Self::Minute => api::metrics::TimeseriesInterval::Minute,
            Self::Hour => api::metrics::TimeseriesInterval::Hour,
            Self::Day => api::metrics::TimeseriesInterval::Day,
            Self::Unknown(name) => return MaybeKnown::Unknown(name),
        };
        MaybeKnown::Known(known)
    }
}

impl fmt::Display for TimeseriesInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Time range for metrics queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub struct TimeRange {
    start_secs: u32,
    end_secs: u32,
}

impl TimeRange {
    /// Create a new [`TimeRange`] with the given start (inclusive) and end (exclusive) timestamps.
    ///
    /// Sub-second precision is floored to whole Unix seconds.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if either timestamp is outside the `0..=u32::MAX` Unix epoch
    /// second range.
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, ValidationError> {
        let start_secs = validate_metrics_timestamp(start, "start")?;
        let end_secs = validate_metrics_timestamp(end, "end")?;
        Ok(Self {
            start_secs,
            end_secs,
        })
    }

    /// Start timestamp (inclusive), floored to whole Unix seconds.
    #[must_use]
    pub fn start(&self) -> Timestamp {
        timestamp_from_epoch_secs(self.start_secs)
    }

    /// End timestamp (exclusive), floored to whole Unix seconds.
    #[must_use]
    pub fn end(&self) -> Timestamp {
        timestamp_from_epoch_secs(self.end_secs)
    }

    /// Attach an accumulation interval to this time range.
    pub fn with_interval(self, interval: TimeseriesInterval) -> TimeRangeAndInterval {
        TimeRangeAndInterval {
            range: self,
            interval: Some(interval),
        }
    }
}

/// Time range and accumulation interval for metrics queries.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct TimeRangeAndInterval {
    range: TimeRange,
    interval: Option<TimeseriesInterval>,
}

impl TimeRangeAndInterval {
    /// Create a new [`TimeRangeAndInterval`] with the given start (inclusive) and end (exclusive)
    /// timestamps.
    ///
    /// Sub-second precision is floored to whole Unix seconds.
    ///
    /// # Errors
    ///
    /// Returns [`ValidationError`] if either timestamp is outside the `0..=u32::MAX` Unix epoch
    /// second range.
    pub fn new(start: Timestamp, end: Timestamp) -> Result<Self, ValidationError> {
        Ok(Self {
            range: TimeRange::new(start, end)?,
            interval: None,
        })
    }

    /// Return the underlying time range.
    pub fn range(&self) -> TimeRange {
        self.range
    }

    /// Start timestamp (inclusive), floored to whole Unix seconds.
    #[must_use]
    pub fn start(&self) -> Timestamp {
        self.range.start()
    }

    /// End timestamp (exclusive), floored to whole Unix seconds.
    #[must_use]
    pub fn end(&self) -> Timestamp {
        self.range.end()
    }

    /// Return the interval to accumulate over, if explicitly configured.
    #[must_use]
    pub fn interval(&self) -> Option<&TimeseriesInterval> {
        self.interval.as_ref()
    }

    /// Set the interval to accumulate over for timeseries metric sets.
    pub fn with_interval(self, interval: TimeseriesInterval) -> Self {
        Self {
            interval: Some(interval),
            ..self
        }
    }
}

impl From<TimeRange> for TimeRangeAndInterval {
    fn from(range: TimeRange) -> Self {
        Self {
            range,
            interval: None,
        }
    }
}

/// Account metric set to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountMetricSet {
    /// Returns a [`LabelMetric`] representing all basins which had at least one stream within the
    /// specified time range.
    ActiveBasins(TimeRange),
    /// Returns [`AccumulationMetric`]s, one per account operation type.
    ///
    /// Each metric represents a timeseries of the number of operations, with one accumulated value
    /// per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to [`hour`](TimeseriesInterval::Hour).
    AccountOps(TimeRangeAndInterval),
    /// Returns [`AccumulationMetric`]s of estimated billable usage in US dollars, one per billing
    /// dimension with usage in the requested time range, and one named `total`.
    ///
    /// Only hours whose usage has been finalized are counted, so the most recent values lag and a
    /// daily value may cover part of a day.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to [`hour`](TimeseriesInterval::Hour),
    /// and may otherwise only be [`day`](TimeseriesInterval::Day).
    EstimatedBillableUsage(TimeRangeAndInterval),
    /// Returns one [`RecordMetric`] per given access token, outcome and source address, describing
    /// the most recent such use. Covers up to 10 most recently used addresses per token and
    /// outcome. Tokens with no recorded use are omitted. May lag by a couple of minutes.
    ///
    /// Between 1 and 50 access token IDs must be given.
    TokenActivity(Vec<AccessTokenId>),
}

impl AccountMetricSet {
    pub(crate) fn into_api(self) -> api::metrics::AccountMetricSetRequest {
        let (set, start, end, interval, token_ids) = match self {
            Self::ActiveBasins(range) => (
                api::metrics::AccountMetricSet::ActiveBasins,
                Some(range.start_secs),
                Some(range.end_secs),
                None,
                Vec::new(),
            ),
            Self::AccountOps(args) => (
                api::metrics::AccountMetricSet::AccountOps,
                Some(args.range.start_secs),
                Some(args.range.end_secs),
                args.interval,
                Vec::new(),
            ),
            Self::EstimatedBillableUsage(args) => (
                api::metrics::AccountMetricSet::EstimatedBillableUsage,
                Some(args.range.start_secs),
                Some(args.range.end_secs),
                args.interval,
                Vec::new(),
            ),
            Self::TokenActivity(token_ids) => (
                api::metrics::AccountMetricSet::TokenActivity,
                None,
                None,
                None,
                token_ids,
            ),
        };
        api::metrics::AccountMetricSetRequest {
            set,
            start,
            end,
            interval: interval.map(TimeseriesInterval::into_api),
            token_ids,
        }
    }
}

/// Basin metric set to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BasinMetricSet {
    /// Returns a [`GaugeMetric`] representing a timeseries of total stored bytes across all streams
    /// in the basin, with one observed value for each hour over the requested time range.
    Storage(TimeRange),
    /// Returns [`AccumulationMetric`]s, one per storage class.
    ///
    /// Each metric represents a timeseries of the number of append operations across all streams
    /// in the basin, with one accumulated value per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    AppendOps(TimeRangeAndInterval),
    /// Returns [`AccumulationMetric`]s, one per read type (unary, streaming).
    ///
    /// Each metric represents a timeseries of the number of read operations across all streams
    /// in the basin, with one accumulated value per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    ReadOps(TimeRangeAndInterval),
    /// Returns an [`AccumulationMetric`] representing a timeseries of total read bytes
    /// across all streams in the basin, with one accumulated value per interval
    /// over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    ReadThroughput(TimeRangeAndInterval),
    /// Returns an [`AccumulationMetric`] representing a timeseries of total appended bytes
    /// across all streams in the basin, with one accumulated value per interval
    /// over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to
    /// [`minute`](TimeseriesInterval::Minute).
    AppendThroughput(TimeRangeAndInterval),
    /// Returns [`AccumulationMetric`]s, one per basin operation type.
    ///
    /// Each metric represents a timeseries of the number of operations, with one accumulated value
    /// per interval over the requested time range.
    ///
    /// [`interval`](TimeRangeAndInterval::interval) defaults to [`hour`](TimeseriesInterval::Hour).
    BasinOps(TimeRangeAndInterval),
}

impl BasinMetricSet {
    pub(crate) fn into_api(self) -> api::metrics::BasinMetricSetRequest {
        let (set, range, interval) = match self {
            Self::Storage(range) => (api::metrics::BasinMetricSet::Storage, range, None),
            Self::AppendOps(args) => (
                api::metrics::BasinMetricSet::AppendOps,
                args.range,
                args.interval,
            ),
            Self::ReadOps(args) => (
                api::metrics::BasinMetricSet::ReadOps,
                args.range,
                args.interval,
            ),
            Self::ReadThroughput(args) => (
                api::metrics::BasinMetricSet::ReadThroughput,
                args.range,
                args.interval,
            ),
            Self::AppendThroughput(args) => (
                api::metrics::BasinMetricSet::AppendThroughput,
                args.range,
                args.interval,
            ),
            Self::BasinOps(args) => (
                api::metrics::BasinMetricSet::BasinOps,
                args.range,
                args.interval,
            ),
        };
        api::metrics::BasinMetricSetRequest {
            set,
            start: Some(range.start_secs),
            end: Some(range.end_secs),
            interval: interval.map(TimeseriesInterval::into_api),
        }
    }
}

/// Stream metric set to return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMetricSet {
    /// Returns a [`GaugeMetric`] representing a timeseries of total stored bytes for the stream,
    /// with one observed value for each minute over the requested time range.
    Storage(TimeRange),
}

impl StreamMetricSet {
    pub(crate) fn into_api(self) -> api::metrics::StreamMetricSetRequest {
        match self {
            Self::Storage(range) => api::metrics::StreamMetricSetRequest {
                set: api::metrics::StreamMetricSet::Storage,
                start: Some(range.start_secs),
                end: Some(range.end_secs),
                interval: None,
            },
        }
    }
}

/// Unit in which metric values are measured.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MetricUnit {
    /// Size in bytes.
    Bytes,
    /// Number of operations.
    Operations,
    /// US dollars.
    Usd,
    /// A unit this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl MetricUnit {
    /// Return the wire name of this metric unit.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Bytes => "bytes",
            Self::Operations => "operations",
            Self::Usd => "usd",
            Self::Unknown(name) => name,
        }
    }

    pub(crate) fn from_api(value: MaybeKnown<api::metrics::MetricUnit>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::metrics::MetricUnit::Bytes => Self::Bytes,
            api::metrics::MetricUnit::Operations => Self::Operations,
            api::metrics::MetricUnit::Usd => Self::Usd,
        }
    }
}

impl fmt::Display for MetricUnit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Single named value.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct ScalarMetric {
    /// Metric name.
    pub name: String,
    /// Unit for the metric value.
    pub unit: MetricUnit,
    /// Metric value.
    pub value: f64,
}

impl ScalarMetric {
    /// Construct a [`ScalarMetric`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(name: impl Into<String>, unit: MetricUnit, value: f64) -> Self {
        Self {
            name: name.into(),
            unit,
            value,
        }
    }
}

/// Named series of `(timestamp, value)` datapoints, each representing an accumulation over a
/// specified interval.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct AccumulationMetric {
    /// Timeseries name.
    pub name: String,
    /// Unit for the accumulated values.
    pub unit: MetricUnit,
    /// The interval at which datapoints are accumulated.
    pub interval: TimeseriesInterval,
    /// Series of `(timestamp, value)` datapoints. Each datapoint represents the accumulated
    /// `value` for the time period starting at the `timestamp`, spanning one `interval`.
    pub values: Vec<(Timestamp, f64)>,
}

impl AccumulationMetric {
    /// Construct an [`AccumulationMetric`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        unit: MetricUnit,
        interval: TimeseriesInterval,
        values: Vec<(Timestamp, f64)>,
    ) -> Self {
        Self {
            name: name.into(),
            unit,
            interval,
            values,
        }
    }
}

/// Named series of `(timestamp, value)` datapoints, each representing an instantaneous value.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct GaugeMetric {
    /// Timeseries name.
    pub name: String,
    /// Unit for the instantaneous values.
    pub unit: MetricUnit,
    /// Series of `(timestamp, value)` datapoints. Each datapoint represents the `value` at the
    /// instant of the `timestamp`.
    pub values: Vec<(Timestamp, f64)>,
}

impl GaugeMetric {
    /// Construct a [`GaugeMetric`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(name: impl Into<String>, unit: MetricUnit, values: Vec<(Timestamp, f64)>) -> Self {
        Self {
            name: name.into(),
            unit,
            values,
        }
    }
}

/// Set of string labels.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LabelMetric {
    /// Label name.
    pub name: String,
    /// Label values.
    pub values: Vec<String>,
}

impl LabelMetric {
    /// Construct a [`LabelMetric`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(name: impl Into<String>, values: Vec<String>) -> Self {
        Self {
            name: name.into(),
            values,
        }
    }
}

/// Named set of string attributes observed at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordMetric {
    /// Record name.
    pub name: String,
    /// Timestamp of the record.
    pub timestamp: Timestamp,
    /// Named string attributes of the record.
    pub fields: BTreeMap<String, String>,
}

impl RecordMetric {
    /// Construct a [`RecordMetric`].
    ///
    /// This is intended for building fixtures in downstream tests.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        timestamp: Timestamp,
        fields: BTreeMap<String, String>,
    ) -> Self {
        Self {
            name: name.into(),
            timestamp,
            fields,
        }
    }
}

/// Individual metric in a returned metric set.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Metric {
    /// Single named value.
    Scalar(ScalarMetric),
    /// Named series of `(timestamp, value)` datapoints, each representing an accumulation over a
    /// specified interval.
    Accumulation(AccumulationMetric),
    /// Named series of `(timestamp, value)` datapoints, each representing an instantaneous value.
    Gauge(GaugeMetric),
    /// Set of string labels.
    Label(LabelMetric),
    /// Named set of string attributes observed at a point in time.
    Record(RecordMetric),
    /// A kind of metric this version of the SDK does not recognize, by its wire name.
    Unknown(String),
}

impl Metric {
    pub(crate) fn from_api(value: MaybeKnown<api::metrics::Metric>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::metrics::Metric::Scalar(sm) => Self::Scalar(ScalarMetric {
                name: sm.name,
                unit: MetricUnit::from_api(sm.unit),
                value: sm.value,
            }),
            api::metrics::Metric::Accumulation(am) => Self::Accumulation(AccumulationMetric {
                name: am.name,
                unit: MetricUnit::from_api(am.unit),
                interval: TimeseriesInterval::from_api(am.interval),
                values: am
                    .values
                    .into_iter()
                    .map(|(ts, v)| (timestamp_from_epoch_secs(ts), v))
                    .collect(),
            }),
            api::metrics::Metric::Gauge(gm) => Self::Gauge(GaugeMetric {
                name: gm.name,
                unit: MetricUnit::from_api(gm.unit),
                values: gm
                    .values
                    .into_iter()
                    .map(|(ts, v)| (timestamp_from_epoch_secs(ts), v))
                    .collect(),
            }),
            api::metrics::Metric::Label(lm) => Self::Label(LabelMetric {
                name: lm.name,
                values: lm.values,
            }),
            api::metrics::Metric::Record(rm) => Self::Record(RecordMetric {
                name: rm.name,
                timestamp: timestamp_from_epoch_secs(rm.timestamp),
                fields: rm.fields,
            }),
        }
    }
}
