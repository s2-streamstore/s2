use std::collections::BTreeMap;

use jiff::Timestamp;
use s2_api::v1::{self as api, MaybeKnown};
use s2_common::{ValidationError, access::AccessTokenId};

use super::{timestamp_from_epoch_secs, validate_metrics_timestamp};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Interval to accumulate over for timeseries metric sets.
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

impl From<TimeseriesInterval> for MaybeKnown<api::metrics::TimeseriesInterval> {
    fn from(value: TimeseriesInterval) -> Self {
        let known = match value {
            TimeseriesInterval::Minute => api::metrics::TimeseriesInterval::Minute,
            TimeseriesInterval::Hour => api::metrics::TimeseriesInterval::Hour,
            TimeseriesInterval::Day => api::metrics::TimeseriesInterval::Day,
            TimeseriesInterval::Unknown(name) => return Self::Unknown(name),
        };
        Self::Known(known)
    }
}

impl From<MaybeKnown<api::metrics::TimeseriesInterval>> for TimeseriesInterval {
    fn from(value: MaybeKnown<api::metrics::TimeseriesInterval>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::metrics::TimeseriesInterval::Minute => TimeseriesInterval::Minute,
            api::metrics::TimeseriesInterval::Hour => TimeseriesInterval::Hour,
            api::metrics::TimeseriesInterval::Day => TimeseriesInterval::Day,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Time range for metrics queries.
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
    pub fn start(&self) -> Timestamp {
        timestamp_from_epoch_secs(self.start_secs)
    }

    /// End timestamp (exclusive), floored to whole Unix seconds.
    pub fn end(&self) -> Timestamp {
        timestamp_from_epoch_secs(self.end_secs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Time range and accumulation interval for metrics queries.
pub struct TimeRangeAndInterval {
    start_secs: u32,
    end_secs: u32,
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
        let start_secs = validate_metrics_timestamp(start, "start")?;
        let end_secs = validate_metrics_timestamp(end, "end")?;
        Ok(Self {
            start_secs,
            end_secs,
            interval: None,
        })
    }

    /// Start timestamp (inclusive), floored to whole Unix seconds.
    pub fn start(&self) -> Timestamp {
        timestamp_from_epoch_secs(self.start_secs)
    }

    /// End timestamp (exclusive), floored to whole Unix seconds.
    pub fn end(&self) -> Timestamp {
        timestamp_from_epoch_secs(self.end_secs)
    }

    /// Return the interval to accumulate over, if explicitly configured.
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

#[derive(Debug, Clone, PartialEq, Eq)]
/// Account metric set to return.
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

impl From<AccountMetricSet> for api::metrics::AccountMetricSetRequest {
    fn from(value: AccountMetricSet) -> Self {
        let (set, start, end, interval, token_ids) = match value {
            AccountMetricSet::ActiveBasins(args) => (
                api::metrics::AccountMetricSet::ActiveBasins,
                Some(args.start_secs),
                Some(args.end_secs),
                None,
                Vec::new(),
            ),
            AccountMetricSet::AccountOps(args) => (
                api::metrics::AccountMetricSet::AccountOps,
                Some(args.start_secs),
                Some(args.end_secs),
                args.interval,
                Vec::new(),
            ),
            AccountMetricSet::EstimatedBillableUsage(args) => (
                api::metrics::AccountMetricSet::EstimatedBillableUsage,
                Some(args.start_secs),
                Some(args.end_secs),
                args.interval,
                Vec::new(),
            ),
            AccountMetricSet::TokenActivity(token_ids) => (
                api::metrics::AccountMetricSet::TokenActivity,
                None,
                None,
                None,
                token_ids,
            ),
        };
        Self {
            set,
            start,
            end,
            interval: interval.map(Into::into),
            token_ids,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Basin metric set to return.
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

impl From<BasinMetricSet> for api::metrics::BasinMetricSetRequest {
    fn from(value: BasinMetricSet) -> Self {
        let (set, start, end, interval) = match value {
            BasinMetricSet::Storage(args) => (
                api::metrics::BasinMetricSet::Storage,
                args.start_secs,
                args.end_secs,
                None,
            ),
            BasinMetricSet::AppendOps(args) => (
                api::metrics::BasinMetricSet::AppendOps,
                args.start_secs,
                args.end_secs,
                args.interval,
            ),
            BasinMetricSet::ReadOps(args) => (
                api::metrics::BasinMetricSet::ReadOps,
                args.start_secs,
                args.end_secs,
                args.interval,
            ),
            BasinMetricSet::ReadThroughput(args) => (
                api::metrics::BasinMetricSet::ReadThroughput,
                args.start_secs,
                args.end_secs,
                args.interval,
            ),
            BasinMetricSet::AppendThroughput(args) => (
                api::metrics::BasinMetricSet::AppendThroughput,
                args.start_secs,
                args.end_secs,
                args.interval,
            ),
            BasinMetricSet::BasinOps(args) => (
                api::metrics::BasinMetricSet::BasinOps,
                args.start_secs,
                args.end_secs,
                args.interval,
            ),
        };
        Self {
            set,
            start: Some(start),
            end: Some(end),
            interval: interval.map(Into::into),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Stream metric set to return.
pub enum StreamMetricSet {
    /// Returns a [`GaugeMetric`] representing a timeseries of total stored bytes for the stream,
    /// with one observed value for each minute over the requested time range.
    Storage(TimeRange),
}

impl From<StreamMetricSet> for api::metrics::StreamMetricSetRequest {
    fn from(value: StreamMetricSet) -> Self {
        let (set, start, end, interval) = match value {
            StreamMetricSet::Storage(args) => (
                api::metrics::StreamMetricSet::Storage,
                args.start_secs,
                args.end_secs,
                None,
            ),
        };
        Self {
            set,
            start: Some(start),
            end: Some(end),
            interval,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Unit in which metric values are measured.
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

impl From<MaybeKnown<api::metrics::MetricUnit>> for MetricUnit {
    fn from(value: MaybeKnown<api::metrics::MetricUnit>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::metrics::MetricUnit::Bytes => MetricUnit::Bytes,
            api::metrics::MetricUnit::Operations => MetricUnit::Operations,
            api::metrics::MetricUnit::Usd => MetricUnit::Usd,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Single named value.
pub struct ScalarMetric {
    /// Metric name.
    pub name: String,
    /// Unit for the metric value.
    pub unit: MetricUnit,
    /// Metric value.
    pub value: f64,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Named series of `(timestamp, value)` datapoints, each representing an accumulation over a
/// specified interval.
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

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Named series of `(timestamp, value)` datapoints, each representing an instantaneous value.
pub struct GaugeMetric {
    /// Timeseries name.
    pub name: String,
    /// Unit for the instantaneous values.
    pub unit: MetricUnit,
    /// Series of `(timestamp, value)` datapoints. Each datapoint represents the `value` at the
    /// instant of the `timestamp`.
    pub values: Vec<(Timestamp, f64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Set of string labels.
pub struct LabelMetric {
    /// Label name.
    pub name: String,
    /// Label values.
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
/// Named set of string attributes observed at a point in time.
pub struct RecordMetric {
    /// Record name.
    pub name: String,
    /// Timestamp of the record.
    pub timestamp: Timestamp,
    /// Named string attributes of the record.
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
/// Individual metric in a returned metric set.
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

impl From<MaybeKnown<api::metrics::Metric>> for Metric {
    fn from(value: MaybeKnown<api::metrics::Metric>) -> Self {
        let value = match value {
            MaybeKnown::Known(value) => value,
            MaybeKnown::Unknown(name) => return Self::Unknown(name),
        };
        match value {
            api::metrics::Metric::Scalar(sm) => Metric::Scalar(ScalarMetric {
                name: sm.name,
                unit: sm.unit.into(),
                value: sm.value,
            }),
            api::metrics::Metric::Accumulation(am) => Metric::Accumulation(AccumulationMetric {
                name: am.name,
                unit: am.unit.into(),
                interval: am.interval.into(),
                values: am
                    .values
                    .into_iter()
                    .map(|(ts, v)| (timestamp_from_epoch_secs(ts), v))
                    .collect(),
            }),
            api::metrics::Metric::Gauge(gm) => Metric::Gauge(GaugeMetric {
                name: gm.name,
                unit: gm.unit.into(),
                values: gm
                    .values
                    .into_iter()
                    .map(|(ts, v)| (timestamp_from_epoch_secs(ts), v))
                    .collect(),
            }),
            api::metrics::Metric::Label(lm) => Metric::Label(LabelMetric {
                name: lm.name,
                values: lm.values,
            }),
            api::metrics::Metric::Record(rm) => Metric::Record(RecordMetric {
                name: rm.name,
                timestamp: timestamp_from_epoch_secs(rm.timestamp),
                fields: rm.fields,
            }),
        }
    }
}
