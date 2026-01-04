use compact_str::CompactString;
use s2_common::types;
use serde::{Deserialize, Serialize};
#[cfg(feature = "utoipa")]
use utoipa::{IntoParams, ToSchema};

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TimeseriesInterval {
    Minute,
    Hour,
    Day,
}

impl From<TimeseriesInterval> for types::metrics::TimeseriesInterval {
    fn from(value: TimeseriesInterval) -> Self {
        match value {
            TimeseriesInterval::Minute => types::metrics::TimeseriesInterval::Minute,
            TimeseriesInterval::Hour => types::metrics::TimeseriesInterval::Hour,
            TimeseriesInterval::Day => types::metrics::TimeseriesInterval::Day,
        }
    }
}

impl From<types::metrics::TimeseriesInterval> for TimeseriesInterval {
    fn from(value: types::metrics::TimeseriesInterval) -> Self {
        match value {
            types::metrics::TimeseriesInterval::Minute => Self::Minute,
            types::metrics::TimeseriesInterval::Hour => Self::Hour,
            types::metrics::TimeseriesInterval::Day => Self::Day,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct AccountMetricSetRequest {
    /// Metric set to return.
    pub set: AccountMetricSet,
    /// Start timestamp as Unix epoch seconds, if applicable for the metric set.
    pub start: Option<u32>,
    /// End timestamp as Unix epoch seconds, if applicable for the metric set.
    pub end: Option<u32>,
    /// Interval to aggregate over for timeseries metric sets.
    pub interval: Option<TimeseriesInterval>,
}

impl From<AccountMetricSetRequest> for types::metrics::AccountMetricsRequest {
    fn from(value: AccountMetricSetRequest) -> Self {
        Self {
            set: match value.set {
                AccountMetricSet::ActiveBasins => types::metrics::AccountMetricSet::ActiveBasins,
                AccountMetricSet::AccountOps => types::metrics::AccountMetricSet::AccountOps,
            },
            start: value.start,
            end: value.end,
            interval: value.interval.map(Into::into),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AccountMetricSet {
    /// Set of all basins that had at least one stream during the specified period.
    ActiveBasins,
    /// Count of append RPC operations, per interval.
    AccountOps,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct BasinMetricSetRequest {
    /// Metric set to return.
    pub set: BasinMetricSet,
    /// Start timestamp as Unix epoch seconds, if applicable for the metric set.
    pub start: Option<u32>,
    /// End timestamp as Unix epoch seconds, if applicable for the metric set.
    pub end: Option<u32>,
    /// Interval to aggregate over for timeseries metric sets.
    pub interval: Option<TimeseriesInterval>,
}

impl From<BasinMetricSetRequest> for types::metrics::BasinMetricsRequest {
    fn from(value: BasinMetricSetRequest) -> Self {
        Self {
            set: match value.set {
                BasinMetricSet::AppendOps => types::metrics::BasinMetricSet::AppendOps,
                BasinMetricSet::AppendThroughput => {
                    types::metrics::BasinMetricSet::AppendThroughput
                }
                BasinMetricSet::BasinOps => types::metrics::BasinMetricSet::BasinOps,
                BasinMetricSet::ReadOps => types::metrics::BasinMetricSet::ReadOps,
                BasinMetricSet::ReadThroughput => types::metrics::BasinMetricSet::ReadThroughput,
                BasinMetricSet::Storage => types::metrics::BasinMetricSet::Storage,
            },
            start: value.start,
            end: value.end,
            interval: value.interval.map(Into::into),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum BasinMetricSet {
    /// Amount of stored data, per hour, aggregated over all streams in a basin.
    Storage,
    /// Append operations, per interval.
    AppendOps,
    /// Read operations, per interval.
    ReadOps,
    /// Read bytes, per interval.
    ReadThroughput,
    /// Appended bytes, per interval.
    AppendThroughput,
    /// Count of basin RPC operations, per interval.
    BasinOps,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct StreamMetricSetRequest {
    /// Metric set to return.
    pub set: StreamMetricSet,
    /// Start timestamp as Unix epoch seconds, if applicable for the metric set.
    pub start: Option<u32>,
    /// End timestamp as Unix epoch seconds, if applicable for metric set.
    pub end: Option<u32>,
    /// Interval to aggregate over for timeseries metric sets.
    pub interval: Option<TimeseriesInterval>,
}

impl From<StreamMetricSetRequest> for types::metrics::StreamMetricsRequest {
    fn from(value: StreamMetricSetRequest) -> Self {
        Self {
            set: match value.set {
                StreamMetricSet::Storage => types::metrics::StreamMetricSet::Storage,
            },
            start: value.start,
            end: value.end,
            interval: value.interval.map(Into::into),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum StreamMetricSet {
    /// Amount of stored data, per minute, for a specific stream.
    Storage,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum MetricUnit {
    Bytes,
    Operations,
}

impl From<types::metrics::MetricUnit> for MetricUnit {
    fn from(value: types::metrics::MetricUnit) -> Self {
        match value {
            types::metrics::MetricUnit::Bytes => MetricUnit::Bytes,
            types::metrics::MetricUnit::Operations => MetricUnit::Operations,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ScalarMetric {
    /// Metric name.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub name: CompactString,
    /// Unit of the metric.
    pub unit: MetricUnit,
    /// Metric value.
    pub value: f64,
}

impl From<types::metrics::ScalarMetric> for ScalarMetric {
    fn from(value: types::metrics::ScalarMetric) -> Self {
        Self {
            name: value.name,
            unit: value.unit.into(),
            value: value.value,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct AccumulationMetric {
    /// Timeseries name.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub name: CompactString,
    /// Unit of the metric.
    pub unit: MetricUnit,
    /// The interval at which data points are accumulated.
    pub interval: TimeseriesInterval,
    /// Timeseries values.
    /// Each element is a tuple of a timestamp in Unix epoch seconds and a data point.
    /// The data point represents the accumulated value for the time period starting at the timestamp, spanning one `interval`.
    pub values: Vec<(u32, f64)>,
}

impl From<types::metrics::AccumulationMetric> for AccumulationMetric {
    fn from(value: types::metrics::AccumulationMetric) -> Self {
        Self {
            name: value.name,
            unit: value.unit.into(),
            interval: value.interval.into(),
            values: value.values,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct GaugeMetric {
    /// Timeseries name.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub name: CompactString,
    /// Unit of the metric.
    pub unit: MetricUnit,
    /// Timeseries values.
    /// Each element is a tuple of a timestamp in Unix epoch seconds and a data point.
    /// The data point represents the value at the instant of the timestamp.
    pub values: Vec<(u32, f64)>,
}

impl From<types::metrics::GaugeMetric> for GaugeMetric {
    fn from(value: types::metrics::GaugeMetric) -> Self {
        Self {
            name: value.name,
            unit: value.unit.into(),
            values: value.values,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct LabelMetric {
    /// Label name.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub name: CompactString,
    /// Label values.
    pub values: Vec<String>,
}

impl From<types::metrics::LabelMetric> for LabelMetric {
    fn from(value: types::metrics::LabelMetric) -> Self {
        Self {
            name: value.name,
            values: value.values,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum Metric {
    /// Single named value.
    Scalar(ScalarMetric),
    /// Named series of `(timestamp, value)` points representing an accumulation over a specified interval.
    Accumulation(AccumulationMetric),
    /// Named series of `(timestamp, value)` points each representing an instantaneous value.
    Gauge(GaugeMetric),
    /// Set of string labels.
    Label(LabelMetric),
}

impl From<types::metrics::Metric> for Metric {
    fn from(value: types::metrics::Metric) -> Self {
        match value {
            types::metrics::Metric::Scalar(scalar) => Metric::Scalar(scalar.into()),
            types::metrics::Metric::Accumulation(timeseries) => {
                Metric::Accumulation(timeseries.into())
            }
            types::metrics::Metric::Gauge(timeseries) => Metric::Gauge(timeseries.into()),
            types::metrics::Metric::Label(label) => Metric::Label(label.into()),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct MetricSetResponse {
    /// Metrics comprising the set.
    pub values: Vec<Metric>,
}

impl From<types::metrics::MetricsResponse> for MetricSetResponse {
    fn from(value: types::metrics::MetricsResponse) -> Self {
        Self {
            values: value.values.into_iter().map(Into::into).collect(),
        }
    }
}
