use compact_str::CompactString;
use serde::{Deserialize, Serialize};

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum TimeseriesInterval {
    Minute,
    Hour,
    Day,
}

impl From<TimeseriesInterval> for s2_common::metrics::TimeseriesInterval {
    fn from(value: TimeseriesInterval) -> Self {
        match value {
            TimeseriesInterval::Minute => s2_common::metrics::TimeseriesInterval::Minute,
            TimeseriesInterval::Hour => s2_common::metrics::TimeseriesInterval::Hour,
            TimeseriesInterval::Day => s2_common::metrics::TimeseriesInterval::Day,
        }
    }
}

impl From<s2_common::metrics::TimeseriesInterval> for TimeseriesInterval {
    fn from(value: s2_common::metrics::TimeseriesInterval) -> Self {
        match value {
            s2_common::metrics::TimeseriesInterval::Minute => Self::Minute,
            s2_common::metrics::TimeseriesInterval::Hour => Self::Hour,
            s2_common::metrics::TimeseriesInterval::Day => Self::Day,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct AccountMetricSetRequest {
    /// Metric set to return.
    pub set: AccountMetricSet,
    /// Start timestamp as Unix epoch seconds, if applicable for the metric set. Time ranges may span at most 90 days.
    pub start: Option<u32>,
    /// End timestamp as Unix epoch seconds, if applicable for the metric set.
    pub end: Option<u32>,
    /// Interval to aggregate over for timeseries metric sets.
    pub interval: Option<TimeseriesInterval>,
}

impl From<AccountMetricSetRequest> for s2_common::metrics::AccountMetricsRequest {
    fn from(value: AccountMetricSetRequest) -> Self {
        Self {
            set: match value.set {
                AccountMetricSet::ActiveBasins => {
                    s2_common::metrics::AccountMetricSet::ActiveBasins
                }
                AccountMetricSet::AccountOps => s2_common::metrics::AccountMetricSet::AccountOps,
                AccountMetricSet::EstimatedBillableUsage => {
                    s2_common::metrics::AccountMetricSet::EstimatedBillableUsage
                }
            },
            start: value.start,
            end: value.end,
            interval: value.interval.map(Into::into),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
/// Account-level metric sets.
/// `estimated-billable-usage` returns estimated USD by billing dimension and as a `total` series.
/// It uses list prices, excluding credits, taxes, and customer-specific pricing; it is not an invoice total.
/// Supports hour (default) and day intervals. Only complete UTC buckets wholly within the requested
/// range are returned, and every hour in a bucket must have finished billing processing.
/// Completed buckets with no usage have a zero total; pending buckets are omitted.
/// Dimension series appear when they have usage in a returned bucket, with zeroes in other completed
/// buckets. Accounts without processed billing hours return no series.
pub enum AccountMetricSet {
    /// Set of all basins that had at least one stream during the specified period.
    ActiveBasins,
    /// Count of account-level RPC operations, per interval.
    AccountOps,
    /// Estimated USD billable usage by dimension, plus a total.
    EstimatedBillableUsage,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct BasinMetricSetRequest {
    /// Metric set to return.
    pub set: BasinMetricSet,
    /// Start timestamp as Unix epoch seconds, if applicable for the metric set. Time ranges may span at most 90 days.
    pub start: Option<u32>,
    /// End timestamp as Unix epoch seconds, if applicable for the metric set.
    pub end: Option<u32>,
    /// Interval to aggregate over for timeseries metric sets.
    pub interval: Option<TimeseriesInterval>,
}

impl From<BasinMetricSetRequest> for s2_common::metrics::BasinMetricsRequest {
    fn from(value: BasinMetricSetRequest) -> Self {
        Self {
            set: match value.set {
                BasinMetricSet::AppendOps => s2_common::metrics::BasinMetricSet::AppendOps,
                BasinMetricSet::AppendThroughput => {
                    s2_common::metrics::BasinMetricSet::AppendThroughput
                }
                BasinMetricSet::BasinOps => s2_common::metrics::BasinMetricSet::BasinOps,
                BasinMetricSet::ReadOps => s2_common::metrics::BasinMetricSet::ReadOps,
                BasinMetricSet::ReadThroughput => {
                    s2_common::metrics::BasinMetricSet::ReadThroughput
                }
                BasinMetricSet::Storage => s2_common::metrics::BasinMetricSet::Storage,
            },
            start: value.start,
            end: value.end,
            interval: value.interval.map(Into::into),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema, utoipa::IntoParams))]
#[cfg_attr(feature = "utoipa", into_params(parameter_in = Query))]
pub struct StreamMetricSetRequest {
    /// Metric set to return.
    pub set: StreamMetricSet,
    /// Start timestamp as Unix epoch seconds, if applicable for the metric set. Time ranges may span at most 90 days.
    pub start: Option<u32>,
    /// End timestamp as Unix epoch seconds, if applicable for metric set.
    pub end: Option<u32>,
    /// Interval to aggregate over for timeseries metric sets.
    pub interval: Option<TimeseriesInterval>,
}

impl From<StreamMetricSetRequest> for s2_common::metrics::StreamMetricsRequest {
    fn from(value: StreamMetricSetRequest) -> Self {
        Self {
            set: match value.set {
                StreamMetricSet::Storage => s2_common::metrics::StreamMetricSet::Storage,
            },
            start: value.start,
            end: value.end,
            interval: value.interval.map(Into::into),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum StreamMetricSet {
    /// Amount of stored data, per minute, for a specific stream.
    Storage,
}

#[rustfmt::skip]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
pub enum MetricUnit {
    Bytes,
    Operations,
    /// US dollars, without currency conversion.
    Usd,
}

impl From<s2_common::metrics::MetricUnit> for MetricUnit {
    fn from(value: s2_common::metrics::MetricUnit) -> Self {
        match value {
            s2_common::metrics::MetricUnit::Bytes => MetricUnit::Bytes,
            s2_common::metrics::MetricUnit::Operations => MetricUnit::Operations,
            s2_common::metrics::MetricUnit::Usd => MetricUnit::Usd,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct ScalarMetric {
    /// Metric name.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub name: CompactString,
    /// Unit of the metric.
    pub unit: MetricUnit,
    /// Metric value.
    pub value: f64,
}

impl From<s2_common::metrics::ScalarMetric> for ScalarMetric {
    fn from(value: s2_common::metrics::ScalarMetric) -> Self {
        Self {
            name: value.name,
            unit: value.unit.into(),
            value: value.value,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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
    /// The series need not contain every interval in the requested range. An omitted interval is not
    /// necessarily zero; availability and completeness depend on the metric set.
    pub values: Vec<(u32, f64)>,
}

impl From<s2_common::metrics::AccumulationMetric> for AccumulationMetric {
    fn from(value: s2_common::metrics::AccumulationMetric) -> Self {
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
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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

impl From<s2_common::metrics::GaugeMetric> for GaugeMetric {
    fn from(value: s2_common::metrics::GaugeMetric) -> Self {
        Self {
            name: value.name,
            unit: value.unit.into(),
            values: value.values,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct LabelMetric {
    /// Label name.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub name: CompactString,
    /// Label values.
    pub values: Vec<String>,
}

impl From<s2_common::metrics::LabelMetric> for LabelMetric {
    fn from(value: s2_common::metrics::LabelMetric) -> Self {
        Self {
            name: value.name,
            values: value.values,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
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

impl From<s2_common::metrics::Metric> for Metric {
    fn from(value: s2_common::metrics::Metric) -> Self {
        match value {
            s2_common::metrics::Metric::Scalar(scalar) => Metric::Scalar(scalar.into()),
            s2_common::metrics::Metric::Accumulation(timeseries) => {
                Metric::Accumulation(timeseries.into())
            }
            s2_common::metrics::Metric::Gauge(timeseries) => Metric::Gauge(timeseries.into()),
            s2_common::metrics::Metric::Label(label) => Metric::Label(label.into()),
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct MetricSetResponse {
    /// Metrics comprising the set.
    pub values: Vec<Metric>,
}

impl From<s2_common::metrics::MetricsResponse> for MetricSetResponse {
    fn from(value: s2_common::metrics::MetricsResponse) -> Self {
        Self {
            values: value.values.into_iter().map(Into::into).collect(),
        }
    }
}
