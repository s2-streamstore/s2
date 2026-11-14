use std::collections::BTreeMap;

use compact_str::CompactString;
use s2_common::access::AccessTokenId;
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
#[derive(Debug, Clone)]
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
    /// Access token IDs, as a repeated parameter. Between 1 and 50 are required for the `token-activity` metric set.
    #[cfg_attr(feature = "utoipa", param(rename = "token_id", value_type = Vec<String>, max_items = 50, required = false))]
    pub token_ids: Vec<AccessTokenId>,
}

// Hand-written because `token_id` repeats, which derived query (de)serialization rejects.
impl Serialize for AccountMetricSetRequest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("set", &self.set)?;
        if let Some(start) = &self.start {
            map.serialize_entry("start", start)?;
        }
        if let Some(end) = &self.end {
            map.serialize_entry("end", end)?;
        }
        if let Some(interval) = &self.interval {
            map.serialize_entry("interval", interval)?;
        }
        for token_id in &self.token_ids {
            map.serialize_entry("token_id", token_id)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for AccountMetricSetRequest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error, IgnoredAny, MapAccess, Visitor};

        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Set,
            Start,
            End,
            Interval,
            TokenId,
            #[serde(other)]
            Other,
        }

        fn set_once<'de, A: MapAccess<'de>, T: Deserialize<'de>>(
            map: &mut A,
            slot: &mut Option<T>,
            field: &'static str,
        ) -> Result<(), A::Error> {
            if slot.is_some() {
                return Err(A::Error::duplicate_field(field));
            }
            *slot = Some(map.next_value()?);
            Ok(())
        }

        struct RequestVisitor;

        impl<'de> Visitor<'de> for RequestVisitor {
            type Value = AccountMetricSetRequest;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("account metric set parameters")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut set = None;
                let mut start = None;
                let mut end = None;
                let mut interval = None;
                let mut token_ids = Vec::new();
                while let Some(field) = map.next_key()? {
                    match field {
                        Field::Set => set_once(&mut map, &mut set, "set")?,
                        Field::Start => set_once(&mut map, &mut start, "start")?,
                        Field::End => set_once(&mut map, &mut end, "end")?,
                        Field::Interval => set_once(&mut map, &mut interval, "interval")?,
                        Field::TokenId => token_ids.push(map.next_value()?),
                        Field::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(AccountMetricSetRequest {
                    set: set.ok_or_else(|| A::Error::missing_field("set"))?,
                    start: start.flatten(),
                    end: end.flatten(),
                    interval: interval.flatten(),
                    token_ids,
                })
            }
        }

        deserializer.deserialize_map(RequestVisitor)
    }
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
                AccountMetricSet::TokenActivity => {
                    s2_common::metrics::AccountMetricSet::TokenActivity
                }
            },
            start: value.start,
            end: value.end,
            interval: value.interval.map(Into::into),
            token_ids: value.token_ids,
        }
    }
}

#[rustfmt::skip]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "kebab-case")]
/// Account-level metric sets.
/// `estimated-billable-usage` returns estimated USD by billing dimension and as a `total` series.
/// Supports hour (default) and day intervals, aggregating finalized hours. Daily points may be partial.
pub enum AccountMetricSet {
    /// Set of all basins that had at least one stream during the specified period.
    ActiveBasins,
    /// Count of account-level RPC operations, per interval.
    AccountOps,
    /// Estimated USD billable usage by dimension, plus a total.
    EstimatedBillableUsage,
    /// Most recent use of each access token given by `token_id`, as one record per token.
    /// Tokens with no recorded use are omitted.
    TokenActivity,
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
pub struct RecordMetric {
    /// Record name.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub name: CompactString,
    /// Timestamp of the record in Unix epoch seconds.
    pub timestamp: u32,
    /// Named string attributes of the record.
    pub fields: BTreeMap<String, String>,
}

impl From<s2_common::metrics::RecordMetric> for RecordMetric {
    fn from(value: s2_common::metrics::RecordMetric) -> Self {
        Self {
            name: value.name,
            timestamp: value.timestamp,
            fields: value.fields,
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
    /// Named set of string attributes observed at a point in time.
    Record(RecordMetric),
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
            s2_common::metrics::Metric::Record(record) => Metric::Record(record.into()),
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
