use compact_str::CompactString;

#[derive(Clone, Copy, Debug)]
pub enum MetricUnit {
    Bytes,
    Operations,
}

#[derive(Clone, Copy, Debug, strum::IntoStaticStr)]
pub enum TimeseriesInterval {
    #[strum(serialize = "minute")]
    Minute,
    #[strum(serialize = "hour")]
    Hour,
    #[strum(serialize = "day")]
    Day,
}

#[derive(Debug, Clone)]
pub struct ScalarMetric {
    pub name: CompactString,
    pub unit: MetricUnit,
    pub value: f64,
}

#[derive(Debug, Clone)]
pub struct AccumulationMetric {
    pub name: CompactString,
    pub unit: MetricUnit,
    pub interval: TimeseriesInterval,
    pub values: Vec<(u32, f64)>,
}

#[derive(Debug, Clone)]
pub struct GaugeMetric {
    pub name: CompactString,
    pub unit: MetricUnit,
    pub values: Vec<(u32, f64)>,
}

#[derive(Debug, Clone)]
pub struct LabelMetric {
    pub name: CompactString,
    pub values: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Metric {
    Scalar(ScalarMetric),
    Accumulation(AccumulationMetric),
    Gauge(GaugeMetric),
    Label(LabelMetric),
}

