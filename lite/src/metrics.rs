use std::sync::LazyLock;

use bytes::{BufMut, Bytes, BytesMut};
use prometheus::{Encoder, Histogram, TextEncoder, register_histogram};

static APPEND_ACK_LATENCY: LazyLock<Histogram> = LazyLock::new(|| {
    register_histogram!(
        "s2_append_ack_latency_seconds",
        "Append ack latency in seconds",
        vec![
            0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500
        ]
    )
    .unwrap()
});

pub fn observe_append_ack_latency(latency: std::time::Duration) {
    APPEND_ACK_LATENCY.observe(latency.as_secs_f64());
}

pub fn gather() -> Bytes {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = BytesMut::new().writer();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    buffer.into_inner().freeze()
}
