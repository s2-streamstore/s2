use std::{sync::LazyLock, time::Duration};

use bytes::{BufMut, Bytes, BytesMut};
use prometheus::{Encoder, Histogram, TextEncoder, register_histogram};

pub fn observe_append_ack_latency(latency: Duration) {
    static HISTOGRAM: LazyLock<Histogram> = LazyLock::new(|| {
        register_histogram!(
            "s2_append_ack_latency_seconds",
            "Append ack latency in seconds",
            vec![
                0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.000, 2.500
            ]
        )
        .unwrap()
    });
    HISTOGRAM.observe(latency.as_secs_f64());
}

pub fn observe_append_batch_size(count: usize, bytes: usize) {
    static BYTES: LazyLock<Histogram> = LazyLock::new(|| {
        register_histogram!(
            "s2_append_batch_bytes",
            "Append batch size in bytes",
            vec![
                512.0,
                1024.0,
                (4 * 1024) as f64,
                (16 * 1024) as f64,
                (64 * 1024) as f64,
                (256 * 1024) as f64,
                (512 * 1024) as f64,
                (1024 * 1024) as f64,
            ]
        )
        .unwrap()
    });
    static RECORDS: LazyLock<Histogram> = LazyLock::new(|| {
        register_histogram!(
            "s2_append_batch_records",
            "Append batch size in number of records",
            vec![1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0]
        )
        .unwrap()
    });
    RECORDS.observe(count as f64);
    BYTES.observe(bytes as f64);
}

pub fn gather() -> Bytes {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = BytesMut::new().writer();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    buffer.into_inner().freeze()
}
