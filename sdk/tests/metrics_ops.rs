mod common;

use std::{future::Future, time::Duration};

use assert_matches::assert_matches;
use common::{S2Stream, s2};
use s2_sdk::types::*;
use test_context::test_context;
use time::OffsetDateTime;

const METRICS_TIMEOUT: Duration = Duration::from_secs(60);
const FAST_METRICS_POLL_MAX: Duration = Duration::from_secs(120);
const FAST_METRICS_POLL_INTERVAL: Duration = Duration::from_secs(5);
const STORAGE_METRICS_POLL_MAX: Duration = Duration::from_secs(8 * 60);
const STORAGE_METRICS_POLL_INTERVAL: Duration = Duration::from_secs(10);

fn epoch_range(hours_ago: u32) -> (u32, u32) {
    let end = OffsetDateTime::now_utc().unix_timestamp() as u32;
    let start = end.saturating_sub(hours_ago * 3600);
    (start, end)
}

fn time_range(hours_ago: u32) -> TimeRange {
    let (start, end) = epoch_range(hours_ago);
    TimeRange::new(start, end)
}

fn time_range_and_interval(
    hours_ago: u32,
    interval: Option<TimeseriesInterval>,
) -> TimeRangeAndInterval {
    let (start, end) = epoch_range(hours_ago);
    let range = TimeRangeAndInterval::new(start, end);
    match interval {
        Some(interval) => range.with_interval(interval),
        None => range,
    }
}

fn invalid_time_ranges(now: u32) -> [(u32, u32); 3] {
    [
        (now, now.saturating_sub(3600)),
        (now.saturating_sub(3600), now.saturating_add(600)),
        (now.saturating_sub(40 * 24 * 3600), now),
    ]
}

async fn append_sample(stream: &S2Stream) -> Result<(), S2Error> {
    let input = AppendInput::new(AppendRecordBatch::try_from_iter([AppendRecord::new(
        "metrics",
    )?])?);
    stream.append(input).await?;
    Ok(())
}

async fn read_sample(stream: &S2Stream) -> Result<(), S2Error> {
    let _ = stream
        .read(
            ReadInput::new()
                .with_stop(ReadStop::new().with_limits(ReadLimits::new().with_count(1))),
        )
        .await?;
    Ok(())
}

fn metric_has_data(metric: &Metric) -> bool {
    match metric {
        Metric::Scalar(_) => true,
        Metric::Accumulation(acc) => !acc.values.is_empty(),
        Metric::Gauge(gauge) => !gauge.values.is_empty(),
        Metric::Label(label) => !label.values.is_empty(),
    }
}

fn metrics_have_data(metrics: &[Metric]) -> bool {
    !metrics.is_empty() && metrics.iter().any(metric_has_data)
}

fn long_metrics_enabled() -> bool {
    std::env::var("S2_METRICS_LONG").is_ok()
}

async fn poll_metrics<Fetch, Fut, Ready>(
    timeout: Duration,
    interval: Duration,
    mut fetch: Fetch,
    mut ready: Ready,
) -> Result<Vec<Metric>, S2Error>
where
    Fetch: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<Metric>, S2Error>>,
    Ready: FnMut(&[Metric]) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_err: Option<S2Error> = None;

    loop {
        match fetch().await {
            Ok(value) => {
                if ready(&value) {
                    return Ok(value);
                }
            }
            Err(err) => {
                last_err = Some(err);
            }
        }

        if tokio::time::Instant::now() >= deadline {
            break;
        }

        tokio::time::sleep(interval).await;
    }

    Err(last_err.unwrap_or_else(|| {
        S2Error::Client(format!("metrics not ready after {}s", timeout.as_secs()))
    }))
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_active_basins(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let long_metrics = long_metrics_enabled();
    let metrics = if long_metrics {
        poll_metrics(
            STORAGE_METRICS_POLL_MAX,
            STORAGE_METRICS_POLL_INTERVAL,
            || async {
                tokio::time::timeout(
                    METRICS_TIMEOUT,
                    client.get_account_metrics(GetAccountMetricsInput::new(
                        AccountMetricSet::ActiveBasins(time_range(1)),
                    )),
                )
                .await
                .expect("account metrics request timed out")
            },
            |metrics| {
                metrics
                    .iter()
                    .any(|m| matches!(m, Metric::Label(l) if !l.values.is_empty()))
            },
        )
        .await?
    } else {
        tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_account_metrics(GetAccountMetricsInput::new(
                AccountMetricSet::ActiveBasins(time_range(1)),
            )),
        )
        .await
        .expect("account metrics request timed out")?
    };

    assert!(metrics.iter().all(|m| matches!(m, Metric::Label(_))));
    if long_metrics {
        assert!(
            metrics
                .iter()
                .any(|m| matches!(m, Metric::Label(l) if !l.values.is_empty()))
        );
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_account_ops_default_interval(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_account_metrics(GetAccountMetricsInput::new(
                    AccountMetricSet::AccountOps(time_range_and_interval(1, None)),
                )),
            )
            .await
            .expect("account metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(metrics.iter().all(|m| {
        matches!(
            m,
            Metric::Accumulation(acc)
                if acc.unit == MetricUnit::Operations
                    && acc.interval == TimeseriesInterval::Hour
        )
    }));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_account_ops_minute_interval(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_account_metrics(GetAccountMetricsInput::new(
                    AccountMetricSet::AccountOps(time_range_and_interval(
                        1,
                        Some(TimeseriesInterval::Minute),
                    )),
                )),
            )
            .await
            .expect("account metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(metrics.iter().all(|m| {
        matches!(
            m,
            Metric::Accumulation(acc)
                if acc.interval == TimeseriesInterval::Minute
        )
    }));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_account_ops_hour_interval(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_account_metrics(GetAccountMetricsInput::new(
                    AccountMetricSet::AccountOps(time_range_and_interval(
                        24,
                        Some(TimeseriesInterval::Hour),
                    )),
                )),
            )
            .await
            .expect("account metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(metrics.iter().all(|m| {
        matches!(
            m,
            Metric::Accumulation(acc)
                if acc.interval == TimeseriesInterval::Hour
        )
    }));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_account_ops_day_interval(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_account_metrics(GetAccountMetricsInput::new(
                    AccountMetricSet::AccountOps(time_range_and_interval(
                        24 * 7,
                        Some(TimeseriesInterval::Day),
                    )),
                )),
            )
            .await
            .expect("account metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(metrics.iter().all(|m| {
        matches!(
            m,
            Metric::Accumulation(acc)
                if acc.interval == TimeseriesInterval::Day
        )
    }));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_empty_time_range(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = tokio::time::timeout(
        METRICS_TIMEOUT,
        client.get_account_metrics(GetAccountMetricsInput::new(AccountMetricSet::ActiveBasins(
            TimeRange::new(0, 3600),
        ))),
    )
    .await
    .expect("account metrics request timed out")?;

    assert!(metrics.iter().all(|m| matches!(m, Metric::Label(_))));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_storage(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let long_metrics = long_metrics_enabled();
    let metrics = if long_metrics {
        poll_metrics(
            STORAGE_METRICS_POLL_MAX,
            STORAGE_METRICS_POLL_INTERVAL,
            || async {
                tokio::time::timeout(
                    METRICS_TIMEOUT,
                    client.get_basin_metrics(GetBasinMetricsInput::new(
                        stream.basin_name().clone(),
                        BasinMetricSet::Storage(time_range(1)),
                    )),
                )
                .await
                .expect("basin metrics request timed out")
            },
            metrics_have_data,
        )
        .await?
    } else {
        tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_basin_metrics(GetBasinMetricsInput::new(
                stream.basin_name().clone(),
                BasinMetricSet::Storage(time_range(1)),
            )),
        )
        .await
        .expect("basin metrics request timed out")?
    };

    assert!(
        metrics
            .iter()
            .all(|m| { matches!(m, Metric::Gauge(g) if g.unit == MetricUnit::Bytes) })
    );
    if long_metrics {
        assert!(metrics_have_data(&metrics));
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_append_ops(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_basin_metrics(GetBasinMetricsInput::new(
                    stream.basin_name().clone(),
                    BasinMetricSet::AppendOps(time_range_and_interval(1, None)),
                )),
            )
            .await
            .expect("basin metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(
        metrics.iter().all(|m| {
            matches!(m, Metric::Accumulation(acc) if acc.unit == MetricUnit::Operations)
        })
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_read_ops(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;
    read_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_basin_metrics(GetBasinMetricsInput::new(
                    stream.basin_name().clone(),
                    BasinMetricSet::ReadOps(time_range_and_interval(1, None)),
                )),
            )
            .await
            .expect("basin metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(
        metrics.iter().all(|m| {
            matches!(m, Metric::Accumulation(acc) if acc.unit == MetricUnit::Operations)
        })
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_read_throughput(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;
    read_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_basin_metrics(GetBasinMetricsInput::new(
                    stream.basin_name().clone(),
                    BasinMetricSet::ReadThroughput(time_range_and_interval(1, None)),
                )),
            )
            .await
            .expect("basin metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(
        metrics
            .iter()
            .all(|m| { matches!(m, Metric::Accumulation(acc) if acc.unit == MetricUnit::Bytes) })
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_append_throughput(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_basin_metrics(GetBasinMetricsInput::new(
                    stream.basin_name().clone(),
                    BasinMetricSet::AppendThroughput(time_range_and_interval(1, None)),
                )),
            )
            .await
            .expect("basin metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(
        metrics
            .iter()
            .all(|m| { matches!(m, Metric::Accumulation(acc) if acc.unit == MetricUnit::Bytes) })
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_basin_ops(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_metrics(
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        || async {
            tokio::time::timeout(
                METRICS_TIMEOUT,
                client.get_basin_metrics(GetBasinMetricsInput::new(
                    stream.basin_name().clone(),
                    BasinMetricSet::BasinOps(time_range_and_interval(1, None)),
                )),
            )
            .await
            .expect("basin metrics request timed out")
        },
        metrics_have_data,
    )
    .await?;

    assert!(
        metrics.iter().all(|m| {
            matches!(m, Metric::Accumulation(acc) if acc.unit == MetricUnit::Operations)
        })
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn stream_metrics_storage(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let long_metrics = long_metrics_enabled();
    let metrics = if long_metrics {
        poll_metrics(
            STORAGE_METRICS_POLL_MAX,
            STORAGE_METRICS_POLL_INTERVAL,
            || async {
                tokio::time::timeout(
                    METRICS_TIMEOUT,
                    client.get_stream_metrics(GetStreamMetricsInput::new(
                        stream.basin_name().clone(),
                        stream.stream_name().clone(),
                        StreamMetricSet::Storage(time_range(1)),
                    )),
                )
                .await
                .expect("stream metrics request timed out")
            },
            metrics_have_data,
        )
        .await?
    } else {
        tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_stream_metrics(GetStreamMetricsInput::new(
                stream.basin_name().clone(),
                stream.stream_name().clone(),
                StreamMetricSet::Storage(time_range(1)),
            )),
        )
        .await
        .expect("stream metrics request timed out")?
    };

    assert!(
        metrics
            .iter()
            .all(|m| { matches!(m, Metric::Gauge(g) if g.unit == MetricUnit::Bytes) })
    );
    if long_metrics {
        assert!(metrics_have_data(&metrics));
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_invalid_time_ranges(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let now = OffsetDateTime::now_utc().unix_timestamp() as u32;

    for (start, end) in invalid_time_ranges(now) {
        let result = tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_account_metrics(GetAccountMetricsInput::new(
                AccountMetricSet::ActiveBasins(TimeRange::new(start, end)),
            )),
        )
        .await
        .expect("account metrics request timed out");

        assert_matches!(
            result,
            Err(S2Error::Server(ErrorResponse { code, .. })) => {
                assert_eq!(code, "invalid");
            }
        );
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_all_sets(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let range = time_range(1);
    let range_with_interval = time_range_and_interval(1, None);
    let sets = [
        AccountMetricSet::ActiveBasins(range),
        AccountMetricSet::AccountOps(range_with_interval),
    ];

    for set in sets {
        let _ = tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_account_metrics(GetAccountMetricsInput::new(set)),
        )
        .await
        .expect("account metrics request timed out")?;
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_empty_time_range(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = tokio::time::timeout(
        METRICS_TIMEOUT,
        client.get_basin_metrics(GetBasinMetricsInput::new(
            stream.basin_name().clone(),
            BasinMetricSet::Storage(TimeRange::new(0, 3600)),
        )),
    )
    .await
    .expect("basin metrics request timed out")?;

    assert!(metrics.iter().all(|m| matches!(m, Metric::Gauge(_))));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_invalid_time_ranges(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let now = OffsetDateTime::now_utc().unix_timestamp() as u32;

    for (start, end) in invalid_time_ranges(now) {
        let result = tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_basin_metrics(GetBasinMetricsInput::new(
                stream.basin_name().clone(),
                BasinMetricSet::Storage(TimeRange::new(start, end)),
            )),
        )
        .await
        .expect("basin metrics request timed out");

        assert_matches!(
            result,
            Err(S2Error::Server(ErrorResponse { code, .. })) => {
                assert_eq!(code, "invalid");
            }
        );
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_all_sets(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;
    read_sample(stream).await?;

    let client = s2();
    let range = time_range(1);
    let range_with_interval = time_range_and_interval(1, None);
    let sets = [
        BasinMetricSet::Storage(range),
        BasinMetricSet::AppendOps(range_with_interval),
        BasinMetricSet::ReadOps(range_with_interval),
        BasinMetricSet::ReadThroughput(range_with_interval),
        BasinMetricSet::AppendThroughput(range_with_interval),
        BasinMetricSet::BasinOps(range_with_interval),
    ];

    for set in sets {
        let _ = tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_basin_metrics(GetBasinMetricsInput::new(stream.basin_name().clone(), set)),
        )
        .await
        .expect("basin metrics request timed out")?;
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn stream_metrics_empty_time_range(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = tokio::time::timeout(
        METRICS_TIMEOUT,
        client.get_stream_metrics(GetStreamMetricsInput::new(
            stream.basin_name().clone(),
            stream.stream_name().clone(),
            StreamMetricSet::Storage(TimeRange::new(0, 3600)),
        )),
    )
    .await
    .expect("stream metrics request timed out")?;

    assert!(metrics.iter().all(|m| matches!(m, Metric::Gauge(_))));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn stream_metrics_invalid_time_ranges(stream: &S2Stream) -> Result<(), S2Error> {
    append_sample(stream).await?;

    let client = s2();
    let now = OffsetDateTime::now_utc().unix_timestamp() as u32;

    for (start, end) in invalid_time_ranges(now) {
        let result = tokio::time::timeout(
            METRICS_TIMEOUT,
            client.get_stream_metrics(GetStreamMetricsInput::new(
                stream.basin_name().clone(),
                stream.stream_name().clone(),
                StreamMetricSet::Storage(TimeRange::new(start, end)),
            )),
        )
        .await
        .expect("stream metrics request timed out");

        assert_matches!(
            result,
            Err(S2Error::Server(ErrorResponse { code, .. })) => {
                assert_eq!(code, "invalid");
            }
        );
    }

    Ok(())
}
