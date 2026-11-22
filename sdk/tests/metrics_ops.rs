mod common;

use std::{future::Future, time::Duration};

use assert_matches::assert_matches;
use common::{S2Stream, s2};
use s2_sdk::{
    error::{RequestError, ServerError},
    types::*,
};
use test_context::test_context;

const METRICS_TIMEOUT: Duration = Duration::from_secs(60);
const FAST_METRICS_POLL_MAX: Duration = Duration::from_secs(120);
const FAST_METRICS_POLL_INTERVAL: Duration = Duration::from_secs(5);
const STORAGE_METRICS_POLL_MAX: Duration = Duration::from_secs(8 * 60);
const STORAGE_METRICS_POLL_INTERVAL: Duration = Duration::from_secs(10);

fn ts(secs: u32) -> Timestamp {
    Timestamp::from_second(i64::from(secs)).expect("u32 fits in Timestamp")
}

fn epoch_range(hours_ago: u32) -> (Timestamp, Timestamp) {
    let end = Timestamp::now();
    let start = end - Duration::from_secs(u64::from(hours_ago) * 3600);
    (start, end)
}

fn time_range(hours_ago: u32) -> TimeRange {
    let (start, end) = epoch_range(hours_ago);
    TimeRange::new(start, end).expect("valid time range")
}

fn time_range_and_interval(
    hours_ago: u32,
    interval: Option<TimeseriesInterval>,
) -> TimeRangeAndInterval {
    let (start, end) = epoch_range(hours_ago);
    let range = TimeRangeAndInterval::new(start, end).expect("valid time range");
    match interval {
        Some(interval) => range.with_interval(interval),
        None => range,
    }
}

fn invalid_time_ranges(now: Timestamp) -> [(Timestamp, Timestamp); 3] {
    [
        (now, now - Duration::from_secs(3600)),
        (
            now - Duration::from_secs(3600),
            now + Duration::from_secs(600),
        ),
        (now - Duration::from_secs(91 * 24 * 3600), now),
    ]
}

async fn append_sample(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    stream.append(AppendRecord::new("metrics")?).await?;
    Ok(())
}

async fn read_sample(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    let _ = stream
        .read(
            ReadInput::new()
                .with_start(ReadFrom::SeqNum(0))
                .with_count(1),
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
        Metric::Record(_) => true,
        _ => false,
    }
}

fn metrics_have_data(metrics: &[Metric]) -> bool {
    !metrics.is_empty() && metrics.iter().any(metric_has_data)
}

fn long_metrics_enabled() -> bool {
    std::env::var("S2_METRICS_LONG").is_ok()
}

async fn fetch_with_timeout<Fut>(label: &str, fut: Fut) -> Result<Vec<Metric>, RequestError>
where
    Fut: Future<Output = Result<Vec<Metric>, RequestError>>,
{
    tokio::time::timeout(METRICS_TIMEOUT, fut)
        .await
        .unwrap_or_else(|_| panic!("{label} metrics request timed out"))
}

async fn poll_metrics<Fetch, Fut, Ready>(
    label: &str,
    timeout: Duration,
    interval: Duration,
    mut fetch: Fetch,
    mut ready: Ready,
) -> Result<Vec<Metric>, Box<dyn std::error::Error>>
where
    Fetch: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<Metric>, RequestError>>,
    Ready: FnMut(&[Metric]) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    let mut last_err: Option<RequestError> = None;

    loop {
        match fetch_with_timeout(label, fetch()).await {
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

    match last_err {
        Some(err) => Err(Box::new(err)),
        None => Err(format!("metrics not ready after {}s", timeout.as_secs()).into()),
    }
}

async fn poll_fast_metrics<Fetch, Fut>(
    label: &str,
    fetch: Fetch,
) -> Result<Vec<Metric>, Box<dyn std::error::Error>>
where
    Fetch: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<Metric>, RequestError>>,
{
    poll_metrics(
        label,
        FAST_METRICS_POLL_MAX,
        FAST_METRICS_POLL_INTERVAL,
        fetch,
        metrics_have_data,
    )
    .await
}

async fn fetch_or_poll_storage<Fetch, Fut, Ready>(
    label: &str,
    mut fetch: Fetch,
    ready: Ready,
) -> Result<Vec<Metric>, Box<dyn std::error::Error>>
where
    Fetch: FnMut() -> Fut,
    Fut: Future<Output = Result<Vec<Metric>, RequestError>>,
    Ready: FnMut(&[Metric]) -> bool,
{
    if long_metrics_enabled() {
        poll_metrics(
            label,
            STORAGE_METRICS_POLL_MAX,
            STORAGE_METRICS_POLL_INTERVAL,
            fetch,
            ready,
        )
        .await
    } else {
        Ok(fetch_with_timeout(label, fetch()).await?)
    }
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_active_basins(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let has_labels = |metrics: &[Metric]| {
        metrics
            .iter()
            .any(|m| matches!(m, Metric::Label(l) if !l.values.is_empty()))
    };
    let metrics = fetch_or_poll_storage(
        "account",
        || client.get_account_metrics(AccountMetricSet::ActiveBasins(time_range(1))),
        has_labels,
    )
    .await?;

    assert!(metrics.iter().all(|m| matches!(m, Metric::Label(_))));
    if long_metrics_enabled() {
        assert!(has_labels(&metrics));
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_account_ops_default_interval(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_fast_metrics("account", || {
        client.get_account_metrics(AccountMetricSet::AccountOps(time_range_and_interval(
            1, None,
        )))
    })
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
async fn account_metrics_account_ops_intervals(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    for (hours, interval) in [
        (1, TimeseriesInterval::Minute),
        (24, TimeseriesInterval::Hour),
        (24 * 7, TimeseriesInterval::Day),
    ] {
        let metrics = poll_fast_metrics("account", || {
            client.get_account_metrics(AccountMetricSet::AccountOps(time_range_and_interval(
                hours,
                Some(interval.clone()),
            )))
        })
        .await?;
        assert!(
            metrics
                .iter()
                .all(|m| { matches!(m, Metric::Accumulation(acc) if acc.interval == interval) })
        );
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_empty_time_range(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = fetch_with_timeout(
        "account",
        client.get_account_metrics(AccountMetricSet::ActiveBasins(TimeRange::new(
            ts(0),
            ts(3600),
        )?)),
    )
    .await?;

    assert!(metrics.iter().all(|m| matches!(m, Metric::Label(_))));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_storage(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = fetch_or_poll_storage(
        "basin",
        || {
            client.get_basin_metrics(
                stream.basin_name().clone(),
                BasinMetricSet::Storage(time_range(1)),
            )
        },
        metrics_have_data,
    )
    .await?;

    assert!(
        metrics
            .iter()
            .all(|m| matches!(m, Metric::Gauge(g) if g.unit == MetricUnit::Bytes))
    );
    if long_metrics_enabled() {
        assert!(metrics_have_data(&metrics));
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_append_ops(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_fast_metrics("basin", || {
        client.get_basin_metrics(
            stream.basin_name().clone(),
            BasinMetricSet::AppendOps(time_range_and_interval(1, None)),
        )
    })
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
async fn basin_metrics_read_ops(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;
    read_sample(stream).await?;

    let client = s2();
    let metrics = poll_fast_metrics("basin", || {
        client.get_basin_metrics(
            stream.basin_name().clone(),
            BasinMetricSet::ReadOps(time_range_and_interval(1, None)),
        )
    })
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
async fn basin_metrics_read_throughput(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;
    read_sample(stream).await?;

    let client = s2();
    let metrics = poll_fast_metrics("basin", || {
        client.get_basin_metrics(
            stream.basin_name().clone(),
            BasinMetricSet::ReadThroughput(time_range_and_interval(1, None)),
        )
    })
    .await?;

    assert!(
        metrics
            .iter()
            .all(|m| matches!(m, Metric::Accumulation(acc) if acc.unit == MetricUnit::Bytes))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_append_throughput(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_fast_metrics("basin", || {
        client.get_basin_metrics(
            stream.basin_name().clone(),
            BasinMetricSet::AppendThroughput(time_range_and_interval(1, None)),
        )
    })
    .await?;

    assert!(
        metrics
            .iter()
            .all(|m| matches!(m, Metric::Accumulation(acc) if acc.unit == MetricUnit::Bytes))
    );

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_basin_ops(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = poll_fast_metrics("basin", || {
        client.get_basin_metrics(
            stream.basin_name().clone(),
            BasinMetricSet::BasinOps(time_range_and_interval(1, None)),
        )
    })
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
async fn stream_metrics_storage(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = fetch_or_poll_storage(
        "stream",
        || {
            client.get_stream_metrics(
                stream.basin_name().clone(),
                stream.stream_name().clone(),
                StreamMetricSet::Storage(time_range(1)),
            )
        },
        metrics_have_data,
    )
    .await?;

    assert!(
        metrics
            .iter()
            .all(|m| matches!(m, Metric::Gauge(g) if g.unit == MetricUnit::Bytes))
    );
    if long_metrics_enabled() {
        assert!(metrics_have_data(&metrics));
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_invalid_time_ranges(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let now = Timestamp::now();

    for (start, end) in invalid_time_ranges(now) {
        let result = fetch_with_timeout(
            "account",
            client.get_account_metrics(AccountMetricSet::ActiveBasins(TimeRange::new(start, end)?)),
        )
        .await;

        assert_matches!(
            result,
            Err(RequestError::Server(ServerError { code, .. })) => {
                assert_eq!(code.as_deref(), Some("invalid"));
            }
        );
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn account_metrics_all_sets(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let range = time_range(1);
    let range_with_interval = time_range_and_interval(1, None);
    let sets = [
        AccountMetricSet::ActiveBasins(range),
        AccountMetricSet::AccountOps(range_with_interval.clone()),
        AccountMetricSet::EstimatedBillableUsage(range_with_interval),
    ];

    for set in sets {
        let _ = fetch_with_timeout("account", client.get_account_metrics(set)).await?;
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_empty_time_range(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = fetch_with_timeout(
        "basin",
        client.get_basin_metrics(
            stream.basin_name().clone(),
            BasinMetricSet::Storage(TimeRange::new(ts(0), ts(3600))?),
        ),
    )
    .await?;

    assert!(metrics.iter().all(|m| matches!(m, Metric::Gauge(_))));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_invalid_time_ranges(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let now = Timestamp::now();

    for (start, end) in invalid_time_ranges(now) {
        let result = fetch_with_timeout(
            "basin",
            client.get_basin_metrics(
                stream.basin_name().clone(),
                BasinMetricSet::Storage(TimeRange::new(start, end)?),
            ),
        )
        .await;

        assert_matches!(
            result,
            Err(RequestError::Server(ServerError { code, .. })) => {
                assert_eq!(code.as_deref(), Some("invalid"));
            }
        );
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn basin_metrics_all_sets(stream: &S2Stream) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;
    read_sample(stream).await?;

    let client = s2();
    let range = time_range(1);
    let range_with_interval = time_range_and_interval(1, None);
    let sets = [
        BasinMetricSet::Storage(range),
        BasinMetricSet::AppendOps(range_with_interval.clone()),
        BasinMetricSet::ReadOps(range_with_interval.clone()),
        BasinMetricSet::ReadThroughput(range_with_interval.clone()),
        BasinMetricSet::AppendThroughput(range_with_interval.clone()),
        BasinMetricSet::BasinOps(range_with_interval),
    ];

    for set in sets {
        let _ = fetch_with_timeout(
            "basin",
            client.get_basin_metrics(stream.basin_name().clone(), set),
        )
        .await?;
    }

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn stream_metrics_empty_time_range(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let metrics = fetch_with_timeout(
        "stream",
        client.get_stream_metrics(
            stream.basin_name().clone(),
            stream.stream_name().clone(),
            StreamMetricSet::Storage(TimeRange::new(ts(0), ts(3600))?),
        ),
    )
    .await?;

    assert!(metrics.iter().all(|m| matches!(m, Metric::Gauge(_))));

    Ok(())
}

#[test_context(S2Stream)]
#[tokio_shared_rt::test(shared)]
async fn stream_metrics_invalid_time_ranges(
    stream: &S2Stream,
) -> Result<(), Box<dyn std::error::Error>> {
    append_sample(stream).await?;

    let client = s2();
    let now = Timestamp::now();

    for (start, end) in invalid_time_ranges(now) {
        let result = fetch_with_timeout(
            "stream",
            client.get_stream_metrics(
                stream.basin_name().clone(),
                stream.stream_name().clone(),
                StreamMetricSet::Storage(TimeRange::new(start, end)?),
            ),
        )
        .await;

        assert_matches!(
            result,
            Err(RequestError::Server(ServerError { code, .. })) => {
                assert_eq!(code.as_deref(), Some("invalid"));
            }
        );
    }

    Ok(())
}
