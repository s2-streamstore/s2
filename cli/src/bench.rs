use std::{
    collections::BTreeMap,
    future::Future,
    num::NonZeroU64,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use colored::Colorize;
use futures::{Stream, StreamExt, stream::FuturesUnordered};
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use rand::{Rng, SeedableRng};
use s2_sdk::{
    S2Stream,
    producer::{IndexedAppendAck, ProducerConfig},
    types::{
        AppendRecord, Header, MeteredBytes as _, RECORD_BATCH_MAX, ReadFrom, ReadInput, ReadStart,
        ReadStop, S2Error, SequencedRecord,
    },
};
use tokio::{
    sync::mpsc,
    time::{Instant, MissedTickBehavior},
};
use xxhash_rust::xxh3::Xxh3Default;

use crate::{
    error::{CliError, OpKind},
    types::LatencyStats,
};

const HASH_HEADER_NAME: &[u8] = b"hash";
const HEADER_VALUE_LEN: usize = 8;
const RECORD_OVERHEAD_BYTES: usize = 8 + 2 + HASH_HEADER_NAME.len() + HEADER_VALUE_LEN;
const WRITE_DONE_SENTINEL: u64 = u64::MAX;
const LIVE_UI_REFRESH_HZ: u8 = 20;
const LIVE_UI_REFRESH_MS: u64 = 1000 / LIVE_UI_REFRESH_HZ as u64;
const LATENCY_TABLE_COLUMN_WIDTH: usize = 44;
const LATENCY_TABLE_GAP: &str = "    ";
const LATENCY_TABLE_SIDE_BY_SIDE_WIDTH: usize =
    LATENCY_TABLE_COLUMN_WIDTH * 2 + LATENCY_TABLE_GAP.len();

type PendingAck =
    Pin<Box<dyn Future<Output = (Instant, Result<IndexedAppendAck, S2Error>)> + Send>>;

pub struct BenchWriteSample {
    pub bytes: u64,
    pub records: u64,
    pub elapsed: Duration,
    pub ack_latencies: Vec<Duration>,
    pub chain_hash: Option<u64>,
}

pub struct BenchReadSample {
    pub bytes: u64,
    pub records: u64,
    pub elapsed: Duration,
    pub e2e_latencies: Vec<Duration>,
    pub chain_hash: Option<u64>,
}

trait BenchSample {
    fn bytes(&self) -> u64;
    fn records(&self) -> u64;
    fn elapsed(&self) -> Duration;

    fn mib_per_sec(&self) -> f64 {
        let mib = self.bytes() as f64 / (1024.0 * 1024.0);
        let secs = self.elapsed().as_secs_f64();
        if secs > 0.0 { mib / secs } else { 0.0 }
    }

    fn records_per_sec(&self) -> f64 {
        let secs = self.elapsed().as_secs_f64();
        if secs > 0.0 {
            self.records() as f64 / secs
        } else {
            0.0
        }
    }
}

impl BenchSample for BenchWriteSample {
    fn bytes(&self) -> u64 {
        self.bytes
    }
    fn records(&self) -> u64 {
        self.records
    }
    fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

impl BenchSample for BenchReadSample {
    fn bytes(&self) -> u64 {
        self.bytes
    }
    fn records(&self) -> u64 {
        self.records
    }
    fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

#[derive(Debug, Default)]
pub struct StreamingLatencyStats {
    count: u64,
    samples: BTreeMap<u64, u64>,
}

#[derive(Debug, Clone)]
pub struct LiveLatencySnapshot {
    pub count: u64,
    pub stats: LatencyStats,
}

impl StreamingLatencyStats {
    pub fn extend(&mut self, samples: impl IntoIterator<Item = Duration>) {
        for sample in samples {
            self.record(sample);
        }
    }

    fn record(&mut self, sample: Duration) {
        self.count += 1;
        *self.samples.entry(duration_nanos(sample)).or_default() += 1;
    }

    pub fn snapshot(&self) -> Option<LiveLatencySnapshot> {
        if self.count == 0 {
            return None;
        }

        let min = Duration::from_nanos(*self.samples.keys().next()?);
        let max = Duration::from_nanos(*self.samples.keys().next_back()?);
        let p50_rank = Self::percentile_rank(self.count, 0.50);
        let p90_rank = Self::percentile_rank(self.count, 0.90);
        let p99_rank = Self::percentile_rank(self.count, 0.99);

        let mut seen = 0;
        let mut p50 = None;
        let mut p90 = None;
        let mut p99 = None;

        for (nanos, sample_count) in &self.samples {
            seen += *sample_count;
            if p50.is_none() && seen >= p50_rank {
                p50 = Some(Duration::from_nanos(*nanos));
            }
            if p90.is_none() && seen >= p90_rank {
                p90 = Some(Duration::from_nanos(*nanos));
            }
            if p99.is_none() && seen >= p99_rank {
                p99 = Some(Duration::from_nanos(*nanos));
                break;
            }
        }

        Some(LiveLatencySnapshot {
            count: self.count,
            stats: LatencyStats {
                min,
                p50: p50.unwrap_or(max),
                p90: p90.unwrap_or(max),
                p99: p99.unwrap_or(max),
                max,
            },
        })
    }

    fn percentile_rank(count: u64, percentile: f64) -> u64 {
        ((count as f64) * percentile).ceil().max(1.0) as u64
    }
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn format_latency_duration(duration: Duration) -> String {
    let nanos = duration_nanos(duration);
    if nanos < 1_000 {
        format!("{nanos}ns")
    } else if nanos < 1_000_000 {
        format!("{:.1}us", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2}ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", duration.as_secs_f64())
    }
}

fn format_latency_stat_row(key: &str, value: Option<Duration>, colored: bool) -> String {
    match value {
        Some(value) => {
            let formatted = format_latency_duration(value);
            if colored {
                format!("{key:7}: {:>9}", formatted.green().bold())
            } else {
                format!("{key:7}: {:>9}", formatted)
            }
        }
        None => format!("{key:7}: {:>9}", "-"),
    }
}

#[derive(Debug, Clone, Copy)]
enum LatencyTableLayout {
    SideBySide,
    Stacked,
}

fn latency_table_layout() -> LatencyTableLayout {
    let width = terminal_size::terminal_size()
        .map(|(terminal_size::Width(width), _)| width as usize)
        .unwrap_or(usize::MAX);

    if width >= LATENCY_TABLE_SIDE_BY_SIDE_WIDTH {
        LatencyTableLayout::SideBySide
    } else {
        LatencyTableLayout::Stacked
    }
}

fn latency_header(title: &str, snapshot: Option<&LiveLatencySnapshot>) -> String {
    format!(
        "{title} (n={})",
        snapshot.map_or(0, |snapshot| snapshot.count)
    )
}

fn latency_table_rows(snapshot: Option<&LiveLatencySnapshot>, colored: bool) -> Vec<String> {
    let stats = snapshot.map(|snapshot| &snapshot.stats);

    vec![
        format_latency_stat_row("min", stats.map(|stats| stats.min), colored),
        format_latency_stat_row("p50", stats.map(|stats| stats.p50), colored),
        format_latency_stat_row("p90", stats.map(|stats| stats.p90), colored),
        format_latency_stat_row("p99", stats.map(|stats| stats.p99), colored),
        format_latency_stat_row("max", stats.map(|stats| stats.max), colored),
    ]
}

fn format_latency_header(line: String) -> String {
    line.yellow().bold().to_string()
}

fn format_latency_header_cell(line: String) -> String {
    format!("{line:<LATENCY_TABLE_COLUMN_WIDTH$}")
        .yellow()
        .bold()
        .to_string()
}

fn format_latency_plain_cell(line: String) -> String {
    format!("{line:<LATENCY_TABLE_COLUMN_WIDTH$}")
}

fn format_latency_tables(
    ack: Option<&LiveLatencySnapshot>,
    e2e: Option<&LiveLatencySnapshot>,
    layout: LatencyTableLayout,
    colored: bool,
) -> Vec<String> {
    // Side-by-side layout uses fixed-width padding that ANSI codes would break.
    let color_values = colored && matches!(layout, LatencyTableLayout::Stacked);
    let ack_header = latency_header("Ack Latency Statistics", ack);
    let e2e_header = latency_header("End-to-End Latency Statistics", e2e);
    let ack_rows = latency_table_rows(ack, color_values);
    let e2e_rows = latency_table_rows(e2e, color_values);

    match layout {
        LatencyTableLayout::SideBySide => {
            let mut lines = Vec::with_capacity(6);
            lines.push(format!(
                "{}{LATENCY_TABLE_GAP}{}",
                format_latency_header_cell(ack_header),
                format_latency_header(e2e_header)
            ));

            for (ack_row, e2e_row) in ack_rows.into_iter().zip(e2e_rows) {
                lines.push(format!(
                    "{}{LATENCY_TABLE_GAP}{}",
                    format_latency_plain_cell(ack_row),
                    e2e_row
                ));
            }

            lines
        }
        LatencyTableLayout::Stacked => {
            let mut lines = Vec::with_capacity(13);
            lines.push(format_latency_header(ack_header));
            lines.extend(ack_rows);
            lines.push(String::new());
            lines.push(format_latency_header(e2e_header));
            lines.extend(e2e_rows);
            lines
        }
    }
}

struct LiveLatencyTables {
    layout: LatencyTableLayout,
    lines: Vec<ProgressBar>,
}

impl LiveLatencyTables {
    fn new(multi: &MultiProgress, layout: LatencyTableLayout) -> Self {
        let line_count = match layout {
            LatencyTableLayout::SideBySide => 6,
            LatencyTableLayout::Stacked => 13,
        };
        let lines = (0..line_count)
            .map(|_| {
                multi.add(
                    ProgressBar::no_length().with_style(
                        ProgressStyle::default_bar()
                            .template("{msg}")
                            .expect("valid template"),
                    ),
                )
            })
            .collect();

        let tables = Self { layout, lines };
        tables.update(None, None);
        tables
    }

    fn update(&self, ack: Option<&LiveLatencySnapshot>, e2e: Option<&LiveLatencySnapshot>) {
        for (bar, line) in
            self.lines
                .iter()
                .zip(format_latency_tables(ack, e2e, self.layout, false))
        {
            bar.set_message(line);
        }
    }

    fn finish_and_clear(&self) {
        for line in &self.lines {
            line.finish_and_clear();
        }
    }
}

fn body_size(record_size: usize) -> usize {
    record_size.saturating_sub(RECORD_OVERHEAD_BYTES)
}

fn record_body(record_size: usize, rng: &mut rand::rngs::StdRng) -> Bytes {
    let mut body = vec![0u8; body_size(record_size)];
    rng.fill_bytes(&mut body);
    Bytes::from(body)
}

fn new_record(body: Bytes, timestamp: u64, hash: u64) -> AppendRecord {
    AppendRecord::new(body)
        .and_then(|record| {
            record.with_headers([Header::new(HASH_HEADER_NAME, hash.to_be_bytes().to_vec())])
        })
        .expect("valid")
        .with_timestamp(timestamp)
}

fn record_hash(record: &SequencedRecord) -> Result<u64, String> {
    let header = record
        .headers
        .iter()
        .find(|h| h.name.as_ref() == HASH_HEADER_NAME)
        .ok_or_else(|| "missing bench hash header".to_string())?;
    let value = header.value.as_ref();
    if value.len() != HEADER_VALUE_LEN {
        return Err(format!("invalid bench hash header length: {}", value.len()));
    }
    Ok(u64::from_be_bytes(
        value.try_into().expect("length checked"),
    ))
}

fn chain_hash(prev_hash: u64, body: &[u8]) -> u64 {
    let mut hasher = Xxh3Default::new();
    hasher.update(&prev_hash.to_be_bytes());
    hasher.update(body);
    hasher.digest()
}

pub fn bench_write(
    stream: S2Stream,
    record_size: usize,
    target_mibps: NonZeroU64,
    stop: Arc<AtomicBool>,
    write_done_records: Arc<AtomicU64>,
    bench_start: Instant,
) -> impl Stream<Item = Result<BenchWriteSample, CliError>> + Send {
    let metered_size =
        new_record(Bytes::from(vec![0u8; body_size(record_size)]), 0, 0).metered_bytes();
    assert_eq!(metered_size, record_size);

    let producer = stream.producer(ProducerConfig::default());

    async_stream::stream! {
        let target_bps = target_mibps.get() as f64 * 1024.0 * 1024.0;

        let mut total_bytes: u64 = 0;
        let mut total_records: u64 = 0;
        let throughput_start = Instant::now();
        let mut last_yield = Instant::now();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0);
        let mut prev_hash: u64 = 0;
        let mut next_seq_num: u64 = 0;

        let mut pending_acks: FuturesUnordered<PendingAck> = FuturesUnordered::new();
        let mut ack_latencies: Vec<Duration> = Vec::new();

        // Rate limiting state (time-based)
        let mut bytes_submitted: usize = 0;

        let stopping = || stop.load(Ordering::Relaxed);

        loop {
            if stopping() && pending_acks.is_empty() {
                break;
            }

            // Rate limiting: calculate delay needed based on bytes submitted vs time elapsed
            let throttle_delay = {
                if bytes_submitted == 0 {
                    None
                } else {
                    let expected_elapsed = Duration::from_secs_f64(bytes_submitted as f64 / target_bps);
                    let actual_elapsed = throughput_start.elapsed();
                    if expected_elapsed > actual_elapsed {
                        Some(expected_elapsed - actual_elapsed)
                    } else {
                        None
                    }
                }
            };

            tokio::select! {
                biased;

                Some((submit_time, res)) = pending_acks.next() => {
                    match res {
                        Ok(ack) => {
                            let latency = submit_time.elapsed();
                            ack_latencies.push(latency);
                            total_bytes += record_size as u64;
                            total_records += 1;
                            next_seq_num = ack.seq_num + 1;

                            if last_yield.elapsed() >= Duration::from_millis(100) {
                                last_yield = Instant::now();
                                yield Ok(BenchWriteSample {
                                    bytes: total_bytes,
                                    records: total_records,
                                    elapsed: throughput_start.elapsed(),
                                    ack_latencies: std::mem::take(&mut ack_latencies),
                                    chain_hash: None,
                                });
                            }
                        }
                        Err(e) => {
                            yield Err(CliError::op(OpKind::Bench, e));
                            return;
                        }
                    }
                }

                _ = tokio::time::sleep(throttle_delay.unwrap_or(Duration::ZERO)), if throttle_delay.is_some() && !stopping() => {
                    // Rate limit delay
                }

                permit = producer.reserve(record_size as u32), if !stopping() && throttle_delay.is_none() => {
                    match permit {
                        Ok(permit) => {
                            let submit_time = Instant::now();
                            let timestamp = bench_start.elapsed().as_micros() as u64;
                            let body = record_body(record_size, &mut rng);
                            let hash = chain_hash(prev_hash, body.as_ref());
                            prev_hash = hash;
                            let record = new_record(body, timestamp, hash);
                            pending_acks.push(Box::pin(async move {
                                let res = permit.submit(record).await;
                                (submit_time, res)
                            }));
                            bytes_submitted += record_size;
                        }
                        Err(e) => {
                            yield Err(CliError::op(OpKind::Bench, e));
                            return;
                        }
                    }
                }
            }
        }

        write_done_records.store(next_seq_num, Ordering::Release);
        yield Ok(BenchWriteSample {
            bytes: total_bytes,
            records: total_records,
            elapsed: throughput_start.elapsed(),
            ack_latencies,
            chain_hash: Some(prev_hash),
        });
    }
}

pub fn bench_read(
    stream: S2Stream,
    record_size: usize,
    write_done_records: Arc<AtomicU64>,
    bench_start: Instant,
) -> impl Stream<Item = Result<BenchReadSample, CliError>> + Send {
    bench_read_inner(
        stream,
        record_size,
        ReadStop::new(),
        write_done_records,
        bench_start,
    )
}

pub fn bench_read_catchup(
    stream: S2Stream,
    record_size: usize,
    bench_start: Instant,
) -> impl Stream<Item = Result<BenchReadSample, CliError>> + Send {
    bench_read_inner(
        stream,
        record_size,
        ReadStop::new().with_wait(0),
        Arc::new(AtomicU64::new(WRITE_DONE_SENTINEL)),
        bench_start,
    )
}

fn bench_read_inner(
    stream: S2Stream,
    record_size: usize,
    stop: ReadStop,
    write_done_records: Arc<AtomicU64>,
    bench_start: Instant,
) -> impl Stream<Item = Result<BenchReadSample, CliError>> + Send {
    async_stream::stream! {
        let read_input = ReadInput::new()
            .with_start(ReadStart::new().with_from(ReadFrom::SeqNum(0)))
            .with_stop(stop);
        let mut read_session = stream
            .read_session(read_input)
            .await
            .map_err(|e| CliError::op(OpKind::Bench, e))?;

        let mut total_bytes: u64 = 0;
        let mut total_records: u64 = 0;
        let throughput_start = Instant::now();
        let mut last_yield = Instant::now();
        let mut e2e_latencies: Vec<Duration> = Vec::new();
        let mut prev_hash: u64 = 0;

        let mut poll_interval = tokio::time::interval(Duration::from_millis(250));

        let done_records = || {
            let value = write_done_records.load(Ordering::Acquire);
            if value == WRITE_DONE_SENTINEL {
                None
            } else {
                Some(value)
            }
        };

        loop {
            tokio::select! {
                _ = poll_interval.tick() => {
                    if let Some(expected) = done_records() &&  total_records >= expected {
                        break;
                    }
                }
                batch_result = read_session.next() => {
                    match batch_result {
                        Some(Ok(batch)) => {
                            let now_micros = bench_start.elapsed().as_micros() as u64;
                            let batch_records = batch.records.len() as u64;
                            let mut batch_bytes: u64 = 0;
                            let expected_body_size = body_size(record_size);
                            for record in &batch.records {
                                if record.body.len() != expected_body_size {
                                    yield Err(CliError::BenchVerification(format!(
                                        "unexpected record body size at seq_num {}: expected {}, got {}",
                                        record.seq_num,
                                        expected_body_size,
                                        record.body.len()
                                    )));
                                    return;
                                }

                                let header_hash = match record_hash(record) {
                                    Ok(hash) => hash,
                                    Err(err) => {
                                        yield Err(CliError::BenchVerification(format!(
                                            "invalid bench hash at seq_num {}: {err}",
                                            record.seq_num
                                        )));
                                        return;
                                    }
                                };

                                if record.seq_num > 0 && header_hash == prev_hash {
                                    yield Err(CliError::BenchVerification(format!(
                                        "duplicate record hash at seq_num {}",
                                        record.seq_num
                                    )));
                                    return;
                                }

                                let computed_hash = chain_hash(prev_hash, record.body.as_ref());
                                if computed_hash != header_hash {
                                    yield Err(CliError::BenchVerification(format!(
                                        "unexpected record hash at seq_num {}",
                                        record.seq_num
                                    )));
                                    return;
                                }
                                prev_hash = computed_hash;
                                e2e_latencies.push(Duration::from_micros(
                                    now_micros.saturating_sub(record.timestamp),
                                ));
                                batch_bytes += record_size as u64;
                            }
                            total_bytes += batch_bytes;
                            total_records += batch_records;

                            if last_yield.elapsed() >= Duration::from_millis(100) {
                                last_yield = Instant::now();
                                yield Ok(BenchReadSample {
                                    bytes: total_bytes,
                                    records: total_records,
                                    elapsed: throughput_start.elapsed(),
                                    e2e_latencies: std::mem::take(&mut e2e_latencies),
                                    chain_hash: None,
                                });
                            }

                            if let Some(expected) = done_records() && total_records >= expected {
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            yield Err(CliError::op(OpKind::Bench, e));
                            return;
                        }
                        None => break,
                    }
                }
            }
        }

        yield Ok(BenchReadSample {
            bytes: total_bytes,
            records: total_records,
            elapsed: throughput_start.elapsed(),
            e2e_latencies,
            chain_hash: Some(prev_hash),
        });
    }
}

pub async fn run(
    stream: S2Stream,
    record_size: usize,
    target_mibps: NonZeroU64,
    duration: Duration,
    catchup_delay: Duration,
) -> Result<(), CliError> {
    assert!(record_size <= RECORD_BATCH_MAX.bytes);

    let bench_start = Instant::now();

    let multi =
        MultiProgress::with_draw_target(ProgressDrawTarget::stderr_with_hz(LIVE_UI_REFRESH_HZ));

    let write_bar = multi.add(
        ProgressBar::no_length().with_style(
            ProgressStyle::default_bar()
                .template("{msg}")
                .expect("valid template"),
        ),
    );
    let read_bar = multi.add(
        ProgressBar::no_length().with_style(
            ProgressStyle::default_bar()
                .template("{msg}")
                .expect("valid template"),
        ),
    );
    fn blank_bar(multi: &MultiProgress) -> ProgressBar {
        multi.add(
            ProgressBar::no_length().with_style(
                ProgressStyle::default_bar()
                    .template("{msg}")
                    .expect("valid template"),
            ),
        )
    }

    let latency_gap = blank_bar(&multi);
    let latency_tables = LiveLatencyTables::new(&multi, latency_table_layout());

    fn update_bench_bar<T: BenchSample>(
        bar: &ProgressBar,
        label: impl std::fmt::Display,
        sample: &T,
    ) {
        bar.set_message(format!(
            "{label}: {:.2} MiB/s, {:.0} records/s ({} bytes, {} records in {:.2}s)",
            sample.mib_per_sec(),
            sample.records_per_sec(),
            sample.bytes(),
            sample.records(),
            sample.elapsed().as_secs_f64(),
        ));
    }

    fn finish_live_bars(bars: &[&ProgressBar], latency_tables: &LiveLatencyTables) {
        for bar in bars {
            bar.finish_and_clear();
        }
        latency_tables.finish_and_clear();
    }

    fn update_live_bars(
        write_bar: &ProgressBar,
        read_bar: &ProgressBar,
        latency_tables: &LiveLatencyTables,
        write_sample: Option<&BenchWriteSample>,
        read_sample: Option<&BenchReadSample>,
        ack_latency_stats: &StreamingLatencyStats,
        e2e_latency_stats: &StreamingLatencyStats,
    ) {
        if let Some(sample) = write_sample {
            update_bench_bar(write_bar, "Write".bold().blue(), sample);
        }
        if let Some(sample) = read_sample {
            update_bench_bar(read_bar, "Read".bold().green(), sample);
        }
        let ack_snapshot = ack_latency_stats.snapshot();
        let e2e_snapshot = e2e_latency_stats.snapshot();
        latency_tables.update(ack_snapshot.as_ref(), e2e_snapshot.as_ref());
    }

    let mut write_sample: Option<BenchWriteSample> = None;
    let mut read_sample: Option<BenchReadSample> = None;
    let mut ack_latency_stats = StreamingLatencyStats::default();
    let mut e2e_latency_stats = StreamingLatencyStats::default();
    let mut write_chain_hash: Option<u64> = None;
    let mut read_chain_hash: Option<u64> = None;

    let stop = Arc::new(AtomicBool::new(false));
    let write_done_records = Arc::new(AtomicU64::new(WRITE_DONE_SENTINEL));
    let write_stream = bench_write(
        stream.clone(),
        record_size,
        target_mibps,
        stop.clone(),
        write_done_records.clone(),
        bench_start,
    );
    let read_stream = bench_read(
        stream.clone(),
        record_size,
        write_done_records.clone(),
        bench_start,
    );

    enum BenchEvent {
        Write(Result<BenchWriteSample, CliError>),
        Read(Result<BenchReadSample, CliError>),
        WriteDone,
        ReadDone,
    }

    let (tx, mut rx) = mpsc::unbounded_channel();
    let write_tx = tx.clone();
    let write_handle = tokio::spawn(async move {
        let mut write_stream = std::pin::pin!(write_stream);
        while let Some(sample) = write_stream.next().await {
            if write_tx.send(BenchEvent::Write(sample)).is_err() {
                return;
            }
        }
        let _ = write_tx.send(BenchEvent::WriteDone);
    });
    let read_tx = tx.clone();
    let read_handle = tokio::spawn(async move {
        let mut read_stream = std::pin::pin!(read_stream);
        while let Some(sample) = read_stream.next().await {
            if read_tx.send(BenchEvent::Read(sample)).is_err() {
                return;
            }
        }
        let _ = read_tx.send(BenchEvent::ReadDone);
    });
    drop(tx);

    let deadline = bench_start + duration;
    let mut write_done = false;
    let mut read_done = false;
    let mut interrupted = false;
    let mut ui_tick = tokio::time::interval(Duration::from_millis(LIVE_UI_REFRESH_MS));
    ui_tick.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        if write_done && read_done {
            break;
        }
        tokio::select! {
            _ = ui_tick.tick() => {
                update_live_bars(
                    &write_bar,
                    &read_bar,
                    &latency_tables,
                    write_sample.as_ref(),
                    read_sample.as_ref(),
                    &ack_latency_stats,
                    &e2e_latency_stats,
                );
            }
            _ = tokio::time::sleep_until(deadline), if !stop.load(Ordering::Relaxed) => {
                stop.store(true, Ordering::Relaxed);
            }
            _ = tokio::signal::ctrl_c() => {
                interrupted = true;
                stop.store(true, Ordering::Relaxed);
                write_handle.abort();
                read_handle.abort();
                break;
            }
            event = rx.recv() => {
                match event {
                    Some(BenchEvent::Write(Ok(sample))) => {
                        ack_latency_stats.extend(sample.ack_latencies.iter().copied());
                        if let Some(hash) = sample.chain_hash {
                            write_chain_hash = Some(hash);
                        }
                        write_sample = Some(sample);
                    }
                    Some(BenchEvent::Write(Err(e))) => {
                        finish_live_bars(
                            &[&write_bar, &read_bar, &latency_gap],
                            &latency_tables,
                        );
                        stop.store(true, Ordering::Relaxed);
                        write_handle.abort();
                        read_handle.abort();
                        return Err(e);
                    }
                    Some(BenchEvent::WriteDone) => {
                        write_done = true;
                    }
                    Some(BenchEvent::Read(Ok(sample))) => {
                        e2e_latency_stats.extend(sample.e2e_latencies.iter().copied());
                        if let Some(hash) = sample.chain_hash {
                            read_chain_hash = Some(hash);
                        }
                        read_sample = Some(sample);
                    }
                    Some(BenchEvent::Read(Err(e))) => {
                        finish_live_bars(
                            &[&write_bar, &read_bar, &latency_gap],
                            &latency_tables,
                        );
                        stop.store(true, Ordering::Relaxed);
                        write_handle.abort();
                        read_handle.abort();
                        return Err(e);
                    }
                    Some(BenchEvent::ReadDone) => read_done = true,
                    None => {
                        write_done = true;
                        read_done = true;
                    }
                }
            }
        }
    }

    let _ = write_handle.await;
    let _ = read_handle.await;

    finish_live_bars(&[&write_bar, &read_bar, &latency_gap], &latency_tables);

    if interrupted {
        eprintln!();
        eprintln!(
            "{}",
            "Interrupted by Ctrl+C; showing partial results.".yellow()
        );
    }

    eprintln!();
    if let Some(sample) = &write_sample {
        eprintln!(
            "{}: {:.2} MiB/s, {:.0} records/s ({} bytes, {} records in {:.2}s)",
            "Write".bold().blue(),
            sample.mib_per_sec(),
            sample.records_per_sec(),
            sample.bytes,
            sample.records,
            sample.elapsed.as_secs_f64()
        );
    }
    if let Some(sample) = &read_sample {
        eprintln!(
            "{}: {:.2} MiB/s, {:.0} records/s ({} bytes, {} records in {:.2}s)",
            "Read".bold().green(),
            sample.mib_per_sec(),
            sample.records_per_sec(),
            sample.bytes,
            sample.records,
            sample.elapsed.as_secs_f64()
        );
    }

    let ack_latency_snapshot = ack_latency_stats.snapshot();
    let e2e_latency_snapshot = e2e_latency_stats.snapshot();
    if ack_latency_snapshot.is_some() || e2e_latency_snapshot.is_some() {
        eprintln!();
        print_latency_stats(
            ack_latency_snapshot.as_ref(),
            e2e_latency_snapshot.as_ref(),
            latency_tables.layout,
        );
    }

    if interrupted {
        return Ok(());
    }

    if let (Some(write_sample), Some(read_sample)) = (write_sample.as_ref(), read_sample.as_ref())
        && write_sample.records != read_sample.records
    {
        return Err(CliError::BenchVerification(format!(
            "live read record count mismatch: expected {}, got {}",
            write_sample.records, read_sample.records
        )));
    }

    if let (Some(expected), Some(actual)) = (write_chain_hash, read_chain_hash)
        && expected != actual
    {
        return Err(CliError::BenchVerification(format!(
            "live read hash mismatch: expected {expected}, got {actual}"
        )));
    }

    eprintln!();
    eprintln!("Waiting {:?} before catchup read...", catchup_delay);
    tokio::select! {
        _ = tokio::time::sleep(catchup_delay) => {}
        _ = tokio::signal::ctrl_c() => return Ok(()),
    }

    let catchup_bar = ProgressBar::no_length().with_style(
        ProgressStyle::default_bar()
            .template("{msg}")
            .expect("valid template"),
    );
    let mut catchup_sample: Option<BenchReadSample> = None;
    let mut catchup_chain_hash: Option<u64> = None;
    let catchup_stream = bench_read_catchup(stream.clone(), record_size, bench_start);
    let mut catchup_stream = std::pin::pin!(catchup_stream);
    let catchup_timeout = Duration::from_secs(300);
    let catchup_deadline = tokio::time::Instant::now() + catchup_timeout;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                catchup_bar.finish_and_clear();
                return Ok(());
            }
            next = tokio::time::timeout_at(catchup_deadline, catchup_stream.next()) => {
                match next {
                    Ok(Some(Ok(sample))) => {
                        update_bench_bar(&catchup_bar, "Catchup".bold().cyan(), &sample);
                        if let Some(hash) = sample.chain_hash {
                            catchup_chain_hash = Some(hash);
                        }
                        catchup_sample = Some(sample);
                    }
                    Ok(Some(Err(e))) => {
                        catchup_bar.finish_and_clear();
                        return Err(e);
                    }
                    Ok(None) => break,
                    Err(_) => {
                        catchup_bar.finish_and_clear();
                        return Err(CliError::BenchVerification(
                            "catchup read timed out after 5 minutes".to_string(),
                        ));
                    }
                }
            }
        }
    }

    catchup_bar.finish_and_clear();
    if let Some(sample) = &catchup_sample {
        eprintln!(
            "{}: {:.2} MiB/s, {:.0} records/s ({} bytes, {} records in {:.2}s)",
            "Catchup".bold().cyan(),
            sample.mib_per_sec(),
            sample.records_per_sec(),
            sample.bytes,
            sample.records,
            sample.elapsed.as_secs_f64()
        );
    } else {
        eprintln!(
            "{}: no records available for catchup read",
            "Catchup".bold().cyan()
        );
    }

    match (write_sample.as_ref(), catchup_sample.as_ref()) {
        (Some(write_sample), Some(catchup_sample))
            if write_sample.records != catchup_sample.records =>
        {
            return Err(CliError::BenchVerification(format!(
                "catchup read record count mismatch: expected {}, got {}",
                write_sample.records, catchup_sample.records
            )));
        }
        (Some(write_sample), None) if write_sample.records > 0 => {
            return Err(CliError::BenchVerification(format!(
                "catchup read returned no records but write produced {}",
                write_sample.records
            )));
        }
        _ => {}
    }

    if let (Some(expected), Some(actual)) = (write_chain_hash, catchup_chain_hash)
        && expected != actual
    {
        return Err(CliError::BenchVerification(format!(
            "catchup read hash mismatch: expected {expected}, got {actual}"
        )));
    }

    Ok(())
}

fn print_latency_stats(
    ack: Option<&LiveLatencySnapshot>,
    e2e: Option<&LiveLatencySnapshot>,
    layout: LatencyTableLayout,
) {
    for line in format_latency_tables(ack, e2e, layout, true) {
        eprintln!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{LatencyTableLayout, StreamingLatencyStats, format_latency_tables};

    #[test]
    fn streaming_latency_stats_tracks_percentiles() {
        let mut stats = StreamingLatencyStats::default();
        stats.extend((1..=10).map(Duration::from_millis));

        let snapshot = stats.snapshot().expect("stats available");

        assert_eq!(snapshot.count, 10);
        assert_eq!(snapshot.stats.min, Duration::from_millis(1));
        assert_eq!(snapshot.stats.p50, Duration::from_millis(5));
        assert_eq!(snapshot.stats.p90, Duration::from_millis(9));
        assert_eq!(snapshot.stats.p99, Duration::from_millis(10));
        assert_eq!(snapshot.stats.max, Duration::from_millis(10));
    }

    #[test]
    fn streaming_latency_stats_counts_duplicate_samples() {
        let mut stats = StreamingLatencyStats::default();
        stats.extend([
            Duration::from_millis(1),
            Duration::from_millis(5),
            Duration::from_millis(5),
            Duration::from_millis(10),
        ]);

        let snapshot = stats.snapshot().expect("stats available");

        assert_eq!(snapshot.count, 4);
        assert_eq!(snapshot.stats.p50, Duration::from_millis(5));
        assert_eq!(snapshot.stats.p90, Duration::from_millis(10));
        assert_eq!(snapshot.stats.p99, Duration::from_millis(10));
    }

    #[test]
    fn latency_tables_can_render_side_by_side() {
        let mut ack_stats = StreamingLatencyStats::default();
        ack_stats.extend((1..=10).map(Duration::from_millis));
        let ack = ack_stats.snapshot().expect("ack stats available");

        let mut e2e_stats = StreamingLatencyStats::default();
        e2e_stats.extend((11..=20).map(Duration::from_millis));
        let e2e = e2e_stats.snapshot().expect("e2e stats available");

        let lines = format_latency_tables(
            Some(&ack),
            Some(&e2e),
            LatencyTableLayout::SideBySide,
            false,
        );

        assert_eq!(lines.len(), 6);
        assert!(lines[0].contains("Ack Latency Statistics (n=10)"));
        assert!(lines[0].contains("End-to-End Latency Statistics (n=10)"));
        assert!(lines[1].contains("min"));
        assert!(lines[1].contains("1.00ms"));
        assert!(lines[1].contains("11.00ms"));
    }
}
