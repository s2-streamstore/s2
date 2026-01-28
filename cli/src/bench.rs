use std::{
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
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use rand::{RngCore, SeedableRng};
use s2_sdk::{
    S2Stream,
    producer::{IndexedAppendAck, ProducerConfig},
    types::{
        AppendRecord, Header, MeteredBytes as _, RECORD_BATCH_MAX, ReadFrom, ReadInput, ReadStart,
        ReadStop, S2Error, SequencedRecord,
    },
};
use tokio::{sync::mpsc, time::Instant};
use xxhash_rust::xxh3::Xxh3Default;

use crate::{
    error::{CliError, OpKind},
    types::LatencyStats,
};

const HASH_HEADER_NAME: &[u8] = b"hash";
const HEADER_VALUE_LEN: usize = 8;
const RECORD_OVERHEAD_BYTES: usize = 8 + 2 + HASH_HEADER_NAME.len() + HEADER_VALUE_LEN;
const WRITE_DONE_SENTINEL: u64 = u64::MAX;

type PendingAck =
    Pin<Box<dyn Future<Output = (Instant, Result<IndexedAppendAck, S2Error>)> + Send>>;

struct BenchWriteSample {
    bytes: u64,
    records: u64,
    elapsed: Duration,
    ack_latencies: Vec<Duration>,
    chain_hash: Option<u64>,
}

struct BenchReadSample {
    bytes: u64,
    records: u64,
    elapsed: Duration,
    e2e_latencies: Vec<Duration>,
    chain_hash: Option<u64>,
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

fn bench_write(
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

fn bench_read(
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

fn bench_read_catchup(
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

                                if header_hash == prev_hash {
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

    let multi = MultiProgress::new();
    let prefix_width = 7;

    let write_bar = multi.add(
        ProgressBar::no_length()
            .with_prefix(format!("{:width$}", "write", width = prefix_width))
            .with_style(
                ProgressStyle::default_bar()
                    .template("{prefix:.bold.blue} {msg}")
                    .expect("valid template"),
            ),
    );
    let read_bar = multi.add(
        ProgressBar::no_length()
            .with_prefix(format!("{:width$}", "read", width = prefix_width))
            .with_style(
                ProgressStyle::default_bar()
                    .template("{prefix:.bold.green} {msg}")
                    .expect("valid template"),
            ),
    );

    fn update_bench_bar<T: BenchSample>(bar: &ProgressBar, sample: &T) {
        const MIBPS_WIDTH: usize = 10;
        const RECPS_WIDTH: usize = 9;
        const BYTES_WIDTH: usize = 12;
        const RECORDS_WIDTH: usize = 12;

        bar.set_message(format!(
            "{:>mibps_width$.2} MiB/s  {:>recps_width$.0} rec/s | {:>bytes_width$} bytes | {:>records_width$} records",
            sample.mib_per_sec(),
            sample.records_per_sec(),
            sample.bytes(),
            sample.records(),
            mibps_width = MIBPS_WIDTH,
            recps_width = RECPS_WIDTH,
            bytes_width = BYTES_WIDTH,
            records_width = RECORDS_WIDTH,
        ));
    }

    let mut write_sample: Option<BenchWriteSample> = None;
    let mut read_sample: Option<BenchReadSample> = None;
    let mut all_ack_latencies: Vec<Duration> = Vec::new();
    let mut all_e2e_latencies: Vec<Duration> = Vec::new();
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

    loop {
        if write_done && read_done {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline), if !stop.load(Ordering::Relaxed) => {
                stop.store(true, Ordering::Relaxed);
            }
            _ = tokio::signal::ctrl_c(), if !stop.load(Ordering::Relaxed) => {
                stop.store(true, Ordering::Relaxed);
            }
            event = rx.recv() => {
                match event {
                    Some(BenchEvent::Write(Ok(sample))) => {
                        update_bench_bar(&write_bar, &sample);
                        all_ack_latencies.extend(sample.ack_latencies.iter().copied());
                        if let Some(hash) = sample.chain_hash {
                            write_chain_hash = Some(hash);
                        }
                        write_sample = Some(sample);
                    }
                    Some(BenchEvent::Write(Err(e))) => {
                        write_bar.finish_and_clear();
                        read_bar.finish_and_clear();
                        stop.store(true, Ordering::Relaxed);
                        write_handle.abort();
                        read_handle.abort();
                        return Err(e);
                    }
                    Some(BenchEvent::WriteDone) => {
                        write_done = true;
                    }
                    Some(BenchEvent::Read(Ok(sample))) => {
                        update_bench_bar(&read_bar, &sample);
                        all_e2e_latencies.extend(sample.e2e_latencies.iter().copied());
                        if let Some(hash) = sample.chain_hash {
                            read_chain_hash = Some(hash);
                        }
                        read_sample = Some(sample);
                    }
                    Some(BenchEvent::Read(Err(e))) => {
                        write_bar.finish_and_clear();
                        read_bar.finish_and_clear();
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

    write_bar.finish_and_clear();
    read_bar.finish_and_clear();

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

    if !all_ack_latencies.is_empty() {
        eprintln!();
        print_latency_stats(LatencyStats::compute(all_ack_latencies), "Ack");
    }
    if !all_e2e_latencies.is_empty() {
        eprintln!();
        print_latency_stats(LatencyStats::compute(all_e2e_latencies), "End-to-End");
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
    tokio::time::sleep(catchup_delay).await;

    let catchup_bar = ProgressBar::no_length()
        .with_prefix(format!("{:width$}", "catchup", width = prefix_width))
        .with_style(
            ProgressStyle::default_bar()
                .template("{prefix:.bold.cyan} {msg}")
                .expect("valid template"),
        );
    let mut catchup_sample: Option<BenchReadSample> = None;
    let mut catchup_chain_hash: Option<u64> = None;
    let catchup_stream = bench_read_catchup(stream.clone(), record_size, bench_start);
    let mut catchup_stream = std::pin::pin!(catchup_stream);
    while let Some(result) = catchup_stream.next().await {
        match result {
            Ok(sample) => {
                update_bench_bar(&catchup_bar, &sample);
                if let Some(hash) = sample.chain_hash {
                    catchup_chain_hash = Some(hash);
                }
                catchup_sample = Some(sample);
            }
            Err(e) => {
                catchup_bar.finish_and_clear();
                return Err(e);
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

    if let (Some(write_sample), Some(catchup_sample)) =
        (write_sample.as_ref(), catchup_sample.as_ref())
        && write_sample.records != catchup_sample.records
    {
        return Err(CliError::BenchVerification(format!(
            "catchup read record count mismatch: expected {}, got {}",
            write_sample.records, catchup_sample.records
        )));
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

fn print_latency_stats(stats: LatencyStats, name: &str) {
    eprintln!("{}", format!("{name} Latency Statistics ").yellow().bold());

    fn stat_duration(key: &str, val: Duration, scale: f64) {
        let bar = "⠸".repeat((val.as_millis() as f64 * scale).round() as usize);
        eprintln!(
            "{:7}: {:>7} │ {}",
            key,
            format!("{} ms", val.as_millis()).green().bold(),
            bar
        );
    }

    let stats = stats.into_vec();
    let max_val = stats
        .iter()
        .map(|(_, val)| val)
        .max()
        .unwrap_or(&Duration::ZERO);

    let max_bar_len = 50;
    let scale = if max_val.as_millis() > max_bar_len {
        max_bar_len as f64 / max_val.as_millis() as f64
    } else {
        1.0
    };

    for (name, val) in stats {
        stat_duration(&name, val, scale);
    }
}
