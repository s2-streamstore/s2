use std::{pin::Pin, time::Duration};

use futures::{Stream, StreamExt, TryStreamExt, stream, stream::FuturesUnordered};
use s2_sdk::{
    self as sdk, S2, S2Stream,
    batching::BatchingConfig,
    producer::{IndexedAppendAck, ProducerConfig},
    types::{
        AccessTokenId, AccessTokenInfo, AccessTokenScopeInput, AccountMetricSet, AppendAck,
        AppendInput, AppendRecord, AppendRecordBatch, BasinInfo, BasinMetricSet, BasinName,
        BasinReconfiguration, CommandRecord, CreateBasinInput, CreateStreamInput, DeleteBasinInput,
        DeleteStreamInput, FencingToken, GetAccountMetricsInput, GetBasinMetricsInput,
        GetStreamMetricsInput, IssueAccessTokenInput, ListAccessTokensInput,
        ListAllAccessTokensInput, ListAllBasinsInput, ListAllStreamsInput, ListBasinsInput,
        ListStreamsInput, MeteredBytes, Metric, ReadBatch, ReadFrom, ReadInput, ReadLimits,
        ReadStart, ReadStop, ReconfigureBasinInput, ReconfigureStreamInput, S2DateTime,
        SequencedRecord, StreamInfo, StreamMetricSet, StreamPosition, StreamReconfiguration,
        Streaming, TimeRange, TimeRangeAndInterval,
    },
};

use crate::{
    cli::{
        CreateBasinArgs, CreateStreamArgs, FenceArgs, GetAccountMetricsArgs, GetBasinMetricsArgs,
        GetStreamMetricsArgs, IssueAccessTokenArgs, ListAccessTokensArgs, ListBasinsArgs,
        ListStreamsArgs, ReadArgs, ReconfigureBasinArgs, ReconfigureStreamArgs, TailArgs,
        TimeRangeArgs, TrimArgs,
    },
    error::{CliError, OpKind},
    types::{BasinConfig, Interval, S2BasinAndStreamUri, StreamConfig},
};

pub async fn list_basins<'a>(
    s2: &'a S2,
    args: ListBasinsArgs,
) -> Result<Pin<Box<dyn Stream<Item = Result<BasinInfo, CliError>> + Send + 'a>>, CliError> {
    let ListBasinsArgs {
        prefix,
        start_after,
        limit,
        no_auto_paginate,
    } = args;

    if no_auto_paginate {
        let mut input = ListBasinsInput::new();
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = start_after {
            input = input.with_start_after(s);
        }
        if let Some(l) = limit {
            input = input.with_limit(l);
        }

        let page = s2
            .list_basins(input)
            .await
            .map_err(|e| CliError::op(OpKind::ListBasins, e))?;

        Ok(Box::pin(stream::iter(page.values.into_iter().map(Ok))))
    } else {
        let mut input = ListAllBasinsInput::new().with_include_deleted(true);
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = start_after {
            input = input.with_start_after(s);
        }

        let stream = s2
            .list_all_basins(input)
            .take(limit.unwrap_or(usize::MAX))
            .map_err(|e| CliError::op(OpKind::ListBasins, e));

        Ok(Box::pin(stream))
    }
}

pub async fn create_basin(s2: &S2, args: CreateBasinArgs) -> Result<BasinInfo, CliError> {
    let input = CreateBasinInput::new(args.basin.into()).with_config(args.config.into());
    s2.create_basin(input)
        .await
        .map_err(|e| CliError::op(OpKind::CreateBasin, e))
}

pub async fn delete_basin(s2: &S2, basin: &BasinName) -> Result<(), CliError> {
    s2.delete_basin(DeleteBasinInput::new(basin.clone()))
        .await
        .map_err(|e| CliError::op(OpKind::DeleteBasin, e))
}

pub async fn get_basin_config(
    s2: &S2,
    basin: &BasinName,
) -> Result<sdk::types::BasinConfig, CliError> {
    s2.get_basin_config(basin.clone())
        .await
        .map_err(|e| CliError::op(OpKind::GetBasinConfig, e))
}

pub async fn reconfigure_basin(
    s2: &S2,
    args: ReconfigureBasinArgs,
) -> Result<BasinConfig, CliError> {
    let mut reconfig =
        BasinReconfiguration::new().with_default_stream_config(args.default_stream_config.into());
    if let Some(val) = args.create_stream_on_append {
        reconfig = reconfig.with_create_stream_on_append(val);
    }
    if let Some(val) = args.create_stream_on_read {
        reconfig = reconfig.with_create_stream_on_read(val);
    }

    let config = s2
        .reconfigure_basin(ReconfigureBasinInput::new(args.basin.into(), reconfig))
        .await
        .map_err(|e| CliError::op(OpKind::ReconfigureBasin, e))?;

    Ok(config.into())
}

pub async fn list_access_tokens<'a>(
    s2: &'a S2,
    args: ListAccessTokensArgs,
) -> Result<Pin<Box<dyn Stream<Item = Result<AccessTokenInfo, CliError>> + Send + 'a>>, CliError> {
    let ListAccessTokensArgs {
        prefix,
        start_after,
        limit,
        no_auto_paginate,
    } = args;

    if no_auto_paginate {
        let mut input = ListAccessTokensInput::new();
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = start_after {
            input = input.with_start_after(s);
        }
        if let Some(l) = limit {
            input = input.with_limit(l);
        }

        let page = s2
            .list_access_tokens(input)
            .await
            .map_err(|e| CliError::op(OpKind::ListAccessTokens, e))?;

        Ok(Box::pin(stream::iter(page.values.into_iter().map(Ok))))
    } else {
        let mut input = ListAllAccessTokensInput::new();
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = start_after {
            input = input.with_start_after(s);
        }

        let stream = s2
            .list_all_access_tokens(input)
            .take(limit.unwrap_or(usize::MAX))
            .map_err(|e| CliError::op(OpKind::ListAccessTokens, e));

        Ok(Box::pin(stream))
    }
}

pub async fn issue_access_token(s2: &S2, args: IssueAccessTokenArgs) -> Result<String, CliError> {
    let mut scope = AccessTokenScopeInput::from_ops(args.ops.into_iter().map(|op| op.into()));
    if let Some(basins) = args.basins {
        scope = scope.with_basins(basins.into());
    }
    if let Some(streams) = args.streams {
        scope = scope.with_streams(streams.into());
    }
    if let Some(access_tokens) = args.access_tokens {
        scope = scope.with_access_tokens(access_tokens.into());
    }
    if let Some(op_group_perms) = args.op_group_perms {
        scope = scope.with_op_group_perms(op_group_perms.into());
    }

    let mut input = IssueAccessTokenInput::new(args.id, scope);
    if let Some(expires_in) = args.expires_in {
        let expiry_time = std::time::SystemTime::now() + *expires_in;
        let rfc3339 = humantime::format_rfc3339(expiry_time).to_string();
        let dt: S2DateTime = rfc3339.parse().map_err(|e| {
            CliError::InvalidArgs(miette::miette!("Invalid expiration time: {}", e))
        })?;
        input = input.with_expires_at(dt);
    } else if let Some(expires_at) = args.expires_at {
        let dt: S2DateTime = expires_at.parse().map_err(|e| {
            CliError::InvalidArgs(miette::miette!(
                "Invalid expires_at (expected RFC3339 format, e.g., '2024-12-31T23:59:59Z'): {}",
                e
            ))
        })?;
        input = input.with_expires_at(dt);
    }
    if args.auto_prefix_streams {
        input = input.with_auto_prefix_streams(true);
    }

    s2.issue_access_token(input)
        .await
        .map_err(|e| CliError::op(OpKind::IssueAccessToken, e))
}

pub async fn revoke_access_token(s2: &S2, id: AccessTokenId) -> Result<(), CliError> {
    s2.revoke_access_token(id)
        .await
        .map_err(|e| CliError::op(OpKind::RevokeAccessToken, e))
}

pub async fn get_account_metrics(
    s2: &S2,
    args: GetAccountMetricsArgs,
) -> Result<Vec<Metric>, CliError> {
    use crate::cli::AccountMetricCommand;

    let set = match args.metric {
        AccountMetricCommand::ActiveBasins(t) => {
            let (start, end) = resolve_time_range(&t);
            AccountMetricSet::ActiveBasins(TimeRange::new(start, end))
        }
        AccountMetricCommand::AccountOps(t) => {
            let (start, end) = resolve_time_range(&t.time_range);
            AccountMetricSet::AccountOps(time_range_and_interval(start, end, t.interval))
        }
    };

    let input = GetAccountMetricsInput::new(set);
    s2.get_account_metrics(input)
        .await
        .map_err(|e| CliError::op(OpKind::GetAccountMetrics, e))
}

pub async fn get_basin_metrics(
    s2: &S2,
    args: GetBasinMetricsArgs,
) -> Result<Vec<Metric>, CliError> {
    use crate::cli::BasinMetricCommand;

    let set = match args.metric {
        BasinMetricCommand::Storage(t) => {
            let (start, end) = resolve_time_range(&t);
            BasinMetricSet::Storage(TimeRange::new(start, end))
        }
        BasinMetricCommand::AppendOps(t) => {
            let (start, end) = resolve_time_range(&t.time_range);
            BasinMetricSet::AppendOps(time_range_and_interval(start, end, t.interval))
        }
        BasinMetricCommand::ReadOps(t) => {
            let (start, end) = resolve_time_range(&t.time_range);
            BasinMetricSet::ReadOps(time_range_and_interval(start, end, t.interval))
        }
        BasinMetricCommand::ReadThroughput(t) => {
            let (start, end) = resolve_time_range(&t.time_range);
            BasinMetricSet::ReadThroughput(time_range_and_interval(start, end, t.interval))
        }
        BasinMetricCommand::AppendThroughput(t) => {
            let (start, end) = resolve_time_range(&t.time_range);
            BasinMetricSet::AppendThroughput(time_range_and_interval(start, end, t.interval))
        }
        BasinMetricCommand::BasinOps(t) => {
            let (start, end) = resolve_time_range(&t.time_range);
            BasinMetricSet::BasinOps(time_range_and_interval(start, end, t.interval))
        }
    };

    let input = GetBasinMetricsInput::new(args.basin.into(), set);
    s2.get_basin_metrics(input)
        .await
        .map_err(|e| CliError::op(OpKind::GetBasinMetrics, e))
}

pub async fn get_stream_metrics(
    s2: &S2,
    args: GetStreamMetricsArgs,
) -> Result<Vec<Metric>, CliError> {
    use crate::cli::StreamMetricCommand;

    let set = match args.metric {
        StreamMetricCommand::Storage(t) => {
            let (start, end) = resolve_time_range(&t);
            StreamMetricSet::Storage(TimeRange::new(start, end))
        }
    };

    let input = GetStreamMetricsInput::new(args.uri.basin, args.uri.stream, set);
    s2.get_stream_metrics(input)
        .await
        .map_err(|e| CliError::op(OpKind::GetStreamMetrics, e))
}

pub async fn list_streams<'a>(
    s2: &'a S2,
    args: ListStreamsArgs,
) -> Result<Pin<Box<dyn Stream<Item = Result<StreamInfo, CliError>> + Send + 'a>>, CliError> {
    let prefix = args.uri.stream.or(args.prefix);
    let basin = s2.basin(args.uri.basin);

    if args.no_auto_paginate {
        let mut input = ListStreamsInput::new();
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = args.start_after {
            input = input.with_start_after(s);
        }
        if let Some(l) = args.limit {
            input = input.with_limit(l);
        }

        let page = basin
            .list_streams(input)
            .await
            .map_err(|e| CliError::op(OpKind::ListStreams, e))?;

        Ok(Box::pin(stream::iter(page.values.into_iter().map(Ok))))
    } else {
        let mut input = ListAllStreamsInput::new().with_include_deleted(true);
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = args.start_after {
            input = input.with_start_after(s);
        }

        let stream = basin
            .list_all_streams(input)
            .take(args.limit.unwrap_or(usize::MAX))
            .map_err(|e| CliError::op(OpKind::ListStreams, e));

        Ok(Box::pin(stream))
    }
}

pub async fn create_stream(s2: &S2, args: CreateStreamArgs) -> Result<StreamInfo, CliError> {
    let basin = s2.basin(args.uri.basin);
    let input = CreateStreamInput::new(args.uri.stream).with_config(args.config.into());
    basin
        .create_stream(input)
        .await
        .map_err(|e| CliError::op(OpKind::CreateStream, e))
}

pub async fn delete_stream(s2: &S2, uri: S2BasinAndStreamUri) -> Result<(), CliError> {
    let basin = s2.basin(uri.basin);
    basin
        .delete_stream(DeleteStreamInput::new(uri.stream))
        .await
        .map_err(|e| CliError::op(OpKind::DeleteStream, e))
}

pub async fn get_stream_config(
    s2: &S2,
    uri: S2BasinAndStreamUri,
) -> Result<sdk::types::StreamConfig, CliError> {
    let basin = s2.basin(uri.basin);
    basin
        .get_stream_config(uri.stream)
        .await
        .map_err(|e| CliError::op(OpKind::GetStreamConfig, e))
}

pub async fn reconfigure_stream(
    s2: &S2,
    args: ReconfigureStreamArgs,
) -> Result<StreamConfig, CliError> {
    let basin = s2.basin(args.uri.basin);

    let reconfig: StreamReconfiguration = args.config.into();
    let config = basin
        .reconfigure_stream(ReconfigureStreamInput::new(args.uri.stream, reconfig))
        .await
        .map_err(|e| CliError::op(OpKind::ReconfigureStream, e))?;

    Ok(config.into())
}

pub async fn check_tail(s2: &S2, uri: S2BasinAndStreamUri) -> Result<StreamPosition, CliError> {
    let stream = s2.basin(uri.basin).stream(uri.stream);
    stream
        .check_tail()
        .await
        .map_err(|e| CliError::op(OpKind::CheckTail, e))
}

pub async fn trim(s2: &S2, args: TrimArgs) -> Result<AppendAck, CliError> {
    let stream = s2.basin(args.uri.basin).stream(args.uri.stream);
    append_command(
        &stream,
        CommandRecord::trim(args.trim_point),
        args.fencing_token,
        args.match_seq_num,
        OpKind::Trim,
    )
    .await
}

pub async fn fence(s2: &S2, args: FenceArgs) -> Result<AppendAck, CliError> {
    let stream = s2.basin(args.uri.basin).stream(args.uri.stream);
    append_command(
        &stream,
        CommandRecord::fence(args.new_fencing_token),
        args.fencing_token,
        args.match_seq_num,
        OpKind::Fence,
    )
    .await
}

pub async fn read(s2: &S2, args: &ReadArgs) -> Result<Streaming<ReadBatch>, CliError> {
    use std::time::SystemTime;

    let uri = args.uri.clone();
    let stream = s2.basin(uri.basin).stream(uri.stream);

    let from = match (args.seq_num, args.timestamp, args.tail_offset, args.ago) {
        (Some(seq), None, None, None) => ReadFrom::SeqNum(seq),
        (None, Some(ts), None, None) => ReadFrom::Timestamp(ts),
        (None, None, Some(offset), None) => ReadFrom::TailOffset(offset),
        (None, None, None, Some(ago)) => {
            let ts = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .saturating_sub(ago.as_millis()) as u64;
            ReadFrom::Timestamp(ts)
        }
        (None, None, None, None) => ReadFrom::TailOffset(0),
        _ => unreachable!("clap ensures only one start option"),
    };

    let start = ReadStart::new()
        .with_from(from)
        .with_clamp_to_tail(args.clamp);

    let mut limits = ReadLimits::new();
    if let Some(count) = args.count {
        limits = limits.with_count(count as usize);
    }
    if let Some(bytes) = args.bytes {
        limits = limits.with_bytes(bytes as usize);
    }

    let mut stop = ReadStop::new().with_limits(limits);
    if let Some(until) = args.until {
        stop = stop.with_until(..until);
    }

    stream
        .read_session(ReadInput::new().with_start(start).with_stop(stop))
        .await
        .map_err(|e| CliError::op(OpKind::Read, e))
}

pub fn append<'a, S, E>(
    s2: &'a S2,
    records: S,
    uri: S2BasinAndStreamUri,
    fencing_token: Option<FencingToken>,
    match_seq_num: Option<u64>,
    linger: Duration,
) -> impl Stream<Item = Result<IndexedAppendAck, CliError>> + Send + 'a
where
    S: Stream<Item = Result<AppendRecord, E>> + Send + Unpin + 'a,
    E: std::error::Error + Send + Sync + 'static,
{
    let stream = s2.basin(uri.basin).stream(uri.stream);

    let batching_config = BatchingConfig::new().with_linger(linger);
    let mut producer_config = ProducerConfig::new().with_batching(batching_config);
    if let Some(ft) = fencing_token {
        producer_config = producer_config.with_fencing_token(ft);
    }
    if let Some(seq) = match_seq_num {
        producer_config = producer_config.with_match_seq_num(seq);
    }

    let producer = stream.producer(producer_config);

    async_stream::stream! {
        let mut records = records;
        let mut pending_acks = FuturesUnordered::new();
        let mut input_done = false;
        let mut stashed_record: Option<AppendRecord> = None;
        let mut stashed_bytes: u32 = 0;

        'inner: loop {
            tokio::select! {
                permit = producer.reserve(stashed_bytes), if stashed_record.is_some() => {
                    match permit {
                        Ok(permit) => {
                            let record = stashed_record.take().unwrap();
                            pending_acks.push(permit.submit(record));
                        }
                        Err(e) => {
                            yield Err(CliError::op(OpKind::Append, e));
                            break 'inner;
                        }
                    }
                }

                res = records.next(), if stashed_record.is_none() && !input_done => {
                    match res {
                        Some(Ok(record)) => {
                            stashed_bytes = record.metered_bytes() as u32;
                            stashed_record = Some(record);
                        }
                        Some(Err(e)) => {
                            yield Err(CliError::RecordReaderInit(e.to_string()));
                            break 'inner;
                        }
                        None => {
                            input_done = true;
                        }
                    }
                }

                Some(res) = pending_acks.next() => {
                    match res {
                        Ok(ack) => yield Ok(ack),
                        Err(e) => {
                            yield Err(CliError::op(OpKind::Append, e));
                            break 'inner;
                        }
                    }
                }

                else => {
                    if input_done && stashed_record.is_none() && pending_acks.is_empty() {
                        break;
                    }
                }
            }
        }

        if let Err(e) = producer.close().await {
            yield Err(CliError::op(OpKind::Append, e));
            return;
        }

        while let Some(res) = pending_acks.next().await {
            match res {
                Ok(ack) => yield Ok(ack),
                Err(e) => {
                    yield Err(CliError::op(OpKind::Append, e));
                    return;
                }
            }
        }
    }
}

pub async fn tail(
    s2: &S2,
    args: &TailArgs,
) -> Result<Pin<Box<dyn Stream<Item = Result<SequencedRecord, CliError>> + Send>>, CliError> {
    let uri = args.uri.clone();
    let stream = s2.basin(uri.basin).stream(uri.stream);

    let start = ReadStart::new().with_from(ReadFrom::TailOffset(args.lines));
    let stop = if args.follow {
        ReadStop::new()
    } else {
        ReadStop::new().with_limits(ReadLimits::new().with_count(args.lines as usize))
    };

    let batches = stream
        .read_session(ReadInput::new().with_start(start).with_stop(stop))
        .await
        .map_err(|e| CliError::op(OpKind::Tail, e))?;

    Ok(Box::pin(
        batches
            .map_err(|e| CliError::op(OpKind::Tail, e))
            .flat_map(|batch_result| match batch_result {
                Ok(batch) => stream::iter(batch.records.into_iter().map(Ok)).left_stream(),
                Err(e) => stream::iter(std::iter::once(Err(e))).right_stream(),
            }),
    ))
}

async fn append_command(
    stream: &S2Stream,
    command: CommandRecord,
    fencing_token: Option<FencingToken>,
    match_seq_num: Option<u64>,
    op_error: OpKind,
) -> Result<AppendAck, CliError> {
    let record: AppendRecord = command.into();
    let records = AppendRecordBatch::try_from_iter([record])
        .expect("single command record should always fit in a batch");
    let mut input = AppendInput::new(records);
    if let Some(ft) = fencing_token {
        input = input.with_fencing_token(ft);
    }
    if let Some(seq) = match_seq_num {
        input = input.with_match_seq_num(seq);
    }
    stream
        .append(input)
        .await
        .map_err(|e| CliError::op(op_error, e))
}

fn resolve_time(timestamp: Option<u32>, ago: Option<humantime::Duration>) -> u32 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;

    match (timestamp, ago) {
        (Some(ts), None) => ts,
        (None, Some(ago)) => now.saturating_sub(ago.as_secs() as u32),
        (None, None) => unreachable!("clap group ensures one is specified"),
        (Some(_), Some(_)) => unreachable!("clap group ensures only one is specified"),
    }
}

fn resolve_time_range(args: &TimeRangeArgs) -> (u32, u32) {
    (
        resolve_time(args.start_timestamp, args.start_ago),
        resolve_time(args.end_timestamp, args.end_ago),
    )
}

fn time_range_and_interval(
    start: u32,
    end: u32,
    interval: Option<Interval>,
) -> TimeRangeAndInterval {
    let mut range = TimeRangeAndInterval::new(start, end);
    if let Some(interval) = interval {
        range = range.with_interval(interval.into());
    }
    range
}
