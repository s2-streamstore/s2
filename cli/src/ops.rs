use std::time::Duration;

use futures::{Stream, StreamExt, TryStreamExt, stream::FuturesOrdered};
use s2_api::v1::{
    access::AccessTokenInfo as ApiAccessTokenInfo,
    config::{BasinConfig as ApiBasinConfig, StreamConfig as ApiStreamConfig},
};
use s2_sdk::{
    self as sdk, S2, S2Stream,
    producer::{ProducerConfig, RecordAck},
    read_session::{ReadBatchSession, ReadSessionConfig},
    types::{
        AccessTokenId, AccessTokenInfo, AccessTokenScopeInput, AccountMetricSet, AppendAck,
        AppendInput, AppendRecord, AppendRecordBatch, AwsPrivateNetPolicy, BasinInfo,
        BasinMetricSet, BasinName, BasinReconfiguration, CommandRecord, CreateBasinInput,
        CreateStreamInput, EncryptionKey, FencingToken, IssueAccessTokenInput,
        ListAccessTokensInput, ListAllAccessTokensInput, ListAllBasinsInput,
        ListAllNetworkPoliciesInput, ListAllStreamsInput, ListBasinsInput,
        ListNetworkPoliciesInput, ListStreamsInput, LocationInfo, LocationName, MeteredBytes,
        Metric, NetworkPolicy, NetworkPolicyInfo, NetworkPolicySelector, PublicNetPolicy, ReadFrom,
        ReadInput, SequencedRecord, StreamInfo, StreamMetricSet, StreamNamePrefix, StreamPosition,
        StreamReconfiguration, TimeRangeAndInterval, TimeseriesInterval, Timestamp,
    },
};

fn stream_with_encryption(
    s2: &S2,
    uri: S2BasinAndStreamUri,
    encryption_key: Option<&EncryptionKey>,
) -> S2Stream {
    let stream = s2.basin(uri.basin).stream(uri.stream);
    match encryption_key {
        Some(encryption_key) => stream.with_encryption_key(encryption_key.clone()),
        None => stream,
    }
}

use crate::{
    cli::{
        CreateBasinArgs, CreateNetworkPolicyArgs, CreateStreamArgs, FenceArgs,
        GetAccountMetricsArgs, GetBasinMetricsArgs, GetStreamMetricsArgs, IssueAccessTokenArgs,
        ListAccessTokensArgs, ListBasinsArgs, ListNetworkPoliciesArgs, ListStreamsArgs, ReadArgs,
        ReconfigureBasinArgs, ReconfigureStreamArgs, TailArgs, TimeRangeArgs, TrimArgs,
    },
    error::{CliError, OpKind},
    types::{BasinConfig, Interval, PermittedOperationGroups, S2BasinAndStreamUri, StreamConfig},
};

/// List basins, returning items and whether there are more.
/// If `no_auto_paginate` is true, returns a single page.
/// If false, fetches all pages and returns (all_items, false).
pub async fn list_basins(
    s2: &S2,
    args: ListBasinsArgs,
) -> Result<(Vec<BasinInfo>, bool), CliError> {
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
        Ok((page.values, page.has_more))
    } else {
        let mut input = ListAllBasinsInput::new().with_include_deleted(true);
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = start_after {
            input = input.with_start_after(s);
        }

        let items: Vec<_> = s2
            .list_all_basins(input)
            .take(limit.unwrap_or(usize::MAX))
            .try_collect()
            .await
            .map_err(|e| CliError::op(OpKind::ListBasins, e))?;

        Ok((items, false))
    }
}

pub async fn create_basin(s2: &S2, args: CreateBasinArgs) -> Result<BasinInfo, CliError> {
    let mut input = CreateBasinInput::new(args.basin.into()).with_config(args.config.into());
    if let Some(location) = args.location {
        input = input.with_location(location);
    }
    s2.create_basin(input)
        .await
        .map_err(|e| CliError::op(OpKind::CreateBasin, e))
}

pub async fn delete_basin(s2: &S2, basin: &BasinName) -> Result<(), CliError> {
    s2.delete_basin(basin.clone())
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

pub async fn get_basin_config_api(s2: &S2, basin: &BasinName) -> Result<ApiBasinConfig, CliError> {
    s2.get_basin_config_api(basin.clone())
        .await
        .map_err(|e| CliError::op(OpKind::GetBasinConfig, e))
}

pub async fn reconfigure_basin(
    s2: &S2,
    args: ReconfigureBasinArgs,
) -> Result<BasinConfig, CliError> {
    let mut reconfig = BasinReconfiguration::new();
    if !args.default_stream_config.is_empty() {
        reconfig = reconfig.with_default_stream_config(args.default_stream_config.into());
    }
    if let Some(algorithm) = args.stream_cipher {
        reconfig = reconfig.with_stream_cipher(algorithm.into());
    }
    if let Some(val) = args.create_stream_on_append {
        reconfig = reconfig.with_create_stream_on_append(val);
    }
    if let Some(val) = args.create_stream_on_read {
        reconfig = reconfig.with_create_stream_on_read(val);
    }

    reconfigure_basin_with(s2, args.basin.into(), reconfig).await
}

pub async fn reconfigure_basin_with(
    s2: &S2,
    basin: BasinName,
    reconfig: BasinReconfiguration,
) -> Result<BasinConfig, CliError> {
    let config = s2
        .reconfigure_basin(basin, reconfig)
        .await
        .map_err(|e| CliError::op(OpKind::ReconfigureBasin, e))?;

    Ok(config.into())
}

/// List access tokens, returning items and whether there are more.
pub async fn list_access_tokens(
    s2: &S2,
    args: ListAccessTokensArgs,
) -> Result<(Vec<AccessTokenInfo>, bool), CliError> {
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

        Ok((page.values, page.has_more))
    } else {
        let mut input = ListAllAccessTokensInput::new();
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = start_after {
            input = input.with_start_after(s);
        }

        let items: Vec<_> = s2
            .list_all_access_tokens(input)
            .take(limit.unwrap_or(usize::MAX))
            .try_collect()
            .await
            .map_err(|e| CliError::op(OpKind::ListAccessTokens, e))?;

        Ok((items, false))
    }
}

pub async fn get_access_token_api(
    s2: &S2,
    id: AccessTokenId,
) -> Result<ApiAccessTokenInfo, CliError> {
    let page = s2
        .list_access_tokens_api(
            ListAccessTokensInput::new()
                .with_prefix(id.clone().into())
                .with_limit(1),
        )
        .await
        .map_err(|e| CliError::op(OpKind::ListAccessTokens, e))?;

    page.access_tokens
        .into_iter()
        .find(|info| info.id == id)
        .ok_or_else(|| CliError::AccessTokenNotFound(id.to_string()))
}

/// A preset allows every resource of a kind that no flag names. Without one, the token cannot
/// access that kind at all.
fn access_token_scope(args: &IssueAccessTokenArgs) -> Result<AccessTokenScopeInput, CliError> {
    let op_group_perms = args
        .preset
        .map(PermittedOperationGroups::from)
        .or_else(|| args.op_group_perms.clone());
    if op_group_perms.is_none() && args.ops.is_empty() {
        return Err(CliError::InvalidArgs(miette::miette!(
            help = "Use '--preset full-access' or '--preset read-only', or choose operations with '--op-group-perms' or '--ops'",
            "No permissions given for the access token"
        )));
    }
    let all = args.preset.is_some();

    let mut scope = AccessTokenScopeInput::from_ops(args.ops.iter().cloned().map(|op| op.into()));
    if let Some(v) = args.basins_exact.clone() {
        scope = scope.with_basins(sdk::types::BasinMatcher::Exact(v));
    } else if let Some(v) = args.basins_prefix.clone().or(all.then(Default::default)) {
        scope = scope.with_basins(sdk::types::BasinMatcher::Prefix(v));
    }
    if let Some(v) = args.streams_exact.clone() {
        scope = scope.with_streams(sdk::types::StreamMatcher::Exact(v));
    } else if let Some(v) = args.streams_prefix.clone().or(all.then(Default::default)) {
        scope = scope.with_streams(sdk::types::StreamMatcher::Prefix(v));
    }
    if let Some(v) = args.access_tokens_exact.clone() {
        scope = scope.with_access_tokens(sdk::types::AccessTokenMatcher::Exact(v));
    } else if let Some(v) = args
        .access_tokens_prefix
        .clone()
        .or(all.then(Default::default))
    {
        scope = scope.with_access_tokens(sdk::types::AccessTokenMatcher::Prefix(v));
    }
    if let Some(op_group_perms) = op_group_perms {
        scope = scope.with_op_group_perms(op_group_perms.into());
    }
    Ok(scope)
}

pub async fn issue_access_token(s2: &S2, args: IssueAccessTokenArgs) -> Result<String, CliError> {
    let scope = access_token_scope(&args)?;

    let mut input = IssueAccessTokenInput::new(args.id, scope);
    if let Some(expires_in) = args.expires_in {
        let dt = Timestamp::now()
            .checked_add(*expires_in)
            .map_err(|e| CliError::InvalidArgs(miette::miette!("Invalid expiration time: {e}")))?;
        input = input
            .with_expires_at(dt)
            .map_err(|e| CliError::InvalidArgs(miette::miette!("Invalid expiration time: {e}")))?;
    } else if let Some(expires_at) = args.expires_at {
        let dt: Timestamp = expires_at.parse().map_err(|e| {
            CliError::InvalidArgs(miette::miette!(
                "Invalid expires_at (expected RFC3339 format, e.g., '2024-12-31T23:59:59Z'): {}",
                e
            ))
        })?;
        input = input
            .with_expires_at(dt)
            .map_err(|e| CliError::InvalidArgs(miette::miette!("Invalid expires_at: {e}")))?;
    }
    if args.auto_prefix_streams {
        input = input.with_auto_prefix_streams(true);
    }
    if let Some(network_policy) = args.network_policy {
        input = input.with_network_policy(network_policy);
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

/// List network policies, returning items and whether there are more.
pub async fn list_network_policies(
    s2: &S2,
    args: ListNetworkPoliciesArgs,
) -> Result<(Vec<NetworkPolicyInfo>, bool), CliError> {
    let ListNetworkPoliciesArgs {
        prefix,
        start_after,
        limit,
        no_auto_paginate,
    } = args;

    if no_auto_paginate {
        let mut input = ListNetworkPoliciesInput::new();
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
            .list_network_policies(input)
            .await
            .map_err(|e| CliError::op(OpKind::ListNetworkPolicies, e))?;

        Ok((page.values, page.has_more))
    } else {
        let mut input = ListAllNetworkPoliciesInput::new();
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = start_after {
            input = input.with_start_after(s);
        }

        let items: Vec<_> = s2
            .list_all_network_policies(input)
            .take(limit.unwrap_or(usize::MAX))
            .try_collect()
            .await
            .map_err(|e| CliError::op(OpKind::ListNetworkPolicies, e))?;

        Ok((items, false))
    }
}

pub async fn create_network_policy(
    s2: &S2,
    args: CreateNetworkPolicyArgs,
) -> Result<NetworkPolicyInfo, CliError> {
    let CreateNetworkPolicyArgs {
        slug,
        cidr,
        aws_vpce,
    } = args;

    let mut policy = NetworkPolicy::new();
    if !cidr.is_empty() {
        policy = policy.with_public_net(PublicNetPolicy::Cidrs(cidr));
    }
    if !aws_vpce.is_empty() {
        policy = policy.with_private_net(AwsPrivateNetPolicy::new(aws_vpce));
    }

    s2.create_network_policy(slug, policy)
        .await
        .map_err(|e| CliError::op(OpKind::CreateNetworkPolicy, e))
}

pub async fn get_network_policy(
    s2: &S2,
    selector: NetworkPolicySelector,
) -> Result<NetworkPolicyInfo, CliError> {
    s2.get_network_policy(selector)
        .await
        .map_err(|e| CliError::op(OpKind::GetNetworkPolicy, e))
}

pub async fn delete_network_policy(s2: &S2, id: NetworkPolicySelector) -> Result<(), CliError> {
    s2.delete_network_policy(id)
        .await
        .map_err(|e| CliError::op(OpKind::DeleteNetworkPolicy, e))
}

/// List locations.
pub async fn list_locations(s2: &S2) -> Result<Vec<LocationInfo>, CliError> {
    s2.list_locations()
        .await
        .map_err(|e| CliError::op(OpKind::ListLocations, e))
}

pub async fn get_default_location(s2: &S2) -> Result<LocationInfo, CliError> {
    s2.get_default_location()
        .await
        .map_err(|e| CliError::op(OpKind::GetDefaultLocation, e))
}

pub async fn set_default_location(
    s2: &S2,
    location: LocationName,
) -> Result<LocationInfo, CliError> {
    s2.set_default_location(location)
        .await
        .map_err(|e| CliError::op(OpKind::SetDefaultLocation, e))
}

/// The time range and interval asked for, alongside the metrics, for a metric set that takes them.
pub type MetricsInRange = (Option<TimeRangeAndInterval>, Vec<Metric>);

pub async fn get_account_metrics(
    s2: &S2,
    args: GetAccountMetricsArgs,
) -> Result<MetricsInRange, CliError> {
    use crate::cli::AccountMetricCommand;

    let (range, set) = match args.metric {
        AccountMetricCommand::ActiveBasins(t) => {
            let range = resolve_time_range(&t, None::<Interval>);
            let set = AccountMetricSet::ActiveBasins(range.range());
            (Some(range), set)
        }
        AccountMetricCommand::AccountOps(t) => {
            let range = resolve_time_range(&t.time_range, t.interval);
            (Some(range.clone()), AccountMetricSet::AccountOps(range))
        }
        AccountMetricCommand::EstimatedBillableUsage(t) => {
            let range = resolve_time_range(&t.time_range, t.interval);
            let set = AccountMetricSet::EstimatedBillableUsage(range.clone());
            (Some(range), set)
        }
        AccountMetricCommand::TokenActivity(t) => {
            (None, AccountMetricSet::TokenActivity(t.token_ids))
        }
    };

    let metrics = s2
        .get_account_metrics(set)
        .await
        .map_err(|e| CliError::op(OpKind::GetAccountMetrics, e))?;
    Ok((range, metrics))
}

pub async fn get_basin_metrics(
    s2: &S2,
    args: GetBasinMetricsArgs,
) -> Result<MetricsInRange, CliError> {
    use crate::cli::BasinMetricCommand;

    let (range, set) = match args.metric {
        BasinMetricCommand::Storage(t) => {
            let range = resolve_time_range(&t, None::<Interval>);
            let set = BasinMetricSet::Storage(range.range());
            (range, set)
        }
        BasinMetricCommand::AppendOps(t) => {
            let range = resolve_time_range(&t.time_range, t.interval);
            (range.clone(), BasinMetricSet::AppendOps(range))
        }
        BasinMetricCommand::ReadOps(t) => {
            let range = resolve_time_range(&t.time_range, t.interval);
            (range.clone(), BasinMetricSet::ReadOps(range))
        }
        BasinMetricCommand::ReadThroughput(t) => {
            let range = resolve_time_range(&t.time_range, t.interval);
            (range.clone(), BasinMetricSet::ReadThroughput(range))
        }
        BasinMetricCommand::AppendThroughput(t) => {
            let range = resolve_time_range(&t.time_range, t.interval);
            (range.clone(), BasinMetricSet::AppendThroughput(range))
        }
        BasinMetricCommand::BasinOps(t) => {
            let range = resolve_time_range(&t.time_range, t.interval);
            (range.clone(), BasinMetricSet::BasinOps(range))
        }
    };

    let metrics = s2
        .get_basin_metrics(args.basin.into(), set)
        .await
        .map_err(|e| CliError::op(OpKind::GetBasinMetrics, e))?;
    Ok((Some(range), metrics))
}

pub async fn get_stream_metrics(
    s2: &S2,
    args: GetStreamMetricsArgs,
) -> Result<MetricsInRange, CliError> {
    use crate::cli::StreamMetricCommand;

    let (range, set) = match args.metric {
        StreamMetricCommand::Storage(t) => {
            let range = resolve_time_range(&t, None::<Interval>);
            let set = StreamMetricSet::Storage(range.range());
            (range, set)
        }
    };

    let metrics = s2
        .get_stream_metrics(args.uri.basin, args.uri.stream, set)
        .await
        .map_err(|e| CliError::op(OpKind::GetStreamMetrics, e))?;
    Ok((Some(range), metrics))
}

fn list_streams_prefix(
    uri_prefix: Option<StreamNamePrefix>,
    prefix: Option<StreamNamePrefix>,
) -> Result<Option<StreamNamePrefix>, CliError> {
    match (uri_prefix, prefix) {
        (Some(_), Some(_)) => Err(CliError::InvalidArgs(miette::miette!(
            help = "Make sure to provide the prefix once either using '--prefix' opt or in URI like 's2://basin-name/prefix'",
            "Multiple prefixes provided"
        ))),
        (uri_prefix, prefix) => Ok(uri_prefix.or(prefix)),
    }
}

/// List streams, returning items and whether there are more.
pub async fn list_streams(
    s2: &S2,
    args: ListStreamsArgs,
) -> Result<(Vec<StreamInfo>, bool), CliError> {
    let prefix = list_streams_prefix(args.uri.stream, args.prefix)?;
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
        Ok((page.values, page.has_more))
    } else {
        let mut input = ListAllStreamsInput::new().with_include_deleted(true);
        if let Some(p) = prefix {
            input = input.with_prefix(p);
        }
        if let Some(s) = args.start_after {
            input = input.with_start_after(s);
        }

        let items: Vec<_> = basin
            .list_all_streams(input)
            .take(args.limit.unwrap_or(usize::MAX))
            .try_collect()
            .await
            .map_err(|e| CliError::op(OpKind::ListStreams, e))?;

        Ok((items, false))
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
        .delete_stream(uri.stream)
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

pub async fn get_stream_config_api(
    s2: &S2,
    uri: S2BasinAndStreamUri,
) -> Result<ApiStreamConfig, CliError> {
    let basin = s2.basin(uri.basin);
    basin
        .get_stream_config_api(uri.stream)
        .await
        .map_err(|e| CliError::op(OpKind::GetStreamConfig, e))
}

pub async fn reconfigure_stream(
    s2: &S2,
    args: ReconfigureStreamArgs,
) -> Result<StreamConfig, CliError> {
    let reconfig: StreamReconfiguration = args.config.into();
    reconfigure_stream_with(s2, args.uri, reconfig).await
}

pub async fn reconfigure_stream_with(
    s2: &S2,
    uri: S2BasinAndStreamUri,
    reconfig: StreamReconfiguration,
) -> Result<StreamConfig, CliError> {
    let config = s2
        .basin(uri.basin)
        .reconfigure_stream(uri.stream, reconfig)
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

pub fn read(
    s2: &S2,
    args: &ReadArgs,
    encryption_key: Option<&EncryptionKey>,
) -> Result<ReadBatchSession, CliError> {
    use std::time::SystemTime;

    let stream = stream_with_encryption(s2, args.uri.clone(), encryption_key);

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

    let mut input = ReadInput::new().with_from(from).with_clamp(args.clamp);
    if let Some(count) = args.count {
        input = input.with_count(count);
    }
    if let Some(bytes) = args.bytes {
        input = input.with_bytes(bytes);
    }
    if let Some(until) = args.until {
        input = input.with_until(until);
    }
    if !args.stream_config.is_empty() {
        input = input.with_stream_config(args.stream_config.clone().into());
    }

    stream
        .read_batch_session(input, ReadSessionConfig::default())
        .map_err(|e| CliError::op(OpKind::Read, e))
}

/// Options controlling how records are appended.
pub struct AppendOptions {
    pub fencing_token: Option<FencingToken>,
    pub match_seq_num: Option<u64>,
    pub linger: Duration,
    /// Stream configuration to apply if the stream is created on append.
    pub stream_config: Option<sdk::types::StreamConfig>,
}

pub fn append<'a, S, E>(
    s2: &'a S2,
    records: S,
    uri: S2BasinAndStreamUri,
    encryption_key: Option<&'a EncryptionKey>,
    options: AppendOptions,
) -> impl Stream<Item = Result<RecordAck, CliError>> + Send + 'a
where
    S: Stream<Item = Result<AppendRecord, E>> + Send + Unpin + 'a,
    E: std::error::Error + Send + Sync + 'static,
{
    let stream = stream_with_encryption(s2, uri, encryption_key);

    let mut producer_config = ProducerConfig::new().with_linger(options.linger);
    if let Some(config) = options.stream_config {
        producer_config = producer_config.with_stream_config(config);
    }
    if let Some(ft) = options.fencing_token {
        producer_config = producer_config.with_fencing_token(ft);
    }
    if let Some(seq) = options.match_seq_num {
        producer_config = producer_config.with_match_seq_num(seq);
    }

    let producer = stream.producer(producer_config);

    async_stream::stream! {
        let producer = match producer {
            Ok(producer) => producer,
            Err(e) => {
                yield Err(CliError::op(OpKind::Append, e));
                return;
            }
        };
        let mut records = records;
        let mut pending_acks = FuturesOrdered::new();
        let mut stashed_record: Option<AppendRecord> = None;
        let mut stashed_bytes: u32 = 0;

        'inner: loop {
            tokio::select! {
                permit = producer.reserve(stashed_bytes), if stashed_record.is_some() => {
                    match permit {
                        Ok(permit) => {
                            let record = stashed_record.take().unwrap();
                            match permit.submit(record) {
                                Ok(ticket) => pending_acks.push_back(ticket),
                                Err(e) => {
                                    yield Err(CliError::op(OpKind::Append, e));
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            yield Err(CliError::op(OpKind::Append, e));
                            return;
                        }
                    }
                }

                res = records.next(), if stashed_record.is_none() => {
                    match res {
                        Some(Ok(record)) => {
                            stashed_bytes = record.metered_bytes() as u32;
                            stashed_record = Some(record);
                        }
                        Some(Err(e)) => {
                            yield Err(CliError::RecordReaderInit(e.to_string()));
                            return;
                        }
                        None => {
                            break 'inner;
                        }
                    }
                }

                Some(res) = pending_acks.next() => {
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

        let close_res = producer.close().await;

        while let Some(res) = pending_acks.next().await {
            match res {
                Ok(ack) => yield Ok(ack),
                Err(e) => {
                    yield Err(CliError::op(OpKind::Append, e));
                    return;
                }
            }
        }

        if let Err(e) = close_res {
            yield Err(CliError::op(OpKind::Append, e));
        }
    }
}

pub fn tail(
    s2: &S2,
    args: &TailArgs,
    encryption_key: Option<&EncryptionKey>,
) -> Result<impl Stream<Item = Result<SequencedRecord, CliError>> + Send + Unpin, CliError> {
    let stream = stream_with_encryption(s2, args.uri.clone(), encryption_key);

    // Use clamp to handle empty streams gracefully - if we ask for
    // TailOffset(10) but there are fewer records, clamp to the actual start.
    let mut input = ReadInput::new()
        .with_from(ReadFrom::TailOffset(args.lines))
        .with_clamp(true);
    if !args.follow {
        input = input.with_count(args.lines);
    }

    let mut records = stream
        .read_session(input, ReadSessionConfig::default())
        .map_err(|e| CliError::op(OpKind::Tail, e))?;

    let follow = args.follow;
    Ok(Box::pin(async_stream::stream! {
        let mut seen_any = false;
        while let Some(item) = records.next().await {
            match item {
                Ok(record) => {
                    seen_any = true;
                    yield Ok(record);
                }
                // Non-follow tail on an empty or fully-trimmed stream returns initial 416;
                // treat that as clean 0-record EOF.
                Err(sdk::error::ReadSessionError::ReadUnwritten(_)) if !follow && !seen_any => {
                    break;
                }
                Err(e) => {
                    yield Err(CliError::op(OpKind::Tail, e));
                    break;
                }
            }
        }
    }))
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

fn resolve_time(timestamp: Option<u32>, ago: Option<humantime::Duration>, now: u32) -> Option<u32> {
    match (timestamp, ago) {
        (Some(ts), None) => Some(ts),
        (None, Some(ago)) => {
            let secs = u32::try_from(ago.as_secs()).unwrap_or(u32::MAX);
            Some(now.saturating_sub(secs))
        }
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap group ensures only one is specified"),
    }
}

/// Up to now, where an end is not given, and from 30 days before the end, where a start is not.
/// The start follows the end so that an end in the past alone is still a valid range.
fn resolve_time_range(
    args: &TimeRangeArgs,
    interval: Option<impl Into<TimeseriesInterval>>,
) -> TimeRangeAndInterval {
    const DEFAULT_SPAN_SECS: u32 = 30 * 24 * 60 * 60;
    let now = u32::try_from(Timestamp::now().as_second().max(0)).unwrap_or(u32::MAX);
    let end = resolve_time(args.end_timestamp, args.end_ago, now).unwrap_or(now);
    let start = resolve_time(args.start_timestamp, args.start_ago, now)
        .unwrap_or_else(|| end.saturating_sub(DEFAULT_SPAN_SECS));
    let start = Timestamp::from_second(i64::from(start)).expect("u32 fits in Timestamp");
    let end = Timestamp::from_second(i64::from(end)).expect("u32 fits in Timestamp");
    let range = TimeRangeAndInterval::new(start, end).expect("u32 seconds in range");
    match interval {
        Some(interval) => range.with_interval(interval.into()),
        None => range,
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::cli::{AccessTokenCommand, Cli, Command};

    #[test]
    fn access_token_preset_is_all_resources_unless_narrowed() {
        let scope = |flags: &[&str]| {
            let cli = Cli::try_parse_from(["s2", "access-token", "issue", "t"].iter().chain(flags))
                .unwrap();
            let Some(Command::AccessToken(AccessTokenCommand::Issue(args))) = cli.command else {
                panic!("not an issue command");
            };
            access_token_scope(&args).map(|scope| format!("{scope:?}"))
        };
        assert_eq!(
            scope(&["--preset", "full-access"]).unwrap(),
            scope(&[
                "--basins-prefix",
                "",
                "--streams-prefix",
                "",
                "--access-tokens-prefix",
                "",
                "--op-group-perms",
                "account=rw,basin=rw,stream=rw",
            ])
            .unwrap()
        );
        assert_eq!(
            scope(&["--preset", "read-only", "--basins-exact", "my-basin"]).unwrap(),
            scope(&[
                "--basins-exact",
                "my-basin",
                "--streams-prefix",
                "",
                "--access-tokens-prefix",
                "",
                "--op-group-perms",
                "account=r,basin=r,stream=r",
            ])
            .unwrap()
        );
        assert!(matches!(scope(&[]), Err(CliError::InvalidArgs(_))));
    }

    #[test]
    fn list_streams_prefix_rejects_uri_and_flag_prefix() {
        let prefix = |s: &str| Some(s.parse::<StreamNamePrefix>().unwrap());
        assert!(matches!(
            list_streams_prefix(prefix("a"), prefix("b")),
            Err(CliError::InvalidArgs(_))
        ));
        assert_eq!(list_streams_prefix(prefix("a"), None).unwrap(), prefix("a"));
        assert_eq!(list_streams_prefix(None, prefix("b")).unwrap(), prefix("b"));
        assert_eq!(list_streams_prefix(None, None).unwrap(), None);
    }
}
