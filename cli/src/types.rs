use std::{str::FromStr, time::Duration};

use clap::{Args, Parser, ValueEnum};
use s2_sdk::{
    self as sdk,
    types::{
        AccessTokenId, AccessTokenIdPrefix, BasinName, BasinNamePrefix, StreamName,
        StreamNamePrefix, TimeseriesInterval,
    },
};
use serde::Serialize;

use crate::error::{OpGroupsParseError, S2UriParseError};

#[derive(Debug, Clone, PartialEq)]
struct S2Uri {
    basin: BasinName,
    stream: Option<String>,
}

impl FromStr for S2Uri {
    type Err = S2UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, s) = s
            .split_once("://")
            .ok_or(S2UriParseError::MissingUriScheme)?;
        if scheme != "s2" {
            return Err(S2UriParseError::InvalidUriScheme(scheme.to_owned()));
        }

        let (basin, stream) = match s.split_once("/") {
            Some((basin, stream)) => (basin, (!stream.is_empty()).then(|| stream.to_owned())),
            None => (s, None),
        };

        Ok(S2Uri {
            basin: basin
                .parse()
                .map_err(|e| S2UriParseError::InvalidBasinName(format!("{e}")))?,
            stream,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct S2BasinUri(pub BasinName);

impl From<S2BasinUri> for BasinName {
    fn from(value: S2BasinUri) -> Self {
        value.0
    }
}

impl FromStr for S2BasinUri {
    type Err = S2UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match S2Uri::from_str(s) {
            Ok(S2Uri {
                basin,
                stream: None,
            }) => Ok(Self(basin)),
            Ok(S2Uri {
                basin: _,
                stream: Some(_),
            }) => Err(S2UriParseError::UnexpectedStreamName),
            Err(S2UriParseError::MissingUriScheme) => {
                Ok(Self(s.parse().map_err(|e| {
                    S2UriParseError::InvalidBasinName(format!("{e}"))
                })?))
            }
            Err(other) => Err(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct S2BasinAndMaybeStreamUri {
    pub basin: BasinName,
    pub stream: Option<StreamNamePrefix>,
}

impl FromStr for S2BasinAndMaybeStreamUri {
    type Err = S2UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match S2Uri::from_str(s) {
            Ok(S2Uri { basin, stream }) => {
                let stream = stream
                    .map(|s| {
                        s.parse()
                            .map_err(|e| S2UriParseError::InvalidStreamName(format!("{e}")))
                    })
                    .transpose()?;
                Ok(Self { basin, stream })
            }
            Err(S2UriParseError::MissingUriScheme) => Ok(Self {
                basin: s
                    .parse()
                    .map_err(|e| S2UriParseError::InvalidBasinName(format!("{e}")))?,
                stream: None,
            }),
            Err(other) => Err(other),
        }
    }
}

/// String Format: s2://{basin}/{stream}
#[derive(Debug, Clone, PartialEq)]
pub struct S2BasinAndStreamUri {
    pub basin: BasinName,
    pub stream: StreamName,
}

impl FromStr for S2BasinAndStreamUri {
    type Err = S2UriParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let S2Uri { basin, stream } = s.parse()?;
        let stream = stream.ok_or(S2UriParseError::MissingStreamName)?;
        let stream: StreamName = stream
            .parse()
            .map_err(|e| S2UriParseError::InvalidStreamName(format!("{e}")))?;
        Ok(Self { basin, stream })
    }
}

#[derive(Parser, Debug, Clone, Serialize)]
pub struct BasinConfig {
    #[clap(flatten)]
    pub default_stream_config: StreamConfig,
    /// Create stream on append with basin defaults if it doesn't exist.
    #[arg(long, default_value_t = false)]
    pub create_stream_on_append: bool,
    /// Create stream on read with basin defaults if it doesn't exist.
    #[arg(long, default_value_t = false)]
    pub create_stream_on_read: bool,
}

#[derive(Parser, Debug, Clone, Serialize, Default)]
pub struct StreamConfig {
    #[arg(long)]
    /// Storage class for a stream.
    pub storage_class: Option<StorageClass>,
    #[arg(long, help("Example: 1d, 1w, 1y"))]
    /// Retention policy for a stream.
    pub retention_policy: Option<RetentionPolicy>,
    #[clap(flatten)]
    /// Timestamping configuration.
    pub timestamping: Option<TimestampingConfig>,
    #[clap(flatten)]
    /// Delete-on-empty configuration.
    pub delete_on_empty: Option<DeleteOnEmptyConfig>,
}

impl StreamConfig {
    pub fn is_empty(&self) -> bool {
        let Self {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = self;
        storage_class.is_none()
            && retention_policy.is_none()
            && timestamping.is_none()
            && delete_on_empty.is_none()
    }
}

#[derive(ValueEnum, Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageClass {
    Standard,
    Express,
}

#[derive(ValueEnum, Debug, Clone, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampingMode {
    ClientPrefer,
    ClientRequire,
    Arrival,
}

#[derive(Parser, Debug, Clone, Serialize)]
pub struct TimestampingConfig {
    #[arg(long)]
    /// Timestamping mode.
    pub timestamping_mode: Option<TimestampingMode>,

    #[arg(long)]
    /// Uncapped timestamps.
    pub timestamping_uncapped: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub enum RetentionPolicy {
    #[allow(dead_code)]
    Age(Duration),
    Infinite,
}

impl TryFrom<&str> for RetentionPolicy {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value == "infinite" {
            return Ok(RetentionPolicy::Infinite);
        } else if let Ok(d) = humantime::parse_duration(value) {
            return Ok(RetentionPolicy::Age(d));
        }
        Err("invalid retention policy: expected a duration, or 'infinite'")
    }
}

impl FromStr for RetentionPolicy {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RetentionPolicy::try_from(s)
    }
}

#[derive(Args, Clone, Debug, Serialize)]
pub struct DeleteOnEmptyConfig {
    #[arg(long, value_parser = humantime::parse_duration, required = false)]
    /// Minimum age before an empty stream can be deleted.
    /// Example: 1d, 1w, 1y
    pub delete_on_empty_min_age: Duration,
}

impl From<DeleteOnEmptyConfig> for sdk::types::DeleteOnEmptyConfig {
    fn from(value: DeleteOnEmptyConfig) -> Self {
        sdk::types::DeleteOnEmptyConfig::new().with_min_age(value.delete_on_empty_min_age)
    }
}

impl From<DeleteOnEmptyConfig> for sdk::types::DeleteOnEmptyReconfiguration {
    fn from(value: DeleteOnEmptyConfig) -> Self {
        sdk::types::DeleteOnEmptyReconfiguration::new().with_min_age(value.delete_on_empty_min_age)
    }
}

impl From<sdk::types::DeleteOnEmptyConfig> for DeleteOnEmptyConfig {
    fn from(value: sdk::types::DeleteOnEmptyConfig) -> Self {
        Self {
            delete_on_empty_min_age: Duration::from_secs(value.min_age_secs),
        }
    }
}

impl From<BasinConfig> for sdk::types::BasinConfig {
    fn from(config: BasinConfig) -> Self {
        sdk::types::BasinConfig::new()
            .with_default_stream_config(config.default_stream_config.into())
            .with_create_stream_on_append(config.create_stream_on_append)
            .with_create_stream_on_read(config.create_stream_on_read)
    }
}

impl From<StreamConfig> for sdk::types::StreamConfig {
    fn from(config: StreamConfig) -> Self {
        let mut stream_config = sdk::types::StreamConfig::new();
        if let Some(storage_class) = config.storage_class {
            stream_config = stream_config.with_storage_class(storage_class.into());
        }
        if let Some(retention_policy) = config.retention_policy {
            stream_config = stream_config.with_retention_policy(retention_policy.into());
        }
        if let Some(timestamping) = config.timestamping {
            stream_config = stream_config.with_timestamping(timestamping.into());
        }
        if let Some(delete_on_empty) = config.delete_on_empty {
            stream_config = stream_config.with_delete_on_empty(delete_on_empty.into());
        }
        stream_config
    }
}

impl From<StorageClass> for sdk::types::StorageClass {
    fn from(class: StorageClass) -> Self {
        match class {
            StorageClass::Standard => sdk::types::StorageClass::Standard,
            StorageClass::Express => sdk::types::StorageClass::Express,
        }
    }
}

impl From<sdk::types::StorageClass> for StorageClass {
    fn from(class: sdk::types::StorageClass) -> Self {
        match class {
            sdk::types::StorageClass::Standard => StorageClass::Standard,
            sdk::types::StorageClass::Express => StorageClass::Express,
        }
    }
}

impl From<TimestampingMode> for sdk::types::TimestampingMode {
    fn from(mode: TimestampingMode) -> Self {
        match mode {
            TimestampingMode::ClientPrefer => sdk::types::TimestampingMode::ClientPrefer,
            TimestampingMode::ClientRequire => sdk::types::TimestampingMode::ClientRequire,
            TimestampingMode::Arrival => sdk::types::TimestampingMode::Arrival,
        }
    }
}

impl From<sdk::types::TimestampingMode> for TimestampingMode {
    fn from(mode: sdk::types::TimestampingMode) -> Self {
        match mode {
            sdk::types::TimestampingMode::ClientPrefer => TimestampingMode::ClientPrefer,
            sdk::types::TimestampingMode::ClientRequire => TimestampingMode::ClientRequire,
            sdk::types::TimestampingMode::Arrival => TimestampingMode::Arrival,
        }
    }
}

impl From<TimestampingConfig> for sdk::types::TimestampingConfig {
    fn from(config: TimestampingConfig) -> Self {
        let mut result = sdk::types::TimestampingConfig::new();
        if let Some(mode) = config.timestamping_mode {
            result = result.with_mode(mode.into());
        }
        if let Some(uncapped) = config.timestamping_uncapped {
            result = result.with_uncapped(uncapped);
        }
        result
    }
}

impl From<sdk::types::TimestampingConfig> for TimestampingConfig {
    fn from(config: sdk::types::TimestampingConfig) -> Self {
        TimestampingConfig {
            timestamping_mode: config.mode.map(Into::into),
            timestamping_uncapped: Some(config.uncapped),
        }
    }
}

impl From<RetentionPolicy> for sdk::types::RetentionPolicy {
    fn from(policy: RetentionPolicy) -> Self {
        match policy {
            RetentionPolicy::Age(d) => sdk::types::RetentionPolicy::Age(d.as_secs()),
            RetentionPolicy::Infinite => sdk::types::RetentionPolicy::Infinite,
        }
    }
}

impl From<sdk::types::RetentionPolicy> for RetentionPolicy {
    fn from(policy: sdk::types::RetentionPolicy) -> Self {
        match policy {
            sdk::types::RetentionPolicy::Age(secs) => {
                RetentionPolicy::Age(Duration::from_secs(secs))
            }
            sdk::types::RetentionPolicy::Infinite => RetentionPolicy::Infinite,
        }
    }
}

impl From<sdk::types::BasinConfig> for BasinConfig {
    fn from(config: sdk::types::BasinConfig) -> Self {
        BasinConfig {
            default_stream_config: config
                .default_stream_config
                .map(Into::into)
                .unwrap_or_default(),
            create_stream_on_append: config.create_stream_on_append,
            create_stream_on_read: config.create_stream_on_read,
        }
    }
}

impl From<sdk::types::StreamConfig> for StreamConfig {
    fn from(config: sdk::types::StreamConfig) -> Self {
        StreamConfig {
            storage_class: config.storage_class.map(Into::into),
            retention_policy: config.retention_policy.map(Into::into),
            timestamping: config.timestamping.map(Into::into),
            delete_on_empty: config.delete_on_empty.map(Into::into),
        }
    }
}

impl From<StreamConfig> for sdk::types::StreamReconfiguration {
    fn from(config: StreamConfig) -> Self {
        let mut reconfig = sdk::types::StreamReconfiguration::new();
        if let Some(storage_class) = config.storage_class {
            reconfig = reconfig.with_storage_class(storage_class.into());
        }
        if let Some(retention_policy) = config.retention_policy {
            reconfig = reconfig.with_retention_policy(retention_policy.into());
        }
        if let Some(timestamping) = config.timestamping {
            let ts_reconfig = sdk::types::TimestampingReconfiguration::from(timestamping);
            reconfig = reconfig.with_timestamping(ts_reconfig);
        }
        if let Some(delete_on_empty) = config.delete_on_empty {
            reconfig = reconfig.with_delete_on_empty(delete_on_empty.into());
        }
        reconfig
    }
}

impl From<TimestampingConfig> for sdk::types::TimestampingReconfiguration {
    fn from(config: TimestampingConfig) -> Self {
        let mut result = sdk::types::TimestampingReconfiguration::new();
        if let Some(mode) = config.timestamping_mode {
            result = result.with_mode(mode.into());
        }
        if let Some(uncapped) = config.timestamping_uncapped {
            result = result.with_uncapped(uncapped);
        }
        result
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BasinMatcher {
    #[serde(serialize_with = "serialize_display")]
    Exact(BasinName),
    #[serde(serialize_with = "serialize_display")]
    Prefix(BasinNamePrefix),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMatcher {
    #[serde(serialize_with = "serialize_display")]
    Exact(StreamName),
    #[serde(serialize_with = "serialize_display")]
    Prefix(StreamNamePrefix),
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTokenMatcher {
    #[serde(serialize_with = "serialize_display")]
    Exact(AccessTokenId),
    #[serde(serialize_with = "serialize_display")]
    Prefix(AccessTokenIdPrefix),
}

fn serialize_display<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: std::fmt::Display,
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

impl FromStr for BasinMatcher {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(value) = s.strip_prefix('=') {
            Ok(Self::Exact(value.parse().map_err(|e| format!("{e}"))?))
        } else {
            Ok(Self::Prefix(s.parse().map_err(|e| format!("{e}"))?))
        }
    }
}

impl FromStr for StreamMatcher {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(value) = s.strip_prefix('=') {
            Ok(Self::Exact(value.parse().map_err(|e| format!("{e}"))?))
        } else {
            Ok(Self::Prefix(s.parse().map_err(|e| format!("{e}"))?))
        }
    }
}

impl FromStr for AccessTokenMatcher {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(value) = s.strip_prefix('=') {
            Ok(Self::Exact(value.parse().map_err(|e| format!("{e}"))?))
        } else {
            Ok(Self::Prefix(s.parse().map_err(|e| format!("{e}"))?))
        }
    }
}

impl From<BasinMatcher> for sdk::types::BasinMatcher {
    fn from(matcher: BasinMatcher) -> Self {
        match matcher {
            BasinMatcher::Exact(v) => sdk::types::BasinMatcher::Exact(v),
            BasinMatcher::Prefix(v) => sdk::types::BasinMatcher::Prefix(v),
        }
    }
}

impl From<StreamMatcher> for sdk::types::StreamMatcher {
    fn from(matcher: StreamMatcher) -> Self {
        match matcher {
            StreamMatcher::Exact(v) => sdk::types::StreamMatcher::Exact(v),
            StreamMatcher::Prefix(v) => sdk::types::StreamMatcher::Prefix(v),
        }
    }
}

impl From<AccessTokenMatcher> for sdk::types::AccessTokenMatcher {
    fn from(matcher: AccessTokenMatcher) -> Self {
        match matcher {
            AccessTokenMatcher::Exact(v) => sdk::types::AccessTokenMatcher::Exact(v),
            AccessTokenMatcher::Prefix(v) => sdk::types::AccessTokenMatcher::Prefix(v),
        }
    }
}

impl From<sdk::types::BasinMatcher> for BasinMatcher {
    fn from(matcher: sdk::types::BasinMatcher) -> Self {
        match matcher {
            sdk::types::BasinMatcher::Exact(v) => BasinMatcher::Exact(v),
            sdk::types::BasinMatcher::Prefix(v) => BasinMatcher::Prefix(v),
            sdk::types::BasinMatcher::None => BasinMatcher::Prefix(Default::default()),
        }
    }
}

impl From<sdk::types::StreamMatcher> for StreamMatcher {
    fn from(matcher: sdk::types::StreamMatcher) -> Self {
        match matcher {
            sdk::types::StreamMatcher::Exact(v) => StreamMatcher::Exact(v),
            sdk::types::StreamMatcher::Prefix(v) => StreamMatcher::Prefix(v),
            sdk::types::StreamMatcher::None => StreamMatcher::Prefix(Default::default()),
        }
    }
}

impl From<sdk::types::AccessTokenMatcher> for AccessTokenMatcher {
    fn from(matcher: sdk::types::AccessTokenMatcher) -> Self {
        match matcher {
            sdk::types::AccessTokenMatcher::Exact(v) => AccessTokenMatcher::Exact(v),
            sdk::types::AccessTokenMatcher::Prefix(v) => AccessTokenMatcher::Prefix(v),
            sdk::types::AccessTokenMatcher::None => AccessTokenMatcher::Prefix(Default::default()),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PermittedOperationGroups {
    pub account: Option<ReadWritePermissions>,
    pub basin: Option<ReadWritePermissions>,
    pub stream: Option<ReadWritePermissions>,
}

impl From<PermittedOperationGroups> for sdk::types::OperationGroupPermissions {
    fn from(groups: PermittedOperationGroups) -> Self {
        let mut result = sdk::types::OperationGroupPermissions::new();
        if let Some(account) = groups.account {
            result = result.with_account(account.into());
        }
        if let Some(basin) = groups.basin {
            result = result.with_basin(basin.into());
        }
        if let Some(stream) = groups.stream {
            result = result.with_stream(stream.into());
        }
        result
    }
}

impl From<sdk::types::OperationGroupPermissions> for PermittedOperationGroups {
    fn from(groups: sdk::types::OperationGroupPermissions) -> Self {
        PermittedOperationGroups {
            account: groups.account.map(Into::into),
            basin: groups.basin.map(Into::into),
            stream: groups.stream.map(Into::into),
        }
    }
}

impl FromStr for PermittedOperationGroups {
    type Err = OpGroupsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut account = None;
        let mut basin = None;
        let mut stream = None;

        if s.is_empty() {
            return Ok(PermittedOperationGroups {
                account,
                basin,
                stream,
            });
        }

        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let (key, value) =
                part.split_once('=')
                    .ok_or_else(|| OpGroupsParseError::InvalidFormat {
                        value: part.to_owned(),
                    })?;
            let perms = value.parse::<ReadWritePermissions>()?;
            match key {
                "account" => account = Some(perms),
                "basin" => basin = Some(perms),
                "stream" => stream = Some(perms),
                _ => {
                    return Err(OpGroupsParseError::InvalidKey {
                        key: key.to_owned(),
                    });
                }
            }
        }

        Ok(PermittedOperationGroups {
            account,
            basin,
            stream,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReadWritePermissions {
    pub read: bool,
    pub write: bool,
}

impl FromStr for ReadWritePermissions {
    type Err = OpGroupsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut read = false;
        let mut write = false;
        for c in s.chars() {
            match c {
                'r' => read = true,
                'w' => write = true,
                _ => return Err(OpGroupsParseError::InvalidPermissionChar(c)),
            }
        }
        if !read && !write {
            return Err(OpGroupsParseError::MissingPermission);
        }
        Ok(ReadWritePermissions { read, write })
    }
}

impl From<ReadWritePermissions> for sdk::types::ReadWritePermissions {
    fn from(permissions: ReadWritePermissions) -> Self {
        match (permissions.read, permissions.write) {
            (true, true) => sdk::types::ReadWritePermissions::read_write(),
            (true, false) => sdk::types::ReadWritePermissions::read_only(),
            (false, true) => sdk::types::ReadWritePermissions::write_only(),
            (false, false) => sdk::types::ReadWritePermissions::new(),
        }
    }
}

impl From<sdk::types::ReadWritePermissions> for ReadWritePermissions {
    fn from(permissions: sdk::types::ReadWritePermissions) -> Self {
        ReadWritePermissions {
            read: permissions.read,
            write: permissions.write,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AccessTokenInfo {
    pub id: String,
    pub expires_at: String,
    pub auto_prefix_streams: bool,
    pub scope: AccessTokenScope,
}

impl From<sdk::types::AccessTokenInfo> for AccessTokenInfo {
    fn from(info: sdk::types::AccessTokenInfo) -> Self {
        AccessTokenInfo {
            id: info.id.to_string(),
            expires_at: info.expires_at.to_string(),
            auto_prefix_streams: info.auto_prefix_streams,
            scope: info.scope.into(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AccessTokenScope {
    pub basins: Option<BasinMatcher>,
    pub streams: Option<StreamMatcher>,
    pub access_tokens: Option<AccessTokenMatcher>,
    pub op_group_perms: Option<PermittedOperationGroups>,
    pub ops: Vec<Operation>,
}

impl From<sdk::types::AccessTokenScope> for AccessTokenScope {
    fn from(scope: sdk::types::AccessTokenScope) -> Self {
        AccessTokenScope {
            basins: scope.basins.map(Into::into),
            streams: scope.streams.map(Into::into),
            access_tokens: scope.access_tokens.map(Into::into),
            op_group_perms: scope.op_group_perms.map(Into::into),
            ops: scope.ops.into_iter().map(Operation::from).collect(),
        }
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, clap::ValueEnum, strum::Display, strum::EnumString,
)]
#[serde(rename_all = "snake_case")]
#[clap(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum Operation {
    ListBasins,
    CreateBasin,
    DeleteBasin,
    GetBasinConfig,
    ReconfigureBasin,
    ListAccessTokens,
    IssueAccessToken,
    RevokeAccessToken,
    GetAccountMetrics,
    GetBasinMetrics,
    GetStreamMetrics,
    ListStreams,
    CreateStream,
    DeleteStream,
    GetStreamConfig,
    ReconfigureStream,
    CheckTail,
    Trim,
    Fence,
    Append,
    Read,
}

impl From<Operation> for sdk::types::Operation {
    fn from(op: Operation) -> Self {
        match op {
            Operation::ListBasins => sdk::types::Operation::ListBasins,
            Operation::CreateBasin => sdk::types::Operation::CreateBasin,
            Operation::DeleteBasin => sdk::types::Operation::DeleteBasin,
            Operation::GetBasinConfig => sdk::types::Operation::GetBasinConfig,
            Operation::ReconfigureBasin => sdk::types::Operation::ReconfigureBasin,
            Operation::ListAccessTokens => sdk::types::Operation::ListAccessTokens,
            Operation::IssueAccessToken => sdk::types::Operation::IssueAccessToken,
            Operation::RevokeAccessToken => sdk::types::Operation::RevokeAccessToken,
            Operation::GetAccountMetrics => sdk::types::Operation::GetAccountMetrics,
            Operation::GetBasinMetrics => sdk::types::Operation::GetBasinMetrics,
            Operation::GetStreamMetrics => sdk::types::Operation::GetStreamMetrics,
            Operation::ListStreams => sdk::types::Operation::ListStreams,
            Operation::CreateStream => sdk::types::Operation::CreateStream,
            Operation::DeleteStream => sdk::types::Operation::DeleteStream,
            Operation::GetStreamConfig => sdk::types::Operation::GetStreamConfig,
            Operation::ReconfigureStream => sdk::types::Operation::ReconfigureStream,
            Operation::CheckTail => sdk::types::Operation::CheckTail,
            Operation::Trim => sdk::types::Operation::Trim,
            Operation::Fence => sdk::types::Operation::Fence,
            Operation::Append => sdk::types::Operation::Append,
            Operation::Read => sdk::types::Operation::Read,
        }
    }
}

impl From<sdk::types::Operation> for Operation {
    fn from(op: sdk::types::Operation) -> Self {
        match op {
            sdk::types::Operation::ListBasins => Operation::ListBasins,
            sdk::types::Operation::CreateBasin => Operation::CreateBasin,
            sdk::types::Operation::DeleteBasin => Operation::DeleteBasin,
            sdk::types::Operation::GetBasinConfig => Operation::GetBasinConfig,
            sdk::types::Operation::ReconfigureBasin => Operation::ReconfigureBasin,
            sdk::types::Operation::ListAccessTokens => Operation::ListAccessTokens,
            sdk::types::Operation::IssueAccessToken => Operation::IssueAccessToken,
            sdk::types::Operation::RevokeAccessToken => Operation::RevokeAccessToken,
            sdk::types::Operation::GetAccountMetrics => Operation::GetAccountMetrics,
            sdk::types::Operation::GetBasinMetrics => Operation::GetBasinMetrics,
            sdk::types::Operation::GetStreamMetrics => Operation::GetStreamMetrics,
            sdk::types::Operation::ListStreams => Operation::ListStreams,
            sdk::types::Operation::CreateStream => Operation::CreateStream,
            sdk::types::Operation::DeleteStream => Operation::DeleteStream,
            sdk::types::Operation::GetStreamConfig => Operation::GetStreamConfig,
            sdk::types::Operation::ReconfigureStream => Operation::ReconfigureStream,
            sdk::types::Operation::CheckTail => Operation::CheckTail,
            sdk::types::Operation::Trim => Operation::Trim,
            sdk::types::Operation::Fence => Operation::Fence,
            sdk::types::Operation::Append => Operation::Append,
            sdk::types::Operation::Read => Operation::Read,
        }
    }
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub enum Interval {
    /// Per-minute intervals.
    Minute,
    /// Per-hour intervals.
    Hour,
    /// Per-day intervals.
    Day,
}

impl From<Interval> for TimeseriesInterval {
    fn from(value: Interval) -> Self {
        match value {
            Interval::Minute => TimeseriesInterval::Minute,
            Interval::Hour => TimeseriesInterval::Hour,
            Interval::Day => TimeseriesInterval::Day,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LatencyStats {
    pub min: std::time::Duration,
    pub median: std::time::Duration,
    pub p90: std::time::Duration,
    pub p99: std::time::Duration,
    pub max: std::time::Duration,
}

impl LatencyStats {
    pub fn compute(mut data: Vec<std::time::Duration>) -> Self {
        data.sort_unstable();

        let n = data.len();

        if n == 0 {
            return Self {
                min: std::time::Duration::ZERO,
                median: std::time::Duration::ZERO,
                p90: std::time::Duration::ZERO,
                p99: std::time::Duration::ZERO,
                max: std::time::Duration::ZERO,
            };
        }

        let median = if n.is_multiple_of(2) {
            (data[n / 2 - 1] + data[n / 2]) / 2
        } else {
            data[n / 2]
        };

        let p_idx = |p: f64| ((n as f64) * p).ceil() as usize - 1;

        Self {
            min: data[0],
            median,
            p90: data[p_idx(0.90)],
            p99: data[p_idx(0.99)],
            max: data[n - 1],
        }
    }

    pub fn into_vec(self) -> Vec<(String, std::time::Duration)> {
        vec![
            ("min".to_owned(), self.min),
            ("median".to_owned(), self.median),
            ("p90".to_owned(), self.p90),
            ("p99".to_owned(), self.p99),
            ("max".to_owned(), self.max),
        ]
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{
        OpGroupsParseError, PermittedOperationGroups, ReadWritePermissions,
        S2BasinAndMaybeStreamUri, S2BasinAndStreamUri, S2BasinUri, S2Uri,
    };
    use crate::error::S2UriParseError;

    #[rstest]
    #[case("", Ok(PermittedOperationGroups {
        account: None,
        basin: None,
        stream: None,
    }))]
    #[case("account=r", Ok(PermittedOperationGroups {
        account: Some(ReadWritePermissions {
            read: true,
            write: false,
        }),
        basin: None,
        stream: None,
    }))]
    #[case("account=w", Ok(PermittedOperationGroups {
        account: Some(ReadWritePermissions {
            read: false,
            write: true,
        }),
        basin: None,
        stream: None,
    }))]
    #[case("account=rw", Ok(PermittedOperationGroups {
        account: Some(ReadWritePermissions {
            read: true,
            write: true,
        }),
        basin: None,
        stream: None,
    }))]
    #[case("basin=r,stream=w", Ok(PermittedOperationGroups {
        account: None,
        basin: Some(ReadWritePermissions {
            read: true,
            write: false,
        }),
        stream: Some(ReadWritePermissions {
            read: false,
            write: true,
        }),
    }))]
    #[case("account=rw,basin=rw,stream=rw", Ok(PermittedOperationGroups {
        account: Some(ReadWritePermissions {
            read: true,
            write: true,
        }),
        basin: Some(ReadWritePermissions {
            read: true,
            write: true,
        }),
        stream: Some(ReadWritePermissions {
            read: true,
            write: true,
        }),
    }))]
    #[case("invalid", Err(OpGroupsParseError::InvalidFormat { value: "invalid".to_owned() }))]
    #[case("unknown=rw", Err(OpGroupsParseError::InvalidKey { key: "unknown".to_owned() }))]
    #[case("account=", Err(OpGroupsParseError::MissingPermission))]
    #[case("account=x", Err(OpGroupsParseError::InvalidPermissionChar('x')))]
    fn test_parse_op_groups(
        #[case] input: &str,
        #[case] expected: Result<PermittedOperationGroups, OpGroupsParseError>,
    ) {
        assert_eq!(
            input.parse::<PermittedOperationGroups>(),
            expected,
            "Testing input: {input}"
        );
    }

    #[test]
    fn test_s2_uri_parse() {
        let test_cases = vec![
            (
                "valid-basin",
                Err(S2UriParseError::MissingUriScheme),
                Ok(S2BasinUri("valid-basin".parse().unwrap())),
                Err(S2UriParseError::MissingUriScheme),
                Ok(S2BasinAndMaybeStreamUri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: None,
                }),
            ),
            (
                "s2://valid-basin",
                Ok(S2Uri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: None,
                }),
                Ok(S2BasinUri("valid-basin".parse().unwrap())),
                Err(S2UriParseError::MissingStreamName),
                Ok(S2BasinAndMaybeStreamUri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: None,
                }),
            ),
            (
                "s2://valid-basin/",
                Ok(S2Uri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: None,
                }),
                Ok(S2BasinUri("valid-basin".parse().unwrap())),
                Err(S2UriParseError::MissingStreamName),
                Ok(S2BasinAndMaybeStreamUri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: None,
                }),
            ),
            (
                "s2://valid-basin/stream/name",
                Ok(S2Uri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: Some("stream/name".to_owned()),
                }),
                Err(S2UriParseError::UnexpectedStreamName),
                Ok(S2BasinAndStreamUri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: "stream/name".parse().unwrap(),
                }),
                Ok(S2BasinAndMaybeStreamUri {
                    basin: "valid-basin".parse().unwrap(),
                    stream: Some("stream/name".parse().unwrap()),
                }),
            ),
            (
                "-invalid-basin",
                Err(S2UriParseError::MissingUriScheme),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::MissingUriScheme),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
            ),
            (
                "http://valid-basin",
                Err(S2UriParseError::InvalidUriScheme("http".to_owned())),
                Err(S2UriParseError::InvalidUriScheme("http".to_owned())),
                Err(S2UriParseError::InvalidUriScheme("http".to_owned())),
                Err(S2UriParseError::InvalidUriScheme("http".to_owned())),
            ),
            (
                "s2://-invalid-basin",
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
            ),
            (
                "s2:///stream/name",
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
            ),
            (
                "random:::string",
                Err(S2UriParseError::MissingUriScheme),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
                Err(S2UriParseError::MissingUriScheme),
                Err(S2UriParseError::InvalidBasinName("".to_owned())),
            ),
        ];

        for (
            s,
            expected_uri,
            expected_basin_uri,
            expected_basin_and_stream_uri,
            expected_basin_and_maybe_stream_uri,
        ) in test_cases
        {
            assert_eq!(s.parse(), expected_uri, "S2Uri: {s}");
            assert_eq!(s.parse(), expected_basin_uri, "S2BasinUri: {s}");
            assert_eq!(
                s.parse(),
                expected_basin_and_stream_uri,
                "S2BasinAndStreamUri: {s}"
            );
            assert_eq!(
                s.parse(),
                expected_basin_and_maybe_stream_uri,
                "S2BasinAndMaybeStreamUri: {s}"
            );
        }
    }
}
