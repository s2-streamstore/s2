//! Diffing over typed presentation views of Basins, Streams, and Access Tokens.
//!
//! - Configs are fetched as API DTOs and converted into `s2_common` domain types via the existing
//!   `TryFrom` conversions, which also resolve omitted fields to their effective defaults (e.g. an
//!   unset `storage_class` becomes `express`).
//!
//! - Domain values are rendered into `*View` structs and serialized to JSON, which is diffed
//!   field-by-field. Views own all presentation: compact exact durations (`"7d"`, `"1h"`),
//!   wire-format enum names, canonically ordered operation sets.

use colored::Colorize;
use s2_api::v1::access::AccessTokenInfo as ApiAccessTokenInfo;
use s2_common::access::{PermittedOperationGroups, ReadWritePermissions, ResourceSet};
use s2_sdk::types::AccessTokenId;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    cli::{DiffArgs, DiffOutput, DiffResourceKind},
    error::CliError,
    ops,
    types::{DiffResource, S2BasinAndStreamUri, S2BasinUri},
};

#[derive(Debug, Serialize)]
struct FieldDiff {
    path: String,
    left: Option<Value>,
    right: Option<Value>,
}

struct ResolvedDiff {
    comparison: DiffComparison,
    left: DiffResource,
    right: DiffResource,
    left_label: String,
    right_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffComparison {
    Basin,
    Stream,
    AccessToken,
    StreamVsBasinDefaults,
}

impl DiffComparison {
    fn as_str(self) -> &'static str {
        match self {
            Self::Basin => "basin",
            Self::Stream => "stream",
            Self::AccessToken => "access-token",
            Self::StreamVsBasinDefaults => "stream-vs-basin-defaults",
        }
    }
}

#[derive(Debug)]
pub struct DiffOutcome {
    pub has_differences: bool,
}

#[derive(Serialize)]
struct JsonDiff<'a> {
    resource: &'static str,
    left: &'a str,
    right: &'a str,
    differences: &'a [FieldDiff],
}

pub fn validate_args(args: &DiffArgs) -> Result<(), CliError> {
    resolve_args(args).map(|_| ())
}

pub async fn run(s2: &s2_sdk::S2, args: DiffArgs) -> Result<DiffOutcome, CliError> {
    let ResolvedDiff {
        comparison,
        left,
        right,
        left_label,
        right_label,
    } = resolve_args(&args)?;

    let (left_view, right_view) = match (left, right) {
        (DiffResource::Basin(left), DiffResource::Basin(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_basin_config_api(s2, &left),
                ops::get_basin_config_api(s2, &right),
            )?;
            (basin_view(left_config)?, basin_view(right_config)?)
        }
        (DiffResource::Stream(left), DiffResource::Stream(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_stream_config_api(s2, left),
                ops::get_stream_config_api(s2, right),
            )?;
            (stream_view(left_config)?, stream_view(right_config)?)
        }
        (DiffResource::Basin(basin), DiffResource::Stream(stream)) => {
            let (basin_config, stream_config) = tokio::try_join!(
                ops::get_basin_config_api(s2, &basin),
                ops::get_stream_config_api(s2, stream),
            )?;
            (
                basin_stream_defaults_view(basin_config)?,
                stream_view(stream_config)?,
            )
        }
        (DiffResource::Stream(stream), DiffResource::Basin(basin)) => {
            let (stream_config, basin_config) = tokio::try_join!(
                ops::get_stream_config_api(s2, stream),
                ops::get_basin_config_api(s2, &basin),
            )?;
            (
                stream_view(stream_config)?,
                basin_stream_defaults_view(basin_config)?,
            )
        }
        (DiffResource::AccessToken(left), DiffResource::AccessToken(right)) => {
            let (left_info, right_info) = tokio::try_join!(
                ops::get_access_token_api(s2, left),
                ops::get_access_token_api(s2, right),
            )?;
            (
                access_token_view(left_info)?,
                access_token_view(right_info)?,
            )
        }
        _ => unreachable!("diff arguments are resolved to matching resource types"),
    };

    let differences = field_diffs(&left_view, &right_view);
    let has_differences = !differences.is_empty();

    match args.output {
        DiffOutput::Text => print_text_diff(&left_label, &right_label, &differences),
        DiffOutput::Json => println!(
            "{}",
            serde_json::to_string_pretty(&JsonDiff {
                resource: comparison.as_str(),
                left: &args.left,
                right: &args.right,
                differences: &differences,
            })?
        ),
    }

    Ok(DiffOutcome { has_differences })
}

fn resolve_args(args: &DiffArgs) -> Result<ResolvedDiff, CliError> {
    let (comparison, left, right) = match args.resource {
        Some(kind) => {
            let comparison = comparison_for_kind(kind);
            (
                comparison,
                parse_explicit_resource(kind, &args.left)?,
                parse_explicit_resource(kind, &args.right)?,
            )
        }
        None => {
            let left = infer_resource(&args.left)?;
            let right = infer_resource(&args.right)?;
            let left_kind = resource_kind(&left);
            let right_kind = resource_kind(&right);
            let comparison = if left_kind == right_kind {
                comparison_for_kind(left_kind)
            } else if stream_belongs_to_basin(&left, &right) {
                DiffComparison::StreamVsBasinDefaults
            } else if matches!(
                (&left, &right),
                (DiffResource::Basin(_), DiffResource::Stream(_))
                    | (DiffResource::Stream(_), DiffResource::Basin(_))
            ) {
                return Err(different_basin_error(&left, &right));
            } else {
                return Err(CliError::InvalidArgs(miette::miette!(
                    help = "Both operands must identify the same kind of resource. A stream may also be compared with its own basin's defaults.",
                    "Cannot diff a {} against a {}",
                    left_kind.as_str(),
                    right_kind.as_str(),
                )));
            };
            (comparison, left, right)
        }
    };

    let mut left_label = args.left.clone();
    let mut right_label = args.right.clone();
    if comparison == DiffComparison::StreamVsBasinDefaults {
        if matches!(&left, DiffResource::Basin(_)) {
            left_label.push_str(" (stream defaults)");
        } else {
            right_label.push_str(" (stream defaults)");
        }
    }

    Ok(ResolvedDiff {
        comparison,
        left,
        right,
        left_label,
        right_label,
    })
}

fn comparison_for_kind(kind: DiffResourceKind) -> DiffComparison {
    match kind {
        DiffResourceKind::Basin => DiffComparison::Basin,
        DiffResourceKind::Stream => DiffComparison::Stream,
        DiffResourceKind::AccessToken => DiffComparison::AccessToken,
    }
}

fn stream_belongs_to_basin(left: &DiffResource, right: &DiffResource) -> bool {
    match (left, right) {
        (DiffResource::Basin(basin), DiffResource::Stream(stream))
        | (DiffResource::Stream(stream), DiffResource::Basin(basin)) => &stream.basin == basin,
        _ => false,
    }
}

fn different_basin_error(left: &DiffResource, right: &DiffResource) -> CliError {
    let (basin, stream) = match (left, right) {
        (DiffResource::Basin(basin), DiffResource::Stream(stream))
        | (DiffResource::Stream(stream), DiffResource::Basin(basin)) => (basin, stream),
        _ => unreachable!("called only for a basin and stream pair"),
    };

    CliError::InvalidArgs(miette::miette!(
        help = format!(
            "Use `s2://{}` to compare this stream with its basin defaults.",
            stream.basin
        ),
        "Stream `s2://{}/{}` does not belong to basin `s2://{basin}`",
        stream.basin,
        stream.stream,
    ))
}

fn infer_resource(value: &str) -> Result<DiffResource, CliError> {
    if !value.contains("://") {
        return Err(CliError::InvalidArgs(miette::miette!(
            help = "Specify `--resource basin` for basin names or `--resource access-token` for access token IDs.",
            "Cannot infer a resource type from bare name `{value}`"
        )));
    }

    value.parse().map_err(|error: String| {
        CliError::InvalidArgs(miette::miette!(
            help = "Use an S2 URI such as `s2://my-basin` or `s2://my-basin/my-stream`.",
            "Invalid S2 resource `{value}`: {error}"
        ))
    })
}

fn parse_explicit_resource(kind: DiffResourceKind, value: &str) -> Result<DiffResource, CliError> {
    let parsed = match kind {
        DiffResourceKind::Basin => value
            .parse::<S2BasinUri>()
            .map(|uri| DiffResource::Basin(uri.0))
            .map_err(|error| error.to_string()),
        DiffResourceKind::Stream => value
            .parse::<S2BasinAndStreamUri>()
            .map(DiffResource::Stream)
            .map_err(|error| error.to_string()),
        DiffResourceKind::AccessToken => value
            .parse::<AccessTokenId>()
            .map(DiffResource::AccessToken)
            .map_err(|error| error.to_string()),
    };

    parsed.map_err(|error| {
        CliError::InvalidArgs(miette::miette!(
            help = explicit_resource_help(kind),
            "Invalid {} `{value}`: {error}",
            kind.as_str(),
        ))
    })
}

fn explicit_resource_help(kind: DiffResourceKind) -> &'static str {
    match kind {
        DiffResourceKind::Basin => {
            "Use a basin name such as `my-basin` or an S2 URI such as `s2://my-basin`."
        }
        DiffResourceKind::Stream => "Use an S2 URI such as `s2://my-basin/my-stream`.",
        DiffResourceKind::AccessToken => "Use an access token ID such as `production-reader`.",
    }
}

fn resource_kind(resource: &DiffResource) -> DiffResourceKind {
    match resource {
        DiffResource::Basin(_) => DiffResourceKind::Basin,
        DiffResource::Stream(_) => DiffResourceKind::Stream,
        DiffResource::AccessToken(_) => DiffResourceKind::AccessToken,
    }
}

/// Presentation of an effective (fully resolved) stream configuration.
///
/// - Field names and nesting mirror the API wire format so that `--output json` paths line up with
///   API responses.
/// - Durations render compact (`"7d"`, `"1h30m"`); retention renders as `"infinite"` or an age
///   duration.
#[derive(Serialize)]
struct StreamConfigView {
    storage_class: String,
    retention_policy: String,
    timestamping: TimestampingConfigView,
    delete_on_empty: DeleteOnEmptyConfigView,
}

#[derive(Serialize)]
struct TimestampingConfigView {
    mode: String,
    uncapped: bool,
}

#[derive(Serialize)]
struct DeleteOnEmptyConfigView {
    min_age: String,
}

impl From<s2_common::config::StreamConfig> for StreamConfigView {
    fn from(config: s2_common::config::StreamConfig) -> Self {
        let s2_common::config::StreamConfig {
            storage_class,
            retention_policy,
            timestamping,
            delete_on_empty,
        } = config;
        let s2_common::config::TimestampingConfig { mode, uncapped } = timestamping;

        Self {
            storage_class: wire_name(s2_api::v1::config::StorageClass::from(storage_class)),
            retention_policy: match retention_policy {
                s2_common::config::RetentionPolicy::Age(age) => compact_duration(age),
                s2_common::config::RetentionPolicy::Infinite() => "infinite".to_owned(),
            },
            timestamping: TimestampingConfigView {
                mode: wire_name(s2_api::v1::config::TimestampingMode::from(mode)),
                uncapped,
            },
            delete_on_empty: DeleteOnEmptyConfigView {
                min_age: compact_duration(delete_on_empty.min_age),
            },
        }
    }
}

/// Presentation of an effective basin configuration, with stream defaults materialized.
#[derive(Serialize)]
struct BasinConfigView {
    default_stream_config: StreamConfigView,
    stream_cipher: String,
    create_stream_on_append: bool,
    create_stream_on_read: bool,
}

impl From<s2_common::config::BasinConfig> for BasinConfigView {
    fn from(config: s2_common::config::BasinConfig) -> Self {
        let s2_common::config::BasinConfig {
            default_stream_config,
            stream_cipher,
            create_stream_on_append,
            create_stream_on_read,
        } = config;

        Self {
            default_stream_config: s2_common::config::StreamConfig::from(default_stream_config)
                .into(),
            stream_cipher: match stream_cipher {
                None => "none".to_owned(),
                Some(cipher) => wire_name(s2_api::v1::config::EncryptionAlgorithm::from(cipher)),
            },
            create_stream_on_append,
            create_stream_on_read,
        }
    }
}

/// Presentation of an access token.
///
/// - The token ID is identity, not configuration, so it is deliberately excluded.
/// - Operations render as a sorted list of wire-format names; sets and permissions render as
///   compact strings (`"prefix: \"prod-\""`, `"rw"`).
#[derive(Serialize)]
struct AccessTokenInfoView {
    expires_at: String,
    auto_prefix_streams: bool,
    scope: AccessTokenScopeView,
}

#[derive(Serialize)]
struct AccessTokenScopeView {
    basins: String,
    streams: String,
    access_tokens: String,
    op_groups: OperationGroupsView,
    ops: Vec<String>,
}

#[derive(Serialize)]
struct OperationGroupsView {
    account: String,
    basin: String,
    stream: String,
}

impl From<s2_common::access::AccessTokenScope> for AccessTokenScopeView {
    fn from(scope: s2_common::access::AccessTokenScope) -> Self {
        let s2_common::access::AccessTokenScope {
            basins,
            streams,
            access_tokens,
            op_groups,
            ops,
        } = scope;
        let PermittedOperationGroups {
            account,
            basin,
            stream,
        } = op_groups;

        let mut ops = ops
            .iter()
            .map(|op| wire_name(s2_api::v1::access::Operation::from(op)))
            .collect::<Vec<_>>();
        ops.sort();

        Self {
            basins: resource_set_view(basins),
            streams: resource_set_view(streams),
            access_tokens: resource_set_view(access_tokens),
            op_groups: OperationGroupsView {
                account: permissions_view(account),
                basin: permissions_view(basin),
                stream: permissions_view(stream),
            },
            ops,
        }
    }
}

fn resource_set_view<E: std::fmt::Display, P: std::fmt::Display>(set: ResourceSet<E, P>) -> String {
    match set {
        ResourceSet::None => "none".to_owned(),
        ResourceSet::Exact(exact) => format!("exact: \"{exact}\""),
        ResourceSet::Prefix(prefix) => format!("prefix: \"{prefix}\""),
    }
}

fn permissions_view(permissions: ReadWritePermissions) -> String {
    let ReadWritePermissions { read, write } = permissions;
    match (read, write) {
        (true, true) => "rw",
        (true, false) => "r",
        (false, true) => "w",
        (false, false) => "none",
    }
    .to_owned()
}

fn basin_view(config: s2_api::v1::config::BasinConfig) -> Result<Value, CliError> {
    let config: s2_common::config::BasinConfig = config.try_into()?;
    Ok(serde_json::to_value(BasinConfigView::from(config))?)
}

/// Renders a basin's effective stream defaults for comparison against a concrete stream.
fn basin_stream_defaults_view(config: s2_api::v1::config::BasinConfig) -> Result<Value, CliError> {
    let config: s2_common::config::BasinConfig = config.try_into()?;
    let defaults = s2_common::config::StreamConfig::from(config.default_stream_config);
    Ok(serde_json::to_value(StreamConfigView::from(defaults))?)
}

fn stream_view(config: s2_api::v1::config::StreamConfig) -> Result<Value, CliError> {
    let config: s2_common::config::OptionalStreamConfig = config.try_into()?;
    let config = s2_common::config::StreamConfig::from(config);
    Ok(serde_json::to_value(StreamConfigView::from(config))?)
}

fn access_token_view(info: ApiAccessTokenInfo) -> Result<Value, CliError> {
    let ApiAccessTokenInfo {
        // Identity, not configuration.
        id: _,
        expires_at,
        auto_prefix_streams,
        scope,
    } = info;
    let scope: s2_common::access::AccessTokenScope = scope.try_into()?;

    Ok(serde_json::to_value(AccessTokenInfoView {
        expires_at: match expires_at {
            None => "never".to_owned(),
            Some(at) => humantime::format_rfc3339_seconds(at.into()).to_string(),
        },
        auto_prefix_streams,
        scope: scope.into(),
    })?)
}

/// Wire-format name of a unit enum variant, taken from its serde serialization so that
/// presentation never drifts from the API's actual field vocabulary.
fn wire_name(value: impl Serialize) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(name)) => name,
        _ => unreachable!("wire enums serialize to strings"),
    }
}

/// Compact, exact duration rendering.
///
/// - Uses only units with a fixed number of seconds (`d`/`h`/`m`/`s`), so the rendering is exact
///   and round-trips with CLI inputs: a `60d` retention policy renders as `60d`, not humantime's
///   approximate `1month 29d 13h 26m 24s`.
/// - Distinct durations always render as distinct strings, which the diff relies on.
fn compact_duration(duration: std::time::Duration) -> String {
    use std::fmt::Write;

    let mut seconds = duration.as_secs();
    if seconds == 0 {
        return "0s".to_owned();
    }

    let mut rendered = String::new();
    for (unit_seconds, unit) in [(86_400, "d"), (3_600, "h"), (60, "m"), (1, "s")] {
        let count = seconds / unit_seconds;
        seconds %= unit_seconds;
        if count > 0 {
            if !rendered.is_empty() {
                rendered.push(' ');
            }
            write!(rendered, "{count}{unit}").expect("string writes are infallible");
        }
    }
    rendered
}

fn print_text_diff(left_label: &str, right_label: &str, differences: &[FieldDiff]) {
    println!("{}", format!("--- {left_label}").red().bold());
    println!("{}", format!("+++ {right_label}").green().bold());

    if differences.is_empty() {
        println!();
        println!("{}", "✓ No differences".green().bold());
        return;
    }

    for difference in differences {
        println!();
        println!("{}", difference.path.bold());
        print_value("-", difference.left.as_ref(), true);
        print_value("+", difference.right.as_ref(), false);
    }
}

fn print_value(prefix: &str, value: Option<&Value>, removed: bool) {
    for line in format_value_lines(value) {
        if removed {
            println!("{} {}", prefix.red().bold(), line.red());
        } else {
            println!("{} {}", prefix.green().bold(), line.green());
        }
    }
}

fn format_value_lines(value: Option<&Value>) -> Vec<String> {
    match value {
        None => vec!["∅".to_owned()],
        Some(Value::String(value)) => vec![value.clone()],
        Some(value @ (Value::Array(_) | Value::Object(_))) => serde_json::to_string_pretty(value)
            .expect("JSON values always serialize")
            .lines()
            .map(str::to_owned)
            .collect(),
        Some(value) => vec![value.to_string()],
    }
}

fn field_diffs(left: &Value, right: &Value) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();
    collect_field_diffs(None, Some(left), Some(right), &mut diffs);
    diffs
}

fn collect_field_diffs(
    path: Option<&str>,
    left: Option<&Value>,
    right: Option<&Value>,
    diffs: &mut Vec<FieldDiff>,
) {
    match (left, right) {
        (Some(Value::Object(left)), Some(Value::Object(right))) => {
            collect_object_diffs(path, left, right, diffs);
        }
        (Some(left), Some(right)) if left == right => {}
        _ => diffs.push(FieldDiff {
            path: path.unwrap_or("value").to_owned(),
            left: left.cloned(),
            right: right.cloned(),
        }),
    }
}

fn collect_object_diffs(
    path: Option<&str>,
    left: &Map<String, Value>,
    right: &Map<String, Value>,
    diffs: &mut Vec<FieldDiff>,
) {
    for (field, left_value) in left {
        let field_path = join_path(path, field);
        collect_field_diffs(Some(&field_path), Some(left_value), right.get(field), diffs);
    }

    for (field, right_value) in right {
        if !left.contains_key(field) {
            let field_path = join_path(path, field);
            collect_field_diffs(Some(&field_path), None, Some(right_value), diffs);
        }
    }
}

fn join_path(parent: Option<&str>, field: &str) -> String {
    match parent {
        Some(parent) => format!("{parent}.{field}"),
        None => field.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        DiffComparison, access_token_view, basin_stream_defaults_view, basin_view, field_diffs,
        format_value_lines, resolve_args, resource_kind, stream_view,
    };
    use crate::cli::{DiffArgs, DiffOutput, DiffResourceKind};

    fn args(left: &str, right: &str, resource: Option<DiffResourceKind>) -> DiffArgs {
        DiffArgs {
            left: left.to_owned(),
            right: right.to_owned(),
            resource,
            output: DiffOutput::Text,
            exit_code: false,
        }
    }

    #[test]
    fn infers_streams_from_s2_uris() {
        let resolved = resolve_args(&args(
            "s2://left-basin/stream",
            "s2://right-basin/stream",
            None,
        ))
        .expect("resources resolve");

        assert_eq!(resource_kind(&resolved.left), DiffResourceKind::Stream);
        assert_eq!(resource_kind(&resolved.right), DiffResourceKind::Stream);
    }

    #[test]
    fn resolves_explicit_access_tokens() {
        let resolved = resolve_args(&args(
            "token-left",
            "token-right",
            Some(DiffResourceKind::AccessToken),
        ))
        .expect("resources resolve");

        assert_eq!(resolved.comparison, DiffComparison::AccessToken);
    }

    #[test]
    fn resolves_stream_against_its_basin_defaults() {
        let resolved = resolve_args(&args(
            "s2://shared-basin",
            "s2://shared-basin/my-stream",
            None,
        ))
        .expect("resources resolve");

        assert_eq!(resolved.comparison, DiffComparison::StreamVsBasinDefaults);
        assert_eq!(resolved.left_label, "s2://shared-basin (stream defaults)");
        assert_eq!(resolved.right_label, "s2://shared-basin/my-stream");
    }

    #[test]
    fn resolves_stream_against_basin_defaults_in_reverse() {
        let resolved = resolve_args(&args(
            "s2://shared-basin/my-stream",
            "s2://shared-basin",
            None,
        ))
        .expect("resources resolve");

        assert_eq!(resolved.comparison, DiffComparison::StreamVsBasinDefaults);
        assert_eq!(resolved.left_label, "s2://shared-basin/my-stream");
        assert_eq!(resolved.right_label, "s2://shared-basin (stream defaults)");
    }

    #[test]
    fn rejects_stream_against_defaults_from_another_basin() {
        let error = resolve_args(&args(
            "s2://first-basin",
            "s2://second-basin/my-stream",
            None,
        ))
        .err()
        .expect("different basins are rejected")
        .to_string();

        assert!(error.contains("does not belong to basin"));
    }

    #[test]
    fn rejects_bare_names_without_resource_type() {
        let error = resolve_args(&args("token-left", "token-right", None))
            .err()
            .expect("bare names are rejected")
            .to_string();

        assert!(error.contains("Cannot infer a resource type"));
    }

    #[test]
    fn stream_views_resolve_defaults_and_format_durations() {
        let config = serde_json::from_value(json!({
            "retention_policy": {"age": 172800},
            "delete_on_empty": {"min_age_secs": 3600}
        }))
        .expect("stream config deserializes");

        let view = stream_view(config).expect("stream view renders");

        // Pins the full default-resolved view: a rename or format regression fails here.
        assert_eq!(
            view,
            json!({
                "storage_class": "express",
                "retention_policy": "2d",
                "timestamping": {"mode": "client-prefer", "uncapped": false},
                "delete_on_empty": {"min_age": "1h"}
            })
        );
    }

    #[test]
    fn durations_render_exactly_at_every_scale() {
        for (seconds, rendered) in [
            (0, "0s"),
            (1, "1s"),
            (90 * 60, "1h 30m"),
            (86_400, "1d"),
            (36 * 3_600, "1d 12h"),
            (60 * 86_400, "60d"),
            (90 * 86_400, "90d"),
            (365 * 86_400, "365d"),
            (86_400 + 3_600 + 60 + 1, "1d 1h 1m 1s"),
        ] {
            assert_eq!(
                super::compact_duration(std::time::Duration::from_secs(seconds)),
                rendered,
            );
        }
    }

    #[test]
    fn omitted_and_explicit_defaults_render_identically() {
        let omitted = serde_json::from_value(json!({})).expect("empty config deserializes");
        let explicit = serde_json::from_value(json!({
            "storage_class": "express",
            "retention_policy": {"age": 604800},
            "timestamping": {"mode": "client-prefer", "uncapped": false},
            "delete_on_empty": {"min_age_secs": 0}
        }))
        .expect("explicit config deserializes");

        assert_eq!(
            stream_view(omitted).expect("omitted view renders"),
            stream_view(explicit).expect("explicit view renders"),
        );
    }

    #[test]
    fn basin_views_materialize_effective_stream_defaults() {
        let config = serde_json::from_value(json!({
            "default_stream_config": null,
            "stream_cipher": null,
            "create_stream_on_append": true,
            "create_stream_on_read": false
        }))
        .expect("basin config deserializes");

        let view = basin_view(config).expect("basin view renders");

        assert_eq!(
            view,
            json!({
                "default_stream_config": {
                    "storage_class": "express",
                    "retention_policy": "7d",
                    "timestamping": {"mode": "client-prefer", "uncapped": false},
                    "delete_on_empty": {"min_age": "0s"}
                },
                "stream_cipher": "none",
                "create_stream_on_append": true,
                "create_stream_on_read": false
            })
        );
    }

    #[test]
    fn basin_defaults_view_matches_equivalent_stream_view() {
        let basin = serde_json::from_value(json!({
            "default_stream_config": {"retention_policy": {"age": 259200}},
            "stream_cipher": null,
            "create_stream_on_append": false,
            "create_stream_on_read": false
        }))
        .expect("basin config deserializes");
        let stream = serde_json::from_value(json!({
            "retention_policy": {"age": 259200}
        }))
        .expect("stream config deserializes");

        assert_eq!(
            basin_stream_defaults_view(basin).expect("defaults view renders"),
            stream_view(stream).expect("stream view renders"),
        );
    }

    #[test]
    fn infinite_and_finite_retention_render_distinctly() {
        let infinite = serde_json::from_value(json!({
            "retention_policy": {"infinite": {}}
        }))
        .expect("infinite config deserializes");
        let finite = serde_json::from_value(json!({
            "retention_policy": {"age": 604800}
        }))
        .expect("finite config deserializes");

        let diffs = field_diffs(
            &stream_view(infinite).expect("infinite view renders"),
            &stream_view(finite).expect("finite view renders"),
        );

        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "retention_policy");
        assert_eq!(format_value_lines(diffs[0].left.as_ref()), ["infinite"]);
        assert_eq!(format_value_lines(diffs[0].right.as_ref()), ["7d"]);
    }

    #[test]
    fn access_token_views_canonicalize_ops_and_drop_identity() {
        let left = serde_json::from_value(json!({
            "id": "left-token",
            "expires_at": null,
            "auto_prefix_streams": false,
            "scope": {
                "basins": {"prefix": "prod-"},
                "streams": null,
                "access_tokens": null,
                "op_groups": {"account": {"read": true, "write": false}},
                "ops": ["read", "get-stream-config", "account-metrics"]
            }
        }))
        .expect("left access token deserializes");
        let right = serde_json::from_value(json!({
            "id": "right-token",
            "expires_at": null,
            "auto_prefix_streams": false,
            "scope": {
                "basins": {"prefix": "prod-"},
                "streams": null,
                "access_tokens": null,
                "op_groups": {"account": {"read": true, "write": false}},
                "ops": ["account-metrics", "read", "get-stream-config"]
            }
        }))
        .expect("right access token deserializes");

        let left = access_token_view(left).expect("left view renders");
        let right = access_token_view(right).expect("right view renders");

        // Identity and operation order do not affect the diff.
        assert_eq!(left, right);
        assert_eq!(
            left["scope"]["ops"],
            json!(["account-metrics", "get-stream-config", "read"])
        );
        assert_eq!(left["scope"]["basins"], json!("prefix: \"prod-\""));
        assert_eq!(left["scope"]["op_groups"]["account"], json!("r"));
        assert_eq!(left["scope"]["op_groups"]["stream"], json!("none"));
        assert_eq!(left["expires_at"], json!("never"));
        assert!(left.get("id").is_none());
    }

    #[test]
    fn reports_nested_field_differences() {
        let diffs = field_diffs(
            &json!({"unchanged": true, "config": {"storage_class": "standard"}}),
            &json!({"unchanged": true, "config": {"storage_class": "express"}}),
        );

        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "config.storage_class");
        assert_eq!(format_value_lines(diffs[0].left.as_ref()), ["standard"]);
        assert_eq!(format_value_lines(diffs[0].right.as_ref()), ["express"]);
    }

    #[test]
    fn reports_added_and_removed_fields() {
        let diffs = field_diffs(&json!({"left": 1}), &json!({"right": 2}));

        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].path, "left");
        assert_eq!(format_value_lines(diffs[0].right.as_ref()), ["∅"]);
        assert_eq!(diffs[1].path, "right");
        assert_eq!(format_value_lines(diffs[1].left.as_ref()), ["∅"]);
    }

    #[test]
    fn formats_structured_values_across_lines() {
        assert_eq!(
            format_value_lines(Some(&json!(["read", "append"]))),
            ["[", "  \"read\",", "  \"append\"", "]"]
        );
    }

    #[test]
    fn omits_unchanged_fields() {
        assert!(field_diffs(&json!({"same": [1, 2]}), &json!({"same": [1, 2]})).is_empty());
    }
}
