//! Diffing over typed presentation views of basins, streams, and access tokens.

use colored::Colorize;
use s2_sdk::types::{
    AccessTokenId, AccessTokenInfo, AccessTokenMatcher, AccessTokenScope, BasinConfig,
    BasinMatcher, ReadWritePermissions, StreamConfig, StreamMatcher, Timestamp,
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    cli::{DiffArgs, DiffOutput, DiffResourceKind},
    error::CliError,
    ops,
    types::{DiffResource, S2BasinAndStreamUri, S2BasinUri, resolve_stream_config},
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unresolved: Vec<&'static str>,
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

    let (left_view, right_view, storage_class_unresolved) = match (left, right) {
        (DiffResource::Basin(left), DiffResource::Basin(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_basin_config(s2, &left),
                ops::get_basin_config(s2, &right),
            )?;
            (basin_view(left_config)?, basin_view(right_config)?, false)
        }
        (DiffResource::Stream(left), DiffResource::Stream(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_stream_config(s2, left),
                ops::get_stream_config(s2, right),
            )?;
            (stream_view(left_config)?, stream_view(right_config)?, false)
        }
        (DiffResource::Basin(basin), DiffResource::Stream(stream)) => {
            let (basin_config, stream_config) = tokio::try_join!(
                ops::get_basin_config(s2, &basin),
                ops::get_stream_config(s2, stream),
            )?;
            let default_sc =
                if needs_default_storage_class_for_stream_diff(&basin_config, &stream_config) {
                    ops::default_storage_class(s2).await?
                } else {
                    None
                };
            stream_vs_basin_defaults_views(basin_config, stream_config, default_sc.as_deref())?
        }
        (DiffResource::Stream(stream), DiffResource::Basin(basin)) => {
            let (stream_config, basin_config) = tokio::try_join!(
                ops::get_stream_config(s2, stream),
                ops::get_basin_config(s2, &basin),
            )?;
            let default_sc =
                if needs_default_storage_class_for_stream_diff(&basin_config, &stream_config) {
                    ops::default_storage_class(s2).await?
                } else {
                    None
                };
            let (basin_view, stream_view, unresolved) =
                stream_vs_basin_defaults_views(basin_config, stream_config, default_sc.as_deref())?;
            (stream_view, basin_view, unresolved)
        }
        (DiffResource::AccessToken(left), DiffResource::AccessToken(right)) => {
            let (left_info, right_info) = tokio::try_join!(
                ops::get_access_token(s2, left),
                ops::get_access_token(s2, right),
            )?;
            (
                access_token_view(left_info)?,
                access_token_view(right_info)?,
                false,
            )
        }
        _ => unreachable!("diff arguments are resolved to matching resource types"),
    };

    let differences = field_diffs(&left_view, &right_view);
    let has_differences = !differences.is_empty();
    let unresolved = if storage_class_unresolved {
        vec!["storage_class"]
    } else {
        Vec::new()
    };

    match args.output {
        DiffOutput::Text => print_text_diff(
            &left_label,
            &right_label,
            &differences,
            storage_class_unresolved,
        ),
        DiffOutput::Json => println!(
            "{}",
            serde_json::to_string_pretty(&JsonDiff {
                resource: comparison.as_str(),
                left: &args.left,
                right: &args.right,
                differences: &differences,
                unresolved,
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

/// Presentation of a stream configuration for comparison.
///
/// - Field names and nesting mirror the API wire format so that `--output json` paths line up with
///   API responses.
/// - Durations render compact (`"7d"`, `"1h30m"`); retention renders as `"infinite"` or an age
///   duration.
#[derive(Serialize)]
struct StreamConfigView {
    storage_class: Option<String>,
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

impl From<crate::types::ResolvedStreamConfig> for StreamConfigView {
    fn from(config: crate::types::ResolvedStreamConfig) -> Self {
        let crate::types::ResolvedStreamConfig {
            storage_class,
            retention_policy,
            timestamping_mode,
            timestamping_uncapped,
            delete_on_empty_min_age,
        } = config;

        Self {
            storage_class,
            retention_policy: match retention_policy {
                s2_sdk::types::RetentionPolicy::Age(secs) => {
                    compact_duration(std::time::Duration::from_secs(secs))
                }
                s2_sdk::types::RetentionPolicy::Infinite => "infinite".to_owned(),
                s2_sdk::types::RetentionPolicy::Unknown(name) => name,
                _ => "unknown".to_owned(),
            },
            timestamping: TimestampingConfigView {
                mode: timestamping_mode.as_str().to_owned(),
                uncapped: timestamping_uncapped,
            },
            delete_on_empty: DeleteOnEmptyConfigView {
                min_age: compact_duration(delete_on_empty_min_age),
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

impl From<BasinConfig> for BasinConfigView {
    fn from(config: BasinConfig) -> Self {
        Self {
            default_stream_config: resolve_stream_config(
                config.default_stream_config().cloned().unwrap_or_default(),
                Default::default(),
            )
            .into(),
            stream_cipher: config
                .stream_cipher()
                .map_or_else(|| "none".to_owned(), |c| c.as_str().to_owned()),
            create_stream_on_append: config.create_stream_on_append(),
            create_stream_on_read: config.create_stream_on_read(),
        }
    }
}

/// Presentation of an access token.
///
/// - The token ID is identity, not configuration, so it is deliberately excluded.
/// - Operations render as a sorted list of wire-format names; sets and permissions render as
///   compact strings (`"prefix: \"prod-\""`, `"rw"`).
/// - The network policy renders as its `<slug>.<nonce>` reference, or `none`: it decides where the
///   token may be used from, so two tokens that differ only in it are different.
#[derive(Serialize)]
struct AccessTokenInfoView {
    expires_at: String,
    auto_prefix_streams: bool,
    network_policy: String,
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

impl From<&AccessTokenScope> for AccessTokenScopeView {
    fn from(scope: &AccessTokenScope) -> Self {
        let op_groups = scope.op_group_perms().unwrap_or_default();
        let mut ops = scope
            .ops()
            .iter()
            .map(|op| op.as_str().to_owned())
            .collect::<Vec<_>>();
        ops.sort();

        Self {
            basins: match scope.basins() {
                BasinMatcher::None => "none".to_owned(),
                BasinMatcher::Exact(exact) => format!("exact: \"{exact}\""),
                BasinMatcher::Prefix(prefix) => format!("prefix: \"{prefix}\""),
                BasinMatcher::Unknown(kind) => kind.clone(),
                _ => "unknown".to_owned(),
            },
            streams: match scope.streams() {
                StreamMatcher::None => "none".to_owned(),
                StreamMatcher::Exact(exact) => format!("exact: \"{exact}\""),
                StreamMatcher::Prefix(prefix) => format!("prefix: \"{prefix}\""),
                StreamMatcher::Unknown(kind) => kind.clone(),
                _ => "unknown".to_owned(),
            },
            access_tokens: match scope.access_tokens() {
                AccessTokenMatcher::None => "none".to_owned(),
                AccessTokenMatcher::Exact(exact) => format!("exact: \"{exact}\""),
                AccessTokenMatcher::Prefix(prefix) => format!("prefix: \"{prefix}\""),
                AccessTokenMatcher::Unknown(kind) => kind.clone(),
                _ => "unknown".to_owned(),
            },
            op_groups: OperationGroupsView {
                account: permissions_view(op_groups.account()),
                basin: permissions_view(op_groups.basin()),
                stream: permissions_view(op_groups.stream()),
            },
            ops,
        }
    }
}

fn permissions_view(permissions: Option<ReadWritePermissions>) -> String {
    let permissions = permissions.unwrap_or_default();
    match (permissions.read(), permissions.write()) {
        (true, true) => "rw",
        (true, false) => "r",
        (false, true) => "w",
        (false, false) => "none",
    }
    .to_owned()
}

fn basin_view(config: BasinConfig) -> Result<Value, CliError> {
    Ok(serde_json::to_value(BasinConfigView::from(config))?)
}

fn needs_default_storage_class_for_stream_diff(
    basin_config: &BasinConfig,
    stream_config: &StreamConfig,
) -> bool {
    basin_config
        .default_stream_config()
        .and_then(|c| c.storage_class())
        .is_none()
        && stream_config.storage_class().is_some()
}

/// Renders a basin's effective stream defaults and a concrete stream config for comparison.
///
/// When the basin leaves `default_stream_config.storage_class` unset so streams inherit the
/// location default, fill in `default_storage_class` if known. If discovery is unavailable while
/// the stream carries a server-resolved storage class, omit `storage_class` from both views and
/// return `storage_class_unresolved = true` so inherited defaults are not reported as drift.
fn stream_vs_basin_defaults_views(
    basin_config: BasinConfig,
    stream_config: StreamConfig,
    default_storage_class: Option<&str>,
) -> Result<(Value, Value, bool), CliError> {
    let mut basin_defaults = basin_config
        .default_stream_config()
        .cloned()
        .unwrap_or_default();
    let mut storage_class_unresolved = false;

    if basin_defaults.storage_class().is_none() {
        if let Some(sc) = default_storage_class {
            basin_defaults = basin_defaults.with_storage_class(sc.to_owned());
        } else if stream_config.storage_class().is_some() {
            storage_class_unresolved = true;
        }
    }

    let mut basin_view = stream_view(basin_defaults)?;
    let mut stream_view = stream_view(stream_config)?;
    if storage_class_unresolved {
        if let Some(map) = basin_view.as_object_mut() {
            map.remove("storage_class");
        }
        if let Some(map) = stream_view.as_object_mut() {
            map.remove("storage_class");
        }
    }
    Ok((basin_view, stream_view, storage_class_unresolved))
}

#[cfg(test)]
/// Renders a basin's effective stream defaults for comparison against a concrete stream.
fn basin_stream_defaults_view(config: BasinConfig) -> Result<Value, CliError> {
    stream_view(config.default_stream_config().cloned().unwrap_or_default())
}

fn stream_view(config: StreamConfig) -> Result<Value, CliError> {
    let config = resolve_stream_config(config, Default::default());
    Ok(serde_json::to_value(StreamConfigView::from(config))?)
}

fn access_token_view(info: AccessTokenInfo) -> Result<Value, CliError> {
    let AccessTokenInfo {
        // Identity, not configuration.
        id: _,
        expires_at,
        auto_prefix_streams,
        scope,
        network_policy,
        ..
    } = info;

    Ok(serde_json::to_value(AccessTokenInfoView {
        expires_at: match expires_at {
            None => "never".to_owned(),
            Some(at) => Timestamp::from_second(at.as_second())
                .expect("valid timestamp second")
                .to_string(),
        },
        auto_prefix_streams,
        network_policy: match network_policy {
            None => "none".to_owned(),
            Some(id) => id.to_string(),
        },
        scope: AccessTokenScopeView::from(&scope),
    })?)
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

fn print_text_diff(
    left_label: &str,
    right_label: &str,
    differences: &[FieldDiff],
    storage_class_unresolved: bool,
) {
    println!("{}", format!("--- {left_label}").red().bold());
    println!("{}", format!("+++ {right_label}").green().bold());

    if differences.is_empty() {
        println!();
        println!("{}", "✓ No differences".green().bold());
        if storage_class_unresolved {
            println!(
                "{}",
                "  (storage_class not compared: location default unavailable)".dimmed()
            );
        }
        return;
    }

    for difference in differences {
        println!();
        println!("{}", difference.path.bold());
        print_value("-", difference.left.as_ref(), true);
        print_value("+", difference.right.as_ref(), false);
    }

    if storage_class_unresolved {
        println!();
        println!(
            "{}",
            "storage_class: not compared (location default unavailable)".dimmed()
        );
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
        let config = s2_sdk::types::StreamConfig::new()
            .with_retention_policy(s2_sdk::types::RetentionPolicy::Age(172_800))
            .with_delete_on_empty(
                s2_sdk::types::DeleteOnEmptyConfig::new().with_min_age_secs(3600),
            );

        let view = stream_view(config).expect("stream view renders");

        // Pins the full default-resolved view: a rename or format regression fails here.
        assert_eq!(
            view,
            json!({
                "storage_class": null,
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
        let omitted = s2_sdk::types::StreamConfig::new();
        let explicit = s2_sdk::types::StreamConfig::new()
            .with_retention_policy(s2_sdk::types::RetentionPolicy::Age(604_800))
            .with_timestamping(
                s2_sdk::types::TimestampingConfig::new()
                    .with_mode(s2_sdk::types::TimestampingMode::ClientPrefer)
                    .with_uncapped(false),
            )
            .with_delete_on_empty(s2_sdk::types::DeleteOnEmptyConfig::new().with_min_age_secs(0));

        assert_eq!(
            stream_view(omitted).expect("omitted view renders"),
            stream_view(explicit).expect("explicit view renders"),
        );
    }

    #[test]
    fn basin_views_materialize_effective_stream_defaults() {
        let config = s2_sdk::types::BasinConfig::new()
            .with_create_stream_on_append(true)
            .with_create_stream_on_read(false);

        let view = basin_view(config).expect("basin view renders");

        assert_eq!(
            view,
            json!({
                "default_stream_config": {
                    "storage_class": null,
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
        let basin = s2_sdk::types::BasinConfig::new().with_default_stream_config(
            s2_sdk::types::StreamConfig::new()
                .with_retention_policy(s2_sdk::types::RetentionPolicy::Age(259_200)),
        );
        let stream = s2_sdk::types::StreamConfig::new()
            .with_retention_policy(s2_sdk::types::RetentionPolicy::Age(259_200));

        assert_eq!(
            basin_stream_defaults_view(basin).expect("defaults view renders"),
            stream_view(stream).expect("stream view renders"),
        );
    }

    #[test]
    fn infinite_and_finite_retention_render_distinctly() {
        let infinite = s2_sdk::types::StreamConfig::new()
            .with_retention_policy(s2_sdk::types::RetentionPolicy::Infinite);
        let finite = s2_sdk::types::StreamConfig::new()
            .with_retention_policy(s2_sdk::types::RetentionPolicy::Age(604_800));

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
        use s2_sdk::types::{
            AccessTokenInfo, AccessTokenScope, BasinMatcher, Operation, OperationGroupPermissions,
            ReadWritePermissions,
        };

        let left = AccessTokenInfo::new(
            "left-token".parse().unwrap(),
            AccessTokenScope::new()
                .with_basins(BasinMatcher::Prefix("prod-".parse().unwrap()))
                .with_op_group_perms(
                    OperationGroupPermissions::new()
                        .with_account(ReadWritePermissions::read_only()),
                )
                .with_ops([
                    Operation::Read,
                    Operation::Unknown("some-future-op".to_owned()),
                    Operation::GetStreamConfig,
                    Operation::GetAccountMetrics,
                ]),
        );
        let right = AccessTokenInfo::new(
            "right-token".parse().unwrap(),
            AccessTokenScope::new()
                .with_basins(BasinMatcher::Prefix("prod-".parse().unwrap()))
                .with_op_group_perms(
                    OperationGroupPermissions::new()
                        .with_account(ReadWritePermissions::read_only()),
                )
                .with_ops([
                    Operation::GetAccountMetrics,
                    Operation::Read,
                    Operation::GetStreamConfig,
                    Operation::Unknown("some-future-op".to_owned()),
                ]),
        );

        let left = access_token_view(left).expect("left view renders");
        let right = access_token_view(right).expect("right view renders");

        // Identity and operation order do not affect the diff.
        assert_eq!(left, right);
        assert_eq!(
            left["scope"]["ops"],
            json!([
                "account-metrics",
                "get-stream-config",
                "read",
                "some-future-op"
            ])
        );
        assert_eq!(left["scope"]["basins"], json!("prefix: \"prod-\""));
        assert_eq!(left["scope"]["op_groups"]["account"], json!("r"));
        assert_eq!(left["scope"]["op_groups"]["stream"], json!("none"));
        assert_eq!(left["expires_at"], json!("never"));
        assert_eq!(left["network_policy"], json!("none"));
        assert!(left.get("id").is_none());
    }

    #[test]
    fn access_token_views_preserve_unknown_resource_matchers() {
        use s2_sdk::types::{
            AccessTokenInfo, AccessTokenMatcher, AccessTokenScope, BasinMatcher, Operation,
            StreamMatcher,
        };

        let info = AccessTokenInfo::new(
            "future-token".parse().unwrap(),
            AccessTokenScope::from_ops([Operation::Read])
                .with_basins(BasinMatcher::Unknown("regex".to_owned()))
                .with_streams(StreamMatcher::Unknown("glob".to_owned()))
                .with_access_tokens(AccessTokenMatcher::Unknown("tag".to_owned())),
        );

        let view =
            access_token_view(info).expect("view renders without failing on unknown matchers");
        assert_eq!(view["scope"]["basins"], json!("regex"));
        assert_eq!(view["scope"]["streams"], json!("glob"));
        assert_eq!(view["scope"]["access_tokens"], json!("tag"));
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

    #[test]
    fn stream_vs_basin_defaults_uses_discovered_location_default() {
        let basin = s2_sdk::types::BasinConfig::new();
        let matching_stream = s2_sdk::types::StreamConfig::new().with_storage_class("express");
        let (left, right, unresolved) =
            super::stream_vs_basin_defaults_views(basin.clone(), matching_stream, Some("express"))
                .expect("views render");
        assert!(!unresolved);
        assert!(field_diffs(&left, &right).is_empty());

        let differing_stream = s2_sdk::types::StreamConfig::new().with_storage_class("standard");
        let (left, right, unresolved) =
            super::stream_vs_basin_defaults_views(basin, differing_stream, Some("express"))
                .expect("views render");
        assert!(!unresolved);
        let diffs = field_diffs(&left, &right);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "storage_class");
        assert_eq!(diffs[0].left, Some(json!("express")));
        assert_eq!(diffs[0].right, Some(json!("standard")));
    }

    #[test]
    fn stream_vs_basin_defaults_skips_unresolved_storage_class_without_discovery() {
        let basin = s2_sdk::types::BasinConfig::new();
        let stream = s2_sdk::types::StreamConfig::new().with_storage_class("express");
        let (left, right, unresolved) =
            super::stream_vs_basin_defaults_views(basin.clone(), stream, None)
                .expect("views render");
        assert!(unresolved);
        assert!(field_diffs(&left, &right).is_empty());

        let stream_with_other_diff = s2_sdk::types::StreamConfig::new()
            .with_storage_class("express")
            .with_retention_policy(s2_sdk::types::RetentionPolicy::Infinite);
        let (left, right, unresolved) =
            super::stream_vs_basin_defaults_views(basin, stream_with_other_diff, None)
                .expect("views render");
        assert!(unresolved);
        let diffs = field_diffs(&left, &right);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "retention_policy");
    }

    #[test]
    fn stream_vs_basin_defaults_compares_explicit_basin_storage_class_without_discovery() {
        let basin = s2_sdk::types::BasinConfig::new().with_default_stream_config(
            s2_sdk::types::StreamConfig::new().with_storage_class("standard"),
        );
        let stream = s2_sdk::types::StreamConfig::new().with_storage_class("express");
        let (left, right, unresolved) =
            super::stream_vs_basin_defaults_views(basin, stream, None).expect("views render");
        assert!(!unresolved);
        let diffs = field_diffs(&left, &right);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "storage_class");
        assert_eq!(diffs[0].left, Some(json!("standard")));
        assert_eq!(diffs[0].right, Some(json!("express")));
    }
}
