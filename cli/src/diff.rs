use colored::Colorize;
use s2_api::v1::config::{BasinConfig as ApiBasinConfig, StreamConfig as ApiStreamConfig};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotKind {
    Basin,
    Stream,
    AccessToken,
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

    let (left_value, right_value) = match (left, right) {
        (DiffResource::Basin(left), DiffResource::Basin(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_basin_config_api(s2, &left),
                ops::get_basin_config_api(s2, &right),
            )?;

            (
                api_snapshot(api_basin_config(left_config), SnapshotKind::Basin)?,
                api_snapshot(api_basin_config(right_config), SnapshotKind::Basin)?,
            )
        }
        (DiffResource::Stream(left), DiffResource::Stream(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_stream_config_api(s2, left),
                ops::get_stream_config_api(s2, right),
            )?;

            (
                api_snapshot(left_config, SnapshotKind::Stream)?,
                api_snapshot(right_config, SnapshotKind::Stream)?,
            )
        }
        (DiffResource::Basin(basin), DiffResource::Stream(stream)) => {
            let (basin_config, stream_config) = tokio::try_join!(
                ops::get_basin_config_api(s2, &basin),
                ops::get_stream_config_api(s2, stream),
            )?;

            let basin_config = api_basin_config(basin_config);
            (
                api_snapshot(
                    basin_config
                        .default_stream_config
                        .expect("basin API snapshots always resolve stream defaults"),
                    SnapshotKind::Stream,
                )?,
                api_snapshot(stream_config, SnapshotKind::Stream)?,
            )
        }
        (DiffResource::Stream(stream), DiffResource::Basin(basin)) => {
            let (stream_config, basin_config) = tokio::try_join!(
                ops::get_stream_config_api(s2, stream),
                ops::get_basin_config_api(s2, &basin),
            )?;

            let basin_config = api_basin_config(basin_config);
            (
                api_snapshot(stream_config, SnapshotKind::Stream)?,
                api_snapshot(
                    basin_config
                        .default_stream_config
                        .expect("basin API snapshots always resolve stream defaults"),
                    SnapshotKind::Stream,
                )?,
            )
        }
        (DiffResource::AccessToken(left), DiffResource::AccessToken(right)) => {
            let (left_info, right_info) = tokio::try_join!(
                ops::get_access_token_api(s2, left),
                ops::get_access_token_api(s2, right),
            )?;

            let mut left = api_snapshot(left_info, SnapshotKind::AccessToken)?;
            let mut right = api_snapshot(right_info, SnapshotKind::AccessToken)?;
            remove_identity(&mut left);
            remove_identity(&mut right);
            (left, right)
        }
        _ => unreachable!("diff arguments are resolved to matching resource types"),
    };

    let differences = field_diffs(&left_value, &right_value);

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

    Ok(DiffOutcome {
        has_differences: !differences.is_empty(),
    })
}

fn api_basin_config(mut config: ApiBasinConfig) -> ApiBasinConfig {
    config
        .default_stream_config
        .get_or_insert_with(ApiStreamConfig::default);
    config
}

fn api_snapshot(value: impl Serialize, kind: SnapshotKind) -> Result<Value, serde_json::Error> {
    let mut value = serde_json::to_value(value)?;
    canonicalize_value(&mut value, kind, "");
    Ok(value)
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

fn remove_identity(value: &mut Value) {
    if let Value::Object(object) = value {
        object.remove("id");
    }
}

fn canonicalize_value(value: &mut Value, kind: SnapshotKind, path: &str) {
    // Keep presentation rules path-scoped so newly added API fields pass through untouched.
    if normalize_default_value(value, kind, path) {
        return;
    }
    if is_stream_config_path(kind, path, "retention_policy")
        && let Some(retention_policy) = canonical_retention_policy(value)
    {
        *value = Value::String(retention_policy);
        return;
    }
    if is_stream_config_path(kind, path, "delete_on_empty.min_age")
        && let Some(seconds) = value.as_u64()
    {
        *value = Value::String(compact_seconds(seconds));
        return;
    }

    match value {
        Value::Object(object) => {
            let entries = std::mem::take(object);
            for (key, mut value) in entries {
                let key = canonical_field_name(kind, path, &key);
                let child_path = join_snapshot_path(path, key);
                canonicalize_value(&mut value, kind, &child_path);
                object.insert(key.to_owned(), value);
            }
        }
        Value::Array(values) => {
            for value in values.iter_mut() {
                canonicalize_value(value, kind, path);
            }
            if is_access_token_ops_path(kind, path) {
                values.sort_by_key(Value::to_string);
            }
        }
        Value::String(value) => {
            if is_access_token_ops_path(kind, path) {
                *value = canonical_operation(value);
            } else if is_stream_config_path(kind, path, "delete_on_empty.min_age") {
                *value = compact_duration(value);
            }
        }
        _ => {}
    }
}

fn normalize_default_value(value: &mut Value, kind: SnapshotKind, path: &str) -> bool {
    if !value.is_null() {
        return false;
    }

    *value = if is_stream_config_path(kind, path, "storage_class") {
        Value::String("express".to_owned())
    } else if is_stream_config_path(kind, path, "retention_policy") {
        Value::String("7d".to_owned())
    } else if is_stream_config_path(kind, path, "timestamping") {
        serde_json::json!({
            "mode": "client-prefer",
            "uncapped": false,
        })
    } else if is_stream_config_path(kind, path, "timestamping.mode") {
        Value::String("client-prefer".to_owned())
    } else if is_stream_config_path(kind, path, "timestamping.uncapped") {
        Value::Bool(false)
    } else if is_stream_config_path(kind, path, "delete_on_empty") {
        serde_json::json!({"min_age": "0s"})
    } else if is_stream_config_path(kind, path, "delete_on_empty.min_age") {
        Value::String("0s".to_owned())
    } else if kind == SnapshotKind::Basin && path == "stream_cipher" {
        Value::String("none".to_owned())
    } else if is_access_token_ops_path(kind, path) {
        Value::Array(Vec::new())
    } else {
        return false;
    };
    true
}

fn canonical_retention_policy(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if value.eq_ignore_ascii_case("infinite") => {
            Some("infinite".to_owned())
        }
        Value::Object(object) if object.len() == 1 => {
            if let Some(age) = object.get("Age").or_else(|| object.get("age")) {
                canonical_duration(age)
            } else if object
                .get("Infinite")
                .or_else(|| object.get("infinite"))
                .is_some_and(|payload| payload.as_object().is_some_and(Map::is_empty))
            {
                Some("infinite".to_owned())
            } else {
                None
            }
        }
        _ => None,
    }
}

fn canonical_field_name<'a>(kind: SnapshotKind, parent: &str, field: &'a str) -> &'a str {
    if is_stream_config_path(kind, parent, "timestamping") {
        match field {
            "timestamping_mode" => return "mode",
            "timestamping_uncapped" => return "uncapped",
            _ => {}
        }
    } else if is_stream_config_path(kind, parent, "delete_on_empty")
        && matches!(field, "delete_on_empty_min_age" | "min_age_secs")
    {
        return "min_age";
    } else if is_stream_config_path(kind, parent, "retention_policy") {
        match field {
            "Age" => return "age",
            "Infinite" => return "infinite",
            _ => {}
        }
    } else if kind == SnapshotKind::AccessToken && parent == "scope" && field == "op_groups" {
        return "op_group_perms";
    }
    field
}

fn is_stream_config_path(kind: SnapshotKind, path: &str, relative: &str) -> bool {
    match kind {
        SnapshotKind::Stream => path == relative,
        SnapshotKind::Basin => path
            .strip_prefix("default_stream_config.")
            .is_some_and(|path| path == relative),
        SnapshotKind::AccessToken => false,
    }
}

fn is_access_token_ops_path(kind: SnapshotKind, path: &str) -> bool {
    kind == SnapshotKind::AccessToken && path == "scope.ops"
}

fn join_snapshot_path(parent: &str, field: &str) -> String {
    if parent.is_empty() {
        field.to_owned()
    } else {
        format!("{parent}.{field}")
    }
}

fn canonical_duration(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(compact_duration(value)),
        Value::Number(value) => value.as_u64().map(compact_seconds),
        _ => None,
    }
}

fn compact_seconds(seconds: u64) -> String {
    compact_duration(
        &humantime::format_duration(std::time::Duration::from_secs(seconds)).to_string(),
    )
}

fn canonical_operation(value: &str) -> String {
    match value {
        "account-metrics" => "get_account_metrics".to_owned(),
        "basin-metrics" => "get_basin_metrics".to_owned(),
        "stream-metrics" => "get_stream_metrics".to_owned(),
        _ => value.replace('-', "_"),
    }
}

fn compact_duration(value: &str) -> String {
    [
        ("nanoseconds", "ns"),
        ("nanosecond", "ns"),
        ("microseconds", "us"),
        ("microsecond", "us"),
        ("milliseconds", "ms"),
        ("millisecond", "ms"),
        ("weeks", "w"),
        ("week", "w"),
        ("days", "d"),
        ("day", "d"),
        ("hours", "h"),
        ("hour", "h"),
        ("minutes", "m"),
        ("minute", "m"),
        ("seconds", "s"),
        ("second", "s"),
    ]
    .into_iter()
    .fold(value.to_owned(), |value, (long, short)| {
        value.replace(long, short)
    })
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
        DiffComparison, SnapshotKind, api_basin_config, api_snapshot, canonicalize_value,
        field_diffs, format_value_lines, resolve_args, resource_kind,
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
    fn canonicalizes_config_paths_and_durations() {
        let mut left = json!({
            "retention_policy": {"age": 172800},
            "timestamping": {"mode": "client-prefer"},
            "delete_on_empty": {"min_age_secs": 600}
        });
        let mut right = json!({
            "retention_policy": {"age": 2592000},
            "timestamping": {"mode": "arrival"},
            "delete_on_empty": {"min_age_secs": 3600}
        });

        canonicalize_value(&mut left, SnapshotKind::Stream, "");
        canonicalize_value(&mut right, SnapshotKind::Stream, "");
        let diffs = field_diffs(&left, &right);

        assert_eq!(diffs[0].path, "retention_policy");
        assert_eq!(format_value_lines(diffs[0].left.as_ref()), ["2d"]);
        assert_eq!(diffs[1].path, "timestamping.mode");
        assert_eq!(diffs[2].path, "delete_on_empty.min_age");
        assert_eq!(format_value_lines(diffs[2].right.as_ref()), ["1h"]);
    }

    #[test]
    fn canonicalizes_finite_and_infinite_retention_consistently() {
        let mut left = json!({
            "default_stream_config": {"retention_policy": {"infinite": {}}}
        });
        let mut right = json!({
            "default_stream_config": {"retention_policy": {"age": 604800}}
        });

        canonicalize_value(&mut left, SnapshotKind::Basin, "");
        canonicalize_value(&mut right, SnapshotKind::Basin, "");
        let diffs = field_diffs(&left, &right);

        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "default_stream_config.retention_policy");
        assert_eq!(format_value_lines(diffs[0].left.as_ref()), ["infinite"]);
        assert_eq!(format_value_lines(diffs[0].right.as_ref()), ["7d"]);
    }

    #[test]
    fn canonicalizes_omitted_config_defaults_to_effective_values() {
        let mut left = json!({
            "default_stream_config": {
                "storage_class": null,
                "retention_policy": null,
                "timestamping": null,
                "delete_on_empty": null
            }
        });
        let mut right = json!({
            "default_stream_config": {
                "storage_class": null,
                "retention_policy": {"age": 604800},
                "timestamping": {
                    "mode": "arrival",
                    "uncapped": null
                },
                "delete_on_empty": null
            }
        });

        canonicalize_value(&mut left, SnapshotKind::Basin, "");
        canonicalize_value(&mut right, SnapshotKind::Basin, "");
        let diffs = field_diffs(&left, &right);

        assert_eq!(diffs.len(), 1);
        assert_eq!(
            left["default_stream_config"]["storage_class"],
            json!("express")
        );
        assert_eq!(
            left["default_stream_config"]["retention_policy"],
            json!("7d")
        );
        assert_eq!(diffs[0].path, "default_stream_config.timestamping.mode");
        assert_eq!(
            format_value_lines(diffs[0].left.as_ref()),
            ["client-prefer"]
        );
        assert_eq!(format_value_lines(diffs[0].right.as_ref()), ["arrival"]);
    }

    #[test]
    fn typed_api_snapshots_use_canonical_presentation() {
        use s2_api::v1::config::{DeleteOnEmptyConfig, RetentionPolicy, StreamConfig};

        let snapshot = api_snapshot(
            StreamConfig {
                retention_policy: Some(RetentionPolicy::Age(7 * 24 * 60 * 60)),
                delete_on_empty: Some(DeleteOnEmptyConfig { min_age_secs: 600 }),
                ..Default::default()
            },
            SnapshotKind::Stream,
        )
        .expect("API config serializes");

        assert_eq!(snapshot["storage_class"], json!("express"));
        assert_eq!(snapshot["retention_policy"], json!("7d"));
        assert_eq!(snapshot["delete_on_empty"]["min_age"], json!("10m"));
    }

    #[test]
    fn basin_api_snapshots_materialize_effective_stream_defaults() {
        let config = api_basin_config(s2_common::config::BasinConfig::default().into());

        assert!(config.default_stream_config.is_some());
    }

    #[test]
    fn canonicalizes_access_token_api_names_and_set_order() {
        let mut left = json!({
            "scope": {
                "op_groups": null,
                "ops": ["read", "get-stream-config", "account-metrics"]
            }
        });
        let mut right = json!({
            "scope": {
                "op_groups": null,
                "ops": ["account-metrics", "read", "get-stream-config"]
            }
        });

        canonicalize_value(&mut left, SnapshotKind::AccessToken, "");
        canonicalize_value(&mut right, SnapshotKind::AccessToken, "");

        assert_eq!(left, right);
        assert_eq!(
            left["scope"]["ops"],
            json!(["get_account_metrics", "get_stream_config", "read"])
        );
        assert!(left["scope"].get("op_group_perms").is_some());
        assert!(left["scope"].get("op_groups").is_none());
    }

    #[test]
    fn future_api_fields_flow_into_diffs_without_snapshot_changes() {
        #[derive(serde::Serialize)]
        struct FutureStreamConfig {
            #[serde(flatten)]
            config: s2_api::v1::config::StreamConfig,
            future_api_field: u64,
        }

        let left = api_snapshot(
            FutureStreamConfig {
                config: Default::default(),
                future_api_field: 1,
            },
            SnapshotKind::Stream,
        )
        .expect("future API config serializes");
        let right = api_snapshot(
            FutureStreamConfig {
                config: Default::default(),
                future_api_field: 2,
            },
            SnapshotKind::Stream,
        )
        .expect("future API config serializes");

        let diffs = field_diffs(&left, &right);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "future_api_field");
    }

    #[test]
    fn preserves_unknown_nested_fields_verbatim() {
        let expected = json!({
            "future_config": {
                "mode": null,
                "age": 42,
                "min_age": 7,
                "ops": ["z-op", "a-op"],
                "stream_cipher": null,
                "retention_policy": {"infinite": {}}
            }
        });
        let mut actual = expected.clone();

        canonicalize_value(&mut actual, SnapshotKind::Stream, "");

        assert_eq!(actual, expected);
    }

    #[test]
    fn preserves_enriched_retention_payload() {
        let expected = json!({
            "retention_policy": {
                "infinite": {
                    "future_api_field": true,
                    "mode": null,
                    "ops": ["z-op", "a-op"]
                }
            }
        });
        let mut actual = expected.clone();

        canonicalize_value(&mut actual, SnapshotKind::Stream, "");

        assert_eq!(actual, expected);
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
