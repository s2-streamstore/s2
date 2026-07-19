use colored::Colorize;
use s2_sdk::types::AccessTokenId;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::{
    cli::{DiffArgs, DiffOutput, DiffResourceKind},
    error::CliError,
    ops,
    types::{
        AccessTokenInfo, BasinConfig, DiffResource, S2BasinAndStreamUri, S2BasinUri, StreamConfig,
    },
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

    let (mut left_value, mut right_value) = match (left, right) {
        (DiffResource::Basin(left), DiffResource::Basin(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_basin_config(s2, &left),
                ops::get_basin_config(s2, &right),
            )?;

            (
                serde_json::to_value(BasinConfig::from(left_config))?,
                serde_json::to_value(BasinConfig::from(right_config))?,
            )
        }
        (DiffResource::Stream(left), DiffResource::Stream(right)) => {
            let (left_config, right_config) = tokio::try_join!(
                ops::get_stream_config(s2, left),
                ops::get_stream_config(s2, right),
            )?;

            (
                serde_json::to_value(StreamConfig::from(left_config))?,
                serde_json::to_value(StreamConfig::from(right_config))?,
            )
        }
        (DiffResource::Basin(basin), DiffResource::Stream(stream)) => {
            let (basin_config, stream_config) = tokio::try_join!(
                ops::get_basin_config(s2, &basin),
                ops::get_stream_config(s2, stream),
            )?;

            (
                serde_json::to_value(BasinConfig::from(basin_config).default_stream_config)?,
                serde_json::to_value(StreamConfig::from(stream_config))?,
            )
        }
        (DiffResource::Stream(stream), DiffResource::Basin(basin)) => {
            let (stream_config, basin_config) = tokio::try_join!(
                ops::get_stream_config(s2, stream),
                ops::get_basin_config(s2, &basin),
            )?;

            (
                serde_json::to_value(StreamConfig::from(stream_config))?,
                serde_json::to_value(BasinConfig::from(basin_config).default_stream_config)?,
            )
        }
        (DiffResource::AccessToken(left), DiffResource::AccessToken(right)) => {
            let (left_info, right_info) = tokio::try_join!(
                ops::get_access_token(s2, left),
                ops::get_access_token(s2, right),
            )?;

            let mut left = serde_json::to_value(AccessTokenInfo::from(left_info))?;
            let mut right = serde_json::to_value(AccessTokenInfo::from(right_info))?;
            remove_identity(&mut left);
            remove_identity(&mut right);
            (left, right)
        }
        _ => unreachable!("diff arguments are resolved to matching resource types"),
    };

    canonicalize_value(&mut left_value, None);
    canonicalize_value(&mut right_value, None);
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

fn canonicalize_value(value: &mut Value, field: Option<&str>) {
    if let Some(field) = field {
        if normalize_default_value(value, field) {
            return;
        }
        if field == "retention_policy"
            && let Some(retention_policy) = canonical_retention_policy(value)
        {
            *value = Value::String(retention_policy);
            return;
        }
    }

    match value {
        Value::Object(object) => {
            let entries = std::mem::take(object);
            for (key, mut value) in entries {
                let key = canonical_field_name(&key);
                canonicalize_value(&mut value, Some(key));
                object.insert(key.to_owned(), value);
            }
        }
        Value::Array(values) => {
            for value in values {
                canonicalize_value(value, None);
            }
        }
        Value::String(value) => {
            if value == "Infinite" {
                *value = "infinite".to_owned();
            } else if matches!(field, Some("age" | "min_age")) {
                *value = compact_duration(value);
            }
        }
        _ => {}
    }
}

fn normalize_default_value(value: &mut Value, field: &str) -> bool {
    if !value.is_null() {
        return false;
    }

    *value = match field {
        "storage_class" => Value::String("express".to_owned()),
        "retention_policy" => Value::String("7d".to_owned()),
        "timestamping" => serde_json::json!({
            "mode": "client-prefer",
            "uncapped": false,
        }),
        "mode" => Value::String("client-prefer".to_owned()),
        "uncapped" => Value::Bool(false),
        "delete_on_empty" => serde_json::json!({"min_age": "0s"}),
        "min_age" => Value::String("0s".to_owned()),
        "stream_cipher" => Value::String("none".to_owned()),
        _ => return false,
    };
    true
}

fn canonical_retention_policy(value: &Value) -> Option<String> {
    match value {
        Value::String(value) if value.eq_ignore_ascii_case("infinite") => {
            Some("infinite".to_owned())
        }
        Value::Object(object) => object
            .get("Age")
            .or_else(|| object.get("age"))
            .and_then(Value::as_str)
            .map(compact_duration),
        _ => None,
    }
}

fn canonical_field_name(field: &str) -> &str {
    match field {
        "timestamping_mode" => "mode",
        "timestamping_uncapped" => "uncapped",
        "delete_on_empty_min_age" => "min_age",
        _ => field,
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
        DiffComparison, canonicalize_value, field_diffs, format_value_lines, resolve_args,
        resource_kind,
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
            "retention_policy": {"Age": "2days"},
            "timestamping": {"timestamping_mode": "client-prefer"},
            "delete_on_empty": {"delete_on_empty_min_age": "10m"}
        });
        let mut right = json!({
            "retention_policy": {"Age": "30days"},
            "timestamping": {"timestamping_mode": "arrival"},
            "delete_on_empty": {"delete_on_empty_min_age": "1hour"}
        });

        canonicalize_value(&mut left, None);
        canonicalize_value(&mut right, None);
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
            "default_stream_config": {"retention_policy": "Infinite"}
        });
        let mut right = json!({
            "default_stream_config": {"retention_policy": {"Age": "7days"}}
        });

        canonicalize_value(&mut left, None);
        canonicalize_value(&mut right, None);
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
                "retention_policy": {"Age": "7days"},
                "timestamping": {
                    "timestamping_mode": "arrival",
                    "timestamping_uncapped": null
                },
                "delete_on_empty": null
            }
        });

        canonicalize_value(&mut left, None);
        canonicalize_value(&mut right, None);
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
