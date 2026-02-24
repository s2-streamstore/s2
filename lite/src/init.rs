//! Declarative basin/stream initialization from a JSON spec file.
//!
//! Loaded at startup when `--init-file` / `S2LITE_INIT_FILE` is set.

use std::{path::Path, time::Duration};

use s2_common::{
    maybe::Maybe,
    types::{
        basin::BasinName,
        config::{
            BasinReconfiguration, DeleteOnEmptyReconfiguration, RetentionPolicy, StorageClass,
            StreamReconfiguration, TimestampingMode, TimestampingReconfiguration,
        },
        resources::CreateMode,
        stream::StreamName,
    },
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::backend::Backend;

#[derive(Debug, Deserialize, Default, schemars::JsonSchema)]
pub struct ResourcesSpec {
    #[serde(default)]
    pub basins: Vec<BasinSpec>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BasinSpec {
    pub name: String,
    #[serde(default)]
    pub config: Option<BasinConfigSpec>,
    #[serde(default)]
    pub streams: Vec<StreamSpec>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamSpec {
    pub name: String,
    #[serde(default)]
    pub config: Option<StreamConfigSpec>,
}

#[derive(Debug, Clone, Deserialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BasinConfigSpec {
    #[serde(default)]
    pub default_stream_config: Option<StreamConfigSpec>,
    /// Create stream on append if it doesn't exist, using the default stream configuration.
    #[serde(default)]
    pub create_stream_on_append: Option<bool>,
    /// Create stream on read if it doesn't exist, using the default stream configuration.
    #[serde(default)]
    pub create_stream_on_read: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamConfigSpec {
    /// Storage class for recent writes.
    #[serde(default)]
    pub storage_class: Option<StorageClassSpec>,
    /// Retention policy for the stream. If unspecified, the default is to retain records for 7
    /// days.
    #[serde(default)]
    pub retention_policy: Option<RetentionPolicySpec>,
    /// Timestamping behavior.
    #[serde(default)]
    pub timestamping: Option<TimestampingSpec>,
    /// Delete-on-empty configuration.
    #[serde(default)]
    pub delete_on_empty: Option<DeleteOnEmptySpec>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageClassSpec {
    Standard,
    Express,
}

impl schemars::JsonSchema for StorageClassSpec {
    fn schema_name() -> String {
        "StorageClassSpec".to_string()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some("Storage class for recent writes.".to_string()),
                ..Default::default()
            })),
            enum_values: Some(vec![
                serde_json::Value::String("standard".to_string()),
                serde_json::Value::String("express".to_string()),
            ]),
            ..Default::default()
        })
    }
}

impl From<StorageClassSpec> for StorageClass {
    fn from(s: StorageClassSpec) -> Self {
        match s {
            StorageClassSpec::Standard => StorageClass::Standard,
            StorageClassSpec::Express => StorageClass::Express,
        }
    }
}

/// Accepts `"infinite"` or a humantime duration string such as `"7d"`, `"1w"`.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicySpec(pub RetentionPolicy);

impl RetentionPolicySpec {
    pub fn age_secs(self) -> Option<u64> {
        self.0.age().map(|d| d.as_secs())
    }
}

impl TryFrom<String> for RetentionPolicySpec {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.eq_ignore_ascii_case("infinite") {
            return Ok(RetentionPolicySpec(RetentionPolicy::Infinite()));
        }
        let d = humantime::parse_duration(&s)
            .map_err(|e| format!("invalid retention_policy {:?}: {}", s, e))?;
        Ok(RetentionPolicySpec(RetentionPolicy::Age(d)))
    }
}

impl<'de> Deserialize<'de> for RetentionPolicySpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        RetentionPolicySpec::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl schemars::JsonSchema for RetentionPolicySpec {
    fn schema_name() -> String {
        "RetentionPolicySpec".to_string()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "Retain records unless explicitly trimmed (\"infinite\"), or automatically \
                     trim records older than the given duration (e.g. \"7days\", \"1week\")."
                        .to_string(),
                ),
                examples: vec![
                    serde_json::Value::String("infinite".to_string()),
                    serde_json::Value::String("7days".to_string()),
                    serde_json::Value::String("1week".to_string()),
                ],
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TimestampingSpec {
    /// Timestamping mode for appends that influences how timestamps are handled.
    #[serde(default)]
    pub mode: Option<TimestampingModeSpec>,
    /// Allow client-specified timestamps to exceed the arrival time.
    /// If this is `false` or not set, client timestamps will be capped at the arrival time.
    #[serde(default)]
    pub uncapped: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampingModeSpec {
    ClientPrefer,
    ClientRequire,
    Arrival,
}

impl schemars::JsonSchema for TimestampingModeSpec {
    fn schema_name() -> String {
        "TimestampingModeSpec".to_string()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "Timestamping mode for appends that influences how timestamps are handled."
                        .to_string(),
                ),
                ..Default::default()
            })),
            enum_values: Some(vec![
                serde_json::Value::String("client-prefer".to_string()),
                serde_json::Value::String("client-require".to_string()),
                serde_json::Value::String("arrival".to_string()),
            ]),
            ..Default::default()
        })
    }
}

impl From<TimestampingModeSpec> for TimestampingMode {
    fn from(m: TimestampingModeSpec) -> Self {
        match m {
            TimestampingModeSpec::ClientPrefer => TimestampingMode::ClientPrefer,
            TimestampingModeSpec::ClientRequire => TimestampingMode::ClientRequire,
            TimestampingModeSpec::Arrival => TimestampingMode::Arrival,
        }
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteOnEmptySpec {
    /// Minimum age before an empty stream can be deleted.
    /// Set to 0 (default) to disable delete-on-empty (don't delete automatically).
    #[serde(default)]
    pub min_age: Option<HumanDuration>,
}

/// A `std::time::Duration` deserialized from a humantime string (e.g. `"1d"`, `"2h 30m"`).
#[derive(Debug, Clone, Copy)]
pub struct HumanDuration(pub Duration);

impl TryFrom<String> for HumanDuration {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        humantime::parse_duration(&s)
            .map(HumanDuration)
            .map_err(|e| format!("invalid duration {:?}: {}", s, e))
    }
}

impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        HumanDuration::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl schemars::JsonSchema for HumanDuration {
    fn schema_name() -> String {
        "HumanDuration".to_string()
    }

    fn json_schema(_: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::Schema::Object(schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "A duration string in humantime format, e.g. \"1day\", \"2h 30m\"".to_string(),
                ),
                examples: vec![
                    serde_json::Value::String("1day".to_string()),
                    serde_json::Value::String("2h 30m".to_string()),
                ],
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

impl From<BasinConfigSpec> for BasinReconfiguration {
    fn from(s: BasinConfigSpec) -> Self {
        BasinReconfiguration {
            default_stream_config: s
                .default_stream_config
                .map(|dsc| Some(StreamReconfiguration::from(dsc)))
                .map_or(Maybe::Unspecified, Maybe::Specified),
            create_stream_on_append: s
                .create_stream_on_append
                .map_or(Maybe::Unspecified, Maybe::Specified),
            create_stream_on_read: s
                .create_stream_on_read
                .map_or(Maybe::Unspecified, Maybe::Specified),
        }
    }
}

impl From<StreamConfigSpec> for StreamReconfiguration {
    fn from(s: StreamConfigSpec) -> Self {
        StreamReconfiguration {
            storage_class: s
                .storage_class
                .map(|sc| Some(StorageClass::from(sc)))
                .map_or(Maybe::Unspecified, Maybe::Specified),
            retention_policy: s
                .retention_policy
                .map(|rp| Some(rp.0))
                .map_or(Maybe::Unspecified, Maybe::Specified),
            timestamping: s
                .timestamping
                .map(|ts| {
                    Some(TimestampingReconfiguration {
                        mode: ts
                            .mode
                            .map(|m| Some(TimestampingMode::from(m)))
                            .map_or(Maybe::Unspecified, Maybe::Specified),
                        uncapped: ts
                            .uncapped
                            .map(Some)
                            .map_or(Maybe::Unspecified, Maybe::Specified),
                    })
                })
                .map_or(Maybe::Unspecified, Maybe::Specified),
            delete_on_empty: s
                .delete_on_empty
                .map(|doe| {
                    Some(DeleteOnEmptyReconfiguration {
                        min_age: doe
                            .min_age
                            .map(|h| Some(h.0))
                            .map_or(Maybe::Unspecified, Maybe::Specified),
                    })
                })
                .map_or(Maybe::Unspecified, Maybe::Specified),
        }
    }
}

pub fn json_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ResourcesSpec)).unwrap()
}

pub fn validate(spec: &ResourcesSpec) -> eyre::Result<()> {
    let mut errors = Vec::new();
    let mut seen_basins = std::collections::HashSet::new();

    for basin_spec in &spec.basins {
        if !seen_basins.insert(basin_spec.name.clone()) {
            errors.push(format!("duplicate basin name {:?}", basin_spec.name));
        }

        if let Err(e) = basin_spec.name.parse::<BasinName>() {
            errors.push(format!("invalid basin name {:?}: {}", basin_spec.name, e));
            continue;
        }

        let mut seen_streams = std::collections::HashSet::new();
        for stream_spec in &basin_spec.streams {
            if !seen_streams.insert(stream_spec.name.clone()) {
                errors.push(format!(
                    "duplicate stream name {:?} in basin {:?}",
                    stream_spec.name, basin_spec.name
                ));
            }
            if let Err(e) = stream_spec.name.parse::<StreamName>() {
                errors.push(format!(
                    "invalid stream name {:?} in basin {:?}: {}",
                    stream_spec.name, basin_spec.name, e
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(eyre::eyre!("{}", errors.join("\n")))
    }
}

pub fn load(path: &Path) -> eyre::Result<ResourcesSpec> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("failed to read init file {:?}: {}", path, e))?;
    let spec: ResourcesSpec = serde_json::from_str(&contents)
        .map_err(|e| eyre::eyre!("failed to parse init file {:?}: {}", path, e))?;
    Ok(spec)
}

pub async fn apply(backend: &Backend, spec: ResourcesSpec) -> eyre::Result<()> {
    validate(&spec)?;

    for basin_spec in spec.basins {
        let basin: BasinName = basin_spec
            .name
            .parse()
            .map_err(|e| eyre::eyre!("invalid basin name {:?}: {}", basin_spec.name, e))?;

        let reconfiguration = basin_spec
            .config
            .map(BasinReconfiguration::from)
            .unwrap_or_default();

        backend
            .create_basin(
                basin.clone(),
                reconfiguration,
                CreateMode::CreateOrReconfigure,
            )
            .await
            .map_err(|e| eyre::eyre!("failed to apply basin {:?}: {}", basin.as_ref(), e))?;

        info!(basin = basin.as_ref(), "basin applied");

        for stream_spec in basin_spec.streams {
            let stream: StreamName = stream_spec
                .name
                .parse()
                .map_err(|e| eyre::eyre!("invalid stream name {:?}: {}", stream_spec.name, e))?;

            let reconfiguration = stream_spec
                .config
                .map(StreamReconfiguration::from)
                .unwrap_or_default();

            backend
                .create_stream(
                    basin.clone(),
                    stream.clone(),
                    reconfiguration,
                    CreateMode::CreateOrReconfigure,
                )
                .await
                .map_err(|e| {
                    eyre::eyre!(
                        "failed to apply stream {:?}/{:?}: {}",
                        basin.as_ref(),
                        stream.as_ref(),
                        e
                    )
                })?;

            info!(
                basin = basin.as_ref(),
                stream = stream.as_ref(),
                "stream applied"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_spec(json: &str) -> ResourcesSpec {
        serde_json::from_str(json).expect("valid JSON")
    }

    #[test]
    fn empty_spec() {
        let spec = parse_spec("{}");
        assert!(spec.basins.is_empty());
    }

    #[test]
    fn basin_no_config() {
        let spec = parse_spec(r#"{"basins":[{"name":"my-basin"}]}"#);
        assert_eq!(spec.basins.len(), 1);
        assert_eq!(spec.basins[0].name, "my-basin");
        assert!(spec.basins[0].config.is_none());
        assert!(spec.basins[0].streams.is_empty());
    }

    #[test]
    fn retention_policy_infinite() {
        let rp: RetentionPolicySpec = serde_json::from_str(r#""infinite""#).expect("deserialize");
        assert!(matches!(rp.0, RetentionPolicy::Infinite()));
    }

    #[test]
    fn retention_policy_duration() {
        let rp: RetentionPolicySpec = serde_json::from_str(r#""7days""#).expect("deserialize");
        assert!(matches!(rp.0, RetentionPolicy::Age(_)));
        if let RetentionPolicy::Age(d) = rp.0 {
            assert_eq!(d, Duration::from_secs(7 * 24 * 3600));
        }
    }

    #[test]
    fn retention_policy_invalid() {
        let err = serde_json::from_str::<RetentionPolicySpec>(r#""not-a-duration""#);
        assert!(err.is_err());
    }

    #[test]
    fn human_duration() {
        let hd: HumanDuration = serde_json::from_str(r#""1day""#).expect("deserialize");
        assert_eq!(hd.0, Duration::from_secs(86400));
    }

    #[test]
    fn full_spec_roundtrip() {
        let json = r#"
        {
          "basins": [
            {
              "name": "my-basin",
              "config": {
                "create_stream_on_append": true,
                "create_stream_on_read": false,
                "default_stream_config": {
                  "storage_class": "express",
                  "retention_policy": "7days",
                  "timestamping": {
                    "mode": "client-prefer",
                    "uncapped": false
                  },
                  "delete_on_empty": {
                    "min_age": "1day"
                  }
                }
              },
              "streams": [
                {
                  "name": "events",
                  "config": {
                    "storage_class": "standard",
                    "retention_policy": "infinite"
                  }
                }
              ]
            }
          ]
        }"#;

        let spec = parse_spec(json);
        assert_eq!(spec.basins.len(), 1);
        let basin = &spec.basins[0];
        assert_eq!(basin.name, "my-basin");

        let config = basin.config.as_ref().unwrap();
        assert_eq!(config.create_stream_on_append, Some(true));
        assert_eq!(config.create_stream_on_read, Some(false));

        let dsc = config.default_stream_config.as_ref().unwrap();
        assert!(matches!(dsc.storage_class, Some(StorageClassSpec::Express)));
        assert!(matches!(
            dsc.retention_policy.as_ref().map(|r| &r.0),
            Some(RetentionPolicy::Age(_))
        ));

        let ts = dsc.timestamping.as_ref().unwrap();
        assert!(matches!(ts.mode, Some(TimestampingModeSpec::ClientPrefer)));
        assert_eq!(ts.uncapped, Some(false));

        let doe = dsc.delete_on_empty.as_ref().unwrap();
        assert_eq!(
            doe.min_age.as_ref().map(|h| h.0),
            Some(Duration::from_secs(86400))
        );

        assert_eq!(basin.streams.len(), 1);
        let stream = &basin.streams[0];
        assert_eq!(stream.name, "events");
        let sc = stream.config.as_ref().unwrap();
        assert!(matches!(sc.storage_class, Some(StorageClassSpec::Standard)));
        assert!(matches!(
            sc.retention_policy.as_ref().map(|r| &r.0),
            Some(RetentionPolicy::Infinite())
        ));
    }

    #[test]
    fn basin_config_conversion() {
        let spec = BasinConfigSpec {
            default_stream_config: None,
            create_stream_on_append: Some(true),
            create_stream_on_read: None,
        };
        let reconfig = BasinReconfiguration::from(spec);
        assert!(matches!(
            reconfig.create_stream_on_append,
            Maybe::Specified(true)
        ));
        assert!(matches!(reconfig.create_stream_on_read, Maybe::Unspecified));
        assert!(matches!(reconfig.default_stream_config, Maybe::Unspecified));
    }

    #[test]
    fn validate_valid_spec() {
        let spec = parse_spec(
            r#"{"basins":[{"name":"my-basin","streams":[{"name":"events"},{"name":"logs"}]}]}"#,
        );
        assert!(validate(&spec).is_ok());
    }

    #[test]
    fn validate_invalid_basin_name() {
        let spec = parse_spec(r#"{"basins":[{"name":"INVALID_BASIN"}]}"#);
        let err = validate(&spec).unwrap_err();
        assert!(err.to_string().contains("invalid basin name"));
    }

    #[test]
    fn validate_invalid_stream_name() {
        let spec = parse_spec(r#"{"basins":[{"name":"my-basin","streams":[{"name":""}]}]}"#);
        let err = validate(&spec).unwrap_err();
        assert!(err.to_string().contains("invalid stream name"));
    }

    #[test]
    fn validate_duplicate_basin_names() {
        let spec = parse_spec(r#"{"basins":[{"name":"my-basin"},{"name":"my-basin"}]}"#);
        let err = validate(&spec).unwrap_err();
        assert!(err.to_string().contains("duplicate basin name"));
    }

    #[test]
    fn validate_duplicate_stream_names() {
        let spec = parse_spec(
            r#"{"basins":[{"name":"my-basin","streams":[{"name":"events"},{"name":"events"}]}]}"#,
        );
        let err = validate(&spec).unwrap_err();
        assert!(err.to_string().contains("duplicate stream name"));
    }

    #[test]
    fn validate_multiple_errors() {
        let spec = parse_spec(r#"{"basins":[{"name":"INVALID"},{"name":"INVALID"}]}"#);
        let err = validate(&spec).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid basin name"));
        assert!(msg.contains("duplicate basin name"));
    }

    #[test]
    fn json_schema_is_valid() {
        let schema = json_schema();
        assert!(schema.is_object());
        let schema_obj = schema.as_object().unwrap();
        // Should have at minimum a definitions/properties structure
        assert!(
            schema_obj.contains_key("definitions") || schema_obj.contains_key("properties"),
            "schema should have definitions or properties"
        );
    }

    #[test]
    fn stream_config_conversion() {
        let spec = StreamConfigSpec {
            storage_class: Some(StorageClassSpec::Standard),
            retention_policy: Some(RetentionPolicySpec(RetentionPolicy::Infinite())),
            timestamping: None,
            delete_on_empty: None,
        };
        let reconfig = StreamReconfiguration::from(spec);
        assert!(matches!(
            reconfig.storage_class,
            Maybe::Specified(Some(StorageClass::Standard))
        ));
        assert!(matches!(
            reconfig.retention_policy,
            Maybe::Specified(Some(RetentionPolicy::Infinite()))
        ));
        assert!(matches!(reconfig.timestamping, Maybe::Unspecified));
        assert!(matches!(reconfig.delete_on_empty, Maybe::Unspecified));
    }
}
