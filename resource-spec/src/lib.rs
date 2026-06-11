//! Declarative basin/stream resource spec shared by CLI apply and lite init files.

use std::{borrow::Cow, time::Duration};

use s2_common::{
    encryption::EncryptionAlgorithm,
    types::{
        basin::BasinName,
        config::{
            BasinConfig, OptionalDeleteOnEmptyConfig, OptionalStreamConfig,
            OptionalTimestampingConfig, RetentionPolicy, StorageClass, TimestampingMode,
        },
        stream::StreamName,
    },
};
use serde::{Deserialize, Serialize};

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
    /// Encryption algorithm to apply to newly created streams in the basin.
    #[serde(default)]
    pub stream_cipher: Option<EncryptionAlgorithmSpec>,
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
    fn schema_name() -> Cow<'static, str> {
        "StorageClassSpec".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Storage class for recent writes.",
            "enum": ["standard", "express"]
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum EncryptionAlgorithmSpec {
    #[serde(rename = "aegis-256")]
    Aegis256,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl schemars::JsonSchema for EncryptionAlgorithmSpec {
    fn schema_name() -> Cow<'static, str> {
        "EncryptionAlgorithmSpec".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Encryption algorithm to apply to newly created streams in the basin.",
            "enum": ["aegis-256", "aes-256-gcm"]
        })
    }
}

impl From<EncryptionAlgorithmSpec> for EncryptionAlgorithm {
    fn from(m: EncryptionAlgorithmSpec) -> Self {
        match m {
            EncryptionAlgorithmSpec::Aegis256 => Self::Aegis256,
            EncryptionAlgorithmSpec::Aes256Gcm => Self::Aes256Gcm,
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
    fn schema_name() -> Cow<'static, str> {
        "RetentionPolicySpec".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Retain records unless explicitly trimmed (\"infinite\"), or automatically \
                trim records older than the given duration (e.g. \"7days\", \"1week\").",
            "examples": ["infinite", "7days", "1week"]
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
    fn schema_name() -> Cow<'static, str> {
        "TimestampingModeSpec".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Timestamping mode for appends that influences how timestamps are handled.",
            "enum": ["client-prefer", "client-require", "arrival"]
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
    fn schema_name() -> Cow<'static, str> {
        "HumanDuration".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "A duration string in humantime format, e.g. \"1day\", \"2h 30m\"",
            "examples": ["1day", "2h 30m"]
        })
    }
}

impl From<BasinConfigSpec> for BasinConfig {
    fn from(s: BasinConfigSpec) -> Self {
        BasinConfig {
            default_stream_config: s.default_stream_config.map(Into::into).unwrap_or_default(),
            stream_cipher: s.stream_cipher.map(Into::into),
            create_stream_on_append: s.create_stream_on_append.unwrap_or_default(),
            create_stream_on_read: s.create_stream_on_read.unwrap_or_default(),
        }
    }
}

impl From<TimestampingSpec> for OptionalTimestampingConfig {
    fn from(s: TimestampingSpec) -> Self {
        OptionalTimestampingConfig {
            mode: s.mode.map(Into::into),
            uncapped: s.uncapped,
        }
    }
}

impl From<DeleteOnEmptySpec> for OptionalDeleteOnEmptyConfig {
    fn from(s: DeleteOnEmptySpec) -> Self {
        OptionalDeleteOnEmptyConfig {
            min_age: s.min_age.map(|h| h.0),
        }
    }
}

impl From<StreamConfigSpec> for OptionalStreamConfig {
    fn from(s: StreamConfigSpec) -> Self {
        OptionalStreamConfig {
            storage_class: s.storage_class.map(Into::into),
            retention_policy: s.retention_policy.map(|rp| rp.0),
            timestamping: s.timestamping.map(Into::into).unwrap_or_default(),
            delete_on_empty: s.delete_on_empty.map(Into::into).unwrap_or_default(),
        }
    }
}

pub fn json_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(ResourcesSpec)).unwrap()
}

pub fn validate(spec: &ResourcesSpec) -> Result<(), String> {
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
        Err(errors.join("\n"))
    }
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
            stream_cipher: None,
            create_stream_on_append: Some(true),
            create_stream_on_read: None,
        };
        let config = BasinConfig::from(spec);
        assert!(config.create_stream_on_append);
        assert!(!config.create_stream_on_read);
        assert_eq!(
            config.default_stream_config,
            OptionalStreamConfig::default()
        );
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

        // using the default generated
        assert_eq!(
            schema_obj.get("$schema"),
            Some(&serde_json::Value::String(
                "https://json-schema.org/draft/2020-12/schema".to_string()
            ))
        );

        assert!(
            schema_obj.contains_key("properties"),
            "schema should have root properties"
        );

        assert!(
            schema_obj.contains_key("$defs"),
            "schema should have $defs for reusable definitions"
        );

        let properties = schema_obj.get("properties").unwrap().as_object().unwrap();
        assert!(
            properties.contains_key("basins"),
            "schema should include the `basins` property"
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
        let config = OptionalStreamConfig::from(spec);
        assert_eq!(config.storage_class, Some(StorageClass::Standard));
        assert_eq!(config.retention_policy, Some(RetentionPolicy::Infinite()));
        assert_eq!(config.timestamping, OptionalTimestampingConfig::default());
        assert_eq!(
            config.delete_on_empty,
            OptionalDeleteOnEmptyConfig::default()
        );
    }
}
