//! Declarative basin/stream resource spec shared by CLI apply and lite init files.

use std::{borrow::Cow, time::Duration};

use s2_common::{basin::BasinName, stream::StreamName};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Default, schemars::JsonSchema)]
pub struct Resources {
    #[serde(default)]
    pub basins: Vec<Basin>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Basin {
    #[schemars(with = "String")]
    pub name: BasinName,
    #[serde(default)]
    pub config: Option<BasinConfig>,
    #[serde(default)]
    pub streams: Vec<Stream>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    #[schemars(with = "String")]
    pub name: StreamName,
    #[serde(default)]
    pub config: Option<StreamConfig>,
}

#[derive(Debug, Clone, Deserialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BasinConfig {
    #[serde(default)]
    pub default_stream_config: Option<StreamConfig>,
    /// Encryption algorithm to apply to newly created streams in the basin.
    #[serde(default)]
    pub stream_cipher: Option<EncryptionAlgorithm>,
    /// Create stream on append if it doesn't exist, using the default stream configuration.
    #[serde(default)]
    pub create_stream_on_append: Option<bool>,
    /// Create stream on read if it doesn't exist, using the default stream configuration.
    #[serde(default)]
    pub create_stream_on_read: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    /// Storage class for recent writes.
    #[serde(default)]
    pub storage_class: Option<StorageClass>,
    /// Retention policy for the stream. If unspecified, the default is to retain records for 7
    /// days.
    #[serde(default)]
    pub retention_policy: Option<RetentionPolicy>,
    /// Timestamping behavior.
    #[serde(default)]
    pub timestamping: Option<Timestamping>,
    /// Delete-on-empty configuration.
    #[serde(default)]
    pub delete_on_empty: Option<DeleteOnEmpty>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageClass {
    Standard,
    Express,
}

impl schemars::JsonSchema for StorageClass {
    fn schema_name() -> Cow<'static, str> {
        "StorageClass".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Storage class for recent writes.",
            "enum": ["standard", "express"]
        })
    }
}

impl From<StorageClass> for s2_common::config::StorageClass {
    fn from(s: StorageClass) -> Self {
        match s {
            StorageClass::Standard => Self::Standard,
            StorageClass::Express => Self::Express,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum EncryptionAlgorithm {
    #[serde(rename = "aegis-256")]
    Aegis256,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
}

impl schemars::JsonSchema for EncryptionAlgorithm {
    fn schema_name() -> Cow<'static, str> {
        "EncryptionAlgorithm".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Encryption algorithm to apply to newly created streams in the basin.",
            "enum": ["aegis-256", "aes-256-gcm"]
        })
    }
}

impl From<EncryptionAlgorithm> for s2_common::encryption::EncryptionAlgorithm {
    fn from(m: EncryptionAlgorithm) -> Self {
        match m {
            EncryptionAlgorithm::Aegis256 => Self::Aegis256,
            EncryptionAlgorithm::Aes256Gcm => Self::Aes256Gcm,
        }
    }
}

/// Accepts `"infinite"` or a humantime duration string such as `"7d"`, `"1w"`.
#[derive(Debug, Clone, Copy)]
pub struct RetentionPolicy(pub s2_common::config::RetentionPolicy);

impl RetentionPolicy {
    pub fn age_secs(self) -> Option<u64> {
        self.0.age().map(|d| d.as_secs())
    }
}

impl TryFrom<String> for RetentionPolicy {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        if s.eq_ignore_ascii_case("infinite") {
            return Ok(RetentionPolicy(
                s2_common::config::RetentionPolicy::Infinite(),
            ));
        }
        let d = humantime::parse_duration(&s)
            .map_err(|e| format!("invalid retention_policy {:?}: {}", s, e))?;
        Ok(RetentionPolicy(s2_common::config::RetentionPolicy::Age(d)))
    }
}

impl<'de> Deserialize<'de> for RetentionPolicy {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        RetentionPolicy::try_from(s).map_err(serde::de::Error::custom)
    }
}

impl schemars::JsonSchema for RetentionPolicy {
    fn schema_name() -> Cow<'static, str> {
        "RetentionPolicy".into()
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
pub struct Timestamping {
    /// Timestamping mode for appends that influences how timestamps are handled.
    #[serde(default)]
    pub mode: Option<TimestampingMode>,
    /// Allow client-specified timestamps to exceed the arrival time.
    /// If this is `false` or not set, client timestamps will be capped at the arrival time.
    #[serde(default)]
    pub uncapped: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampingMode {
    ClientPrefer,
    ClientRequire,
    Arrival,
}

impl schemars::JsonSchema for TimestampingMode {
    fn schema_name() -> Cow<'static, str> {
        "TimestampingMode".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "Timestamping mode for appends that influences how timestamps are handled.",
            "enum": ["client-prefer", "client-require", "arrival"]
        })
    }
}

impl From<TimestampingMode> for s2_common::config::TimestampingMode {
    fn from(m: TimestampingMode) -> Self {
        match m {
            TimestampingMode::ClientPrefer => Self::ClientPrefer,
            TimestampingMode::ClientRequire => Self::ClientRequire,
            TimestampingMode::Arrival => Self::Arrival,
        }
    }
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteOnEmpty {
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

impl From<BasinConfig> for s2_common::config::BasinConfig {
    fn from(s: BasinConfig) -> Self {
        Self {
            default_stream_config: s.default_stream_config.map(Into::into).unwrap_or_default(),
            stream_cipher: s.stream_cipher.map(Into::into),
            create_stream_on_append: s.create_stream_on_append.unwrap_or_default(),
            create_stream_on_read: s.create_stream_on_read.unwrap_or_default(),
        }
    }
}

impl From<Timestamping> for s2_common::config::OptionalTimestampingConfig {
    fn from(s: Timestamping) -> Self {
        Self {
            mode: s.mode.map(Into::into),
            uncapped: s.uncapped,
        }
    }
}

impl From<DeleteOnEmpty> for s2_common::config::OptionalDeleteOnEmptyConfig {
    fn from(s: DeleteOnEmpty) -> Self {
        Self {
            min_age: s.min_age.map(|h| h.0),
        }
    }
}

impl From<StreamConfig> for s2_common::config::OptionalStreamConfig {
    fn from(s: StreamConfig) -> Self {
        Self {
            storage_class: s.storage_class.map(Into::into),
            retention_policy: s.retention_policy.map(|rp| rp.0),
            timestamping: s.timestamping.map(Into::into).unwrap_or_default(),
            delete_on_empty: s.delete_on_empty.map(Into::into).unwrap_or_default(),
        }
    }
}

pub fn json_schema() -> serde_json::Value {
    serde_json::to_value(schemars::schema_for!(Resources)).unwrap()
}

pub fn validate(spec: &Resources) -> Result<(), String> {
    let mut errors = Vec::new();
    let mut seen_basins = std::collections::HashSet::new();

    for basin_spec in &spec.basins {
        if !seen_basins.insert(basin_spec.name.clone()) {
            errors.push(format!("duplicate basin name {:?}", basin_spec.name));
        }

        let mut seen_streams = std::collections::HashSet::new();
        for stream_spec in &basin_spec.streams {
            if !seen_streams.insert(stream_spec.name.clone()) {
                errors.push(format!(
                    "duplicate stream name {:?} in basin {:?}",
                    stream_spec.name, basin_spec.name
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

    fn parse_spec(json: &str) -> Resources {
        serde_json::from_str(json).expect("valid JSON")
    }

    fn parse_spec_err(json: &str) -> serde_json::Error {
        serde_json::from_str::<Resources>(json).expect_err("invalid resource spec")
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
        assert_eq!(spec.basins[0].name.as_ref(), "my-basin");
        assert!(spec.basins[0].config.is_none());
        assert!(spec.basins[0].streams.is_empty());
    }

    #[test]
    fn retention_policy_infinite() {
        let rp: RetentionPolicy = serde_json::from_str(r#""infinite""#).expect("deserialize");
        assert!(matches!(
            rp.0,
            s2_common::config::RetentionPolicy::Infinite()
        ));
    }

    #[test]
    fn retention_policy_duration() {
        let rp: RetentionPolicy = serde_json::from_str(r#""7days""#).expect("deserialize");
        assert!(matches!(rp.0, s2_common::config::RetentionPolicy::Age(_)));
        if let s2_common::config::RetentionPolicy::Age(d) = rp.0 {
            assert_eq!(d, Duration::from_secs(7 * 24 * 3600));
        }
    }

    #[test]
    fn retention_policy_invalid() {
        let err = serde_json::from_str::<RetentionPolicy>(r#""not-a-duration""#);
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
        assert_eq!(basin.name.as_ref(), "my-basin");

        let config = basin.config.as_ref().unwrap();
        assert_eq!(config.create_stream_on_append, Some(true));
        assert_eq!(config.create_stream_on_read, Some(false));

        let dsc = config.default_stream_config.as_ref().unwrap();
        assert!(matches!(dsc.storage_class, Some(StorageClass::Express)));
        assert!(matches!(
            dsc.retention_policy.as_ref().map(|r| &r.0),
            Some(s2_common::config::RetentionPolicy::Age(_))
        ));

        let ts = dsc.timestamping.as_ref().unwrap();
        assert!(matches!(ts.mode, Some(TimestampingMode::ClientPrefer)));
        assert_eq!(ts.uncapped, Some(false));

        let doe = dsc.delete_on_empty.as_ref().unwrap();
        assert_eq!(
            doe.min_age.as_ref().map(|h| h.0),
            Some(Duration::from_secs(86400))
        );

        assert_eq!(basin.streams.len(), 1);
        let stream = &basin.streams[0];
        assert_eq!(stream.name.as_ref(), "events");
        let sc = stream.config.as_ref().unwrap();
        assert!(matches!(sc.storage_class, Some(StorageClass::Standard)));
        assert!(matches!(
            sc.retention_policy.as_ref().map(|r| &r.0),
            Some(s2_common::config::RetentionPolicy::Infinite())
        ));
    }

    #[test]
    fn basin_config_conversion() {
        let spec = BasinConfig {
            default_stream_config: None,
            stream_cipher: None,
            create_stream_on_append: Some(true),
            create_stream_on_read: None,
        };
        let config = s2_common::config::BasinConfig::from(spec);
        assert!(config.create_stream_on_append);
        assert!(!config.create_stream_on_read);
        assert_eq!(
            config.default_stream_config,
            s2_common::config::OptionalStreamConfig::default()
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
    fn deserialize_invalid_basin_name() {
        let err = parse_spec_err(r#"{"basins":[{"name":"INVALID_BASIN"}]}"#);
        assert!(err.to_string().contains("basin name"));
    }

    #[test]
    fn deserialize_invalid_stream_name() {
        let err = parse_spec_err(r#"{"basins":[{"name":"my-basin","streams":[{"name":""}]}]}"#);
        assert!(err.to_string().contains("stream name"));
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
        let spec = parse_spec(
            r#"{"basins":[{"name":"my-basin","streams":[{"name":"events"},{"name":"events"}]},{"name":"my-basin"}]}"#,
        );
        let err = validate(&spec).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("duplicate basin name"));
        assert!(msg.contains("duplicate stream name"));
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
        let spec = StreamConfig {
            storage_class: Some(StorageClass::Standard),
            retention_policy: Some(RetentionPolicy(
                s2_common::config::RetentionPolicy::Infinite(),
            )),
            timestamping: None,
            delete_on_empty: None,
        };
        let config = s2_common::config::OptionalStreamConfig::from(spec);
        assert_eq!(
            config.storage_class,
            Some(s2_common::config::StorageClass::Standard)
        );
        assert_eq!(
            config.retention_policy,
            Some(s2_common::config::RetentionPolicy::Infinite())
        );
        assert_eq!(
            config.timestamping,
            s2_common::config::OptionalTimestampingConfig::default()
        );
        assert_eq!(
            config.delete_on_empty,
            s2_common::config::OptionalDeleteOnEmptyConfig::default()
        );
    }
}
