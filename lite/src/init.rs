//! Declarative basin/stream initialization from a JSON spec file.
//!
//! Loaded at startup when `--init-file` / `S2LITE_INIT_FILE` is set.

use std::{path::Path, time::Duration};

use s2_common::types::{
    basin::BasinName,
    config::{
        BasinConfig, OptionalDeleteOnEmptyConfig, OptionalStreamConfig, OptionalTimestampingConfig,
        RetentionPolicy, StorageClass, TimestampingMode,
    },
    resources::CreateMode,
    stream::StreamName,
};
use serde::Deserialize;
use tracing::info;

use crate::backend::{
    Backend,
    error::{CreateBasinError, CreateStreamError},
};

#[derive(Debug, Deserialize, Default)]
pub struct ResourcesSpec {
    #[serde(default)]
    pub basins: Vec<BasinSpec>,
}

#[derive(Debug, Deserialize)]
pub struct BasinSpec {
    pub name: String,
    #[serde(default)]
    pub config: Option<BasinConfigSpec>,
    #[serde(default)]
    pub streams: Vec<StreamSpec>,
}

#[derive(Debug, Deserialize)]
pub struct StreamSpec {
    pub name: String,
    #[serde(default)]
    pub config: Option<StreamConfigSpec>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BasinConfigSpec {
    #[serde(default)]
    pub default_stream_config: Option<StreamConfigSpec>,
    #[serde(default)]
    pub create_stream_on_append: Option<bool>,
    #[serde(default)]
    pub create_stream_on_read: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct StreamConfigSpec {
    #[serde(default)]
    pub storage_class: Option<StorageClassSpec>,
    #[serde(default)]
    pub retention_policy: Option<RetentionPolicySpec>,
    #[serde(default)]
    pub timestamping: Option<TimestampingSpec>,
    #[serde(default)]
    pub delete_on_empty: Option<DeleteOnEmptySpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageClassSpec {
    Standard,
    Express,
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

#[derive(Debug, Clone, Deserialize)]
pub struct TimestampingSpec {
    #[serde(default)]
    pub mode: Option<TimestampingModeSpec>,
    #[serde(default)]
    pub uncapped: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimestampingModeSpec {
    ClientPrefer,
    ClientRequire,
    Arrival,
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

#[derive(Debug, Clone, Deserialize)]
pub struct DeleteOnEmptySpec {
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

impl From<BasinConfigSpec> for BasinConfig {
    fn from(s: BasinConfigSpec) -> Self {
        BasinConfig {
            default_stream_config: s
                .default_stream_config
                .map(OptionalStreamConfig::from)
                .unwrap_or_default(),
            create_stream_on_append: s.create_stream_on_append.unwrap_or(false),
            create_stream_on_read: s.create_stream_on_read.unwrap_or(false),
        }
    }
}

impl From<StreamConfigSpec> for OptionalStreamConfig {
    fn from(s: StreamConfigSpec) -> Self {
        OptionalStreamConfig {
            storage_class: s.storage_class.map(StorageClass::from),
            retention_policy: s.retention_policy.map(|r| r.0),
            timestamping: s
                .timestamping
                .map(|t| OptionalTimestampingConfig {
                    mode: t.mode.map(TimestampingMode::from),
                    uncapped: t.uncapped,
                })
                .unwrap_or_default(),
            delete_on_empty: s
                .delete_on_empty
                .map(|d| OptionalDeleteOnEmptyConfig {
                    min_age: d.min_age.map(|h| h.0),
                })
                .unwrap_or_default(),
        }
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
    for basin_spec in spec.basins {
        let basin: BasinName = basin_spec
            .name
            .parse()
            .map_err(|e| eyre::eyre!("invalid basin name {:?}: {}", basin_spec.name, e))?;

        let mode = if basin_spec.config.is_some() {
            CreateMode::CreateOrReconfigure
        } else {
            CreateMode::CreateOnly(None)
        };
        let config = basin_spec.config.map(BasinConfig::from).unwrap_or_default();

        match backend.create_basin(basin.clone(), config, mode).await {
            Ok(_) => info!(basin = basin.as_ref(), "basin applied"),
            Err(CreateBasinError::BasinAlreadyExists(_)) => {
                info!(basin = basin.as_ref(), "basin already exists, skipping")
            }
            Err(e) => {
                return Err(eyre::eyre!(
                    "failed to create/reconfigure basin {:?}: {}",
                    basin,
                    e
                ));
            }
        }

        for stream_spec in basin_spec.streams {
            let stream: StreamName = stream_spec
                .name
                .parse()
                .map_err(|e| eyre::eyre!("invalid stream name {:?}: {}", stream_spec.name, e))?;

            let mode = if stream_spec.config.is_some() {
                CreateMode::CreateOrReconfigure
            } else {
                CreateMode::CreateOnly(None)
            };
            let config = stream_spec
                .config
                .map(OptionalStreamConfig::from)
                .unwrap_or_default();

            match backend
                .create_stream(basin.clone(), stream.clone(), config, mode)
                .await
            {
                Ok(_) => info!(
                    basin = basin.as_ref(),
                    stream = stream.as_ref(),
                    "stream applied"
                ),
                Err(CreateStreamError::StreamAlreadyExists(_)) => info!(
                    basin = basin.as_ref(),
                    stream = stream.as_ref(),
                    "stream already exists, skipping"
                ),
                Err(e) => {
                    return Err(eyre::eyre!(
                        "failed to create/reconfigure stream {:?}/{:?}: {}",
                        basin,
                        stream,
                        e
                    ));
                }
            }
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
        let config = BasinConfig::from(spec);
        assert!(config.create_stream_on_append);
        assert!(!config.create_stream_on_read);
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
        assert!(matches!(config.storage_class, Some(StorageClass::Standard)));
        assert!(matches!(
            config.retention_policy,
            Some(RetentionPolicy::Infinite())
        ));
    }
}
