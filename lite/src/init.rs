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
use serde::Deserialize;
use tracing::info;

use crate::backend::Backend;

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
