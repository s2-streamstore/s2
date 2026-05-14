//! Declarative basin/stream configuration via a JSON spec file.

use std::path::Path;

use colored::Colorize;
use s2_common::{
    encryption::EncryptionAlgorithm,
    types::{
        basin::BasinName,
        config::{
            BasinConfig, OptionalStreamConfig, RetentionPolicy, StorageClass, StreamConfig,
            TimestampingMode,
        },
        stream::StreamName,
    },
};
use s2_lite::init::{BasinConfigSpec, ResourcesSpec, StreamConfigSpec};

fn basin_config_from_sdk(config: s2_sdk::types::BasinConfig) -> miette::Result<BasinConfig> {
    let config: s2_api::v1::config::BasinConfig = config.into();
    config
        .try_into()
        .map_err(|e| miette::miette!("invalid basin config returned by server: {}", e))
}

fn stream_config_from_sdk(config: s2_sdk::types::StreamConfig) -> miette::Result<StreamConfig> {
    let config: s2_api::v1::config::StreamConfig = config.into();
    let config: OptionalStreamConfig = config
        .try_into()
        .map_err(|e| miette::miette!("invalid stream config returned by server: {}", e))?;
    Ok(config.into())
}

fn format_encryption_algorithm(algorithm: EncryptionAlgorithm) -> &'static str {
    match algorithm {
        EncryptionAlgorithm::Aegis256 => "aegis-256",
        EncryptionAlgorithm::Aes256Gcm => "aes-256-gcm",
    }
}

pub fn validate(spec: &ResourcesSpec) -> miette::Result<()> {
    s2_lite::init::validate(spec).map_err(|e| miette::miette!("{}", e))
}

pub fn load(path: &Path) -> miette::Result<ResourcesSpec> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read spec file {:?}: {}", path.display(), e))?;
    let spec: ResourcesSpec = serde_json::from_str(&contents)
        .map_err(|e| miette::miette!("failed to parse spec file {:?}: {}", path.display(), e))?;
    Ok(spec)
}

pub async fn apply(s2: &s2_sdk::S2, spec: ResourcesSpec) -> miette::Result<()> {
    validate(&spec)?;

    for basin_spec in spec.basins {
        let basin: BasinName = basin_spec
            .name
            .parse()
            .map_err(|e| miette::miette!("invalid basin name {:?}: {}", basin_spec.name, e))?;

        apply_basin(s2, basin.clone(), basin_spec.config).await?;

        for stream_spec in basin_spec.streams {
            let stream: StreamName = stream_spec.name.parse().map_err(|e| {
                miette::miette!("invalid stream name {:?}: {}", stream_spec.name, e)
            })?;
            apply_stream(s2, basin.clone(), stream, stream_spec.config).await?;
        }
    }
    Ok(())
}

async fn apply_basin(
    s2: &s2_sdk::S2,
    basin: BasinName,
    config: Option<BasinConfigSpec>,
) -> miette::Result<()> {
    let mut input = s2_sdk::types::EnsureBasinInput::new(basin.clone());
    if let Some(c) = config {
        input = input.with_config(BasinConfig::from(c));
    }
    match s2
        .ensure_basin(input)
        .await
        .map_err(|e| miette::miette!("failed to apply basin {:?}: {}", basin.as_ref(), e))?
    {
        s2_sdk::types::ProvisionResult::Created(_) => {
            eprintln!("{}", format!("  basin {basin}").green().bold());
        }
        s2_sdk::types::ProvisionResult::Updated(_) => {
            eprintln!("{}", format!("  basin {basin} (updated)").yellow().bold());
        }
    }
    Ok(())
}

async fn apply_stream(
    s2: &s2_sdk::S2,
    basin: BasinName,
    stream: StreamName,
    config: Option<StreamConfigSpec>,
) -> miette::Result<()> {
    let mut input = s2_sdk::types::EnsureStreamInput::new(stream.clone());
    if let Some(c) = config {
        input = input.with_config(OptionalStreamConfig::from(c));
    }
    let basin_client = s2.basin(basin.clone());
    match basin_client.ensure_stream(input).await.map_err(|e| {
        miette::miette!(
            "failed to apply stream {:?}/{:?}: {}",
            basin.as_ref(),
            stream.as_ref(),
            e
        )
    })? {
        s2_sdk::types::ProvisionResult::Created(_) => {
            eprintln!("{}", format!("  stream {basin}/{stream}").green().bold());
        }
        s2_sdk::types::ProvisionResult::Updated(_) => {
            eprintln!(
                "{}",
                format!("  stream {basin}/{stream} (updated)")
                    .yellow()
                    .bold()
            );
        }
    }
    Ok(())
}

enum ResourceAction {
    Create,
    Ensure(Vec<FieldDiff>),
    Unchanged,
}

struct FieldDiff {
    field: &'static str,
    old: String,
    new: String,
}

fn is_not_found_error(e: &s2_sdk::types::S2Error) -> bool {
    matches!(e, s2_sdk::types::S2Error::Server(s2_sdk::types::ErrorResponse { code, .. }) if code == "basin_not_found" || code == "stream_not_found")
}

fn format_storage_class(sc: StorageClass) -> &'static str {
    match sc {
        StorageClass::Standard => "standard",
        StorageClass::Express => "express",
    }
}

fn format_retention_policy(rp: RetentionPolicy) -> String {
    match rp {
        RetentionPolicy::Age(age) => humantime::format_duration(age).to_string(),
        RetentionPolicy::Infinite() => "infinite".to_string(),
    }
}

fn format_timestamping_mode(m: TimestampingMode) -> &'static str {
    match m {
        TimestampingMode::ClientPrefer => "client-prefer",
        TimestampingMode::ClientRequire => "client-require",
        TimestampingMode::Arrival => "arrival",
    }
}

fn merge_stream_config(
    config: OptionalStreamConfig,
    basin_defaults: OptionalStreamConfig,
) -> StreamConfig {
    config.merge(basin_defaults)
}

fn default_stream_config_field(field: &'static str) -> &'static str {
    match field {
        "storage_class" => "default_stream_config.storage_class",
        "retention_policy" => "default_stream_config.retention_policy",
        "timestamping.mode" => "default_stream_config.timestamping.mode",
        "timestamping.uncapped" => "default_stream_config.timestamping.uncapped",
        "delete_on_empty.min_age" => "default_stream_config.delete_on_empty.min_age",
        _ => field,
    }
}

fn diff_basin_config(existing: &BasinConfig, desired: &BasinConfig) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();

    if existing.stream_cipher != desired.stream_cipher {
        diffs.push(FieldDiff {
            field: "stream_cipher",
            old: existing
                .stream_cipher
                .map(format_encryption_algorithm)
                .unwrap_or("none")
                .to_string(),
            new: desired
                .stream_cipher
                .map(format_encryption_algorithm)
                .unwrap_or("none")
                .to_string(),
        });
    }

    if existing.create_stream_on_append != desired.create_stream_on_append {
        diffs.push(FieldDiff {
            field: "create_stream_on_append",
            old: existing.create_stream_on_append.to_string(),
            new: desired.create_stream_on_append.to_string(),
        });
    }

    if existing.create_stream_on_read != desired.create_stream_on_read {
        diffs.push(FieldDiff {
            field: "create_stream_on_read",
            old: existing.create_stream_on_read.to_string(),
            new: desired.create_stream_on_read.to_string(),
        });
    }

    let existing_dsc: StreamConfig = existing.default_stream_config.clone().into();
    let desired_dsc: StreamConfig = desired.default_stream_config.clone().into();
    for sd in diff_stream_configs(&existing_dsc, &desired_dsc) {
        diffs.push(FieldDiff {
            field: default_stream_config_field(sd.field),
            old: sd.old,
            new: sd.new,
        });
    }

    diffs
}

fn diff_stream_configs(existing: &StreamConfig, desired: &StreamConfig) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();

    if existing.storage_class != desired.storage_class {
        diffs.push(FieldDiff {
            field: "storage_class",
            old: format_storage_class(existing.storage_class).to_string(),
            new: format_storage_class(desired.storage_class).to_string(),
        });
    }

    if existing.retention_policy != desired.retention_policy {
        diffs.push(FieldDiff {
            field: "retention_policy",
            old: format_retention_policy(existing.retention_policy),
            new: format_retention_policy(desired.retention_policy),
        });
    }

    if existing.timestamping.mode != desired.timestamping.mode {
        diffs.push(FieldDiff {
            field: "timestamping.mode",
            old: format_timestamping_mode(existing.timestamping.mode).to_string(),
            new: format_timestamping_mode(desired.timestamping.mode).to_string(),
        });
    }

    if existing.timestamping.uncapped != desired.timestamping.uncapped {
        diffs.push(FieldDiff {
            field: "timestamping.uncapped",
            old: existing.timestamping.uncapped.to_string(),
            new: desired.timestamping.uncapped.to_string(),
        });
    }

    if existing.delete_on_empty.min_age != desired.delete_on_empty.min_age {
        diffs.push(FieldDiff {
            field: "delete_on_empty.min_age",
            old: humantime::format_duration(existing.delete_on_empty.min_age).to_string(),
            new: humantime::format_duration(desired.delete_on_empty.min_age).to_string(),
        });
    }

    diffs
}

fn spec_basin_fields(spec: &BasinConfigSpec) -> Vec<FieldDiff> {
    let mut fields = Vec::new();

    if let Some(algorithm) = spec.stream_cipher.clone().map(EncryptionAlgorithm::from) {
        fields.push(FieldDiff {
            field: "stream_cipher",
            old: String::new(),
            new: format_encryption_algorithm(algorithm).to_string(),
        });
    }
    if let Some(v) = spec.create_stream_on_append {
        fields.push(FieldDiff {
            field: "create_stream_on_append",
            old: String::new(),
            new: v.to_string(),
        });
    }
    if let Some(v) = spec.create_stream_on_read {
        fields.push(FieldDiff {
            field: "create_stream_on_read",
            old: String::new(),
            new: v.to_string(),
        });
    }
    if let Some(ref dsc) = spec.default_stream_config {
        for f in spec_stream_fields(dsc) {
            fields.push(FieldDiff {
                field: default_stream_config_field(f.field),
                old: f.old,
                new: f.new,
            });
        }
    }

    fields
}

fn spec_stream_fields(spec: &StreamConfigSpec) -> Vec<FieldDiff> {
    let mut fields = Vec::new();

    if let Some(ref sc) = spec.storage_class {
        fields.push(FieldDiff {
            field: "storage_class",
            old: String::new(),
            new: format_storage_class(sc.clone().into()).to_string(),
        });
    }
    if let Some(ref rp) = spec.retention_policy {
        fields.push(FieldDiff {
            field: "retention_policy",
            old: String::new(),
            new: format_retention_policy(rp.0),
        });
    }
    if let Some(ref ts) = spec.timestamping {
        if let Some(ref mode) = ts.mode {
            fields.push(FieldDiff {
                field: "timestamping.mode",
                old: String::new(),
                new: format_timestamping_mode(mode.clone().into()).to_string(),
            });
        }
        if let Some(uncapped) = ts.uncapped {
            fields.push(FieldDiff {
                field: "timestamping.uncapped",
                old: String::new(),
                new: uncapped.to_string(),
            });
        }
    }
    if let Some(ref doe) = spec.delete_on_empty
        && let Some(ref min_age) = doe.min_age
    {
        fields.push(FieldDiff {
            field: "delete_on_empty.min_age",
            old: String::new(),
            new: humantime::format_duration(min_age.0).to_string(),
        });
    }

    fields
}

fn print_basin_result(basin: &str, action: &ResourceAction) {
    match action {
        ResourceAction::Create => {
            println!("{}", format!("+ basin {basin}").green().bold());
        }
        ResourceAction::Ensure(diffs) => {
            println!("{}", format!("~ basin {basin}").yellow().bold());
            for diff in diffs {
                println!("    {}: {} → {}", diff.field, diff.old.dimmed(), diff.new);
            }
        }
        ResourceAction::Unchanged => {
            println!("{}", format!("= basin {basin}").dimmed());
        }
    }
}

fn print_stream_result(basin: &str, stream: &str, action: &ResourceAction) {
    match action {
        ResourceAction::Create => {
            println!("{}", format!("  + stream {basin}/{stream}").green().bold());
        }
        ResourceAction::Ensure(diffs) => {
            println!("{}", format!("  ~ stream {basin}/{stream}").yellow().bold());
            for diff in diffs {
                println!("      {}: {} → {}", diff.field, diff.old.dimmed(), diff.new);
            }
        }
        ResourceAction::Unchanged => {
            println!("{}", format!("  = stream {basin}/{stream}").dimmed());
        }
    }
}

fn print_basin_create(basin: &str, spec: &Option<BasinConfigSpec>) {
    println!("{}", format!("+ basin {basin}").green().bold());
    if let Some(config) = spec {
        for field in spec_basin_fields(config) {
            println!("    {}: {}", field.field, field.new);
        }
    }
}

fn print_stream_create(basin: &str, stream: &str, spec: &Option<StreamConfigSpec>) {
    println!("{}", format!("  + stream {basin}/{stream}").green().bold());
    if let Some(config) = spec {
        for field in spec_stream_fields(config) {
            println!("      {}: {}", field.field, field.new);
        }
    }
}

pub async fn dry_run(s2: &s2_sdk::S2, spec: ResourcesSpec) -> miette::Result<()> {
    validate(&spec)?;

    for basin_spec in spec.basins {
        let basin: BasinName = basin_spec
            .name
            .parse()
            .map_err(|e| miette::miette!("invalid basin name {:?}: {}", basin_spec.name, e))?;
        let desired_basin_config = basin_spec
            .config
            .clone()
            .map(BasinConfig::from)
            .unwrap_or_default();
        let desired_basin_default_stream_config =
            desired_basin_config.default_stream_config.clone();

        let basin_action = match s2.get_basin_config(basin.clone()).await {
            Ok(existing) => {
                let existing = basin_config_from_sdk(existing)?;
                let diffs = diff_basin_config(&existing, &desired_basin_config);
                if diffs.is_empty() {
                    ResourceAction::Unchanged
                } else {
                    ResourceAction::Ensure(diffs)
                }
            }
            Err(e) if is_not_found_error(&e) => ResourceAction::Create,
            Err(e) => {
                return Err(miette::miette!(
                    "failed to check basin {:?}: {}",
                    basin.as_ref(),
                    e
                ));
            }
        };

        match &basin_action {
            ResourceAction::Create => {
                print_basin_create(basin.as_ref(), &basin_spec.config);
            }
            action => {
                print_basin_result(basin.as_ref(), action);
            }
        }

        let basin_client = s2.basin(basin.clone());

        for stream_spec in basin_spec.streams {
            let stream: StreamName = stream_spec.name.parse().map_err(|e| {
                miette::miette!("invalid stream name {:?}: {}", stream_spec.name, e)
            })?;

            let stream_action = match basin_client.get_stream_config(stream.clone()).await {
                Ok(existing) => {
                    let existing = stream_config_from_sdk(existing)?;
                    let desired_stream_config = merge_stream_config(
                        stream_spec
                            .config
                            .clone()
                            .map(OptionalStreamConfig::from)
                            .unwrap_or_default(),
                        desired_basin_default_stream_config.clone(),
                    );
                    let diffs = diff_stream_configs(&existing, &desired_stream_config);
                    if diffs.is_empty() {
                        ResourceAction::Unchanged
                    } else {
                        ResourceAction::Ensure(diffs)
                    }
                }
                Err(e) if is_not_found_error(&e) => ResourceAction::Create,
                Err(e) => {
                    return Err(miette::miette!(
                        "failed to check stream {:?}/{:?}: {}",
                        basin.as_ref(),
                        stream.as_ref(),
                        e
                    ));
                }
            };

            match &stream_action {
                ResourceAction::Create => {
                    print_stream_create(basin.as_ref(), stream.as_ref(), &stream_spec.config);
                }
                action => {
                    print_stream_result(basin.as_ref(), stream.as_ref(), action);
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use s2_lite::init::{
        DeleteOnEmptySpec, RetentionPolicySpec, StorageClassSpec, TimestampingModeSpec,
        TimestampingSpec,
    };

    use super::*;

    #[test]
    fn common_stream_config_preserves_omitted_timestamping_fields() {
        let config = OptionalStreamConfig::from(StreamConfigSpec {
            storage_class: None,
            retention_policy: None,
            timestamping: Some(TimestampingSpec {
                mode: Some(TimestampingModeSpec::Arrival),
                uncapped: None,
            }),
            delete_on_empty: None,
        });

        assert_eq!(config.timestamping.mode, Some(TimestampingMode::Arrival));
        assert_eq!(config.timestamping.uncapped, None);
    }

    #[test]
    fn dry_run_merge_uses_basin_defaults_for_omitted_nested_fields() {
        let basin_defaults = StreamConfigSpec {
            storage_class: Some(StorageClassSpec::Standard),
            retention_policy: None,
            timestamping: Some(TimestampingSpec {
                mode: None,
                uncapped: Some(true),
            }),
            delete_on_empty: Some(DeleteOnEmptySpec {
                min_age: Some(s2_lite::init::HumanDuration(Duration::from_secs(60))),
            }),
        };
        let stream_config = StreamConfigSpec {
            storage_class: None,
            retention_policy: Some(RetentionPolicySpec::try_from("infinite".to_string()).unwrap()),
            timestamping: Some(TimestampingSpec {
                mode: Some(TimestampingModeSpec::Arrival),
                uncapped: None,
            }),
            delete_on_empty: Some(DeleteOnEmptySpec { min_age: None }),
        };

        let merged = merge_stream_config(
            OptionalStreamConfig::from(stream_config),
            OptionalStreamConfig::from(basin_defaults),
        );

        assert_eq!(merged.storage_class, StorageClass::Standard);
        assert_eq!(merged.retention_policy, RetentionPolicy::Infinite());
        assert_eq!(merged.timestamping.mode, TimestampingMode::Arrival);
        assert!(merged.timestamping.uncapped);
        assert_eq!(merged.delete_on_empty.min_age, Duration::from_secs(60));
    }
}
