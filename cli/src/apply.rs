//! Declarative basin/stream configuration via a JSON spec file.

use std::{path::Path, time::Duration};

use colored::Colorize;
use s2_common::{encryption::EncryptionAlgorithm, types::config as common_config};
use s2_lite::init::{BasinConfigSpec, ResourcesSpec, StreamConfigSpec};
use s2_sdk::{
    S2,
    types::{
        BasinName, EnsureBasinInput, EnsureStreamInput, ErrorResponse, ProvisionResult, S2Error,
        StreamName,
    },
};

struct DryRunBasinConfig {
    default_stream_config: common_config::StreamConfig,
    stream_cipher: Option<EncryptionAlgorithm>,
    create_stream_on_append: bool,
    create_stream_on_read: bool,
}

fn dry_run_basin_config_from_common(config: common_config::BasinConfig) -> DryRunBasinConfig {
    DryRunBasinConfig {
        default_stream_config: config.default_stream_config.into(),
        stream_cipher: config.stream_cipher,
        create_stream_on_append: config.create_stream_on_append,
        create_stream_on_read: config.create_stream_on_read,
    }
}

fn dry_run_basin_config_from_sdk(config: s2_sdk::types::BasinConfig) -> DryRunBasinConfig {
    DryRunBasinConfig {
        default_stream_config: config
            .default_stream_config
            .map(stream_config_from_sdk)
            .unwrap_or_default(),
        stream_cipher: config.stream_cipher,
        create_stream_on_append: config.create_stream_on_append,
        create_stream_on_read: config.create_stream_on_read,
    }
}

fn storage_class_from_sdk(s: s2_sdk::types::StorageClass) -> common_config::StorageClass {
    match s {
        s2_sdk::types::StorageClass::Standard => common_config::StorageClass::Standard,
        s2_sdk::types::StorageClass::Express => common_config::StorageClass::Express,
    }
}

fn retention_policy_from_sdk(rp: s2_sdk::types::RetentionPolicy) -> common_config::RetentionPolicy {
    match rp {
        s2_sdk::types::RetentionPolicy::Age(secs) => {
            common_config::RetentionPolicy::Age(Duration::from_secs(secs))
        }
        s2_sdk::types::RetentionPolicy::Infinite => common_config::RetentionPolicy::Infinite(),
    }
}

fn timestamping_mode_from_sdk(
    m: s2_sdk::types::TimestampingMode,
) -> common_config::TimestampingMode {
    match m {
        s2_sdk::types::TimestampingMode::ClientPrefer => {
            common_config::TimestampingMode::ClientPrefer
        }
        s2_sdk::types::TimestampingMode::ClientRequire => {
            common_config::TimestampingMode::ClientRequire
        }
        s2_sdk::types::TimestampingMode::Arrival => common_config::TimestampingMode::Arrival,
    }
}

fn stream_config_from_sdk(config: s2_sdk::types::StreamConfig) -> common_config::StreamConfig {
    let timestamping = config
        .timestamping
        .map(|timestamping| common_config::TimestampingConfig {
            mode: timestamping
                .mode
                .map(timestamping_mode_from_sdk)
                .unwrap_or_default(),
            uncapped: timestamping.uncapped,
        })
        .unwrap_or_default();
    let delete_on_empty = config
        .delete_on_empty
        .map(|delete_on_empty| common_config::DeleteOnEmptyConfig {
            min_age: Duration::from_secs(delete_on_empty.min_age_secs),
        })
        .unwrap_or_default();

    common_config::StreamConfig {
        storage_class: config
            .storage_class
            .map(storage_class_from_sdk)
            .unwrap_or_default(),
        retention_policy: config
            .retention_policy
            .map(retention_policy_from_sdk)
            .unwrap_or_default(),
        timestamping,
        delete_on_empty,
    }
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

pub async fn apply(s2: &S2, spec: ResourcesSpec) -> miette::Result<()> {
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
    s2: &S2,
    basin: BasinName,
    config: Option<BasinConfigSpec>,
) -> miette::Result<()> {
    let mut input = EnsureBasinInput::new(basin.clone());
    if let Some(c) = config {
        input = input.with_config(common_config::BasinConfig::from(c));
    }
    match s2
        .ensure_basin(input)
        .await
        .map_err(|e| miette::miette!("failed to apply basin {:?}: {}", basin.as_ref(), e))?
    {
        ProvisionResult::Created(_) => {
            eprintln!("{}", format!("  basin {basin}").green().bold());
        }
        ProvisionResult::Updated(_) => {
            eprintln!("{}", format!("  basin {basin} (updated)").yellow().bold());
        }
    }
    Ok(())
}

async fn apply_stream(
    s2: &S2,
    basin: BasinName,
    stream: StreamName,
    config: Option<StreamConfigSpec>,
) -> miette::Result<()> {
    let mut input = EnsureStreamInput::new(stream.clone());
    if let Some(c) = config {
        input = input.with_config(common_config::OptionalStreamConfig::from(c));
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
        ProvisionResult::Created(_) => {
            eprintln!("{}", format!("  stream {basin}/{stream}").green().bold());
        }
        ProvisionResult::Updated(_) => {
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

fn is_not_found_error(e: &S2Error) -> bool {
    matches!(e, S2Error::Server(ErrorResponse { code, .. }) if code == "basin_not_found" || code == "stream_not_found")
}

fn format_storage_class(sc: common_config::StorageClass) -> &'static str {
    match sc {
        common_config::StorageClass::Standard => "standard",
        common_config::StorageClass::Express => "express",
    }
}

fn format_retention_policy(rp: common_config::RetentionPolicy) -> String {
    match rp {
        common_config::RetentionPolicy::Age(age) => humantime::format_duration(age).to_string(),
        common_config::RetentionPolicy::Infinite() => "infinite".to_string(),
    }
}

fn format_timestamping_mode(m: common_config::TimestampingMode) -> &'static str {
    match m {
        common_config::TimestampingMode::ClientPrefer => "client-prefer",
        common_config::TimestampingMode::ClientRequire => "client-require",
        common_config::TimestampingMode::Arrival => "arrival",
    }
}

fn merge_stream_config(
    config: common_config::OptionalStreamConfig,
    basin_defaults: common_config::OptionalStreamConfig,
) -> common_config::StreamConfig {
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

fn diff_basin_config(existing: &DryRunBasinConfig, desired: &DryRunBasinConfig) -> Vec<FieldDiff> {
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

    for sd in diff_stream_configs(
        &existing.default_stream_config,
        &desired.default_stream_config,
    ) {
        diffs.push(FieldDiff {
            field: default_stream_config_field(sd.field),
            old: sd.old,
            new: sd.new,
        });
    }

    diffs
}

fn diff_stream_configs(
    existing: &common_config::StreamConfig,
    desired: &common_config::StreamConfig,
) -> Vec<FieldDiff> {
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

pub async fn dry_run(s2: &S2, spec: ResourcesSpec) -> miette::Result<()> {
    validate(&spec)?;

    for basin_spec in spec.basins {
        let basin: BasinName = basin_spec
            .name
            .parse()
            .map_err(|e| miette::miette!("invalid basin name {:?}: {}", basin_spec.name, e))?;
        let desired_basin_common_config = basin_spec
            .config
            .clone()
            .map(common_config::BasinConfig::from)
            .unwrap_or_default();
        let desired_basin_config =
            dry_run_basin_config_from_common(desired_basin_common_config.clone());
        let desired_basin_default_stream_config =
            desired_basin_common_config.default_stream_config.clone();

        let basin_action = match s2.get_basin_config(basin.clone()).await {
            Ok(existing) => {
                let existing = dry_run_basin_config_from_sdk(existing);
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
                    let existing = stream_config_from_sdk(existing);
                    let desired_stream_config = merge_stream_config(
                        stream_spec
                            .config
                            .clone()
                            .map(common_config::OptionalStreamConfig::from)
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
    use s2_lite::init::{
        DeleteOnEmptySpec, RetentionPolicySpec, StorageClassSpec, TimestampingModeSpec,
        TimestampingSpec,
    };

    use super::*;

    #[test]
    fn common_stream_config_preserves_omitted_timestamping_fields() {
        let config = common_config::OptionalStreamConfig::from(StreamConfigSpec {
            storage_class: None,
            retention_policy: None,
            timestamping: Some(TimestampingSpec {
                mode: Some(TimestampingModeSpec::Arrival),
                uncapped: None,
            }),
            delete_on_empty: None,
        });

        assert_eq!(
            config.timestamping.mode,
            Some(common_config::TimestampingMode::Arrival)
        );
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
            common_config::OptionalStreamConfig::from(stream_config),
            common_config::OptionalStreamConfig::from(basin_defaults),
        );

        assert_eq!(merged.storage_class, common_config::StorageClass::Standard);
        assert_eq!(
            merged.retention_policy,
            common_config::RetentionPolicy::Infinite()
        );
        assert_eq!(
            merged.timestamping.mode,
            common_config::TimestampingMode::Arrival
        );
        assert!(merged.timestamping.uncapped);
        assert_eq!(merged.delete_on_empty.min_age, Duration::from_secs(60));
    }
}
