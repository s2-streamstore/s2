//! Declarative basin/stream configuration via a JSON spec file.

use std::path::Path;

use colored::Colorize;
use s2_common::{
    basin::BasinName,
    config::{
        BasinConfig, OptionalDeleteOnEmptyConfig, OptionalStreamConfig, OptionalTimestampingConfig,
        RetentionPolicy, StorageClass, StreamConfig, TimestampingMode,
    },
    encryption::EncryptionAlgorithm,
    stream::StreamName,
};

fn basin_config_from_sdk(config: s2_sdk::types::BasinConfig) -> BasinConfig {
    BasinConfig {
        default_stream_config: config
            .default_stream_config
            .map(optional_stream_config_from_sdk)
            .unwrap_or_default(),
        stream_cipher: config.stream_cipher,
        create_stream_on_append: config.create_stream_on_append,
        create_stream_on_read: config.create_stream_on_read,
    }
}

fn stream_config_from_sdk(config: s2_sdk::types::StreamConfig) -> StreamConfig {
    optional_stream_config_from_sdk(config).into()
}

fn optional_stream_config_from_sdk(config: s2_sdk::types::StreamConfig) -> OptionalStreamConfig {
    OptionalStreamConfig {
        storage_class: config.storage_class.map(storage_class_from_sdk),
        retention_policy: config.retention_policy.map(retention_policy_from_sdk),
        timestamping: config
            .timestamping
            .map(timestamping_from_sdk)
            .unwrap_or_default(),
        delete_on_empty: config
            .delete_on_empty
            .map(delete_on_empty_from_sdk)
            .unwrap_or_default(),
    }
}

fn storage_class_from_sdk(storage_class: s2_sdk::types::StorageClass) -> StorageClass {
    match storage_class {
        s2_sdk::types::StorageClass::Standard => StorageClass::Standard,
        s2_sdk::types::StorageClass::Express => StorageClass::Express,
    }
}

fn retention_policy_from_sdk(retention_policy: s2_sdk::types::RetentionPolicy) -> RetentionPolicy {
    match retention_policy {
        s2_sdk::types::RetentionPolicy::Age(secs) => {
            RetentionPolicy::Age(std::time::Duration::from_secs(secs))
        }
        s2_sdk::types::RetentionPolicy::Infinite => RetentionPolicy::Infinite(),
    }
}

fn timestamping_from_sdk(
    timestamping: s2_sdk::types::TimestampingConfig,
) -> OptionalTimestampingConfig {
    OptionalTimestampingConfig {
        mode: timestamping.mode.map(timestamping_mode_from_sdk),
        uncapped: timestamping.uncapped,
    }
}

fn timestamping_mode_from_sdk(mode: s2_sdk::types::TimestampingMode) -> TimestampingMode {
    match mode {
        s2_sdk::types::TimestampingMode::ClientPrefer => TimestampingMode::ClientPrefer,
        s2_sdk::types::TimestampingMode::ClientRequire => TimestampingMode::ClientRequire,
        s2_sdk::types::TimestampingMode::Arrival => TimestampingMode::Arrival,
    }
}

fn delete_on_empty_from_sdk(
    delete_on_empty: s2_sdk::types::DeleteOnEmptyConfig,
) -> OptionalDeleteOnEmptyConfig {
    OptionalDeleteOnEmptyConfig {
        min_age: Some(std::time::Duration::from_secs(delete_on_empty.min_age_secs)),
    }
}

fn basin_config_to_sdk(config: s2_resource_spec::BasinConfig) -> s2_sdk::types::BasinConfig {
    let mut sdk_config = s2_sdk::types::BasinConfig::new();
    if let Some(default_stream_config) = config.default_stream_config {
        sdk_config =
            sdk_config.with_default_stream_config(stream_config_to_sdk(default_stream_config));
    }
    if let Some(stream_cipher) = config.stream_cipher {
        sdk_config = sdk_config.with_stream_cipher(stream_cipher.into());
    }
    if let Some(create_stream_on_append) = config.create_stream_on_append {
        sdk_config = sdk_config.with_create_stream_on_append(create_stream_on_append);
    }
    if let Some(create_stream_on_read) = config.create_stream_on_read {
        sdk_config = sdk_config.with_create_stream_on_read(create_stream_on_read);
    }
    sdk_config
}

fn stream_config_to_sdk(config: s2_resource_spec::StreamConfig) -> s2_sdk::types::StreamConfig {
    let mut sdk_config = s2_sdk::types::StreamConfig::new();
    if let Some(storage_class) = config.storage_class {
        sdk_config = sdk_config.with_storage_class(storage_class_to_sdk(storage_class));
    }
    if let Some(retention_policy) = config.retention_policy {
        sdk_config = sdk_config.with_retention_policy(retention_policy_to_sdk(retention_policy));
    }
    if let Some(timestamping) = config.timestamping {
        sdk_config = sdk_config.with_timestamping(timestamping_to_sdk(timestamping));
    }
    if let Some(delete_on_empty) = config.delete_on_empty.and_then(delete_on_empty_to_sdk) {
        sdk_config = sdk_config.with_delete_on_empty(delete_on_empty);
    }
    sdk_config
}

fn storage_class_to_sdk(
    storage_class: s2_resource_spec::StorageClass,
) -> s2_sdk::types::StorageClass {
    match storage_class {
        s2_resource_spec::StorageClass::Standard => s2_sdk::types::StorageClass::Standard,
        s2_resource_spec::StorageClass::Express => s2_sdk::types::StorageClass::Express,
    }
}

fn retention_policy_to_sdk(
    retention_policy: s2_resource_spec::RetentionPolicy,
) -> s2_sdk::types::RetentionPolicy {
    match retention_policy.0 {
        RetentionPolicy::Age(duration) => s2_sdk::types::RetentionPolicy::Age(duration.as_secs()),
        RetentionPolicy::Infinite() => s2_sdk::types::RetentionPolicy::Infinite,
    }
}

fn timestamping_to_sdk(
    timestamping: s2_resource_spec::Timestamping,
) -> s2_sdk::types::TimestampingConfig {
    let mut sdk_config = s2_sdk::types::TimestampingConfig::new();
    if let Some(mode) = timestamping.mode {
        sdk_config = sdk_config.with_mode(timestamping_mode_to_sdk(mode));
    }
    if let Some(uncapped) = timestamping.uncapped {
        sdk_config = sdk_config.with_uncapped(uncapped);
    }
    sdk_config
}

fn timestamping_mode_to_sdk(
    mode: s2_resource_spec::TimestampingMode,
) -> s2_sdk::types::TimestampingMode {
    match mode {
        s2_resource_spec::TimestampingMode::ClientPrefer => {
            s2_sdk::types::TimestampingMode::ClientPrefer
        }
        s2_resource_spec::TimestampingMode::ClientRequire => {
            s2_sdk::types::TimestampingMode::ClientRequire
        }
        s2_resource_spec::TimestampingMode::Arrival => s2_sdk::types::TimestampingMode::Arrival,
    }
}

fn delete_on_empty_to_sdk(
    delete_on_empty: s2_resource_spec::DeleteOnEmpty,
) -> Option<s2_sdk::types::DeleteOnEmptyConfig> {
    delete_on_empty
        .min_age
        .map(|min_age| s2_sdk::types::DeleteOnEmptyConfig::new().with_min_age(min_age.0))
}

fn format_encryption_algorithm(algorithm: EncryptionAlgorithm) -> &'static str {
    match algorithm {
        EncryptionAlgorithm::Aegis256 => "aegis-256",
        EncryptionAlgorithm::Aes256Gcm => "aes-256-gcm",
    }
}

pub fn validate(spec: &s2_resource_spec::Resources) -> miette::Result<()> {
    s2_resource_spec::validate(spec).map_err(|e| miette::miette!("{}", e))
}

pub fn load(path: &Path) -> miette::Result<s2_resource_spec::Resources> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read spec file {:?}: {}", path.display(), e))?;
    let spec: s2_resource_spec::Resources = serde_json::from_str(&contents)
        .map_err(|e| miette::miette!("failed to parse spec file {:?}: {}", path.display(), e))?;
    Ok(spec)
}

pub async fn apply(s2: &s2_sdk::S2, spec: s2_resource_spec::Resources) -> miette::Result<()> {
    validate(&spec)?;

    for basin_spec in spec.basins {
        let basin = basin_spec.name;
        apply_basin(s2, basin.clone(), basin_spec.config).await?;

        for stream_spec in basin_spec.streams {
            let stream = stream_spec.name;
            apply_stream(s2, basin.clone(), stream, stream_spec.config).await?;
        }
    }
    Ok(())
}

async fn apply_basin(
    s2: &s2_sdk::S2,
    basin: BasinName,
    config: Option<s2_resource_spec::BasinConfig>,
) -> miette::Result<()> {
    let mut input = s2_sdk::types::EnsureBasinInput::new(basin.clone());
    if let Some(c) = config {
        input = input.with_config(basin_config_to_sdk(c));
    }
    match s2
        .ensure_basin(input)
        .await
        .map_err(|e| miette::miette!("failed to apply basin {:?}: {}", basin.as_ref(), e))?
    {
        s2_sdk::types::EnsureOutput::Created(_) => {
            eprintln!("{}", format!("  basin {basin} (created)").green().bold());
        }
        s2_sdk::types::EnsureOutput::ConfigUpdated(_) => {
            eprintln!(
                "{}",
                format!("  basin {basin} (config updated)").yellow().bold()
            );
        }
        s2_sdk::types::EnsureOutput::ConfigUnchanged(_) => {
            eprintln!("{}", format!("  basin {basin} (config unchanged)").dimmed());
        }
    }
    Ok(())
}

async fn apply_stream(
    s2: &s2_sdk::S2,
    basin: BasinName,
    stream: StreamName,
    config: Option<s2_resource_spec::StreamConfig>,
) -> miette::Result<()> {
    let basin_client = s2.basin(basin.clone());

    let mut input = s2_sdk::types::EnsureStreamInput::new(stream.clone());
    if let Some(c) = config {
        input = input.with_config(stream_config_to_sdk(c));
    }
    match basin_client.ensure_stream(input).await.map_err(|e| {
        miette::miette!(
            "failed to apply stream {:?}/{:?}: {}",
            basin.as_ref(),
            stream.as_ref(),
            e
        )
    })? {
        s2_sdk::types::EnsureOutput::Created(_) => {
            eprintln!(
                "{}",
                format!("  stream {basin}/{stream} (created)")
                    .green()
                    .bold()
            );
        }
        s2_sdk::types::EnsureOutput::ConfigUpdated(_) => {
            eprintln!(
                "{}",
                format!("  stream {basin}/{stream} (config updated)")
                    .yellow()
                    .bold()
            );
        }
        s2_sdk::types::EnsureOutput::ConfigUnchanged(_) => {
            eprintln!(
                "{}",
                format!("  stream {basin}/{stream} (config unchanged)").dimmed()
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

fn spec_basin_fields(spec: &s2_resource_spec::BasinConfig) -> Vec<FieldDiff> {
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

fn spec_stream_fields(spec: &s2_resource_spec::StreamConfig) -> Vec<FieldDiff> {
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

fn print_basin_create(basin: &str, spec: &Option<s2_resource_spec::BasinConfig>) {
    println!("{}", format!("+ basin {basin}").green().bold());
    if let Some(config) = spec {
        for field in spec_basin_fields(config) {
            println!("    {}: {}", field.field, field.new);
        }
    }
}

fn print_stream_create(basin: &str, stream: &str, spec: &Option<s2_resource_spec::StreamConfig>) {
    println!("{}", format!("  + stream {basin}/{stream}").green().bold());
    if let Some(config) = spec {
        for field in spec_stream_fields(config) {
            println!("      {}: {}", field.field, field.new);
        }
    }
}

pub async fn dry_run(s2: &s2_sdk::S2, spec: s2_resource_spec::Resources) -> miette::Result<()> {
    validate(&spec)?;

    for basin_spec in spec.basins {
        let basin = basin_spec.name;
        let desired_basin_config = basin_spec
            .config
            .clone()
            .map(BasinConfig::from)
            .unwrap_or_default();
        let desired_basin_default_stream_config =
            desired_basin_config.default_stream_config.clone();

        let basin_action = match s2.get_basin_config(basin.clone()).await {
            Ok(existing) => {
                let existing = basin_config_from_sdk(existing);
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
            let stream = stream_spec.name;

            let stream_action = match basin_client.get_stream_config(stream.clone()).await {
                Ok(existing) => {
                    let existing = stream_config_from_sdk(existing);
                    let desired_stream_config = stream_spec
                        .config
                        .clone()
                        .map(OptionalStreamConfig::from)
                        .unwrap_or_default()
                        .merge(desired_basin_default_stream_config.clone());
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
