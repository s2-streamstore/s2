//! Declarative basin/stream configuration via a JSON spec file.

use std::{path::Path, time::Duration};

use colored::Colorize;
use s2_lite::init::{
    BasinConfigSpec, DeleteOnEmptySpec, ResourcesSpec, RetentionPolicySpec, StorageClassSpec,
    StreamConfigSpec, TimestampingModeSpec, TimestampingSpec,
};
use s2_sdk::{
    S2,
    types::{
        BasinConfig, BasinName, DeleteOnEmptyConfig, EncryptionAlgorithm, EnsureBasinInput,
        EnsureStreamInput, ErrorResponse, ProvisionResult, RetentionPolicy, S2Error, StorageClass,
        StreamConfig, StreamName, TimestampingConfig, TimestampingMode,
    },
};

fn storage_class_from_spec(s: StorageClassSpec) -> StorageClass {
    match s {
        StorageClassSpec::Standard => StorageClass::Standard,
        StorageClassSpec::Express => StorageClass::Express,
    }
}

fn retention_policy_from_spec(rp: RetentionPolicySpec) -> RetentionPolicy {
    match rp.age_secs() {
        Some(secs) => RetentionPolicy::Age(secs),
        None => RetentionPolicy::Infinite,
    }
}

fn timestamping_mode_from_spec(m: TimestampingModeSpec) -> TimestampingMode {
    match m {
        TimestampingModeSpec::ClientPrefer => TimestampingMode::ClientPrefer,
        TimestampingModeSpec::ClientRequire => TimestampingMode::ClientRequire,
        TimestampingModeSpec::Arrival => TimestampingMode::Arrival,
    }
}

fn encryption_algorithm_from_spec(
    a: s2_lite::init::EncryptionAlgorithmSpec,
) -> EncryptionAlgorithm {
    match a {
        s2_lite::init::EncryptionAlgorithmSpec::Aegis256 => EncryptionAlgorithm::Aegis256,
        s2_lite::init::EncryptionAlgorithmSpec::Aes256Gcm => EncryptionAlgorithm::Aes256Gcm,
    }
}

fn format_encryption_algorithm(algorithm: EncryptionAlgorithm) -> &'static str {
    match algorithm {
        EncryptionAlgorithm::Aegis256 => "aegis-256",
        EncryptionAlgorithm::Aes256Gcm => "aes-256-gcm",
    }
}

fn timestamping_config_from_spec(ts: TimestampingSpec) -> TimestampingConfig {
    let mut tsr = TimestampingConfig::new();
    if let Some(m) = ts.mode {
        tsr = tsr.with_mode(timestamping_mode_from_spec(m));
    }
    if let Some(u) = ts.uncapped {
        tsr = tsr.with_uncapped(u);
    }
    tsr
}

fn delete_on_empty_config_from_spec(doe: DeleteOnEmptySpec) -> DeleteOnEmptyConfig {
    let mut doer = DeleteOnEmptyConfig::new();
    if let Some(ma) = doe.min_age {
        doer = doer.with_min_age(ma.0);
    }
    doer
}

fn stream_config_from_spec(s: StreamConfigSpec) -> StreamConfig {
    let mut r = StreamConfig::new();
    if let Some(sc) = s.storage_class {
        r = r.with_storage_class(storage_class_from_spec(sc));
    }
    if let Some(rp) = s.retention_policy {
        r = r.with_retention_policy(retention_policy_from_spec(rp));
    }
    if let Some(ts) = s.timestamping {
        r = r.with_timestamping(timestamping_config_from_spec(ts));
    }
    if let Some(doe) = s.delete_on_empty {
        r = r.with_delete_on_empty(delete_on_empty_config_from_spec(doe));
    }
    r
}

fn basin_config_from_spec(s: BasinConfigSpec) -> BasinConfig {
    let mut r = BasinConfig::new();
    if let Some(dsc) = s.default_stream_config {
        r = r.with_default_stream_config(stream_config_from_spec(dsc));
    }
    if let Some(algorithm) = s.stream_cipher {
        r = r.with_stream_cipher(encryption_algorithm_from_spec(algorithm));
    }
    if let Some(v) = s.create_stream_on_append {
        r = r.with_create_stream_on_append(v);
    }
    if let Some(v) = s.create_stream_on_read {
        r = r.with_create_stream_on_read(v);
    }
    r
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
        input = input.with_config(basin_config_from_spec(c));
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
        input = input.with_config(stream_config_from_spec(c));
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

fn format_storage_class(sc: StorageClass) -> &'static str {
    match sc {
        StorageClass::Standard => "standard",
        StorageClass::Express => "express",
    }
}

fn format_retention_policy(rp: RetentionPolicy) -> String {
    match rp {
        RetentionPolicy::Age(secs) => {
            humantime::format_duration(Duration::from_secs(secs)).to_string()
        }
        RetentionPolicy::Infinite => "infinite".to_string(),
    }
}

fn format_timestamping_mode(m: TimestampingMode) -> &'static str {
    match m {
        TimestampingMode::ClientPrefer => "client-prefer",
        TimestampingMode::ClientRequire => "client-require",
        TimestampingMode::Arrival => "arrival",
    }
}

fn effective_storage_class(sc: Option<StorageClass>) -> StorageClass {
    sc.unwrap_or(StorageClass::Express)
}

fn effective_retention_policy(rp: Option<RetentionPolicy>) -> RetentionPolicy {
    rp.unwrap_or(RetentionPolicy::Age(7 * 24 * 60 * 60))
}

fn effective_timestamping_mode(ts: Option<&TimestampingConfig>) -> TimestampingMode {
    ts.and_then(|cfg| cfg.mode)
        .unwrap_or(TimestampingMode::ClientPrefer)
}

fn effective_timestamping_uncapped(ts: Option<&TimestampingConfig>) -> bool {
    ts.map(|cfg| cfg.uncapped).unwrap_or(false)
}

fn effective_delete_on_empty_min_age_secs(doe: Option<&DeleteOnEmptyConfig>) -> u64 {
    doe.map(|cfg| cfg.min_age_secs).unwrap_or(0)
}

fn merge_stream_config(
    config: StreamConfig,
    basin_defaults: Option<&StreamConfig>,
) -> StreamConfig {
    let default_timestamping = basin_defaults.and_then(|cfg| cfg.timestamping.as_ref());
    let timestamping = config.timestamping.as_ref();
    let default_delete_on_empty = basin_defaults.and_then(|cfg| cfg.delete_on_empty.as_ref());

    let delete_on_empty_min_age_secs = config
        .delete_on_empty
        .as_ref()
        .map(|cfg| cfg.min_age_secs)
        .or_else(|| default_delete_on_empty.map(|cfg| cfg.min_age_secs))
        .unwrap_or_default();

    let timestamping = TimestampingConfig::new()
        .with_mode(
            timestamping
                .and_then(|cfg| cfg.mode)
                .or_else(|| default_timestamping.and_then(|cfg| cfg.mode))
                .unwrap_or(TimestampingMode::ClientPrefer),
        )
        .with_uncapped(
            timestamping
                .map(|cfg| cfg.uncapped)
                .or_else(|| default_timestamping.map(|cfg| cfg.uncapped))
                .unwrap_or_default(),
        );

    let mut merged = StreamConfig::new()
        .with_storage_class(
            config
                .storage_class
                .or_else(|| basin_defaults.and_then(|cfg| cfg.storage_class))
                .unwrap_or(StorageClass::Express),
        )
        .with_retention_policy(
            config
                .retention_policy
                .or_else(|| basin_defaults.and_then(|cfg| cfg.retention_policy))
                .unwrap_or(RetentionPolicy::Age(7 * 24 * 60 * 60)),
        )
        .with_timestamping(timestamping);

    if delete_on_empty_min_age_secs > 0 {
        merged = merged.with_delete_on_empty(
            DeleteOnEmptyConfig::new()
                .with_min_age(Duration::from_secs(delete_on_empty_min_age_secs)),
        );
    }

    merged
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

    let existing_dsc = existing.default_stream_config.clone().unwrap_or_default();
    let desired_dsc = desired.default_stream_config.clone().unwrap_or_default();
    for sd in diff_stream_configs(&existing_dsc, &desired_dsc) {
        diffs.push(FieldDiff {
            field: sd.field,
            old: sd.old,
            new: sd.new,
        });
    }

    diffs
}

fn diff_stream_configs(existing: &StreamConfig, desired: &StreamConfig) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();

    let existing_sc = effective_storage_class(existing.storage_class);
    let desired_sc = effective_storage_class(desired.storage_class);
    if existing_sc != desired_sc {
        diffs.push(FieldDiff {
            field: "storage_class",
            old: format_storage_class(existing_sc).to_string(),
            new: format_storage_class(desired_sc).to_string(),
        });
    }

    let existing_rp = effective_retention_policy(existing.retention_policy);
    let desired_rp = effective_retention_policy(desired.retention_policy);
    if existing_rp != desired_rp {
        diffs.push(FieldDiff {
            field: "retention_policy",
            old: format_retention_policy(existing_rp),
            new: format_retention_policy(desired_rp),
        });
    }

    let existing_ts = existing.timestamping.as_ref();
    let desired_ts = desired.timestamping.as_ref();
    let existing_mode = effective_timestamping_mode(existing_ts);
    let desired_mode = effective_timestamping_mode(desired_ts);
    if existing_mode != desired_mode {
        diffs.push(FieldDiff {
            field: "timestamping.mode",
            old: format_timestamping_mode(existing_mode).to_string(),
            new: format_timestamping_mode(desired_mode).to_string(),
        });
    }

    let existing_uncapped = effective_timestamping_uncapped(existing_ts);
    let desired_uncapped = effective_timestamping_uncapped(desired_ts);
    if existing_uncapped != desired_uncapped {
        diffs.push(FieldDiff {
            field: "timestamping.uncapped",
            old: existing_uncapped.to_string(),
            new: desired_uncapped.to_string(),
        });
    }

    let existing_min_age =
        effective_delete_on_empty_min_age_secs(existing.delete_on_empty.as_ref());
    let desired_min_age = effective_delete_on_empty_min_age_secs(desired.delete_on_empty.as_ref());
    if existing_min_age != desired_min_age {
        diffs.push(FieldDiff {
            field: "delete_on_empty.min_age",
            old: humantime::format_duration(Duration::from_secs(existing_min_age)).to_string(),
            new: humantime::format_duration(Duration::from_secs(desired_min_age)).to_string(),
        });
    }

    diffs
}

fn spec_basin_fields(spec: &BasinConfigSpec) -> Vec<FieldDiff> {
    let mut fields = Vec::new();

    if let Some(algorithm) = spec
        .stream_cipher
        .clone()
        .map(encryption_algorithm_from_spec)
    {
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
            fields.push(f);
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
            new: format_storage_class(storage_class_from_spec(sc.clone())).to_string(),
        });
    }
    if let Some(ref rp) = spec.retention_policy {
        fields.push(FieldDiff {
            field: "retention_policy",
            old: String::new(),
            new: format_retention_policy(retention_policy_from_spec(*rp)),
        });
    }
    if let Some(ref ts) = spec.timestamping {
        if let Some(ref mode) = ts.mode {
            fields.push(FieldDiff {
                field: "timestamping.mode",
                old: String::new(),
                new: format_timestamping_mode(timestamping_mode_from_spec(mode.clone()))
                    .to_string(),
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
        let desired_basin_config = basin_spec
            .config
            .clone()
            .map(basin_config_from_spec)
            .unwrap_or_default();

        let basin_action = match s2.get_basin_config(basin.clone()).await {
            Ok(existing) => {
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
                    let desired_stream_config = merge_stream_config(
                        stream_spec
                            .config
                            .clone()
                            .map(stream_config_from_spec)
                            .unwrap_or_default(),
                        desired_basin_config.default_stream_config.as_ref(),
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
