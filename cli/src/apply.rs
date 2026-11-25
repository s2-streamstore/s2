//! Declarative basin/stream configuration via a JSON spec file.

use std::{collections::HashMap, path::Path, time::Duration};

use colored::Colorize;
use s2_common::{
    basin::BasinName,
    config::{RetentionPolicy, TimestampingMode},
    stream::StreamName,
};
use s2_sdk::{
    error::{ErrorCode, RequestError},
    types::{BasinConfig, LocationName, StreamConfig},
};

use crate::{
    ops,
    types::{ResolvedStreamConfig, resolve_stream_config},
};

fn basin_config_to_sdk(config: s2_resource_spec::BasinConfig) -> s2_sdk::types::BasinConfig {
    let mut sdk_config = s2_sdk::types::BasinConfig::new();
    if let Some(default_stream_config) = config.default_stream_config {
        sdk_config =
            sdk_config.with_default_stream_config(stream_config_to_sdk(default_stream_config));
    }
    if let Some(stream_cipher) = config.stream_cipher {
        sdk_config = sdk_config.with_stream_cipher(encryption_algorithm_to_sdk(stream_cipher));
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
        sdk_config = sdk_config.with_storage_class(storage_class);
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

fn encryption_algorithm_to_sdk(
    algorithm: s2_resource_spec::EncryptionAlgorithm,
) -> s2_sdk::types::EncryptionAlgorithm {
    match algorithm {
        s2_resource_spec::EncryptionAlgorithm::Aegis256 => {
            s2_sdk::types::EncryptionAlgorithm::Aegis256
        }
        s2_resource_spec::EncryptionAlgorithm::Aes256Gcm => {
            s2_sdk::types::EncryptionAlgorithm::Aes256Gcm
        }
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
    delete_on_empty.min_age.map(|min_age| {
        s2_sdk::types::DeleteOnEmptyConfig::new().with_min_age_secs(min_age.0.as_secs())
    })
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
        apply_basin(s2, basin_spec.name.clone(), basin_spec.config).await?;

        for stream_spec in basin_spec.streams {
            apply_stream(
                s2,
                basin_spec.name.clone(),
                stream_spec.name,
                stream_spec.config,
            )
            .await?;
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
        s2_sdk::types::EnsureOutput::Updated(_) => {
            eprintln!(
                "{}",
                format!("  basin {basin} (config updated)").yellow().bold()
            );
        }
        s2_sdk::types::EnsureOutput::Noop(_) => {
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
        s2_sdk::types::EnsureOutput::Updated(_) => {
            eprintln!(
                "{}",
                format!("  stream {basin}/{stream} (config updated)")
                    .yellow()
                    .bold()
            );
        }
        s2_sdk::types::EnsureOutput::Noop(_) => {
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
    Ensure {
        diffs: Vec<FieldDiff>,
        storage_class_unresolved: bool,
    },
    Unchanged,
}

impl ResourceAction {
    fn from_diff(diffs: Vec<FieldDiff>, storage_class_unresolved: bool) -> Self {
        if diffs.is_empty() && !storage_class_unresolved {
            Self::Unchanged
        } else {
            Self::Ensure {
                diffs,
                storage_class_unresolved,
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct FieldDiff {
    field: &'static str,
    old: String,
    new: String,
}

fn is_not_found_error(error: &RequestError) -> bool {
    error.has_error_code(ErrorCode::BasinNotFound)
        || error.has_error_code(ErrorCode::StreamNotFound)
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

fn format_sdk_retention_policy(rp: &s2_sdk::types::RetentionPolicy) -> String {
    match rp {
        s2_sdk::types::RetentionPolicy::Age(secs) => {
            humantime::format_duration(Duration::from_secs(*secs)).to_string()
        }
        s2_sdk::types::RetentionPolicy::Infinite => "infinite".to_string(),
        s2_sdk::types::RetentionPolicy::Unknown(name) => name.clone(),
        _ => "unknown".to_string(),
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

fn diff_basin_config(
    existing: &BasinConfig,
    desired: &BasinConfig,
    existing_default_storage_class: Option<&str>,
) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();

    if existing.stream_cipher() != desired.stream_cipher() {
        diffs.push(FieldDiff {
            field: "stream_cipher",
            old: existing
                .stream_cipher()
                .map(s2_sdk::types::EncryptionAlgorithm::as_str)
                .unwrap_or("none")
                .to_string(),
            new: desired
                .stream_cipher()
                .map(s2_sdk::types::EncryptionAlgorithm::as_str)
                .unwrap_or("none")
                .to_string(),
        });
    }

    if existing.create_stream_on_append() != desired.create_stream_on_append() {
        diffs.push(FieldDiff {
            field: "create_stream_on_append",
            old: existing.create_stream_on_append().to_string(),
            new: desired.create_stream_on_append().to_string(),
        });
    }

    if existing.create_stream_on_read() != desired.create_stream_on_read() {
        diffs.push(FieldDiff {
            field: "create_stream_on_read",
            old: existing.create_stream_on_read().to_string(),
            new: desired.create_stream_on_read().to_string(),
        });
    }

    let existing_dsc = resolve_existing_stream_config(
        existing
            .default_stream_config()
            .cloned()
            .unwrap_or_default(),
        existing_default_storage_class,
    );
    let desired_dsc = resolve_stream_config(
        desired.default_stream_config().cloned().unwrap_or_default(),
        Default::default(),
    );
    for sd in diff_stream_configs(&existing_dsc, &desired_dsc) {
        diffs.push(FieldDiff {
            field: default_stream_config_field(sd.field),
            old: sd.old,
            new: sd.new,
        });
    }

    diffs
}

fn resolve_existing_stream_config(
    existing: StreamConfig,
    fallback_storage_class: Option<&str>,
) -> ResolvedStreamConfig {
    let mut defaults = StreamConfig::new();
    if let Some(sc) = fallback_storage_class {
        defaults = defaults.with_storage_class(sc.to_owned());
    }
    resolve_stream_config(existing, defaults)
}

fn diff_stream_configs(
    existing: &ResolvedStreamConfig,
    desired: &ResolvedStreamConfig,
) -> Vec<FieldDiff> {
    let mut diffs = Vec::new();

    if let Some(storage_class) = &desired.storage_class
        && existing.storage_class.as_ref() != Some(storage_class)
    {
        diffs.push(FieldDiff {
            field: "storage_class",
            old: existing
                .storage_class
                .as_deref()
                .unwrap_or("unspecified")
                .to_owned(),
            new: storage_class.to_string(),
        });
    }

    if existing.retention_policy != desired.retention_policy {
        diffs.push(FieldDiff {
            field: "retention_policy",
            old: format_sdk_retention_policy(&existing.retention_policy),
            new: format_sdk_retention_policy(&desired.retention_policy),
        });
    }

    if existing.timestamping_mode != desired.timestamping_mode {
        diffs.push(FieldDiff {
            field: "timestamping.mode",
            old: existing.timestamping_mode.as_str().to_string(),
            new: desired.timestamping_mode.as_str().to_string(),
        });
    }

    if existing.timestamping_uncapped != desired.timestamping_uncapped {
        diffs.push(FieldDiff {
            field: "timestamping.uncapped",
            old: existing.timestamping_uncapped.to_string(),
            new: desired.timestamping_uncapped.to_string(),
        });
    }

    if existing.delete_on_empty_min_age != desired.delete_on_empty_min_age {
        diffs.push(FieldDiff {
            field: "delete_on_empty.min_age",
            old: humantime::format_duration(existing.delete_on_empty_min_age).to_string(),
            new: humantime::format_duration(desired.delete_on_empty_min_age).to_string(),
        });
    }

    diffs
}

fn spec_basin_fields(spec: &s2_resource_spec::BasinConfig) -> Vec<FieldDiff> {
    let mut fields = Vec::new();

    if let Some(algorithm) = spec.stream_cipher.clone().map(encryption_algorithm_to_sdk) {
        fields.push(FieldDiff {
            field: "stream_cipher",
            old: String::new(),
            new: algorithm.as_str().to_string(),
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
            new: sc.to_string(),
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
        ResourceAction::Ensure {
            diffs,
            storage_class_unresolved,
        } => {
            let marker = if diffs.is_empty() { "?" } else { "~" };
            println!("{}", format!("{marker} basin {basin}").yellow().bold());
            for diff in diffs {
                println!("    {}: {} → {}", diff.field, diff.old.dimmed(), diff.new);
            }
            if *storage_class_unresolved {
                println!("    default_stream_config.storage_class: resolved at apply");
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
        ResourceAction::Ensure {
            diffs,
            storage_class_unresolved,
        } => {
            let marker = if diffs.is_empty() { "?" } else { "~" };
            println!(
                "{}",
                format!("  {marker} stream {basin}/{stream}")
                    .yellow()
                    .bold()
            );
            for diff in diffs {
                println!("      {}: {} → {}", diff.field, diff.old.dimmed(), diff.new);
            }
            if *storage_class_unresolved {
                println!("      storage_class: resolved at apply");
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

    let mut location_defaults: Option<Option<HashMap<LocationName, Option<String>>>> = None;

    for basin_spec in spec.basins {
        let raw_desired_basin_config = basin_spec
            .config
            .clone()
            .map(basin_config_to_sdk)
            .unwrap_or_default();
        let mut desired_basin_defaults = raw_desired_basin_config
            .default_stream_config()
            .cloned()
            .unwrap_or_default();
        let basin_spec_omits_storage_class = desired_basin_defaults.storage_class().is_none();

        let (basin_action, existing_basin_storage_class, basin_default_storage_class) = match s2
            .get_basin_config(basin_spec.name.clone())
            .await
        {
            Ok(existing) => {
                let basin_default_storage_class = if basin_spec_omits_storage_class {
                    let location =
                        ops::basin_location(s2, &basin_spec.name)
                            .await
                            .map_err(|error| {
                                miette::miette!(
                                    "failed to look up location for basin {:?}: {error}",
                                    basin_spec.name.as_ref()
                                )
                            })?;
                    match location {
                        Some(location) => {
                            let map = match &location_defaults {
                                Some(map) => map.as_ref(),
                                None => {
                                    let fetched = ops::list_locations_optional(s2)
                                            .await
                                            .map_err(|error| {
                                                miette::miette!(
                                                    "failed to list locations for default storage class: {error}"
                                                )
                                            })?
                                            .map(|locations| {
                                                locations
                                                    .into_iter()
                                                    .map(|loc| {
                                                        (loc.name, loc.default_storage_class)
                                                    })
                                                    .collect::<HashMap<_, _>>()
                                            });
                                    location_defaults = Some(fetched);
                                    location_defaults.as_ref().and_then(Option::as_ref)
                                }
                            };
                            map.and_then(|map| map.get(&location).cloned().flatten())
                        }
                        None => None,
                    }
                } else {
                    None
                };

                if basin_spec_omits_storage_class && let Some(ref sc) = basin_default_storage_class
                {
                    desired_basin_defaults = desired_basin_defaults.with_storage_class(sc.clone());
                }
                let desired_basin_config = raw_desired_basin_config
                    .with_default_stream_config(desired_basin_defaults.clone());

                let existing_sc = existing
                    .default_stream_config()
                    .and_then(|c| c.storage_class())
                    .map(str::to_owned);
                let existing_default_sc = basin_spec_omits_storage_class
                    .then_some(basin_default_storage_class.as_deref())
                    .flatten();
                let diffs =
                    diff_basin_config(&existing, &desired_basin_config, existing_default_sc);
                let action = ResourceAction::from_diff(
                    diffs,
                    desired_basin_defaults.storage_class().is_none(),
                );
                (action, existing_sc, basin_default_storage_class)
            }
            Err(e) if is_not_found_error(&e) => (ResourceAction::Create, None, None),
            Err(e) => {
                return Err(miette::miette!(
                    "failed to check basin {:?}: {}",
                    basin_spec.name.as_ref(),
                    e
                ));
            }
        };

        match &basin_action {
            ResourceAction::Create => {
                print_basin_create(basin_spec.name.as_ref(), &basin_spec.config);
            }
            action => {
                print_basin_result(basin_spec.name.as_ref(), action);
            }
        }

        let basin_client = s2.basin(basin_spec.name.clone());

        for stream_spec in basin_spec.streams {
            let stream_action = match basin_client
                .get_stream_config(stream_spec.name.clone())
                .await
            {
                Ok(existing) => {
                    let desired_raw = stream_spec
                        .config
                        .clone()
                        .map(stream_config_to_sdk)
                        .unwrap_or_default();
                    let desired_uses_location_default =
                        desired_raw.storage_class().is_none() && basin_spec_omits_storage_class;
                    let existing_fallback_sc =
                        existing_basin_storage_class.as_deref().or_else(|| {
                            desired_uses_location_default
                                .then_some(basin_default_storage_class.as_deref())
                                .flatten()
                        });
                    let existing = resolve_existing_stream_config(existing, existing_fallback_sc);
                    let desired_stream_config =
                        resolve_stream_config(desired_raw, desired_basin_defaults.clone());
                    let diffs = diff_stream_configs(&existing, &desired_stream_config);
                    ResourceAction::from_diff(diffs, desired_stream_config.storage_class.is_none())
                }
                Err(e) if is_not_found_error(&e) => ResourceAction::Create,
                Err(e) => {
                    return Err(miette::miette!(
                        "failed to check stream {:?}/{:?}: {}",
                        basin_spec.name.as_ref(),
                        stream_spec.name.as_ref(),
                        e
                    ));
                }
            };

            match &stream_action {
                ResourceAction::Create => {
                    print_stream_create(
                        basin_spec.name.as_ref(),
                        stream_spec.name.as_ref(),
                        &stream_spec.config,
                    );
                }
                action => {
                    print_stream_result(
                        basin_spec.name.as_ref(),
                        stream_spec.name.as_ref(),
                        action,
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use s2_sdk::types::{BasinConfig, StreamConfig};

    use super::{
        FieldDiff, diff_basin_config, diff_stream_configs, resolve_existing_stream_config,
    };
    use crate::types::resolve_stream_config;

    #[test]
    fn omitted_basin_storage_class_with_location_default_has_no_diff() {
        let existing = BasinConfig::new();
        let desired = BasinConfig::new()
            .with_default_stream_config(StreamConfig::new().with_storage_class("express"));

        let diffs = diff_basin_config(&existing, &desired, Some("express"));
        assert!(diffs.is_empty(), "expected no diffs, got {diffs:?}");
    }

    #[test]
    fn explicit_basin_storage_class_against_unspecified_existing_reports_diff() {
        let existing = BasinConfig::new();
        let desired = BasinConfig::new()
            .with_default_stream_config(StreamConfig::new().with_storage_class("express"));

        let diffs = diff_basin_config(&existing, &desired, None);
        assert_eq!(
            diffs,
            vec![FieldDiff {
                field: "default_stream_config.storage_class",
                old: "unspecified".to_owned(),
                new: "express".to_owned(),
            }]
        );
    }

    #[test]
    fn stored_basin_storage_class_differing_from_location_default_reports_diff() {
        let existing = BasinConfig::new()
            .with_default_stream_config(StreamConfig::new().with_storage_class("standard"));
        let desired = BasinConfig::new()
            .with_default_stream_config(StreamConfig::new().with_storage_class("express"));

        let diffs = diff_basin_config(&existing, &desired, Some("express"));
        assert_eq!(
            diffs,
            vec![FieldDiff {
                field: "default_stream_config.storage_class",
                old: "standard".to_owned(),
                new: "express".to_owned(),
            }]
        );
    }

    #[test]
    fn omitted_stream_storage_class_resolves_symmetrically_against_inherited_default() {
        let existing = resolve_existing_stream_config(StreamConfig::new(), Some("express"));
        let desired = resolve_stream_config(
            StreamConfig::new(),
            StreamConfig::new().with_storage_class("express"),
        );

        assert!(diff_stream_configs(&existing, &desired).is_empty());

        let existing_standard = resolve_existing_stream_config(
            StreamConfig::new().with_storage_class("standard"),
            Some("express"),
        );
        assert_eq!(
            diff_stream_configs(&existing_standard, &desired),
            vec![FieldDiff {
                field: "storage_class",
                old: "standard".to_owned(),
                new: "express".to_owned(),
            }]
        );
    }
}
