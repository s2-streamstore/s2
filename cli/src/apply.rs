//! Declarative basin/stream configuration via a JSON spec file.

use std::path::Path;

use colored::Colorize;
use s2_lite::init::{
    BasinConfigSpec, DeleteOnEmptySpec, ResourcesSpec, RetentionPolicySpec, StorageClassSpec,
    StreamConfigSpec, TimestampingModeSpec, TimestampingSpec,
};
use s2_sdk::{
    S2,
    types::{
        BasinConfig, BasinName, CreateOrReconfigureBasinInput, CreateOrReconfigureStreamInput,
        CreateOrReconfigured, DeleteOnEmptyConfig, RetentionPolicy, StorageClass, StreamConfig,
        StreamName, TimestampingConfig, TimestampingMode,
    },
};

fn stream_config_to_sdk(s: StreamConfigSpec) -> StreamConfig {
    let mut c = StreamConfig::new();
    if let Some(sc) = s.storage_class {
        c = c.with_storage_class(storage_class_to_sdk(sc));
    }
    if let Some(rp) = s.retention_policy {
        c = c.with_retention_policy(retention_policy_to_sdk(rp));
    }
    if let Some(ts) = s.timestamping {
        c = c.with_timestamping(timestamping_to_sdk(ts));
    }
    if let Some(doe) = s.delete_on_empty {
        c = c.with_delete_on_empty(delete_on_empty_to_sdk(doe));
    }
    c
}

fn basin_config_to_sdk(s: BasinConfigSpec) -> BasinConfig {
    let mut c = BasinConfig::new();
    if let Some(dsc) = s.default_stream_config {
        c = c.with_default_stream_config(stream_config_to_sdk(dsc));
    }
    if let Some(v) = s.create_stream_on_append {
        c = c.with_create_stream_on_append(v);
    }
    if let Some(v) = s.create_stream_on_read {
        c = c.with_create_stream_on_read(v);
    }
    c
}

fn storage_class_to_sdk(s: StorageClassSpec) -> StorageClass {
    match s {
        StorageClassSpec::Standard => StorageClass::Standard,
        StorageClassSpec::Express => StorageClass::Express,
    }
}

fn retention_policy_to_sdk(rp: RetentionPolicySpec) -> RetentionPolicy {
    match rp.age_secs() {
        Some(secs) => RetentionPolicy::Age(secs),
        None => RetentionPolicy::Infinite,
    }
}

fn timestamping_mode_to_sdk(m: TimestampingModeSpec) -> TimestampingMode {
    match m {
        TimestampingModeSpec::ClientPrefer => TimestampingMode::ClientPrefer,
        TimestampingModeSpec::ClientRequire => TimestampingMode::ClientRequire,
        TimestampingModeSpec::Arrival => TimestampingMode::Arrival,
    }
}

fn timestamping_to_sdk(ts: TimestampingSpec) -> TimestampingConfig {
    let mut tsc = TimestampingConfig::new();
    if let Some(m) = ts.mode {
        tsc = tsc.with_mode(timestamping_mode_to_sdk(m));
    }
    if let Some(u) = ts.uncapped {
        tsc = tsc.with_uncapped(u);
    }
    tsc
}

fn delete_on_empty_to_sdk(doe: DeleteOnEmptySpec) -> DeleteOnEmptyConfig {
    let mut doec = DeleteOnEmptyConfig::new();
    if let Some(ma) = doe.min_age {
        doec = doec.with_min_age(ma.0);
    }
    doec
}

pub fn load(path: &Path) -> miette::Result<ResourcesSpec> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| miette::miette!("failed to read spec file {:?}: {}", path.display(), e))?;
    let spec: ResourcesSpec = serde_json::from_str(&contents)
        .map_err(|e| miette::miette!("failed to parse spec file {:?}: {}", path.display(), e))?;
    Ok(spec)
}

pub async fn apply(s2: &S2, spec: ResourcesSpec) -> miette::Result<()> {
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
    let mut input = CreateOrReconfigureBasinInput::new(basin.clone());
    if let Some(c) = config {
        input = input.with_config(basin_config_to_sdk(c));
    }
    match s2
        .create_or_reconfigure_basin(input)
        .await
        .map_err(|e| miette::miette!("failed to apply basin {:?}: {}", basin.as_ref(), e))?
    {
        CreateOrReconfigured::Created(_) => {
            eprintln!("{}", format!("  basin {basin}").green().bold());
        }
        CreateOrReconfigured::Reconfigured(_) => {
            eprintln!(
                "{}",
                format!("  basin {basin} (reconfigured)").yellow().bold()
            );
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
    let mut input = CreateOrReconfigureStreamInput::new(stream.clone());
    if let Some(c) = config {
        input = input.with_config(stream_config_to_sdk(c));
    }
    let basin_client = s2.basin(basin.clone());
    match basin_client
        .create_or_reconfigure_stream(input)
        .await
        .map_err(|e| {
            miette::miette!(
                "failed to apply stream {:?}/{:?}: {}",
                basin.as_ref(),
                stream.as_ref(),
                e
            )
        })? {
        CreateOrReconfigured::Created(_) => {
            eprintln!("{}", format!("  stream {basin}/{stream}").green().bold());
        }
        CreateOrReconfigured::Reconfigured(_) => {
            eprintln!(
                "{}",
                format!("  stream {basin}/{stream} (reconfigured)")
                    .yellow()
                    .bold()
            );
        }
    }
    Ok(())
}
