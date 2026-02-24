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
        BasinName, BasinReconfiguration, CreateBasinInput, CreateStreamInput, DeleteOnEmptyConfig,
        DeleteOnEmptyReconfiguration, ErrorResponse, ReconfigureBasinInput, ReconfigureStreamInput,
        S2Error, StreamName, StreamReconfiguration, TimestampingConfig, TimestampingReconfiguration,
    },
};

fn stream_config_to_sdk(s: StreamConfigSpec) -> s2_sdk::types::StreamConfig {
    let mut c = s2_sdk::types::StreamConfig::new();
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

fn basin_config_to_sdk(s: BasinConfigSpec) -> s2_sdk::types::BasinConfig {
    let mut c = s2_sdk::types::BasinConfig::new();
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

fn stream_config_to_reconfig(s: StreamConfigSpec) -> StreamReconfiguration {
    let mut r = StreamReconfiguration::new();
    if let Some(sc) = s.storage_class {
        r = r.with_storage_class(storage_class_to_sdk(sc));
    }
    if let Some(rp) = s.retention_policy {
        r = r.with_retention_policy(retention_policy_to_sdk(rp));
    }
    if let Some(ts) = s.timestamping {
        let mut tsr = TimestampingReconfiguration::new();
        if let Some(m) = ts.mode {
            tsr = tsr.with_mode(timestamping_mode_to_sdk(m));
        }
        if let Some(u) = ts.uncapped {
            tsr = tsr.with_uncapped(u);
        }
        r = r.with_timestamping(tsr);
    }
    if let Some(doe) = s.delete_on_empty {
        let mut doer = DeleteOnEmptyReconfiguration::new();
        if let Some(ma) = doe.min_age {
            doer = doer.with_min_age(ma.0);
        }
        r = r.with_delete_on_empty(doer);
    }
    r
}

fn basin_config_to_reconfig(s: BasinConfigSpec) -> BasinReconfiguration {
    let mut r = BasinReconfiguration::new();
    if let Some(dsc) = s.default_stream_config {
        r = r.with_default_stream_config(stream_config_to_reconfig(dsc));
    }
    if let Some(v) = s.create_stream_on_append {
        r = r.with_create_stream_on_append(v);
    }
    if let Some(v) = s.create_stream_on_read {
        r = r.with_create_stream_on_read(v);
    }
    r
}

fn storage_class_to_sdk(s: StorageClassSpec) -> s2_sdk::types::StorageClass {
    match s {
        StorageClassSpec::Standard => s2_sdk::types::StorageClass::Standard,
        StorageClassSpec::Express => s2_sdk::types::StorageClass::Express,
    }
}

fn retention_policy_to_sdk(rp: RetentionPolicySpec) -> s2_sdk::types::RetentionPolicy {
    match rp.age_secs() {
        Some(secs) => s2_sdk::types::RetentionPolicy::Age(secs),
        None => s2_sdk::types::RetentionPolicy::Infinite,
    }
}

fn timestamping_mode_to_sdk(m: TimestampingModeSpec) -> s2_sdk::types::TimestampingMode {
    match m {
        TimestampingModeSpec::ClientPrefer => s2_sdk::types::TimestampingMode::ClientPrefer,
        TimestampingModeSpec::ClientRequire => s2_sdk::types::TimestampingMode::ClientRequire,
        TimestampingModeSpec::Arrival => s2_sdk::types::TimestampingMode::Arrival,
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

fn is_already_exists(err: &S2Error) -> bool {
    matches!(
        err,
        S2Error::Server(ErrorResponse { code, .. }) if code == "resource_already_exists"
    )
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
    let sdk_config = config
        .as_ref()
        .cloned()
        .map(basin_config_to_sdk)
        .unwrap_or_default();

    let input = CreateBasinInput::new(basin.clone()).with_config(sdk_config);
    match s2.create_basin(input).await {
        Ok(_) => {
            eprintln!("{}", format!("  basin {basin}").green().bold());
        }
        Err(ref e) if is_already_exists(e) => {
            let reconfig = config.map(basin_config_to_reconfig).unwrap_or_default();
            s2.reconfigure_basin(ReconfigureBasinInput::new(basin.clone(), reconfig))
                .await
                .map_err(|e| {
                    miette::miette!("failed to reconfigure basin {:?}: {}", basin.as_ref(), e)
                })?;
            eprintln!(
                "{}",
                format!("  basin {basin} (reconfigured)").yellow().bold()
            );
        }
        Err(e) => {
            return Err(miette::miette!(
                "failed to create basin {:?}: {}",
                basin.as_ref(),
                e
            ));
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
    let sdk_config = config
        .as_ref()
        .cloned()
        .map(stream_config_to_sdk)
        .unwrap_or_default();

    let basin_client = s2.basin(basin.clone());
    let input = CreateStreamInput::new(stream.clone()).with_config(sdk_config);
    match basin_client.create_stream(input).await {
        Ok(_) => {
            eprintln!("{}", format!("  stream {basin}/{stream}").green().bold());
        }
        Err(ref e) if is_already_exists(e) => {
            let reconfig = config.map(stream_config_to_reconfig).unwrap_or_default();
            basin_client
                .reconfigure_stream(ReconfigureStreamInput::new(stream.clone(), reconfig))
                .await
                .map_err(|e| {
                    miette::miette!(
                        "failed to reconfigure stream {:?}/{:?}: {}",
                        basin.as_ref(),
                        stream.as_ref(),
                        e
                    )
                })?;
            eprintln!(
                "{}",
                format!("  stream {basin}/{stream} (reconfigured)")
                    .yellow()
                    .bold()
            );
        }
        Err(e) => {
            return Err(miette::miette!(
                "failed to create stream {:?}/{:?}: {}",
                basin.as_ref(),
                stream.as_ref(),
                e
            ));
        }
    }
    Ok(())
}
