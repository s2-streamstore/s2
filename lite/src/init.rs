//! Declarative basin/stream initialization from a JSON spec file.
//!
//! Loaded at startup when `--init-file` / `S2LITE_INIT_FILE` is set.

use std::path::Path;

use s2_common::{
    basin::BasinName,
    config::{BasinConfig, OptionalStreamConfig},
    resources::ProvisionMode,
    stream::StreamName,
};
use s2_resource_spec as resource_spec;
use tracing::info;

use crate::backend::Backend;

pub fn load(path: &Path) -> eyre::Result<resource_spec::Resources> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("failed to read init file {:?}: {}", path, e))?;
    let spec: resource_spec::Resources = serde_json::from_str(&contents)
        .map_err(|e| eyre::eyre!("failed to parse init file {:?}: {}", path, e))?;
    Ok(spec)
}

pub async fn apply(backend: &Backend, spec: resource_spec::Resources) -> eyre::Result<()> {
    resource_spec::validate(&spec).map_err(|e| eyre::eyre!(e))?;

    for basin_spec in spec.basins {
        let basin: BasinName = basin_spec
            .name
            .parse()
            .map_err(|e| eyre::eyre!("invalid basin name {:?}: {}", basin_spec.name, e))?;

        let config = basin_spec.config.map(BasinConfig::from).unwrap_or_default();

        backend
            .provision_basin(basin.clone(), config, ProvisionMode::Ensure)
            .await
            .map_err(|e| eyre::eyre!("failed to apply basin {:?}: {}", basin.as_ref(), e))?;

        info!(basin = basin.as_ref(), "basin applied");

        for stream_spec in basin_spec.streams {
            let stream: StreamName = stream_spec
                .name
                .parse()
                .map_err(|e| eyre::eyre!("invalid stream name {:?}: {}", stream_spec.name, e))?;

            let config = stream_spec
                .config
                .map(OptionalStreamConfig::from)
                .unwrap_or_default();

            backend
                .provision_stream(basin.clone(), stream.clone(), config, ProvisionMode::Ensure)
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
