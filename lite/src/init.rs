//! Declarative basin/stream initialization from a JSON spec file.
//!
//! Loaded at startup when `--init-file` / `S2LITE_INIT_FILE` is set.

use std::path::Path;

use s2_common::{
    config::{BasinConfig, OptionalStreamConfig},
    resources::ProvisionMode,
};
use tracing::info;

use crate::backend::Backend;

pub fn load(path: &Path) -> eyre::Result<s2_resource_spec::Resources> {
    let contents = std::fs::read_to_string(path)
        .map_err(|e| eyre::eyre!("failed to read init file {:?}: {}", path, e))?;
    let spec: s2_resource_spec::Resources = serde_json::from_str(&contents)
        .map_err(|e| eyre::eyre!("failed to parse init file {:?}: {}", path, e))?;
    Ok(spec)
}

pub async fn apply(backend: &Backend, spec: s2_resource_spec::Resources) -> eyre::Result<()> {
    s2_resource_spec::validate(&spec).map_err(|e| eyre::eyre!(e))?;

    for basin_spec in spec.basins {
        let config = basin_spec.config.map(BasinConfig::from).unwrap_or_default();

        backend
            .provision_basin(basin_spec.name.clone(), config, ProvisionMode::Ensure)
            .await
            .map_err(|e| {
                eyre::eyre!(
                    "failed to apply basin {:?}: {}",
                    basin_spec.name.as_ref(),
                    e
                )
            })?;

        info!(basin = basin_spec.name.as_ref(), "basin applied");

        for stream_spec in basin_spec.streams {
            let config = stream_spec
                .config
                .map(OptionalStreamConfig::from)
                .unwrap_or_default();

            backend
                .provision_stream(
                    basin_spec.name.clone(),
                    stream_spec.name.clone(),
                    config,
                    ProvisionMode::Ensure,
                )
                .await
                .map_err(|e| {
                    eyre::eyre!(
                        "failed to apply stream {:?}/{:?}: {}",
                        basin_spec.name.as_ref(),
                        stream_spec.name.as_ref(),
                        e
                    )
                })?;

            info!(
                basin = basin_spec.name.as_ref(),
                stream = stream_spec.name.as_ref(),
                "stream applied"
            );
        }
    }
    Ok(())
}
