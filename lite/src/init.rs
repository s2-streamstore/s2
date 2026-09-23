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

    let basins = spec
        .basins
        .into_iter()
        .map(|basin| {
            let config = basin
                .config
                .map(BasinConfig::try_from)
                .transpose()?
                .unwrap_or_default();
            let streams = basin
                .streams
                .into_iter()
                .map(|stream| {
                    let config = stream
                        .config
                        .map(OptionalStreamConfig::try_from)
                        .transpose()?
                        .unwrap_or_default();
                    Ok((stream.name, config))
                })
                .collect::<Result<Vec<_>, s2_common::ValidationError>>()?;
            Ok((basin.name, config, streams))
        })
        .collect::<Result<Vec<_>, s2_common::ValidationError>>()?;

    for (basin, config, streams) in basins {
        backend
            .provision_basin(basin.clone(), config, ProvisionMode::Ensure)
            .await
            .map_err(|e| eyre::eyre!("failed to apply basin {:?}: {}", basin.as_ref(), e))?;

        info!(basin = basin.as_ref(), "basin applied");

        for (stream, config) in streams {
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
