//! Testcontainers helpers for the S2 CLI image, with a paved path for s2-lite.
//!
//! ```no_run
//! use s2_testcontainers::S2Lite;
//!
//! #[tokio::test]
//! async fn test_with_s2_lite() -> s2_testcontainers::Result<()> {
//!     let s2 = S2Lite::start().await?;
//!
//!     let client = s2.client()?;
//!     let basin = s2.ensure_basin("test-basin").await?;
//!     let stream = s2.ensure_stream(&basin, "test-stream").await?;
//!
//!     // Use `client`, `basin`, `stream`, and `s2.endpoint()`.
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]

use std::time::Duration;

use s2_sdk::{
    S2,
    types::{
        AccountEndpoint, BasinEndpoint, BasinName, EnsureBasinInput, EnsureStreamInput, S2Config,
        S2Endpoints, S2Error, StreamName, ValidationError,
    },
};
use testcontainers::{
    ContainerAsync, ContainerRequest, GenericImage, ImageExt, TestcontainersError,
    core::IntoContainerPort, runners::AsyncRunner,
};
use tokio::time::{Instant, sleep, timeout};

/// Image repository for the S2 CLI image that embeds s2-lite.
pub const IMAGE: &str = "ghcr.io/s2-streamstore/s2";
/// Default S2 image tag.
pub const DEFAULT_TAG: &str = env!("CARGO_PKG_VERSION");
/// Port exposed by s2-lite.
pub const PORT: u16 = 80;
/// Default access token used by [`S2Lite::client`].
pub const DEFAULT_ACCESS_TOKEN: &str = "ignored";

const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const HEALTH_POLL_INTERVAL: Duration = Duration::from_millis(100);
const HEALTH_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Result type for this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors from s2-testcontainers helpers.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error from Testcontainers.
    #[error("testcontainers error: {0}")]
    Testcontainers(#[from] TestcontainersError),
    /// Error from the S2 SDK.
    #[error("s2 sdk error: {0}")]
    S2(#[from] S2Error),
    /// S2 endpoint or resource name validation error.
    #[error("validation error: {0}")]
    Validation(#[from] ValidationError),
    /// s2-lite did not become healthy before the startup timeout.
    #[error("s2-lite did not become healthy at {endpoint}")]
    NotHealthy {
        /// Endpoint that did not become healthy.
        endpoint: String,
    },
}

/// Running s2-lite Testcontainers instance.
#[derive(Debug)]
pub struct S2Lite {
    container: ContainerAsync<GenericImage>,
    endpoint: String,
}

impl S2Lite {
    /// Start s2-lite with the default image tag.
    pub async fn start() -> Result<Self> {
        Self::start_with(DEFAULT_TAG).await
    }

    /// Start s2-lite with a specific image tag.
    pub async fn start_with(tag: impl Into<String>) -> Result<Self> {
        let container = s2_lite_image_with_tag(tag).start().await?;
        let host = container.get_host().await?;
        let port = container.get_host_port_ipv4(PORT).await?;
        let endpoint = format!("http://{host}:{port}");

        wait_until_healthy(&endpoint).await?;

        Ok(Self {
            container,
            endpoint,
        })
    }

    /// Return the mapped HTTP endpoint for this s2-lite instance.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Build an [`S2Config`] for this s2-lite instance with the provided access token.
    pub fn config(&self, access_token: impl Into<String>) -> Result<S2Config> {
        s2_config_for_endpoint(&self.endpoint, access_token)
    }

    /// Build an [`S2`] client for this s2-lite instance.
    pub fn client(&self) -> Result<S2> {
        Ok(S2::new(self.config(DEFAULT_ACCESS_TOKEN)?)?)
    }

    /// Ensure a basin exists and return its validated name.
    pub async fn ensure_basin(&self, name: impl AsRef<str>) -> Result<BasinName> {
        let name = name.as_ref().parse::<BasinName>()?;
        self.client()?
            .ensure_basin(EnsureBasinInput::new(name.clone()))
            .await?;
        Ok(name)
    }

    /// Ensure a stream exists in a basin and return its validated name.
    pub async fn ensure_stream(
        &self,
        basin: &BasinName,
        name: impl AsRef<str>,
    ) -> Result<StreamName> {
        let name = name.as_ref().parse::<StreamName>()?;
        self.client()?
            .basin(basin.clone())
            .ensure_stream(EnsureStreamInput::new(name.clone()))
            .await?;
        Ok(name)
    }

    /// Return the underlying Testcontainers container.
    pub fn container(&self) -> &ContainerAsync<GenericImage> {
        &self.container
    }
}

/// Return the default S2 CLI [`GenericImage`].
pub fn s2_image() -> GenericImage {
    s2_image_with_tag(DEFAULT_TAG)
}

/// Return an S2 CLI [`GenericImage`] with a specific tag.
pub fn s2_image_with_tag(tag: impl Into<String>) -> GenericImage {
    GenericImage::new(IMAGE.to_string(), tag.into())
}

/// Return the default S2 CLI [`ContainerRequest`] configured to run `s2 lite`.
pub fn s2_lite_image() -> ContainerRequest<GenericImage> {
    s2_lite_image_with_tag(DEFAULT_TAG)
}

/// Return an S2 CLI [`ContainerRequest`] with a specific tag configured to run `s2 lite`.
pub fn s2_lite_image_with_tag(tag: impl Into<String>) -> ContainerRequest<GenericImage> {
    s2_image_with_tag(tag)
        .with_exposed_port(PORT.tcp())
        .with_cmd(["lite"])
}

/// Build an [`S2Config`] wired to use an endpoint for both account and basin APIs.
pub fn s2_config_for_endpoint(
    endpoint: impl AsRef<str>,
    access_token: impl Into<String>,
) -> Result<S2Config> {
    let endpoint = endpoint.as_ref();
    let endpoints = S2Endpoints::new(
        AccountEndpoint::new(endpoint)?,
        BasinEndpoint::new(endpoint)?,
    )?;

    Ok(S2Config::new(access_token).with_endpoints(endpoints))
}

async fn wait_until_healthy(endpoint: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let health_url = format!("{endpoint}/health");
    let deadline = Instant::now() + HEALTH_TIMEOUT;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(Error::NotHealthy {
                endpoint: endpoint.to_string(),
            });
        }

        let request_timeout = HEALTH_REQUEST_TIMEOUT.min(deadline - now);
        if let Ok(Ok(response)) = timeout(request_timeout, client.get(&health_url).send()).await
            && response.status().is_success()
        {
            return Ok(());
        }

        let now = Instant::now();
        if now >= deadline {
            return Err(Error::NotHealthy {
                endpoint: endpoint.to_string(),
            });
        }

        sleep(HEALTH_POLL_INTERVAL.min(deadline - now)).await;
    }
}

#[cfg(test)]
mod tests {
    use testcontainers::Image;

    use super::*;

    #[test]
    fn s2_image_defaults_to_versioned_cli_image() {
        let image = s2_image_with_tag("test-tag");

        assert_eq!(image.name(), IMAGE);
        assert_eq!(image.tag(), "test-tag");
        assert!(image.expose_ports().is_empty());
    }

    #[test]
    fn s2_lite_image_defaults_to_lite_command() {
        let request = s2_lite_image_with_tag("test-tag");

        assert_eq!(request.image().name(), IMAGE);
        assert_eq!(request.image().tag(), "test-tag");
        assert_eq!(request.image().expose_ports(), &[PORT.tcp()]);
        assert_eq!(request.cmd().collect::<Vec<_>>(), ["lite"]);
    }

    #[tokio::test]
    async fn config_uses_same_endpoint_for_account_and_basin() {
        let config = s2_config_for_endpoint("http://localhost:8080", "ignored").unwrap();

        S2::new(config).unwrap();
    }

    #[tokio::test]
    #[ignore = "requires Docker and the S2 CLI image"]
    async fn starts_s2_lite_and_ensures_resources() {
        let s2 = S2Lite::start().await.unwrap();

        let _client = s2.client().unwrap();
        let basin = s2.ensure_basin("test-basin").await.unwrap();
        let stream = s2.ensure_stream(&basin, "test-stream").await.unwrap();

        assert_eq!(basin.as_ref(), "test-basin");
        assert_eq!(stream.as_ref(), "test-stream");
    }
}
