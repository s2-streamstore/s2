use std::{path::PathBuf, time::Duration};

use config::{Config, FileFormat};
use s2_sdk::{
    self as sdk,
    types::{AccountEndpoint, BasinEndpoint, S2Config, S2Endpoints},
};
use serde::{Deserialize, Serialize};

use crate::error::{CliConfigError, CliError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, strum::Display, strum::EnumString)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Compression {
    Gzip,
    Zstd,
}

impl From<Compression> for sdk::types::Compression {
    fn from(value: Compression) -> Self {
        match value {
            Compression::Gzip => sdk::types::Compression::Gzip,
            Compression::Zstd => sdk::types::Compression::Zstd,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CliConfig {
    pub access_token: Option<String>,
    pub account_endpoint: Option<String>,
    pub basin_endpoint: Option<String>,
    pub compression: Option<Compression>,
    pub ssl_no_verify: Option<bool>,
}

#[cfg(target_os = "windows")]
fn config_path() -> Result<PathBuf, CliConfigError> {
    let mut path = dirs::config_dir().ok_or(CliConfigError::DirNotFound)?;
    path.push("s2");
    path.push("config.toml");
    Ok(path)
}

#[cfg(not(target_os = "windows"))]
fn config_path() -> Result<PathBuf, CliConfigError> {
    let mut path = dirs::home_dir().ok_or(CliConfigError::DirNotFound)?;
    path.push(".config");
    path.push("s2");
    path.push("config.toml");
    Ok(path)
}

pub fn load_config_file() -> Result<CliConfig, CliConfigError> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let builder = Config::builder().add_source(config::File::new(
        path.to_str().expect("config path is valid utf8"),
        FileFormat::Toml,
    ));
    Ok(builder.build()?.try_deserialize::<CliConfig>()?)
}

pub fn load_cli_config() -> Result<CliConfig, CliConfigError> {
    let path = config_path()?;
    let mut builder = Config::builder();
    if path.exists() {
        builder = builder.add_source(config::File::new(
            path.to_str().expect("config path is valid utf8"),
            FileFormat::Toml,
        ));
    }
    builder = builder.add_source(config::Environment::with_prefix("S2"));
    Ok(builder.build()?.try_deserialize::<CliConfig>()?)
}

#[derive(
    Debug, Clone, Copy, clap::ValueEnum, strum::Display, strum::EnumString, strum::VariantNames,
)]
#[clap(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ConfigKey {
    AccessToken,
    AccountEndpoint,
    BasinEndpoint,
    Compression,
    SslNoVerify,
}

impl CliConfig {
    pub fn get(&self, key: ConfigKey) -> Option<String> {
        match key {
            ConfigKey::AccessToken => self.access_token.clone(),
            ConfigKey::AccountEndpoint => self.account_endpoint.clone(),
            ConfigKey::BasinEndpoint => self.basin_endpoint.clone(),
            ConfigKey::Compression => self.compression.map(|c| c.to_string()),
            ConfigKey::SslNoVerify => self.ssl_no_verify.map(|v| v.to_string()),
        }
    }

    pub fn set(&mut self, key: ConfigKey, value: String) -> Result<(), CliConfigError> {
        match key {
            ConfigKey::AccessToken => self.access_token = Some(value),
            ConfigKey::AccountEndpoint => self.account_endpoint = Some(value),
            ConfigKey::BasinEndpoint => self.basin_endpoint = Some(value),
            ConfigKey::Compression => {
                self.compression = Some(
                    value
                        .parse()
                        .map_err(|_| CliConfigError::InvalidValue(key.to_string(), value))?,
                );
            }
            ConfigKey::SslNoVerify => {
                self.ssl_no_verify = Some(
                    value
                        .parse()
                        .map_err(|_| CliConfigError::InvalidValue(key.to_string(), value))?,
                );
            }
        }
        Ok(())
    }

    pub fn unset(&mut self, key: ConfigKey) {
        match key {
            ConfigKey::AccessToken => self.access_token = None,
            ConfigKey::AccountEndpoint => self.account_endpoint = None,
            ConfigKey::BasinEndpoint => self.basin_endpoint = None,
            ConfigKey::Compression => self.compression = None,
            ConfigKey::SslNoVerify => self.ssl_no_verify = None,
        }
    }
}

pub fn save_cli_config(config: &CliConfig) -> Result<PathBuf, CliConfigError> {
    let path = config_path()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(CliConfigError::Write)?;
    }

    let toml = toml::to_string(config).map_err(CliConfigError::Serialize)?;
    std::fs::write(&path, toml).map_err(CliConfigError::Write)?;

    Ok(path)
}

pub fn set_config_value(key: ConfigKey, value: String) -> Result<PathBuf, CliConfigError> {
    let mut config = load_config_file().unwrap_or_default();
    config.set(key, value)?;
    save_cli_config(&config)
}

pub fn unset_config_value(key: ConfigKey) -> Result<PathBuf, CliConfigError> {
    let mut config = load_config_file().unwrap_or_default();
    config.unset(key);
    save_cli_config(&config)
}

pub fn sdk_config(config: &CliConfig) -> Result<S2Config, CliError> {
    let access_token = config
        .access_token
        .as_ref()
        .ok_or(CliConfigError::MissingAccessToken)?;

    let compression: sdk::types::Compression = config
        .compression
        .map(Into::into)
        .unwrap_or(sdk::types::Compression::None);

    let mut sdk_config = S2Config::new(access_token)
        .with_user_agent("s2-cli")
        .expect("valid user agent")
        .with_request_timeout(Duration::from_secs(30))
        .with_compression(compression);

    match (&config.account_endpoint, &config.basin_endpoint) {
        (Some(account_endpoint_str), Some(basin_endpoint_str)) => {
            let account_endpoint = AccountEndpoint::new(account_endpoint_str)
                .map_err(|e| CliError::EndpointsFromEnv(e.to_string()))?;
            let basin_endpoint = BasinEndpoint::new(basin_endpoint_str)
                .map_err(|e| CliError::EndpointsFromEnv(e.to_string()))?;
            let endpoints = S2Endpoints::new(account_endpoint, basin_endpoint)
                .map_err(|e| CliError::EndpointsFromEnv(e.to_string()))?;
            sdk_config = sdk_config.with_endpoints(endpoints);
        }
        (Some(_), None) => {
            eprintln!(
                "Warning: account endpoint is set but basin endpoint is not. \
                 Both must be set to use custom endpoints. Using default endpoints"
            );
        }
        (None, Some(_)) => {
            eprintln!(
                "Warning: basin endpoint is set but account endpoint is not. \
                 Both must be set to use custom endpoints. Using default endpoints"
            );
        }
        (None, None) => {}
    }

    if config.ssl_no_verify == Some(true) {
        tracing::warn!("SSL certificate verification is disabled.");
        sdk_config = sdk_config.with_insecure_skip_cert_verification(true);
    }

    Ok(sdk_config)
}
