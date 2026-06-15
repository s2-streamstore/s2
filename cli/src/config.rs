use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use config::{Config, FileFormat};
use s2_sdk::{
    self as sdk,
    types::{AccountEndpoint, BasinEndpoint, S2Config, S2Endpoints},
};
use serde::{Deserialize, Serialize};

use crate::error::{CliConfigError, CliError, TokenSource};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, strum::Display, strum::EnumString,
)]
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
    save_cli_config_to_path(config, &path)?;
    Ok(path)
}

fn save_cli_config_to_path(config: &CliConfig, path: &Path) -> Result<(), CliConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(CliConfigError::Write)?;
        secure_config_dir(parent).map_err(CliConfigError::Write)?;
    }

    let toml = toml::to_string(config).map_err(CliConfigError::Serialize)?;
    write_config_file(path, &toml).map_err(CliConfigError::Write)?;

    Ok(())
}

#[cfg(unix)]
fn secure_config_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn secure_config_dir(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn write_config_file(path: &Path, toml: &str) -> std::io::Result<()> {
    use std::{
        io::Write,
        os::unix::fs::{OpenOptionsExt, PermissionsExt},
    };

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(toml.as_bytes())
}

#[cfg(not(unix))]
fn write_config_file(path: &Path, toml: &str) -> std::io::Result<()> {
    std::fs::write(path, toml)
}

pub fn set_config_value(key: ConfigKey, value: String) -> Result<PathBuf, CliConfigError> {
    let mut config = load_config_file()?;
    config.set(key, value)?;
    save_cli_config(&config)
}

pub fn unset_config_value(key: ConfigKey) -> Result<PathBuf, CliConfigError> {
    let mut config = load_config_file()?;
    config.unset(key);
    save_cli_config(&config)
}

pub fn sdk_config(config: &CliConfig, user_agent: &str) -> Result<S2Config, CliError> {
    let access_token = config
        .access_token
        .as_ref()
        .ok_or(CliConfigError::MissingAccessToken)?;

    let compression: sdk::types::Compression = config
        .compression
        .map(Into::into)
        .unwrap_or(sdk::types::Compression::None);

    let mut sdk_config = S2Config::new(access_token)
        .with_user_agent(user_agent)
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

pub fn access_token_source(config: &CliConfig) -> Option<TokenSource> {
    let has_env_token = std::env::vars_os().any(|(key, _)| {
        key.to_str()
            .map(|k| k.eq_ignore_ascii_case("S2_ACCESS_TOKEN"))
            .unwrap_or(false)
    });
    if has_env_token {
        return Some(TokenSource::Environment);
    }

    if config.access_token.is_some() {
        Some(TokenSource::ConfigFile)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::metadata(path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(unix)]
    #[test]
    fn save_cli_config_creates_config_with_private_permissions() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let path = temp_dir.path().join(".config/s2/config.toml");
        let config = CliConfig {
            access_token: Some("secret".to_owned()),
            ..Default::default()
        };

        save_cli_config_to_path(&config, &path).expect("save config");

        assert_eq!(mode(path.parent().expect("parent")), 0o700);
        assert_eq!(mode(&path), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn save_cli_config_tightens_existing_config_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let parent = temp_dir.path().join(".config/s2");
        let path = parent.join("config.toml");
        std::fs::create_dir_all(&parent).expect("create parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))
            .expect("set parent permissions");
        std::fs::write(&path, "access_token = \"old\"").expect("write existing config");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("set file permissions");
        let config = CliConfig {
            access_token: Some("new".to_owned()),
            ..Default::default()
        };

        save_cli_config_to_path(&config, &path).expect("save config");

        assert_eq!(mode(&parent), 0o700);
        assert_eq!(mode(&path), 0o600);
    }
}
