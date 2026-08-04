use std::{
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};

use config::{Config, FileFormat};
use s2_sdk::{
    self as sdk,
    types::{AccountEndpoint, BasinEndpoint, S2Config, S2Endpoints},
};
use serde::{Deserialize, Serialize};

use crate::error::{CliConfigError, CliError};

const CONFIG_LOCK_TIMEOUT: Duration = Duration::from_secs(60);

pub struct ConfigLock {
    file: File,
}

impl Drop for ConfigLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

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

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CliConfig {
    /// Legacy plaintext access token. New writes use `stored_access_token`.
    pub access_token: Option<String>,
    pub stored_access_token: Option<StoredCredentialReference>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pending_access_token_cleanup: Vec<StoredCredentialReference>,
    pub account_endpoint: Option<String>,
    pub basin_endpoint: Option<String>,
    pub compression: Option<Compression>,
    pub ssl_no_verify: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStore {
    Keyring,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCredentialReference {
    pub credential_id: String,
    pub credential_store: CredentialStore,
}

#[cfg(target_os = "windows")]
pub fn config_path() -> Result<PathBuf, CliConfigError> {
    let mut path = dirs::config_dir().ok_or(CliConfigError::DirNotFound)?;
    path.push("s2");
    path.push("config.toml");
    Ok(path)
}

#[cfg(not(target_os = "windows"))]
pub fn config_path() -> Result<PathBuf, CliConfigError> {
    let mut path = dirs::home_dir().ok_or(CliConfigError::DirNotFound)?;
    path.push(".config");
    path.push("s2");
    path.push("config.toml");
    Ok(path)
}

/// Returns the config file path as a displayable string, falling back to a
/// placeholder if the home directory cannot be determined. Used in user-facing
/// error messages where panicking would be inappropriate.
pub fn config_path_string() -> String {
    config_path()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "<config file>".to_string())
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
    // Validate the secret without putting an environment value in serializable config state.
    access_token_from_environment()?;
    let mut config = load_config_file()?;
    for (name, key) in [
        ("S2_ACCOUNT_ENDPOINT", ConfigKey::AccountEndpoint),
        ("S2_BASIN_ENDPOINT", ConfigKey::BasinEndpoint),
        ("S2_COMPRESSION", ConfigKey::Compression),
        ("S2_SSL_NO_VERIFY", ConfigKey::SslNoVerify),
    ] {
        if let Some(value) = environment_value(name)? {
            config.set(key, value)?;
        }
    }
    Ok(config)
}

fn environment_value(name: &'static str) -> Result<Option<String>, CliConfigError> {
    let Some(value) = std::env::var_os(name) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    value
        .into_string()
        .map(Some)
        .map_err(|_| CliConfigError::InvalidEnvironmentValue(name))
}

pub fn access_token_from_environment() -> Result<Option<String>, CliConfigError> {
    let Some(value) = std::env::var_os("S2_ACCESS_TOKEN") else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }
    value
        .into_string()
        .map(Some)
        .map_err(|_| CliConfigError::InvalidAccessTokenEnvironment)
}

pub async fn acquire_config_lock() -> Result<ConfigLock, CliConfigError> {
    let path = config_path()?;
    let parent = path.parent().ok_or(CliConfigError::DirNotFound)?;
    std::fs::create_dir_all(parent).map_err(CliConfigError::Lock)?;
    secure_config_dir(parent).map_err(CliConfigError::Lock)?;
    let lock_path = path.with_file_name("config.lock");
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(lock_path).map_err(CliConfigError::Lock)?;
    let deadline = tokio::time::Instant::now() + CONFIG_LOCK_TIMEOUT;

    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(ConfigLock { file }),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(CliConfigError::LockTimedOut);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(CliConfigError::Lock(error)),
        }
    }
}

#[derive(
    Debug, Clone, Copy, clap::ValueEnum, strum::Display, strum::EnumString, strum::VariantNames,
)]
#[clap(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ConfigKey {
    #[value(hide = true)]
    AccessToken,
    AccountEndpoint,
    BasinEndpoint,
    Compression,
    SslNoVerify,
}

impl CliConfig {
    pub fn has_stored_access_token(&self) -> bool {
        self.stored_access_token.is_some()
            || self
                .access_token
                .as_ref()
                .is_some_and(|token| !token.is_empty())
    }

    pub fn get(&self, key: ConfigKey) -> Option<String> {
        match key {
            ConfigKey::AccessToken => self
                .has_stored_access_token()
                .then(|| "<redacted>".to_owned()),
            ConfigKey::AccountEndpoint => self.account_endpoint.clone(),
            ConfigKey::BasinEndpoint => self.basin_endpoint.clone(),
            ConfigKey::Compression => self.compression.map(|c| c.to_string()),
            ConfigKey::SslNoVerify => self.ssl_no_verify.map(|v| v.to_string()),
        }
    }

    pub fn set(&mut self, key: ConfigKey, value: String) -> Result<(), CliConfigError> {
        match key {
            ConfigKey::AccessToken => return Err(CliConfigError::CredentialManagedSeparately),
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

    pub fn unset(&mut self, key: ConfigKey) -> Result<(), CliConfigError> {
        match key {
            ConfigKey::AccessToken => return Err(CliConfigError::CredentialManagedSeparately),
            ConfigKey::AccountEndpoint => self.account_endpoint = None,
            ConfigKey::BasinEndpoint => self.basin_endpoint = None,
            ConfigKey::Compression => self.compression = None,
            ConfigKey::SslNoVerify => self.ssl_no_verify = None,
        }
        Ok(())
    }
}

pub fn save_cli_config(config: &CliConfig) -> Result<PathBuf, CliConfigError> {
    let path = config_path()?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(CliConfigError::Write)?;
        secure_config_dir(parent).map_err(CliConfigError::Write)?;
    }

    let toml = toml::to_string(config).map_err(CliConfigError::Serialize)?;
    write_config_file(&path, &toml).map_err(CliConfigError::Write)?;

    Ok(path)
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

fn write_config_file(path: &Path, toml: &str) -> std::io::Result<()> {
    use std::io::Write as _;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid config path")
    })?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temp.as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temp.write_all(toml.as_bytes())?;
    temp.as_file_mut().sync_all()?;
    temp.persist(path).map_err(|error| error.error)?;
    // Rename committed the config; a directory-sync failure cannot be rolled back.
    let _ = sync_directory(parent);
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub async fn set_config_value(key: ConfigKey, value: String) -> Result<PathBuf, CliConfigError> {
    if matches!(key, ConfigKey::AccessToken) {
        return Err(CliConfigError::CredentialManagedSeparately);
    }
    let _lock = acquire_config_lock().await?;
    let mut config = load_config_file()?;
    config.set(key, value)?;
    save_cli_config(&config)
}

pub async fn unset_config_value(key: ConfigKey) -> Result<PathBuf, CliConfigError> {
    if matches!(key, ConfigKey::AccessToken) {
        return Err(CliConfigError::CredentialManagedSeparately);
    }
    let _lock = acquire_config_lock().await?;
    let mut config = load_config_file()?;
    config.unset(key)?;
    save_cli_config(&config)
}

pub fn sdk_config(
    config: &CliConfig,
    access_token: &str,
    user_agent: &str,
) -> Result<S2Config, CliError> {
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
                .map_err(|e| CliError::EndpointsInvalid(e.to_string()))?;
            let basin_endpoint = BasinEndpoint::new(basin_endpoint_str)
                .map_err(|e| CliError::EndpointsInvalid(e.to_string()))?;
            let endpoints = S2Endpoints::new(account_endpoint, basin_endpoint)
                .map_err(|e| CliError::EndpointsInvalid(e.to_string()))?;
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
