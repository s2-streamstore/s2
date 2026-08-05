use std::{
    io::{IsTerminal as _, Read as _},
    path::PathBuf,
};

use miette::Diagnostic;
use secrecy::{ExposeSecret as _, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    cli::{AuthAccessTokenMigrateArgs, AuthAccessTokenSetArgs},
    config::{
        CliConfig, CredentialStore, StoredCredentialReference, access_token_from_environment,
        acquire_config_lock, load_config_file, save_cli_config,
    },
    credential_store::{self, CredentialStoreError},
    error::{CliConfigError, TokenSource},
};

const CREDENTIAL_KIND: &str = "s2_access_token";
const CREDENTIAL_VERSION: u8 = 1;
const MAX_STDIN_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error, Diagnostic)]
pub enum AccessTokenError {
    #[error("Failed to read the access token from standard input")]
    Stdin(#[source] std::io::Error),

    #[error("Failed to read the access token from the terminal")]
    Prompt(#[source] std::io::Error),

    #[error("No access token was provided")]
    #[diagnostic(help(
        "Paste a token at the prompt, or pipe one into `s2 auth access-token set --stdin`."
    ))]
    EmptyInput,

    #[error("`--stdin` requires piped or redirected input")]
    #[diagnostic(help(
        "Pipe the token into this command, or omit `--stdin` to paste it securely at the prompt."
    ))]
    StdinIsTerminal,

    #[error("Cannot prompt for an access token without an interactive terminal")]
    #[diagnostic(help(
        "Pass `--stdin` when piping or redirecting an access token into this command."
    ))]
    PromptUnavailable,

    #[error("The access token is too large")]
    #[diagnostic(help("Provide an access token no larger than 1 MiB."))]
    InputTooLarge,

    #[error("The access token contains whitespace or control characters, or is not ASCII")]
    #[diagnostic(help("Provide exactly one access token followed by an optional newline."))]
    InvalidInput,

    #[error("Failed to serialize the stored access token")]
    Serialize(#[source] serde_json::Error),

    #[error("The stored access token is invalid")]
    Parse(#[source] serde_json::Error),

    #[error("The stored access token does not match its configuration")]
    BindingMismatch,

    #[error("No access token is configured")]
    #[diagnostic(help(
        "Run `s2 auth access-token set`, or set `S2_ACCESS_TOKEN` for a non-persistent override."
    ))]
    NotConfigured,

    #[error("No legacy plaintext access token was found in the config file")]
    #[diagnostic(help("Use `s2 auth access-token set` to store an access token."))]
    NoLegacyToken,

    #[error("A securely stored access token is already configured")]
    #[diagnostic(help(
        "Use `s2 auth access-token set` to replace it. Migration only moves a legacy plaintext token."
    ))]
    AlreadyStored,

    #[error("The access token was deactivated, but its local credential could not be deleted")]
    #[diagnostic(help(
        "Retry `s2 auth access-token remove`; the credential remains queued for cleanup at {recovery}."
    ))]
    RemovalIncomplete { recovery: String },

    #[error(transparent)]
    #[diagnostic(transparent)]
    Store(#[from] CredentialStoreError),

    #[error(transparent)]
    #[diagnostic(transparent)]
    Config(#[from] CliConfigError),
}

pub struct ResolvedAccessToken {
    token: SecretString,
    source: TokenSource,
}

impl ResolvedAccessToken {
    pub fn expose(&self) -> &str {
        self.token.expose_secret()
    }

    pub fn source(&self) -> TokenSource {
        self.source
    }
}

#[derive(Debug)]
pub struct TokenChange {
    pub config_path: PathBuf,
    pub credential_store: CredentialStore,
    pub credential_path: Option<PathBuf>,
    pub replaced: bool,
    pub cleanup_warning: Option<String>,
}

#[derive(Debug)]
pub struct TokenRemoval {
    pub config_path: Option<PathBuf>,
    pub removed: bool,
    pub cleanup_warning: Option<String>,
}

#[derive(Serialize)]
struct StoredCredential<'a> {
    version: u8,
    kind: &'static str,
    credential_id: &'a str,
    access_token: &'a str,
}

#[derive(Deserialize)]
struct LoadedCredential {
    version: u8,
    kind: String,
    credential_id: String,
    access_token: String,
}

pub fn resolve(config: &CliConfig) -> Result<ResolvedAccessToken, AccessTokenError> {
    if let Some(token) = access_token_from_environment()? {
        validate_token(&token)?;
        return Ok(ResolvedAccessToken {
            token: token.into(),
            source: TokenSource::Environment,
        });
    }

    let source = if config.stored_access_token.is_some() {
        TokenSource::StoredAccessToken
    } else {
        TokenSource::ConfigFile
    };
    Ok(ResolvedAccessToken {
        token: load(config)?,
        source,
    })
}

pub async fn set(args: &AuthAccessTokenSetArgs) -> Result<TokenChange, AccessTokenError> {
    let token = if args.stdin {
        read_from_stdin()?
    } else {
        read_from_terminal()?
    };
    store_token(token, requested_store(args.insecure_storage)).await
}

pub async fn set_from_argument(value: String) -> Result<TokenChange, AccessTokenError> {
    validate_token(&value)?;
    store_token(value.into(), CredentialStore::Keyring).await
}

pub async fn migrate(args: &AuthAccessTokenMigrateArgs) -> Result<TokenChange, AccessTokenError> {
    let _lock = acquire_config_lock().await?;
    let config = load_config_file()?;
    let token = config
        .access_token
        .as_ref()
        .filter(|token| !token.is_empty())
        .cloned();
    let Some(token) = token else {
        return Err(if config.stored_access_token.is_some() {
            AccessTokenError::AlreadyStored
        } else {
            AccessTokenError::NoLegacyToken
        });
    };

    if let Some(reference) = config.stored_access_token.clone() {
        // The stored reference is authoritative; only remove the stale plaintext copy.
        load(&config)?;
        let mut config = config;
        config.access_token = None;
        let config_path = save_cli_config(&config)?;
        let credential_path = match reference.credential_store {
            CredentialStore::Keyring => None,
            CredentialStore::File => Some(credential_store::credential_file_path(
                &reference.credential_id,
            )?),
        };
        return Ok(TokenChange {
            config_path,
            credential_store: reference.credential_store,
            credential_path,
            replaced: false,
            cleanup_warning: None,
        });
    }

    validate_token(&token)?;
    let mut change =
        store_with_config(config, token.into(), requested_store(args.insecure_storage))?;
    // Migration moves the existing token; it does not replace it with another token.
    change.replaced = false;
    Ok(change)
}

pub async fn remove() -> Result<TokenRemoval, AccessTokenError> {
    let _lock = acquire_config_lock().await?;
    let mut config = load_config_file()?;
    let reference = config.stored_access_token.clone();
    let had_legacy = config
        .access_token
        .as_ref()
        .is_some_and(|token| !token.is_empty());
    if reference.is_none() && !had_legacy && config.pending_access_token_cleanup.is_empty() {
        return Ok(TokenRemoval {
            config_path: None,
            removed: false,
            cleanup_warning: None,
        });
    }

    config.stored_access_token = None;
    config.access_token = None;
    // Deactivate durably before deletion so interruption leaves cleanup intent.
    if let Some(reference) = reference.as_ref() {
        queue_cleanup(&mut config, reference);
    }
    let config_path = save_cli_config(&config)?;

    let (cleanup_changed, mut cleanup_warning) = cleanup_pending_credentials(&mut config);
    if cleanup_changed && let Err(error) = save_cli_config(&config) {
        append_warning(
            &mut cleanup_warning,
            format!("could not update credential cleanup metadata: {error}"),
        );
    }
    if let Some(reference) = reference.as_ref()
        && config.pending_access_token_cleanup.contains(reference)
    {
        return Err(AccessTokenError::RemovalIncomplete {
            recovery: credential_store::credential_location(
                &reference.credential_id,
                reference.credential_store,
            ),
        });
    }

    Ok(TokenRemoval {
        config_path: Some(config_path),
        removed: reference.is_some() || had_legacy,
        cleanup_warning,
    })
}

fn load(config: &CliConfig) -> Result<SecretString, AccessTokenError> {
    if let Some(reference) = config.stored_access_token.as_ref() {
        let bytes = SecretBox::new(Box::new(credential_store::load(
            &reference.credential_id,
            reference.credential_store,
        )?));
        return decode_stored_credential(reference, bytes.expose_secret());
    }

    let token = config
        .access_token
        .as_ref()
        .filter(|token| !token.is_empty())
        .cloned()
        .ok_or(AccessTokenError::NotConfigured)?;
    validate_token(&token)?;
    Ok(token.into())
}

fn decode_stored_credential(
    reference: &StoredCredentialReference,
    bytes: &[u8],
) -> Result<SecretString, AccessTokenError> {
    let stored: LoadedCredential =
        serde_json::from_slice(bytes).map_err(AccessTokenError::Parse)?;
    if stored.version != CREDENTIAL_VERSION
        || stored.kind != CREDENTIAL_KIND
        || stored.credential_id != reference.credential_id
        || stored.access_token.is_empty()
    {
        return Err(AccessTokenError::BindingMismatch);
    }
    validate_token(&stored.access_token)?;
    Ok(stored.access_token.into())
}

fn read_from_stdin() -> Result<SecretString, AccessTokenError> {
    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err(AccessTokenError::StdinIsTerminal);
    }
    let mut bytes = Vec::new();
    stdin
        .lock()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(AccessTokenError::Stdin)?;
    if bytes.len() as u64 > MAX_STDIN_BYTES {
        return Err(AccessTokenError::InputTooLarge);
    }
    let mut token = String::from_utf8(bytes).map_err(|_| AccessTokenError::InvalidInput)?;
    if token.ends_with("\r\n") {
        token.truncate(token.len() - 2);
    } else if token.ends_with('\n') {
        token.truncate(token.len() - 1);
    }
    validate_token(&token)?;
    Ok(token.into())
}

fn read_from_terminal() -> Result<SecretString, AccessTokenError> {
    if !std::io::stdin().is_terminal() {
        return Err(AccessTokenError::PromptUnavailable);
    }
    let token = rpassword::prompt_password("Enter your access token: ")
        .map_err(AccessTokenError::Prompt)?;
    if token.len() as u64 > MAX_STDIN_BYTES {
        return Err(AccessTokenError::InputTooLarge);
    }
    validate_token(&token)?;
    Ok(token.into())
}

fn validate_token(token: &str) -> Result<(), AccessTokenError> {
    if token.is_empty() {
        return Err(AccessTokenError::EmptyInput);
    }
    if !token.is_ascii()
        || token.chars().any(char::is_whitespace)
        || token.chars().any(char::is_control)
    {
        return Err(AccessTokenError::InvalidInput);
    }
    Ok(())
}

fn requested_store(insecure_storage: bool) -> CredentialStore {
    if insecure_storage {
        CredentialStore::File
    } else {
        CredentialStore::Keyring
    }
}

async fn store_token(
    token: SecretString,
    store: CredentialStore,
) -> Result<TokenChange, AccessTokenError> {
    let _lock = acquire_config_lock().await?;
    let config = load_config_file()?;
    store_with_config(config, token, store)
}

fn store_with_config(
    mut config: CliConfig,
    token: SecretString,
    store: CredentialStore,
) -> Result<TokenChange, AccessTokenError> {
    let previous = config.stored_access_token.clone();
    let replaced = previous.is_some()
        || config
            .access_token
            .as_ref()
            .is_some_and(|token| !token.is_empty());
    let reference = credential_reference_for_write(&config, store);
    let payload = StoredCredential {
        version: CREDENTIAL_VERSION,
        kind: CREDENTIAL_KIND,
        credential_id: &reference.credential_id,
        access_token: token.expose_secret(),
    };
    let bytes = SecretBox::new(Box::new(
        serde_json::to_vec(&payload).map_err(AccessTokenError::Serialize)?,
    ));

    // Journal the new credential before writing it so a crash cannot orphan a secret.
    queue_cleanup(&mut config, &reference);
    save_cli_config(&config)?;

    credential_store::save(
        &reference.credential_id,
        reference.credential_store,
        bytes.expose_secret(),
    )?;

    config.stored_access_token = Some(reference.clone());
    config.access_token = None;
    config
        .pending_access_token_cleanup
        .retain(|pending| pending != &reference);
    if let Some(previous) = previous.as_ref() {
        queue_cleanup(&mut config, previous);
    }
    let config_path = save_cli_config(&config)?;

    let (cleanup_changed, mut cleanup_warning) = cleanup_pending_credentials(&mut config);
    if cleanup_changed && let Err(error) = save_cli_config(&config) {
        append_warning(
            &mut cleanup_warning,
            format!("could not update credential cleanup metadata: {error}"),
        );
    }
    let credential_path = match store {
        CredentialStore::Keyring => None,
        CredentialStore::File => Some(credential_store::credential_file_path(
            &reference.credential_id,
        )?),
    };

    Ok(TokenChange {
        config_path,
        credential_store: store,
        credential_path,
        replaced,
        cleanup_warning,
    })
}

fn credential_reference_for_write(
    config: &CliConfig,
    store: CredentialStore,
) -> StoredCredentialReference {
    // Reuse an inactive slot so repeated failed writes cannot grow the cleanup journal forever.
    config
        .pending_access_token_cleanup
        .iter()
        .find(|reference| reference.credential_store == store)
        .cloned()
        .unwrap_or_else(|| StoredCredentialReference {
            credential_id: Uuid::new_v4().to_string(),
            credential_store: store,
        })
}

fn queue_cleanup(config: &mut CliConfig, reference: &StoredCredentialReference) {
    if !config.pending_access_token_cleanup.contains(reference) {
        config.pending_access_token_cleanup.push(reference.clone());
    }
}

fn cleanup_pending_credentials(config: &mut CliConfig) -> (bool, Option<String>) {
    let pending = std::mem::take(&mut config.pending_access_token_cleanup);
    let mut retained = Vec::new();
    let mut errors = Vec::new();
    let mut removed = false;
    for reference in pending {
        match credential_store::delete(&reference.credential_id, reference.credential_store) {
            Ok(()) => removed = true,
            Err(error) => {
                errors.push(format!("credential {}: {error}", reference.credential_id));
                retained.push(reference);
            }
        }
    }
    config.pending_access_token_cleanup = retained;
    (removed, (!errors.is_empty()).then(|| errors.join("; ")))
}

fn append_warning(warning: &mut Option<String>, message: String) {
    match warning {
        Some(warning) => {
            warning.push_str("; ");
            warning.push_str(&message);
        }
        None => *warning = Some(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference() -> StoredCredentialReference {
        StoredCredentialReference {
            credential_id: "credential-123".to_owned(),
            credential_store: CredentialStore::File,
        }
    }

    #[test]
    fn stored_credential_is_bound_to_kind_and_id() {
        let valid = br#"{"version":1,"kind":"s2_access_token","credential_id":"credential-123","access_token":"secret"}"#;
        assert_eq!(
            decode_stored_credential(&reference(), valid)
                .unwrap()
                .expose_secret(),
            "secret"
        );

        let wrong_kind = br#"{"version":1,"kind":"oauth","credential_id":"credential-123","access_token":"secret"}"#;
        assert!(matches!(
            decode_stored_credential(&reference(), wrong_kind),
            Err(AccessTokenError::BindingMismatch)
        ));
        let wrong_id = br#"{"version":1,"kind":"s2_access_token","credential_id":"other","access_token":"secret"}"#;
        assert!(matches!(
            decode_stored_credential(&reference(), wrong_id),
            Err(AccessTokenError::BindingMismatch)
        ));
    }

    #[test]
    fn failed_write_retries_reuse_the_cleanup_entry() {
        let mut config = CliConfig::default();
        let reference = credential_reference_for_write(&config, CredentialStore::Keyring);
        queue_cleanup(&mut config, &reference);

        for _ in 0..3 {
            let retry = credential_reference_for_write(&config, CredentialStore::Keyring);
            assert_eq!(retry, reference);
            queue_cleanup(&mut config, &retry);
        }

        assert_eq!(config.pending_access_token_cleanup, [reference]);
    }
}
