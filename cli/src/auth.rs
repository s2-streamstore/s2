use std::process::ExitCode;

use colored::Colorize as _;
use s2_sdk::{S2, error::ErrorCode, types::ListBasinsInput};

use crate::{
    config::{CliConfig, CredentialStore, DEFAULT_ACCOUNT_ENDPOINT, sdk_config},
    error::{CliConfigError, CliError, TokenSource},
    login::{LoginError, effective_endpoints, resolve_access_token, uses_loopback_endpoints},
    update,
};

pub async fn status() -> Result<ExitCode, CliError> {
    let (config, credential) = match resolve_access_token().await {
        Ok(resolved) => resolved,
        Err(LoginError::Config(CliConfigError::MissingAccessToken)) => {
            let config = crate::config::load_cli_config()?;
            print_heading(&config);
            eprintln!("  {}", "✗ Not logged in".red().bold());
            eprintln!("  - Run `s2 login`.");
            print_configured_credentials(&config, None);
            return Ok(ExitCode::FAILURE);
        }
        Err(error) => {
            let config = crate::config::load_cli_config()?;
            print_heading(&config);
            print_unverified(&configured_credential_label(&config), &error);
            print_configured_credentials(&config, configured_source(&config));
            return Ok(ExitCode::FAILURE);
        }
    };

    print_heading(&config);
    let label = credential_label(&config, credential.source());
    if let Err(error) = credential.validate_destination(&config) {
        print_unverified(&label, &error);
        print_configured_credentials(&config, Some(credential.source()));
        return Ok(ExitCode::FAILURE);
    }

    let sdk = match sdk_config(&config, credential.access_token(), update::user_agent()) {
        Ok(sdk) => credential.configure_sdk(sdk),
        Err(error) => {
            print_unverified(&label, &error);
            print_configured_credentials(&config, Some(credential.source()));
            return Ok(ExitCode::FAILURE);
        }
    };
    let s2 = match S2::new(sdk) {
        Ok(s2) => s2,
        Err(error) => {
            print_unverified(&label, &error);
            print_configured_credentials(&config, Some(credential.source()));
            return Ok(ExitCode::FAILURE);
        }
    };
    let result = s2.list_basins(ListBasinsInput::new().with_limit(1)).await;

    let exit_code = match result {
        Ok(_) => {
            if uses_loopback_endpoints(&config) {
                print_local_connection();
            } else {
                print_authenticated(&label);
            }
            ExitCode::SUCCESS
        }
        Err(error)
            if error.server_error().and_then(|error| error.known_code())
                == Some(ErrorCode::PermissionDenied) =>
        {
            // The server authenticated the credential before denying this probe.
            print_authenticated(&label);
            ExitCode::SUCCESS
        }
        Err(error)
            if matches!(
                error.server_error().and_then(|error| error.known_code()),
                Some(ErrorCode::Authn | ErrorCode::AccessTokenNotFound)
            ) =>
        {
            eprintln!(
                "  {}",
                format!("✗ Authentication failed for {label}").red().bold()
            );
            eprintln!("  - {}", recovery_command(credential.source()));
            ExitCode::FAILURE
        }
        Err(error) => {
            print_unverified(&label, &error);
            ExitCode::FAILURE
        }
    };

    print_configured_credentials(&config, Some(credential.source()));
    Ok(exit_code)
}

fn print_authenticated(label: &str) {
    eprintln!("  {}", format!("✓ Logged in with {label}").green().bold());
}

fn print_local_connection() {
    eprintln!("  {}", "✓ Connected to local S2 endpoint".green().bold());
    eprintln!("  - Credentials are not verified for local endpoints.");
}

fn print_unverified(label: &str, error: &impl std::fmt::Display) {
    eprintln!(
        "  {}",
        format!("! Could not verify {label}").yellow().bold()
    );
    eprintln!("  - {error}");
}

fn print_heading(config: &CliConfig) {
    let (account_endpoint, _) = effective_endpoints(config);
    let heading = if account_endpoint == DEFAULT_ACCOUNT_ENDPOINT {
        "s2.dev".to_owned()
    } else {
        reqwest::Url::parse(&account_endpoint)
            .ok()
            .and_then(|url| {
                let host = url.host_str()?;
                Some(match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_owned(),
                })
            })
            .unwrap_or_else(|| account_endpoint.clone())
    };
    eprintln!("{}", heading.bold());
}

fn configured_credential_label(config: &CliConfig) -> String {
    configured_source(config).map_or_else(
        || "authentication".to_owned(),
        |source| credential_label(config, source),
    )
}

fn configured_source(config: &CliConfig) -> Option<TokenSource> {
    if std::env::var_os("S2_ACCESS_TOKEN").is_some_and(|value| !value.is_empty()) {
        return Some(TokenSource::Environment);
    }
    match config.auth_method {
        Some(crate::config::AuthMethod::BrowserLogin) if config.oauth.is_some() => {
            Some(TokenSource::BrowserLogin)
        }
        Some(crate::config::AuthMethod::AccessToken) if config.has_stored_access_token() => {
            Some(stored_access_token_source(config))
        }
        Some(_) => None,
        None if config.has_stored_access_token() => Some(stored_access_token_source(config)),
        None if config.oauth.is_some() => Some(TokenSource::BrowserLogin),
        None => None,
    }
}

fn stored_access_token_source(config: &CliConfig) -> TokenSource {
    if config.stored_access_token.is_some() {
        TokenSource::StoredAccessToken
    } else {
        TokenSource::ConfigFile
    }
}

fn credential_label(config: &CliConfig, source: TokenSource) -> String {
    match source {
        TokenSource::Environment => "S2_ACCESS_TOKEN".to_owned(),
        TokenSource::BrowserLogin => browser_login_label(config),
        TokenSource::StoredAccessToken | TokenSource::ConfigFile => access_token_label(config),
    }
}

fn browser_login_label(config: &CliConfig) -> String {
    let storage = config
        .oauth
        .as_ref()
        .map(|session| storage_label(session.credential_store));
    storage.map_or_else(
        || "browser login".to_owned(),
        |storage| format!("browser login ({storage})"),
    )
}

fn access_token_label(config: &CliConfig) -> String {
    if let Some(reference) = config.stored_access_token.as_ref() {
        format!(
            "access token ({})",
            storage_label(reference.credential_store)
        )
    } else if config.has_legacy_access_token() {
        "access token (config.toml)".to_owned()
    } else {
        "access token".to_owned()
    }
}

fn storage_label(store: CredentialStore) -> &'static str {
    match store {
        CredentialStore::Keyring => "keyring",
        CredentialStore::File => "private file",
    }
}

fn print_configured_credentials(config: &CliConfig, active: Option<TokenSource>) {
    let browser_active = matches!(active, Some(TokenSource::BrowserLogin));
    let access_token_active = matches!(
        active,
        Some(TokenSource::StoredAccessToken | TokenSource::ConfigFile)
    );

    if !browser_active && config.oauth.is_some() {
        eprintln!("  - Also configured: {}", browser_login_label(config));
    }

    if !access_token_active && config.has_stored_access_token() {
        eprintln!("  - Also configured: {}", access_token_label(config));
    }

    if config.has_legacy_access_token() {
        eprintln!(
            "{}",
            "  ! The access token is stored in plaintext in config.toml.\n    Run `s2 auth access-token migrate` to secure it."
                .yellow()
        );
    }

    let has_file_storage = config
        .oauth
        .as_ref()
        .is_some_and(|session| session.credential_store == CredentialStore::File)
        || config
            .stored_access_token
            .as_ref()
            .is_some_and(|reference| reference.credential_store == CredentialStore::File);
    if has_file_storage {
        eprintln!(
            "{}",
            "  ! Credentials are stored in a private plaintext file.".yellow()
        );
    }
}

fn recovery_command(source: TokenSource) -> &'static str {
    match source {
        TokenSource::BrowserLogin => "Run `s2 login` again.",
        TokenSource::Environment => "Set S2_ACCESS_TOKEN to a valid access token.",
        TokenSource::StoredAccessToken | TokenSource::ConfigFile => {
            "Run `s2 auth access-token set` to replace it."
        }
    }
}
