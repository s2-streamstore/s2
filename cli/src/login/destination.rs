use reqwest::Url;

use super::{DEFAULT_OAUTH_ISSUER, LoginError, is_loopback_host};
use crate::config::{CliConfig, DEFAULT_ACCOUNT_ENDPOINT, DEFAULT_BASIN_ENDPOINT};

fn is_production_issuer(issuer: &str) -> bool {
    match (Url::parse(issuer), Url::parse(DEFAULT_OAUTH_ISSUER)) {
        (Ok(issuer), Ok(production)) => issuer == production,
        _ => issuer == DEFAULT_OAUTH_ISSUER,
    }
}

pub(crate) fn effective_endpoints(config: &CliConfig) -> (String, String) {
    match (&config.account_endpoint, &config.basin_endpoint) {
        (Some(account), Some(basin)) => (normalize_endpoint(account), normalize_endpoint(basin)),
        // The SDK ignores an incomplete custom-endpoint pair and uses its defaults.
        _ => (
            DEFAULT_ACCOUNT_ENDPOINT.to_owned(),
            DEFAULT_BASIN_ENDPOINT.to_owned(),
        ),
    }
}

pub(crate) fn uses_loopback_endpoints(config: &CliConfig) -> bool {
    let (account, basin) = effective_endpoints(config);
    endpoint_environment(&account, &basin) == Some(EndpointEnvironment::Loopback)
}

fn normalize_endpoint(endpoint: &str) -> String {
    endpoint.trim_end_matches('/').to_owned()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointEnvironment {
    Production,
    Staging,
    Sandbox,
    Loopback,
}

pub(super) fn validate_endpoint_binding(
    issuer: &str,
    account_endpoint: &str,
    basin_endpoint: &str,
    tls_verification_disabled: bool,
) -> Result<(), LoginError> {
    let environment = endpoint_environment(account_endpoint, basin_endpoint)
        .ok_or(LoginError::UnsafeBrowserDestination)?;
    if tls_verification_disabled && environment != EndpointEnvironment::Loopback {
        return Err(LoginError::UnsafeBrowserDestination);
    }
    let issuer_matches = if is_production_issuer(issuer) {
        environment == EndpointEnvironment::Production
    } else {
        matches!(
            environment,
            EndpointEnvironment::Staging
                | EndpointEnvironment::Sandbox
                | EndpointEnvironment::Loopback
        )
    };
    issuer_matches
        .then_some(())
        .ok_or(LoginError::UnsafeBrowserDestination)
}

fn endpoint_environment(account: &str, basin: &str) -> Option<EndpointEnvironment> {
    if account == DEFAULT_ACCOUNT_ENDPOINT && basin == DEFAULT_BASIN_ENDPOINT {
        return Some(EndpointEnvironment::Production);
    }

    let account_url = trusted_endpoint_url(account, false)?;
    let basin_url = trusted_endpoint_url(basin, true)?;
    if is_loopback_host(account_url.host_str()?) && is_loopback_host(basin_url.host_str()?) {
        return Some(EndpointEnvironment::Loopback);
    }
    if account_url.scheme() != "https" || basin_url.scheme() != "https" {
        return None;
    }

    let account_environment = account_endpoint_environment(account_url.host_str()?)?;
    let basin_environment = basin_endpoint_environment(basin_url.host_str()?)?;
    (account_environment == basin_environment).then_some(account_environment)
}

fn trusted_endpoint_url(endpoint: &str, basin: bool) -> Option<Url> {
    let basin_placeholders = endpoint.matches("{basin}.").count();
    if (!basin && basin_placeholders != 0) || basin_placeholders > 1 {
        return None;
    }
    let raw = endpoint.replace("{basin}.", "");
    let url = Url::parse(&raw).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }
    let loopback = url.host_str().is_some_and(is_loopback_host);
    if !matches!(url.scheme(), "http" | "https")
        || (!loopback && url.scheme() != "https")
        || (basin && !loopback && basin_placeholders != 1)
    {
        return None;
    }
    Some(url)
}

fn account_endpoint_environment(host: &str) -> Option<EndpointEnvironment> {
    let labels = host.split('.').collect::<Vec<_>>();
    match labels.as_slice() {
        [_, "o-staging", "s2", "dev"] | [_, "o-staging", _, "s2", "dev"] => {
            Some(EndpointEnvironment::Staging)
        }
        [_, "o-sandbox", "s2", "dev"] | [_, "o-sandbox", _, "s2", "dev"] => {
            Some(EndpointEnvironment::Sandbox)
        }
        _ => None,
    }
}

fn basin_endpoint_environment(host: &str) -> Option<EndpointEnvironment> {
    let labels = host.split('.').collect::<Vec<_>>();
    match labels.as_slice() {
        ["b-staging", "s2", "dev"] | ["b-staging", _, "s2", "dev"] => {
            Some(EndpointEnvironment::Staging)
        }
        ["b-sandbox", "s2", "dev"] | ["b-sandbox", _, "s2", "dev"] => {
            Some(EndpointEnvironment::Sandbox)
        }
        _ => None,
    }
}
