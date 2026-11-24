use reqwest::Url;
use s2_sdk::types::{AccountEndpoint, BasinEndpoint, S2Endpoints};

use super::{DEFAULT_OAUTH_ISSUER, LoginError, is_loopback_host};
use crate::config::{CliConfig, DEFAULT_ACCOUNT_ENDPOINT, DEFAULT_BASIN_ENDPOINT};

fn is_production_issuer(issuer: &str) -> bool {
    match (Url::parse(issuer), Url::parse(DEFAULT_OAUTH_ISSUER)) {
        (Ok(issuer), Ok(production)) => issuer == production,
        _ => issuer == DEFAULT_OAUTH_ISSUER,
    }
}

struct ParsedEndpoints {
    account: String,
    basin: String,
    account_url: Url,
    basin_url: Url,
    basin_has_placeholder: bool,
}

fn parse_endpoints(account: &str, basin: &str) -> Option<ParsedEndpoints> {
    let account = AccountEndpoint::new(account).ok()?;
    let basin = BasinEndpoint::new(basin).ok()?;
    let _ = S2Endpoints::new(account.clone(), basin.clone()).ok()?;

    let account_str = account.to_string();
    let basin_str = basin.to_string();
    let (basin_has_placeholder, basin_raw) = match basin_str.split_once("://{basin}.") {
        Some((scheme, rest)) => (true, format!("{scheme}://{rest}")),
        None => (false, basin_str),
    };

    let account_url = Url::parse(&account_str).ok()?;
    let basin_url = Url::parse(&basin_raw).ok()?;
    let account = canonical_origin(&account_url, false)?;
    let basin = canonical_origin(&basin_url, basin_has_placeholder)?;

    Some(ParsedEndpoints {
        account,
        basin,
        account_url,
        basin_url,
        basin_has_placeholder,
    })
}

fn canonical_origin(url: &Url, basin_placeholder: bool) -> Option<String> {
    let host = url.host_str()?;
    let prefix = if basin_placeholder { "{basin}." } else { "" };
    Some(match url.port() {
        Some(port) => format!("{}://{prefix}{host}:{port}", url.scheme()),
        None => format!("{}://{prefix}{host}", url.scheme()),
    })
}

pub(super) fn canonical_endpoints(account: &str, basin: &str) -> Option<(String, String)> {
    let parsed = parse_endpoints(account, basin)?;
    Some((parsed.account, parsed.basin))
}

pub(crate) fn effective_endpoints(config: &CliConfig) -> Option<(String, String)> {
    match (&config.account_endpoint, &config.basin_endpoint) {
        (Some(account), Some(basin)) => canonical_endpoints(account, basin),
        (None, None) => Some((
            DEFAULT_ACCOUNT_ENDPOINT.to_owned(),
            DEFAULT_BASIN_ENDPOINT.to_owned(),
        )),
        (Some(_), None) | (None, Some(_)) => None,
    }
}

/// Where the CLI is pointed: `s2.dev`, or the host of a custom account endpoint. When only one
/// of the two endpoints is S2's, both are named.
pub(crate) fn destination_label(config: &CliConfig) -> String {
    if let Some((account, basin)) = effective_endpoints(config) {
        let account_default = account == DEFAULT_ACCOUNT_ENDPOINT;
        let basin_default = basin == DEFAULT_BASIN_ENDPOINT;
        let label = |endpoint: &str, default: bool| {
            if default {
                "s2.dev".to_owned()
            } else {
                endpoint_host(endpoint)
            }
        };
        let account_label = label(&account, account_default);
        if account_default == basin_default {
            return account_label;
        }
        return format!(
            "{account_label}, basins at {}",
            label(&basin.replace("{basin}.", ""), basin_default)
        );
    }
    match (&config.account_endpoint, &config.basin_endpoint) {
        (Some(account), Some(_)) => endpoint_host(account),
        (Some(account), None) => format!("{} (basin endpoint unset)", endpoint_host(account)),
        (None, Some(basin)) => format!(
            "account endpoint unset, basins at {}",
            endpoint_host(&basin.replace("{basin}.", ""))
        ),
        (None, None) => "s2.dev".to_owned(),
    }
}

fn endpoint_host(endpoint: &str) -> String {
    Url::parse(endpoint)
        .ok()
        .and_then(|url| {
            let host = url.host_str()?;
            Some(match url.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_owned(),
            })
        })
        .unwrap_or_else(|| endpoint.to_owned())
}

pub(crate) fn uses_default_endpoints(config: &CliConfig) -> bool {
    effective_endpoints(config).is_some_and(|(account, basin)| {
        account == DEFAULT_ACCOUNT_ENDPOINT && basin == DEFAULT_BASIN_ENDPOINT
    })
}

pub(crate) fn uses_loopback_endpoints(config: &CliConfig) -> bool {
    effective_endpoints(config).is_some_and(|(account, basin)| {
        endpoint_environment(&account, &basin) == Some(EndpointEnvironment::Loopback)
    })
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
    let parsed = parse_endpoints(account, basin)?;
    if parsed.account == DEFAULT_ACCOUNT_ENDPOINT && parsed.basin == DEFAULT_BASIN_ENDPOINT {
        return Some(EndpointEnvironment::Production);
    }

    let account_host = parsed.account_url.host_str()?;
    let basin_host = parsed.basin_url.host_str()?;
    if is_loopback_host(account_host) && is_loopback_host(basin_host) {
        return Some(EndpointEnvironment::Loopback);
    }
    if parsed.account_url.scheme() != "https"
        || parsed.basin_url.scheme() != "https"
        || !parsed.basin_has_placeholder
    {
        return None;
    }

    let account_environment = account_endpoint_environment(account_host)?;
    let basin_environment = basin_endpoint_environment(basin_host)?;
    (account_environment == basin_environment).then_some(account_environment)
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
