use biscuit_auth::{builder::Algorithm, builder::BiscuitBuilder, Biscuit, KeyPair, PrivateKey};
use s2_common::types::access::{
    AccessTokenScope, Operation, PermittedOperationGroups, ResourceSet,
};
use time::OffsetDateTime;

use super::keys::{ClientPublicKey, RootKey};

/// Build a Biscuit token from scope and client public key
pub fn build_token(
    root_key: &RootKey,
    client_public_key: &ClientPublicKey,
    expires_at: OffsetDateTime,
    scope: &AccessTokenScope,
) -> Result<Biscuit, TokenBuildError> {
    // Convert to Biscuit's PrivateKey format (P-256 = secp256r1)
    let secret_bytes = root_key.signing_key().to_bytes();
    let private_key = PrivateKey::from_bytes(&secret_bytes, Algorithm::Secp256r1)
        .map_err(|e| TokenBuildError::KeyConversion(e.to_string()))?;
    let keypair = KeyPair::from(&private_key);

    let mut builder = BiscuitBuilder::new();

    // Add client public key binding
    let pubkey_fact = format!("public_key(\"{}\")", client_public_key.to_base58());
    builder = builder.fact(pubkey_fact.as_str())?;

    // Add expiration
    let expires_ts = expires_at.unix_timestamp();
    let expires_fact = format!("expires({})", expires_ts);
    builder = builder.fact(expires_fact.as_str())?;
    let expires_check = format!("check if time($t), $t < {}", expires_ts);
    builder = builder.check(expires_check.as_str())?;

    // Add resource scopes
    builder = add_resource_scope(builder, "basin_scope", &scope.basins)?;
    builder = add_resource_scope(builder, "stream_scope", &scope.streams)?;
    builder = add_resource_scope(builder, "access_token_scope", &scope.access_tokens)?;

    // Add operation groups
    builder = add_op_groups(builder, &scope.op_groups)?;

    // Add individual operations
    for op in scope.ops.iter() {
        let op_fact = format!("op(\"{}\")", op_to_string(op));
        builder = builder.fact(op_fact.as_str())?;
    }

    let biscuit = builder.build(&keypair)?;
    Ok(biscuit)
}

fn add_resource_scope<E, P>(
    mut builder: BiscuitBuilder,
    name: &str,
    resource: &ResourceSet<E, P>,
) -> Result<BiscuitBuilder, TokenBuildError>
where
    E: AsRef<str>,
    P: AsRef<str>,
{
    let fact = match resource {
        ResourceSet::None => format!("{}(\"none\", \"\")", name),
        ResourceSet::Exact(e) => format!("{}(\"exact\", \"{}\")", name, e.as_ref()),
        ResourceSet::Prefix(p) => format!("{}(\"prefix\", \"{}\")", name, p.as_ref()),
    };
    builder = builder.fact(fact.as_str())?;
    Ok(builder)
}

fn add_op_groups(
    mut builder: BiscuitBuilder,
    groups: &PermittedOperationGroups,
) -> Result<BiscuitBuilder, TokenBuildError> {
    if groups.account.read {
        builder = builder.fact("op_group(\"account\", \"read\")")?;
    }
    if groups.account.write {
        builder = builder.fact("op_group(\"account\", \"write\")")?;
    }
    if groups.basin.read {
        builder = builder.fact("op_group(\"basin\", \"read\")")?;
    }
    if groups.basin.write {
        builder = builder.fact("op_group(\"basin\", \"write\")")?;
    }
    if groups.stream.read {
        builder = builder.fact("op_group(\"stream\", \"read\")")?;
    }
    if groups.stream.write {
        builder = builder.fact("op_group(\"stream\", \"write\")")?;
    }
    Ok(builder)
}

fn op_to_string(op: Operation) -> &'static str {
    match op {
        Operation::ListBasins => "list_basins",
        Operation::CreateBasin => "create_basin",
        Operation::DeleteBasin => "delete_basin",
        Operation::ReconfigureBasin => "reconfigure_basin",
        Operation::GetBasinConfig => "get_basin_config",
        Operation::IssueAccessToken => "issue_access_token",
        Operation::RevokeAccessToken => "revoke_access_token",
        Operation::ListAccessTokens => "list_access_tokens",
        Operation::ListStreams => "list_streams",
        Operation::CreateStream => "create_stream",
        Operation::DeleteStream => "delete_stream",
        Operation::GetStreamConfig => "get_stream_config",
        Operation::ReconfigureStream => "reconfigure_stream",
        Operation::CheckTail => "check_tail",
        Operation::Append => "append",
        Operation::Read => "read",
        Operation::Trim => "trim",
        Operation::Fence => "fence",
        Operation::AccountMetrics => "account_metrics",
        Operation::BasinMetrics => "basin_metrics",
        Operation::StreamMetrics => "stream_metrics",
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TokenBuildError {
    #[error("biscuit error: {0}")]
    Biscuit(#[from] biscuit_auth::error::Token),
    #[error("key conversion error: {0}")]
    KeyConversion(String),
}
