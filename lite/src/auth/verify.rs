use biscuit_auth::{builder::Algorithm, builder::AuthorizerBuilder, Biscuit, PublicKey};
use s2_common::types::access::Operation;
use time::OffsetDateTime;

use super::keys::{ClientPublicKey, RootPublicKey};

/// Verified token with extracted claims
pub struct VerifiedToken {
    pub biscuit: Biscuit,
    /// All public keys in token (authority + attenuation blocks)
    /// Used for RFC 9421 signature verification - request signer must match one of these
    pub allowed_public_keys: Vec<ClientPublicKey>,
    pub revocation_ids: Vec<Vec<u8>>,
}

/// Verify a Biscuit token and extract allowed public keys
pub fn verify_token(
    token_bytes: &[u8],
    root_public_key: &RootPublicKey,
) -> Result<VerifiedToken, VerifyError> {
    // Convert root public key to Biscuit's PublicKey type
    let biscuit_pubkey = public_key_to_biscuit(root_public_key)?;

    // Parse and verify the Biscuit
    let biscuit = Biscuit::from(token_bytes, biscuit_pubkey)?;

    // Extract all public keys from facts (supports delegation)
    let allowed_public_keys = extract_client_public_keys(&biscuit)?;

    // Get revocation IDs for later checking
    let revocation_ids = biscuit.revocation_identifiers();

    Ok(VerifiedToken {
        biscuit,
        allowed_public_keys,
        revocation_ids,
    })
}

/// Authorize an operation on a resource
pub fn authorize(
    token: &VerifiedToken,
    signer_public_key: &ClientPublicKey,
    basin: Option<&str>,
    stream: Option<&str>,
    operation: Operation,
) -> Result<(), AuthorizeError> {
    let mut builder = AuthorizerBuilder::new();

    // Add current time
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let time_fact = format!("time({})", now);
    builder = builder.fact(time_fact.as_str())?;

    // Add signer fact for delegation support
    // This allows attenuated tokens to bind to a specific client key
    let signer_fact = format!("signer(\"{}\")", signer_public_key.to_base58());
    builder = builder.fact(signer_fact.as_str())?;

    // Add resource context
    if let Some(b) = basin {
        let basin_fact = format!("basin(\"{}\")", b);
        builder = builder.fact(basin_fact.as_str())?;
    }
    if let Some(s) = stream {
        let stream_fact = format!("stream(\"{}\")", s);
        builder = builder.fact(stream_fact.as_str())?;
    }

    // Add operation
    let op_fact = format!("operation(\"{}\")", op_to_string(operation));
    builder = builder.fact(op_fact.as_str())?;

    // Add authorization policy
    builder = builder.code(AUTHORIZATION_POLICY)?;

    // Build authorizer with the token and run authorization
    let mut authorizer = builder.build(&token.biscuit)?;
    authorizer.authorize()?;

    Ok(())
}

fn public_key_to_biscuit(key: &RootPublicKey) -> Result<PublicKey, VerifyError> {
    // Biscuit expects the public key in compressed SEC1 format for secp256r1
    let point = key.verifying_key().to_encoded_point(true);
    PublicKey::from_bytes(point.as_bytes(), Algorithm::Secp256r1)
        .map_err(|e| VerifyError::KeyConversion(e.to_string()))
}

fn extract_client_public_keys(biscuit: &Biscuit) -> Result<Vec<ClientPublicKey>, VerifyError> {
    // Query for all public_key facts (from authority + attenuation blocks)
    let mut authorizer = biscuit.authorizer()?;

    // Use authorizer query to extract all public_key facts
    let facts: Vec<(String,)> = authorizer
        .query("data($pk) <- public_key($pk)")
        .map_err(VerifyError::Biscuit)?;

    if facts.is_empty() {
        return Err(VerifyError::MissingPublicKey);
    }

    facts
        .into_iter()
        .map(|(pk,)| {
            ClientPublicKey::from_base58(&pk)
                .map_err(|e| VerifyError::InvalidPublicKey(e.to_string()))
        })
        .collect()
}

const AUTHORIZATION_POLICY: &str = r#"
// Allow if operation is in explicit ops list
allow if operation($op), op($op);

// Allow if operation matches op_group permissions
// Account-level read operations
allow if operation($op), op_group("account", "read"),
    ["list_basins", "account_metrics"].contains($op);

// Account-level write operations
allow if operation($op), op_group("account", "write"),
    ["create_basin", "delete_basin"].contains($op);

// Basin-level read operations
allow if operation($op), op_group("basin", "read"),
    ["get_basin_config", "list_streams", "list_access_tokens", "basin_metrics"].contains($op);

// Basin-level write operations
allow if operation($op), op_group("basin", "write"),
    ["reconfigure_basin", "create_stream", "delete_stream", "issue_access_token", "revoke_access_token"].contains($op);

// Stream-level read operations
allow if operation($op), op_group("stream", "read"),
    ["get_stream_config", "check_tail", "read", "stream_metrics"].contains($op);

// Stream-level write operations
allow if operation($op), op_group("stream", "write"),
    ["reconfigure_stream", "append", "trim", "fence"].contains($op);

// Deny by default
deny if true;
"#;

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
pub enum VerifyError {
    #[error("biscuit error: {0}")]
    Biscuit(#[from] biscuit_auth::error::Token),
    #[error("key conversion error: {0}")]
    KeyConversion(String),
    #[error("missing public_key fact in token")]
    MissingPublicKey,
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    #[error("biscuit error: {0}")]
    Biscuit(#[from] biscuit_auth::error::Token),
}
