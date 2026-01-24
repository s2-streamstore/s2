use biscuit_auth::{
    Biscuit, PublicKey,
    builder::{Algorithm, AuthorizerBuilder},
};
use s2_common::types::access::Operation;
use time::OffsetDateTime;

use super::{
    keys::{ClientPublicKey, RootPublicKey},
    token::op_to_string,
};

/// Verified token with extracted claims
#[derive(Clone)]
pub struct VerifiedToken {
    pub biscuit: Biscuit,
    /// All public keys in token (authority + attenuation blocks)
    /// Used for RFC 9421 signature verification - request signer must match one of these
    pub allowed_public_keys: Vec<ClientPublicKey>,
    pub revocation_ids: Vec<Vec<u8>>,
}

/// Maximum token size in bytes (64 KB)
/// Prevents DoS via massive tokens with thousands of facts
const MAX_TOKEN_SIZE: usize = 64 * 1024;

/// Verify a Biscuit token and extract allowed public keys
pub fn verify_token(
    token_bytes: &[u8],
    root_public_key: &RootPublicKey,
) -> Result<VerifiedToken, VerifyError> {
    // Reject oversized tokens to prevent DoS
    if token_bytes.len() > MAX_TOKEN_SIZE {
        return Err(VerifyError::TokenTooLarge(token_bytes.len()));
    }

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
///
/// Parameters:
/// - `basin`: The basin being accessed (None for account-level operations)
/// - `stream`: The stream being accessed (None for basin/account-level operations)
/// - `access_token_id`: The access token being operated on (for IssueAccessToken,
///   RevokeAccessToken, etc.)
pub fn authorize(
    token: &VerifiedToken,
    signer_public_key: &ClientPublicKey,
    basin: Option<&str>,
    stream: Option<&str>,
    access_token_id: Option<&str>,
    operation: Operation,
) -> Result<(), AuthorizeError> {
    // Verify the request signer is authorized by this token
    if !token.allowed_public_keys.contains(signer_public_key) {
        return Err(AuthorizeError::UnauthorizedSigner);
    }

    // Check resource scopes in Rust (simpler than Datalog negation)
    check_resource_scopes(&token.biscuit, basin, stream, access_token_id)?;

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

/// Check that the requested resources are within the token's scope
fn check_resource_scopes(
    biscuit: &Biscuit,
    basin: Option<&str>,
    stream: Option<&str>,
    access_token_id: Option<&str>,
) -> Result<(), AuthorizeError> {
    let mut authorizer = biscuit.authorizer()?;

    // Extract scope facts from the token
    // Query failures indicate a malformed token - don't silently allow access
    let basin_scopes: Vec<(String, String)> = authorizer
        .query("data($type, $value) <- basin_scope($type, $value)")
        .map_err(|e| AuthorizeError::MalformedToken(e.to_string()))?;

    let stream_scopes: Vec<(String, String)> = authorizer
        .query("data($type, $value) <- stream_scope($type, $value)")
        .map_err(|e| AuthorizeError::MalformedToken(e.to_string()))?;

    let access_token_scopes: Vec<(String, String)> = authorizer
        .query("data($type, $value) <- access_token_scope($type, $value)")
        .map_err(|e| AuthorizeError::MalformedToken(e.to_string()))?;

    // Check basin scope
    if let Some(basin_name) = basin {
        if !is_resource_in_scope(basin_name, &basin_scopes) {
            return Err(AuthorizeError::OutOfScope("basin".into()));
        }
    }

    // Check stream scope
    if let Some(stream_name) = stream {
        if !is_resource_in_scope(stream_name, &stream_scopes) {
            return Err(AuthorizeError::OutOfScope("stream".into()));
        }
    }

    // Check access_token scope (for IssueAccessToken, RevokeAccessToken, etc.)
    if let Some(token_id) = access_token_id {
        if !is_resource_in_scope(token_id, &access_token_scopes) {
            return Err(AuthorizeError::OutOfScope("access_token".into()));
        }
    }

    Ok(())
}

fn is_resource_in_scope(resource: &str, scopes: &[(String, String)]) -> bool {
    // If no scopes defined, deny by default
    if scopes.is_empty() {
        return false;
    }

    for (scope_type, scope_value) in scopes {
        match scope_type.as_str() {
            "none" => return false, // No access allowed
            "exact" => {
                if resource == scope_value {
                    return true;
                }
            }
            "prefix" => {
                if resource.starts_with(scope_value) {
                    return true;
                }
            }
            _ => {}
        }
    }

    // No matching scope found
    false
}

fn public_key_to_biscuit(key: &RootPublicKey) -> Result<PublicKey, VerifyError> {
    // Biscuit expects the public key in compressed SEC1 format for secp256r1
    let point = key.verifying_key().to_encoded_point(true);
    PublicKey::from_bytes(point.as_bytes(), Algorithm::Secp256r1)
        .map_err(|e| VerifyError::KeyConversion(e.to_string()))
}

fn extract_client_public_keys(biscuit: &Biscuit) -> Result<Vec<ClientPublicKey>, VerifyError> {
    // Extract public_key facts from all blocks (authority + attenuation)
    // We iterate through each block individually to handle trust origin issues
    let mut public_keys = Vec::new();

    let block_count = biscuit.block_count();
    for block_idx in 0..block_count {
        if let Ok(block_source) = biscuit.print_block_source(block_idx) {
            extract_public_keys_from_source(&block_source, &mut public_keys);
        }
    }

    if public_keys.is_empty() {
        return Err(VerifyError::MissingPublicKey);
    }

    Ok(public_keys)
}

/// Extract public_key("...") facts from block source text
///
/// SECURITY: Only extracts from top-level fact declarations, not from string literals
/// inside checks/rules. A fact must appear at a statement boundary (start of source,
/// after newline, or after semicolon) to be considered valid.
fn extract_public_keys_from_source(source: &str, public_keys: &mut Vec<ClientPublicKey>) {
    const MARKER: &str = "public_key(\"";
    let mut search_start = 0;

    while let Some(marker_pos) = source[search_start..].find(MARKER) {
        let abs_pos = search_start + marker_pos;

        // Security check: only accept if at a statement boundary
        // This prevents injection via nested string literals like:
        //   check if foo.contains("public_key(\"ATTACKER\")")
        let at_statement_boundary = if abs_pos == 0 {
            true
        } else {
            let prev_char = source[..abs_pos].chars().last().unwrap();
            // Valid boundaries: newline, semicolon, or start of block after whitespace
            prev_char == '\n'
                || prev_char == ';'
                || (prev_char.is_whitespace() && {
                    // Check if this is the start of a statement (no preceding content on this line)
                    let line_start = source[..abs_pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
                    source[line_start..abs_pos].trim().is_empty()
                })
        };

        let key_start = abs_pos + MARKER.len();

        if at_statement_boundary {
            // Find the closing quote and verify it's followed by ");" or ")\n" or ")" at end
            if let Some(key_len) = source[key_start..].find('"') {
                let key_str = &source[key_start..key_start + key_len];
                let after_quote = key_start + key_len + 1; // position after closing quote

                // Verify this is a complete fact: public_key("...") followed by ; or newline or end
                let valid_termination = if after_quote >= source.len() {
                    false // need at least the closing paren
                } else if source[after_quote..].starts_with(')') {
                    let after_paren = after_quote + 1;
                    after_paren >= source.len()
                        || source[after_paren..].starts_with(';')
                        || source[after_paren..].starts_with('\n')
                        || source[after_paren..].starts_with(' ')
                } else {
                    false
                };

                if valid_termination {
                    if let Ok(pk) = ClientPublicKey::from_base58(key_str) {
                        if !public_keys.contains(&pk) {
                            public_keys.push(pk);
                        }
                    }
                }

                search_start = key_start + key_len;
            } else {
                break;
            }
        } else {
            // Skip this match - it's inside a string literal or other construct
            search_start = abs_pos + MARKER.len();
        }
    }
}

const AUTHORIZATION_POLICY: &str = r#"
// Scope enforcement via checks in token
// The token contains checks like:
//   check if basin($b), $b.starts_with("prefix")
// These are enforced automatically by the authorizer

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
    #[error("token too large: {0} bytes (max {MAX_TOKEN_SIZE})")]
    TokenTooLarge(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum AuthorizeError {
    #[error("biscuit error: {0}")]
    Biscuit(#[from] biscuit_auth::error::Token),
    #[error("{0} out of scope")]
    OutOfScope(String),
    #[error("request signer not authorized by token")]
    UnauthorizedSigner,
    #[error("malformed token: {0}")]
    MalformedToken(String),
}
