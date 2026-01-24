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
///
/// Extracts scope facts directly from block source to avoid Datalog evaluation overhead.
fn check_resource_scopes(
    biscuit: &Biscuit,
    basin: Option<&str>,
    stream: Option<&str>,
    access_token_id: Option<&str>,
) -> Result<(), AuthorizeError> {
    // Extract scope facts directly from block source (avoids Datalog evaluation)
    let mut basin_scopes = Vec::new();
    let mut stream_scopes = Vec::new();
    let mut access_token_scopes = Vec::new();

    let block_count = biscuit.block_count();
    for block_idx in 0..block_count {
        if let Ok(block_source) = biscuit.print_block_source(block_idx) {
            extract_scope_facts(&block_source, "basin_scope", &mut basin_scopes);
            extract_scope_facts(&block_source, "stream_scope", &mut stream_scopes);
            extract_scope_facts(&block_source, "access_token_scope", &mut access_token_scopes);
        }
    }

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

/// Extract scope facts like `basin_scope("prefix", "")` from block source text.
///
/// Similar security considerations as extract_public_keys_from_source - only extracts
/// from top-level fact declarations, not from string literals inside checks/rules.
fn extract_scope_facts(source: &str, fact_name: &str, scopes: &mut Vec<(String, String)>) {
    let marker = format!("{}(\"", fact_name);
    let mut search_start = 0;

    while let Some(marker_pos) = source[search_start..].find(&marker) {
        let abs_pos = search_start + marker_pos;

        // Security check: only accept if at a statement boundary
        let at_statement_boundary = if abs_pos == 0 {
            true
        } else {
            let prev_char = source[..abs_pos].chars().last().unwrap();
            prev_char == '\n'
                || prev_char == ';'
                || (prev_char.is_whitespace() && {
                    let line_start = source[..abs_pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
                    source[line_start..abs_pos].trim().is_empty()
                })
        };

        let first_arg_start = abs_pos + marker.len();

        if at_statement_boundary {
            // Parse: fact_name("arg1", "arg2")
            if let Some(first_quote_end) = source[first_arg_start..].find('"') {
                let first_arg = &source[first_arg_start..first_arg_start + first_quote_end];
                let after_first = first_arg_start + first_quote_end + 1;

                // Look for ", " followed by second argument
                if source[after_first..].starts_with(", \"") {
                    let second_arg_start = after_first + 3;
                    if let Some(second_quote_end) = source[second_arg_start..].find('"') {
                        let second_arg =
                            &source[second_arg_start..second_arg_start + second_quote_end];
                        let after_second = second_arg_start + second_quote_end + 1;

                        // Verify proper termination: )
                        if source[after_second..].starts_with(')') {
                            scopes.push((first_arg.to_string(), second_arg.to_string()));
                        }

                        search_start = after_second;
                        continue;
                    }
                }
            }
        }

        search_start = abs_pos + marker.len();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use biscuit_auth::{KeyPair, PrivateKey, builder::BiscuitBuilder};
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    /// Simulate exactly what the CLI does in bootstrap mode:
    /// 1. Parse root_key as 32 bytes
    /// 2. Create p256 SigningKey
    /// 3. Get compressed public key as base58
    /// 4. Create Biscuit with public_key("...") fact
    /// 5. Extract public keys from Biscuit
    /// 6. Verify the extracted key matches the signing key
    #[test]
    fn test_cli_bootstrap_flow_public_key_extraction() {
        // 1. Generate a random key (simulating root_key)
        let signing_key = SigningKey::random(&mut OsRng);
        let key_bytes = signing_key.to_bytes();

        // 2. Get public key as compressed base58 (exactly like CLI does)
        let public_key = signing_key.verifying_key();
        let public_key_base58 = bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();
        println!("Public key base58: {}", public_key_base58);

        // 3. Create Biscuit keypair from same bytes (exactly like CLI does)
        let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1)
            .expect("should create biscuit private key");
        let biscuit_keypair = KeyPair::from(&biscuit_private);

        // 4. Build Biscuit with public_key fact (exactly like CLI does)
        let mut builder = BiscuitBuilder::new();
        builder = builder
            .fact(format!("public_key(\"{}\")", public_key_base58).as_str())
            .expect("should add public_key fact");

        let biscuit = builder
            .build(&biscuit_keypair)
            .expect("should build biscuit");

        // 5. Print block source to see what we're working with
        let block_source = biscuit.print_block_source(0).expect("should print block");
        println!("Block source:\n{}", block_source);

        // 6. Extract public keys using server's extraction logic
        let extracted_keys = extract_client_public_keys(&biscuit)
            .expect("should extract public keys");

        println!("Extracted {} public keys", extracted_keys.len());
        for (i, key) in extracted_keys.iter().enumerate() {
            println!("  Key {}: {}", i, key.to_base58());
        }

        // 7. Verify we got exactly one key and it matches
        assert_eq!(extracted_keys.len(), 1, "Should extract exactly one public key");
        assert_eq!(
            extracted_keys[0].to_base58(),
            public_key_base58,
            "Extracted key should match original"
        );
    }

    /// Test the full flow: create Biscuit like CLI, verify token, check public keys match
    #[test]
    fn test_cli_bootstrap_full_token_verification() {
        // Generate root key
        let signing_key = SigningKey::random(&mut OsRng);
        let key_bytes = signing_key.to_bytes();

        // Get public key
        let public_key = signing_key.verifying_key();
        let public_key_base58 = bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();

        // Create Biscuit keypair
        let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
        let biscuit_keypair = KeyPair::from(&biscuit_private);

        // Build Biscuit with all the facts the CLI adds
        let expires_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let mut builder = BiscuitBuilder::new();
        builder = builder.fact(format!("public_key(\"{}\")", public_key_base58).as_str()).unwrap();
        builder = builder.fact(format!("expires({})", expires_ts).as_str()).unwrap();
        builder = builder.check(format!("check if time($t), $t < {}", expires_ts).as_str()).unwrap();
        builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
        builder = builder.fact("op_group(\"account\", \"write\")").unwrap();
        builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();

        let biscuit = builder.build(&biscuit_keypair).unwrap();
        let token_bytes = biscuit.to_vec().unwrap();

        // Now verify the token like the server does
        let root_public_key = RootPublicKey::from_base58(&public_key_base58).unwrap();
        let verified = verify_token(&token_bytes, &root_public_key)
            .expect("should verify token");

        // Check that the public key was extracted correctly
        assert_eq!(verified.allowed_public_keys.len(), 1);
        assert_eq!(verified.allowed_public_keys[0].to_base58(), public_key_base58);

        println!("Token verified successfully!");
        println!("Allowed public keys: {:?}", verified.allowed_public_keys.iter().map(|k| k.to_base58()).collect::<Vec<_>>());
    }

    /// Test with the ACTUAL root key from the CLI config to ensure we get the same public key
    #[test]
    fn test_with_actual_root_key() {
        // This is the root key from the user's config
        let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";

        // Decode root key
        let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();
        assert_eq!(key_bytes.len(), 32, "Root key should be 32 bytes");

        // Create signing key (like CLI does)
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();

        // Get public key (like CLI does)
        let public_key = signing_key.verifying_key();
        let public_key_base58 = bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();

        println!("Root key: {}", root_key_base58);
        println!("Public key: {}", public_key_base58);

        // This should match what the server logs: pTGh6RCaGt5PcA3evMKB6ZZmsYfALRSPhCH9tq3xzEsW
        assert_eq!(
            public_key_base58,
            "pTGh6RCaGt5PcA3evMKB6ZZmsYfALRSPhCH9tq3xzEsW",
            "Public key should match server's expected public key"
        );

        // Now create Biscuit like CLI does
        let biscuit_private = PrivateKey::from_bytes(&key_bytes, Algorithm::Secp256r1).unwrap();
        let biscuit_keypair = KeyPair::from(&biscuit_private);

        let expires_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        let mut builder = BiscuitBuilder::new();
        builder = builder.fact(format!("public_key(\"{}\")", public_key_base58).as_str()).unwrap();
        builder = builder.fact(format!("expires({})", expires_ts).as_str()).unwrap();
        builder = builder.check(format!("check if time($t), $t < {}", expires_ts).as_str()).unwrap();
        builder = builder.fact("op_group(\"account\", \"read\")").unwrap();
        builder = builder.fact("basin_scope(\"prefix\", \"\")").unwrap();

        let biscuit = builder.build(&biscuit_keypair).unwrap();

        // Print block source
        let block_source = biscuit.print_block_source(0).unwrap();
        println!("Biscuit block source:\n{}", block_source);

        let token_bytes = biscuit.to_vec().unwrap();

        // Verify with the same public key the server uses
        let root_public_key = RootPublicKey::from_base58(&public_key_base58).unwrap();
        let verified = verify_token(&token_bytes, &root_public_key).unwrap();

        println!("Extracted public keys: {:?}",
            verified.allowed_public_keys.iter().map(|k| k.to_base58()).collect::<Vec<_>>());

        assert_eq!(verified.allowed_public_keys.len(), 1);
        assert_eq!(verified.allowed_public_keys[0].to_base58(), public_key_base58);
    }
}
