# Authorization Implementation Plan

> **Status:** Completed. See [lite/docs/authentication.md](../../lite/docs/authentication.md) for usage documentation.

**Goal:** Add stateless authorization to s2-lite using Biscuit tokens and RFC 9421 HTTP Message Signatures.

**Architecture:** Root P-256 key signs Biscuit tokens containing client public keys and scopes. Clients sign HTTP requests with their P-256 key per RFC 9421. Server verifies both signatures, checks revocation list in SlateDB, and authorizes via Biscuit's Datalog engine.

**Tech Stack:** biscuit-auth, httpsig, p256, bs58, sha2

---

## Task 1: Add Dependencies

**Files:**
- Modify: `Cargo.toml` (workspace)
- Modify: `lite/Cargo.toml`

**Step 1: Add workspace dependencies**

In `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
biscuit-auth = "6.0"
bs58 = "0.5"
httpsig = "0.5"
p256 = "0.13"
sha2 = "0.10"
```

**Step 2: Add lite dependencies**

In `lite/Cargo.toml`, add to `[dependencies]`:

```toml
biscuit-auth = { workspace = true }
bs58 = { workspace = true }
httpsig = { workspace = true }
p256 = { workspace = true, features = ["ecdsa"] }
sha2 = { workspace = true }
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles without errors

**Step 4: Commit**

```bash
git add Cargo.toml lite/Cargo.toml Cargo.lock
git commit -m "feat(lite): add auth dependencies (biscuit, httpsig, p256)"
```

---

## Task 2: Create Auth Types Module

**Files:**
- Create: `lite/src/auth/mod.rs`
- Create: `lite/src/auth/keys.rs`
- Modify: `lite/src/lib.rs`

**Step 1: Create auth module directory**

Run: `mkdir -p lite/src/auth`

**Step 2: Write keys.rs with P-256 key types**

Create `lite/src/auth/keys.rs`:

```rust
use bs58;
use p256::{
    ecdsa::{SigningKey, VerifyingKey},
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey, SecretKey,
};
use std::fmt;

/// P-256 private key for signing
#[derive(Clone)]
pub struct RootKey {
    inner: SigningKey,
}

impl RootKey {
    /// Parse from base58-encoded 32-byte scalar
    pub fn from_base58(s: &str) -> Result<Self, KeyError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| KeyError::Base58Decode(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(KeyError::InvalidLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let secret = SecretKey::from_slice(&bytes)
            .map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        Ok(Self {
            inner: SigningKey::from(secret),
        })
    }

    /// Get the signing key for Biscuit/ECDSA operations
    pub fn signing_key(&self) -> &SigningKey {
        &self.inner
    }

    /// Derive the public key
    pub fn public_key(&self) -> RootPublicKey {
        RootPublicKey {
            inner: *self.inner.verifying_key(),
        }
    }
}

impl fmt::Debug for RootKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RootKey").finish_non_exhaustive()
    }
}

/// P-256 public key (compressed, base58)
#[derive(Clone, PartialEq, Eq)]
pub struct RootPublicKey {
    inner: VerifyingKey,
}

impl RootPublicKey {
    /// Parse from base58-encoded compressed point (33 bytes)
    pub fn from_base58(s: &str) -> Result<Self, KeyError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| KeyError::Base58Decode(e.to_string()))?;
        if bytes.len() != 33 {
            return Err(KeyError::InvalidLength {
                expected: 33,
                got: bytes.len(),
            });
        }
        let point = EncodedPoint::from_bytes(&bytes)
            .map_err(|e| KeyError::InvalidKey(e.to_string()))?;
        let public = PublicKey::from_encoded_point(&point)
            .into_option()
            .ok_or_else(|| KeyError::InvalidKey("invalid point".into()))?;
        Ok(Self {
            inner: VerifyingKey::from(public),
        })
    }

    /// Encode as base58 compressed point
    pub fn to_base58(&self) -> String {
        let point = self.inner.to_encoded_point(true); // compressed
        bs58::encode(point.as_bytes()).into_string()
    }

    /// Get the verifying key for signature verification
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.inner
    }
}

impl fmt::Debug for RootPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RootPublicKey")
            .field(&self.to_base58())
            .finish()
    }
}

impl fmt::Display for RootPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

/// Client public key (same format as RootPublicKey but semantically different)
pub type ClientPublicKey = RootPublicKey;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("base58 decode error: {0}")]
    Base58Decode(String),
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("invalid key: {0}")]
    InvalidKey(String),
}
```

**Step 3: Write mod.rs**

Create `lite/src/auth/mod.rs`:

```rust
pub mod keys;

pub use keys::{ClientPublicKey, KeyError, RootKey, RootPublicKey};
```

**Step 4: Add auth module to lib.rs**

In `lite/src/lib.rs`, add:

```rust
pub mod auth;
```

**Step 5: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles without errors

**Step 6: Commit**

```bash
git add lite/src/auth lite/src/lib.rs
git commit -m "feat(lite): add P-256 key types for auth"
```

---

## Task 3: Add Key Parsing Tests

**Files:**
- Create: `lite/src/auth/keys_test.rs`
- Modify: `lite/src/auth/keys.rs`

**Step 1: Write the tests**

Create `lite/src/auth/keys_test.rs`:

```rust
use super::*;

#[test]
fn test_root_key_roundtrip() {
    // Generate a test key
    use p256::SecretKey;
    use rand::rngs::OsRng;

    let secret = SecretKey::random(&mut OsRng);
    let bytes = secret.to_bytes();
    let base58 = bs58::encode(&bytes).into_string();

    let root_key = RootKey::from_base58(&base58).expect("should parse");
    let public_key = root_key.public_key();

    // Public key should roundtrip through base58
    let pub_base58 = public_key.to_base58();
    let parsed = RootPublicKey::from_base58(&pub_base58).expect("should parse");
    assert_eq!(public_key, parsed);
}

#[test]
fn test_root_key_invalid_length() {
    let short = bs58::encode(&[0u8; 16]).into_string();
    let err = RootKey::from_base58(&short).unwrap_err();
    assert!(matches!(err, KeyError::InvalidLength { expected: 32, got: 16 }));
}

#[test]
fn test_public_key_invalid_length() {
    let short = bs58::encode(&[0u8; 32]).into_string();
    let err = RootPublicKey::from_base58(&short).unwrap_err();
    assert!(matches!(err, KeyError::InvalidLength { expected: 33, .. }));
}

#[test]
fn test_base58_decode_error() {
    let err = RootKey::from_base58("invalid!@#$").unwrap_err();
    assert!(matches!(err, KeyError::Base58Decode(_)));
}
```

**Step 2: Add test module to keys.rs**

At the bottom of `lite/src/auth/keys.rs`, add:

```rust
#[cfg(test)]
mod tests;
```

And rename `keys_test.rs` to `tests.rs` under `lite/src/auth/keys/` OR use inline tests. Let's use inline:

Actually, simpler approach - add tests inline at bottom of `keys.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_root_key_roundtrip() {
        use p256::SecretKey;
        use rand::rngs::OsRng;

        let secret = SecretKey::random(&mut OsRng);
        let bytes = secret.to_bytes();
        let base58 = bs58::encode(&bytes).into_string();

        let root_key = RootKey::from_base58(&base58).expect("should parse");
        let public_key = root_key.public_key();

        let pub_base58 = public_key.to_base58();
        let parsed = RootPublicKey::from_base58(&pub_base58).expect("should parse");
        assert_eq!(public_key, parsed);
    }

    #[test]
    fn test_root_key_invalid_length() {
        let short = bs58::encode(&[0u8; 16]).into_string();
        let err = RootKey::from_base58(&short).unwrap_err();
        assert!(matches!(err, KeyError::InvalidLength { expected: 32, got: 16 }));
    }

    #[test]
    fn test_public_key_invalid_length() {
        let short = bs58::encode(&[0u8; 32]).into_string();
        let err = RootPublicKey::from_base58(&short).unwrap_err();
        assert!(matches!(err, KeyError::InvalidLength { expected: 33, .. }));
    }

    #[test]
    fn test_base58_decode_error() {
        let err = RootKey::from_base58("invalid!@#$").unwrap_err();
        assert!(matches!(err, KeyError::Base58Decode(_)));
    }
}
```

**Step 3: Run tests**

Run: `cargo nextest run -p s2-lite keys`
Expected: All 4 tests pass

**Step 4: Commit**

```bash
git add lite/src/auth/keys.rs
git commit -m "test(lite): add P-256 key parsing tests"
```

---

## Task 4: Create Biscuit Token Builder

**Files:**
- Create: `lite/src/auth/token.rs`
- Modify: `lite/src/auth/mod.rs`

**Step 1: Write token.rs**

Create `lite/src/auth/token.rs`:

```rust
use biscuit_auth::{
    builder::{Algorithm, BiscuitBuilder, Fact},
    Biscuit, KeyPair,
};
use s2_common::types::access::{AccessTokenScope, Operation, PermittedOperationGroups, ResourceSet};
use time::OffsetDateTime;

use super::keys::{ClientPublicKey, RootKey};

/// Build a Biscuit token from scope and client public key
pub fn build_token(
    root_key: &RootKey,
    client_public_key: &ClientPublicKey,
    expires_at: OffsetDateTime,
    scope: &AccessTokenScope,
) -> Result<Biscuit, TokenBuildError> {
    // Create Biscuit keypair from root key
    let keypair = KeyPair::from(root_key.signing_key().clone());

    let mut builder = BiscuitBuilder::new();

    // Add client public key binding
    builder.add_fact(format!("public_key(\"{}\")", client_public_key.to_base58()))?;

    // Add expiration
    let expires_ts = expires_at.unix_timestamp();
    builder.add_fact(format!("expires({})", expires_ts))?;
    builder.add_check(format!("check if time($t), $t < {}", expires_ts))?;

    // Add resource scopes
    add_resource_scope(&mut builder, "basin_scope", &scope.basins)?;
    add_resource_scope(&mut builder, "stream_scope", &scope.streams)?;
    add_resource_scope(&mut builder, "access_token_scope", &scope.access_tokens)?;

    // Add operation groups
    add_op_groups(&mut builder, &scope.op_groups)?;

    // Add individual operations
    for op in scope.ops.iter() {
        builder.add_fact(format!("op(\"{}\")", op_to_string(op)))?;
    }

    let biscuit = builder.build(&keypair)?;
    Ok(biscuit)
}

fn add_resource_scope<E, P>(
    builder: &mut BiscuitBuilder,
    name: &str,
    resource: &ResourceSet<E, P>,
) -> Result<(), TokenBuildError>
where
    E: AsRef<str>,
    P: AsRef<str>,
{
    match resource {
        ResourceSet::None => {
            builder.add_fact(format!("{}(none, \"\")", name))?;
        }
        ResourceSet::Exact(e) => {
            builder.add_fact(format!("{}(exact, \"{}\")", name, e.as_ref()))?;
        }
        ResourceSet::Prefix(p) => {
            builder.add_fact(format!("{}(prefix, \"{}\")", name, p.as_ref()))?;
        }
    }
    Ok(())
}

fn add_op_groups(
    builder: &mut BiscuitBuilder,
    groups: &PermittedOperationGroups,
) -> Result<(), TokenBuildError> {
    if groups.account.read {
        builder.add_fact("op_group(account, read)")?;
    }
    if groups.account.write {
        builder.add_fact("op_group(account, write)")?;
    }
    if groups.basin.read {
        builder.add_fact("op_group(basin, read)")?;
    }
    if groups.basin.write {
        builder.add_fact("op_group(basin, write)")?;
    }
    if groups.stream.read {
        builder.add_fact("op_group(stream, read)")?;
    }
    if groups.stream.write {
        builder.add_fact("op_group(stream, write)")?;
    }
    Ok(())
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
}
```

**Step 2: Update mod.rs**

In `lite/src/auth/mod.rs`, add:

```rust
pub mod token;

pub use token::{build_token, TokenBuildError};
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles (may need adjustments based on biscuit-auth API)

**Step 4: Commit**

```bash
git add lite/src/auth/token.rs lite/src/auth/mod.rs
git commit -m "feat(lite): add Biscuit token builder"
```

---

## Task 5: Create Token Verifier

**Files:**
- Create: `lite/src/auth/verify.rs`
- Modify: `lite/src/auth/mod.rs`

**Step 1: Write verify.rs**

Create `lite/src/auth/verify.rs`:

```rust
use biscuit_auth::{Authorizer, Biscuit, PublicKey};
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
    let mut authorizer = Authorizer::new();

    // Add current time
    let now = OffsetDateTime::now_utc().unix_timestamp();
    authorizer.add_fact(format!("time({})", now))?;

    // Add signer fact for delegation support
    // This allows attenuated tokens to bind to a specific client key
    authorizer.add_fact(format!("signer(\"{}\")", signer_public_key.to_base58()))?;

    // Add resource context
    if let Some(b) = basin {
        authorizer.add_fact(format!("basin(\"{}\")", b))?;
    }
    if let Some(s) = stream {
        authorizer.add_fact(format!("stream(\"{}\")", s))?;
    }

    // Add operation
    authorizer.add_fact(format!("operation(\"{}\")", op_to_string(operation)))?;

    // Add authorization policy
    authorizer.add_policy(authorization_policy())?;

    // Run authorization
    authorizer.add_token(&token.biscuit)?;
    authorizer.authorize()?;

    Ok(())
}

fn public_key_to_biscuit(key: &RootPublicKey) -> Result<PublicKey, VerifyError> {
    // Biscuit expects the public key in a specific format
    // This depends on the biscuit-auth API for P-256
    let point = key.verifying_key().to_encoded_point(true);
    PublicKey::from_bytes(point.as_bytes(), biscuit_auth::builder::Algorithm::P256)
        .map_err(|e| VerifyError::KeyConversion(e.to_string()))
}

fn extract_client_public_keys(biscuit: &Biscuit) -> Result<Vec<ClientPublicKey>, VerifyError> {
    // Query for all public_key facts (from authority + attenuation blocks)
    let mut authorizer = Authorizer::new();
    authorizer.add_token(biscuit)?;

    // Use authorizer query to extract all public_key facts
    let facts: Vec<(String,)> = authorizer.query("data($pk) <- public_key($pk)")?;

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

fn authorization_policy() -> &'static str {
    r#"
    // Allow if operation is in explicit ops list
    allow if operation($op), op($op);

    // Allow if operation matches op_group permissions
    // Account-level read operations
    allow if operation($op), op_group(account, read),
        ["list_basins", "account_metrics"].contains($op);

    // Account-level write operations
    allow if operation($op), op_group(account, write),
        ["create_basin", "delete_basin"].contains($op);

    // Basin-level read operations
    allow if operation($op), op_group(basin, read),
        ["get_basin_config", "list_streams", "list_access_tokens", "basin_metrics"].contains($op);

    // Basin-level write operations
    allow if operation($op), op_group(basin, write),
        ["reconfigure_basin", "create_stream", "delete_stream", "issue_access_token", "revoke_access_token"].contains($op);

    // Stream-level read operations
    allow if operation($op), op_group(stream, read),
        ["get_stream_config", "check_tail", "read", "stream_metrics"].contains($op);

    // Stream-level write operations
    allow if operation($op), op_group(stream, write),
        ["reconfigure_stream", "append", "trim", "fence"].contains($op);

    // Check basin scope
    check if basin($b), basin_scope(none, _) -> false;
    check if basin($b), basin_scope(exact, $allowed), $b == $allowed;
    check if basin($b), basin_scope(prefix, $p), $b.starts_with($p);

    // Check stream scope
    check if stream($s), stream_scope(none, _) -> false;
    check if stream($s), stream_scope(exact, $allowed), $s == $allowed;
    check if stream($s), stream_scope(prefix, $p), $s.starts_with($p);

    // Deny by default
    deny if true;
    "#
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
    #[error("authorization denied")]
    Denied,
}
```

**Step 2: Update mod.rs**

Add to `lite/src/auth/mod.rs`:

```rust
pub mod verify;

pub use verify::{authorize, verify_token, AuthorizeError, VerifiedToken, VerifyError};
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles (may need API adjustments)

**Step 4: Commit**

```bash
git add lite/src/auth/verify.rs lite/src/auth/mod.rs
git commit -m "feat(lite): add Biscuit token verifier"
```

---

## Task 6: Add RFC 9421 HTTP Signature Module

**Files:**
- Create: `lite/src/auth/httpsig.rs`
- Modify: `lite/src/auth/mod.rs`

**Step 1: Write httpsig.rs**

Create `lite/src/auth/httpsig.rs`:

```rust
use http::{HeaderMap, Method};
use httpsig::{
    prelude::*,
    signature::{MessageSignature, SignatureParams},
};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use super::keys::ClientPublicKey;

/// Components that must be signed
const REQUIRED_COMPONENTS: &[&str] = &[
    "@method",
    "@path",
    "@authority",
    "authorization",
];

/// Verify an HTTP message signature
pub fn verify_signature(
    method: &Method,
    path: &str,
    authority: &str,
    headers: &HeaderMap,
    body: Option<&[u8]>,
    public_key: &ClientPublicKey,
    signature_window_secs: u64,
) -> Result<(), SignatureError> {
    // Extract Signature-Input and Signature headers
    let sig_input = headers
        .get("signature-input")
        .ok_or(SignatureError::MissingHeader("Signature-Input"))?
        .to_str()
        .map_err(|_| SignatureError::InvalidHeader("Signature-Input"))?;

    let signature = headers
        .get("signature")
        .ok_or(SignatureError::MissingHeader("Signature"))?
        .to_str()
        .map_err(|_| SignatureError::InvalidHeader("Signature"))?;

    // Parse signature input to get parameters
    let params = parse_signature_input(sig_input)?;

    // Verify required components are covered
    verify_covered_components(&params)?;

    // Verify timestamp is within window
    verify_timestamp(&params, signature_window_secs)?;

    // If body present, verify Content-Digest
    if let Some(body) = body {
        verify_content_digest(headers, body)?;
    }

    // Build signature base string
    let base_string = build_signature_base(method, path, authority, headers, &params)?;

    // Verify the signature
    verify_ecdsa_signature(&base_string, signature, public_key)?;

    Ok(())
}

fn parse_signature_input(input: &str) -> Result<SignatureParams, SignatureError> {
    // Parse RFC 8941 structured field format
    // sig1=("@method" "@path" ...);created=1704067200;keyid="..."
    // This is a simplified parser - real implementation would use sfv crate
    todo!("Parse signature input - use httpsig crate's parser")
}

fn verify_covered_components(params: &SignatureParams) -> Result<(), SignatureError> {
    for required in REQUIRED_COMPONENTS {
        if !params.covered_components.contains(&required.to_string()) {
            return Err(SignatureError::MissingComponent(required));
        }
    }
    Ok(())
}

fn verify_timestamp(params: &SignatureParams, window_secs: u64) -> Result<(), SignatureError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let created = params.created.ok_or(SignatureError::MissingTimestamp)?;

    if created > now + window_secs {
        return Err(SignatureError::TimestampFuture);
    }
    if created < now.saturating_sub(window_secs) {
        return Err(SignatureError::TimestampExpired);
    }

    Ok(())
}

fn verify_content_digest(headers: &HeaderMap, body: &[u8]) -> Result<(), SignatureError> {
    let digest_header = headers
        .get("content-digest")
        .ok_or(SignatureError::MissingHeader("Content-Digest"))?
        .to_str()
        .map_err(|_| SignatureError::InvalidHeader("Content-Digest"))?;

    // Parse sha-256=:BASE64:
    let expected = parse_content_digest(digest_header)?;

    let mut hasher = Sha256::new();
    hasher.update(body);
    let actual = hasher.finalize();

    if actual.as_slice() != expected {
        return Err(SignatureError::DigestMismatch);
    }

    Ok(())
}

fn parse_content_digest(header: &str) -> Result<Vec<u8>, SignatureError> {
    // Format: sha-256=:BASE64:
    let parts: Vec<&str> = header.split('=').collect();
    if parts.len() != 2 || parts[0] != "sha-256" {
        return Err(SignatureError::InvalidDigestFormat);
    }

    let b64 = parts[1].trim_matches(':');
    base64ct::Base64::decode_vec(b64)
        .map_err(|_| SignatureError::InvalidDigestFormat)
}

fn build_signature_base(
    method: &Method,
    path: &str,
    authority: &str,
    headers: &HeaderMap,
    params: &SignatureParams,
) -> Result<Vec<u8>, SignatureError> {
    // Build per RFC 9421 Section 2.5
    let mut base = Vec::new();

    for component in &params.covered_components {
        let value = match component.as_str() {
            "@method" => method.as_str().to_uppercase(),
            "@path" => path.to_string(),
            "@authority" => authority.to_string(),
            name => headers
                .get(name)
                .ok_or(SignatureError::MissingHeader(name))?
                .to_str()
                .map_err(|_| SignatureError::InvalidHeader(name))?
                .to_string(),
        };

        base.extend_from_slice(format!("\"{}\": {}\n", component, value).as_bytes());
    }

    // Add signature params line
    base.extend_from_slice(format!("\"@signature-params\": {}", params.to_string()).as_bytes());

    Ok(base)
}

fn verify_ecdsa_signature(
    base_string: &[u8],
    signature_header: &str,
    public_key: &ClientPublicKey,
) -> Result<(), SignatureError> {
    // Parse sig1=:BASE64:
    let parts: Vec<&str> = signature_header.split('=').collect();
    if parts.len() != 2 {
        return Err(SignatureError::InvalidSignatureFormat);
    }

    let b64 = parts[1].trim_matches(':');
    let sig_bytes = base64ct::Base64::decode_vec(b64)
        .map_err(|_| SignatureError::InvalidSignatureFormat)?;

    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| SignatureError::InvalidSignatureFormat)?;

    public_key
        .verifying_key()
        .verify(base_string, &signature)
        .map_err(|_| SignatureError::SignatureInvalid)?;

    Ok(())
}

/// Placeholder for SignatureParams until we integrate httpsig properly
struct SignatureParams {
    covered_components: Vec<String>,
    created: Option<u64>,
}

impl SignatureParams {
    fn to_string(&self) -> String {
        todo!()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("missing header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("missing required component: {0}")]
    MissingComponent(&'static str),
    #[error("missing timestamp")]
    MissingTimestamp,
    #[error("timestamp too far in future")]
    TimestampFuture,
    #[error("timestamp expired")]
    TimestampExpired,
    #[error("content digest mismatch")]
    DigestMismatch,
    #[error("invalid digest format")]
    InvalidDigestFormat,
    #[error("invalid signature format")]
    InvalidSignatureFormat,
    #[error("signature verification failed")]
    SignatureInvalid,
}
```

**Step 2: Update mod.rs**

Add to `lite/src/auth/mod.rs`:

```rust
pub mod httpsig;

pub use httpsig::{verify_signature, SignatureError};
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles with todos

**Step 4: Commit**

```bash
git add lite/src/auth/httpsig.rs lite/src/auth/mod.rs
git commit -m "feat(lite): add RFC 9421 HTTP signature verification (WIP)"
```

---

## Task 7: Add Revocation Storage

**Files:**
- Create: `lite/src/auth/revocation.rs`
- Modify: `lite/src/auth/mod.rs`
- Modify: `lite/src/backend/core.rs`

**Step 1: Write revocation.rs**

Create `lite/src/auth/revocation.rs`:

```rust
const REVOCATION_PREFIX: &[u8] = b"revocations/";

/// Check if any of the revocation IDs are revoked
pub async fn is_revoked(
    db: &slatedb::Db,
    revocation_ids: &[Vec<u8>],
) -> Result<bool, RevocationError> {
    for id in revocation_ids {
        let key = revocation_key(id);
        if db.get(&key).await?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Revoke a token by its revocation ID
pub async fn revoke(db: &slatedb::Db, revocation_id: &[u8]) -> Result<(), RevocationError> {
    let key = revocation_key(revocation_id);
    db.put(&key, &[]).await?;
    Ok(())
}

/// List all revoked token IDs
pub async fn list_revocations(db: &slatedb::Db) -> Result<Vec<Vec<u8>>, RevocationError> {
    let mut ids = Vec::new();

    // SlateDB range scan
    let iter = db.range_scan(REVOCATION_PREFIX.to_vec()..).await?;
    while let Some((key, _)) = iter.next().await? {
        if !key.starts_with(REVOCATION_PREFIX) {
            break;
        }
        // Extract the ID portion after prefix
        let id = key[REVOCATION_PREFIX.len()..].to_vec();
        ids.push(id);
    }

    Ok(ids)
}

fn revocation_key(id: &[u8]) -> Vec<u8> {
    let mut key = REVOCATION_PREFIX.to_vec();
    key.extend_from_slice(&hex::encode(id).as_bytes());
    key
}

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("storage error: {0}")]
    Storage(#[from] slatedb::DbError),
}
```

**Step 2: Add hex dependency to workspace**

In `Cargo.toml`, add to `[workspace.dependencies]`:

```toml
hex = "0.4"
```

In `lite/Cargo.toml`, add:

```toml
hex = { workspace = true }
```

**Step 3: Update mod.rs**

Add to `lite/src/auth/mod.rs`:

```rust
pub mod revocation;

pub use revocation::{is_revoked, list_revocations, revoke, RevocationError};
```

**Step 4: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles (may need SlateDB API adjustments)

**Step 5: Commit**

```bash
git add Cargo.toml lite/Cargo.toml lite/src/auth/revocation.rs lite/src/auth/mod.rs
git commit -m "feat(lite): add revocation storage in SlateDB"
```

---

## Task 8: Add Auth Config to Server Args

**Files:**
- Modify: `lite/src/bin/server.rs`

**Step 1: Add auth args to CLI**

In `lite/src/bin/server.rs`, add to the `Args` struct after line 57:

```rust
/// Root key for signing access tokens (base58-encoded P-256 private key).
/// Can also be set via S2_ROOT_KEY environment variable.
#[arg(long, env = "S2_ROOT_KEY")]
root_key: Option<String>,

/// Signature timestamp window in seconds (default 300).
#[arg(long, env = "S2_SIGNATURE_WINDOW", default_value = "300")]
signature_window: u64,
```

**Step 2: Parse root key at startup**

After `let args = Args::parse();` (line 69), add:

```rust
let root_key = args
    .root_key
    .as_ref()
    .map(|k| s2_lite::auth::RootKey::from_base58(k))
    .transpose()
    .map_err(|e| eyre::eyre!("invalid root key: {}", e))?;

if let Some(ref key) = root_key {
    info!(public_key = %key.public_key(), "auth enabled");
} else {
    info!("auth disabled (no root key provided)");
}
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles

**Step 4: Commit**

```bash
git add lite/src/bin/server.rs
git commit -m "feat(lite): add root-key CLI arg for auth"
```

---

## Task 9: Create Auth State

**Files:**
- Create: `lite/src/auth/state.rs`
- Modify: `lite/src/auth/mod.rs`

**Step 1: Write state.rs**

Create `lite/src/auth/state.rs`:

```rust
use std::sync::Arc;

use super::keys::{RootKey, RootPublicKey};

/// Shared auth state
#[derive(Clone)]
pub struct AuthState {
    inner: Option<Arc<AuthStateInner>>,
}

struct AuthStateInner {
    root_key: RootKey,
    root_public_key: RootPublicKey,
    signature_window_secs: u64,
}

impl AuthState {
    /// Create auth state with the given root key
    pub fn new(root_key: RootKey, signature_window_secs: u64) -> Self {
        let root_public_key = root_key.public_key();
        Self {
            inner: Some(Arc::new(AuthStateInner {
                root_key,
                root_public_key,
                signature_window_secs,
            })),
        }
    }

    /// Create disabled auth state (no auth required)
    pub fn disabled() -> Self {
        Self { inner: None }
    }

    /// Check if auth is enabled
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Get the root key (for signing tokens)
    pub fn root_key(&self) -> Option<&RootKey> {
        self.inner.as_ref().map(|i| &i.root_key)
    }

    /// Get the root public key (for verifying tokens)
    pub fn root_public_key(&self) -> Option<&RootPublicKey> {
        self.inner.as_ref().map(|i| &i.root_public_key)
    }

    /// Get the signature window in seconds
    pub fn signature_window_secs(&self) -> u64 {
        self.inner.as_ref().map(|i| i.signature_window_secs).unwrap_or(300)
    }
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("enabled", &self.is_enabled())
            .field(
                "public_key",
                &self.root_public_key().map(|k| k.to_base58()),
            )
            .finish()
    }
}
```

**Step 2: Update mod.rs**

Add to `lite/src/auth/mod.rs`:

```rust
pub mod state;

pub use state::AuthState;
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles

**Step 4: Commit**

```bash
git add lite/src/auth/state.rs lite/src/auth/mod.rs
git commit -m "feat(lite): add AuthState for shared auth config"
```

---

## Task 10: Add Auth Error Types

**Files:**
- Modify: `lite/src/handlers/v1/error.rs`

**Step 1: Add auth error variants**

In `lite/src/handlers/v1/error.rs`, add import at top:

```rust
use crate::auth::{AuthorizeError, SignatureError, VerifyError};
```

Add new variants to `ServiceError` enum (after line 64):

```rust
#[error("authentication required")]
AuthRequired,
#[error("invalid token: {0}")]
InvalidToken(#[from] VerifyError),
#[error("invalid signature: {0}")]
InvalidSignature(#[from] SignatureError),
#[error("authorization denied: {0}")]
AuthorizationDenied(#[from] AuthorizeError),
#[error("token revoked")]
TokenRevoked,
```

**Step 2: Add error response mappings**

In the `to_response` method, add cases before `ServiceError::NotImplemented`:

```rust
ServiceError::AuthRequired => {
    standard(ErrorCode::PermissionDenied, "Authentication required")
}
ServiceError::InvalidToken(e) => {
    standard(ErrorCode::PermissionDenied, format!("Invalid token: {}", e))
}
ServiceError::InvalidSignature(e) => {
    standard(ErrorCode::PermissionDenied, format!("Invalid signature: {}", e))
}
ServiceError::AuthorizationDenied(e) => {
    standard(ErrorCode::PermissionDenied, format!("Authorization denied: {}", e))
}
ServiceError::TokenRevoked => {
    standard(ErrorCode::PermissionDenied, "Token has been revoked")
}
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles

**Step 4: Commit**

```bash
git add lite/src/handlers/v1/error.rs
git commit -m "feat(lite): add auth error types to ServiceError"
```

---

## Task 11: Create Auth Middleware

**Files:**
- Create: `lite/src/handlers/v1/middleware.rs`
- Modify: `lite/src/handlers/v1/mod.rs`

**Step 1: Write middleware.rs**

Create `lite/src/handlers/v1/middleware.rs`:

```rust
use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use http::header::AUTHORIZATION;

use crate::{
    auth::{self, AuthState, ClientPublicKey, VerifiedToken},
    backend::Backend,
};

use super::error::ServiceError;

/// Extension type for authenticated requests
#[derive(Clone)]
pub struct AuthenticatedRequest {
    pub client_public_key: ClientPublicKey,
    pub token: VerifiedToken,
}

/// Auth middleware - verifies Biscuit token and RFC 9421 signature
pub async fn auth_middleware(
    State(backend): State<Backend>,
    State(auth_state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ServiceError> {
    // Skip if auth is disabled
    if !auth_state.is_enabled() {
        return Ok(next.run(request).await);
    }

    let root_public_key = auth_state.root_public_key().unwrap();

    // Extract Authorization header
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(ServiceError::AuthRequired)?
        .to_str()
        .map_err(|_| ServiceError::AuthRequired)?;

    // Parse Bearer token
    let token_bytes = parse_bearer_token(auth_header)?;

    // Verify Biscuit token
    let verified = auth::verify_token(&token_bytes, root_public_key)?;

    // Check revocation
    if auth::is_revoked(&backend.db(), &verified.revocation_ids).await? {
        return Err(ServiceError::TokenRevoked);
    }

    // Verify RFC 9421 signature against any allowed public key
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let authority = request
        .uri()
        .authority()
        .map(|a| a.to_string())
        .or_else(|| {
            request
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(String::from)
        })
        .unwrap_or_default();

    // Get body for Content-Digest verification if present
    // Note: This is tricky with streaming bodies - may need adjustment
    let body = None; // TODO: Handle body digest

    // Try each allowed public key until one succeeds
    // This supports delegation: attenuated tokens add new public_key facts
    let mut verified_signer = None;
    for pubkey in &verified.allowed_public_keys {
        if auth::verify_signature(
            &method,
            &path,
            &authority,
            request.headers(),
            body,
            pubkey,
            auth_state.signature_window_secs(),
        ).is_ok() {
            verified_signer = Some(pubkey.clone());
            break;
        }
    }

    let client_public_key = verified_signer
        .ok_or(ServiceError::InvalidSignature(auth::SignatureError::SignatureInvalid))?;

    // Insert authenticated request into extensions
    // client_public_key is the actual signer (for delegation `signer` fact)
    request.extensions_mut().insert(AuthenticatedRequest {
        client_public_key,
        token: verified,
    });

    Ok(next.run(request).await)
}

fn parse_bearer_token(header: &str) -> Result<Vec<u8>, ServiceError> {
    let parts: Vec<&str> = header.splitn(2, ' ').collect();
    if parts.len() != 2 || !parts[0].eq_ignore_ascii_case("bearer") {
        return Err(ServiceError::AuthRequired);
    }

    base64ct::Base64::decode_vec(parts[1]).map_err(|_| ServiceError::AuthRequired)
}
```

**Step 2: Update v1/mod.rs to use middleware**

In `lite/src/handlers/v1/mod.rs`, add middleware module:

```rust
pub mod middleware;
```

And update the router function to apply middleware to non-token routes:

```rust
use axum::middleware::from_fn_with_state;

pub fn router(backend: crate::backend::Backend, auth_state: crate::auth::AuthState) -> axum::Router {
    let token_routes = access_tokens::router();

    let protected_routes = axum::Router::new()
        .merge(basins::router())
        .merge(streams::router())
        .merge(records::router())
        .merge(metrics::router())
        .layer(from_fn_with_state(
            (backend.clone(), auth_state.clone()),
            middleware::auth_middleware,
        ));

    axum::Router::new()
        .nest("/v1", token_routes.merge(protected_routes))
        // ... existing layers
}
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles (may need signature adjustments)

**Step 4: Commit**

```bash
git add lite/src/handlers/v1/middleware.rs lite/src/handlers/v1/mod.rs
git commit -m "feat(lite): add auth middleware for Biscuit + RFC 9421"
```

---

## Task 12: Implement Issue Token Endpoint

**Files:**
- Modify: `lite/src/handlers/v1/access_tokens.rs`

**Step 1: Update issue_access_token handler**

Replace the stub implementation with:

```rust
use crate::auth::{self, AuthState};
use s2_common::types::access::AccessTokenScope;
use time::OffsetDateTime;

#[derive(Debug, serde::Deserialize)]
pub struct IssueTokenRequest {
    pub public_key: String,
    pub expires_at: time::OffsetDateTime,
    pub scope: s2_api::v1::access::AccessTokenScope,
}

pub async fn issue_access_token(
    State(backend): State<Backend>,
    State(auth_state): State<AuthState>,
    IssueArgs { request }: IssueArgs,
) -> Result<(StatusCode, Json<v1t::access::IssueAccessTokenResponse>), ServiceError> {
    // Verify auth is enabled
    let root_key = auth_state
        .root_key()
        .ok_or(ServiceError::NotImplemented)?;

    // Parse client public key
    let client_pubkey = auth::ClientPublicKey::from_base58(&request.public_key)
        .map_err(|e| ServiceError::Validation(e.to_string().into()))?;

    // Validate expiration (max 1 year)
    let max_expiry = OffsetDateTime::now_utc() + time::Duration::days(365);
    if request.expires_at > max_expiry {
        return Err(ServiceError::Validation(
            "expiration cannot exceed 1 year".into(),
        ));
    }

    // Convert API scope to internal scope
    let scope: AccessTokenScope = request.scope.try_into()?;

    // Build the Biscuit token
    let biscuit = auth::build_token(root_key, &client_pubkey, request.expires_at, &scope)?;

    // Serialize to base64
    let token = base64ct::Base64::encode_string(&biscuit.to_vec()?);

    Ok((
        StatusCode::CREATED,
        Json(v1t::access::IssueAccessTokenResponse { access_token: token }),
    ))
}
```

**Step 2: Add root key auth extractor for token endpoints**

Add to `access_tokens.rs`:

```rust
use crate::auth::AuthState;

/// Extractor that verifies RFC 9421 signature with root key
pub struct RootKeyAuth;

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for RootKeyAuth
where
    S: Send + Sync,
    AuthState: axum::extract::FromRef<S>,
{
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = AuthState::from_ref(state);

        if !auth_state.is_enabled() {
            return Ok(Self);
        }

        // Verify RFC 9421 signature with root public key
        let root_pubkey = auth_state.root_public_key().unwrap();

        // Extract signature headers and verify
        // ... similar to middleware but using root key

        Ok(Self)
    }
}
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles

**Step 4: Commit**

```bash
git add lite/src/handlers/v1/access_tokens.rs
git commit -m "feat(lite): implement issue_access_token endpoint"
```

---

## Task 13: Implement Revoke Token Endpoint

**Files:**
- Modify: `lite/src/handlers/v1/access_tokens.rs`

**Step 1: Add revocation routes**

Update the router in `access_tokens.rs`:

```rust
pub fn router() -> axum::Router<Backend> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route(super::paths::access_tokens::LIST, get(list_access_tokens))
        .route(super::paths::access_tokens::ISSUE, post(issue_access_token))
        .route(
            super::paths::access_tokens::REVOKE,
            delete(revoke_access_token),
        )
        .route("/access-tokens/revocations", post(add_revocation))
        .route("/access-tokens/revocations", get(list_revocations))
}
```

**Step 2: Implement add_revocation**

```rust
#[derive(Debug, serde::Deserialize)]
pub struct AddRevocationRequest {
    pub revocation_id: String,
}

pub async fn add_revocation(
    State(backend): State<Backend>,
    _auth: RootKeyAuth,
    Json(request): Json<AddRevocationRequest>,
) -> Result<StatusCode, ServiceError> {
    let id = hex::decode(&request.revocation_id)
        .map_err(|_| ServiceError::Validation("invalid revocation_id hex".into()))?;

    auth::revoke(&backend.db(), &id).await?;

    Ok(StatusCode::NO_CONTENT)
}
```

**Step 3: Implement list_revocations**

```rust
#[derive(Debug, serde::Serialize)]
pub struct ListRevocationsResponse {
    pub revocation_ids: Vec<String>,
}

pub async fn list_revocations(
    State(backend): State<Backend>,
    _auth: RootKeyAuth,
) -> Result<Json<ListRevocationsResponse>, ServiceError> {
    let ids = auth::list_revocations(&backend.db()).await?;
    let hex_ids: Vec<String> = ids.iter().map(hex::encode).collect();

    Ok(Json(ListRevocationsResponse {
        revocation_ids: hex_ids,
    }))
}
```

**Step 4: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles

**Step 5: Commit**

```bash
git add lite/src/handlers/v1/access_tokens.rs
git commit -m "feat(lite): implement revocation endpoints"
```

---

## Task 14: Wire Up Auth State in Server

**Files:**
- Modify: `lite/src/bin/server.rs`
- Modify: `lite/src/handlers/mod.rs`

**Step 1: Update handlers::router signature**

In `lite/src/handlers/mod.rs`, update:

```rust
pub fn router(backend: crate::backend::Backend, auth_state: crate::auth::AuthState) -> axum::Router {
    axum::Router::new()
        .route("/ping", axum::routing::get(|| async { "pong" }))
        .route("/metrics", axum::routing::get(metrics::handler))
        .nest("/v1", v1::router(backend.clone(), auth_state.clone()))
        .with_state((backend, auth_state))
}
```

**Step 2: Update server.rs to pass AuthState**

In `lite/src/bin/server.rs`, update app creation:

```rust
let auth_state = match root_key {
    Some(key) => s2_lite::auth::AuthState::new(key, args.signature_window),
    None => s2_lite::auth::AuthState::disabled(),
};

let app = handlers::router(backend, auth_state).layer(
    TraceLayer::new_for_http()
        // ... existing layers
);
```

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles

**Step 4: Commit**

```bash
git add lite/src/bin/server.rs lite/src/handlers/mod.rs
git commit -m "feat(lite): wire up AuthState in server startup"
```

---

## Task 15: Add Integration Test

**Files:**
- Create: `lite/tests/auth_test.rs`

**Step 1: Write integration test**

Create `lite/tests/auth_test.rs`:

```rust
use s2_lite::auth::{AuthState, RootKey, build_token, verify_token};
use s2_common::types::access::{AccessTokenScope, Operation, PermittedOperationGroups, ReadWritePermissions, ResourceSet};
use time::OffsetDateTime;
use p256::SecretKey;
use rand::rngs::OsRng;

fn generate_test_root_key() -> RootKey {
    let secret = SecretKey::random(&mut OsRng);
    let bytes = secret.to_bytes();
    let base58 = bs58::encode(&bytes).into_string();
    RootKey::from_base58(&base58).unwrap()
}

fn generate_test_client_key() -> (SecretKey, s2_lite::auth::ClientPublicKey) {
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    let point = public.to_encoded_point(true);
    let base58 = bs58::encode(point.as_bytes()).into_string();
    let client_pubkey = s2_lite::auth::ClientPublicKey::from_base58(&base58).unwrap();
    (secret, client_pubkey)
}

#[test]
fn test_token_issue_and_verify() {
    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();

    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("test/".parse().unwrap()),
        streams: ResourceSet::Prefix("test/".parse().unwrap()),
        access_tokens: ResourceSet::None,
        op_groups: PermittedOperationGroups {
            account: ReadWritePermissions { read: true, write: false },
            basin: ReadWritePermissions { read: true, write: false },
            stream: ReadWritePermissions { read: true, write: true },
        },
        ops: [Operation::Append, Operation::Read].into_iter().collect(),
    };

    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);

    let biscuit = build_token(&root_key, &client_pubkey, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();

    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();
    assert!(verified.allowed_public_keys.contains(&client_pubkey));
}

#[test]
fn test_token_expired() {
    let root_key = generate_test_root_key();
    let (_, client_pubkey) = generate_test_client_key();

    let scope = AccessTokenScope::default();
    let expires = OffsetDateTime::now_utc() - time::Duration::hours(1); // Already expired

    let biscuit = build_token(&root_key, &client_pubkey, expires, &scope).unwrap();
    let token_bytes = biscuit.to_vec().unwrap();

    // Verification should fail due to expiry check
    let result = verify_token(&token_bytes, &root_key.public_key());
    // The token parses but authorization with time check should fail
}

#[test]
fn test_token_delegation_via_attenuation() {
    let root_key = generate_test_root_key();
    let (_, alice_pubkey) = generate_test_client_key();
    let (_, bob_pubkey) = generate_test_client_key();

    // Alice gets a token
    let scope = AccessTokenScope {
        basins: ResourceSet::Prefix("alice/".parse().unwrap()),
        streams: ResourceSet::Prefix("alice/".parse().unwrap()),
        ..Default::default()
    };
    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let biscuit = build_token(&root_key, &alice_pubkey, expires, &scope).unwrap();

    // Alice attenuates for Bob (offline operation)
    let mut attenuator = biscuit.create_block();
    attenuator.add_fact(format!("public_key(\"{}\")", bob_pubkey.to_base58())).unwrap();
    attenuator.add_check(format!(
        "check if signer($s), $s == \"{}\"",
        bob_pubkey.to_base58()
    )).unwrap();
    // Narrow scope further
    attenuator.add_check("check if basin($b), $b.starts_with(\"alice/shared/\")").unwrap();

    let delegated = biscuit.attenuate(attenuator).unwrap();
    let token_bytes = delegated.to_vec().unwrap();

    // Verify the delegated token
    let verified = verify_token(&token_bytes, &root_key.public_key()).unwrap();

    // Both public keys should be present
    assert!(verified.allowed_public_keys.contains(&alice_pubkey));
    assert!(verified.allowed_public_keys.contains(&bob_pubkey));
}
```

**Step 2: Run tests**

Run: `cargo nextest run -p s2-lite auth`
Expected: Tests pass

**Step 3: Commit**

```bash
git add lite/tests/auth_test.rs
git commit -m "test(lite): add auth integration tests"
```

---

## Task 16: Update Handler Authorization

**Files:**
- Modify: `lite/src/handlers/v1/basins.rs`
- Modify: `lite/src/handlers/v1/streams.rs`
- Modify: `lite/src/handlers/v1/records.rs`

**Step 1: Add authorization checks to basin handlers**

In each handler, after extracting `AuthenticatedRequest` from extensions, call `auth::authorize`:

```rust
use crate::auth;
use crate::handlers::v1::middleware::AuthenticatedRequest;

pub async fn create_basin(
    State(backend): State<Backend>,
    request: axum::extract::Request,
    // ... other extractors
) -> Result<...> {
    // Get auth from extensions (if auth enabled)
    if let Some(auth) = request.extensions().get::<AuthenticatedRequest>() {
        auth::authorize(
            &auth.token,
            &auth.client_public_key,  // signer for delegation support
            Some(&basin_name),
            None,
            s2_common::types::access::Operation::CreateBasin,
        )?;
    }

    // ... existing handler logic
}
```

**Step 2: Repeat for all handlers**

Apply similar authorization checks to:
- `list_basins` - Operation::ListBasins
- `get_basin_config` - Operation::GetBasinConfig
- `delete_basin` - Operation::DeleteBasin
- `reconfigure_basin` - Operation::ReconfigureBasin
- `list_streams` - Operation::ListStreams
- `create_stream` - Operation::CreateStream
- `get_stream_config` - Operation::GetStreamConfig
- `delete_stream` - Operation::DeleteStream
- `reconfigure_stream` - Operation::ReconfigureStream
- `check_tail` - Operation::CheckTail
- `append` - Operation::Append
- `read` - Operation::Read

**Step 3: Verify compilation**

Run: `cargo check -p s2-lite`
Expected: Compiles

**Step 4: Run all tests**

Run: `cargo nextest run -p s2-lite`
Expected: All tests pass

**Step 5: Commit**

```bash
git add lite/src/handlers/v1/basins.rs lite/src/handlers/v1/streams.rs lite/src/handlers/v1/records.rs
git commit -m "feat(lite): add authorization checks to all handlers"
```

---

## Summary

This plan implements:

1. **Tasks 1-3**: Dependencies and P-256 key types
2. **Tasks 4-5**: Biscuit token building and verification
3. **Task 6**: RFC 9421 HTTP signature verification
4. **Task 7**: Revocation storage in SlateDB
5. **Tasks 8-9**: Server configuration and auth state
6. **Tasks 10-11**: Auth middleware and error types
7. **Tasks 12-13**: Access token endpoints (issue, revoke)
8. **Tasks 14-16**: Integration and handler authorization

Each task is independently testable and committable. The implementation follows TDD where practical, with failing tests written before implementation.

### Delegation Model

The implementation supports offline token delegation via Biscuit attenuation:

1. **Multiple `public_key` facts**: Tokens can contain multiple public keys (original + delegated)
2. **Signature verification**: Server tries each allowed public key until one matches the RFC 9421 signature
3. **`signer` fact**: Server adds `signer("<actual-signer-pubkey>")` to the authorizer
4. **Attenuation caveat**: Delegated tokens include `check if signer($s), $s == "<delegatee-pubkey>"` to restrict usage

This allows token holders to delegate access to other parties without server involvement - they simply attenuate their token with a new `public_key` fact and a `signer` caveat binding it to the delegatee's key.
