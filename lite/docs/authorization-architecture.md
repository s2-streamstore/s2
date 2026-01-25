# Authorization Architecture

Internal architecture documentation for the s2-lite authorization system. For user-facing documentation, see [authentication.md](./authentication.md).

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              HTTP Request                                        │
│  Authorization: Bearer <biscuit>                                                │
│  Signature-Input: sig1=("@method" "@path" "@authority" "authorization");...     │
│  Signature: sig1=:<ecdsa-p256-signature>:                                       │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          auth_middleware                                         │
│                    (lite/src/handlers/v1/middleware.rs)                         │
├─────────────────────────────────────────────────────────────────────────────────┤
│  1. Skip if auth disabled (no root key)                                         │
│  2. Extract + verify Biscuit token ──────────────► verify.rs::verify_token()    │
│  3. Check revocation IDs ────────────────────────► revocation.rs::is_revoked()  │
│  4. Verify RFC 9421 signature ───────────────────► httpsig.rs::verify_request() │
│  5. Check signature timestamp window                                             │
│  6. Inject AuthenticatedRequest into extensions                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              Handler                                             │
│                    (lite/src/handlers/v1/*.rs)                                  │
├─────────────────────────────────────────────────────────────────────────────────┤
│  1. Extract AuthenticatedRequest from extensions                                 │
│  2. Call authorize() with operation + resources ─► verify.rs::authorize()       │
│  3. Execute business logic if authorized                                         │
└─────────────────────────────────────────────────────────────────────────────────┘
```

## Module Structure

```
lite/src/auth/
├── mod.rs           # Public exports
├── keys.rs          # Key types: RootKey, RootPublicKey, ClientPublicKey
├── token.rs         # Biscuit token building (build_token)
├── verify.rs        # Token verification + authorization (verify_token, authorize)
├── httpsig.rs       # RFC 9421 HTTP signature verification
├── revocation.rs    # SlateDB-based revocation storage
└── state.rs         # AuthState: shared config for middleware
```

## Key Types

### `RootKey` (keys.rs:15)

The server's P-256 private key for signing Biscuit tokens.

```rust
pub struct RootKey {
    inner: SigningKey,  // p256::ecdsa::SigningKey
}

impl RootKey {
    // Parse from base58-encoded 32-byte scalar
    pub fn from_base58(s: &str) -> Result<Self, KeyError>;

    // Get the corresponding public key
    pub fn public_key(&self) -> RootPublicKey;

    // Build a Biscuit keypair for token signing
    pub fn biscuit_keypair(&self) -> biscuit_auth::KeyPair;
}
```

### `RootPublicKey` (keys.rs:55)

The server's P-256 public key, derived from RootKey. Used to verify Biscuit tokens.

```rust
pub struct RootPublicKey {
    inner: VerifyingKey,  // p256::ecdsa::VerifyingKey
}

impl RootPublicKey {
    // Parse from base58-encoded compressed point (33 bytes)
    pub fn from_base58(s: &str) -> Result<Self, KeyError>;

    // Encode as base58
    pub fn to_base58(&self) -> String;

    // Build Biscuit public key for verification
    pub fn biscuit_public_key(&self) -> biscuit_auth::PublicKey;
}
```

### `ClientPublicKey` (keys.rs:95)

A client's P-256 public key, embedded in tokens and used to verify RFC 9421 signatures.

```rust
pub struct ClientPublicKey {
    inner: VerifyingKey,
}

impl ClientPublicKey {
    // Same interface as RootPublicKey
    pub fn from_base58(s: &str) -> Result<Self, KeyError>;
    pub fn to_base58(&self) -> String;

    // Convert from VerifyingKey (used for root key comparison)
    pub fn from_verifying_key(key: &VerifyingKey) -> Self;
}
```

## Token Building (token.rs)

### `build_token()`

Creates a Biscuit token from an `AccessTokenScope`.

```rust
pub fn build_token(
    root_key: &RootKey,
    client_public_key: &ClientPublicKey,
    expires_at: OffsetDateTime,
    scope: &AccessTokenScope,
) -> Result<Biscuit, TokenBuildError>;
```

**Token Structure (Datalog facts):**

```datalog
// Client identity - which key can sign requests
public_key("2NEpo7TZRRrLZSi2U8FxKaAqV3FJ8MFmCxLBqQMZxBGZ");

// Expiration
expires(1735689599);
check if time($t), $t < 1735689599;

// Resource scopes (one per resource type)
basin_scope("prefix", "my-app/");      // ResourceSet::Prefix
stream_scope("exact", "my-stream");    // ResourceSet::Exact
access_token_scope("none", "");        // ResourceSet::None

// Operation groups (coarse-grained)
op_group("account", "read");
op_group("stream", "write");

// Individual operations (fine-grained, optional)
op("append");
op("read");
```

**Validation:**
- Expiration must be in the future
- Expiration must be within 1 year
- At least one permission must be granted
- Scope values are sanitized to prevent Datalog injection

## Token Verification (verify.rs)

### `verify_token()`

Verifies a Biscuit token's signature and extracts metadata.

```rust
pub fn verify_token(
    token_bytes: &[u8],
    root_public_key: &RootPublicKey,
) -> Result<VerifiedToken, VerifyError>;

pub struct VerifiedToken {
    pub biscuit: Biscuit,
    pub allowed_public_keys: Vec<ClientPublicKey>,
    pub revocation_ids: Vec<Vec<u8>>,
}
```

**Steps:**
1. Size check (reject > 64KB to prevent DoS)
2. Deserialize Biscuit from bytes
3. Verify signature against root public key
4. Extract all `public_key(...)` facts from all blocks (for delegation)
5. Extract revocation IDs from each block

### `authorize()`

Checks if a verified token authorizes a specific operation.

```rust
pub fn authorize(
    token: &VerifiedToken,
    signer_public_key: &ClientPublicKey,
    root_public_key: Option<&RootPublicKey>,
    basin: Option<&str>,
    stream: Option<&str>,
    access_token_id: Option<&str>,
    operation: Operation,
) -> Result<(), AuthorizeError>;
```

**Authorization Flow:**

```
1. Signer Verification
   └── Is signer_public_key in token.allowed_public_keys?
       └── No → AuthorizeError::UnauthorizedSigner

2. Root Key Restriction (if root_public_key provided)
   └── Is signer the root key?
       └── Yes and operation NOT in [IssueAccessToken, RevokeAccessToken, ListAccessTokens]
           └── AuthorizeError::RootKeyNotAllowed

3. Scope Verification (parsed from token)
   └── Check basin is in scope (if basin provided)
   └── Check stream is in scope (if stream provided)
   └── Check access_token is in scope (if access_token_id provided)

4. Datalog Authorization
   └── Add time fact: time(<unix_timestamp>)
   └── Add signer fact: signer("<pubkey>")
   └── Add resource facts: basin("..."), stream("...")
   └── Add operation fact: operation("append")
   └── Run authorizer with allow/deny policy
       └── Allow if: op("operation") OR matching op_group
       └── Deny otherwise
```

### Scope Checking

Scope facts are parsed from the token and checked in Rust (not Datalog) for clarity:

```rust
fn check_scope(scope_type: &str, scope_value: &str, resource: &str) -> bool {
    match scope_type {
        "none" => false,
        "exact" => scope_value == resource,
        "prefix" => resource.starts_with(scope_value),
        _ => false,
    }
}
```

## HTTP Signature Verification (httpsig.rs)

### `verify_request()`

Verifies an RFC 9421 HTTP signature.

```rust
pub fn verify_request(
    method: &str,
    path: &str,
    authority: &str,
    headers: &HeaderMap,
    body: Option<&[u8]>,
    allowed_public_keys: &[ClientPublicKey],
    signature_window_secs: u64,
) -> Result<ClientPublicKey, HttpSigError>;
```

**Verification Steps:**

```
1. Parse Headers
   └── Extract Signature-Input header (structured field)
   └── Extract Signature header (base64 in :...: format)
   └── Extract Content-Digest (if request has body)

2. Parse Signature-Input
   └── Get covered components: ("@method" "@path" "@authority" "authorization" ...)
   └── Get signature params: created, alg, keyid

3. Validate Algorithm
   └── Must be ecdsa-p256-sha256
   └── Reject if unsupported

4. Check Timestamp
   └── created must be within signature_window_secs of now
   └── Reject stale signatures (replay protection)

5. Build Signature Base (RFC 9421 Section 2.5)
   └── For each covered component:
       └── "@method": GET
       └── "@path": /v1/basins
       └── "@authority": s2.example.com
       └── "authorization": Bearer ...
   └── Append @signature-params line

6. Verify Content-Digest (if body present)
   └── Parse Content-Digest: sha-256=:<base64>:
   └── Compute SHA-256 of body
   └── Compare hashes

7. Verify Signature
   └── For each allowed_public_key:
       └── Attempt ECDSA P-256 verification
       └── Return first matching key
   └── Reject if no key matches
```

**Required Signed Components:**

| Component | Example | Required |
|-----------|---------|----------|
| `@method` | GET | Always |
| `@path` | /v1/basins | Always |
| `@authority` | s2.example.com | Always |
| `authorization` | Bearer ... | Always |
| `content-digest` | sha-256=:...: | If body present |

## Revocation Storage (revocation.rs)

Uses SlateDB for persistent revocation storage.

```rust
// Key format: "revocations/<hex-revocation-id>"
// Value: empty (existence = revoked)

pub async fn is_revoked(db: &Db, revocation_ids: &[Vec<u8>]) -> Result<bool>;
pub async fn revoke(db: &Db, revocation_id: &[u8]) -> Result<()>;
pub async fn list_revocations(db: &Db) -> Result<Vec<String>>;
```

**Revocation Semantics:**

Biscuit tokens have one revocation ID per block:
- Authority block ID: Revoking this revokes the token AND all attenuated versions
- Attenuation block ID: Revoking this revokes only that specific delegation

## Auth State (state.rs)

Shared configuration passed to middleware.

```rust
pub struct AuthState {
    root_key: Option<RootKey>,
    root_public_key: Option<RootPublicKey>,
    signature_window_secs: u64,
    metrics_token: Option<String>,
}

impl AuthState {
    // Full mode: can verify and issue tokens
    pub fn new(root_key: RootKey, signature_window: u64, metrics_token: Option<String>) -> Self;

    // Verify-only: can verify but not issue tokens
    pub fn verify_only(root_public_key: RootPublicKey, ...) -> Self;

    // Auth disabled: no authentication checks
    pub fn disabled() -> Self;

    // Metrics only: just protect metrics endpoints
    pub fn metrics_only(token: String) -> Self;
}
```

## Middleware Integration (handlers/v1/middleware.rs)

### `auth_middleware()`

Axum middleware that runs before every handler.

```rust
pub async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ServiceError>;
```

**Flow:**

```
1. Check if auth enabled
   └── If auth_state.root_public_key() is None, skip all auth

2. Extract token from Authorization header
   └── Parse "Bearer <base64>"
   └── Decode base64 to bytes

3. Verify Biscuit token
   └── Call verify_token()
   └── Get VerifiedToken { biscuit, allowed_public_keys, revocation_ids }

4. Check revocation
   └── Call is_revoked() with revocation_ids
   └── Reject if any ID is revoked

5. Build request context for signature verification
   └── method = request.method().as_str()
   └── path = request.uri().path()
   └── authority = from Host header or URI
   └── body = buffered request body (if present)

6. Verify RFC 9421 signature
   └── Call verify_request()
   └── Get signer_public_key (which allowed key signed)

7. Inject into request extensions
   └── AuthenticatedRequest { token, client_public_key: signer }

8. Call next handler
```

### `AuthenticatedRequest`

Extracted by handlers from request extensions.

```rust
pub struct AuthenticatedRequest {
    pub token: VerifiedToken,
    pub client_public_key: ClientPublicKey,
}
```

## Handler Authorization Pattern

Each handler is responsible for calling `authorize()`:

```rust
pub async fn append(
    State(backend): State<Backend>,
    State(auth_state): State<AuthState>,
    Path((basin, stream)): Path<(String, String)>,
    request: Request,
) -> Result<AppendResponse, ServiceError> {
    // 1. Extract auth from extensions (if present)
    if let Some(auth) = request.extensions().get::<AuthenticatedRequest>() {
        // 2. Authorize the specific operation
        authorize(
            &auth.token,
            &auth.client_public_key,
            auth_state.root_public_key(),  // Prevent root key bypass
            Some(&basin),
            Some(&stream),
            None,  // access_token_id
            Operation::Append,
        )?;
    }

    // 3. Proceed with operation
    backend.append(&basin, &stream, ...).await
}
```

## Delegation Support

Biscuit's attenuation feature enables offline delegation.

### Token Attenuation Flow

```
1. Alice has a token with:
   - public_key("alice-pubkey") in authority block
   - op_group("stream", "write")
   - basin_scope("prefix", "alice/")

2. Bob generates keypair, shares public key with Alice

3. Alice attenuates token (offline, no server):
   - Add new block with:
     - public_key("bob-pubkey")
     - check if signer($s), $s == "bob-pubkey"
     - check if basin($b), $b.starts_with("alice/shared/")

4. Token now has:
   - Authority block: public_key("alice-pubkey"), ...
   - Attenuation block: public_key("bob-pubkey"), signer check

5. Bob uses attenuated token:
   - Signs requests with bob's private key
   - Server extracts both public keys from token
   - Verifies signature with bob's key
   - Adds signer("bob-pubkey") fact to authorizer
   - Caveat `check if signer($s), $s == "bob-pubkey"` passes
```

### Server-Side Handling

In `authorize()`, the `signer` fact is added to bind the authorization to the actual signing key:

```rust
// In authorize():
authorizer.add_fact(format!("signer(\"{}\")", signer_public_key.to_base58()));
```

This enables the `check if signer(...)` caveat in attenuated tokens to work correctly.

## Security Properties

### Implemented

| Property | Mechanism |
|----------|-----------|
| Token authenticity | Biscuit signature with root key |
| Request binding | RFC 9421 signature with client key |
| Replay protection | Signature timestamp window (default 300s) |
| Token revocation | SlateDB-stored revocation IDs |
| Scope attenuation | Biscuit blocks can only add restrictions |
| DoS protection | 64KB token size limit |
| Root key protection | Root key rejected for non-token-management operations |

### Constraints

| Constraint | Enforcement |
|------------|-------------|
| All tokens expire | Token build rejects past expiration |
| Max 1 year expiration | Token build enforces maximum |
| Attenuation can only restrict | Biscuit's cryptographic design |
| No scope escalation | Server-issued tokens only via root key |

## Testing

### Unit Tests

- `keys.rs::tests` - Key parsing roundtrips
- `verify.rs::tests` - Token verification, authorization logic
- `httpsig.rs::tests` - RFC 9421 signature verification
- `state.rs::tests` - AuthState configuration modes
- `revocation.rs::tests` - Revocation storage operations

### Integration Tests

- `tests/auth_test.rs` - End-to-end token flows, delegation
- `tests/auth_http_test.rs` - Full HTTP request signing, middleware integration

### Running Tests

```bash
# All auth tests
cargo test --package s2-lite auth

# Specific module
cargo test --package s2-lite --lib auth::verify

# Integration tests
cargo test --package s2-lite --test auth_test
cargo test --package s2-lite --test auth_http_test
```
