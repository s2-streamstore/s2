# Authorization Design

> **Status:** Implemented. See [lite/docs/authentication.md](../../lite/docs/authentication.md) for usage documentation.

Stateless authorization for s2-lite using Biscuit tokens and RFC 9421 HTTP Message Signatures.

## Overview

| Component | Technology |
|-----------|------------|
| Token format | Biscuit |
| Token signing | ECDSA P-256 (root key) |
| Request signing | RFC 9421 with ECDSA P-256 (client key) |
| Revocation storage | SlateDB |
| Scope model | Existing `AccessTokenScope` |

## Token Structure

Biscuit tokens with P-256 signatures. Client public key baked into token for RFC 9421 binding.

```
=== AUTHORITY BLOCK ===
(signed by root key P-256)

// Identity binding
public_key("2NEpo7TZRRrLZSi2U...");  // client's P-256 pubkey, base58 compressed

// Expiration
expires(2025-12-01T00:00:00Z);
check if time($t), $t < 2025-12-01T00:00:00Z;

// Resource scope
basin_scope(prefix, "tenant-a/");      // or basin_scope(exact, "my-basin") or basin_scope(none)
stream_scope(prefix, "tenant-a/");
access_token_scope(prefix, "tenant-a/");

// Operation groups (coarse)
op_group(account, read);
op_group(basin, read);
op_group(basin, write);
op_group(stream, read);
op_group(stream, write);

// Individual operations (fine-grained)
op(list_basins);
op(create_basin);
op(append);
op(read);
// ... from the 21 operations in common/src/types/access.rs

=== SIGNATURE ===
P-256 ECDSA signature by root private key

=== ATTENUATION BLOCK (optional, added by token holder) ===
(signed by key derived from authority block)

// Can only add restrictions, not expand
check if basin($b), $b.starts_with("tenant-a/project-1/");
check if operation($op), ["read", "check_tail"].contains($op);
check if time($t), $t < 2025-06-01T00:00:00Z;  // tighter expiry

// Delegation: rebind to a different client key
public_key("3ABcd8UVWxyz...");                    // new client's pubkey
check if signer($s), $s == "3ABcd8UVWxyz...";    // only new client can use
```

### Offline Delegation via Attenuation

Token holders can delegate access to another party without server involvement:

1. New client generates keypair (`s2 keygen`)
2. Token holder attenuates their token, adding:
   - `public_key("<new-client-pubkey>")` fact
   - `check if signer($s), $s == "<new-client-pubkey>"` caveat
   - Any additional scope restrictions
3. New client receives attenuated token + uses their private key for RFC 9421 signing

The `signer` caveat ensures only the new client can use the attenuated token, even though the original `public_key` fact remains in the authority block. Server adds `signer("<actual-signer>")` fact during verification.

### Key Formats

- P-256 private key: 32 bytes scalar, base58 encoded (~44 chars)
- P-256 public key: compressed point (33 bytes), base58 encoded (~45 chars)

## HTTP Request Flow

### Authenticated Request

```http
POST /basins/tenant-a/streams/logs/records HTTP/1.1
Host: s2.example.com
Authorization: Bearer <base64-biscuit-token>
Content-Type: application/octet-stream
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@path" "@authority" "authorization" "content-digest");created=1704067200;keyid="2NEpo7TZRRrLZSi2U..."
Signature: sig1=:BASE64_ECDSA_P256_SIGNATURE:

<record bytes>
```

### Server Verification Steps

1. Parse `Authorization: Bearer <token>`, deserialize Biscuit
2. Verify Biscuit signature against root public key
3. Extract all `public_key` facts from token (authority + attenuation blocks)
4. Verify RFC 9421 signature using any matching public key
5. Check `created` timestamp is within allowed window (default ±5 minutes)
6. Extract Biscuit revocation IDs, check against SlateDB revocation list
7. Run Biscuit authorizer:
   - Add facts: `time(now)`, `basin("tenant-a")`, `stream("logs")`, `operation(append)`
   - Add fact: `signer("<pubkey-that-signed-request>")` for delegation support
   - Check all caveats pass (including `check if signer(...)` for delegated tokens)
   - Check scope facts allow this basin/stream
   - Check ops/op_groups allow this operation

Request rejected if any step fails.

### Signing Keys

| Key | Signs |
|-----|-------|
| Root key (P-256) | Biscuit token (authority block) |
| Client key (P-256) | HTTP request via RFC 9421 |

## Access Token Endpoints

These endpoints accept the raw root key for RFC 9421 signing (no Biscuit token needed).

### Issue Token

```http
POST /access_tokens HTTP/1.1
Host: s2.example.com
Content-Type: application/json
Content-Digest: sha-256=:...:
Signature-Input: sig1=("@method" "@path" "@authority" "content-digest");created=1704067200;keyid="root"
Signature: sig1=:P256_SIGNATURE_BY_ROOT_KEY:

{
  "public_key": "2NEpo7TZRRrLZSi2U...",
  "expires_at": "2025-12-01T00:00:00Z",
  "scope": {
    "basins": {"prefix": "tenant-a/"},
    "streams": {"prefix": "tenant-a/"},
    "access_tokens": {"prefix": "tenant-a/"},
    "op_groups": {
      "account": {"read": true},
      "stream": {"read": true, "write": true}
    },
    "ops": ["append", "read", "check_tail"]
  }
}
```

Response:

```json
{
  "token": "<base64-biscuit-token>"
}
```

### Revoke Token

```http
DELETE /access_tokens/revocations HTTP/1.1
Content-Digest: sha-256=:...:
Signature-Input: sig1=("@method" "@path" "@authority" "content-digest");created=...;keyid="root"
Signature: sig1=:...:

{
  "revocation_id": "<biscuit-revocation-id-hex>"
}
```

Stores the revocation ID in SlateDB.

### List Revocations

```http
GET /access_tokens/revocations HTTP/1.1
Signature-Input: sig1=("@method" "@path" "@authority");created=...;keyid="root"
Signature: sig1=:...:
```

Returns list of revoked IDs. No "list active tokens" since we don't track issued tokens (stateless).

## Server Configuration

### CLI Arguments

```bash
s2-lite server \
  --root-key <base58-p256-private-key> \
  --signature-window 300 \
  ...existing args...
```

### Environment Variables

```bash
S2_ROOT_KEY=<base58-p256-private-key>
S2_SIGNATURE_WINDOW=300  # seconds, optional, default 300
```

### Startup Behavior

1. Root key is required - server refuses to start without it
2. Derive root public key from private key
3. Initialize SlateDB (existing) - revocation IDs stored under `revocations/` prefix
4. Start HTTP server with auth middleware enabled

### Generating a Root Key

```bash
# Example with openssl
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl ec -no_public -outform DER | tail -c 32 | base58

# Or any P-256 keygen tool
```

## Auth Middleware Integration

### Extractors

```rust
// For authenticated requests (most endpoints)
pub struct AuthenticatedRequest {
    pub public_key: P256PublicKey,      // caller identity
    pub scope: AccessTokenScope,         // effective permissions
    pub biscuit: Biscuit,                // for further attenuation if needed
}

// For access token endpoints (root key auth)
pub struct RootKeyRequest {
    // Verified via RFC 9421 signature with root key
}
```

### Middleware

```rust
// Applies to all routes except /access_tokens/*
async fn auth_middleware(
    State(backend): State<Backend>,
    request: Request,
    next: Next,
) -> Result<Response, ServiceError> {
    // 1. Extract + verify Biscuit from Authorization header
    // 2. Extract public_key, verify RFC 9421 signature
    // 3. Check timestamp window
    // 4. Check revocation list in SlateDB
    // 5. Inject AuthenticatedRequest into request extensions
    // 6. Call next handler
}
```

### Handler Authorization

```rust
pub async fn append(
    State(backend): State<Backend>,
    auth: AuthenticatedRequest,
    Path((basin, stream)): Path<(BasinName, StreamName)>,
    body: Bytes,
) -> Result<AppendResponse, ServiceError> {
    let mut authorizer = Authorizer::new();
    authorizer.add_fact(format!("basin(\"{}\")", basin));
    authorizer.add_fact(format!("stream(\"{}\")", stream));
    authorizer.add_fact("operation(append)");
    authorizer.add_fact(format!("time({})", now_rfc3339()));
    authorizer.add_fact(format!("signer(\"{}\")", auth.public_key));  // for delegation
    authorizer.authorize(&auth.biscuit)?;

    // Proceed with append...
}
```

## Revocation Storage

### SlateDB Key Layout

```
revocations/<revocation-id-hex> → <empty value>
```

Revocation IDs are Biscuit's built-in cryptographic identifiers (~32 bytes, hex = 64 chars).

### Operations

```rust
impl Backend {
    // Check if token is revoked (called on every request)
    pub async fn is_revoked(&self, revocation_ids: &[RevocationId]) -> Result<bool> {
        // Biscuit tokens have multiple revocation IDs (one per block)
        // Token is revoked if ANY of its IDs are in the list
        for id in revocation_ids {
            let key = format!("revocations/{}", id.to_hex());
            if self.db.get(key.as_bytes()).await?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    // Revoke a token
    pub async fn revoke(&self, revocation_id: RevocationId) -> Result<()> {
        let key = format!("revocations/{}", revocation_id.to_hex());
        self.db.put(key.as_bytes(), &[]).await
    }

    // List revocations (admin use)
    pub async fn list_revocations(&self) -> Result<Vec<RevocationId>> {
        self.db.prefix_scan(b"revocations/").await
            .map(|(k, _)| RevocationId::from_hex(&k[12..]))
            .collect()
    }
}
```

### Revocation Semantics

A Biscuit has one revocation ID per block:
- Revoke authority block ID → original token AND all attenuated versions revoked
- Revoke attenuation block ID → only that specific attenuated token revoked

## Constraints

- Tokens always expire (max 1 year)
- No permanent tokens
- No superuser bypass - root key only for token management endpoints
- Attenuation can only narrow scope, never widen
- Public key in token = user identity

## Dependencies

- `biscuit-auth` - Biscuit token handling
- RFC 9421 implementation - may need to find or build
- `p256` / `ecdsa` crates - P-256 key handling
- `bs58` - base58 encoding
