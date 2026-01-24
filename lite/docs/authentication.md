# Authentication & Authorization

s2-lite supports stateless authentication using [Biscuit tokens](https://biscuitsec.org/) with [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html).

## Overview

| Component | Technology |
|-----------|------------|
| Token format | Biscuit 3.0 |
| Token signing | ECDSA P-256 (secp256r1) |
| Request signing | RFC 9421 HTTP Message Signatures with ECDSA P-256 |
| Revocation storage | SlateDB |
| Scope model | `AccessTokenScope` (basins, streams, access_tokens, operations) |

When authentication is enabled:
1. All API requests require a Biscuit token in the `Authorization: Bearer` header
2. All API requests must be signed per RFC 9421 using the client's P-256 key
3. The client's public key must be embedded in the token

## Quick Start

### 1. Generate a Root Key

The root key is a P-256 private key used to sign access tokens. Generate one using OpenSSL:

```bash
# Generate P-256 private key (32 bytes), encode as base58
openssl ecparam -name prime256v1 -genkey -noout | \
  openssl ec -no_public -outform DER 2>/dev/null | \
  tail -c 32 | base58

# Example output: 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
```

Or using the `s2` CLI (if available):

```bash
s2 keygen
```

### 2. Start Server with Authentication

```bash
# Via environment variable
export S2_ROOT_KEY="5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
s2-lite

# Or via CLI argument
s2-lite --root-key "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
```

The server logs the derived public key on startup:

```
INFO auth enabled public_key=2NEpo7TZRRrLZSi2U...
```

### 3. Generate a Client Key

Each client needs its own P-256 keypair:

```bash
# Generate client private key
openssl ecparam -name prime256v1 -genkey -noout -out client.pem

# Extract public key (compressed, base58)
openssl ec -in client.pem -pubout -conv_form compressed -outform DER 2>/dev/null | \
  tail -c 33 | base58

# Example output: 2NEpo7TZRRrLZSi2U8FxKaAqV3FJ8MFmCxLBqQMZxBGZ
```

### 4. Issue an Access Token

Use the `/access-tokens` endpoint to issue tokens. This endpoint requires authentication when auth is enabled.

```bash
curl -X POST https://s2.example.com/v1/access-tokens \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <existing-token>" \
  -H "Signature-Input: sig1=(\"@method\" \"@path\" \"@authority\" \"authorization\" \"content-digest\");created=$(date +%s);alg=\"ecdsa-p256-sha256\"" \
  -H "Signature: sig1=:<base64-ecdsa-signature>:" \
  -H "Content-Digest: sha-256=:<base64-sha256-of-body>:" \
  -d '{
    "public_key": "2NEpo7TZRRrLZSi2U8FxKaAqV3FJ8MFmCxLBqQMZxBGZ",
    "expires_at": "2025-12-31T23:59:59Z",
    "scope": {
      "basins": {"prefix": "my-app/"},
      "streams": {"prefix": "my-app/"},
      "access_tokens": "none",
      "op_groups": {
        "stream": {"read": true, "write": true}
      }
    }
  }'
```

Response:

```json
{
  "access_token": "<base64-encoded-biscuit-token>"
}
```

## Server Configuration

### CLI Arguments

| Argument | Environment Variable | Default | Description |
|----------|---------------------|---------|-------------|
| `--root-key` | `S2_ROOT_KEY` | (none) | Base58-encoded P-256 private key for signing tokens. If not set, authentication is disabled. |
| `--signature-window` | `S2_SIGNATURE_WINDOW` | `300` | Maximum age of request signatures in seconds. Requests with older signatures are rejected. |
| `--metrics-token` | `S2_METRICS_TOKEN` | (none) | Bearer token for metrics endpoints. If not set, metrics are publicly accessible. |

### Examples

```bash
# Full authentication with 10-minute signature window
s2-lite --root-key "$S2_ROOT_KEY" --signature-window 600

# Authentication disabled, but metrics protected
s2-lite --metrics-token "secret-metrics-token"

# Docker with authentication
docker run -p 8080:80 \
  -e S2_ROOT_KEY="$S2_ROOT_KEY" \
  ghcr.io/s2-streamstore/s2-lite
```

## Token Structure

Biscuit tokens contain Datalog facts that define the token's capabilities:

```datalog
// === AUTHORITY BLOCK (signed by root key) ===

// Client identity - public key that must sign HTTP requests
public_key("2NEpo7TZRRrLZSi2U8FxKaAqV3FJ8MFmCxLBqQMZxBGZ");

// Expiration (Unix timestamp)
expires(1735689599);
check if time($t), $t < 1735689599;

// Resource scopes - which basins/streams/tokens can be accessed
basin_scope("prefix", "my-app/");     // Can access basins starting with "my-app/"
stream_scope("prefix", "my-app/");    // Can access streams starting with "my-app/"
access_token_scope("none", "");        // Cannot manage access tokens

// Operation groups (coarse-grained permissions)
op_group("stream", "read");
op_group("stream", "write");

// Individual operations (fine-grained, optional)
op("append");
op("read");
```

### Scope Types

| Scope Type | Syntax | Description |
|------------|--------|-------------|
| `none` | `{"none": null}` or `"none"` | No access to this resource type |
| `exact` | `{"exact": "my-basin"}` | Access only the exact named resource |
| `prefix` | `{"prefix": "my-app/"}` | Access resources starting with this prefix |

### Operation Groups

Operations are grouped by resource level:

| Group | Read Operations | Write Operations |
|-------|-----------------|------------------|
| `account` | `list_basins`, `account_metrics` | `create_basin`, `delete_basin` |
| `basin` | `get_basin_config`, `list_streams`, `list_access_tokens`, `basin_metrics` | `reconfigure_basin`, `create_stream`, `delete_stream`, `issue_access_token`, `revoke_access_token` |
| `stream` | `get_stream_config`, `check_tail`, `read`, `stream_metrics` | `reconfigure_stream`, `append`, `trim`, `fence` |

## HTTP Request Signing (RFC 9421)

Every authenticated request must include RFC 9421 HTTP message signatures.

### Required Headers

| Header | Description |
|--------|-------------|
| `Authorization` | `Bearer <base64-biscuit-token>` |
| `Signature-Input` | Signature metadata in structured field format |
| `Signature` | The actual signature |
| `Content-Digest` | SHA-256 hash of request body (required for POST/PUT/PATCH with body) |

### Required Signed Components

The signature must cover at minimum:
- `@method` - HTTP method
- `@path` - Request path
- `@authority` - Host header value
- `authorization` - The Authorization header (binds signature to token)

For requests with a body, additionally:
- `content-digest` - The Content-Digest header

### Example Signed Request

```http
POST /v1/basins/my-basin/streams/my-stream/records HTTP/1.1
Host: s2.example.com
Authorization: Bearer eyJhbGciOiJFUzI1NiIs...
Content-Type: application/octet-stream
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Signature-Input: sig1=("@method" "@path" "@authority" "authorization" "content-digest");created=1704067200;alg="ecdsa-p256-sha256"
Signature: sig1=:MEUCIQDXmR2vq0...=:

<request body>
```

### Signature Algorithm

Only `ecdsa-p256-sha256` is supported. The signature is computed as:

1. Build the signature base string per RFC 9421 Section 2.5
2. Sign with ECDSA P-256 using SHA-256
3. Encode the signature as base64 in the `:...:` format

## Token Revocation

Tokens can be revoked by their revocation ID (a cryptographic identifier embedded in the token).

### Revoke a Token

```bash
# Get revocation ID from token (Biscuit provides this)
# The ID is hex-encoded

curl -X DELETE "https://s2.example.com/v1/access-tokens/<hex-revocation-id>" \
  -H "Authorization: Bearer <token>" \
  -H "Signature-Input: sig1=..." \
  -H "Signature: sig1=..."
```

### Revocation Semantics

Biscuit tokens have one revocation ID per block:
- Revoking the **authority block ID** revokes the original token AND all attenuated versions
- Revoking an **attenuation block ID** revokes only that specific attenuated token

Revoked IDs are stored in SlateDB under the `revocations/` prefix and checked on every request.

## Offline Token Delegation

Token holders can delegate access to other parties without server involvement using Biscuit's attenuation feature.

### How Delegation Works

1. **New client generates keypair** - The delegatee creates their own P-256 keypair
2. **Token holder attenuates** - Adds the delegatee's public key and restrictions
3. **Delegatee uses token** - Signs requests with their own private key

### Example Delegation

```rust
// Alice has a token, wants to delegate to Bob
let alice_token: Biscuit = /* ... */;

// Bob generates a keypair and shares public key with Alice
let bob_pubkey = "3ABcd8UVWxyz...";

// Alice creates attenuated token for Bob
let mut block = alice_token.create_block();

// Add Bob's public key (allows Bob to sign requests)
block.add_fact(format!("public_key(\"{}\")", bob_pubkey))?;

// Restrict to only Bob (prevents Alice from using this attenuated token)
block.add_check(format!("check if signer($s), $s == \"{}\"", bob_pubkey))?;

// Optionally add more restrictions
block.add_check("check if basin($b), $b.starts_with(\"alice/shared/\")")?;

let bob_token = alice_token.attenuate(block)?;
```

The server adds a `signer("<actual-signer-pubkey>")` fact during authorization, which the `check if signer(...)` caveat validates.

## Metrics Authentication

Metrics endpoints (`/v1/metrics/*`) support a separate, simpler authentication mechanism:

### Priority Order

1. **Biscuit auth enabled** - Uses Biscuit token with appropriate `*_metrics` operation permission
2. **Metrics token configured** - Uses simple Bearer token (`Authorization: Bearer <metrics-token>`)
3. **Neither** - Metrics are publicly accessible

### Configuration

```bash
# Protect metrics with a simple token (no Biscuit required)
s2-lite --metrics-token "my-metrics-secret"

# Or with full Biscuit auth
s2-lite --root-key "$S2_ROOT_KEY"

# Both (Biscuit takes precedence when used)
s2-lite --root-key "$S2_ROOT_KEY" --metrics-token "fallback-token"
```

### Accessing Metrics

```bash
# With metrics token
curl -H "Authorization: Bearer my-metrics-secret" \
  https://s2.example.com/v1/metrics/account

# With Biscuit token (needs account_metrics operation)
curl -H "Authorization: Bearer <biscuit-token>" \
  -H "Signature-Input: ..." \
  -H "Signature: ..." \
  https://s2.example.com/v1/metrics/account
```

## Security Considerations

### Token Issuance

**WARNING:** The `/v1/access-tokens` endpoint does NOT validate that requested scopes are a subset of the issuer's scope. A user with `issue_access_token` permission can issue tokens with ANY scope, including scopes they don't have access to.

This is effectively root-level access. Only grant `issue_access_token` permission to fully trusted principals.

For proper privilege-separated delegation, use Biscuit's offline attenuation feature to create narrower-scoped tokens from an existing token.

### Signature Window

The `--signature-window` parameter (default: 300 seconds) limits how old request signatures can be. This prevents replay attacks where an attacker captures and later replays a signed request.

Set this value based on your tolerance for clock drift between clients and server.

### Key Management

- **Root key** - Treat as highly sensitive. Anyone with this key can issue tokens with any scope.
- **Client keys** - Each client should have its own keypair. Never share private keys.
- **Key formats**:
  - Private keys: 32-byte scalar, base58 encoded (~44 characters)
  - Public keys: 33-byte compressed point, base58 encoded (~45 characters)

### Token Expiration

- All tokens must have an expiration date
- Maximum expiration is 1 year from issue time
- Expiration cannot be extended via attenuation (only shortened)

### Token Size Limit

Tokens larger than 64 KB are rejected to prevent DoS via massive tokens with thousands of facts.

## API Reference

### Issue Access Token

```
POST /v1/access-tokens
```

Request body:
```json
{
  "public_key": "base58-encoded-p256-public-key",
  "expires_at": "2025-12-31T23:59:59Z",
  "scope": {
    "basins": {"prefix": "my-app/"},
    "streams": {"prefix": "my-app/"},
    "access_tokens": "none",
    "op_groups": {
      "account": {"read": false, "write": false},
      "basin": {"read": true, "write": false},
      "stream": {"read": true, "write": true}
    },
    "ops": ["append", "read"]
  }
}
```

Response (201 Created):
```json
{
  "access_token": "base64-encoded-biscuit-token"
}
```

### Revoke Access Token

```
DELETE /v1/access-tokens/{revocation_id}
```

Where `{revocation_id}` is the hex-encoded Biscuit revocation ID.

Response: 204 No Content

### List Access Tokens

```
GET /v1/access-tokens
```

**Note:** This endpoint returns 501 Not Implemented because Biscuit tokens are stateless. The server does not track issued tokens. Clients must track tokens they've issued. Only revocations are stored.

## Error Responses

| Status | Error Code | Description |
|--------|------------|-------------|
| 403 | `permission_denied` | Missing auth header, invalid token, invalid signature, or insufficient permissions |
| 403 | `permission_denied` | Token has been revoked |

Error response body:
```json
{
  "code": "permission_denied",
  "message": "Authorization denied: stream out of scope"
}
```

## Disabling Authentication

To run without authentication (e.g., for development or testing):

```bash
# Simply don't provide a root key
s2-lite

# Or with Docker
docker run -p 8080:80 ghcr.io/s2-streamstore/s2-lite
```

When auth is disabled:
- All endpoints are accessible without authentication
- Token management endpoints return 501 Not Implemented
- The server logs: `auth disabled (no root key provided)`
