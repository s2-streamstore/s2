use base64ct::Encoding;
use http::{HeaderMap, Method};
use httpsig::prelude::{
    AlgorithmName, HttpSignatureBase, HttpSignatureHeaders, HttpSignatureParams, PublicKey,
    message_component::{HttpMessageComponent, HttpMessageComponentId, HttpMessageComponentName},
};
use sha2::{Digest, Sha256};

use super::keys::ClientPublicKey;

/// Components that must always be signed
const REQUIRED_COMPONENTS: &[&str] = &["@method", "@path", "@authority", "authorization"];

/// Additional components required when request has a body
const REQUIRED_BODY_COMPONENTS: &[&str] = &["content-digest"];

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
        .ok_or_else(|| SignatureError::MissingHeader("Signature-Input".into()))?
        .to_str()
        .map_err(|_| SignatureError::InvalidHeader("Signature-Input".into()))?;

    let signature = headers
        .get("signature")
        .ok_or_else(|| SignatureError::MissingHeader("Signature".into()))?
        .to_str()
        .map_err(|_| SignatureError::InvalidHeader("Signature".into()))?;

    // Parse signature headers
    let sig_headers = HttpSignatureHeaders::try_parse(signature, sig_input)
        .map_err(|e: httpsig::prelude::HttpSigError| SignatureError::ParseError(e.to_string()))?;

    // Get the first (and likely only) signature
    let (_, sig_header) = sig_headers
        .iter()
        .next()
        .ok_or(SignatureError::NoSignature)?;

    let params = sig_header.signature_params();

    // Verify algorithm is ecdsa-p256-sha256
    verify_algorithm(params)?;

    // Verify required components are covered (including content-digest if body present)
    verify_covered_components(params, body.is_some())?;

    // Verify timestamp is within window
    verify_timestamp(params, signature_window_secs)?;

    // If body present, verify Content-Digest
    if let Some(body) = body {
        verify_content_digest(headers, body)?;
    }

    // Build signature base from message components
    let component_lines = build_component_lines(method, path, authority, headers, params)?;
    let signature_base = HttpSignatureBase::try_new(&component_lines, params)
        .map_err(|e: httpsig::prelude::HttpSigError| SignatureError::ParseError(e.to_string()))?;

    // Convert our public key to httpsig's format (uncompressed SEC1)
    let point = public_key.verifying_key().to_encoded_point(false);
    let httpsig_pubkey = PublicKey::from_bytes(AlgorithmName::EcdsaP256Sha256, point.as_bytes())
        .map_err(|e: httpsig::prelude::HttpSigError| {
            SignatureError::KeyConversion(e.to_string())
        })?;

    // Verify the signature
    signature_base
        .verify_signature_headers(&httpsig_pubkey, sig_header)
        .map_err(|e: httpsig::prelude::HttpSigError| {
            SignatureError::SignatureInvalid(e.to_string())
        })?;

    Ok(())
}

fn verify_covered_components(
    params: &HttpSignatureParams,
    has_body: bool,
) -> Result<(), SignatureError> {
    // HttpMessageComponentId.to_string() returns quoted format like "\"@method\""
    // so we need to strip quotes for comparison
    let covered: Vec<String> = params
        .covered_components
        .iter()
        .map(|c: &HttpMessageComponentId| c.to_string().trim_matches('"').to_string())
        .collect();

    for required in REQUIRED_COMPONENTS {
        if !covered.iter().any(|c| c == *required) {
            return Err(SignatureError::MissingComponent((*required).into()));
        }
    }

    // If request has a body, content-digest must also be signed
    if has_body {
        for required in REQUIRED_BODY_COMPONENTS {
            if !covered.iter().any(|c| c == *required) {
                return Err(SignatureError::MissingComponent((*required).into()));
            }
        }
    }

    Ok(())
}

fn verify_algorithm(params: &HttpSignatureParams) -> Result<(), SignatureError> {
    // We only support ecdsa-p256-sha256
    const EXPECTED_ALG: &str = "ecdsa-p256-sha256";
    match &params.alg {
        Some(alg) => {
            if alg != EXPECTED_ALG {
                return Err(SignatureError::UnsupportedAlgorithm(alg.clone()));
            }
        }
        None => {
            // Algorithm is optional in RFC 9421, but we require it for security
            return Err(SignatureError::MissingAlgorithm);
        }
    }
    Ok(())
}

fn verify_timestamp(params: &HttpSignatureParams, window_secs: u64) -> Result<(), SignatureError> {
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
        .ok_or_else(|| SignatureError::MissingHeader("Content-Digest".into()))?
        .to_str()
        .map_err(|_| SignatureError::InvalidHeader("Content-Digest".into()))?;

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
    let parts: Vec<&str> = header.splitn(2, '=').collect();
    if parts.len() != 2 || parts[0] != "sha-256" {
        return Err(SignatureError::InvalidDigestFormat);
    }

    let b64 = parts[1].trim_matches(':');
    base64ct::Base64::decode_vec(b64).map_err(|_| SignatureError::InvalidDigestFormat)
}

fn build_component_lines(
    method: &Method,
    path: &str,
    authority: &str,
    headers: &HeaderMap,
    params: &HttpSignatureParams,
) -> Result<Vec<HttpMessageComponent>, SignatureError> {
    let mut components = Vec::new();

    for component_id in &params.covered_components {
        // Build component line string in RFC 9421 format: "component-id": value
        let line = match &component_id.name {
            HttpMessageComponentName::Derived(derived) => {
                let derived_str: &str = derived.as_ref();
                let value = match derived_str {
                    "@method" => method.as_str().to_uppercase(),
                    "@path" => path.to_string(),
                    "@authority" => authority.to_string(),
                    "@target-uri" => format!("https://{}{}", authority, path),
                    "@scheme" => "https".to_string(),
                    "@request-target" => format!("{} {}", method.as_str(), path),
                    other => {
                        return Err(SignatureError::UnsupportedComponent(other.to_string()));
                    }
                };
                format!("\"{}\": {}", derived_str, value)
            }
            HttpMessageComponentName::HttpField(name) => {
                let value = headers
                    .get(name.as_str())
                    .ok_or_else(|| SignatureError::MissingHeader(name.clone()))?
                    .to_str()
                    .map_err(|_| SignatureError::InvalidHeader(name.clone()))?;
                format!("\"{}\": {}", name, value)
            }
        };

        let component = HttpMessageComponent::try_from(line.as_str()).map_err(
            |e: httpsig::prelude::HttpSigError| SignatureError::ParseError(e.to_string()),
        )?;
        components.push(component);
    }

    Ok(components)
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("missing header: {0}")]
    MissingHeader(String),
    #[error("invalid header: {0}")]
    InvalidHeader(String),
    #[error("missing required component: {0}")]
    MissingComponent(String),
    #[error("unsupported component: {0}")]
    UnsupportedComponent(String),
    #[error("missing timestamp")]
    MissingTimestamp,
    #[error("missing algorithm")]
    MissingAlgorithm,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("timestamp too far in future")]
    TimestampFuture,
    #[error("timestamp expired")]
    TimestampExpired,
    #[error("content digest mismatch")]
    DigestMismatch,
    #[error("invalid digest format")]
    InvalidDigestFormat,
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("key conversion error: {0}")]
    KeyConversion(String),
    #[error("no signature found")]
    NoSignature,
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that we can parse and verify a signature produced by the SDK's httpsig usage.
    /// This uses the exact Signature-Input format the SDK produces.
    #[test]
    fn test_verify_sdk_signature_format() {
        // This is the exact Signature-Input format from the SDK
        let sig_input = r#"sig1=("@method" "@path" "@authority" "authorization");created=1769292040;alg="ecdsa-p256-sha256";keyid="pTGh6RCaGt5PcA3evMKB6ZZmsYfALRSPhCH9tq3xzEsW""#;
        let signature = "sig1=:ICgHLV0iUB8SGE8vZ8dNu2ZV4qpBxN45HrM0RNiQNu8RUg4S318Kj21CmDMRrC8sm+5m34mNs6IoAOAxhYPBcQ==:";

        // Parse the signature headers
        let sig_headers = HttpSignatureHeaders::try_parse(signature, sig_input)
            .expect("should parse signature headers");

        let (_, sig_header) = sig_headers.iter().next().expect("should have a signature");
        let params = sig_header.signature_params();

        // HttpMessageComponentId.to_string() returns quoted format, we strip for comparison
        let covered: Vec<String> = params
            .covered_components
            .iter()
            .map(|c| c.to_string().trim_matches('"').to_string())
            .collect();

        println!("Covered components (after trim): {:?}", covered);

        // This is what REQUIRED_COMPONENTS expects
        let required = ["@method", "@path", "@authority", "authorization"];
        println!("Required components: {:?}", required);

        // Check each required component
        for req in &required {
            let found = covered.iter().any(|c| c == *req);
            println!("Looking for '{}': found={}", req, found);
            assert!(found, "Should find component '{}' in {:?}", req, covered);
        }
    }

    /// Test verify_covered_components with the SDK's signature params
    #[test]
    fn test_verify_covered_components_with_sdk_format() {
        let sig_input = r#"sig1=("@method" "@path" "@authority" "authorization");created=1769292040;alg="ecdsa-p256-sha256";keyid="test""#;
        let signature = "sig1=:dGVzdA==:"; // dummy signature

        let sig_headers =
            HttpSignatureHeaders::try_parse(signature, sig_input).expect("should parse");
        let (_, sig_header) = sig_headers.iter().next().expect("should have sig");
        let params = sig_header.signature_params();

        // This should pass - no body means content-digest not required
        let result = verify_covered_components(params, false);
        println!("verify_covered_components result: {:?}", result);
        assert!(result.is_ok(), "Should pass: {:?}", result);
    }

    /// End-to-end test: sign a request the same way SDK does, verify with server code.
    /// This proves SDK and server are compatible.
    #[test]
    fn test_full_signature_roundtrip_sdk_to_server() {
        use std::time::{SystemTime, UNIX_EPOCH};

        use httpsig::prelude::{
            AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
            message_component::HttpMessageComponentId,
        };
        use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

        // 1. Generate a random key pair (same as SDK does)
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Create ClientPublicKey from verifying key
        let point = verifying_key.to_encoded_point(true); // compressed
        let pub_base58 = bs58::encode(point.as_bytes()).into_string();
        let client_pubkey =
            ClientPublicKey::from_base58(&pub_base58).expect("should create client public key");

        // 2. Request details
        let method = Method::GET;
        let path = "/v1/basins";
        let authority = "localhost";
        let authorization = "Bearer test-token-here";

        // 3. Build covered components (same as SDK)
        let component_ids: Vec<HttpMessageComponentId> =
            ["@method", "@path", "@authority", "authorization"]
                .iter()
                .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
                .collect();

        // 4. Build component lines for signature base (same format as SDK)
        let mut component_lines = Vec::new();
        for id in &component_ids {
            let line = match &id.name {
                HttpMessageComponentName::Derived(derived) => {
                    let derived_str: &str = derived.as_ref();
                    let value = match derived_str {
                        "@method" => method.as_str().to_uppercase(),
                        "@path" => path.to_string(),
                        "@authority" => authority.to_string(),
                        other => panic!("unexpected derived: {}", other),
                    };
                    format!("\"{}\": {}", derived_str, value)
                }
                HttpMessageComponentName::HttpField(name) => {
                    format!("\"{}\": {}", name, authorization)
                }
            };
            let component =
                HttpMessageComponent::try_from(line.as_str()).expect("should parse component");
            component_lines.push(component);
        }

        // 5. Create signature params with timestamp
        let mut sig_params =
            HttpSignatureParams::try_new(&component_ids).expect("should create params");
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        sig_params.set_created(created);

        // 6. Create httpsig SecretKey and set key info
        let key_bytes = signing_key.to_bytes();
        let httpsig_secret = SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes)
            .expect("should create httpsig key");
        sig_params.set_key_info(&httpsig_secret);
        sig_params.set_keyid(&pub_base58);

        // 7. Build signature base and sign
        let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params)
            .expect("should build signature base");
        let sig_headers = signature_base
            .build_signature_headers(&httpsig_secret, Some("sig1"))
            .expect("should build signature headers");

        // 8. Build HTTP headers like SDK does
        let mut headers = HeaderMap::new();
        headers.insert("authorization", authorization.parse().unwrap());
        headers.insert(
            "signature-input",
            sig_headers.signature_input_header_value().parse().unwrap(),
        );
        headers.insert(
            "signature",
            sig_headers.signature_header_value().parse().unwrap(),
        );

        println!(
            "Signature-Input: {}",
            sig_headers.signature_input_header_value()
        );
        println!("Signature: {}", sig_headers.signature_header_value());

        // 9. Verify with server code - this is the actual test
        let result = verify_signature(
            &method,
            path,
            authority,
            &headers,
            None, // no body
            &client_pubkey,
            300, // 5 minute window
        );

        assert!(
            result.is_ok(),
            "Signature verification failed: {:?}",
            result
        );
    }

    /// Test with actual root key - sign like SDK, verify like server
    #[test]
    fn test_with_actual_root_key_full_signature() {
        use std::time::{SystemTime, UNIX_EPOCH};

        use httpsig::prelude::{
            AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
            message_component::HttpMessageComponentId,
        };
        use p256::ecdsa::SigningKey;

        // Actual root key from config
        let root_key_base58 = "ByDGSRM82bqEVQoGYpZzvmmHujrB32UN1sr7WbKN6TPQ";
        let key_bytes = bs58::decode(root_key_base58).into_vec().unwrap();

        // Create signing key (like SDK does)
        let signing_key = SigningKey::from_slice(&key_bytes).unwrap();

        // Get public key (like CLI/SDK does)
        let public_key = signing_key.verifying_key();
        let public_key_base58 =
            bs58::encode(public_key.to_encoded_point(true).as_bytes()).into_string();
        println!("Public key: {}", public_key_base58);

        // Should be pTGh6RCaGt5PcA3evMKB6ZZmsYfALRSPhCH9tq3xzEsW
        assert_eq!(
            public_key_base58,
            "pTGh6RCaGt5PcA3evMKB6ZZmsYfALRSPhCH9tq3xzEsW"
        );

        // Create ClientPublicKey (like server does)
        let client_pubkey = ClientPublicKey::from_base58(&public_key_base58).unwrap();

        // Request details (like SDK sends)
        let method = Method::GET;
        let path = "/v1/basins";
        let authority = "localhost";
        let authorization = "Bearer test-token";

        // Build signature exactly like SDK does
        let component_ids: Vec<HttpMessageComponentId> =
            ["@method", "@path", "@authority", "authorization"]
                .iter()
                .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
                .collect();

        let mut component_lines = Vec::new();
        for id in &component_ids {
            let line = match &id.name {
                HttpMessageComponentName::Derived(derived) => {
                    let derived_str: &str = derived.as_ref();
                    let value = match derived_str {
                        "@method" => method.as_str().to_uppercase(),
                        "@path" => path.to_string(),
                        "@authority" => authority.to_string(),
                        other => panic!("unexpected: {}", other),
                    };
                    format!("\"{}\": {}", derived_str, value)
                }
                HttpMessageComponentName::HttpField(name) => {
                    format!("\"{}\": {}", name, authorization)
                }
            };
            let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
            component_lines.push(component);
        }

        let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        sig_params.set_created(created);

        // SDK creates httpsig SecretKey from signing key bytes
        let httpsig_secret =
            SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
        sig_params.set_key_info(&httpsig_secret);
        sig_params.set_keyid(&public_key_base58);

        let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
        let sig_headers = signature_base
            .build_signature_headers(&httpsig_secret, Some("sig1"))
            .unwrap();

        println!(
            "Signature-Input: {}",
            sig_headers.signature_input_header_value()
        );
        println!("Signature: {}", sig_headers.signature_header_value());

        // Build headers like SDK does
        let mut headers = HeaderMap::new();
        headers.insert("authorization", authorization.parse().unwrap());
        headers.insert(
            "signature-input",
            sig_headers.signature_input_header_value().parse().unwrap(),
        );
        headers.insert(
            "signature",
            sig_headers.signature_header_value().parse().unwrap(),
        );

        // Verify like server does
        let result = verify_signature(
            &method,
            path,
            authority,
            &headers,
            None,
            &client_pubkey,
            300,
        );

        println!("Verification result: {:?}", result);
        assert!(result.is_ok(), "Signature should verify: {:?}", result);
    }

    /// Test authority handling - SDK signs with just "localhost", verify server accepts it
    #[test]
    fn test_authority_without_port() {
        use std::time::{SystemTime, UNIX_EPOCH};

        use httpsig::prelude::{
            AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
            message_component::HttpMessageComponentId,
        };
        use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(true);
        let pub_base58 = bs58::encode(point.as_bytes()).into_string();
        let client_pubkey = ClientPublicKey::from_base58(&pub_base58).unwrap();

        let method = Method::GET;
        let path = "/v1/basins";
        // SDK signs with just "localhost" when port is 80 (default)
        let authority = "localhost";
        let authorization = "Bearer test-token";

        let component_ids: Vec<HttpMessageComponentId> =
            ["@method", "@path", "@authority", "authorization"]
                .iter()
                .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
                .collect();

        let mut component_lines = Vec::new();
        for id in &component_ids {
            let line = match &id.name {
                HttpMessageComponentName::Derived(derived) => {
                    let derived_str: &str = derived.as_ref();
                    let value = match derived_str {
                        "@method" => method.as_str().to_uppercase(),
                        "@path" => path.to_string(),
                        "@authority" => authority.to_string(),
                        other => panic!("unexpected: {}", other),
                    };
                    format!("\"{}\": {}", derived_str, value)
                }
                HttpMessageComponentName::HttpField(name) => {
                    format!("\"{}\": {}", name, authorization)
                }
            };
            let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
            component_lines.push(component);
        }

        let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        sig_params.set_created(created);

        let key_bytes = signing_key.to_bytes();
        let httpsig_secret =
            SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
        sig_params.set_key_info(&httpsig_secret);
        sig_params.set_keyid(&pub_base58);

        let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
        let sig_headers = signature_base
            .build_signature_headers(&httpsig_secret, Some("sig1"))
            .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert("authorization", authorization.parse().unwrap());
        headers.insert(
            "signature-input",
            sig_headers.signature_input_header_value().parse().unwrap(),
        );
        headers.insert(
            "signature",
            sig_headers.signature_header_value().parse().unwrap(),
        );

        // Server verifies with same authority "localhost"
        let result = verify_signature(
            &method,
            path,
            authority,
            &headers,
            None,
            &client_pubkey,
            300,
        );
        assert!(
            result.is_ok(),
            "Should verify with authority 'localhost': {:?}",
            result
        );
    }

    /// Test with body and content-digest
    #[test]
    fn test_full_signature_roundtrip_with_body() {
        use std::time::{SystemTime, UNIX_EPOCH};

        use httpsig::prelude::{
            AlgorithmName, HttpSignatureBase, HttpSignatureParams, SecretKey,
            message_component::HttpMessageComponentId,
        };
        use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
        use sha2::{Digest, Sha256};

        // 1. Generate key pair
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(true);
        let pub_base58 = bs58::encode(point.as_bytes()).into_string();
        let client_pubkey = ClientPublicKey::from_base58(&pub_base58).unwrap();

        // 2. Request with body
        let method = Method::POST;
        let path = "/v1/basins/test/streams/foo/records";
        let authority = "localhost";
        let authorization = "Bearer test-token";
        let body = b"test body content";

        // 3. Compute content-digest (same as SDK)
        let hash = Sha256::digest(body);
        let encoded = base64ct::Base64::encode_string(&hash);
        let content_digest = format!("sha-256=:{}:", encoded);

        // 4. Build covered components including content-digest
        let component_ids: Vec<HttpMessageComponentId> = [
            "@method",
            "@path",
            "@authority",
            "authorization",
            "content-digest",
        ]
        .iter()
        .map(|c| HttpMessageComponentId::try_from(*c).unwrap())
        .collect();

        // 5. Build component lines
        let mut component_lines = Vec::new();
        for id in &component_ids {
            let line = match &id.name {
                HttpMessageComponentName::Derived(derived) => {
                    let derived_str: &str = derived.as_ref();
                    let value = match derived_str {
                        "@method" => method.as_str().to_uppercase(),
                        "@path" => path.to_string(),
                        "@authority" => authority.to_string(),
                        other => panic!("unexpected derived: {}", other),
                    };
                    format!("\"{}\": {}", derived_str, value)
                }
                HttpMessageComponentName::HttpField(name) => {
                    let value = match name.as_str() {
                        "authorization" => authorization.to_string(),
                        "content-digest" => content_digest.clone(),
                        other => panic!("unexpected field: {}", other),
                    };
                    format!("\"{}\": {}", name, value)
                }
            };
            let component = HttpMessageComponent::try_from(line.as_str()).unwrap();
            component_lines.push(component);
        }

        // 6. Create signature params
        let mut sig_params = HttpSignatureParams::try_new(&component_ids).unwrap();
        let created = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        sig_params.set_created(created);

        let key_bytes = signing_key.to_bytes();
        let httpsig_secret =
            SecretKey::from_bytes(AlgorithmName::EcdsaP256Sha256, &key_bytes).unwrap();
        sig_params.set_key_info(&httpsig_secret);
        sig_params.set_keyid(&pub_base58);

        // 7. Sign
        let signature_base = HttpSignatureBase::try_new(&component_lines, &sig_params).unwrap();
        let sig_headers = signature_base
            .build_signature_headers(&httpsig_secret, Some("sig1"))
            .unwrap();

        // 8. Build headers
        let mut headers = HeaderMap::new();
        headers.insert("authorization", authorization.parse().unwrap());
        headers.insert("content-digest", content_digest.parse().unwrap());
        headers.insert(
            "signature-input",
            sig_headers.signature_input_header_value().parse().unwrap(),
        );
        headers.insert(
            "signature",
            sig_headers.signature_header_value().parse().unwrap(),
        );

        // 9. Verify
        let result = verify_signature(
            &method,
            path,
            authority,
            &headers,
            Some(body),
            &client_pubkey,
            300,
        );

        assert!(
            result.is_ok(),
            "Signature verification with body failed: {:?}",
            result
        );
    }
}
