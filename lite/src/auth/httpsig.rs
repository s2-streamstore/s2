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
    let covered: Vec<String> = params
        .covered_components
        .iter()
        .map(|c: &HttpMessageComponentId| c.to_string())
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
