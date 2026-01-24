use base64ct::Encoding;
use http::{HeaderMap, Method};
use httpsig::prelude::{
    message_component::{
        DerivedComponentName, HttpMessageComponent, HttpMessageComponentId,
        HttpMessageComponentName,
    },
    AlgorithmName, HttpSignatureBase, HttpSignatureHeaders, HttpSignatureParams, PublicKey,
};
use sha2::{Digest, Sha256};

use super::keys::ClientPublicKey;

/// Components that must be signed
const REQUIRED_COMPONENTS: &[&str] = &["@method", "@path", "@authority", "authorization"];

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

    // Parse signature headers
    let sig_headers = HttpSignatureHeaders::try_parse(signature, sig_input)
        .map_err(|e: httpsig::prelude::HttpSigError| SignatureError::ParseError(e.to_string()))?;

    // Get the first (and likely only) signature
    let (_, sig_header) = sig_headers
        .iter()
        .next()
        .ok_or(SignatureError::NoSignature)?;

    let params = sig_header.signature_params();

    // Verify required components are covered
    verify_covered_components(params)?;

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
        .map_err(|e: httpsig::prelude::HttpSigError| SignatureError::KeyConversion(e.to_string()))?;

    // Verify the signature
    signature_base
        .verify_signature_headers(&httpsig_pubkey, sig_header)
        .map_err(|e: httpsig::prelude::HttpSigError| SignatureError::SignatureInvalid(e.to_string()))?;

    Ok(())
}

fn verify_covered_components(params: &HttpSignatureParams) -> Result<(), SignatureError> {
    let covered: Vec<String> = params
        .covered_components
        .iter()
        .map(|c: &HttpMessageComponentId| c.to_string())
        .collect();

    for required in REQUIRED_COMPONENTS {
        if !covered.iter().any(|c| c == *required) {
            return Err(SignatureError::MissingComponent(required));
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
        let component = match &component_id.name {
            HttpMessageComponentName::Derived(derived) => match derived {
                DerivedComponentName::Method => HttpMessageComponent {
                    id: component_id.clone(),
                    value: method.as_str().into(),
                },
                DerivedComponentName::Path => HttpMessageComponent {
                    id: component_id.clone(),
                    value: path.into(),
                },
                DerivedComponentName::Authority => HttpMessageComponent {
                    id: component_id.clone(),
                    value: authority.into(),
                },
                DerivedComponentName::TargetUri => {
                    // Need to leak since From is only impl'd for &str
                    let uri: &'static str =
                        Box::leak(format!("https://{}{}", authority, path).into_boxed_str());
                    HttpMessageComponent {
                        id: component_id.clone(),
                        value: uri.into(),
                    }
                }
                _ => {
                    return Err(SignatureError::UnsupportedComponent(
                        component_id.to_string(),
                    ))
                }
            },
            HttpMessageComponentName::HttpField(name) => {
                let value = headers
                    .get(name.as_str())
                    .ok_or_else(|| {
                        SignatureError::MissingHeader(Box::leak(name.clone().into_boxed_str()))
                    })?
                    .to_str()
                    .map_err(|_| {
                        SignatureError::InvalidHeader(Box::leak(name.clone().into_boxed_str()))
                    })?;
                HttpMessageComponent {
                    id: component_id.clone(),
                    value: value.into(),
                }
            }
        };
        components.push(component);
    }

    Ok(components)
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("missing header: {0}")]
    MissingHeader(&'static str),
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("missing required component: {0}")]
    MissingComponent(&'static str),
    #[error("unsupported component: {0}")]
    UnsupportedComponent(String),
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
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("key conversion error: {0}")]
    KeyConversion(String),
    #[error("no signature found")]
    NoSignature,
    #[error("signature verification failed: {0}")]
    SignatureInvalid(String),
}
