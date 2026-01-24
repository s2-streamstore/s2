//! Shared authentication state.

use std::sync::Arc;

use super::keys::{RootKey, RootPublicKey};

/// Shared authentication state.
///
/// This is cheap to clone (uses Arc internally) and can be passed
/// to handlers and middleware.
#[derive(Clone)]
pub struct AuthState {
    inner: Option<Arc<AuthStateInner>>,
    /// Separate metrics token - can be set even if main auth is disabled
    metrics_token: Option<Arc<String>>,
}

struct AuthStateInner {
    /// Private key for signing tokens. None = verify-only mode.
    root_key: Option<RootKey>,
    /// Public key for verifying tokens.
    root_public_key: RootPublicKey,
    signature_window_secs: u64,
}

impl AuthState {
    /// Create auth state with both private and public keys (can issue tokens).
    pub fn new(
        root_key: RootKey,
        signature_window_secs: u64,
        metrics_token: Option<String>,
    ) -> Self {
        let root_public_key = root_key.public_key();
        Self {
            inner: Some(Arc::new(AuthStateInner {
                root_key: Some(root_key),
                root_public_key,
                signature_window_secs,
            })),
            metrics_token: metrics_token.map(Arc::new),
        }
    }

    /// Create auth state with only public key (verify-only, cannot issue tokens).
    pub fn verify_only(
        root_public_key: RootPublicKey,
        signature_window_secs: u64,
        metrics_token: Option<String>,
    ) -> Self {
        Self {
            inner: Some(Arc::new(AuthStateInner {
                root_key: None,
                root_public_key,
                signature_window_secs,
            })),
            metrics_token: metrics_token.map(Arc::new),
        }
    }

    /// Create disabled auth state (no authentication required).
    pub fn disabled() -> Self {
        Self {
            inner: None,
            metrics_token: None,
        }
    }

    /// Create auth state with only metrics token (no Biscuit auth).
    pub fn metrics_only(metrics_token: String) -> Self {
        Self {
            inner: None,
            metrics_token: Some(Arc::new(metrics_token)),
        }
    }

    /// Check if auth is enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.is_some()
    }

    /// Check if token issuance is enabled (has private key).
    pub fn can_issue_tokens(&self) -> bool {
        self.inner
            .as_ref()
            .is_some_and(|i| i.root_key.is_some())
    }

    /// Get the root key (for signing tokens). None if verify-only mode.
    pub fn root_key(&self) -> Option<&RootKey> {
        self.inner.as_ref().and_then(|i| i.root_key.as_ref())
    }

    /// Get the root public key (for verifying tokens).
    pub fn root_public_key(&self) -> Option<&RootPublicKey> {
        self.inner.as_ref().map(|i| &i.root_public_key)
    }

    /// Get the signature window in seconds.
    pub fn signature_window_secs(&self) -> u64 {
        self.inner
            .as_ref()
            .map(|i| i.signature_window_secs)
            .unwrap_or(300)
    }

    /// Get the metrics token if configured.
    pub fn metrics_token(&self) -> Option<&str> {
        self.metrics_token.as_ref().map(|s| s.as_str())
    }
}

impl std::fmt::Debug for AuthState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthState")
            .field("enabled", &self.is_enabled())
            .field("public_key", &self.root_public_key().map(|k| k.to_base58()))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use p256::SecretKey;

    use super::*;

    fn generate_test_root_key() -> RootKey {
        use p256::elliptic_curve::rand_core::OsRng;
        let secret = SecretKey::random(&mut OsRng);
        let bytes = secret.to_bytes();
        let base58 = bs58::encode(&bytes).into_string();
        RootKey::from_base58(&base58).unwrap()
    }

    #[test]
    fn test_auth_state_full() {
        let root_key = generate_test_root_key();
        let state = AuthState::new(root_key, 600, None);

        assert!(state.is_enabled());
        assert!(state.can_issue_tokens());
        assert!(state.root_key().is_some());
        assert!(state.root_public_key().is_some());
        assert_eq!(state.signature_window_secs(), 600);
        assert!(state.metrics_token().is_none());
    }

    #[test]
    fn test_auth_state_verify_only() {
        let root_key = generate_test_root_key();
        let public_key = root_key.public_key();
        let state = AuthState::verify_only(public_key.clone(), 600, None);

        assert!(state.is_enabled());
        assert!(!state.can_issue_tokens());
        assert!(state.root_key().is_none());
        assert!(state.root_public_key().is_some());
        assert_eq!(
            state.root_public_key().unwrap().to_base58(),
            public_key.to_base58()
        );
        assert_eq!(state.signature_window_secs(), 600);
    }

    #[test]
    fn test_auth_state_disabled() {
        let state = AuthState::disabled();

        assert!(!state.is_enabled());
        assert!(!state.can_issue_tokens());
        assert!(state.root_key().is_none());
        assert!(state.root_public_key().is_none());
        assert_eq!(state.signature_window_secs(), 300); // default
    }

    #[test]
    fn test_auth_state_clone() {
        let root_key = generate_test_root_key();
        let state1 = AuthState::new(root_key, 300, Some("test-token".into()));
        let state2 = state1.clone();

        assert!(state1.is_enabled());
        assert!(state2.is_enabled());
        // Both should have the same public key
        assert_eq!(
            state1.root_public_key().unwrap().to_base58(),
            state2.root_public_key().unwrap().to_base58()
        );
        // Both should have the same metrics token
        assert_eq!(state1.metrics_token(), Some("test-token"));
        assert_eq!(state2.metrics_token(), Some("test-token"));
    }
}
