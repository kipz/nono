//! Token broker for the phantom token pattern.
//!
//! Short-lived credentials (ddtool service tokens, STS, kubelogin OIDC,
//! and OAuth tokens captured by the proxy's TLS-intercept layer) are
//! stored here under a `nono_<hex>` nonce. The nonce is returned to the
//! sandbox; the real credential never crosses the sandbox boundary.
//!
//! The broker is **session-scoped and in-memory only**. Anthropic OAuth
//! cross-session resume works without persistence: claude's own
//! keychain entry holds the real tokens, the mediation shim's
//! `capture { format: "json" }` action mints fresh nonces from the
//! real values on every read, and the proxy translates those nonces
//! back on egress — all within the same session.

use std::collections::HashMap;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// In-memory map from broker-issued nonces to the real credential values
/// they substitute for.
///
/// All stored values are wrapped in `Zeroizing` so the heap buffer is
/// zeroed when the broker is dropped at session end.
pub struct TokenBroker {
    tokens: Mutex<HashMap<String, Zeroizing<String>>>,
}

impl TokenBroker {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Store a real credential value and return a `nono_<hex>` nonce.
    ///
    /// The nonce format is `nono_` followed by 64 lowercase hex characters
    /// (32 random bytes). This is clearly distinct from real token formats
    /// (`ghp_`, `AKIA`, `sk-`, `xoxb-`) and longer than any real token.
    pub fn issue(&self, real_value: Zeroizing<String>) -> String {
        use rand::RngExt;
        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let nonce = format!("nono_{}", hex);

        let mut tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.insert(nonce.clone(), real_value);
        nonce
    }

    /// Look up the real credential for a nonce.
    ///
    /// Returns `None` for unknown nonces (silently — callers must not distinguish
    /// "invalid nonce" from "nonce not found" to avoid probing attacks).
    pub fn resolve(&self, nonce: &str) -> Option<Zeroizing<String>> {
        let tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.get(nonce).cloned()
    }
}

/// Implements the `nono-proxy` `TokenResolver` seam so the proxy can
/// hold an `Arc<dyn TokenResolver>` backed by the same broker the
/// mediation server uses for command-mediation phantom tokens.
///
/// The trait's `capture_oauth_pair` default — two independent `issue`
/// calls — is what the proxy ends up calling. No override here.
impl nono_proxy::TokenResolver for TokenBroker {
    fn issue(&self, secret: Zeroizing<String>) -> String {
        TokenBroker::issue(self, secret)
    }

    fn resolve(&self, nonce: &str) -> Option<Zeroizing<String>> {
        TokenBroker::resolve(self, nonce)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn issue_returns_nono_prefix() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("ghp_secret".to_string()));
        assert!(nonce.starts_with("nono_"), "nonce was: {}", nonce);
        assert_eq!(
            nonce.len(),
            5 + 64,
            "expected 'nono_' + 64 hex chars, got: {}",
            nonce
        );
    }

    #[test]
    fn resolve_finds_issued_nonce() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("real_token_value".to_string()));
        let resolved = broker.resolve(&nonce).expect("nonce should resolve");
        assert_eq!(resolved.as_str(), "real_token_value");
    }

    #[test]
    fn resolve_unknown_nonce_returns_none() {
        let broker = TokenBroker::new();
        assert!(broker.resolve("nono_unknown").is_none());
        assert!(broker.resolve("ghp_notanonce").is_none());
        assert!(broker.resolve("").is_none());
    }

    #[test]
    fn each_issue_produces_unique_nonce() {
        let broker = TokenBroker::new();
        let n1 = broker.issue(Zeroizing::new("val1".to_string()));
        let n2 = broker.issue(Zeroizing::new("val2".to_string()));
        assert_ne!(n1, n2);
    }

    #[test]
    fn token_resolver_trait_object_round_trips() {
        // The proxy holds the broker as `Arc<dyn nono_proxy::TokenResolver>`.
        // Issue + resolve through the trait object must return the same
        // value the concrete broker does, proving the seam is wired and
        // the trait is object-safe in our usage.
        use nono_proxy::TokenResolver;
        use std::sync::Arc;

        let resolver: Arc<dyn TokenResolver> = Arc::new(TokenBroker::new());
        let nonce = resolver.issue(Zeroizing::new("real_value".to_string()));
        assert!(nonce.starts_with("nono_"));

        let resolved = resolver
            .resolve(&nonce)
            .expect("nonce issued via trait should resolve via trait");
        assert_eq!(resolved.as_str(), "real_value");

        assert!(
            resolver.resolve("nono_unknown_nonce").is_none(),
            "unknown nonces must resolve to None silently"
        );
    }

    #[test]
    fn capture_oauth_pair_via_trait_default_issues_two_nonces() {
        // The trait default for capture_oauth_pair issues two independent
        // nonces. This documents that our broker relies on that default
        // and confirms it produces resolvable nonces.
        use nono_proxy::TokenResolver;
        use std::sync::Arc;

        let resolver: Arc<dyn TokenResolver> = Arc::new(TokenBroker::new());
        let (access_nonce, refresh_nonce) = resolver.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );
        assert!(access_nonce.starts_with("nono_"));
        assert!(refresh_nonce.starts_with("nono_"));
        assert_ne!(access_nonce, refresh_nonce);
        assert_eq!(
            resolver.resolve(&access_nonce).unwrap().as_str(),
            "real_access"
        );
        assert_eq!(
            resolver.resolve(&refresh_nonce).unwrap().as_str(),
            "real_refresh"
        );
    }
}
