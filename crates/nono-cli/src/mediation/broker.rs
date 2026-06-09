//! Token broker for the phantom token pattern.
//!
//! Short-lived credentials (ddtool service tokens, STS, kubelogin OIDC,
//! and OAuth tokens captured by the proxy's TLS-intercept layer) are
//! stored here under a `nono_<hex>` nonce. The nonce is returned to the
//! sandbox; the real credential never crosses the sandbox boundary.
//!
//! The in-memory map is session-scoped. For OAuth capture, an optional
//! [`BrokerStore`] persists the captured `(access_token, refresh_token)`
//! pair across nono sessions so the nonces sitting in claude's keychain
//! entry from a previous session continue to resolve. See
//! [`broker_store`](super::broker_store) for the macOS Keychain-backed
//! implementation and its threat model.

use crate::mediation::broker_store::{BrokerStore, PersistedRecord};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::warn;
use zeroize::Zeroizing;

/// In-memory map from broker-issued nonces to the real credential values
/// they substitute for, optionally backed by a durable [`BrokerStore`]
/// for OAuth cross-session resume.
///
/// All stored values are wrapped in `Zeroizing` so the heap buffer is
/// zeroed when the broker is dropped at session end.
///
/// When constructed via [`TokenBroker::with_store`], the broker hydrates
/// itself from the store on construction (re-registering the nonces and
/// real tokens of any previously persisted OAuth pair) and persists new
/// captures via [`TokenBroker::capture_oauth_pair`]. The simpler
/// [`TokenBroker::new`] constructor is store-free and behaves identically
/// to the pre-persistence broker for command-mediation phantom tokens.
pub struct TokenBroker {
    tokens: Mutex<HashMap<String, Zeroizing<String>>>,
    store: Option<Arc<dyn BrokerStore>>,
}

impl TokenBroker {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            store: None,
        }
    }

    /// Construct a broker backed by `store`. On success, any OAuth pair
    /// already persisted in `store` is loaded into the in-memory map so
    /// nonces sitting in the user's keychain from a previous session
    /// resolve immediately.
    ///
    /// Returns an error only if the store's `load` itself fails. A store
    /// containing no record (the first-ever-launch case) is not an
    /// error — the broker is simply empty until the first capture.
    pub fn with_store(store: Arc<dyn BrokerStore>) -> nono::Result<Self> {
        let broker = Self {
            tokens: Mutex::new(HashMap::new()),
            store: Some(store.clone()),
        };
        if let Some(record) = store.load()? {
            let mut tokens = broker.tokens.lock().expect("TokenBroker mutex poisoned");
            tokens.insert(record.access_nonce, record.access_token);
            tokens.insert(record.refresh_nonce, record.refresh_token);
        }
        Ok(broker)
    }

    /// Capture an OAuth `(access_token, refresh_token)` pair: mint nonces
    /// for both, register them in memory, and persist the pair to the
    /// configured store (if any) so the mapping survives this session.
    ///
    /// Returns `(access_nonce, refresh_nonce)` so the caller can splice
    /// the nonces into the response body bound for the sandboxed client.
    ///
    /// Persistence is best-effort: a store error is logged at `warn!`
    /// level and swallowed. The in-memory side always succeeds, so
    /// capture-and-rewrite continues to work in the current session
    /// even when durable storage is unavailable. Without a store this
    /// is identical to the trait default — two independent `issue`
    /// calls — so behaviour for callers that constructed via `new()`
    /// is unchanged.
    pub fn capture_oauth_pair(
        &self,
        access: Zeroizing<String>,
        refresh: Zeroizing<String>,
    ) -> (String, String) {
        let access_nonce = self.issue(access.clone());
        let refresh_nonce = self.issue(refresh.clone());
        if let Some(store) = self.store.as_ref() {
            let record = PersistedRecord {
                access_nonce: access_nonce.clone(),
                refresh_nonce: refresh_nonce.clone(),
                access_token: access,
                refresh_token: refresh,
            };
            if let Err(e) = store.save(&record) {
                warn!("OAuth broker persistence failed (continuing in-memory only): {e}");
            }
        }
        (access_nonce, refresh_nonce)
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
/// The `capture_oauth_pair` override routes through
/// [`TokenBroker::capture_oauth_pair`] so persistence (when a store is
/// configured) happens on the proxy's capture path.
impl nono_proxy::TokenResolver for TokenBroker {
    fn issue(&self, secret: Zeroizing<String>) -> String {
        TokenBroker::issue(self, secret)
    }

    fn resolve(&self, nonce: &str) -> Option<Zeroizing<String>> {
        TokenBroker::resolve(self, nonce)
    }

    fn capture_oauth_pair(
        &self,
        access: Zeroizing<String>,
        refresh: Zeroizing<String>,
    ) -> (String, String) {
        TokenBroker::capture_oauth_pair(self, access, refresh)
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

    // ── Persistence tests (MemoryBrokerStore-backed) ─────────────────────────

    use crate::mediation::broker_store::test_support::MemoryBrokerStore;
    use std::sync::Arc;

    #[test]
    fn capture_oauth_pair_without_store_just_issues_two_nonces() {
        // Store-free broker: capture_oauth_pair must still produce two
        // distinct, resolvable nonces. No persistence side-effect to assert.
        let broker = TokenBroker::new();
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );
        assert!(access_nonce.starts_with("nono_"));
        assert!(refresh_nonce.starts_with("nono_"));
        assert_ne!(access_nonce, refresh_nonce);
        assert_eq!(
            broker.resolve(&access_nonce).unwrap().as_str(),
            "real_access"
        );
        assert_eq!(
            broker.resolve(&refresh_nonce).unwrap().as_str(),
            "real_refresh"
        );
    }

    #[test]
    fn capture_oauth_pair_with_store_persists_record() {
        // With a store, capture_oauth_pair writes through. The persisted
        // record must round-trip the in-memory nonces and the original
        // real tokens so a subsequent session can rehydrate.
        let store = Arc::new(MemoryBrokerStore::new());
        let broker = TokenBroker::with_store(store.clone()).expect("empty store loads OK");

        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );

        let persisted = store.current().expect("save wrote a record");
        assert_eq!(persisted.access_nonce, access_nonce);
        assert_eq!(persisted.refresh_nonce, refresh_nonce);
        assert_eq!(persisted.access_token.as_str(), "real_access");
        assert_eq!(persisted.refresh_token.as_str(), "real_refresh");
    }

    #[test]
    fn with_store_hydrates_existing_record_into_memory() {
        // Cross-session resume: a record left in the store by a previous
        // session must rehydrate so the nonces sitting in claude's
        // keychain resolve from the first lookup, before any new capture.
        let preloaded = PersistedRecord {
            access_nonce: "nono_persisted_access".to_string(),
            refresh_nonce: "nono_persisted_refresh".to_string(),
            access_token: Zeroizing::new("real_access".to_string()),
            refresh_token: Zeroizing::new("real_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let broker = TokenBroker::with_store(store).expect("preloaded store loads OK");

        assert_eq!(
            broker.resolve("nono_persisted_access").unwrap().as_str(),
            "real_access",
            "preloaded access nonce must resolve immediately"
        );
        assert_eq!(
            broker.resolve("nono_persisted_refresh").unwrap().as_str(),
            "real_refresh",
            "preloaded refresh nonce must resolve immediately"
        );
    }

    /// Store implementation whose `load` always fails — used to verify
    /// that load errors propagate (in contrast to save errors, which are
    /// best-effort and swallowed).
    struct FailingLoadStore;
    impl crate::mediation::broker_store::BrokerStore for FailingLoadStore {
        fn load(&self) -> nono::Result<Option<PersistedRecord>> {
            Err(nono::NonoError::KeystoreAccess(
                "simulated load failure".to_string(),
            ))
        }
        fn save(&self, _record: &PersistedRecord) -> nono::Result<()> {
            Ok(())
        }
        fn clear(&self) -> nono::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn with_store_propagates_load_errors() {
        // Construction must fail loudly when the store load fails.
        // Silently degrading to an empty broker would mask a stale or
        // corrupted persisted record on a real keychain.
        let store: Arc<dyn crate::mediation::broker_store::BrokerStore> =
            Arc::new(FailingLoadStore);
        let err = match TokenBroker::with_store(store) {
            Ok(_) => panic!("load failure must propagate"),
            Err(e) => e,
        };
        assert!(
            format!("{err}").contains("simulated load failure"),
            "error must surface store's message: {err}"
        );
    }

    /// Store implementation whose `save` always fails — used to verify
    /// that save errors are best-effort and the current session still
    /// works.
    struct FailingSaveStore;
    impl crate::mediation::broker_store::BrokerStore for FailingSaveStore {
        fn load(&self) -> nono::Result<Option<PersistedRecord>> {
            Ok(None)
        }
        fn save(&self, _record: &PersistedRecord) -> nono::Result<()> {
            Err(nono::NonoError::KeystoreAccess(
                "simulated save failure".to_string(),
            ))
        }
        fn clear(&self) -> nono::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn capture_oauth_pair_swallows_save_errors() {
        // Save errors are best-effort: the in-memory side must still
        // resolve so the current session's API calls work even when
        // durable storage is unavailable.
        let store: Arc<dyn crate::mediation::broker_store::BrokerStore> =
            Arc::new(FailingSaveStore);
        let broker = TokenBroker::with_store(store).expect("empty store loads OK");
        let (access_nonce, refresh_nonce) = broker.capture_oauth_pair(
            Zeroizing::new("real_access".to_string()),
            Zeroizing::new("real_refresh".to_string()),
        );
        assert_eq!(
            broker.resolve(&access_nonce).unwrap().as_str(),
            "real_access"
        );
        assert_eq!(
            broker.resolve(&refresh_nonce).unwrap().as_str(),
            "real_refresh"
        );
    }
}
