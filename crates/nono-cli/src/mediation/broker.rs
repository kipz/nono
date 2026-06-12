//! Token broker for the phantom token pattern.
//!
//! Short-lived credentials (service tokens, STS, kubelogin OIDC,
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
    /// Nonces of the currently-live OAuth pair, if any. Tracked
    /// separately from `tokens` so [`capture_oauth_pair`] can prune
    /// the previous pair on a refresh-rotation (limitation #4 in the
    /// 2026-06-09 addendum). `None` if no OAuth pair has been
    /// captured or hydrated this run.
    current_pair: Mutex<Option<(String, String)>>,
}

/// Hook used by [`TokenBroker::with_store`] to inspect claude's own
/// `Claude Code-credentials` keychain entry at hydrate time. Returns the
/// access-token field from the entry (typically a `nono_<hex>` nonce or
/// a `sk-ant-…` real token), or `None` if the entry is missing /
/// unreadable / lacks the field.
///
/// Production callers pass the real reader from
/// [`super::broker_store::current_claude_access_token`]. Tests pass a
/// closure that returns a known value so the orphan-GC paths are
/// exercised without touching the user's keychain.
pub type ClaudeAccessTokenReader = Box<dyn Fn() -> Option<String>>;

impl TokenBroker {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
            store: None,
            current_pair: Mutex::new(None),
        }
    }

    /// Construct a broker backed by `store`, hydrating from any
    /// previously persisted OAuth pair.
    ///
    /// See [`with_store_and_reader`](Self::with_store_and_reader) for
    /// the orphan-GC behaviour. This shorthand passes a no-op reader
    /// (always returns `None`), which disables GC — appropriate for
    /// command-mediation callers that don't have a `Claude
    /// Code-credentials` entry to cross-reference.
    pub fn with_store(store: Arc<dyn BrokerStore>) -> nono::Result<Self> {
        Self::with_store_and_reader(store, Box::new(|| None))
    }

    /// Construct a broker backed by `store`, cross-referencing the
    /// persisted record against `claude_access_token_reader` to detect
    /// orphaned records (limitation #1 in the 2026-06-09 addendum).
    ///
    /// On startup:
    /// 1. Load the persisted record from `store`. If empty, return an
    ///    empty broker.
    /// 2. Call `claude_access_token_reader` to read claude's own
    ///    `Claude Code-credentials` keychain entry.
    /// 3. If claude's `accessToken` field matches the stored
    ///    `access_nonce`, the persisted record is live — hydrate the
    ///    in-memory map and set `current_pair`.
    /// 4. Otherwise (entry missing, holds a real `sk-ant-…` token, or
    ///    holds a different nonce), the persisted record is stale —
    ///    clear it from the store and return an empty broker. The next
    ///    `/login` capture will create a fresh record.
    ///
    /// Rationale: when the user runs `/logout` inside claude, the
    /// `Claude Code-credentials` entry is wiped but our broker's
    /// persisted record still holds the real refresh token. Without
    /// this GC the broker would keep hydrating dead tokens for as long
    /// as Anthropic considers them valid (~1 year for OAuth refresh
    /// tokens), violating the user's "logout means tokens are gone"
    /// mental model. Cross-referencing claude's keychain entry catches
    /// this state and prunes the broker.
    ///
    /// Returns an error only if the store's `load` itself fails — read
    /// failures from `claude_access_token_reader` are treated as
    /// "entry missing" (the GC-stale path), which is the conservative
    /// choice: better to drop a live record and force a re-`/login`
    /// than to leak a real token because we couldn't tell.
    pub fn with_store_and_reader(
        store: Arc<dyn BrokerStore>,
        claude_access_token_reader: ClaudeAccessTokenReader,
    ) -> nono::Result<Self> {
        let broker = Self {
            tokens: Mutex::new(HashMap::new()),
            store: Some(store.clone()),
            current_pair: Mutex::new(None),
        };

        let Some(record) = store.load()? else {
            return Ok(broker);
        };

        let claude_access = claude_access_token_reader();
        let live = matches!(claude_access.as_deref(), Some(t) if t == record.access_nonce);

        if !live {
            tracing::info!(
                "OAuth broker persisted record does not match Claude Code-credentials \
                 entry (claude_access_present={}); clearing stale record",
                claude_access.is_some()
            );
            if let Err(e) = store.clear() {
                warn!("OAuth broker stale-record clear failed (continuing without hydration): {e}");
            }
            return Ok(broker);
        }

        let mut tokens = broker.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.insert(record.access_nonce.clone(), record.access_token);
        tokens.insert(record.refresh_nonce.clone(), record.refresh_token);
        drop(tokens);
        *broker
            .current_pair
            .lock()
            .expect("TokenBroker current_pair mutex poisoned") =
            Some((record.access_nonce, record.refresh_nonce));
        Ok(broker)
    }

    /// Capture an OAuth `(access_token, refresh_token)` pair: mint nonces
    /// for both, register them in memory, and persist the pair to the
    /// configured store (if any) so the mapping survives this session.
    ///
    /// If a previous OAuth pair is currently live (either hydrated from
    /// the store on startup or minted by a prior `capture_oauth_pair`
    /// call this session), its nonces are removed from the in-memory
    /// map before the new pair is issued. This handles the refresh-
    /// rotation case (limitation #4): claude exchanges a refresh token,
    /// the proxy intercepts the new pair, and the broker prunes the
    /// old nonces so the in-memory map doesn't grow with refresh count.
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
        // Prune the previous pair, if any, before minting the new one.
        // The new nonces are inserted below; doing the prune first keeps
        // the map's size bounded over a long session with many refresh
        // rotations.
        if let Some((old_access_nonce, old_refresh_nonce)) = self
            .current_pair
            .lock()
            .expect("TokenBroker current_pair mutex poisoned")
            .take()
        {
            let mut tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
            tokens.remove(&old_access_nonce);
            tokens.remove(&old_refresh_nonce);
        }

        let access_nonce = self.issue(access.clone());
        let refresh_nonce = self.issue(refresh.clone());

        *self
            .current_pair
            .lock()
            .expect("TokenBroker current_pair mutex poisoned") =
            Some((access_nonce.clone(), refresh_nonce.clone()));

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
    fn with_store_hydrates_existing_record_when_claude_keychain_matches() {
        // Cross-session resume happy path: the persisted record's
        // access_nonce matches the value currently in claude's
        // `Claude Code-credentials` entry, so the broker hydrates.
        // This is the path that makes session-2 API calls work
        // without re-`/login`.
        let preloaded = PersistedRecord {
            access_nonce: "nono_persisted_access".to_string(),
            refresh_nonce: "nono_persisted_refresh".to_string(),
            access_token: Zeroizing::new("real_access".to_string()),
            refresh_token: Zeroizing::new("real_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let matching_reader: ClaudeAccessTokenReader =
            Box::new(|| Some("nono_persisted_access".to_string()));
        let broker = TokenBroker::with_store_and_reader(store.clone(), matching_reader)
            .expect("matching-reader store loads OK");

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
        assert!(
            store.current().is_some(),
            "live record must remain in store after hydrate"
        );
    }

    #[test]
    fn with_store_clears_orphan_when_claude_keychain_missing() {
        // User did `/logout` inside claude (or never had the entry):
        // claude's `Claude Code-credentials` is empty, so the broker's
        // persisted record holds a real refresh token that no longer
        // corresponds to any active session. GC must clear it.
        let preloaded = PersistedRecord {
            access_nonce: "nono_orphan_access".to_string(),
            refresh_nonce: "nono_orphan_refresh".to_string(),
            access_token: Zeroizing::new("real_orphan_access".to_string()),
            refresh_token: Zeroizing::new("real_orphan_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let empty_reader: ClaudeAccessTokenReader = Box::new(|| None);
        let broker = TokenBroker::with_store_and_reader(store.clone(), empty_reader)
            .expect("empty-reader path is not an error");

        assert!(
            store.current().is_none(),
            "orphan record must be cleared from the store"
        );
        assert!(
            broker.resolve("nono_orphan_access").is_none(),
            "orphan nonce must not be hydrated into memory"
        );
        assert!(
            broker.resolve("nono_orphan_refresh").is_none(),
            "orphan refresh nonce must not be hydrated into memory"
        );
    }

    #[test]
    fn with_store_clears_orphan_when_claude_keychain_holds_real_token() {
        // User did `/logout` outside nono and then `/login` outside
        // nono, so claude's entry now holds `sk-ant-…` rather than a
        // broker nonce. Our persisted record is stale — different
        // user, different tokens. Clear it.
        let preloaded = PersistedRecord {
            access_nonce: "nono_orphan_access".to_string(),
            refresh_nonce: "nono_orphan_refresh".to_string(),
            access_token: Zeroizing::new("real_orphan_access".to_string()),
            refresh_token: Zeroizing::new("real_orphan_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let real_token_reader: ClaudeAccessTokenReader =
            Box::new(|| Some("sk-ant-oat01-fresh-real-token".to_string()));
        let broker = TokenBroker::with_store_and_reader(store.clone(), real_token_reader)
            .expect("real-token-reader path is not an error");

        assert!(
            store.current().is_none(),
            "stale broker record must be cleared when claude holds a real token"
        );
        assert!(broker.resolve("nono_orphan_access").is_none());
    }

    #[test]
    fn with_store_clears_orphan_when_claude_keychain_holds_different_nonce() {
        // Another nono session captured between our save and our
        // restart. Claude's entry now references a different nonce.
        // Treat our record as stale and let the latest capture win.
        let preloaded = PersistedRecord {
            access_nonce: "nono_old_access".to_string(),
            refresh_nonce: "nono_old_refresh".to_string(),
            access_token: Zeroizing::new("real_old_access".to_string()),
            refresh_token: Zeroizing::new("real_old_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let other_nonce_reader: ClaudeAccessTokenReader =
            Box::new(|| Some("nono_different_session_access".to_string()));
        let broker = TokenBroker::with_store_and_reader(store.clone(), other_nonce_reader)
            .expect("different-nonce-reader path is not an error");

        assert!(
            store.current().is_none(),
            "broker record must be cleared when claude references a different nonce"
        );
        assert!(broker.resolve("nono_old_access").is_none());
    }

    #[test]
    fn capture_oauth_pair_prunes_previous_pair_from_memory() {
        // Refresh-rotation: the proxy intercepts a refresh response,
        // mints a new pair, calls capture_oauth_pair. The OLD pair's
        // nonces must be removed from the in-memory map so it does
        // not grow with refresh count over a long session.
        let store = Arc::new(MemoryBrokerStore::new());
        let broker = TokenBroker::with_store(store).expect("empty store loads OK");

        let (old_access, old_refresh) = broker.capture_oauth_pair(
            Zeroizing::new("real_access_v1".to_string()),
            Zeroizing::new("real_refresh_v1".to_string()),
        );
        assert!(broker.resolve(&old_access).is_some(), "v1 must be live");

        let (new_access, new_refresh) = broker.capture_oauth_pair(
            Zeroizing::new("real_access_v2".to_string()),
            Zeroizing::new("real_refresh_v2".to_string()),
        );

        assert!(
            broker.resolve(&old_access).is_none(),
            "old access nonce must be pruned"
        );
        assert!(
            broker.resolve(&old_refresh).is_none(),
            "old refresh nonce must be pruned"
        );
        assert_eq!(
            broker.resolve(&new_access).unwrap().as_str(),
            "real_access_v2",
            "new access nonce must resolve"
        );
        assert_eq!(
            broker.resolve(&new_refresh).unwrap().as_str(),
            "real_refresh_v2",
            "new refresh nonce must resolve"
        );
    }

    #[test]
    fn hydrate_then_capture_prunes_hydrated_pair() {
        // Session boundary into refresh: the broker hydrates a pair on
        // startup, then claude refreshes — the proxy captures the new
        // pair. The hydrated pair must be pruned just like a same-
        // session capture-then-capture (else the first refresh of
        // every new session would silently grow the map).
        let preloaded = PersistedRecord {
            access_nonce: "nono_hydrated_access".to_string(),
            refresh_nonce: "nono_hydrated_refresh".to_string(),
            access_token: Zeroizing::new("real_old".to_string()),
            refresh_token: Zeroizing::new("real_old_refresh".to_string()),
        };
        let store = Arc::new(MemoryBrokerStore::preload(preloaded));
        let matching: ClaudeAccessTokenReader =
            Box::new(|| Some("nono_hydrated_access".to_string()));
        let broker = TokenBroker::with_store_and_reader(store, matching).expect("hydrate OK");

        assert!(broker.resolve("nono_hydrated_access").is_some());

        let _ = broker.capture_oauth_pair(
            Zeroizing::new("real_new_access".to_string()),
            Zeroizing::new("real_new_refresh".to_string()),
        );

        assert!(
            broker.resolve("nono_hydrated_access").is_none(),
            "hydrated nonce must be pruned after the post-hydrate capture"
        );
        assert!(broker.resolve("nono_hydrated_refresh").is_none());
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
