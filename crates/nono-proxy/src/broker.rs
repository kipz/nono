//! Cross-crate credential brokering trait for the TLS-intercept layer.
//!
//! The `TokenResolver` trait abstracts the in-process token vault that
//! holds real credentials (e.g. captured OAuth `access_token` /
//! `refresh_token`) behind opaque `nono_<hex>` nonces. The proxy's
//! TLS-intercept code (Layer 1.2 of the OAuth-capture design) calls
//! [`TokenResolver::issue`] on captured tokens and
//! [`TokenResolver::resolve`] to translate phantom nonces back to real
//! values at the egress boundary.
//!
//! The CLI implements this trait on its existing `TokenBroker` (in
//! `crates/nono-cli/src/mediation/broker.rs`) so the same vault backs
//! command mediation *and* credential mediation. The proxy receives the
//! handle via [`crate::server::ProxyRuntime::token_resolver`] at startup
//! — it never constructs a broker itself.
//!
//! ## Object safety
//!
//! All methods take `&self` and use sized return types, so the trait is
//! object-safe and may be used as `Arc<dyn TokenResolver>`.

use zeroize::Zeroizing;

/// In-process credential vault accessed by the proxy.
///
/// Implementations must be `Send + Sync` because the proxy holds the
/// resolver as `Arc<dyn TokenResolver>` shared across async tasks.
pub trait TokenResolver: Send + Sync {
    /// Store `secret` and return an opaque `nono_<hex>` nonce that
    /// resolves back to it via [`Self::resolve`]. Each call must yield
    /// a fresh nonce, even for repeated calls with the same secret.
    fn issue(&self, secret: Zeroizing<String>) -> String;

    /// Look up the real value for `nonce`.
    ///
    /// Returns `None` for unknown nonces *silently* — implementations
    /// must not distinguish "invalid format" from "not in vault" so a
    /// caller cannot probe the keyspace by inspecting error variants.
    fn resolve(&self, nonce: &str) -> Option<Zeroizing<String>>;

    /// Mint nonces for a captured OAuth `(access_token, refresh_token)`
    /// pair.
    ///
    /// Distinct from two separate [`Self::issue`] calls because
    /// implementations may persist the pair to durable storage so the
    /// mapping survives across sessions. The default implementation is
    /// infallible and persistence-free — it just calls `issue` twice —
    /// so non-OAuth callers and test fakes need no extra work.
    ///
    /// Persistence failures must NOT propagate: an implementation that
    /// cannot write to durable storage should still return valid
    /// in-memory nonces and log a warning. Capture-and-rewrite must keep
    /// working even when persistence is unavailable.
    fn capture_oauth_pair(
        &self,
        access: Zeroizing<String>,
        refresh: Zeroizing<String>,
    ) -> (String, String) {
        (self.issue(access), self.issue(refresh))
    }
}
