//! Token broker for the phantom token pattern.
//!
//! Short-lived credentials (ddtool service tokens, STS, kubelogin OIDC) are
//! captured by the mediation server and stored here under a `nono_<hex>` nonce.
//! The nonce is returned to the sandbox; the real credential never crosses the
//! sandbox boundary.
//!
//! On passthrough, the server promotes nonce-bearing env vars by replacing the
//! nonce with the real value before exec-ing the real binary.

use std::collections::HashMap;
use std::sync::Mutex;
use tracing::warn;
use zeroize::Zeroizing;

/// Identifies a single redemption site within a profile.
/// `<command>.default` refers to the command's default action.
/// `<command>.<intercept-id>` refers to a named intercept rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GrantDescriptor {
    pub command: String,
    pub intercept_id: String,
}

impl GrantDescriptor {
    /// Parse a `"<command>.<intercept-id>"` string. Returns `None` if
    /// the string lacks the `.` separator or has an empty piece.
    pub fn parse(s: &str) -> Option<GrantDescriptor> {
        let (cmd, id) = s.split_once('.')?;
        if cmd.is_empty() || id.is_empty() {
            return None;
        }
        Some(GrantDescriptor {
            command: cmd.to_string(),
            intercept_id: id.to_string(),
        })
    }
}

/// Grant policy for a captured nonce.
#[derive(Debug, Clone)]
pub enum GrantSet {
    /// Never redeemable. Useful for defensive captures whose nonces have
    /// no legitimate consumer.
    None,
    /// Allow-list of consumers.
    Allow(Vec<GrantDescriptor>),
}

impl GrantSet {
    /// Returns true if `consumer` is admitted by this grant set.
    pub fn admits(&self, consumer: &ConsumerContext) -> bool {
        match self {
            GrantSet::None => false,
            GrantSet::Allow(list) => list
                .iter()
                .any(|d| d.command == consumer.command && d.intercept_id == consumer.intercept_id),
        }
    }
}

/// Identifies the redemption site attempting to resolve a nonce.
/// `intercept_id` is the matched intercept's `id` (or `"default"` for the
/// no-match fall-through / default dispatch path).
#[derive(Debug, Clone)]
pub struct ConsumerContext<'a> {
    pub command: &'a str,
    pub intercept_id: &'a str,
}

struct BrokerEntry {
    value: Zeroizing<String>,
    grants: GrantSet,
}

/// In-memory store mapping nonces to real credential values.
///
/// Session-scoped: created in `setup()`, dropped when the session ends.
/// All stored values are wrapped in `Zeroizing` so memory is wiped on drop.
pub struct TokenBroker {
    tokens: Mutex<HashMap<String, BrokerEntry>>,
}

impl TokenBroker {
    pub fn new() -> Self {
        Self {
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Mint a nonce wrapping `real_value`. The nonce is redeemable only by
    /// consumers admitted by `grants`.
    ///
    /// The nonce format is `nono_` followed by 64 lowercase hex characters
    /// (32 random bytes). This is clearly distinct from real token formats
    /// (`ghp_`, `AKIA`, `sk-`, `xoxb-`) and longer than any real token.
    pub fn issue(&self, real_value: Zeroizing<String>, grants: GrantSet) -> String {
        use rand::RngExt;
        let mut rng = rand::rng();
        let bytes: [u8; 32] = rng.random();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let nonce = format!("nono_{}", hex);

        let mut tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        tokens.insert(
            nonce.clone(),
            BrokerEntry {
                value: real_value,
                grants,
            },
        );
        nonce
    }

    /// Resolve a nonce if the consumer is in its grant set. Returns `None`
    /// for unknown nonces or rejected consumers.
    ///
    /// Callers must not distinguish "invalid nonce" from "nonce not found"
    /// or "consumer not admitted" — all return None — to avoid probing
    /// attacks.
    ///
    /// When a *known* nonce is refused because the consumer is outside its
    /// grant set, emits a `warn!` audit line naming the consumer descriptor.
    /// Unknown nonces stay silent so the resolve path doesn't double as a
    /// probing oracle for "is this nonce-shaped string in the broker?".
    pub fn resolve(&self, nonce: &str, consumer: &ConsumerContext) -> Option<Zeroizing<String>> {
        let tokens = self.tokens.lock().expect("TokenBroker mutex poisoned");
        let entry = tokens.get(nonce)?;
        if entry.grants.admits(consumer) {
            Some(entry.value.clone())
        } else {
            warn!(
                "mediation: refused nonce redemption at {}.{}",
                consumer.command, consumer.intercept_id
            );
            None
        }
    }
}

impl Default for TokenBroker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a `GrantSet::Allow` matching the test consumer below.
    fn allow_anything_default() -> GrantSet {
        GrantSet::Allow(vec![GrantDescriptor {
            command: "anything".to_string(),
            intercept_id: "default".to_string(),
        }])
    }

    #[test]
    fn issue_returns_nono_prefix() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(
            Zeroizing::new("ghp_secret".to_string()),
            allow_anything_default(),
        );
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
        let nonce = broker.issue(
            Zeroizing::new("real_token_value".to_string()),
            allow_anything_default(),
        );
        let consumer = ConsumerContext {
            command: "anything",
            intercept_id: "default",
        };
        let resolved = broker
            .resolve(&nonce, &consumer)
            .expect("nonce should resolve");
        assert_eq!(resolved.as_str(), "real_token_value");
    }

    #[test]
    fn resolve_unknown_nonce_returns_none() {
        let broker = TokenBroker::new();
        let consumer = ConsumerContext {
            command: "anything",
            intercept_id: "default",
        };
        assert!(broker.resolve("nono_unknown", &consumer).is_none());
        assert!(broker.resolve("ghp_notanonce", &consumer).is_none());
        assert!(broker.resolve("", &consumer).is_none());
    }

    #[test]
    fn each_issue_produces_unique_nonce() {
        let broker = TokenBroker::new();
        let n1 = broker.issue(Zeroizing::new("val1".to_string()), allow_anything_default());
        let n2 = broker.issue(Zeroizing::new("val2".to_string()), allow_anything_default());
        assert_ne!(n1, n2);
    }

    #[test]
    fn grant_set_none_rejects_every_consumer() {
        let broker = TokenBroker::new();
        let n = broker.issue(Zeroizing::new("v".to_string()), GrantSet::None);
        let c = ConsumerContext {
            command: "curl",
            intercept_id: "default",
        };
        assert!(broker.resolve(&n, &c).is_none());
    }

    #[test]
    fn grant_set_allow_admits_matching_descriptor() {
        let broker = TokenBroker::new();
        let n = broker.issue(
            Zeroizing::new("v".to_string()),
            GrantSet::Allow(vec![GrantDescriptor {
                command: "curl".to_string(),
                intercept_id: "gitlab".to_string(),
            }]),
        );
        let c_match = ConsumerContext {
            command: "curl",
            intercept_id: "gitlab",
        };
        let c_miss_cmd = ConsumerContext {
            command: "wget",
            intercept_id: "gitlab",
        };
        let c_miss_id = ConsumerContext {
            command: "curl",
            intercept_id: "default",
        };
        assert!(broker.resolve(&n, &c_match).is_some());
        assert!(broker.resolve(&n, &c_miss_cmd).is_none());
        assert!(broker.resolve(&n, &c_miss_id).is_none());
    }

    #[test]
    fn grant_descriptor_parse_round_trip() {
        let d = GrantDescriptor::parse("curl.gitlab").unwrap();
        assert_eq!(d.command, "curl");
        assert_eq!(d.intercept_id, "gitlab");
        assert!(GrantDescriptor::parse("nodot").is_none());
        assert!(GrantDescriptor::parse(".empty").is_none());
        assert!(GrantDescriptor::parse("empty.").is_none());
    }
}
