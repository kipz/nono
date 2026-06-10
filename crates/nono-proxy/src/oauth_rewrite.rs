//! Shared OAuth-response JSON-body rewriter.
//!
//! Both the TLS-intercept dispatcher (`crate::intercept::rewrite_oauth_response`)
//! and the reverse-proxy capture path (`crate::reverse::capture_and_rewrite_response`)
//! parse a JSON OAuth-token response, mint nonces for `access_token` and
//! `refresh_token` via the [`crate::broker::TokenResolver`], and re-serialise.
//! They differ in framing (hyper bodies vs. raw HTTP/TCP), so this module
//! does only the bytes-in / bytes-out core; each caller owns its own
//! framing (Content-Length rebuild, header strip, etc.).
//!
//! ## Pass-through-on-error invariant
//!
//! Capture is best-effort: every failure mode (body is not JSON, body is
//! JSON but not an object, no relevant fields, re-serialisation failure)
//! returns one of the pass-through outcomes so the caller can forward the
//! original bytes unchanged. `/login` must keep working even when the
//! upstream returns something unexpected.

use crate::broker::TokenResolver;
use bytes::Bytes;
use zeroize::Zeroizing;

/// Outcome of attempting to rewrite an OAuth-token JSON body.
///
/// `NotJson` and `NoTokenFields` both signal "forward original bytes
/// unchanged" — they are kept distinct only so the caller can log at the
/// appropriate level (`warn!` for malformed upstream responses, `debug!`
/// for the routine "no token here" case).
pub(crate) enum OauthRewriteOutcome {
    /// Body did not parse as JSON. Forward original bytes; this is
    /// upstream-side weirdness worth logging at warn level.
    NotJson,
    /// Body parsed as JSON but contained no `access_token` /
    /// `refresh_token` strings to substitute, *or* re-serialisation
    /// failed. Forward original bytes; this is the routine
    /// matched-URL-but-not-an-OAuth-shape case.
    NoTokenFields,
    /// Body was rewritten. Forward `bytes` and rebuild framing. The
    /// `substituted` count is 1 or 2 depending on whether one or both
    /// of `access_token` / `refresh_token` were present.
    Rewritten { bytes: Bytes, substituted: u32 },
}

/// Parse `body` as JSON and substitute any `access_token` /
/// `refresh_token` fields with nonces minted by `resolver`.
///
/// When both fields are present, the broker is told they belong to the
/// same OAuth pair via [`TokenResolver::capture_oauth_pair`] so it can
/// persist them together for cross-session resume. When only one is
/// present, the single-token [`TokenResolver::issue`] path is used (no
/// persistence — pair semantics are lost without the matching half).
pub(crate) fn rewrite_oauth_json_body(
    body: &[u8],
    resolver: &(dyn TokenResolver + 'static),
) -> OauthRewriteOutcome {
    let mut value: serde_json::Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return OauthRewriteOutcome::NotJson,
    };

    let Some(obj) = value.as_object_mut() else {
        return OauthRewriteOutcome::NoTokenFields;
    };

    let access = obj
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .map(|s| Zeroizing::new(s.to_string()));
    let refresh = obj
        .get("refresh_token")
        .and_then(serde_json::Value::as_str)
        .map(|s| Zeroizing::new(s.to_string()));

    let substituted: u32 = match (access, refresh) {
        (Some(a), Some(r)) => {
            let (access_nonce, refresh_nonce) = resolver.capture_oauth_pair(a, r);
            obj.insert(
                "access_token".to_string(),
                serde_json::Value::String(access_nonce),
            );
            obj.insert(
                "refresh_token".to_string(),
                serde_json::Value::String(refresh_nonce),
            );
            2
        }
        (Some(a), None) => {
            let nonce = resolver.issue(a);
            obj.insert("access_token".to_string(), serde_json::Value::String(nonce));
            1
        }
        (None, Some(r)) => {
            let nonce = resolver.issue(r);
            obj.insert(
                "refresh_token".to_string(),
                serde_json::Value::String(nonce),
            );
            1
        }
        (None, None) => 0,
    };

    if substituted == 0 {
        return OauthRewriteOutcome::NoTokenFields;
    }

    match serde_json::to_vec(&value) {
        Ok(b) => OauthRewriteOutcome::Rewritten {
            bytes: Bytes::from(b),
            substituted,
        },
        Err(_) => OauthRewriteOutcome::NoTokenFields,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test fake: records issued/captured tokens and returns deterministic
    /// nonces so assertions on the rewritten JSON are stable.
    struct RecordingResolver {
        issued: Mutex<Vec<String>>,
        captured: Mutex<Vec<(String, String)>>,
    }

    impl RecordingResolver {
        fn new() -> Self {
            Self {
                issued: Mutex::new(Vec::new()),
                captured: Mutex::new(Vec::new()),
            }
        }
    }

    impl TokenResolver for RecordingResolver {
        fn issue(&self, secret: Zeroizing<String>) -> String {
            let s = secret.as_str().to_string();
            self.issued
                .lock()
                .expect("RecordingResolver issued mutex poisoned")
                .push(s.clone());
            format!("nono_issued_{s}")
        }

        fn resolve(&self, _nonce: &str) -> Option<Zeroizing<String>> {
            unreachable!("rewrite path does not call resolve")
        }

        fn capture_oauth_pair(
            &self,
            access: Zeroizing<String>,
            refresh: Zeroizing<String>,
        ) -> (String, String) {
            let a = access.as_str().to_string();
            let r = refresh.as_str().to_string();
            self.captured
                .lock()
                .expect("RecordingResolver captured mutex poisoned")
                .push((a.clone(), r.clone()));
            (
                format!("nono_pair_access_{a}"),
                format!("nono_pair_refresh_{r}"),
            )
        }
    }

    fn parse_obj(bytes: &[u8]) -> serde_json::Map<String, serde_json::Value> {
        let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        v.as_object().unwrap().clone()
    }

    #[test]
    fn rewrites_pair_via_capture_oauth_pair() {
        let resolver = RecordingResolver::new();
        let body = br#"{"access_token":"real_a","refresh_token":"real_r","expires_in":3600}"#;

        match rewrite_oauth_json_body(body, &resolver) {
            OauthRewriteOutcome::Rewritten { bytes, substituted } => {
                assert_eq!(substituted, 2);
                let obj = parse_obj(&bytes);
                assert_eq!(
                    obj.get("access_token").and_then(|v| v.as_str()),
                    Some("nono_pair_access_real_a")
                );
                assert_eq!(
                    obj.get("refresh_token").and_then(|v| v.as_str()),
                    Some("nono_pair_refresh_real_r")
                );
                // Untouched sibling fields are preserved.
                assert_eq!(obj.get("expires_in").and_then(|v| v.as_i64()), Some(3600));
            }
            _ => panic!("expected Rewritten outcome"),
        }

        // Pair path — capture_oauth_pair was used, not single issue().
        let captured = resolver.captured.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0], ("real_a".to_string(), "real_r".to_string()));
        assert!(resolver.issued.lock().unwrap().is_empty());
    }

    #[test]
    fn rewrites_access_only_via_single_issue() {
        let resolver = RecordingResolver::new();
        let body = br#"{"access_token":"only_a"}"#;

        match rewrite_oauth_json_body(body, &resolver) {
            OauthRewriteOutcome::Rewritten { bytes, substituted } => {
                assert_eq!(substituted, 1);
                let obj = parse_obj(&bytes);
                assert_eq!(
                    obj.get("access_token").and_then(|v| v.as_str()),
                    Some("nono_issued_only_a")
                );
                assert!(obj.get("refresh_token").is_none());
            }
            _ => panic!("expected Rewritten outcome"),
        }

        // Single-token path: issue() was used, capture_oauth_pair was not.
        assert_eq!(resolver.issued.lock().unwrap().as_slice(), &["only_a"]);
        assert!(resolver.captured.lock().unwrap().is_empty());
    }

    #[test]
    fn rewrites_refresh_only_via_single_issue() {
        let resolver = RecordingResolver::new();
        let body = br#"{"refresh_token":"only_r"}"#;

        match rewrite_oauth_json_body(body, &resolver) {
            OauthRewriteOutcome::Rewritten { bytes, substituted } => {
                assert_eq!(substituted, 1);
                let obj = parse_obj(&bytes);
                assert_eq!(
                    obj.get("refresh_token").and_then(|v| v.as_str()),
                    Some("nono_issued_only_r")
                );
                assert!(obj.get("access_token").is_none());
            }
            _ => panic!("expected Rewritten outcome"),
        }

        assert_eq!(resolver.issued.lock().unwrap().as_slice(), &["only_r"]);
        assert!(resolver.captured.lock().unwrap().is_empty());
    }

    #[test]
    fn no_token_fields_when_object_has_neither() {
        let resolver = RecordingResolver::new();
        let body = br#"{"foo":"bar","expires_in":3600}"#;

        assert!(matches!(
            rewrite_oauth_json_body(body, &resolver),
            OauthRewriteOutcome::NoTokenFields
        ));

        // Resolver was never called.
        assert!(resolver.issued.lock().unwrap().is_empty());
        assert!(resolver.captured.lock().unwrap().is_empty());
    }

    #[test]
    fn not_json_signalled_for_invalid_body() {
        let resolver = RecordingResolver::new();
        let body = b"not a json document";

        assert!(matches!(
            rewrite_oauth_json_body(body, &resolver),
            OauthRewriteOutcome::NotJson
        ));
    }

    #[test]
    fn no_token_fields_when_root_is_not_an_object() {
        // JSON arrays, strings, and numbers parse as Value but are not
        // OAuth-token responses; they fall through the as_object_mut
        // branch.
        let resolver = RecordingResolver::new();
        for body in [
            &b"[\"access_token\",\"refresh_token\"]"[..],
            &b"\"just_a_string\""[..],
            &b"42"[..],
        ] {
            assert!(matches!(
                rewrite_oauth_json_body(body, &resolver),
                OauthRewriteOutcome::NoTokenFields
            ));
        }
    }

    #[test]
    fn empty_object_is_no_token_fields() {
        let resolver = RecordingResolver::new();
        assert!(matches!(
            rewrite_oauth_json_body(b"{}", &resolver),
            OauthRewriteOutcome::NoTokenFields
        ));
    }

    #[test]
    fn non_string_token_fields_are_ignored() {
        // If `access_token` is present but not a string (e.g. null,
        // number), the as_str() filter drops it and we treat the body
        // as having no token fields. Belt-and-braces against unusual
        // upstream shapes.
        let resolver = RecordingResolver::new();
        let body = br#"{"access_token":null,"refresh_token":42}"#;

        assert!(matches!(
            rewrite_oauth_json_body(body, &resolver),
            OauthRewriteOutcome::NoTokenFields
        ));
    }
}
