//! Audit event emitted by the seccomp exec filter.
//!
//! Filter events are conceptually a distinct class from shim events —
//! kernel-trap decisions vs post-execution completions — so they use their
//! own struct. The existing shim [`super::AuditEvent`] is unchanged; both
//! event shapes land in the same `~/.nono/sessions/audit.jsonl` file,
//! distinguished by the `action_type` field (shim events use
//! `"capture"` / `"respond"` / `"approve"` or omit it for audit-only;
//! filter events use values prefixed with `exec_filter_`).

use serde::{Deserialize, Serialize};

/// Reason field values for `FilterAuditEvent` deny events.
///
/// Mirrored as string literals in the JSONL output. A struct would let us
/// derive `strum` or similar, but string literals are what downstream
/// consumers see and what we need to assert on in tests, so we expose
/// canonical constants instead of an enum.
pub mod reasons {
    /// Path is a member of the deny set built from `mediation.commands`.
    pub const DENY_SET: &str = "deny_set";
    /// Shebang chain walker found an interpreter in the deny set.
    pub const SHEBANG_CHAIN: &str = "shebang_chain";
    /// Double-read detected user-memory or file-content mutation between
    /// our check and the kernel's re-read.
    pub const TOCTOU_MISMATCH: &str = "toctou_mismatch";
    /// Path argument could not be resolved or canonicalized; fail-closed.
    pub const PATH_RESOLUTION_FAILED: &str = "path_resolution_failed";
}

/// `action_type` values identifying filter-emitted audit records.
pub mod action_types {
    /// The exec was permitted by the supervisor but targeted a binary
    /// that was not in `mediation.commands`. Outcome not observed by the
    /// supervisor (process runs in the agent's tree; exit code unknown
    /// from the filter's vantage point).
    pub const ALLOW_UNMEDIATED: &str = "exec_filter_allow_unmediated";
    /// The exec was denied by the supervisor with `EACCES`. `exit_code`
    /// is `126` to match the existing mediation-denied convention at
    /// `crates/nono-cli/src/mediation/policy.rs:169` ("command invoked
    /// cannot execute").
    pub const DENY: &str = "exec_filter_deny";
}

/// Audit record emitted by the exec filter.
///
/// Layout:
/// - `command` / `args` / `ts` match the semantics of the shim's
///   [`super::AuditEvent`] for consumer compatibility.
/// - `action_type` is always present (unlike on shim events where it is
///   `Option<String>`); the discriminator is load-bearing on filter
///   events. Values come from [`action_types`].
/// - `exit_code` is `Some(126)` on deny, absent (`None`) on
///   allow_unmediated. Omitting the field honestly represents "outcome
///   not observed" rather than fabricating a zero that would collide with
///   the existing `exit_code == 0` semantics on shim events.
/// - `reason`, `path`, `interpreter_chain` are filter-specific and absent
///   on events where they do not apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterAuditEvent {
    /// Basename of the canonical target.
    pub command: String,
    /// `argv` without `argv[0]`, matching the shim's convention.
    pub args: Vec<String>,
    /// Unix seconds.
    pub ts: u64,
    /// One of [`action_types::ALLOW_UNMEDIATED`] or
    /// [`action_types::DENY`].
    pub action_type: String,
    /// `Some(126)` on deny; `None` on allow_unmediated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// Populated only on deny; one of the strings in [`reasons`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Canonical resolved path of the target. Populated on all filter
    /// events; the basename-only `command` field does not preserve
    /// direct-path context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// On shebang-driven denies, the list of interpreter paths the filter
    /// chased (outermost first). Absent otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter_chain: Option<Vec<String>>,
}

impl FilterAuditEvent {
    /// Construct an `allow_unmediated` event.
    pub fn allow_unmediated(command: String, args: Vec<String>, ts: u64, path: String) -> Self {
        Self {
            command,
            args,
            ts,
            action_type: action_types::ALLOW_UNMEDIATED.to_string(),
            exit_code: None,
            reason: None,
            path: Some(path),
            interpreter_chain: None,
        }
    }

    /// Construct a `deny` event with the given reason and canonical path.
    pub fn deny(
        command: String,
        args: Vec<String>,
        ts: u64,
        reason: &'static str,
        path: String,
    ) -> Self {
        Self {
            command,
            args,
            ts,
            action_type: action_types::DENY.to_string(),
            exit_code: Some(126),
            reason: Some(reason.to_string()),
            path: Some(path),
            interpreter_chain: None,
        }
    }

    /// Attach a shebang interpreter chain to a deny event.
    pub fn with_interpreter_chain(mut self, chain: Vec<String>) -> Self {
        self.interpreter_chain = Some(chain);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_allow_unmediated_omits_optional_fields() {
        let evt = FilterAuditEvent::allow_unmediated(
            "jq".to_string(),
            vec!["-r".to_string(), ".items[]".to_string()],
            1776973803,
            "/usr/bin/jq".to_string(),
        );
        let json = serde_json::to_string(&evt).expect("serialize");
        // exit_code, reason, and interpreter_chain are absent on
        // allow_unmediated events; path is present.
        assert!(
            !json.contains("\"exit_code\""),
            "allow_unmediated must omit exit_code: {json}"
        );
        assert!(
            !json.contains("\"reason\""),
            "allow_unmediated must omit reason: {json}"
        );
        assert!(
            !json.contains("\"interpreter_chain\""),
            "allow_unmediated must omit interpreter_chain: {json}"
        );
        assert!(json.contains("\"action_type\":\"exec_filter_allow_unmediated\""));
        assert!(json.contains("\"command\":\"jq\""));
        assert!(json.contains("\"path\":\"/usr/bin/jq\""));
    }

    #[test]
    fn serialize_deny_set_event_has_exit_code_126_and_reason() {
        let evt = FilterAuditEvent::deny(
            "gh".to_string(),
            vec!["auth".to_string(), "token".to_string()],
            1776973803,
            reasons::DENY_SET,
            "/opt/homebrew/bin/gh".to_string(),
        );
        let json = serde_json::to_string(&evt).expect("serialize");
        assert!(json.contains("\"action_type\":\"exec_filter_deny\""));
        assert!(
            json.contains("\"exit_code\":126"),
            "deny must set exit_code = 126: {json}"
        );
        assert!(json.contains("\"reason\":\"deny_set\""));
        assert!(json.contains("\"path\":\"/opt/homebrew/bin/gh\""));
        assert!(
            !json.contains("\"interpreter_chain\""),
            "non-shebang deny must omit interpreter_chain: {json}"
        );
    }

    #[test]
    fn serialize_shebang_chain_deny_includes_interpreter_chain() {
        let evt = FilterAuditEvent::deny(
            "evil.sh".to_string(),
            Vec::new(),
            1776973803,
            reasons::SHEBANG_CHAIN,
            "/tmp/evil.sh".to_string(),
        )
        .with_interpreter_chain(vec!["/opt/homebrew/bin/gh".to_string()]);
        let json = serde_json::to_string(&evt).expect("serialize");
        assert!(json.contains("\"reason\":\"shebang_chain\""));
        assert!(json.contains("\"interpreter_chain\":[\"/opt/homebrew/bin/gh\"]"));
        assert!(json.contains("\"exit_code\":126"));
    }

    #[test]
    fn command_is_basename_by_convention() {
        // Constructor accepts any string for `command`; callers pass the
        // basename. This test documents the convention rather than
        // enforcing it at the type level.
        let evt = FilterAuditEvent::allow_unmediated(
            "jq".to_string(),
            Vec::new(),
            0,
            "/usr/bin/jq".to_string(),
        );
        assert_eq!(evt.command, "jq");
        assert!(evt.path.as_deref().unwrap().ends_with("/jq"));
    }

    #[test]
    fn roundtrip_preserves_all_populated_fields() {
        let original = FilterAuditEvent::deny(
            "gh".to_string(),
            vec!["auth".to_string(), "token".to_string()],
            1776973803,
            reasons::DENY_SET,
            "/opt/homebrew/bin/gh".to_string(),
        );
        let json = serde_json::to_string(&original).expect("serialize");
        let parsed: FilterAuditEvent = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_allow_unmediated_missing_optionals_succeeds() {
        let json = r#"{"command":"jq","args":[],"ts":1776973803,"action_type":"exec_filter_allow_unmediated","path":"/usr/bin/jq"}"#;
        let parsed: FilterAuditEvent = serde_json::from_str(json).expect("parse");
        assert_eq!(parsed.command, "jq");
        assert!(parsed.exit_code.is_none());
        assert!(parsed.reason.is_none());
        assert!(parsed.interpreter_chain.is_none());
        assert_eq!(parsed.action_type, "exec_filter_allow_unmediated");
    }

    #[test]
    fn action_type_is_always_present() {
        // Required field; deserialization fails if missing.
        let json_without = r#"{"command":"x","args":[],"ts":0}"#;
        let r: Result<FilterAuditEvent, _> = serde_json::from_str(json_without);
        assert!(
            r.is_err(),
            "action_type must be required, but deserialized: {:?}",
            r.ok()
        );
    }
}
