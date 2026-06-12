//! Auto-injected mediation rule that refuses subprocess reads of the OAuth
//! broker keychain entry.
//!
//! ## Why this exists
//!
//! The persistence branch saves captured Anthropic OAuth pairs to the macOS
//! Keychain under `service="nono", account="claude_oauth_broker"`
//! ([`super::broker_store`]). The entry's legacy `SecAccess` ACL restricts
//! reads to the nono binary by code signature, but the legacy ACL **does not
//! silently deny** non-trusted callers — it triggers a macOS dialog the user
//! can click Allow on. A sophisticated prompt-injected agent that
//! social-engineers the user into clicking Allow defeats the ACL.
//!
//! This module closes the realistic version of that threat (subprocess access
//! via `/usr/bin/security`) by injecting a mediation rule into the
//! [`super::MediationConfig`] whenever a profile declares a credential
//! route with `OauthIntercept` capture. The mediation shim intercepts
//! matching `security` invocations in the
//! unsandboxed parent process and returns `errSecItemNotFound` (exit 44, empty
//! stdout) without ever invoking the real binary. From the agent's
//! perspective, the entry simply does not exist — no dialog, no Allow button,
//! no social-engineering surface.
//!
//! ## Layered protection
//!
//! - **Primary (this module):** subprocess `security find-generic-password`
//!   reads are refused in the parent. The agent gets "not found." This is
//!   what the threat model that motivates persistence cares about.
//! - **Defense-in-depth (the broker entry's ACL):** if an attacker bypasses
//!   the mediation shim by linking Security framework directly and calling
//!   `SecItemCopyMatching` via Mach IPC, the ACL on the broker entry refuses
//!   the non-nono caller and triggers a dialog. The same residual the
//!   2026-06-03 plan acknowledges for the `Claude Code-credentials` entry.
//!
//! ## Coverage scope (resolved decision)
//!
//! Reads only. The auto-injected rules cover `find-generic-password` against
//! the broker entry. Write attempts (`add-generic-password`,
//! `delete-generic-password`) fall through to passthrough; the legacy ACL
//! refuses non-nono callers and the user sees the dialog. Write attempts
//! therefore stay visible as defense-in-depth, while read attempts are
//! silently refused (the realistic exfiltration path).
//!
//! ## Argv-shape coverage
//!
//! `mediation::policy::subcommand_matches` filters any argv element starting
//! with `-` before matching `args_prefix`. So `-w`, `-g`, `-gw`, `-s`, `-a`
//! and similar option introducers don't affect matching, but the option
//! *values* (`nono`, `claude_oauth_broker`) do. Two rules cover the only
//! orderings the `security` CLI actually accepts for service/account flags:
//!
//! 1. `-s nono -a claude_oauth_broker [-w] [keychain]` → positional stream
//!    `["find-generic-password", "nono", "claude_oauth_broker", ...]`
//! 2. `-a claude_oauth_broker -s nono [-w] [keychain]` → positional stream
//!    `["find-generic-password", "claude_oauth_broker", "nono", ...]`
//!
//! Pure-positional forms (`security find-generic-password nono
//! claude_oauth_broker`) were tested and do not actually work against the
//! `security` CLI — service/account must be passed via `-s`/`-a` flags. A
//! leading positional like an explicit `[keychain]` path changes the search
//! target (BSD getopt stops at first positional, ignoring subsequent flags),
//! so it cannot read the broker entry through this bypass.
//!
//! ## Known limitation
//!
//! `security dump-keychain -d` enumerates and reads every entry it can
//! access. The broker entry's per-item ACL triggers a dialog when
//! `dump-keychain -d` reaches it (same defense-in-depth as direct read). The
//! enumeration is loud and per-entry; not a silent bypass. This module does
//! not block `dump-keychain` because doing so would also block legitimate
//! diagnostics. The realistic attack remains `find-generic-password`.

use super::{CallerPolicy, CommandEntry, InterceptAction, InterceptRule, MediationConfig};

/// Service name of the OAuth broker keychain entry. Mirrors
/// `super::broker_store::SERVICE_NAME` (which is itself macOS-gated). Hard-
/// coded here so this module compiles on every target without `cfg` walls
/// around a literal-string match.
pub const BROKER_SERVICE: &str = "nono";

/// Account name of the OAuth broker keychain entry. Mirrors
/// `super::broker_store::CLAUDE_OAUTH_ACCOUNT`. Same rationale as
/// [`BROKER_SERVICE`] for the duplication.
pub const BROKER_ACCOUNT: &str = "claude_oauth_broker";

/// Exit code from `/usr/bin/security` when `SecKeychainSearchCopyNext`
/// returns "item not found" (`errSecItemNotFound`, OSStatus -25300). The
/// CLI maps this to process exit 44. Synthesizing exit 44 in our `Respond`
/// action makes the refused call indistinguishable from "entry never
/// existed."
const ERR_SEC_ITEM_NOT_FOUND_EXIT: i32 = 44;

/// Subcommand name on `/usr/bin/security` whose reads we refuse.
const SUBCOMMAND_FIND: &str = "find-generic-password";

/// Build the auto-injected `CommandEntry` for `security`. Returns a single-
/// element vec for symmetry with `oauth_capture_routes()` and to leave room
/// for additional entries (e.g. a future `dump-keychain` variant) without
/// changing the function signature.
pub fn oauth_capture_mediation_rules() -> Vec<CommandEntry> {
    vec![CommandEntry {
        name: "security".to_string(),
        binary_path: None,
        intercept: refusal_intercepts(),
        sandbox: None,
        caller_policy: CallerPolicy::default(),
    }]
}

/// The `respond` intercept rules that refuse broker-entry reads.
fn refusal_intercepts() -> Vec<InterceptRule> {
    vec![
        // `-s nono -a claude_oauth_broker [-w]` and the same with a trailing
        // `[keychain]` positional. After filtering `-`-prefixed tokens, the
        // positional stream is `["find-generic-password", "nono",
        // "claude_oauth_broker", ...]`, matched as a prefix.
        InterceptRule {
            args_prefix: vec![
                SUBCOMMAND_FIND.to_string(),
                BROKER_SERVICE.to_string(),
                BROKER_ACCOUNT.to_string(),
            ],
            admin: false,
            action: not_found_response(),
        },
        // `-a claude_oauth_broker -s nono [-w]` and trailing-`[keychain]`
        // variant. Different positional ordering, same effect.
        InterceptRule {
            args_prefix: vec![
                SUBCOMMAND_FIND.to_string(),
                BROKER_ACCOUNT.to_string(),
                BROKER_SERVICE.to_string(),
            ],
            admin: false,
            action: not_found_response(),
        },
    ]
}

/// Construct the synthetic "not found" response. Empty stdout + exit 44 is
/// what `/usr/bin/security` produces for `errSecItemNotFound`.
fn not_found_response() -> InterceptAction {
    InterceptAction::Respond {
        stdout: String::new(),
        exit_code: ERR_SEC_ITEM_NOT_FOUND_EXIT,
    }
}

/// Prepend the auto-injected `security` intercepts onto an existing
/// [`MediationConfig`].
///
/// Merge semantics (resolved decision: **Prepend**):
/// - If `config.commands` already contains a `CommandEntry` named
///   `security`, the auto-injected intercepts are inserted at the FRONT of
///   that entry's `intercept` list. Profile-declared intercepts follow and
///   are evaluated only if none of the auto-injected rules matched. This
///   prevents a downstream profile from accidentally or deliberately
///   displacing the broker-refusal protection (e.g. via a broad earlier
///   passthrough/approve rule).
/// - If no `security` entry exists, a new `CommandEntry` is appended.
/// - The existing entry's `sandbox`, `binary_path`, and `caller_policy`
///   fields are preserved; only `intercept` is modified.
///
/// Idempotent only if `intercepts_already_injected(...)` is checked
/// externally — repeated calls will prepend duplicates. The call site in
/// `sandbox_prepare` invokes this exactly once per profile resolution, so
/// duplication is not a practical concern.
pub fn inject_into(config: &mut MediationConfig) {
    let injected = refusal_intercepts();
    if let Some(existing) = config.commands.iter_mut().find(|c| c.name == "security") {
        let profile_declared = std::mem::take(&mut existing.intercept);
        existing.intercept = injected;
        existing.intercept.extend(profile_declared);
    } else {
        config.commands.extend(oauth_capture_mediation_rules());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The function returns exactly one `CommandEntry` named `security`.
    #[test]
    fn oauth_capture_mediation_rules_returns_security_command_entry() {
        let rules = oauth_capture_mediation_rules();
        assert_eq!(rules.len(), 1, "expected exactly one CommandEntry");
        assert_eq!(rules[0].name, "security");
        assert!(rules[0].binary_path.is_none());
        assert!(rules[0].sandbox.is_none());
    }

    /// Every refusal intercept must use `Respond` with exit 44 and empty
    /// stdout. The empty-stdout check is the defensive one: a future edit
    /// that accidentally echoes the credential back here would leak it. The
    /// exit-44 check encodes the spec ("indistinguishable from not-found").
    #[test]
    fn refusal_intercepts_use_not_found_response() {
        for rule in refusal_intercepts() {
            match rule.action {
                InterceptAction::Respond { stdout, exit_code } => {
                    assert!(
                        stdout.is_empty(),
                        "refusal stdout must be empty to avoid leaking entry contents (was: {stdout:?})"
                    );
                    assert_eq!(
                        exit_code, ERR_SEC_ITEM_NOT_FOUND_EXIT,
                        "refusal exit code must match errSecItemNotFound (44)"
                    );
                }
                other => panic!("refusal rule must use Respond, got {other:?}"),
            }
            assert!(
                !rule.admin,
                "refusal rules must not require admin (would prompt user, defeating silent refusal)"
            );
        }
    }

    /// Both `-s X -a Y` and `-a Y -s X` orderings produce distinct
    /// `args_prefix` rules. Two rules total.
    #[test]
    fn refusal_intercepts_cover_both_orderings() {
        let intercepts = refusal_intercepts();
        assert_eq!(intercepts.len(), 2, "expected two argv-ordering rules");

        let prefixes: Vec<&[String]> = intercepts
            .iter()
            .map(|r| r.args_prefix.as_slice())
            .collect();

        // Service-first: -s nono -a claude_oauth_broker
        assert!(
            prefixes.iter().any(|p| p
                == &[
                    SUBCOMMAND_FIND.to_string(),
                    BROKER_SERVICE.to_string(),
                    BROKER_ACCOUNT.to_string(),
                ]),
            "missing service-first ordering ({SUBCOMMAND_FIND} {BROKER_SERVICE} {BROKER_ACCOUNT})"
        );
        // Account-first: -a claude_oauth_broker -s nono
        assert!(
            prefixes.iter().any(|p| p
                == &[
                    SUBCOMMAND_FIND.to_string(),
                    BROKER_ACCOUNT.to_string(),
                    BROKER_SERVICE.to_string(),
                ]),
            "missing account-first ordering ({SUBCOMMAND_FIND} {BROKER_ACCOUNT} {BROKER_SERVICE})"
        );
    }

    /// When the profile didn't declare a `security` entry, injection adds
    /// one.
    #[test]
    fn inject_into_creates_entry_when_security_absent() {
        let mut config = MediationConfig::default();
        inject_into(&mut config);
        assert_eq!(config.commands.len(), 1);
        assert_eq!(config.commands[0].name, "security");
        assert_eq!(config.commands[0].intercept.len(), 2);
    }

    /// When the profile already declared a `security` entry (e.g.
    /// shadowfax's `Claude Code-credentials` rules), injection prepends to
    /// it. The profile's intercepts follow and are evaluated only after
    /// the auto-injected ones.
    #[test]
    fn inject_into_prepends_to_existing_security_entry() {
        let profile_declared_intercept = InterceptRule {
            args_prefix: vec![
                "find-generic-password".to_string(),
                "Claude Code-credentials".to_string(),
            ],
            admin: false,
            action: InterceptAction::Respond {
                stdout: "profile-stdout".to_string(),
                exit_code: 99,
            },
        };

        let mut config = MediationConfig::default();
        config.commands.push(CommandEntry {
            name: "security".to_string(),
            binary_path: None,
            intercept: vec![profile_declared_intercept.clone()],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        });

        inject_into(&mut config);

        assert_eq!(
            config.commands.len(),
            1,
            "must not duplicate the security entry; modify in place"
        );
        let security = &config.commands[0];
        assert_eq!(security.intercept.len(), 3, "two injected + one profile");

        // Auto-injected MUST come first (prepend semantics).
        assert_eq!(
            security.intercept[0].args_prefix,
            vec![
                SUBCOMMAND_FIND.to_string(),
                BROKER_SERVICE.to_string(),
                BROKER_ACCOUNT.to_string(),
            ],
            "first intercept must be the auto-injected service-first rule"
        );
        assert_eq!(
            security.intercept[1].args_prefix,
            vec![
                SUBCOMMAND_FIND.to_string(),
                BROKER_ACCOUNT.to_string(),
                BROKER_SERVICE.to_string(),
            ],
            "second intercept must be the auto-injected account-first rule"
        );

        // Profile-declared follows last.
        assert_eq!(
            security.intercept[2].args_prefix, profile_declared_intercept.args_prefix,
            "profile intercept must follow the auto-injected ones"
        );
    }

    /// `inject_into` does not affect other CommandEntry names — only
    /// `security` is modified.
    #[test]
    fn inject_into_does_not_touch_other_commands() {
        let mut config = MediationConfig::default();
        config.commands.push(CommandEntry {
            name: "gh".to_string(),
            binary_path: None,
            intercept: vec![InterceptRule {
                args_prefix: vec!["auth".to_string()],
                admin: false,
                action: InterceptAction::Approve { script: None },
            }],
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        });

        inject_into(&mut config);

        assert_eq!(config.commands.len(), 2, "added security alongside gh");
        let gh = config
            .commands
            .iter()
            .find(|c| c.name == "gh")
            .expect("gh entry preserved");
        assert_eq!(gh.intercept.len(), 1, "gh's intercepts untouched");
    }

    /// Match constants against the values declared by `broker_store` on
    /// macOS. Compile-time guard: if a future edit changes one and not the
    /// other, this test fails on macOS builds. Linux builds skip it
    /// because `broker_store::SERVICE_NAME` is macOS-gated.
    #[test]
    #[cfg(target_os = "macos")]
    fn broker_service_and_account_match_broker_store_constants() {
        assert_eq!(BROKER_SERVICE, super::super::broker_store::SERVICE_NAME);
        assert_eq!(
            BROKER_ACCOUNT,
            super::super::broker_store::CLAUDE_OAUTH_ACCOUNT
        );
    }
}
