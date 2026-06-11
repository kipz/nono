//! Pre-flight checks for `oauth_capture: true` and `apikey_gateway`.
//! macOS only for the keychain pieces; the helper-coverage check is
//! cross-platform.
//!
//! Protection of the macOS `Claude Code-credentials` keychain entry is
//! handled by the mediation shim's `capture` action with `format: "json"`
//! (see `docs/plans/2026-06-03-mediation-based-oauth-capture.md`). This
//! module does not rewrite the keychain; profile authors configure the
//! substitution declaratively. Pre-flight only checks for fail-closed
//! conditions — namely the presence of a credential surface that the
//! broker-backed proxy path cannot translate, or a configured
//! `apiKeyHelper` whose argv is not covered by a `capture` mediation
//! rule.
//!
//! ### API-key surfaces (fail-closed)
//!
//! Surfaces that carry an API key are fatal because the proxy's
//! TLS-intercept translates `Authorization: Bearer nono_<hex>` but not
//! `x-api-key: nono_<hex>` — the child would 401 on every request. When
//! any API-key surface is detected pre-flight fails with a clear message:
//!
//! - environment: `ANTHROPIC_API_KEY`, `CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR`
//!   (skipped if the profile's `denied_env_vars` would strip them anyway)
//! - macOS keychain entry `Claude Code` (no `-credentials` suffix)
//! - `primaryApiKey` field in `~/.claude.json`
//!
//! ### apiKeyHelper coverage (apikey_gateway only, fail-closed)
//!
//! When `apikey_gateway` is set, Claude Code is expected to fetch its
//! bearer via the `apiKeyHelper` command declared in
//! `~/.claude/settings.json`. The mediation shim captures that helper's
//! stdout into the broker and returns a `nono_<hex>` nonce to the
//! sandbox. Without a matching `capture` mediation rule, the real
//! bearer flows into the sandbox uncaptured — defeating the purpose of
//! `apikey_gateway`. Pre-flight refuses to launch unless a covering
//! rule is found.

use crate::exec_strategy::is_env_var_denied;
use crate::mediation::broker::TokenBroker;
use crate::mediation::{CaptureFormat, InterceptAction, MediationConfig};
use crate::profile::ApiKeyGatewayConfig;
use nono::{NonoError, Result};
use serde_json::Value;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// API-key environment variables. The proxy does not rewrite
/// `x-api-key: nono_<hex>` headers inside the CONNECT tunnel, so
/// capturing these into the broker would just produce a 401 on every
/// upstream request. Flag them as fatal instead of silently breaking
/// the child.
const API_KEY_ENV_VARS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR",
    "ANTHROPIC_UNIX_SOCKET",
];

#[derive(Debug, Default)]
pub(crate) struct PreflightOutcome;

/// Run the pre-flight check if the target program is `claude` and
/// OAuth capture is active. For any other program this is a quiet
/// no-op — pre-flight is a Claude-Code-specific feature.
///
/// `denied_env_vars` is the profile's env-var deny list. Any API-key
/// env var the profile would strip before the child sees it is excluded
/// from the fail-closed check.
pub(crate) fn run_oauth_preflight(
    _broker: &TokenBroker,
    program: &OsStr,
    denied_env_vars: Option<&[String]>,
    apikey_gateway: Option<&ApiKeyGatewayConfig>,
    mediation: &MediationConfig,
) -> Result<PreflightOutcome> {
    if !program_is_claude(program) {
        debug!("oauth_capture: target program is not claude; skipping pre-flight");
        return Ok(PreflightOutcome);
    }

    // apikey_gateway and existing API-key surfaces are NOT mutually
    // exclusive in shape: apikey_gateway expects Claude Code's
    // `apiKeyHelper` to mint a fresh bearer each TTL window, so there
    // should *not* be a static API-key surface lingering on the host.
    // The fail-closed check still fires unconditionally — if the user
    // has both apikey_gateway and a static ANTHROPIC_API_KEY env, the
    // static one would win in Claude Code's resolution order and the
    // proxy's bearer-translation path would never trigger.
    if let Some(reason) = detect_blocking_api_key_surface(denied_env_vars)? {
        return Err(NonoError::SandboxInit(format!(
            "oauth_capture/apikey_gateway is enabled but an API-key credential is already configured: {reason}. \
             The broker-backed proxy path translates Authorization: Bearer tokens; \
             x-api-key requests inside the CONNECT tunnel would fail authentication. \
             Either clear the API key (unset the env var, delete the keychain entry, \
             or remove `primaryApiKey` from ~/.claude.json) and re-run, or remove \
             `oauth_capture`/`apikey_gateway` from your profile to use API-key auth as-is."
        )));
    }

    if let Some(gateway_cfg) = apikey_gateway {
        run_apikey_gateway_preflight(gateway_cfg, mediation)?;
    }

    Ok(PreflightOutcome)
}

/// Verify that the host's Claude Code `apiKeyHelper` is covered by a
/// mediation `capture` rule.
///
/// Read `~/.claude/settings.json` (and `CLAUDE_CONFIG_DIR` overrides if
/// set). If `apiKeyHelper` is declared, shell-split its value and
/// compare the resulting argv against the configured
/// `helper_argv_prefix` from the profile's [`ApiKeyGatewayConfig`].
/// Fail closed unless the helper's first token resolves to a binary
/// name that has a matching `mediation.commands` entry with an
/// `args_prefix` that is a prefix of the helper's positional args.
///
/// Beyond the helper-vs-profile shape check, the resolved
/// `MediationConfig` is searched for a `Capture` intercept rule
/// targeting the helper's binary name with an `args_prefix` that is a
/// prefix of the helper's positional args. Without a covering rule the
/// real bearer would flow into the sandbox uncaptured.
fn run_apikey_gateway_preflight(
    gateway_cfg: &ApiKeyGatewayConfig,
    mediation: &MediationConfig,
) -> Result<()> {
    let (config_dir, _explicit) = claude_config_dir_pair()
        .map_err(|msg| NonoError::SandboxInit(format!("apikey_gateway preflight: {msg}")))?;
    let settings_path = config_dir.join("settings.json");
    let helper = match read_apikey_helper(&settings_path)? {
        Some(value) => value,
        None => {
            // No apiKeyHelper declared. apikey_gateway is still meaningful
            // (the override of ANTHROPIC_BASE_URL routes through the
            // broker for any bearer the agent already holds), but the
            // common case is that the user does declare it. Warn loudly
            // rather than fail — the operator may be testing the
            // gateway path with a different bearer source.
            tracing::warn!(
                "apikey_gateway is enabled but no `apiKeyHelper` is declared in {}. \
                 The gateway route will only translate bearers the sandboxed agent \
                 already possesses (e.g. via a separate mediation capture). \
                 If you intend the helper to mint bearers, add it to settings.json.",
                settings_path.display()
            );
            return Ok(());
        }
    };
    let helper_argv = shell_split(&helper).ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "apikey_gateway preflight: could not parse apiKeyHelper '{helper}' as a shell command \
             (quote/escape sequences may be malformed). Refusing to start because the helper-coverage \
             check cannot run."
        ))
    })?;
    if helper_argv.is_empty() {
        return Err(NonoError::SandboxInit(format!(
            "apikey_gateway preflight: apiKeyHelper '{helper}' parses to an empty argv. \
             Refusing to start."
        )));
    }
    let helper_bin = std::path::Path::new(&helper_argv[0])
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&helper_argv[0])
        .to_string();
    let helper_positionals: Vec<&str> = helper_argv
        .iter()
        .skip(1)
        .filter(|s| !s.starts_with('-'))
        .map(|s| s.as_str())
        .collect();

    if gateway_cfg.helper_argv_prefix.is_empty() {
        return Err(NonoError::SandboxInit(format!(
            "apikey_gateway preflight: apiKeyHelper '{helper}' is declared in settings.json \
             but apikey_gateway.helper_argv_prefix is empty in the profile. \
             Declare the expected positional-args prefix so the coverage check can run, \
             e.g. helper_argv_prefix: [\"auth\", \"token\", \"example-scope\"]."
        )));
    }
    // The configured helper_argv_prefix must be a prefix of the
    // helper's positional args. Treating it as a strict prefix rather
    // than substring guards against an `apiKeyHelper` that quietly
    // changes binary or subcommand without the profile being updated.
    let matches = helper_positionals.len() >= gateway_cfg.helper_argv_prefix.len()
        && helper_positionals
            .iter()
            .zip(gateway_cfg.helper_argv_prefix.iter())
            .all(|(actual, expected)| *actual == expected.as_str());
    if !matches {
        return Err(NonoError::SandboxInit(format!(
            "apikey_gateway preflight: apiKeyHelper '{helper}' (positional args {helper_positionals:?}) \
             does NOT match the configured helper_argv_prefix {:?}. \
             Either fix the profile's helper_argv_prefix to match the deployed helper, \
             or update settings.json so the helper invocation aligns with the profile.",
            gateway_cfg.helper_argv_prefix
        )));
    }

    // Verify a `capture` mediation rule covers the helper. Without
    // it, the helper's stdout (real bearer) would flow into the
    // sandbox untouched.
    let covering_rule = mediation.commands.iter().find(|cmd| {
        cmd.name == helper_bin
            && cmd.intercept.iter().any(|rule| {
                matches!(
                    rule.action,
                    InterceptAction::Capture {
                        format: None,
                        ..
                    } | InterceptAction::Capture {
                        format: Some(CaptureFormat::Json),
                        ..
                    }
                ) && is_args_prefix_match(&rule.args_prefix, &helper_positionals)
            })
    });
    if covering_rule.is_none() {
        return Err(NonoError::SandboxInit(format!(
            "apikey_gateway preflight: no `mediation.commands` rule covers the host's \
             apiKeyHelper. Helper binary '{helper_bin}', positional args {helper_positionals:?}. \
             Add a CommandEntry to the profile, e.g.:\n\
             \n\
             {{\n  \
               \"name\": \"{helper_bin}\",\n  \
               \"intercept\": [{{\n    \
                 \"args_prefix\": {:?},\n    \
                 \"action\": {{\"type\": \"capture\"}}\n  \
               }}]\n\
             }}\n\
             Refusing to start because the real bearer would otherwise reach the sandbox.",
            gateway_cfg.helper_argv_prefix
        )));
    }

    info!(
        "apikey_gateway preflight: helper '{}' positional argv {:?} matches helper_argv_prefix {:?} \
         and is covered by mediation rule",
        helper_bin, helper_positionals, gateway_cfg.helper_argv_prefix
    );
    Ok(())
}

/// Returns true if `prefix` is a prefix of `args`.
fn is_args_prefix_match(prefix: &[String], args: &[&str]) -> bool {
    if prefix.len() > args.len() {
        return false;
    }
    prefix
        .iter()
        .zip(args.iter())
        .all(|(p, a)| p.as_str() == *a)
}

/// Minimal shell-string splitter for `apiKeyHelper` values.
///
/// Handles plain whitespace tokenisation plus single- and double-quoted
/// segments. Does NOT handle backslash escapes, variable expansion,
/// command substitution, or globbing — Claude Code's `apiKeyHelper`
/// values in practice are simple `binary arg1 arg2 --flag value`
/// invocations and we want a deterministic check, not a full POSIX
/// shell. Returns `None` when quotes are unbalanced.
fn shell_split(s: &str) -> Option<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut in_single = false;
    let mut in_double = false;
    for ch in s.chars() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            c if c.is_whitespace() && !in_single && !in_double => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if in_single || in_double {
        return None;
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Some(out)
}

/// Read `apiKeyHelper` from settings.json. Returns `Ok(None)` when the
/// file or field is absent; an `Err` for malformed JSON.
fn read_apikey_helper(settings_path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(settings_path) {
        Ok(raw) => {
            let parsed: Value = serde_json::from_str(&raw).map_err(|err| {
                NonoError::SandboxInit(format!(
                    "apikey_gateway preflight: could not parse {}: {err}",
                    settings_path.display()
                ))
            })?;
            Ok(parsed
                .get("apiKeyHelper")
                .and_then(Value::as_str)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(NonoError::SandboxInit(format!(
            "apikey_gateway preflight: could not read {}: {err}",
            settings_path.display()
        ))),
    }
}

/// Resolve the Claude Code config dir (honouring `CLAUDE_CONFIG_DIR`).
///
/// Hoisted from the macOS-only `claude_config_dir` below so the
/// helper-coverage check can run cross-platform.
fn claude_config_dir_pair() -> std::result::Result<(PathBuf, bool), String> {
    if let Some(value) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Ok((PathBuf::from(value), true));
    }
    let home = dirs::home_dir().ok_or_else(|| "no HOME set".to_string())?;
    Ok((home.join(".claude"), false))
}

fn program_is_claude(program: &OsStr) -> bool {
    Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .map(|name| name == "claude")
        .unwrap_or(false)
}

/// Returns `Some(reason)` if an API-key credential is present anywhere
/// pre-flight would otherwise need to handle. The caller treats this as
/// fatal — see the module docstring.
///
/// `denied_env_vars` is the profile's env-var deny list. Any API-key var
/// the profile would strip from the child's env is excluded from the
/// check — it won't reach the child regardless.
fn detect_blocking_api_key_surface(denied_env_vars: Option<&[String]>) -> Result<Option<String>> {
    if let Some(reason) = detect_api_key_env_var_from(|k| std::env::var_os(k), denied_env_vars) {
        return Ok(Some(reason));
    }

    if let Some(home) = dirs::home_dir() {
        let global_config = home.join(".claude.json");
        if let Some(reason) = detect_primary_api_key_in_file(&global_config)? {
            return Ok(Some(reason));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(reason) = detect_api_key_keychain_macos()? {
            return Ok(Some(reason));
        }
    }

    Ok(None)
}

/// Test-friendly: scan `API_KEY_ENV_VARS` against an injected env reader,
/// skipping any var the profile's deny list would strip before the child
/// sees it.
fn detect_api_key_env_var_from<F>(
    env_reader: F,
    denied_env_vars: Option<&[String]>,
) -> Option<String>
where
    F: Fn(&str) -> Option<std::ffi::OsString>,
{
    for &key in API_KEY_ENV_VARS {
        // The profile would deny this var to the child anyway — skip it.
        if let Some(denied) = denied_env_vars
            && is_env_var_denied(key, denied)
        {
            continue;
        }
        if let Some(value) = env_reader(key)
            && !value.is_empty()
        {
            return Some(format!("environment variable {key}"));
        }
    }
    None
}

/// Test-friendly: scan a `.claude.json` for a non-empty `primaryApiKey`.
fn detect_primary_api_key_in_file(global_config: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(global_config) {
        Ok(raw) => {
            if global_config_has_primary_api_key(&raw)? {
                Ok(Some(format!(
                    "primaryApiKey in {}",
                    global_config.display()
                )))
            } else {
                Ok(None)
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not read {}: {err}",
            global_config.display()
        ))),
    }
}

fn global_config_has_primary_api_key(raw: &str) -> Result<bool> {
    let parsed: Value = serde_json::from_str(raw).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not parse ~/.claude.json: {err}"
        ))
    })?;
    Ok(parsed
        .get("primaryApiKey")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty()))
}

#[cfg(target_os = "macos")]
fn detect_api_key_keychain_macos() -> Result<Option<String>> {
    let (config_dir, explicit) = match claude_config_dir() {
        Ok(pair) => pair,
        Err(err) => {
            return Err(NonoError::SandboxInit(format!(
                "oauth_capture pre-flight: {err}"
            )));
        }
    };
    let service = claude_keychain_service_name(&config_dir, explicit, "");
    let account = claude_keychain_account_name();
    if read_keychain_item(&account, &service).is_some_and(|v| !v.trim().is_empty()) {
        return Ok(Some(format!(
            "macOS keychain entry service \"{service}\" account \"{account}\""
        )));
    }
    Ok(None)
}

// --- macOS keychain helpers (duplicated thin wrappers around the same
//     ones in `sandbox_prepare`; kept private here so this module stays
//     self-contained and re-usable in tests without dragging the full
//     `SandboxArgs` machinery into the test fixtures). ---

#[cfg(target_os = "macos")]
fn claude_config_dir() -> std::result::Result<(PathBuf, bool), String> {
    claude_config_dir_pair()
}

#[cfg(target_os = "macos")]
fn claude_keychain_service_name(
    config_dir: &Path,
    config_dir_explicit: bool,
    service_suffix: &str,
) -> String {
    use sha2::{Digest, Sha256};

    let dir_hash = if config_dir_explicit {
        let digest = Sha256::digest(config_dir.to_string_lossy().as_bytes());
        let prefix = digest[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("-{prefix}")
    } else {
        String::new()
    };
    format!(
        "Claude Code{}{}{}",
        claude_oauth_suffix_macos(),
        service_suffix,
        dir_hash
    )
}

#[cfg(target_os = "macos")]
fn claude_oauth_suffix_macos() -> &'static str {
    if std::env::var_os("CLAUDE_CODE_CUSTOM_OAUTH_URL").is_some() {
        return "-custom-oauth";
    }
    if std::env::var("USER_TYPE").ok().as_deref() == Some("ant") {
        if env_truthy_macos("USE_LOCAL_OAUTH") {
            return "-local-oauth";
        }
        if env_truthy_macos("USE_STAGING_OAUTH") {
            return "-staging-oauth";
        }
    }
    ""
}

#[cfg(target_os = "macos")]
fn env_truthy_macos(key: &str) -> bool {
    std::env::var(key).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

#[cfg(target_os = "macos")]
fn claude_keychain_account_name() -> String {
    std::env::var("USER").unwrap_or_else(|_| "claude-code-user".to_string())
}

/// In-process keychain read instead of spawning `/usr/bin/security`.
///
/// The subprocess path surfaces a "security wants to use your confidential
/// information" dialog that requires the keychain master password every
/// time — there's no way to grant `security` persistent trust on an
/// entry's ACL. The in-process API instead prompts as the running binary
/// ("nono wants to access…"), which the user can permit with
/// "Always Allow" once and never see again for that entry.
#[cfg(target_os = "macos")]
fn read_keychain_item(account: &str, service: &str) -> Option<String> {
    use security_framework::os::macos::passwords::find_generic_password;

    let (password_bytes, _item) = find_generic_password(None, service, account).ok()?;
    let s = std::str::from_utf8(password_bytes.as_ref()).ok()?;
    Some(s.to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn program_is_claude_matches_basename_only() {
        assert!(program_is_claude(OsStr::new("/opt/homebrew/bin/claude")));
        assert!(program_is_claude(OsStr::new("claude")));
        assert!(!program_is_claude(OsStr::new("/usr/bin/codex")));
        assert!(!program_is_claude(OsStr::new("claude-wrapper")));
    }

    #[test]
    fn run_oauth_preflight_no_op_when_target_is_not_claude() {
        // Even with a real-token-bearing env var, pre-flight skips when
        // the program isn't claude. (Other binaries don't read these.)
        let broker = TokenBroker::new();
        let mediation = MediationConfig::default();
        run_oauth_preflight(
            &broker,
            OsStr::new("/usr/bin/codex"),
            None,
            None,
            &mediation,
        )
        .unwrap();
    }

    #[test]
    fn global_config_has_primary_api_key_handles_shapes() {
        assert!(
            !global_config_has_primary_api_key(r#"{"primaryApiKey":""}"#).unwrap(),
            "empty string must not count as having a key"
        );
        assert!(
            global_config_has_primary_api_key(r#"{"primaryApiKey":"sk-ant-api03-xxx"}"#).unwrap()
        );
        assert!(!global_config_has_primary_api_key(r#"{}"#).unwrap());
        assert!(!global_config_has_primary_api_key(r#"{"primaryApiKey":null}"#).unwrap());
        assert!(global_config_has_primary_api_key("not json").is_err());
    }

    /// Helper: build an env-reader closure from a static slice of pairs.
    fn fake_env(
        pairs: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str) -> Option<std::ffi::OsString> {
        move |k| {
            pairs
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| std::ffi::OsString::from(*v))
        }
    }

    #[test]
    fn detect_api_key_env_var_flags_first_non_empty_match() {
        assert_eq!(detect_api_key_env_var_from(fake_env(&[]), None), None);
        assert_eq!(
            detect_api_key_env_var_from(fake_env(&[("ANTHROPIC_API_KEY", "")]), None),
            None,
            "empty value must not count"
        );
        assert_eq!(
            detect_api_key_env_var_from(
                fake_env(&[("ANTHROPIC_API_KEY", "sk-ant-api03-xxx")]),
                None
            )
            .unwrap(),
            "environment variable ANTHROPIC_API_KEY"
        );
    }

    #[test]
    fn detect_api_key_env_var_skips_vars_denied_by_profile() {
        // A var the profile would deny to the child should not trigger
        // the fail-closed check — the child won't see it regardless.
        let denied = vec!["ANTHROPIC_API_KEY".to_string()];
        assert_eq!(
            detect_api_key_env_var_from(
                fake_env(&[("ANTHROPIC_API_KEY", "sk-ant-api03-real")]),
                Some(&denied),
            ),
            None,
            "denied var must not trigger fail-closed"
        );
        // A different API-key var that is NOT in the deny list should still block.
        assert!(
            detect_api_key_env_var_from(
                fake_env(&[
                    ("ANTHROPIC_API_KEY", "sk-ant-api03-real"),
                    ("ANTHROPIC_UNIX_SOCKET", "/tmp/socket"),
                ]),
                Some(&denied),
            )
            .is_some(),
            "non-denied API-key var must still trigger fail-closed"
        );
    }

    #[test]
    fn detect_api_key_env_var_respects_glob_patterns_in_deny_list() {
        // Profile deny lists can use glob-like patterns (e.g. GITHUB_*).
        // Verify the check delegates to `is_env_var_denied` correctly.
        let denied = vec!["ANTHROPIC_*".to_string()];
        assert_eq!(
            detect_api_key_env_var_from(
                fake_env(&[("ANTHROPIC_API_KEY", "sk-ant-api03-real")]),
                Some(&denied),
            ),
            None,
            "glob-matched denied var must not trigger fail-closed"
        );
    }

    #[test]
    fn detect_primary_api_key_in_file_flags_non_empty_value() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".claude.json");

        std::fs::write(&path, r#"{"primaryApiKey":"sk-ant-api03-xxx"}"#).unwrap();
        assert!(
            detect_primary_api_key_in_file(&path)
                .unwrap()
                .unwrap()
                .contains("primaryApiKey")
        );

        std::fs::write(&path, r#"{"primaryApiKey":""}"#).unwrap();
        assert!(detect_primary_api_key_in_file(&path).unwrap().is_none());

        std::fs::write(&path, r#"{}"#).unwrap();
        assert!(detect_primary_api_key_in_file(&path).unwrap().is_none());

        std::fs::remove_file(&path).unwrap();
        assert!(
            detect_primary_api_key_in_file(&path).unwrap().is_none(),
            "missing file must not be an error"
        );
    }

    // --- apikey_gateway preflight tests ---

    use crate::mediation::{CommandEntry, InterceptRule};
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    fn example_capture_rule() -> CommandEntry {
        CommandEntry {
            name: "auth-helper".to_string(),
            binary_path: None,
            intercept: vec![InterceptRule {
                args_prefix: vec![
                    "auth".to_string(),
                    "token".to_string(),
                    "example-scope".to_string(),
                ],
                admin: false,
                action: InterceptAction::Capture {
                    script: None,
                    format: None,
                    secret_paths: Vec::new(),
                },
            }],
            sandbox: None,
            caller_policy: Default::default(),
        }
    }

    #[test]
    fn shell_split_plain_args() {
        assert_eq!(
            shell_split("auth-helper auth token example-scope --datacenter region-a"),
            Some(vec![
                "auth-helper".to_string(),
                "auth".to_string(),
                "token".to_string(),
                "example-scope".to_string(),
                "--datacenter".to_string(),
                "region-a".to_string(),
            ])
        );
    }

    #[test]
    fn shell_split_handles_quotes() {
        assert_eq!(
            shell_split(r#"helper --flag "value with spaces" 'single quoted'"#),
            Some(vec![
                "helper".to_string(),
                "--flag".to_string(),
                "value with spaces".to_string(),
                "single quoted".to_string(),
            ])
        );
    }

    #[test]
    fn shell_split_rejects_unbalanced_quotes() {
        assert_eq!(shell_split(r#"helper "unterminated"#), None);
    }

    #[test]
    fn is_args_prefix_match_basic() {
        let prefix = vec!["auth".to_string(), "token".to_string()];
        let args = vec!["auth", "token", "example-scope"];
        assert!(is_args_prefix_match(&prefix, &args));

        let mismatched = vec!["auth", "OTHER"];
        assert!(!is_args_prefix_match(&prefix, &mismatched));

        let too_short = vec!["auth"];
        assert!(!is_args_prefix_match(&prefix, &too_short));
    }

    #[test]
    fn apikey_gateway_preflight_passes_with_matching_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_dir = tmp.path().to_path_buf();
        std::fs::write(
            cfg_dir.join("settings.json"),
            r#"{"apiKeyHelper":"auth-helper auth token example-scope --datacenter region-a"}"#,
        )
        .unwrap();
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvVarGuard::set_all(&[(
            "CLAUDE_CONFIG_DIR",
            cfg_dir.to_str().expect("tempdir path is UTF-8"),
        )]);

        let gateway = ApiKeyGatewayConfig {
            url: "https://gateway.example.com".to_string(),
            helper_argv_prefix: vec![
                "auth".to_string(),
                "token".to_string(),
                "example-scope".to_string(),
            ],
        };
        let mediation = MediationConfig {
            commands: vec![example_capture_rule()],
            env: Default::default(),
        };

        let res = run_apikey_gateway_preflight(&gateway, &mediation);
        assert!(res.is_ok(), "preflight should pass: {:?}", res.err());
    }

    #[test]
    fn apikey_gateway_preflight_fails_without_mediation_rule() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_dir = tmp.path().to_path_buf();
        std::fs::write(
            cfg_dir.join("settings.json"),
            r#"{"apiKeyHelper":"auth-helper auth token example-scope"}"#,
        )
        .unwrap();
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvVarGuard::set_all(&[(
            "CLAUDE_CONFIG_DIR",
            cfg_dir.to_str().expect("tempdir path is UTF-8"),
        )]);

        let gateway = ApiKeyGatewayConfig {
            url: "https://gateway.example.com".to_string(),
            helper_argv_prefix: vec![
                "auth".to_string(),
                "token".to_string(),
                "example-scope".to_string(),
            ],
        };
        let empty = MediationConfig::default();

        let err = run_apikey_gateway_preflight(&gateway, &empty)
            .expect_err("should fail without covering mediation rule");
        assert!(
            err.to_string().contains("no `mediation.commands` rule"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn apikey_gateway_preflight_fails_on_argv_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg_dir = tmp.path().to_path_buf();
        std::fs::write(
            cfg_dir.join("settings.json"),
            r#"{"apiKeyHelper":"auth-helper auth token SOMETHING_ELSE"}"#,
        )
        .unwrap();
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvVarGuard::set_all(&[(
            "CLAUDE_CONFIG_DIR",
            cfg_dir.to_str().expect("tempdir path is UTF-8"),
        )]);

        let gateway = ApiKeyGatewayConfig {
            url: "https://gateway.example.com".to_string(),
            helper_argv_prefix: vec![
                "auth".to_string(),
                "token".to_string(),
                "example-scope".to_string(),
            ],
        };
        let mediation = MediationConfig {
            commands: vec![example_capture_rule()],
            env: Default::default(),
        };

        let err = run_apikey_gateway_preflight(&gateway, &mediation)
            .expect_err("should fail on argv mismatch");
        assert!(
            err.to_string().contains("does NOT match"),
            "unexpected error: {err}"
        );
    }
}
