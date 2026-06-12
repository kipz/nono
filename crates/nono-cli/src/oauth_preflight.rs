//! Per-route preflight checks driven by `credential_routes[].preflight`.
//! macOS only for the keychain surface scan; the helper-coverage check
//! is cross-platform.
//!
//! Protection of the macOS `Claude Code-credentials` keychain entry is
//! handled by the mediation shim's `capture` action with `format: "json"`
//! (see `docs/plans/2026-06-03-mediation-based-oauth-capture.md`). This
//! module does not rewrite the keychain; profile authors configure the
//! substitution declaratively. Preflight only checks fail-closed
//! conditions — namely the presence of a credential surface the
//! broker-backed proxy path cannot translate, or a configured
//! `apiKeyHelper` whose argv is not covered by a `capture` mediation
//! rule.
//!
//! ### `NoStaticApiKeySurfaces`
//!
//! Surfaces that carry an API key are fatal because the proxy's
//! TLS-intercept translates `Authorization: Bearer nono_<hex>` but not
//! `x-api-key: nono_<hex>` — the child would 401 on every request. When
//! any API-key surface is detected preflight fails with a clear message:
//!
//! - environment: `ANTHROPIC_API_KEY`, `CLAUDE_CODE_API_KEY_FILE_DESCRIPTOR`
//!   (skipped if the profile's `denied_env_vars` would strip them anyway)
//! - macOS keychain entry `Claude Code` (no `-credentials` suffix)
//! - `primaryApiKey` field in `~/.claude.json`
//!
//! ### `ClaudeCodeApiKeyHelperConfigured`
//!
//! For a `mediated_helper` capture, Claude Code is expected to fetch
//! its bearer via the `apiKeyHelper` command declared in
//! `~/.claude/settings.json`. The mediation shim captures that helper's
//! stdout into the broker and returns a `nono_<hex>` nonce to the
//! sandbox. Without a matching `capture` mediation rule, the real
//! bearer flows into the sandbox uncaptured — defeating the route's
//! design. Preflight refuses to launch unless a covering rule is found.

use crate::exec_strategy::is_env_var_denied;
use crate::mediation::broker::TokenBroker;
use crate::mediation::{CaptureFormat, InterceptAction, MediationConfig};
use crate::profile::{CredentialRouteCapture, CredentialRoutePreflight, ManagedCredentialRoute};
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

/// Run preflight checks declared on each credential route.
///
/// Iterates `routes`, gathering the union of declared
/// [`CredentialRoutePreflight`] checks. Each unique check runs once
/// (de-duped so two routes both declaring `NoStaticApiKeySurfaces`
/// don't run the host-scan twice).
///
/// Preflight is a Claude-Code-specific feature today —
/// `program_is_claude` is the gate. For other agents the credential
/// routes still drive proxy/broker behaviour, but route-declared
/// preflights are skipped.
///
/// `denied_env_vars` is the profile's env-var deny list. API-key vars
/// the profile would strip before the child sees them are excluded
/// from the API-key surface check.
pub(crate) fn run_credential_routes_preflight(
    _broker: &TokenBroker,
    program: &OsStr,
    denied_env_vars: Option<&[String]>,
    routes: &[ManagedCredentialRoute],
    mediation: &MediationConfig,
) -> Result<PreflightOutcome> {
    if !program_is_claude(program) {
        debug!("credential_routes: target program is not claude; skipping preflight");
        return Ok(PreflightOutcome);
    }

    let mut ran_no_static = false;
    let mut ran_helper_check = false;

    for route in routes {
        for check in &route.preflight {
            match check {
                CredentialRoutePreflight::NoStaticApiKeySurfaces => {
                    if ran_no_static {
                        continue;
                    }
                    ran_no_static = true;
                    // Effective deny list = `environment.deny_vars`
                    // (passed in as `denied_env_vars`) UNION
                    // `mediation.env.block`. Both strip vars before the
                    // child sees them, so either-or coverage of an
                    // API-key env var means it's safe to launch.
                    let mut effective_deny: Vec<String> =
                        denied_env_vars.map(|v| v.to_vec()).unwrap_or_default();
                    effective_deny.extend(mediation.env.block.iter().cloned());
                    let effective_deny_slice = if effective_deny.is_empty() {
                        None
                    } else {
                        Some(effective_deny.as_slice())
                    };
                    if let Some(reason) = detect_blocking_api_key_surface(effective_deny_slice)? {
                        return Err(NonoError::SandboxInit(format!(
                            "credential_routes preflight: an API-key credential is already configured on the host: {reason}. \
                             Broker-backed routes translate `Authorization: Bearer` / `x-api-key` headers carrying \
                             `nono_<hex>` nonces; a static API key would short-circuit Claude Code's auth resolution \
                             before the broker path runs. Either clear the API key (unset the env var, delete the \
                             keychain entry, or remove `primaryApiKey` from ~/.claude.json) and re-run, or remove the \
                             credential route from your profile to use API-key auth as-is."
                        )));
                    }
                }
                CredentialRoutePreflight::ClaudeCodeApiKeyHelperConfigured => {
                    if ran_helper_check {
                        continue;
                    }
                    ran_helper_check = true;
                    run_mediated_helper_preflight(route, mediation)?;
                }
            }
        }
    }

    Ok(PreflightOutcome)
}

/// Verify that the host's Claude Code `apiKeyHelper` is covered by a
/// mediation `capture` rule that matches the credential route's
/// `MediatedHelper` capture configuration.
///
/// Reads `~/.claude/settings.json` (and `CLAUDE_CONFIG_DIR` overrides if
/// set). If `apiKeyHelper` is declared, shell-split its value and
/// compare the resulting argv against the route's `args_prefix`.
/// Then verify the resolved `MediationConfig` has a `Capture` rule
/// covering the helper. Without a covering rule the real bearer would
/// flow into the sandbox uncaptured.
fn run_mediated_helper_preflight(
    route: &ManagedCredentialRoute,
    mediation: &MediationConfig,
) -> Result<()> {
    let (expected_command, expected_args_prefix) = match &route.capture {
        CredentialRouteCapture::MediatedHelper {
            command,
            args_prefix,
        } => (command.clone(), args_prefix.clone()),
        CredentialRouteCapture::OauthIntercept { .. }
        | CredentialRouteCapture::ProxyProvisionedCredential { .. } => {
            // ClaudeCodeApiKeyHelperConfigured doesn't apply to either
            // OAuth-intercept or proxy-provisioned routes. For OAuth,
            // there's no helper command involved. For
            // proxy-provisioned, the proxy itself runs the source
            // command — claude's apiKeyHelper, if any, is shadowed by
            // an auto-injected `respond` mediation rule, so even when
            // settings.json declares a helper it's not actually doing
            // the credential fetch. Skip silently.
            return Ok(());
        }
    };
    let (config_dir, _explicit) = claude_config_dir_pair()
        .map_err(|msg| NonoError::SandboxInit(format!("mediated_helper preflight: {msg}")))?;
    let settings_path = config_dir.join("settings.json");
    let helper = match read_apikey_helper(&settings_path)? {
        Some(value) => value,
        None => {
            // No apiKeyHelper declared on the host. The route's
            // delivery still translates bearers the sandboxed agent
            // already possesses (e.g. from a separate capture), but
            // the common case is that the user does declare a
            // helper. Warn loudly rather than fail.
            tracing::warn!(
                "credential route '{}' declares a MediatedHelper capture but no `apiKeyHelper` \
                 is declared in {}. The route will only translate bearers the sandboxed agent \
                 already possesses (e.g. via a separate mediation capture). If you intend the \
                 helper to mint bearers, add it to settings.json.",
                route.name,
                settings_path.display()
            );
            return Ok(());
        }
    };
    let helper_argv = shell_split(&helper).ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "mediated_helper preflight: could not parse apiKeyHelper '{helper}' as a shell command \
             (quote/escape sequences may be malformed). Refusing to start because the helper-coverage \
             check cannot run."
        ))
    })?;
    if helper_argv.is_empty() {
        return Err(NonoError::SandboxInit(format!(
            "mediated_helper preflight: apiKeyHelper '{helper}' parses to an empty argv. \
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

    // Validate the host's helper binary matches the route's
    // `command`. An empty `command` skips this check and trusts
    // whatever binary the host has — kept for callers that want to
    // defer binary identity to settings.json rather than declaring it
    // up front.
    if !expected_command.is_empty() && helper_bin != expected_command {
        return Err(NonoError::SandboxInit(format!(
            "mediated_helper preflight: route '{}' expects helper binary '{}' but the host's \
             apiKeyHelper resolves to '{}'. Either fix the profile or update settings.json so the \
             two agree.",
            route.name, expected_command, helper_bin
        )));
    }

    if expected_args_prefix.is_empty() {
        return Err(NonoError::SandboxInit(format!(
            "mediated_helper preflight: apiKeyHelper '{helper}' is declared in settings.json \
             but credential route '{}' has an empty args_prefix. Declare the expected \
             positional-args prefix so the coverage check can run, e.g. [\"auth\", \"token\", \
             \"example-scope\"].",
            route.name
        )));
    }
    // The configured args_prefix must be a prefix of the helper's
    // positional args. Treating it as a strict prefix rather than
    // substring guards against an `apiKeyHelper` that quietly changes
    // binary or subcommand without the profile being updated.
    let matches = helper_positionals.len() >= expected_args_prefix.len()
        && helper_positionals
            .iter()
            .zip(expected_args_prefix.iter())
            .all(|(actual, expected)| *actual == expected.as_str());
    if !matches {
        return Err(NonoError::SandboxInit(format!(
            "mediated_helper preflight: apiKeyHelper '{helper}' (positional args {helper_positionals:?}) \
             does NOT match the route's args_prefix {:?}. Either fix the profile's args_prefix \
             to match the deployed helper, or update settings.json so the helper invocation \
             aligns with the profile.",
            expected_args_prefix
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
                    InterceptAction::Capture { format: None, .. }
                        | InterceptAction::Capture {
                            format: Some(CaptureFormat::Json),
                            ..
                        }
                ) && is_args_prefix_match(&rule.args_prefix, &helper_positionals)
            })
    });
    if covering_rule.is_none() {
        return Err(NonoError::SandboxInit(format!(
            "mediated_helper preflight: no `mediation.commands` rule covers the host's apiKeyHelper. \
             Helper binary '{helper_bin}', positional args {helper_positionals:?}. \
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
            expected_args_prefix
        )));
    }

    info!(
        "mediated_helper preflight: route '{}' helper '{}' positional argv {:?} matches \
         args_prefix {:?} and is covered by mediation rule",
        route.name, helper_bin, helper_positionals, expected_args_prefix
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
                    "mediated_helper preflight: could not parse {}: {err}",
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
            "mediated_helper preflight: could not read {}: {err}",
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
            "credential_routes preflight: could not read {}: {err}",
            global_config.display()
        ))),
    }
}

fn global_config_has_primary_api_key(raw: &str) -> Result<bool> {
    let parsed: Value = serde_json::from_str(raw).map_err(|err| {
        NonoError::SandboxInit(format!(
            "credential_routes preflight: could not parse ~/.claude.json: {err}"
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
                "credential_routes preflight: {err}"
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
    fn run_credential_routes_preflight_no_op_when_target_is_not_claude() {
        // Even with a real-token-bearing env var, pre-flight skips when
        // the program isn't claude. (Other binaries don't read these.)
        let broker = TokenBroker::new();
        let mediation = MediationConfig::default();
        let routes = vec![ManagedCredentialRoute {
            name: "test".to_string(),
            upstream: "https://example.com".to_string(),
            capture: CredentialRouteCapture::OauthIntercept {
                token_url_match: "/x".to_string(),
                refresh_url_match: "/x".to_string(),
            },
            delivery: crate::profile::CredentialRouteDelivery::Direct,
            bearer: crate::profile::CredentialRouteBearer {
                header: "authorization".to_string(),
                format: "Bearer {}".to_string(),
            },
            egress_headers: Default::default(),
            preflight: vec![CredentialRoutePreflight::NoStaticApiKeySurfaces],
        }];
        run_credential_routes_preflight(
            &broker,
            OsStr::new("/usr/bin/codex"),
            None,
            &routes,
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

    // --- mediated_helper preflight tests ---

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

    fn helper_route(args_prefix: Vec<String>) -> ManagedCredentialRoute {
        ManagedCredentialRoute {
            name: "test_helper".to_string(),
            upstream: "https://gateway.example.com".to_string(),
            capture: CredentialRouteCapture::MediatedHelper {
                command: "auth-helper".to_string(),
                args_prefix,
            },
            delivery: crate::profile::CredentialRouteDelivery::Direct,
            bearer: crate::profile::CredentialRouteBearer {
                header: "x-api-key".to_string(),
                format: "{}".to_string(),
            },
            egress_headers: Default::default(),
            preflight: vec![CredentialRoutePreflight::ClaudeCodeApiKeyHelperConfigured],
        }
    }

    #[test]
    fn mediated_helper_preflight_passes_with_matching_rule() {
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

        let route = helper_route(vec![
            "auth".to_string(),
            "token".to_string(),
            "example-scope".to_string(),
        ]);
        let mediation = MediationConfig {
            commands: vec![example_capture_rule()],
            env: Default::default(),
        };

        let res = run_mediated_helper_preflight(&route, &mediation);
        assert!(res.is_ok(), "preflight should pass: {:?}", res.err());
    }

    #[test]
    fn mediated_helper_preflight_fails_without_mediation_rule() {
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

        let route = helper_route(vec![
            "auth".to_string(),
            "token".to_string(),
            "example-scope".to_string(),
        ]);
        let empty = MediationConfig::default();

        let err = run_mediated_helper_preflight(&route, &empty)
            .expect_err("should fail without covering mediation rule");
        assert!(
            err.to_string().contains("no `mediation.commands` rule"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mediated_helper_preflight_fails_on_argv_mismatch() {
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

        let route = helper_route(vec![
            "auth".to_string(),
            "token".to_string(),
            "example-scope".to_string(),
        ]);
        let mediation = MediationConfig {
            commands: vec![example_capture_rule()],
            env: Default::default(),
        };

        let err = run_mediated_helper_preflight(&route, &mediation)
            .expect_err("should fail on argv mismatch");
        assert!(
            err.to_string().contains("does NOT match"),
            "unexpected error: {err}"
        );
    }
}
