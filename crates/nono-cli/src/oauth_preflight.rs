//! Pre-flight checks for `oauth_capture: true`.
//!
//! ### macOS
//!
//! Protection of the macOS `Claude Code-credentials` keychain entry is
//! handled by the mediation shim's `capture` action with `format: "json"`
//! (see `docs/plans/2026-06-03-mediation-based-oauth-capture.md`). This
//! module no longer rewrites the keychain; profile authors configure
//! the substitution declaratively. Pre-flight on macOS only checks
//! for fail-closed conditions — namely the presence of an API-key
//! surface that the OAuth-capture path cannot translate.
//!
//! ### Linux
//!
//! `~/.claude/.credentials.json` is the only credential store on Linux
//! (no keychain). The file is rewritten in place to hold nonces. This
//! path is unchanged from the original PR-40 design.
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

use crate::exec_strategy::is_env_var_denied;
use crate::mediation::broker::TokenBroker;
use nono::{NonoError, Result};
use serde_json::Value;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use tracing::debug;
#[cfg(any(test, not(target_os = "macos")))]
use tracing::info;
#[cfg(any(test, not(target_os = "macos")))]
use zeroize::Zeroizing;

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

/// Run the pre-flight rewrite if the target program is `claude` and
/// OAuth capture is active. For any other program this is a quiet
/// no-op — pre-flight is a Claude-Code-specific feature.
///
/// `denied_env_vars` is the profile's env-var deny list. Any API-key
/// env var the profile would strip before the child sees it is excluded
/// from the fail-closed check.
pub(crate) fn run_oauth_preflight(
    broker: &TokenBroker,
    program: &OsStr,
    silent: bool,
    denied_env_vars: Option<&[String]>,
) -> Result<PreflightOutcome> {
    if !program_is_claude(program) {
        debug!("oauth_capture: target program is not claude; skipping pre-flight");
        return Ok(PreflightOutcome);
    }

    if let Some(reason) = detect_blocking_api_key_surface(denied_env_vars)? {
        return Err(NonoError::SandboxInit(format!(
            "oauth_capture is enabled but an API-key credential is already configured: {reason}. \
             The OAuth-capture path proxies Authorization: Bearer tokens; \
             x-api-key requests inside the CONNECT tunnel would fail authentication. \
             Either clear the API key (unset the env var, delete the keychain entry, \
             or remove `primaryApiKey` from ~/.claude.json) and re-run, or remove \
             `oauth_capture: true` from your profile to use API-key auth as-is."
        )));
    }

    // macOS: keychain protection is delivered by the mediation shim's
    // `capture` action; no preflight write happens here.
    // Linux: rewrite .credentials.json so plugins reading the file see
    // nonces. Env vars are handled by the profile's denied_env_vars at
    // exec time.
    rewrite_credentials_file(broker, silent)?;

    Ok(PreflightOutcome)
}

fn program_is_claude(program: &OsStr) -> bool {
    Path::new(program)
        .file_name()
        .and_then(OsStr::to_str)
        .map(|name| name == "claude")
        .unwrap_or(false)
}

#[cfg(any(test, not(target_os = "macos")))]
fn log_capture(silent: bool, surface: &str) {
    info!("oauth_capture pre-flight: captured existing credential from {surface}");
    if !silent {
        eprintln!("  [nono] OAuth capture: replaced real token in {surface} with nono_ nonce");
    }
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

/// Rewrite `~/.claude/.credentials.json` on Linux (the only credential
/// store on that platform). On macOS `load_claude_oauth_state()` reads
/// the keychain first and never reaches the file once the keychain holds
/// nonces, so sweeping it would be redundant.
#[cfg(not(target_os = "macos"))]
fn rewrite_credentials_file(broker: &TokenBroker, silent: bool) -> Result<()> {
    let config_dir = match claude_config_dir_cross_platform() {
        Some(dir) => dir,
        None => return Ok(()),
    };
    rewrite_credentials_file_at(&config_dir, broker, silent)
}

#[cfg(target_os = "macos")]
fn rewrite_credentials_file(_broker: &TokenBroker, _silent: bool) -> Result<()> {
    Ok(())
}

/// Test-friendly variant: rewrite `<config_dir>/.credentials.json`. The
/// production code path resolves `config_dir` from `CLAUDE_CONFIG_DIR`
/// or `~/.claude`; tests inject a path directly so they don't have to
/// mutate process-global env vars (which race under cargo's parallel
/// test runner).
#[cfg(any(test, not(target_os = "macos")))]
fn rewrite_credentials_file_at(
    config_dir: &Path,
    broker: &TokenBroker,
    silent: bool,
) -> Result<()> {
    let path = config_dir.join(".credentials.json");
    let raw = match std::fs::read_to_string(&path) {
        Ok(r) => r,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(NonoError::SandboxInit(format!(
                "oauth_capture pre-flight: could not read {}: {err}",
                path.display()
            )));
        }
    };

    let mut parsed: Value = serde_json::from_str(&raw).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: {} is not valid JSON: {err}",
            path.display()
        ))
    })?;

    let oauth = match parsed
        .as_object_mut()
        .and_then(|obj| obj.get_mut("claudeAiOauth"))
        .and_then(Value::as_object_mut)
    {
        Some(obj) => obj,
        None => return Ok(()),
    };

    let access = oauth
        .get("accessToken")
        .and_then(Value::as_str)
        .map(str::to_string);
    let refresh = oauth
        .get("refreshToken")
        .and_then(Value::as_str)
        .map(str::to_string);

    if access.as_deref().is_none_or(str::is_empty)
        || access.as_deref().is_some_and(|v| v.starts_with("nono_"))
    {
        return Ok(());
    }

    let access_token = access.ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: {} has no accessToken to capture",
            path.display()
        ))
    })?;

    let (access_nonce, refresh_nonce) = match refresh.as_deref() {
        Some(real_refresh) if !real_refresh.is_empty() && !real_refresh.starts_with("nono_") => {
            // Two independent `issue` calls — same behaviour the broker's
            // former `capture_oauth_pair` had now that durable persistence
            // is gone.
            let access_nonce = broker.issue(Zeroizing::new(access_token));
            let refresh_nonce = broker.issue(Zeroizing::new(real_refresh.to_string()));
            (access_nonce, refresh_nonce)
        }
        _ => {
            let access_nonce = broker.issue(Zeroizing::new(access_token));
            let refresh_nonce = refresh.unwrap_or_default();
            (access_nonce, refresh_nonce)
        }
    };

    oauth.insert(
        "accessToken".to_string(),
        Value::String(access_nonce.clone()),
    );
    if !refresh_nonce.is_empty() {
        oauth.insert("refreshToken".to_string(), Value::String(refresh_nonce));
    }

    let rewritten = serde_json::to_string(&parsed).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not re-serialise {}: {err}",
            path.display()
        ))
    })?;

    atomic_write(&path, &rewritten)?;
    log_capture(silent, &format!("file {}", path.display()));
    Ok(())
}

/// Atomic file replace preserving owner-only permissions on Unix. Writes
/// to a sibling `.tmp` file, fsyncs, then renames into place.
#[cfg(any(test, not(target_os = "macos")))]
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: {} has no parent directory",
            path.display()
        ))
    })?;
    let tmp = parent.join(format!(".credentials.json.nono-{}", std::process::id()));

    let mut open_opts = std::fs::OpenOptions::new();
    open_opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_opts.mode(0o600);
    }

    let mut file = open_opts.open(&tmp).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: could not open {} for write: {err}",
            tmp.display()
        ))
    })?;
    file.write_all(content.as_bytes()).map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: write to {} failed: {err}",
            tmp.display()
        ))
    })?;
    file.sync_all().map_err(|err| {
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: fsync {} failed: {err}",
            tmp.display()
        ))
    })?;
    drop(file);

    std::fs::rename(&tmp, path).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        NonoError::SandboxInit(format!(
            "oauth_capture pre-flight: rename {} -> {} failed: {err}",
            tmp.display(),
            path.display()
        ))
    })?;
    Ok(())
}

/// Resolve the Claude config directory the same way `claude` itself does.
/// Returns `None` if `HOME` is unset (very rare, like an empty CI env).
#[cfg(not(target_os = "macos"))]
fn claude_config_dir_cross_platform() -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Some(PathBuf::from(value));
    }
    dirs::home_dir().map(|h| h.join(".claude"))
}

// --- macOS keychain helpers (duplicated thin wrappers around the same
//     ones in `sandbox_prepare`; kept private here so this module stays
//     self-contained and re-usable in tests without dragging the full
//     `SandboxArgs` machinery into the test fixtures). ---

#[cfg(target_os = "macos")]
fn claude_config_dir() -> std::result::Result<(PathBuf, bool), String> {
    if let Some(value) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Ok((PathBuf::from(value), true));
    }
    let home = dirs::home_dir().ok_or_else(|| "no HOME set".to_string())?;
    Ok((home.join(".claude"), false))
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
        run_oauth_preflight(&broker, OsStr::new("/usr/bin/codex"), true, None).unwrap();
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

    fn write_credentials_at(config_dir: &Path, contents: &str) -> PathBuf {
        std::fs::create_dir_all(config_dir).unwrap();
        let path = config_dir.join(".credentials.json");
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn rewrite_credentials_file_replaces_real_pair_with_nonces() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let path = write_credentials_at(
            &config_dir,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-real-access","refreshToken":"sk-ant-ort01-real-refresh","subscriptionType":"max"}}"#,
        );

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let rewritten = std::fs::read_to_string(&path).unwrap();
        let parsed: Value = serde_json::from_str(&rewritten).unwrap();
        let oauth = parsed.get("claudeAiOauth").unwrap();
        let new_access = oauth.get("accessToken").unwrap().as_str().unwrap();
        let new_refresh = oauth.get("refreshToken").unwrap().as_str().unwrap();
        assert!(
            new_access.starts_with("nono_"),
            "access not nonced: {new_access}"
        );
        assert!(
            new_refresh.starts_with("nono_"),
            "refresh not nonced: {new_refresh}"
        );
        assert_ne!(new_access, new_refresh);
        assert_eq!(
            oauth.get("subscriptionType").unwrap().as_str().unwrap(),
            "max",
            "non-oauth fields must be preserved across rewrite"
        );

        assert_eq!(
            broker.resolve(new_access).unwrap().as_str(),
            "sk-ant-oat01-real-access"
        );
        assert_eq!(
            broker.resolve(new_refresh).unwrap().as_str(),
            "sk-ant-ort01-real-refresh"
        );
    }

    #[test]
    fn rewrite_credentials_file_is_idempotent_when_nonces_already_present() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let original = r#"{"claudeAiOauth":{"accessToken":"nono_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","refreshToken":"nono_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#;
        let path = write_credentials_at(&config_dir, original);

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, original, "nonce-bearing file must be left untouched");
    }

    #[test]
    fn rewrite_credentials_file_handles_missing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&config_dir).unwrap();

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();
    }

    #[test]
    fn rewrite_credentials_file_returns_err_on_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        write_credentials_at(&config_dir, "not json at all");

        let broker = TokenBroker::new();
        let err = rewrite_credentials_file_at(&config_dir, &broker, true).unwrap_err();
        assert!(err.to_string().contains("not valid JSON"), "got: {err}");
    }

    #[test]
    #[allow(non_snake_case)]
    fn rewrite_credentials_file_no_claudeAiOauth_object_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let original = r#"{"otherField":"value"}"#;
        let path = write_credentials_at(&config_dir, original);

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, original);
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

    #[test]
    fn rewrite_credentials_file_only_access_token_uses_issue_not_capture_pair() {
        // If the file only has accessToken (no refresh), we still mint a
        // nonce for the access token via `issue` and leave the refresh
        // slot untouched (or empty). `capture_oauth_pair` wouldn't be a
        // good fit because it always persists a pair to the broker store;
        // single-token surfaces just get a session-scoped resolve.
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join(".claude");
        let path = write_credentials_at(
            &config_dir,
            r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-only"}}"#,
        );

        let broker = TokenBroker::new();
        rewrite_credentials_file_at(&config_dir, &broker, true).unwrap();

        let after: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let oauth = after.get("claudeAiOauth").unwrap();
        let new_access = oauth.get("accessToken").unwrap().as_str().unwrap();
        assert!(new_access.starts_with("nono_"));
        assert_eq!(
            broker.resolve(new_access).unwrap().as_str(),
            "sk-ant-oat01-only"
        );
        assert!(
            oauth.get("refreshToken").is_none(),
            "must not invent a refresh slot we didn't have"
        );
    }
}
