//! Policy engine for the mediation server.
//!
//! For each incoming `ShimRequest`, this module:
//! 1. Finds the matching `ResolvedCommand` entry.
//! 2. Checks `intercept` rules in order (positional subcommand match).
//! 3. If matched with `Respond`: returns the configured `ShimResponse` without calling the binary.
//! 4. If matched with `Capture`: runs the real binary (or a script), stores output in the broker,
//!    returns a `nono_<hex>` nonce to the sandbox.
//! 5. If not matched: execs the real binary. Nonce-bearing env vars from the sandbox are promoted
//!    (replaced with real values); all other sandbox env vars are discarded.

use super::approval::ApprovalGate;
use super::broker::TokenBroker;
use super::session::{ResolvedAction, ResolvedCommand};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Request forwarded from the shim binary to the mediation server.
#[derive(Debug, Deserialize)]
pub struct ShimRequest {
    pub command: String,
    pub args: Vec<String>,
    pub stdin: String,
    /// Session authentication token. Must match the token injected via
    /// `NONO_SESSION_TOKEN`. Requests with a missing or wrong token are
    /// silently rejected. Old shims missing this field fail deserialization
    /// and receive a 127 error — the correct security behaviour.
    pub session_token: String,
    /// Environment variables from the sandbox at invocation time.
    /// Used only for nonce promotion — all non-nonce vars are discarded.
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Response the mediation server sends back to the shim binary.
#[derive(Debug, Serialize)]
pub struct ShimResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Env var names that must never receive a nonce-promoted value, even if a
/// nonce-bearing var with this name appears in the sandbox env.
static DANGEROUS_ENV_VAR_NAMES: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FORCE_FLAT_NAMESPACE",
];

/// Apply policy to a shim request and produce a response.
///
/// - If the command is unknown: returns an error response (not found).
/// - If an intercept rule matches with `admin: true`: invokes the approval gate.
///   If denied, returns exit 126 immediately without executing the action.
/// - If an intercept rule matches with `Respond`: returns the pre-resolved output.
/// - If an intercept rule matches with `Capture`: runs the binary/script, issues a nonce.
/// - Otherwise: execs the real binary with strict env filtering.
pub async fn apply(
    request: ShimRequest,
    commands: &[ResolvedCommand],
    broker: Arc<TokenBroker>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
) -> ShimResponse {
    // Find matching command entry
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("mediation: unknown command '{}'", request.command);
        return ShimResponse {
            stdout: String::new(),
            stderr: format!(
                "nono-mediation: command '{}' not configured\n",
                request.command
            ),
            exit_code: 127,
        };
    };

    // Check intercept rules in order
    for rule in &cmd.intercepts {
        if subcommand_matches(&rule.args_prefix, &request.args) {
            debug!(
                "mediation: intercepting '{}' with prefix {:?}",
                request.command, rule.args_prefix
            );

            // Admin gate: require user authentication before executing the action.
            if rule.admin {
                let command = request.command.clone();
                let args = request.args.clone();
                let approval_clone = Arc::clone(&approval);
                let allowed =
                    tokio::task::spawn_blocking(move || approval_clone.approve(&command, &args))
                        .await
                        .unwrap_or(false);
                if !allowed {
                    let invocation = if request.args.is_empty() {
                        request.command.clone()
                    } else {
                        format!("{} {}", request.command, request.args.join(" "))
                    };
                    return ShimResponse {
                        stdout: String::new(),
                        stderr: format!("nono: '{}' was not approved\n", invocation),
                        exit_code: 126,
                    };
                }
            }

            return match &rule.action {
                ResolvedAction::Respond { stdout } => ShimResponse {
                    stdout: stdout.clone(),
                    stderr: String::new(),
                    exit_code: rule.exit_code,
                },
                ResolvedAction::Capture { script } => {
                    let result = match script {
                        Some(sh) => exec_script(sh, &request.env, &broker).await,
                        None => {
                            // No per-command sandbox during capture — the real binary needs
                            // full access to system resources (e.g. Keychain) to fetch the credential.
                            exec_passthrough(
                                cmd,
                                &request.args,
                                &request.stdin,
                                &request.env,
                                &broker,
                                None,
                            )
                            .await
                        }
                    };
                    if result.exit_code != 0 {
                        return result;
                    }
                    let nonce = broker.issue(Zeroizing::new(result.stdout.trim().to_string()));
                    ShimResponse {
                        stdout: format!("{}\n", nonce),
                        stderr: String::new(),
                        exit_code: 0,
                    }
                }
            };
        }
    }

    // No intercept matched — pass through to the real binary
    debug!(
        "mediation: passthrough '{}' {:?} -> {}",
        request.command,
        request.args,
        cmd.real_path.display()
    );
    exec_passthrough(
        cmd,
        &request.args,
        &request.stdin,
        &request.env,
        &broker,
        cmd.sandbox.clone(),
    )
    .await
}

/// Check if the invocation's positional args start with the given prefix.
///
/// Flags (args starting with `-`) are ignored, allowing matches regardless of
/// flag placement. E.g. `["auth", "github", "token"]` matches both
/// `ddtool auth github token` and `ddtool --debug auth github token`.
pub fn subcommand_matches(prefix: &[String], args: &[String]) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if prefix.len() > positional.len() {
        return false;
    }
    prefix.iter().zip(positional.iter()).all(|(p, a)| p == *a)
}

/// Execute a shell script and collect its output.
///
/// Uses the same strict env-building as `exec_passthrough`: starts from the
/// trusted parent env, promotes nonce-bearing sandbox vars, blocks dangerous names.
async fn exec_script(
    script: &str,
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
) -> ShimResponse {
    let env = build_exec_env(sandbox_env, broker);
    let script = script.to_string();

    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::process::{Command, Stdio};

        let child = Command::new("sh")
            .args(["-c", &script])
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(NonoError::CommandExecution)?;

        let output = child
            .wait_with_output()
            .map_err(NonoError::CommandExecution)?;
        Ok(ShimResponse {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(1),
        })
    })
    .await;

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: script exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    }
}

/// Execute the real binary and collect its output.
///
/// Env building:
/// - Starts from the trusted parent (mediation server) environment.
/// - From the sandbox env, promotes only nonce-bearing vars (`nono_` prefix).
///   All other sandbox env vars are discarded to prevent sandbox injection.
/// - Dangerous var names (PATH, LD_PRELOAD, etc.) are blocked even with valid nonces.
/// - Arg nonces: any arg starting with `nono_` is replaced with the real value.
async fn exec_passthrough(
    cmd: &ResolvedCommand,
    args: &[String],
    stdin_data: &str,
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
    sandbox: Option<super::CommandSandbox>,
) -> ShimResponse {
    let env = build_exec_env(sandbox_env, broker);

    // Promote nonce values in args
    let args: Vec<String> = args
        .iter()
        .map(|a| {
            if a.starts_with("nono_") {
                broker
                    .resolve(a)
                    .map(|r| r.as_str().to_string())
                    .unwrap_or_else(|| a.clone())
            } else {
                a.clone()
            }
        })
        .collect();

    let real_path = cmd.real_path.clone();
    let stdin_data = stdin_data.to_string();
    let maybe_sandbox = sandbox;

    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::io::Write;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut cmd_builder = Command::new(&real_path);
        cmd_builder
            .args(&args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(sb) = maybe_sandbox {
            let mut caps = nono::CapabilitySet::new();

            // Apply platform system read paths so the binary can actually exec.
            // Mirrors the system_read_macos / system_read_linux groups applied to the main sandbox.
            if let Ok(policy) = crate::policy::load_embedded_policy() {
                let platform_group = if cfg!(target_os = "macos") {
                    "system_read_macos"
                } else {
                    "system_read_linux"
                };
                let _ = crate::policy::resolve_groups(
                    &policy,
                    &[platform_group.to_string()],
                    &mut caps,
                );
            }

            // Also allow the binary's own directory, in case it lives outside the standard
            // system paths (e.g. ~/dd/devtools/bin/gh). Use the ORIGINAL (pre-canonicalize)
            // parent so FsCapability emits Seatbelt rules for both the symlink path and the
            // resolved canonical path — Seatbelt checks paths as-accessed (pre-resolution).
            if let Some(parent) = real_path.parent() {
                if parent.exists() {
                    caps = caps.allow_path(parent, nono::AccessMode::Read)?;
                }
            }

            // Add command-specific configured paths (~ is expanded to $HOME).
            for path in &sb.fs_read {
                let expanded = expand_home(path);
                let p = std::path::Path::new(&expanded);
                if p.is_file() {
                    caps = caps.allow_file(&expanded, nono::AccessMode::Read)?;
                } else if p.is_dir() {
                    caps = caps.allow_path(&expanded, nono::AccessMode::Read)?;
                }
            }
            for path in &sb.fs_write {
                let expanded = expand_home(path);
                let p = std::path::Path::new(&expanded);
                if p.is_file() {
                    caps = caps.allow_file(&expanded, nono::AccessMode::Write)?;
                } else if p.is_dir() {
                    caps = caps.allow_path(&expanded, nono::AccessMode::Write)?;
                }
            }
            if sb.network.block {
                caps = caps.block_network();
            }
            unsafe {
                cmd_builder.pre_exec(move || {
                    nono::Sandbox::apply(&caps).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string())
                    })
                });
            }
        }

        let mut child = cmd_builder.spawn().map_err(NonoError::CommandExecution)?;

        if !stdin_data.is_empty() {
            if let Some(mut si) = child.stdin.take() {
                let _ = si.write_all(stdin_data.as_bytes());
            }
        }

        let output = child
            .wait_with_output()
            .map_err(NonoError::CommandExecution)?;

        Ok(ShimResponse {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(1),
        })
    })
    .await;

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    }
}

/// Expand a leading `~` to the current user's home directory.
fn expand_home(path: &str) -> String {
    if path == "~" {
        return std::env::var("HOME").unwrap_or_else(|_| path.to_string());
    }
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    path.to_string()
}

/// Build the environment map for an exec'd child.
///
/// Starts from the trusted parent env, then promotes nonce-bearing sandbox vars.
/// Non-nonce sandbox vars and dangerous var names are silently discarded.
fn build_exec_env(
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
) -> HashMap<String, String> {
    // Start from parent (trusted) env
    let mut env: HashMap<String, String> = std::env::vars().collect();

    // From sandbox env: only promote nonce-bearing vars; discard everything else.
    for (key, value) in sandbox_env {
        if !value.starts_with("nono_") {
            continue;
        }
        if DANGEROUS_ENV_VAR_NAMES.contains(&key.as_str()) {
            warn!(
                "mediation: blocked nonce injection into dangerous var {}",
                key
            );
            continue;
        }
        if let Some(real) = broker.resolve(value) {
            env.insert(key.clone(), real.as_str().to_string());
        }
        // Unknown nonce: silently discard — don't let sandbox probe broker contents.
    }

    env
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::approval::{AlwaysAllow, AlwaysDeny};
    use crate::mediation::session::{ResolvedCommand, ResolvedIntercept};
    use std::path::PathBuf;

    fn make_broker() -> Arc<TokenBroker> {
        Arc::new(TokenBroker::new())
    }

    fn always_allow() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysAllow)
    }

    fn always_deny() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysDeny)
    }

    fn make_cmd(intercepts: Vec<ResolvedIntercept>) -> ResolvedCommand {
        ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts,
            sandbox: None,
        }
    }

    #[tokio::test]
    async fn test_unknown_command_returns_127() {
        let req = ShimRequest {
            command: "doesnotexist".to_string(),
            args: vec![],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        let resp = apply(req, &[], make_broker(), always_allow()).await;
        assert_eq!(resp.exit_code, 127);
    }

    #[tokio::test]
    async fn test_intercept_respond_exact_prefix_match() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec![
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ],
            action: ResolvedAction::Respond {
                stdout: "static_output\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        let resp = apply(req, &[cmd], make_broker(), always_allow()).await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "static_output\n");
    }

    #[tokio::test]
    async fn test_intercept_prefix_matches_longer_args() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            action: ResolvedAction::Respond {
                stdout: "matched\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string(), "github".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        let resp = apply(req, &[cmd], make_broker(), always_allow()).await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "matched\n");
    }

    #[tokio::test]
    async fn test_no_intercept_match_falls_through() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string(), "github".to_string()],
            action: ResolvedAction::Respond {
                stdout: "secret\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        // Falls through to passthrough exec of /usr/bin/true
        let resp = apply(req, &[cmd], make_broker(), always_allow()).await;
        assert_eq!(resp.exit_code, 0);
    }

    // --- Admin gate tests ---

    #[tokio::test]
    async fn test_admin_rule_allow_proceeds() {
        // AlwaysAllow gate + admin=true rule → normal Respond action is returned.
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["repo".to_string(), "delete".to_string()],
            action: ResolvedAction::Respond {
                stdout: "Aborted by policy.\n".to_string(),
            },
            exit_code: 1,
            admin: true,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "repo".to_string(),
                "delete".to_string(),
                "my-repo".to_string(),
            ],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        let resp = apply(req, &[cmd], make_broker(), always_allow()).await;
        // Approved → action fires, returns configured exit_code=1 and stdout
        assert_eq!(resp.exit_code, 1);
        assert_eq!(resp.stdout, "Aborted by policy.\n");
    }

    #[tokio::test]
    async fn test_admin_rule_deny_blocks() {
        // AlwaysDeny gate + admin=true rule → exit 126, denial stderr.
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["repo".to_string(), "delete".to_string()],
            action: ResolvedAction::Respond {
                stdout: "Aborted by policy.\n".to_string(),
            },
            exit_code: 1,
            admin: true,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "repo".to_string(),
                "delete".to_string(),
                "my-repo".to_string(),
            ],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        let resp = apply(req, &[cmd], make_broker(), always_deny()).await;
        assert_eq!(resp.exit_code, 126);
        assert!(resp.stdout.is_empty());
        assert!(resp.stderr.contains("was not approved"));
    }

    #[tokio::test]
    async fn test_non_admin_rule_skips_gate() {
        // AlwaysDeny gate + admin=false rule → gate is NOT called, action executes normally.
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            action: ResolvedAction::Respond {
                stdout: "token\n".to_string(),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        // Even though the gate always denies, admin=false means it is never called.
        let resp = apply(req, &[cmd], make_broker(), always_deny()).await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "token\n");
    }

    // --- subcommand_matches tests ---

    #[test]
    fn test_subcommand_matches_basic() {
        assert!(subcommand_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string(), "b".to_string(), "c".to_string()]
        ));
        assert!(subcommand_matches(&[], &["a".to_string()]));
        assert!(!subcommand_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string()]
        ));
        assert!(!subcommand_matches(&["a".to_string()], &["b".to_string()]));
    }

    #[test]
    fn test_subcommand_matches_ignores_leading_flags() {
        // --debug before positional args should not break matching
        assert!(subcommand_matches(
            &[
                "auth".to_string(),
                "github".to_string(),
                "token".to_string()
            ],
            &[
                "--debug".to_string(),
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ]
        ));
    }

    #[test]
    fn test_subcommand_matches_ignores_interleaved_flags() {
        // flags between subcommands should be ignored
        assert!(subcommand_matches(
            &["auth".to_string(), "github".to_string()],
            &[
                "auth".to_string(),
                "--verbose".to_string(),
                "github".to_string(),
            ]
        ));
    }

    #[test]
    fn test_subcommand_matches_empty_prefix_matches_anything() {
        assert!(subcommand_matches(&[], &[]));
        assert!(subcommand_matches(&[], &["anything".to_string()]));
    }

    // --- Capture tests ---

    #[tokio::test]
    async fn test_capture_runs_real_binary_and_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            action: ResolvedAction::Capture { script: None },
            exit_code: 0,
            admin: false,
        }]);
        // Use a command that outputs something: `echo hello` → "hello"
        let cmd = ResolvedCommand {
            real_path: PathBuf::from("/bin/echo"),
            ..cmd
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // args passed to echo: "auth" "hello" → output "auth hello"
            args: vec!["auth".to_string(), "hello".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        let broker = make_broker();
        let resp = apply(req, &[cmd], Arc::clone(&broker), always_allow()).await;
        assert_eq!(resp.exit_code, 0);
        assert!(
            resp.stdout.trim().starts_with("nono_"),
            "stdout was: {}",
            resp.stdout
        );
        // The nonce resolves to the trimmed stdout of `echo auth hello`
        let nonce = resp.stdout.trim();
        let resolved = broker.resolve(nonce).expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "auth hello");
    }

    #[tokio::test]
    async fn test_capture_script_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            action: ResolvedAction::Capture {
                script: Some("echo my_secret_token".to_string()),
            },
            exit_code: 0,
            admin: false,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string()],
            stdin: String::new(),
            session_token: String::new(),
            env: HashMap::new(),
        };
        let broker = make_broker();
        let resp = apply(req, &[cmd], Arc::clone(&broker), always_allow()).await;
        assert_eq!(resp.exit_code, 0);
        let nonce = resp.stdout.trim();
        assert!(nonce.starts_with("nono_"), "expected nonce, got: {}", nonce);
        let resolved = broker.resolve(nonce).expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "my_secret_token");
    }

    // --- Env filtering tests ---

    #[test]
    fn test_build_exec_env_discards_non_nonce_sandbox_vars() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("SOME_VAR".to_string(), "not_a_nonce".to_string());
        sandbox_env.insert("ANOTHER".to_string(), "regular_value".to_string());

        let env = build_exec_env(&sandbox_env, &broker);
        // Non-nonce vars from sandbox should not appear (unless they were in parent env)
        // We can only check that the non-nonce values weren't injected from sandbox.
        // (Parent env values may be present; we just check sandbox-specific ones.)
        assert_ne!(env.get("SOME_VAR").map(|s| s.as_str()), Some("not_a_nonce"));
        assert_ne!(
            env.get("ANOTHER").map(|s| s.as_str()),
            Some("regular_value")
        );
    }

    #[test]
    fn test_build_exec_env_promotes_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("real_credential".to_string()));

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("GH_TOKEN".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker);
        assert_eq!(
            env.get("GH_TOKEN").map(|s| s.as_str()),
            Some("real_credential")
        );
    }

    #[test]
    fn test_build_exec_env_blocks_dangerous_var_even_with_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("/evil/path".to_string()));

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("PATH".to_string(), nonce.clone());
        sandbox_env.insert("LD_PRELOAD".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker);
        // PATH from sandbox must not be the injected value (parent PATH is used instead)
        assert_ne!(env.get("PATH").map(|s| s.as_str()), Some("/evil/path"));
        // LD_PRELOAD should not have been injected
        assert_ne!(
            env.get("LD_PRELOAD").map(|s| s.as_str()),
            Some("/evil/path")
        );
    }

    #[test]
    fn test_build_exec_env_discards_unknown_nonce() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        // A nonce-like value that was never issued
        sandbox_env.insert(
            "MY_TOKEN".to_string(),
            "nono_0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        let env = build_exec_env(&sandbox_env, &broker);
        // Unknown nonce: var should not be set to any nonce value
        assert_ne!(
            env.get("MY_TOKEN").map(|s| s.as_str()),
            Some("nono_0000000000000000000000000000000000000000000000000000000000000000")
        );
    }
}
