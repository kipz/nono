//! Policy engine for the mediation server.
//!
//! For each incoming `ShimRequest`, this module:
//! 1. Finds the matching `ResolvedCommand` entry.
//! 2. Checks `intercept` rules in order via each rule's compiled `ResolvedArgsMatcher`
//!    (predicate trees over regex leaves: combinators `all`/`any`/`not` over
//!    `any_arg_matches`, `all_args_match`, `nth_arg_matches`).
//! 3. If matched with `Deny`: returns the configured `ShimResponse` without calling the binary.
//! 4. If matched with `Capture`: runs the real binary (or a script), stores output in the broker,
//!    returns a `nono_<hex>` nonce to the sandbox.
//! 5. If not matched: execs the real binary. `nono_<64-hex>` substrings inside both argv and
//!    env-var values are replaced with the broker's real value before exec.

use super::approval::ApprovalGate;
use super::broker::{ConsumerContext, GrantSet, TokenBroker};
use super::session::{ResolvedAction, ResolvedCommand, ResolvedSandboxBinding};
use crate::mediation::CommandSandbox;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::io::OwnedFd;
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Request forwarded from the shim binary to the mediation server.
///
/// The shim sends this JSON request followed by a single SCM_RIGHTS message
/// carrying stdin/stdout/stderr fds together. The fds are received out-of-band
/// by the server and threaded into `apply` — they are not part of this struct.
#[derive(Debug, Default, Deserialize)]
pub struct ShimRequest {
    pub command: String,
    pub args: Vec<String>,
    /// Session authentication token. Must match the token injected via
    /// `NONO_SESSION_TOKEN`. Requests with a missing or wrong token are
    /// silently rejected. Old shims missing this field fail deserialization
    /// and receive a 127 error — the correct security behaviour.
    pub session_token: String,
    /// Environment variables from the sandbox at invocation time.
    /// Used only for nonce promotion — all non-nonce vars are discarded.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// PID of the shim process itself — the process that ran this command.
    /// Used to populate `command_pid` in the audit log.
    #[serde(default)]
    pub pid: u32,
    /// Working directory of the shim at invocation time — the caller's cwd.
    /// Used to set the spawned real binary's cwd via `Command::current_dir`.
    /// Without this, the spawned binary inherits the mediation server's cwd
    /// (the nono launch cwd), which silently breaks tools that resolve config
    /// from cwd — git in a worktree being the canonical case. `None` (older
    /// shim, or unreadable cwd) preserves the legacy behaviour.
    #[serde(default)]
    pub cwd: Option<String>,
}

/// Response the mediation server sends back to the shim binary.
#[derive(Debug, Serialize)]
pub struct ShimResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Mediation session context passed to policy functions.
///
/// Bundles the per-session paths and token needed by `apply` and `exec_passthrough`.
pub struct SessionCtx<'a> {
    pub shim_dir: &'a std::path::Path,
    pub socket_path: &'a std::path::Path,
    pub session_token: &'a str,
    /// Working directory of the nono session (the parent launch cwd or
    /// `--workdir`). Threaded into `expand_vars` so `$WORKDIR` in mediated
    /// sandbox paths resolves consistently across the main and per-command
    /// sandboxes.
    pub workdir: &'a std::path::Path,
    /// Commands the agent (primary sandbox) may invoke directly. Populated
    /// from `MediationConfig::session_can_use`. Used by the authorization
    /// graph gate in `apply`.
    pub session_can_use: Vec<String>,
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
    "NONO_SANDBOX_CONTEXT",
];

/// Apply policy to a shim request and produce a response.
///
/// - If the command is unknown: returns an error response (not found).
/// - If an intercept rule matches with `Deny`: returns the pre-resolved output.
/// - If an intercept rule matches with `Capture`: runs the binary/script, issues a nonce.
/// - Otherwise: execs the real binary with strict env filtering.
///
/// `stdin_fd`/`stdout_fd`/`stderr_fd` are the shim's stdio fds, received via
/// SCM_RIGHTS. The streaming passthrough path moves them into the spawned
/// child via `Stdio::from(...)` so binary streams (ssh/git) are not buffered
/// or corrupted. The `Capture`/`Deny`/`Approve` paths drop them and keep
/// the existing `Stdio::piped()` + `wait_with_output` behaviour.
#[allow(clippy::too_many_arguments)]
pub async fn apply(
    request: ShimRequest,
    commands: &[ResolvedCommand],
    broker: Arc<TokenBroker>,
    ctx: &SessionCtx<'_>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
    stdin_fd: OwnedFd,
    stdout_fd: OwnedFd,
    stderr_fd: OwnedFd,
) -> (ShimResponse, &'static str) {
    // Find matching command entry
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("mediation: unknown command '{}'", request.command);
        return (
            ShimResponse {
                stdout: String::new(),
                stderr: format!(
                    "nono-mediation: command '{}' not configured\n",
                    request.command
                ),
                exit_code: 127,
            },
            "unknown",
        );
    };

    // Authorization graph gate (replaces caller_policy).
    // - No NONO_SANDBOX_CONTEXT → caller is the agent; allowed iff command is in session_can_use.
    // - NONO_SANDBOX_CONTEXT present → caller is mediated parent P; allowed iff command is in P.can_use.
    let sandbox_consumer = ConsumerContext {
        command: &request.command,
        intercept_id: "default",
    };
    let caller_parent = request
        .env
        .get("NONO_SANDBOX_CONTEXT")
        .and_then(|nonce| broker.resolve(nonce, &sandbox_consumer));
    let authorized = match &caller_parent {
        None => ctx.session_can_use.iter().any(|c| c == &request.command),
        Some(parent) => {
            let parent_name: &str = parent;
            match commands.iter().find(|c| c.name == parent_name) {
                None => {
                    warn!(
                        "mediation: rejecting '{}': parent '{}' is not a registered command",
                        request.command, parent_name
                    );
                    false
                }
                Some(p) => p.can_use.iter().any(|c| c == &request.command),
            }
        }
    };
    if !authorized {
        let who = caller_parent.as_deref().map_or("the agent", |p| p);
        warn!(
            "mediation: rejecting '{}' from {} (not authorized by can_use/session_can_use)",
            request.command, who
        );
        return (
            ShimResponse {
                stdout: String::new(),
                stderr: format!(
                    "nono-mediation: '{}' is not authorized for this caller\n",
                    request.command
                ),
                exit_code: 126,
            },
            "denied",
        );
    }

    // Per-caller behaviour from the `from` map (callee-side). `can_use` already
    // authorised the call. Agent callers (caller_parent == None) always go through
    // normal mediation — never passthrough.
    //
    // `Passthrough`: skip intercepts so credentials flow between trusted
    // sub-processes, not to the agent. The child's own per-command sandbox is
    // still applied (see issue #249).
    let from_binding = match caller_parent.as_deref() {
        Some(parent) => cmd.from.get(parent),
        None => None,
    };
    match from_binding {
        Some(super::session::ResolvedCallerBinding::Deny) => {
            warn!(
                "mediation: rejecting '{}': from[{}] = deny",
                request.command,
                caller_parent.as_deref().map_or("agent", |p| p)
            );
            return (
                ShimResponse {
                    stdout: String::new(),
                    stderr: format!(
                        "nono-mediation: '{}' is denied for this caller\n",
                        request.command
                    ),
                    exit_code: 126,
                },
                "denied",
            );
        }
        Some(super::session::ResolvedCallerBinding::Bound {
            action: crate::mediation::CallerAction::Passthrough,
            sandbox,
        }) => {
            // Skip intercepts — return real output to the trusted parent process.
            // Apply the binding's sandbox if present, otherwise fall back to the
            // command-level default.
            let sb = sandbox.clone().or_else(|| cmd.default.sandbox.clone()).or_else(|| cmd.sandbox.clone());
            debug!(
                "mediation: skipping intercepts for '{}' (called from '{}' via from[passthrough])",
                request.command,
                caller_parent.as_deref().map_or("agent", |p| p)
            );
            let result = exec_passthrough(
                cmd,
                &request.args,
                &request.env,
                &broker,
                sb,
                ctx,
                commands,
                Some((stdin_fd, stdout_fd, stderr_fd)),
                request.cwd.as_deref(),
                "default",
                cmd.default.promote_filter.as_ref(),
            )
            .await;
            return (result, "passthrough");
        }
        _ => {} // Allow or absent: fall through to normal intercept / default dispatch.
    }

    // Check intercept rules in order
    for rule in &cmd.intercepts {
        if rule.matcher.matches(&request.args) {
            debug!(
                "mediation: intercepting '{}' with matcher {:?}",
                request.command, rule.matcher
            );

            // Admin gate: require user authentication before executing this rule.
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
                    let action_type = match &rule.action {
                        ResolvedAction::Deny { .. } => "deny",
                        ResolvedAction::Capture { .. } => "capture",
                        ResolvedAction::Allow { .. } => "allow",
                    };
                    return (
                        ShimResponse {
                            stdout: String::new(),
                            stderr: format!("nono: '{}' was not approved\n", invocation),
                            exit_code: 126,
                        },
                        action_type,
                    );
                }
            }

            // For buffered intercept paths (`respond`/`capture`/`approve`) the
            // passed stdio fds are not used — the duplicated fds drop in each
            // branch, leaving the originals open in the shim so it can write
            // the buffered response to them. The `passthrough` arm keeps the
            // fds and hands them to `exec_passthrough` for streaming.
            return match &rule.action {
                ResolvedAction::Deny {
                    stdout,
                    stderr,
                    exit_code,
                } => {
                    drop(stdin_fd);
                    drop(stdout_fd);
                    drop(stderr_fd);
                    (
                        ShimResponse {
                            stdout: stdout.clone(),
                            stderr: stderr.clone(),
                            exit_code: *exit_code,
                        },
                        "deny",
                    )
                }
                ResolvedAction::Capture { script, grants } => {
                    drop(stdin_fd);
                    drop(stdout_fd);
                    drop(stderr_fd);
                    let capture_consumer = ConsumerContext {
                        command: &cmd.name,
                        intercept_id: rule.id.as_deref().unwrap_or(""),
                    };
                    let result = match script {
                        Some(sh) => {
                            exec_script(
                                sh,
                                &request.env,
                                &broker,
                                &capture_consumer,
                                rule.promote_filter.as_ref(),
                            )
                            .await
                        }
                        None => {
                            // No per-command sandbox during capture — the real binary needs
                            // full access to system resources (e.g. Keychain) to fetch the credential.
                            exec_passthrough(
                                cmd,
                                &request.args,
                                &request.env,
                                &broker,
                                None,
                                ctx,
                                commands,
                                None,
                                request.cwd.as_deref(),
                                rule.id.as_deref().unwrap_or(""),
                                rule.promote_filter.as_ref(),
                            )
                            .await
                        }
                    };
                    if result.exit_code != 0 {
                        return (result, "capture");
                    }
                    let nonce = broker.issue(
                        Zeroizing::new(result.stdout.trim().to_string()),
                        grants.clone(),
                    );
                    (
                        ShimResponse {
                            stdout: format!("{}\n", nonce),
                            stderr: String::new(),
                            exit_code: 0,
                        },
                        "capture",
                    )
                }
                ResolvedAction::Allow { script } => {
                    // Allow streams the real binary's stdio directly, with the
                    // matched rule's tri-state sandbox binding: `Explicit`
                    // overrides; `ExplicitlyUnsandboxed` opts out;
                    // `InheritFromDefault` falls back to
                    // `cmd.default.sandbox` then the legacy
                    // command-level `cmd.sandbox`. Optionally substitutes the
                    // command with a shell script (same semantics as
                    // `Capture.script`).
                    let effective_sandbox: Option<CommandSandbox> = match &rule.sandbox {
                        ResolvedSandboxBinding::Explicit(sb) => Some(sb.clone()),
                        ResolvedSandboxBinding::ExplicitlyUnsandboxed => None,
                        ResolvedSandboxBinding::InheritFromDefault => {
                            cmd.default.sandbox.clone().or_else(|| cmd.sandbox.clone())
                        }
                    };
                    let run_consumer = ConsumerContext {
                        command: &cmd.name,
                        intercept_id: rule.id.as_deref().unwrap_or(""),
                    };
                    if let Some(script_str) = script {
                        drop(stdin_fd);
                        drop(stdout_fd);
                        drop(stderr_fd);
                        return (
                            exec_script(
                                script_str,
                                &request.env,
                                &broker,
                                &run_consumer,
                                rule.promote_filter.as_ref(),
                            )
                            .await,
                            "allow",
                        );
                    }
                    let result = exec_passthrough(
                        cmd,
                        &request.args,
                        &request.env,
                        &broker,
                        effective_sandbox,
                        ctx,
                        commands,
                        Some((stdin_fd, stdout_fd, stderr_fd)),
                        request.cwd.as_deref(),
                        rule.id.as_deref().unwrap_or(""),
                        rule.promote_filter.as_ref(),
                    )
                    .await;
                    (result, "allow")
                }
            };
        }
    }

    // No intercept matched — dispatch the command's default action.
    debug!("mediation: dispatching default for '{}'", request.command);
    let default_entry = &cmd.default;
    match &default_entry.action {
        ResolvedAction::Deny {
            stdout,
            stderr,
            exit_code,
        } => {
            drop(stdin_fd);
            drop(stdout_fd);
            drop(stderr_fd);
            (
                ShimResponse {
                    stdout: stdout.clone(),
                    stderr: stderr.clone(),
                    exit_code: *exit_code,
                },
                "deny",
            )
        }
        ResolvedAction::Allow { script } => {
            // The default's sandbox wins; fall back to the legacy
            // command-level `cmd.sandbox` when the default omits one.
            // If a `from[P]` binding with an explicit sandbox is present,
            // it takes highest precedence (overrides the command-default).
            let from_sandbox = match caller_parent.as_deref() {
                Some(p) => match cmd.from.get(p) {
                    Some(super::session::ResolvedCallerBinding::Bound { sandbox, .. }) => {
                        sandbox.clone()
                    }
                    _ => None,
                },
                None => None,
            };
            let effective_sandbox = from_sandbox
                .or_else(|| default_entry.sandbox.clone())
                .or_else(|| cmd.sandbox.clone());
            let default_consumer = ConsumerContext {
                command: &cmd.name,
                intercept_id: "default",
            };
            if let Some(script_str) = script {
                drop(stdin_fd);
                drop(stdout_fd);
                drop(stderr_fd);
                return (
                    exec_script(
                        script_str,
                        &request.env,
                        &broker,
                        &default_consumer,
                        default_entry.promote_filter.as_ref(),
                    )
                    .await,
                    "allow",
                );
            }
            let result = exec_passthrough(
                cmd,
                &request.args,
                &request.env,
                &broker,
                effective_sandbox,
                ctx,
                commands,
                Some((stdin_fd, stdout_fd, stderr_fd)),
                request.cwd.as_deref(),
                "default",
                default_entry.promote_filter.as_ref(),
            )
            .await;
            (result, "allow")
        }
        ResolvedAction::Capture { .. } => {
            // Rejected at profile load (see session::setup validation), but
            // surface a clear error if it ever reaches here.
            drop(stdin_fd);
            drop(stdout_fd);
            drop(stderr_fd);
            (
                ShimResponse {
                    stdout: String::new(),
                    stderr: format!(
                        "nono-mediation: command '{}': default.action cannot be 'capture'\n",
                        request.command
                    ),
                    exit_code: 1,
                },
                "error",
            )
        }
    }
}

/// Execute the real binary without any mediation — no intercept rules, no env
/// var filtering, no nonce promotion. Used when admin mode is active.
///
/// This is an intentional bypass. The operator explicitly granted admin mode
/// via biometric or password auth. All calls are logged at WARN level.
///
/// Stdio is streamed directly through the shim's passed fds so binary
/// streams (e.g. ssh/git) work correctly under admin mode too.
pub async fn admin_passthrough(
    request: &ShimRequest,
    commands: &[ResolvedCommand],
    stdin_fd: OwnedFd,
    stdout_fd: OwnedFd,
    stderr_fd: OwnedFd,
) -> (ShimResponse, &'static str) {
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("admin passthrough: unknown command '{}'", request.command);
        return (
            ShimResponse {
                stdout: String::new(),
                stderr: format!(
                    "nono-mediation: command '{}' not configured\n",
                    request.command
                ),
                exit_code: 127,
            },
            "admin_passthrough",
        );
    };

    // Build env from parent process — no filtering, no nonce promotion.
    let env: HashMap<String, String> = std::env::vars().collect();
    let args = request.args.clone();
    let real_path = cmd.real_path.clone();
    let cmd_name = cmd.name.clone();
    // Resolve caller cwd off the blocking thread so the warning is emitted on
    // the tokio runtime thread.
    let spawn_cwd: Option<std::path::PathBuf> = request.cwd.as_deref().and_then(|cwd| {
        let path = std::path::Path::new(cwd);
        if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            warn!(
                "admin passthrough: caller cwd '{}' is not a directory, spawning '{}' with server cwd",
                cwd, cmd_name
            );
            None
        }
    });

    let result = tokio::task::spawn_blocking(move || -> nono::Result<ShimResponse> {
        use std::process::{Command, Stdio};

        let mut cmd_builder = Command::new(&real_path);
        cmd_builder
            .args(&args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::from(stdin_fd))
            .stdout(Stdio::from(stdout_fd))
            .stderr(Stdio::from(stderr_fd));
        if let Some(ref cwd) = spawn_cwd {
            cmd_builder.current_dir(cwd);
        }

        let mut child = cmd_builder
            .spawn()
            .map_err(nono::NonoError::CommandExecution)?;

        let status = child.wait().map_err(nono::NonoError::CommandExecution)?;

        Ok(ShimResponse {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: status.code().unwrap_or(1),
        })
    })
    .await;

    let resp = match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: admin passthrough exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    };
    (resp, "admin_passthrough")
}

/// Execute a shell script and collect its output.
///
/// Uses the same strict env-building as `exec_passthrough`: starts from the
/// trusted parent env, promotes nonce-bearing sandbox vars, blocks dangerous names.
async fn exec_script(
    script: &str,
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
    consumer: &ConsumerContext<'_>,
    promote_filter: Option<&super::promote::ResolvedPromoteFilter>,
) -> ShimResponse {
    let env = build_exec_env(sandbox_env, broker, consumer, promote_filter);
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
/// - Prepends `shim_dir` to PATH so subprocess invocations of mediated commands
///   route through the mediation server instead of running directly inside the
///   per-command sandbox (where network is restricted).
/// - From the sandbox env, every `nono_<64-hex>` substring inside a value is
///   promoted to the broker's stored real value. Non-nonce text passes through.
/// - Dangerous var names (PATH, LD_PRELOAD, etc.) are blocked even with valid nonces.
/// - Arg nonces: any `nono_<64-hex>` substring inside an arg is replaced with
///   the real value, so embedded uses like `-H "Authorization: Bearer nono_..."`
///   work without the caller having to put the nonce at the start of the arg.
///
/// `stdio_fds`:
/// - `Some((stdin, stdout, stderr))`: streaming mode — the real binary inherits
///   the shim's fds directly, the response carries empty stdout/stderr and the
///   call uses `wait()` instead of `wait_with_output()`. This is required for
///   binary streams (ssh, git over ssh) and avoids buffering for any
///   long-running command (gh, kubectl, dd-attest, etc.).
/// - `None`: buffered mode — the real binary's stdout/stderr are captured
///   into the `ShimResponse` (used by Capture/Approve flows so the server can
///   inspect or relay the output).
#[allow(clippy::too_many_arguments)]
async fn exec_passthrough(
    cmd: &ResolvedCommand,
    args: &[String],
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
    sandbox: Option<super::CommandSandbox>,
    ctx: &SessionCtx<'_>,
    all_commands: &[ResolvedCommand],
    stdio_fds: Option<(OwnedFd, OwnedFd, OwnedFd)>,
    request_cwd: Option<&str>,
    consumer_intercept_id: &str,
    promote_filter: Option<&super::promote::ResolvedPromoteFilter>,
) -> ShimResponse {
    let consumer = ConsumerContext {
        command: &cmd.name,
        intercept_id: consumer_intercept_id,
    };
    let mut env = build_exec_env(sandbox_env, broker, &consumer, promote_filter);

    // Build PATH: prepend the shim directory so subprocess invocations of
    // mediated commands route through the mediation server.
    let shim_dir_str = ctx.shim_dir.to_string_lossy().to_string();
    let parent_path = env
        .get("PATH")
        .cloned()
        .unwrap_or_else(|| "/usr/bin:/bin".to_string());
    let path_parts = vec![shim_dir_str.clone(), parent_path];
    env.insert("PATH".to_string(), path_parts.join(":"));

    // Update NONO_SHIM_DIR so nono-shim can skip its own directory when
    // resolving the real binary, preventing infinite exec recursion (EAGAIN).
    env.insert("NONO_SHIM_DIR".to_string(), shim_dir_str.clone());

    // Inject mediation socket path and session token so the shim binaries
    // invoked by the exec'd command can authenticate to the mediation server.
    // This allows exec plugins (e.g. kubectl's credential plugin) to route
    // through mediation rather than running directly in the per-command sandbox.
    env.insert(
        "NONO_MEDIATION_SOCKET".to_string(),
        ctx.socket_path.to_string_lossy().to_string(),
    );
    env.insert(
        "NONO_SESSION_TOKEN".to_string(),
        ctx.session_token.to_string(),
    );

    // Inject a sandbox context nonce so the mediation server can identify
    // shim requests originating from within this per-command sandbox.
    // Credentials flow between trusted sub-processes, not to the agent.
    // The nonce is unforgeable — only the server can issue valid nonces.
    //
    // Grant set: every mediated command's `default` descriptor — the
    // caller-policy gate uses `intercept_id="default"` and the called
    // command's own name, so any mediated command may resolve this nonce
    // when looking up its own caller.
    let sandbox_context_grants = GrantSet::Allow(
        all_commands
            .iter()
            .map(|c| crate::mediation::broker::GrantDescriptor {
                command: c.name.clone(),
                intercept_id: "default".to_string(),
            })
            .collect(),
    );
    let sandbox_context_nonce =
        broker.issue(Zeroizing::new(cmd.name.clone()), sandbox_context_grants);
    env.insert("NONO_SANDBOX_CONTEXT".to_string(), sandbox_context_nonce);

    // Promote nonce values in args. Any `nono_<64-hex>` substring is replaced
    // with the broker's resolved value, so headers like
    // `Authorization: Bearer nono_...` expand to the real token before the
    // exec'd command sees them.
    //
    // Per-slot scoping: `allows_arg` returns false when `promote_filter` is
    // None or has no `args` sub-predicate. This is the secure-default switch
    // — a rule that says nothing about argv promotion gets no argv promotion.
    let args: Vec<String> = args
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let allow = super::promote::ResolvedPromoteFilter::allows_arg(promote_filter, args, i);
            promote_nonces_in_str(a, broker, &consumer, allow)
        })
        .collect();

    let real_path = cmd.real_path.clone();
    let pin = cmd.pin.clone();
    let cmd_name = cmd.name.clone();
    // Owned shim paths for use in spawn_blocking (which requires 'static captures).
    let shim_dir_buf = ctx.shim_dir.to_path_buf();
    let real_shim_binary = std::fs::canonicalize(ctx.shim_dir.join(&cmd.name)).ok();
    // Own the session workdir for use inside spawn_blocking (profile::expand_vars
    // borrows it).
    let workdir_buf = ctx.workdir.to_path_buf();


    // Start a per-command proxy if allowed_hosts is configured (and block is not set).
    let mut proxy_handle: Option<nono_proxy::ProxyHandle> = None;
    let mut proxy_port: Option<u16> = None;

    if let Some(ref sb) = sandbox
        && !sb.network.allowed_hosts.is_empty()
        && !sb.network.block
    {
        let proxy_config = nono_proxy::ProxyConfig {
            allowed_hosts: sb.network.allowed_hosts.clone(),
            ..Default::default()
        };
        match nono_proxy::start(proxy_config).await {
            Ok(handle) => {
                for (k, v) in handle.env_vars() {
                    env.insert(k, v);
                }
                proxy_port = Some(handle.port);
                proxy_handle = Some(handle);
            }
            Err(e) => {
                return ShimResponse {
                    stdout: String::new(),
                    stderr: format!("nono-mediation: failed to start network proxy: {}\n", e),
                    exit_code: 1,
                };
            }
        }
    }

    let maybe_sandbox = sandbox;

    let streaming = stdio_fds.is_some();

    // Resolve the spawn cwd once, off the spawn_blocking thread, so we can log
    // a warning if the caller's cwd is unusable. We only honour it when it
    // points at an existing directory; otherwise the spawned binary inherits
    // the server's cwd (legacy behaviour). `None` (older shim or unreadable
    // cwd) also falls back to legacy behaviour.
    let spawn_cwd: Option<std::path::PathBuf> = request_cwd.and_then(|cwd| {
        let path = std::path::Path::new(cwd);
        if path.is_dir() {
            Some(path.to_path_buf())
        } else {
            warn!(
                "mediation: caller cwd '{}' is not a directory, spawning '{}' with server cwd",
                cwd, cmd_name
            );
            None
        }
    });

    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let mut cmd_builder = Command::new(&real_path);
        cmd_builder.args(&args).env_clear().envs(&env);
        if let Some(ref cwd) = spawn_cwd {
            cmd_builder.current_dir(cwd);
        }

        // Streaming: child inherits the shim's stdio fds directly so binary
        // data (ssh/git) flows through unmodified. Buffered: capture stdout
        // and stderr so the server can read them (e.g. Capture nonce flow).
        match stdio_fds {
            Some((stdin_fd, stdout_fd, stderr_fd)) => {
                cmd_builder
                    .stdin(Stdio::from(stdin_fd))
                    .stdout(Stdio::from(stdout_fd))
                    .stderr(Stdio::from(stderr_fd));
            }
            None => {
                cmd_builder
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
        }

        if let Some(sb) = maybe_sandbox {
            let mut caps = nono::CapabilitySet::new();

            // Apply platform system read+write paths so the binary can actually exec
            // and use standard devices (e.g. /dev/null). Mirrors the system groups
            // applied to the main sandbox.
            if let Ok(policy) = crate::policy::load_embedded_policy() {
                let (read_group, write_group) = if cfg!(target_os = "macos") {
                    ("system_read_macos", "system_write_macos")
                } else {
                    ("system_read_linux", "system_write_linux")
                };
                let _ = crate::policy::resolve_groups(
                    &policy,
                    &[read_group.to_string(), write_group.to_string()],
                    &mut caps,
                );
            }

            // Also allow the binary's own directory, in case it lives outside the standard
            // system paths (e.g. ~/dd/devtools/bin/gh). Use the ORIGINAL (pre-canonicalize)
            // parent so FsCapability emits Seatbelt rules for both the symlink path and the
            // resolved canonical path — Seatbelt checks paths as-accessed (pre-resolution).
            if let Some(parent) = real_path.parent()
                && parent.exists()
            {
                caps = caps.allow_path(parent, nono::AccessMode::Read)?;
            }

            // Allow the shim directory and the nono-shim binary so that subprocesses
            // of the exec'd command (e.g. kubectl's exec credential plugin) can exec
            // the shim binaries and route through the mediation server.
            caps = caps.allow_path(&shim_dir_buf, nono::AccessMode::Read)?;
            if let Some(ref real_shim) = real_shim_binary {
                caps = caps.allow_file(real_shim, nono::AccessMode::Read)?;
            }

            // Process-spawn gating.
            //
            // By default a per-command sandbox cannot spawn child processes via
            // process-exec. This closes the ssh ProxyCommand exfil class where a
            // Seatbelt child inherits ssh's fs_read access to ~/.ssh and uses
            // /bin/sh -c to smuggle private keys out via the network. Commands
            // that legitimately shell out to helpers (git, gh, aws, kubectl, etc.)
            // must opt in with `allow_process_exec: true` in their CommandSandbox.
            // See docs/cli/features/profile-authoring.mdx § "Per-command Sandboxes".
            if !sb.allow_process_exec {
                caps = caps.restrict_process_exec();
                caps = caps.allow_exec_path(&real_path);
                if let Some(ref real_shim) = real_shim_binary {
                    caps = caps.allow_exec_path(real_shim);
                }
            }

            // Add command-specific configured paths. `~` and `$VAR` tokens
            // (including $WORKDIR, $HOME, XDG dirs, and any env var set at
            // launch time such as $GIT_ROOT) are resolved via `expand_vars`
            // so they behave identically to top-level sandbox paths.
            for path in &sb.fs_read {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_dir(caps, &expanded, nono::AccessMode::Read, &cmd_name)?;
            }
            for path in &sb.fs_read_file {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_file(caps, &expanded, nono::AccessMode::Read, &cmd_name)?;
            }
            for path in &sb.fs_write {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_dir(caps, &expanded, nono::AccessMode::Write, &cmd_name)?;
            }
            for path in &sb.fs_write_file {
                let expanded = expand_sandbox_path(path, &workdir_buf, &cmd_name);
                caps = add_sandbox_file(caps, &expanded, nono::AccessMode::Write, &cmd_name)?;
            }
            // macOS Keychain access: grant read to keychain DB files so the
            // Seatbelt profile skips its mach-lookup denies for security daemons.
            // This allows the command to retrieve credentials from the system
            // keychain without exposing them to the agent (the token flows through
            // the command's internal auth, not stdout).
            #[cfg(target_os = "macos")]
            if sb.keychain_access
                && let Ok(home) = std::env::var("HOME")
            {
                let login = format!("{}/Library/Keychains/login.keychain-db", home);
                let metadata = format!("{}/Library/Keychains/metadata.keychain-db", home);
                caps = add_sandbox_file(caps, &login, nono::AccessMode::Read, &cmd_name)?;
                caps = add_sandbox_file(caps, &metadata, nono::AccessMode::Read, &cmd_name)?;
            }

            if sb.network.block {
                caps = caps.block_network();
            } else if let Some(port) = proxy_port {
                caps = caps.proxy_only(port);
            }

            // Nono is responsible for ensuring sandboxed child processes can always
            // reach the mediation server via its Unix domain socket, regardless of
            // network mode. The shim injected into PATH needs AF_UNIX socket creation
            // (system-socket) and the ability to connect to a unix-socket path
            // (network-outbound). Without these, nested nono-mediated commands (e.g.
            // `git remote -v` called from a git hook) cannot reach the mediation server
            // even under AllowAll network mode, because (deny default) blocks
            // system-socket() calls unless explicitly allowed.
            for rule in [
                "(allow system-socket (socket-domain AF_UNIX))",
                "(allow network-outbound (remote unix-socket))",
            ] {
                if let Err(e) = caps.add_platform_rule(rule) {
                    warn!("mediation: failed to add mediation socket rule: {}", e);
                }
            }
            unsafe {
                cmd_builder.pre_exec(move || {
                    nono::Sandbox::apply(&caps).map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string())
                    })
                });
            }
        }

        let verify_path = real_path.canonicalize().unwrap_or_else(|_| real_path.clone());
        if let Err(e) = crate::mediation::session::verify_pin(&verify_path, &pin) {
            warn!("mediation: pin verification failed for '{}': {}", cmd_name, e);
            return Ok(ShimResponse {
                stdout: String::new(),
                stderr: format!("nono-mediation: '{}' failed integrity check\n", cmd_name),
                exit_code: 126,
            });
        }

        let mut child = cmd_builder.spawn().map_err(NonoError::CommandExecution)?;

        if streaming {
            // Streaming: stdio is connected directly to the shim's fds. Just
            // wait for exit; there is no buffered output to collect.
            let status = child.wait().map_err(NonoError::CommandExecution)?;
            Ok(ShimResponse {
                stdout: String::new(),
                stderr: String::new(),
                exit_code: status.code().unwrap_or(1),
            })
        } else {
            let output = child
                .wait_with_output()
                .map_err(NonoError::CommandExecution)?;
            Ok(ShimResponse {
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code: output.status.code().unwrap_or(1),
            })
        }
    })
    .await;

    if let Some(handle) = proxy_handle {
        handle.shutdown();
    }

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

/// Expand `~` and `$VAR` / `${VAR}` tokens in a per-command sandbox path.
///
/// Delegates to `crate::profile::expand_vars`, which matches the main-sandbox
/// expansion (supports `$WORKDIR`, `$HOME`, XDG vars, `$TMPDIR`, `$UID`, and
/// generic env vars). On failure (e.g. invalid `$HOME`), falls back to the
/// raw path — `add_sandbox_*` will then log "does not exist, skipping" which
/// is the same outcome as an unset variable. This preserves robustness: a
/// misconfigured env var in one entry never aborts the whole session.
fn expand_sandbox_path(path: &str, workdir: &std::path::Path, cmd_name: &str) -> String {
    match crate::profile::expand_vars(path, workdir) {
        Ok(buf) => buf.to_string_lossy().into_owned(),
        Err(e) => {
            warn!(
                "mediation: command '{}' failed to expand sandbox path '{}': {}",
                cmd_name, path, e
            );
            path.to_string()
        }
    }
}

/// Add a directory capability to the sandbox.
/// Warns and skips on non-existent paths.
fn add_sandbox_dir(
    caps: nono::CapabilitySet,
    path: &str,
    access: nono::AccessMode,
    command_name: &str,
) -> Result<nono::CapabilitySet> {
    match nono::FsCapability::new_dir(path, access) {
        Ok(cap) => {
            let mut caps = caps;
            caps.add_fs(cap);
            Ok(caps)
        }
        Err(NonoError::PathNotFound(_)) => {
            warn!(
                "mediation: command '{}' sandbox dir '{}' does not exist, skipping",
                command_name, path
            );
            Ok(caps)
        }
        Err(e) => Err(e),
    }
}

/// Add a file capability to the sandbox.
/// Warns and skips on non-existent paths.
fn add_sandbox_file(
    caps: nono::CapabilitySet,
    path: &str,
    access: nono::AccessMode,
    command_name: &str,
) -> Result<nono::CapabilitySet> {
    match nono::FsCapability::new_file(path, access) {
        Ok(cap) => {
            let mut caps = caps;
            caps.add_fs(cap);
            Ok(caps)
        }
        Err(NonoError::PathNotFound(_)) => {
            warn!(
                "mediation: command '{}' sandbox file '{}' does not exist, skipping",
                command_name, path
            );
            Ok(caps)
        }
        Err(e) => Err(e),
    }
}

/// Build the environment map for an exec'd child.
///
/// Starts from the trusted parent env, then promotes nonce-bearing sandbox vars.
/// Non-nonce sandbox vars and dangerous var names are silently discarded.
///
/// `promote_filter` scopes which env vars are admitted for nonce promotion.
/// When absent (or its `env` sub-predicate is absent), the built-in safe-
/// shape name allowlist
/// ([`super::promote::PROMOTE_ENV_DEFAULT_NAMES`]) decides — credential-shaped
/// names like `AUTHORIZATION`, `*_TOKEN`, `*_HEADER`, etc. flow promotion;
/// anything else stays literal. Profiles widen this by setting an explicit
/// `EnvPredicate` that unions the default regex with extra names.
fn build_exec_env(
    sandbox_env: &HashMap<String, String>,
    broker: &Arc<TokenBroker>,
    consumer: &ConsumerContext,
    promote_filter: Option<&super::promote::ResolvedPromoteFilter>,
) -> HashMap<String, String> {
    // Start from parent (trusted) env
    let mut env: HashMap<String, String> = std::env::vars().collect();

    // From sandbox env: promote nonce-bearing vars and forward all other non-dangerous
    // vars. If a var was not blocked by the profile's `env.block` list it is permitted
    // to flow through to mediated commands. System execution vars (PATH, LD_PRELOAD,
    // etc.) are always blocked as defense-in-depth regardless of profile configuration.
    //
    // Substring promotion: any `nono_<64-hex>` substring in a value is replaced with
    // the broker's resolved value, so capture rules that emit shaped values like
    // `Authorization: Bearer <jwt>` expand correctly when consumed via the env.
    for (key, value) in sandbox_env {
        if DANGEROUS_ENV_VAR_NAMES.contains(&key.as_str()) {
            warn!("mediation: blocked dangerous var {} from sandbox env", key);
            continue;
        }
        // Per-var scoping: allow promotion only for env keys the filter
        // admits (or that match the built-in safe-shape allowlist when no
        // explicit env predicate is set). Non-admitted vars still flow
        // through with their literal value — only the nonce promotion is
        // suppressed.
        let allow = super::promote::ResolvedPromoteFilter::allows_env(
            promote_filter,
            key,
            value,
        );
        env.insert(
            key.clone(),
            promote_nonces_in_str(value, broker, consumer, allow),
        );
    }

    env
}

/// Replace every `nono_<64-hex>` substring in `s` with the broker's resolved
/// value. Substrings that look like nonces but were never issued are left in
/// place verbatim, matching the existing argv behaviour and avoiding a probe
/// oracle that would only return shape information the caller already has.
///
/// `allow` is the per-slot decision computed one scope up by
/// `ResolvedPromoteFilter::allows_arg` / `allows_env`. When `false`, returns
/// the original string unchanged so the call site does not have to branch.
fn promote_nonces_in_str(
    s: &str,
    broker: &TokenBroker,
    consumer: &ConsumerContext,
    allow: bool,
) -> String {
    if !allow {
        return s.to_string();
    }

    const PREFIX: &[u8] = b"nono_";
    const HEX_LEN: usize = 64;
    const NONCE_LEN: usize = PREFIX.len() + HEX_LEN;

    let bytes = s.as_bytes();
    if bytes.len() < NONCE_LEN {
        return s.to_string();
    }

    let mut out = String::with_capacity(s.len());
    let mut last_end = 0usize;
    let mut i = 0usize;
    while i + NONCE_LEN <= bytes.len() {
        if &bytes[i..i + PREFIX.len()] == PREFIX
            && bytes[i + PREFIX.len()..i + NONCE_LEN]
                .iter()
                .all(|b| b.is_ascii_digit() || (*b >= b'a' && *b <= b'f'))
        {
            // bytes[i] == b'n' is ASCII, so i is on a UTF-8 char boundary and
            // s[last_end..i] / s[i..i+NONCE_LEN] are valid str slices.
            out.push_str(&s[last_end..i]);
            let nonce = &s[i..i + NONCE_LEN];
            match broker.resolve(nonce, consumer) {
                Some(real) => out.push_str(real.as_str()),
                None => out.push_str(nonce),
            }
            i += NONCE_LEN;
            last_end = i;
            continue;
        }
        i += 1;
    }
    out.push_str(&s[last_end..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::approval::{AlwaysAllow, AlwaysDeny};
    use crate::mediation::broker::GrantDescriptor;
    use crate::mediation::matcher::ResolvedArgsMatcher;
    use crate::mediation::session::{PinnedBinary, ResolvedCommand, ResolvedDefault, ResolvedIntercept};
    use std::path::PathBuf;

    fn make_broker() -> Arc<TokenBroker> {
        Arc::new(TokenBroker::new())
    }

    /// Default consumer context for tests that just need to redeem
    /// nonces issued with a permissive `GrantSet::Allow` covering this
    /// `(command, intercept_id)`.
    fn test_consumer() -> ConsumerContext<'static> {
        ConsumerContext {
            command: "testcmd",
            intercept_id: "default",
        }
    }

    /// Permissive grant set used by tests that need a nonce redeemable by
    /// any of the consumer contexts the policy code constructs:
    /// `(testcmd, default)` for build_exec_env/promote_nonces helpers, and
    /// the `(*, default)` shapes used by the caller-policy gate when
    /// resolving a sandbox-context nonce. Replaces the former
    /// `test_grants()` in tests; no equivalent variant exists in the
    /// production code path now.
    fn test_grants() -> GrantSet {
        GrantSet::Allow(vec![
            GrantDescriptor {
                command: "testcmd".to_string(),
                intercept_id: "default".to_string(),
            },
            GrantDescriptor {
                command: "anything".to_string(),
                intercept_id: "default".to_string(),
            },
        ])
    }

    fn always_allow() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysAllow)
    }

    fn always_deny() -> Arc<dyn ApprovalGate + Send + Sync> {
        Arc::new(AlwaysDeny)
    }

    /// Compute a real `PinnedBinary` for `path` so `verify_pin` passes in tests
    /// that exec the binary through `exec_passthrough`.
    fn real_pin(path: &std::path::Path) -> PinnedBinary {
        crate::mediation::session::pin_binary(path).expect("pin_binary failed in test")
    }

    fn make_cmd(intercepts: Vec<ResolvedIntercept>) -> ResolvedCommand {
        let path = PathBuf::from("/usr/bin/true");
        let pin = real_pin(&path);
        ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: path,
            pin,
            intercepts,
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        }
    }

    /// Test harness for the streaming-passthrough fd protocol.
    ///
    /// Holds the test-side of the three socketpairs that back the child's
    /// stdin/stdout/stderr. Tests call `make_passthrough_fds()` to get the
    /// child fds (to pass into `apply`) plus this harness. Drainer threads
    /// (started by `apply_capture`) consume the child's output concurrently
    /// so a chatty child can't block on a full socketpair buffer.
    struct PassthroughHarness {
        stdin_writer: std::os::unix::net::UnixStream,
        stdout_reader: std::os::unix::net::UnixStream,
        stderr_reader: std::os::unix::net::UnixStream,
    }

    /// Create three socketpair-backed fds for streaming passthrough tests.
    ///
    /// Returns `(child_stdin, child_stdout, child_stderr, harness)`. Pass the
    /// three `OwnedFd`s into `apply`; keep `harness` bound until after `apply`
    /// returns so the child does not see EPIPE while writing.
    fn make_passthrough_fds() -> (OwnedFd, OwnedFd, OwnedFd, PassthroughHarness) {
        use std::os::unix::net::UnixStream;
        let (child_in, test_in) = UnixStream::pair().expect("socketpair stdin");
        let (child_out, test_out) = UnixStream::pair().expect("socketpair stdout");
        let (child_err, test_err) = UnixStream::pair().expect("socketpair stderr");
        (
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
            PassthroughHarness {
                stdin_writer: test_in,
                stdout_reader: test_out,
                stderr_reader: test_err,
            },
        )
    }

    /// Test wrapper around `apply` that handles the new fd-passing protocol.
    ///
    /// Creates a streaming socketpair harness, drains stdout/stderr in
    /// background threads while the child runs (so a chatty child cannot
    /// block on a full socketpair buffer), and merges what the child
    /// streamed into the returned `ShimResponse` so existing tests can
    /// continue to assert on `resp.stdout`/`resp.stderr` regardless of
    /// whether the path was streaming (passthrough) or buffered (Capture/
    /// Deny/Approve).
    async fn apply_capture(
        req: ShimRequest,
        cmds: &[ResolvedCommand],
        broker: Arc<TokenBroker>,
        ctx: &SessionCtx<'_>,
        approval: Arc<dyn ApprovalGate + Send + Sync>,
    ) -> (ShimResponse, &'static str) {
        let (stdin_fd, stdout_fd, stderr_fd, harness) = make_passthrough_fds();

        // Close the parent-side stdin writer so any child that reads stdin
        // sees an immediate EOF instead of hanging.
        drop(harness.stdin_writer);

        let stdout_reader = harness.stdout_reader;
        let stderr_reader = harness.stderr_reader;
        let stdout_handle = std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = (&stdout_reader).read_to_end(&mut buf);
            buf
        });
        let stderr_handle = std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = Vec::new();
            let _ = (&stderr_reader).read_to_end(&mut buf);
            buf
        });

        let (mut resp, action) = apply(
            req, cmds, broker, ctx, approval, stdin_fd, stdout_fd, stderr_fd,
        )
        .await;

        let stdout_streamed = stdout_handle.join().unwrap_or_default();
        let stderr_streamed = stderr_handle.join().unwrap_or_default();

        if resp.stdout.is_empty() {
            resp.stdout = String::from_utf8_lossy(&stdout_streamed).into_owned();
        }
        if resp.stderr.is_empty() {
            resp.stderr = String::from_utf8_lossy(&stderr_streamed).into_owned();
        }
        (resp, action)
    }

    #[tokio::test]
    async fn test_unknown_command_returns_127() {
        let req = ShimRequest {
            command: "doesnotexist".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 127);
    }

    // --- authorization graph gate (can_use / session_can_use) ---

    fn ctx() -> SessionCtx<'static> {
        SessionCtx {
            shim_dir: std::path::Path::new("/tmp"),
            socket_path: std::path::Path::new("/tmp/test.sock"),
            session_token: "test_token",
            workdir: std::path::Path::new("/tmp"),
            session_can_use: vec![
                "testcmd".to_string(),
                "echo".to_string(),
                "vault".to_string(),
            ],
        }
    }

    /// Agent may invoke a command that is in `session_can_use`.
    #[tokio::test]
    async fn test_caller_policy_agent_allowed_by_default() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]),
            action: ResolvedAction::Deny {
                stdout: "ok\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            // No NONO_SANDBOX_CONTEXT — caller is the agent.
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "deny");
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "ok\n");
    }

    /// Agent is denied when the command is not in `session_can_use`, regardless
    /// of the legacy `agent_allowed` field.
    #[tokio::test]
    async fn test_caller_policy_rejects_agent_when_agent_allowed_false() {
        let cmd = make_cmd(vec![]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };
        // ctx with empty session_can_use → agent cannot invoke testcmd.
        let ctx_empty = SessionCtx {
            shim_dir: std::path::Path::new("/tmp"),
            socket_path: std::path::Path::new("/tmp/test.sock"),
            session_token: "test_token",
            workdir: std::path::Path::new("/tmp"),
            session_can_use: vec![],
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx_empty, always_allow()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("testcmd"),
            "stderr should name the denied command: {}",
            resp.stderr
        );
    }

    /// A parent with `can_use` containing the child command is permitted.
    #[tokio::test]
    async fn test_caller_policy_allows_listed_parent() {
        let child_cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]),
            action: ResolvedAction::Deny {
                stdout: "from_git\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        // "git" parent has testcmd in its can_use.
        let parent_cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: std::path::PathBuf::from("/usr/bin/true"),

            pin: real_pin(&std::path::PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec!["testcmd".to_string()],
            from: Default::default(),
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("git".to_string()), test_grants());
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) =
            apply_capture(req, &[child_cmd, parent_cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "deny", "stderr: {}", resp.stderr);
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "from_git\n");
    }

    /// A parent whose `can_use` does not include the child command is denied.
    #[tokio::test]
    async fn test_caller_policy_rejects_unlisted_parent() {
        let child_cmd = make_cmd(vec![]);

        // "kubectl" parent does not have testcmd in its can_use.
        let parent_cmd = ResolvedCommand {
            name: "kubectl".to_string(),
            real_path: std::path::PathBuf::from("/usr/bin/true"),

            pin: real_pin(&std::path::PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("kubectl".to_string()), test_grants());
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) =
            apply_capture(req, &[child_cmd, parent_cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("testcmd"),
            "stderr should name the denied command: {}",
            resp.stderr
        );
    }

    /// A parent with empty `can_use` cannot invoke any child command.
    #[tokio::test]
    async fn test_caller_policy_empty_allowed_parents_blocks_all_parents() {
        let child_cmd = make_cmd(vec![]);

        // "git" parent has empty can_use → cannot invoke testcmd.
        let parent_cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: std::path::PathBuf::from("/usr/bin/true"),

            pin: real_pin(&std::path::PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("git".to_string()), test_grants());
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) =
            apply_capture(req, &[child_cmd, parent_cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
    }

    /// A parent with `can_use` containing the child is permitted to invoke it.
    /// Replaces the old `allowed_parents: None` open-by-default behaviour.
    #[tokio::test]
    async fn test_caller_policy_none_allowed_parents_accepts_any() {
        let child_cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]),
            action: ResolvedAction::Deny {
                stdout: "any_parent_ok\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        // "anything" parent explicitly lists testcmd in can_use.
        let parent_cmd = ResolvedCommand {
            name: "anything".to_string(),
            real_path: std::path::PathBuf::from("/usr/bin/true"),

            pin: real_pin(&std::path::PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec!["testcmd".to_string()],
            from: Default::default(),
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("anything".to_string()), test_grants());
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) =
            apply_capture(req, &[child_cmd, parent_cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "deny");
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "any_parent_ok\n");
    }

    // --- can_use / session_can_use gate tests ---

    /// Agent is denied when it calls a command that is not in `session_can_use`.
    /// No NONO_SANDBOX_CONTEXT → caller is the agent → the command must appear
    /// in ctx.session_can_use, otherwise the request is rejected with exit 126.
    #[tokio::test]
    async fn test_session_can_use_agent_denied_when_command_not_listed() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]),
            action: ResolvedAction::Deny {
                stdout: "should_not_reach\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            // No NONO_SANDBOX_CONTEXT → caller is the agent.
            ..Default::default()
        };
        // session_can_use does NOT include "testcmd" → must be denied.
        let ctx_no_testcmd = SessionCtx {
            shim_dir: std::path::Path::new("/tmp"),
            socket_path: std::path::Path::new("/tmp/test.sock"),
            session_token: "test_token",
            workdir: std::path::Path::new("/tmp"),
            session_can_use: vec![],
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx_no_testcmd, always_allow()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("testcmd"),
            "stderr should name the denied command: {}",
            resp.stderr
        );
    }

    /// Agent is allowed when the command is in `session_can_use`.
    #[tokio::test]
    async fn test_session_can_use_agent_allowed_when_command_listed() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]),
            action: ResolvedAction::Deny {
                stdout: "reached\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };
        // session_can_use includes "testcmd" → must pass through to intercept.
        let ctx_with_testcmd = SessionCtx {
            shim_dir: std::path::Path::new("/tmp"),
            socket_path: std::path::Path::new("/tmp/test.sock"),
            session_token: "test_token",
            workdir: std::path::Path::new("/tmp"),
            session_can_use: vec!["testcmd".to_string()],
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx_with_testcmd, always_allow()).await;
        assert_eq!(action, "deny");
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "reached\n");
    }

    /// A mediated parent is denied when it tries to invoke a command not in
    /// its own `can_use` list. The parent is identified via the broker nonce
    /// in NONO_SANDBOX_CONTEXT.
    #[tokio::test]
    async fn test_can_use_parent_denied_when_child_not_in_can_use() {
        // "testcmd" is the child being invoked.
        let child_cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]),
            action: ResolvedAction::Deny {
                stdout: "should_not_reach\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        // "git" is the parent. Its can_use does NOT include "testcmd".
        let parent_cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: std::path::PathBuf::from("/usr/bin/true"),

            pin: real_pin(&std::path::PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![], // "testcmd" not listed
            from: Default::default(),
        };

        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("git".to_string()), test_grants());
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) =
            apply_capture(req, &[child_cmd, parent_cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("testcmd"),
            "stderr should name the denied command: {}",
            resp.stderr
        );
    }

    #[tokio::test]
    async fn test_can_use_parent_unknown_command_denied() {
        // Parent nonce resolves to a name not registered in commands → denied.
        // (Ensures the gate is fail-closed for unregistered parents.)
        let child_cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]),
            action: ResolvedAction::Deny {
                stdout: "should_not_reach\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        // "git" is registered in commands; the nonce will resolve to "unknown-parent"
        // which is NOT registered in commands.
        let git_cmd = ResolvedCommand {
            name: "git".to_string(),
            real_path: std::path::PathBuf::from("/usr/bin/true"),

            pin: real_pin(&std::path::PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec!["testcmd".to_string()],
            from: Default::default(),
        };

        let broker = make_broker();
        // Issue a nonce for a name that is NOT in the commands list.
        let nonce = broker.issue(
            Zeroizing::new("unknown-parent".to_string()),
            test_grants(),
        );
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };
        let (resp, action) =
            apply_capture(req, &[child_cmd, git_cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("testcmd"),
            "stderr should name the denied command: {}",
            resp.stderr
        );
    }

    #[tokio::test]
    async fn test_intercept_deny_exact_prefix_match() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^auth$").unwrap()),
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^github$").unwrap()),
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^token$").unwrap()),
            ]),
            action: ResolvedAction::Deny {
                stdout: "static_output\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "auth".to_string(),
                "github".to_string(),
                "token".to_string(),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "static_output\n");
    }

    #[tokio::test]
    async fn test_intercept_prefix_matches_longer_args() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![ResolvedArgsMatcher::AnyArgMatches(
                ::regex::Regex::new("^auth$").unwrap(),
            )]),
            action: ResolvedAction::Deny {
                stdout: "matched\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string(), "github".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "matched\n");
    }

    #[tokio::test]
    async fn test_no_intercept_match_falls_through() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^auth$").unwrap()),
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^github$").unwrap()),
            ]),
            action: ResolvedAction::Deny {
                stdout: "secret\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        // Falls through to passthrough exec of /usr/bin/true
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
    }

    #[tokio::test]
    async fn test_admin_rule_allow_proceeds() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^repo$").unwrap()),
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^delete$").unwrap()),
            ]),
            action: ResolvedAction::Deny {
                stdout: "deleted\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: true,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["repo".to_string(), "delete".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "deleted\n");
    }

    #[tokio::test]
    async fn test_admin_rule_deny_blocks() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^repo$").unwrap()),
                ResolvedArgsMatcher::AnyArgMatches(::regex::Regex::new("^delete$").unwrap()),
            ]),
            action: ResolvedAction::Deny {
                stdout: "deleted\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: true,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["repo".to_string(), "delete".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_deny(),
        )
        .await;
        assert_eq!(resp.exit_code, 126);
        assert!(resp.stderr.contains("was not approved"));
    }

    #[tokio::test]
    async fn test_non_admin_rule_skips_gate() {
        // admin=false rule with AlwaysDeny gate — gate must NOT be called, action executes.
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![ResolvedArgsMatcher::AnyArgMatches(
                ::regex::Regex::new("^status$").unwrap(),
            )]),
            action: ResolvedAction::Deny {
                stdout: "ok\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_deny(),
        )
        .await;
        // Gate not consulted; action executes normally.
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "ok\n");
    }

    // --- Capture tests ---

    #[tokio::test]
    async fn test_capture_runs_real_binary_and_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![ResolvedArgsMatcher::AnyArgMatches(
                ::regex::Regex::new("^auth$").unwrap(),
            )]),
            action: ResolvedAction::Capture {
                script: None,
                grants: test_grants(),
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);
        // Use a command that outputs something: `echo hello` → "hello"
        let cmd = ResolvedCommand {
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            can_use: vec![],
            ..cmd
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // args passed to echo: "auth" "hello" → output "auth hello"
            args: vec!["auth".to_string(), "hello".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        assert!(
            resp.stdout.trim().starts_with("nono_"),
            "stdout was: {}",
            resp.stdout
        );
        // The nonce resolves to the trimmed stdout of `echo auth hello`
        let nonce = resp.stdout.trim();
        let resolved = broker
            .resolve(nonce, &test_consumer())
            .expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "auth hello");
    }

    #[tokio::test]
    async fn test_capture_script_returns_nonce() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![ResolvedArgsMatcher::AnyArgMatches(
                ::regex::Regex::new("^auth$").unwrap(),
            )]),
            action: ResolvedAction::Capture {
                script: Some("echo my_secret_token".to_string()),
                grants: test_grants(),
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        assert_eq!(resp.exit_code, 0);
        let nonce = resp.stdout.trim();
        assert!(nonce.starts_with("nono_"), "expected nonce, got: {}", nonce);
        let resolved = broker
            .resolve(nonce, &test_consumer())
            .expect("nonce should be in broker");
        assert_eq!(resolved.as_str(), "my_secret_token");
    }

    // --- Env filtering tests ---

    #[test]
    fn test_build_exec_env_forwards_context_vars_and_blocks_dangerous() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        // Dangerous vars must never be forwarded.
        sandbox_env.insert("PATH".to_string(), "/evil".to_string());
        sandbox_env.insert("LD_PRELOAD".to_string(), "/evil.so".to_string());
        // Non-dangerous context vars (e.g. from kubectl exec plugin config) should
        // be forwarded when not already in the parent env. Use an unlikely-to-exist key.
        sandbox_env.insert(
            "NONO_TEST_CONTEXT_12345".to_string(),
            "context_value".to_string(),
        );

        let env = build_exec_env(&sandbox_env, &broker, &test_consumer(), None);

        // Dangerous vars must not be injected from sandbox.
        assert_ne!(env.get("PATH").map(|s| s.as_str()), Some("/evil"));
        assert_ne!(env.get("LD_PRELOAD").map(|s| s.as_str()), Some("/evil.so"));
        // Non-dangerous context var should be forwarded.
        assert_eq!(
            env.get("NONO_TEST_CONTEXT_12345").map(|s| s.as_str()),
            Some("context_value")
        );
    }

    #[test]
    fn test_build_exec_env_promotes_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("real_credential".to_string()), test_grants());

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("GH_TOKEN".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker, &test_consumer(), None);
        assert_eq!(
            env.get("GH_TOKEN").map(|s| s.as_str()),
            Some("real_credential")
        );
    }

    #[test]
    fn test_build_exec_env_blocks_dangerous_var_even_with_valid_nonce() {
        let broker = make_broker();
        let nonce = broker.issue(Zeroizing::new("/evil/path".to_string()), test_grants());

        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("PATH".to_string(), nonce.clone());
        sandbox_env.insert("LD_PRELOAD".to_string(), nonce.clone());

        let env = build_exec_env(&sandbox_env, &broker, &test_consumer(), None);
        // PATH from sandbox must not be the injected value (parent PATH is used instead)
        assert_ne!(env.get("PATH").map(|s| s.as_str()), Some("/evil/path"));
        // LD_PRELOAD should not have been injected
        assert_ne!(
            env.get("LD_PRELOAD").map(|s| s.as_str()),
            Some("/evil/path")
        );
    }

    #[test]
    fn test_build_exec_env_leaves_unknown_nonce_in_place() {
        let broker = make_broker();
        let mut sandbox_env = HashMap::new();
        // A nonce-shaped value that was never issued by this broker.
        let unknown =
            "nono_0000000000000000000000000000000000000000000000000000000000000000".to_string();
        sandbox_env.insert("MY_TOKEN".to_string(), unknown.clone());

        let env = build_exec_env(&sandbox_env, &broker, &test_consumer(), None);
        // Substring promotion: unknown nonces are passed through verbatim
        // rather than discarded. The sandbox can probe shape but cannot recover
        // any issued nonce this way.
        assert_eq!(
            env.get("MY_TOKEN").map(|s| s.as_str()),
            Some(unknown.as_str())
        );
    }

    // --- Per-command proxy tests ---

    /// When `allowed_hosts` is configured, exec_passthrough injects HTTPS_PROXY
    /// pointing to 127.0.0.1 into the environment passed to the command.
    #[tokio::test]
    async fn test_allowed_hosts_injects_https_proxy() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: false,
                allow_process_exec: false,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // `env` prints its own environment; grep output for HTTPS_PROXY
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        // The command ran (exit 0) and output should contain HTTPS_PROXY pointing to 127.0.0.1
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "HTTPS_PROXY not found in env output: {}",
            resp.stdout
        );
        assert!(
            resp.stdout.contains("127.0.0.1"),
            "proxy addr not 127.0.0.1: {}",
            resp.stdout
        );
    }

    /// When `block: true` and `allowed_hosts` is also set, `block` takes
    /// precedence: no proxy is started, network is blocked at OS level.
    /// We verify this by checking the env printed by the child does NOT
    /// contain an HTTPS_PROXY entry.
    #[tokio::test]
    async fn test_block_takes_precedence_over_allowed_hosts() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: false,
                allow_process_exec: false,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;
        // Command may fail due to sandbox (network block applies via pre_exec),
        // but crucially HTTPS_PROXY must NOT have been injected.
        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "HTTPS_PROXY should not be set when block=true, got: {}",
            resp.stdout
        );
    }

    /// A `Allow` rule with `sandbox: ExplicitlyUnsandboxed` runs the real
    /// binary without applying the command-level sandbox. This is the
    /// replacement for the legacy `Approve` action: profile authors who want
    /// "real binary, no sandbox" use `Allow` with `"sandbox": null`.
    ///
    /// We verify by checking that HTTPS_PROXY is NOT injected even when the
    /// command-level sandbox has `allowed_hosts` configured, proving the
    /// command-level sandbox was skipped in favour of the rule's binding.
    #[tokio::test]
    async fn test_allow_explicitly_unsandboxed_skips_command_sandbox() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![ResolvedIntercept {
                id: None,
                matcher: ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
                promote_filter: None,
            }],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: false,
                allow_process_exec: false,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        // HTTPS_PROXY must NOT be present — Allow with ExplicitlyUnsandboxed
        // skips the command-level sandbox.
        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "Allow with ExplicitlyUnsandboxed should NOT apply per-command sandbox, but HTTPS_PROXY found: {}",
            resp.stdout
        );
    }

    // --- keychain_access tests ---

    /// Passthrough with `keychain_access: true` and `allowed_hosts` runs
    /// successfully and still applies network restrictions (HTTPS_PROXY).
    /// Proves keychain_access doesn't break the sandbox or disable network filtering.
    #[tokio::test]
    async fn test_passthrough_keychain_access_with_allowed_hosts() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: true,
                allow_process_exec: false,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "keychain_access should not disable network restrictions, HTTPS_PROXY missing: {}",
            resp.stdout
        );
    }

    /// Passthrough with `keychain_access: false` (default) and `allowed_hosts`
    /// preserves existing behavior: runs successfully with network restrictions.
    #[tokio::test]
    async fn test_passthrough_keychain_access_false_default() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: false,
                    allowed_hosts: vec!["api.github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: false,
                allow_process_exec: false,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "Default keychain_access=false should still apply network restrictions: {}",
            resp.stdout
        );
    }

    /// `keychain_access: true` with `network.block: true` — block takes
    /// precedence, no proxy started, HTTPS_PROXY not injected.
    /// Proves keychain_access doesn't interfere with network block mode.
    #[tokio::test]
    async fn test_keychain_access_does_not_disable_network_block() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec!["github.com".to_string()],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: true,
                allow_process_exec: false,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;

        assert!(
            !resp.stdout.contains("HTTPS_PROXY=http://nono:"),
            "keychain_access should not override network block, but HTTPS_PROXY found: {}",
            resp.stdout
        );
    }

    // --- allow_process_exec tests ---

    /// Default per-command sandbox (allow_process_exec: false) blocks subprocess
    /// spawning at the Seatbelt layer. This closes the ssh ProxyCommand exfil
    /// class — a sandbox that grants ~/.ssh fs_read cannot launch /bin/sh to
    /// smuggle key material out.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_per_command_sandbox_denies_subprocess_by_default() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec![],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: false,
                allow_process_exec: false,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["/usr/bin/true".to_string()],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "allow");
        // /bin/sh runs (its path is allowed via real_path) but cannot launch
        // /usr/bin/true; sh reports non-zero exit.
        assert_ne!(
            resp.exit_code, 0,
            "expected sh to fail launching /usr/bin/true under deny-by-default; stdout={} stderr={}",
            resp.stdout, resp.stderr
        );
    }

    /// `allow_process_exec: true` lifts the deny so a command can shell out to
    /// helpers freely. Used by trusted commands with helper sprawl (git, gh, aws,
    /// kubectl, etc.) where enumerating every helper is impractical.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_per_command_sandbox_allows_subprocess_when_opted_in() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec![],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: false,
                allow_process_exec: true,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["/usr/bin/true".to_string()],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;

        assert_eq!(action_type, "allow");
        assert_eq!(
            resp.exit_code, 0,
            "expected sh -c /usr/bin/true to succeed with allow_process_exec=true; stderr={}",
            resp.stderr
        );
    }

    /// Regression: `allow_process_exec: true` does not bypass the filesystem sandbox.
    ///
    /// git (and similar commands) carry `allow_process_exec: true` so they can run
    /// hooks and credential helpers. The risk is that a subprocess spawned by git
    /// (e.g. ssh via a ProxyCommand) could read sensitive files such as `~/.ssh`
    /// private keys. This test verifies that even with `allow_process_exec: true`,
    /// the per-command filesystem grants still bound what subprocesses can read.
    ///
    /// We write a sentinel file to `$HOME` (outside system_read_macos paths like
    /// /tmp and /var) and verify a subprocess spawned inside a sandbox that does not
    /// grant `$HOME` read access cannot exfiltrate it.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn test_allow_process_exec_does_not_bypass_fs_sandbox() {
        use crate::mediation::CommandSandbox;
        use crate::mediation::NetworkConfig;

        let sentinel_value = "NONO_FS_SENTINEL_12345";

        // Hold ENV_LOCK while reading HOME: other tests (rollback_runtime,
        // exec_strategy) temporarily set HOME to a /tmp path while holding
        // this lock. If we read HOME concurrently without the lock we may get
        // a temp path that is inside system_read_macos (/tmp, /var) and the
        // sentinel would be readable, causing a false failure.
        let sentinel_path: String = {
            let _lock = crate::test_env::ENV_LOCK.lock().expect("env lock");
            let home = std::env::var("HOME").expect("HOME must be set");
            // If HOME is a temp dir (set by a parallel test) the sentinel
            // would land in a system-readable location — skip the test.
            if home.starts_with("/tmp")
                || home.starts_with("/private/tmp")
                || home.starts_with("/var")
            {
                return;
            }
            let dir = format!("{}/.nono-test-regression-{}", home, std::process::id());
            std::fs::create_dir_all(&dir).expect("create sentinel dir");
            let path = format!("{}/secret", dir);
            std::fs::write(&path, sentinel_value).expect("write sentinel");
            path
            // lock drops here
        };
        let sentinel_dir = std::path::Path::new(&sentinel_path)
            .parent()
            .expect("sentinel has parent")
            .to_path_buf();

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![],
            sandbox: Some(CommandSandbox {
                network: NetworkConfig {
                    block: true,
                    allowed_hosts: vec![],
                },
                fs_read: vec![],
                fs_read_file: vec![],
                fs_write: vec![],
                fs_write_file: vec![],
                keychain_access: false,
                allow_process_exec: true,
            }),
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "sh".to_string(),
                "-c".to_string(),
                format!("cat '{}' 2>/dev/null; echo done", sentinel_path),
            ],
            session_token: String::new(),
            env: HashMap::new(),
            pid: 0,
            cwd: None,
        };

        let broker = make_broker();
        let (resp, _action_type) = apply_capture(
            req,
            &[cmd],
            Arc::clone(&broker),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
        )
        .await;

        let _ = std::fs::remove_dir_all(&sentinel_dir);

        assert!(
            !resp.stdout.contains(sentinel_value),
            "subprocess with allow_process_exec: true read a file outside fs_read grants \
             (git ProxyCommand bypass); stdout={}",
            resp.stdout
        );
    }

    // --- Streaming passthrough fd-protocol tests ---

    /// Pipe binary data (every byte 0x00..=0xFF, including 0xFF) through the
    /// child's stdin and read it back via stdout. Verifies the new SCM_RIGHTS
    /// path streams bytes unchanged — no UTF-8 lossy conversion, no 50ms
    /// stdin truncation, no buffering.
    #[tokio::test]
    async fn test_passthrough_streams_binary_stdin_unchanged() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/bin/cat"),

            pin: real_pin(&PathBuf::from("/bin/cat")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let (child_in, mut test_in) = UnixStream::pair().expect("pair stdin");
        let (child_out, test_out) = UnixStream::pair().expect("pair stdout");
        let (child_err, _test_err) = UnixStream::pair().expect("pair stderr");

        // 4 KiB of binary data covering every byte value, including 0xFF.
        let payload: Vec<u8> = (0u32..4096).map(|i| (i & 0xff) as u8).collect();

        // Drain stdout in a thread so cat doesn't block on a full buffer.
        let payload_clone = payload.clone();
        let drain = std::thread::spawn(move || {
            use std::io::Read;
            let mut received = Vec::with_capacity(payload_clone.len());
            let mut r = test_out;
            let _ = r.read_to_end(&mut received);
            received
        });

        // Write the payload, then close the writer so cat sees EOF and exits.
        test_in.write_all(&payload).expect("write payload");
        drop(test_in);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let (resp, action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
        )
        .await;

        assert_eq!(action_type, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        // Streaming path: the response carries no buffered output.
        assert!(
            resp.stdout.is_empty(),
            "expected empty resp.stdout in streaming mode, got {} bytes",
            resp.stdout.len()
        );
        assert!(
            resp.stderr.is_empty(),
            "expected empty resp.stderr in streaming mode, got {} bytes",
            resp.stderr.len()
        );

        let received = drain.join().expect("drain thread");
        assert_eq!(
            received,
            payload,
            "binary payload corrupted: lengths {} vs {}",
            received.len(),
            payload.len()
        );
    }

    /// Capture/Deny/Approve paths drop the passed fds and produce buffered
    /// output via the response. Verifies the dropped fds let the test side
    /// see EOF (no hang) and that the buffered stdout flows through normally.
    #[tokio::test]
    async fn test_buffered_paths_drop_passed_fds_and_buffer_output() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![ResolvedArgsMatcher::AnyArgMatches(
                ::regex::Regex::new("^auth$").unwrap(),
            )]),
            action: ResolvedAction::Deny {
                stdout: "buffered_response\n".to_string(),
                stderr: String::new(),
                exit_code: 0,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);

        let (child_in, _test_in) = UnixStream::pair().expect("pair stdin");
        let (child_out, mut test_out) = UnixStream::pair().expect("pair stdout");
        let (child_err, _test_err) = UnixStream::pair().expect("pair stderr");

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string()],
            session_token: String::new(),
            ..Default::default()
        };

        let (resp, action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
        )
        .await;

        assert_eq!(action_type, "deny");
        assert_eq!(resp.stdout, "buffered_response\n");

        // The Deny path dropped the child_out fd, so the test side
        // immediately sees EOF — read_to_end returns 0 bytes without
        // hanging because there are no other writers on the socketpair.
        let mut buf = Vec::new();
        let _ = test_out.read_to_end(&mut buf);
        assert!(
            buf.is_empty(),
            "Deny path should not write anything to passed stdout fd, got {:?}",
            buf
        );
    }

    /// Passthrough spawns the real binary with the caller's cwd from
    /// `ShimRequest.cwd`, not the mediation server's own cwd. Regression test
    /// for the worktree bug where `git` from a Claude worktree silently
    /// resolved to the main repo because the spawn inherited the server's
    /// launch cwd.
    #[tokio::test]
    async fn test_passthrough_uses_request_cwd() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        // Use /bin/pwd because it prints its cwd and exits — independent of
        // any external binary on PATH.
        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/bin/pwd"),

            pin: real_pin(&PathBuf::from("/bin/pwd")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        // Use a tempdir as the caller cwd so it differs from whatever cwd the
        // test runner has. Canonicalise because /bin/pwd resolves symlinks
        // (e.g. /tmp -> /private/tmp on macOS).
        let temp = tempfile::tempdir().expect("tempdir");
        let caller_cwd = std::fs::canonicalize(temp.path())
            .expect("canonicalize tempdir")
            .to_string_lossy()
            .into_owned();

        let (child_in, _test_in) = UnixStream::pair().expect("pair stdin");
        let (child_out, mut test_out) = UnixStream::pair().expect("pair stdout");
        let (child_err, _test_err) = UnixStream::pair().expect("pair stderr");

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![],
            session_token: String::new(),
            cwd: Some(caller_cwd.clone()),
            ..Default::default()
        };

        let (resp, action_type) = apply(
            req,
            &[cmd],
            make_broker(),
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["testcmd".to_string()],
            },
            always_allow(),
            OwnedFd::from(child_in),
            OwnedFd::from(child_out),
            OwnedFd::from(child_err),
        )
        .await;

        assert_eq!(action_type, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);

        let mut buf = Vec::new();
        let _ = test_out.read_to_end(&mut buf);
        let pwd_output = String::from_utf8(buf).expect("utf8 pwd output");
        assert_eq!(
            pwd_output.trim_end(),
            caller_cwd,
            "pwd should print the caller's cwd from ShimRequest.cwd"
        );
    }

    // --- promote_nonces_in_str ---

    #[test]
    fn promote_nonces_substitutes_pure_nonce_arg() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("real-token".to_string()), test_grants());
        assert_eq!(
            promote_nonces_in_str(&nonce, &broker, &test_consumer(), true),
            "real-token"
        );
    }

    #[test]
    fn promote_nonces_substitutes_embedded_nonce() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("real-token".to_string()), test_grants());
        let arg = format!("X-Token: {}", nonce);
        assert_eq!(
            promote_nonces_in_str(&arg, &broker, &test_consumer(), true),
            "X-Token: real-token"
        );
    }

    #[test]
    fn promote_nonces_substitutes_multiple_nonces_in_one_arg() {
        let broker = TokenBroker::new();
        let a = broker.issue(Zeroizing::new("AAA".to_string()), test_grants());
        let b = broker.issue(Zeroizing::new("BBB".to_string()), test_grants());
        let arg = format!("first={} second={}", a, b);
        assert_eq!(
            promote_nonces_in_str(&arg, &broker, &test_consumer(), true),
            "first=AAA second=BBB"
        );
    }

    #[test]
    fn promote_nonces_leaves_malformed_prefix_alone() {
        let broker = TokenBroker::new();
        // Too few hex chars after the prefix — not a valid nonce shape.
        let arg = "nono_abc123";
        assert_eq!(promote_nonces_in_str(arg, &broker, &test_consumer(), true), arg);
        // Prefix followed by non-hex characters in the 64-char window.
        let arg2 = format!("nono_{}", "z".repeat(64));
        assert_eq!(
            promote_nonces_in_str(&arg2, &broker, &test_consumer(), true),
            arg2
        );
        // Uppercase hex must not match — broker only emits lowercase.
        let arg3 = format!("nono_{}", "A".repeat(64));
        assert_eq!(
            promote_nonces_in_str(&arg3, &broker, &test_consumer(), true),
            arg3
        );
    }

    #[test]
    fn promote_nonces_leaves_unknown_nonce_alone() {
        let broker = TokenBroker::new();
        // Shape is valid but the nonce was never issued.
        let arg = format!("nono_{}", "a".repeat(64));
        assert_eq!(promote_nonces_in_str(&arg, &broker, &test_consumer(), true), arg);
    }

    #[test]
    fn promote_nonces_preserves_surrounding_text() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("XYZ".to_string()), test_grants());
        let arg = format!("prefix-{}-suffix", nonce);
        assert_eq!(
            promote_nonces_in_str(&arg, &broker, &test_consumer(), true),
            "prefix-XYZ-suffix"
        );
    }

    #[test]
    fn promote_nonces_no_match_returns_original() {
        let broker = TokenBroker::new();
        assert_eq!(
            promote_nonces_in_str("plain string", &broker, &test_consumer(), true),
            "plain string"
        );
        assert_eq!(promote_nonces_in_str("", &broker, &test_consumer(), true), "");
    }

    /// `allow=false` short-circuits before any nonce scanning. Used by the
    /// per-arg / per-env-key filter wiring so the per-slot decision happens
    /// one scope up.
    #[test]
    fn promote_nonces_allow_false_returns_input_verbatim() {
        let broker = TokenBroker::new();
        let nonce = broker.issue(Zeroizing::new("real-token".to_string()), test_grants());
        let arg = format!("Authorization: Bearer {}", nonce);
        // allow=true promotes
        assert_eq!(
            promote_nonces_in_str(&arg, &broker, &test_consumer(), true),
            "Authorization: Bearer real-token"
        );
        // allow=false leaves verbatim — same string, including the nonce
        assert_eq!(
            promote_nonces_in_str(&arg, &broker, &test_consumer(), false),
            arg
        );
    }

    #[test]
    fn build_exec_env_promotes_substring_in_value() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("jwt-body".to_string()), test_grants());
        let mut sandbox_env = HashMap::new();
        sandbox_env.insert(
            "AUTH_HEADER".to_string(),
            format!("Authorization: Bearer {}", nonce),
        );
        let env = build_exec_env(&sandbox_env, &broker, &test_consumer(), None);
        assert_eq!(
            env.get("AUTH_HEADER").map(String::as_str),
            Some("Authorization: Bearer jwt-body"),
        );
    }

    #[test]
    fn build_exec_env_still_blocks_dangerous_names() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("evil".to_string()), test_grants());
        let mut sandbox_env = HashMap::new();
        sandbox_env.insert("LD_PRELOAD".to_string(), nonce.clone());
        // SAFE matches no safe-shape pattern in the built-in default, so
        // it stays literal — the nonce flows through verbatim, the var
        // still flows through (only the promotion is suppressed).
        sandbox_env.insert("SAFE".to_string(), nonce.clone());
        let env = build_exec_env(&sandbox_env, &broker, &test_consumer(), None);
        assert!(!env.contains_key("LD_PRELOAD"));
        // SAFE flows through but the nonce stays literal.
        assert_eq!(env.get("SAFE").map(String::as_str), Some(nonce.as_str()));
    }

    /// Built-in env default: any *_HEADER name flows promotion when no
    /// filter is set. AUTH_HEADER matches the `.+_header` pattern.
    #[test]
    fn build_exec_env_default_admits_safe_shape_names() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("jwt".to_string()), test_grants());
        let mut env_in = HashMap::new();
        env_in.insert(
            "AUTH_HEADER".to_string(),
            format!("Bearer {}", nonce),
        );
        env_in.insert("X_TOKEN".to_string(), nonce.clone());
        let env = build_exec_env(&env_in, &broker, &test_consumer(), None);
        assert_eq!(env.get("AUTH_HEADER").map(String::as_str), Some("Bearer jwt"));
        assert_eq!(env.get("X_TOKEN").map(String::as_str), Some("jwt"));
    }

    /// Built-in env default: random names like MY_VAR are NOT admitted —
    /// nonce stays literal.
    #[test]
    fn build_exec_env_default_rejects_random_names() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("real".to_string()), test_grants());
        let mut env_in = HashMap::new();
        env_in.insert("MY_VAR".to_string(), nonce.clone());
        let env = build_exec_env(&env_in, &broker, &test_consumer(), None);
        assert_eq!(env.get("MY_VAR").map(String::as_str), Some(nonce.as_str()));
    }

    /// Built-in env default is case-insensitive — lowercase
    /// `authorization` admits.
    #[test]
    fn build_exec_env_default_is_case_insensitive() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("real".to_string()), test_grants());
        let mut env_in = HashMap::new();
        env_in.insert("authorization".to_string(), format!("Bearer {}", nonce));
        let env = build_exec_env(&env_in, &broker, &test_consumer(), None);
        assert_eq!(
            env.get("authorization").map(String::as_str),
            Some("Bearer real")
        );
    }

    /// Explicit env predicate REPLACES the built-in default — when set,
    /// only the predicate decides. AUTH_HEADER is no longer in play.
    #[test]
    fn build_exec_env_explicit_predicate_replaces_default() {
        use crate::mediation::PromoteFilter;
        let broker = Arc::new(TokenBroker::new());
        let nonce_a = broker.issue(Zeroizing::new("AAA".to_string()), test_grants());
        let nonce_b = broker.issue(Zeroizing::new("BBB".to_string()), test_grants());
        let p: PromoteFilter = serde_json::from_value(serde_json::json!({
            "env": { "name_matches": "^MY_VAR$" }
        }))
        .unwrap();
        let filter =
            crate::mediation::promote::compile_promote_filter(&p, "echo").expect("compile");

        let mut env_in = HashMap::new();
        env_in.insert(
            "AUTH_HEADER".to_string(),
            format!("Bearer {}", nonce_a),
        );
        env_in.insert("MY_VAR".to_string(), nonce_b.clone());
        let env = build_exec_env(&env_in, &broker, &test_consumer(), Some(&filter));
        // AUTH_HEADER no longer auto-promotes — the explicit predicate replaced
        // the default and only admits MY_VAR.
        assert_eq!(
            env.get("AUTH_HEADER").map(String::as_str),
            Some(format!("Bearer {}", nonce_a).as_str()),
        );
        assert_eq!(env.get("MY_VAR").map(String::as_str), Some("BBB"));
    }

    /// Documented widening pattern: union the default regex with a custom
    /// name to keep the safe-shape allowlist AND admit a bespoke env var.
    #[test]
    fn build_exec_env_explicit_predicate_can_union_default() {
        use crate::mediation::{PromoteFilter, promote::PROMOTE_ENV_DEFAULT_NAMES};
        let broker = Arc::new(TokenBroker::new());
        let nonce_a = broker.issue(Zeroizing::new("AAA".to_string()), test_grants());
        let nonce_b = broker.issue(Zeroizing::new("BBB".to_string()), test_grants());
        let p: PromoteFilter = serde_json::from_value(serde_json::json!({
            "env": {
                "any_of": [
                    { "name_matches": PROMOTE_ENV_DEFAULT_NAMES },
                    { "name_matches": "^MY_CUSTOM_NONCE_VAR$" }
                ]
            }
        }))
        .unwrap();
        let filter =
            crate::mediation::promote::compile_promote_filter(&p, "echo").expect("compile");

        let mut env_in = HashMap::new();
        env_in.insert(
            "AUTH_HEADER".to_string(),
            format!("Bearer {}", nonce_a),
        );
        env_in.insert("MY_CUSTOM_NONCE_VAR".to_string(), nonce_b);
        let env = build_exec_env(&env_in, &broker, &test_consumer(), Some(&filter));
        assert_eq!(env.get("AUTH_HEADER").map(String::as_str), Some("Bearer AAA"));
        assert_eq!(
            env.get("MY_CUSTOM_NONCE_VAR").map(String::as_str),
            Some("BBB")
        );
    }

    /// `not` env predicate inverts: promotes everywhere except the named
    /// one.
    #[test]
    fn build_exec_env_not_env_predicate_inverts() {
        use crate::mediation::PromoteFilter;
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("real".to_string()), test_grants());
        let p: PromoteFilter = serde_json::from_value(serde_json::json!({
            "env": { "not": { "name_matches": "^DD_API_KEY$" } }
        }))
        .unwrap();
        let filter =
            crate::mediation::promote::compile_promote_filter(&p, "echo").expect("compile");

        let mut env_in = HashMap::new();
        env_in.insert("DD_API_KEY".to_string(), nonce.clone());
        env_in.insert("ANY".to_string(), nonce.clone());
        let env = build_exec_env(&env_in, &broker, &test_consumer(), Some(&filter));
        // DD_API_KEY: not(name=DD_API_KEY) → false → no promotion.
        assert_eq!(
            env.get("DD_API_KEY").map(String::as_str),
            Some(nonce.as_str()),
        );
        // ANY: not(name=DD_API_KEY) → true → promote.
        assert_eq!(env.get("ANY").map(String::as_str), Some("real"));
    }

    /// args-only filter still uses the built-in env default — the env
    /// scope is independent of the args scope.
    #[test]
    fn build_exec_env_args_only_filter_still_uses_default() {
        use crate::mediation::PromoteFilter;
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("real".to_string()), test_grants());
        let p: PromoteFilter = serde_json::from_value(serde_json::json!({
            "args": { "self_matches": "^-H" }
        }))
        .unwrap();
        let filter =
            crate::mediation::promote::compile_promote_filter(&p, "echo").expect("compile");

        let mut env_in = HashMap::new();
        env_in.insert(
            "AUTH_HEADER".to_string(),
            format!("Bearer {}", nonce),
        );
        env_in.insert("MY_VAR".to_string(), nonce.clone());
        let env = build_exec_env(&env_in, &broker, &test_consumer(), Some(&filter));
        // AUTH_HEADER still promotes via the built-in default.
        assert_eq!(env.get("AUTH_HEADER").map(String::as_str), Some("Bearer real"));
        // MY_VAR doesn't.
        assert_eq!(env.get("MY_VAR").map(String::as_str), Some(nonce.as_str()));
    }

    /// A `Allow` intercept runs the real binary the same way the
    /// no-intercept-matched fall-through does. We point `real_path` at
    /// `/bin/echo` and check that its stdout reaches the streamed response.
    #[tokio::test]
    async fn test_allow_intercept_streams_real_binary() {
        let cmd = ResolvedCommand {
            name: "echo".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![ResolvedIntercept {
                id: None,
                matcher: crate::mediation::matcher::ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
                promote_filter: None,
            }],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(
            resp.stdout.contains("hello"),
            "expected echo output, got: {:?}",
            resp.stdout
        );
    }

    // ------------------------------------------------------------------
    // Per-arg promotion filter (promote_in.args)
    //
    // These tests use /bin/echo as the real binary so the streamed stdout
    // shows exactly which argv slots the filter promoted (real token) vs
    // left literal (`nono_<hex>`).
    // ------------------------------------------------------------------

    /// Builds an echo-backed ResolvedCommand whose single matching rule
    /// carries the given `promote_filter`. The grant is permissive across
    /// the consumer contexts we exercise so the grant gate is not the
    /// bottleneck — only the filter.
    fn echo_cmd_with_filter(
        promote_filter: Option<crate::mediation::promote::ResolvedPromoteFilter>,
    ) -> ResolvedCommand {
        ResolvedCommand {
            name: "echo".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![ResolvedIntercept {
                id: Some("filtered".to_string()),
                matcher: crate::mediation::matcher::ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
                promote_filter,
            }],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        }
    }

    fn echo_grants() -> GrantSet {
        GrantSet::Allow(vec![GrantDescriptor {
            command: "echo".to_string(),
            intercept_id: "filtered".to_string(),
        }])
    }

    fn compile(filter_json: serde_json::Value) -> crate::mediation::promote::ResolvedPromoteFilter {
        let p: crate::mediation::PromoteFilter =
            serde_json::from_value(filter_json).expect("parse");
        crate::mediation::promote::compile_promote_filter(&p, "echo").expect("compile")
    }

    /// Test 1: separate-arg `["-H", "Authorization: Bearer nono_X"]` with
    /// `preceded_by_arg: ^-H$` promotes the value slot.
    #[tokio::test]
    async fn promote_args_separate_form_promotes_value_slot() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("real-tok".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": { "preceded_by_arg": "^-H$" }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec![
                "-H".to_string(),
                format!("Authorization: Bearer {}", nonce),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(
            resp.stdout.contains("real-tok"),
            "value slot must contain promoted token, got: {:?}",
            resp.stdout
        );
        assert!(
            !resp.stdout.contains("nono_"),
            "no nonce should remain literal, got: {:?}",
            resp.stdout
        );
    }

    /// Test 2: attached form `["-Hnono_X"]` with `self_matches: ^-H`
    /// promotes the single slot.
    #[tokio::test]
    async fn promote_args_attached_form_promotes_self_slot() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("attached-tok".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": { "self_matches": "^-H" }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec![format!("-H{}", nonce)],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(
            resp.stdout.contains("attached-tok"),
            "attached -H slot must promote, got: {:?}",
            resp.stdout
        );
    }

    /// Test 3: long-equals form `["--header=Authorization: Bearer nono_X"]`
    /// with `self_matches: ^--header=` promotes.
    #[tokio::test]
    async fn promote_args_long_equals_form_promotes() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("eq-tok".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": { "self_matches": "^--header=" }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec![format!("--header=Authorization: Bearer {}", nonce)],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(
            resp.stdout.contains("eq-tok"),
            "long-equals slot must promote, got: {:?}",
            resp.stdout
        );
    }

    /// Test 4: a `--data-binary` body slot must NOT promote when the filter
    /// only admits `-H` predecessors.
    #[tokio::test]
    async fn promote_args_body_slot_stays_literal() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("body-tok".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": { "preceded_by_arg": "^-H$" }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec![
                "--data-binary".to_string(),
                format!("X: {}", nonce),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        // The body slot predecessor is "--data-binary", not "-H" → filter
        // rejects. Nonce stays literal in the streamed output.
        assert!(
            !resp.stdout.contains("body-tok"),
            "body slot must NOT promote, got: {:?}",
            resp.stdout
        );
        assert!(
            resp.stdout.contains("nono_"),
            "literal nonce must remain, got: {:?}",
            resp.stdout
        );
    }

    /// Test 5: upload-file `["-T", "/tmp/nono_X.bin"]` keeps the path
    /// literal under a header-only filter.
    #[tokio::test]
    async fn promote_args_upload_path_stays_literal() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("upload-tok".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": { "preceded_by_arg": "^-H$" }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["-T".to_string(), format!("/tmp/{}.bin", nonce)],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(
            !resp.stdout.contains("upload-tok"),
            "upload-file path must NOT promote, got: {:?}",
            resp.stdout
        );
    }

    /// Test 6: `any_of` combinator admits both attached and separate forms.
    #[tokio::test]
    async fn promote_args_any_of_covers_both_header_forms() {
        let broker = Arc::new(TokenBroker::new());
        let nonce_a = broker.issue(Zeroizing::new("AAA".to_string()), echo_grants());
        let nonce_b = broker.issue(Zeroizing::new("BBB".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": {
                "any_of": [
                    { "preceded_by_arg": "^(-H|--header)$" },
                    { "self_matches":    "^(-H|--header=)" }
                ]
            }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec![
                "-H".to_string(),
                format!("Bearer {}", nonce_a),
                format!("--header=X-Other: {}", nonce_b),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(resp.stdout.contains("AAA"));
        assert!(resp.stdout.contains("BBB"));
    }

    /// Test 7: `not` combinator that inverts a body-slot rule promotes
    /// everywhere except after body flags.
    #[tokio::test]
    async fn promote_args_not_body_inverts_correctly() {
        let broker = Arc::new(TokenBroker::new());
        let body_nonce = broker.issue(Zeroizing::new("REAL-BODY-X".to_string()), echo_grants());
        let header_nonce = broker.issue(Zeroizing::new("REAL-HDR-Y".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": {
                "not": {
                    "preceded_by_arg": "^(-d|--data-binary)$"
                }
            }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec![
                "--data-binary".to_string(),
                body_nonce,
                "-H".to_string(),
                format!("Bearer {}", header_nonce),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        // Body slot promoted? No — `not(preceded_by_arg=^(-d|--data-binary)$)`
        // evaluates false there, so the nonce stays literal.
        assert!(
            !resp.stdout.contains("REAL-BODY-X"),
            "body slot must stay literal, got: {:?}",
            resp.stdout
        );
        // Header slot promotes — predecessor is `-H`, not a body flag.
        assert!(
            resp.stdout.contains("REAL-HDR-Y"),
            "header slot must promote, got: {:?}",
            resp.stdout
        );
    }

    /// Test 8: secure default — a rule with no `promote_in` field gets no
    /// argv promotion at all, even when a valid nonce is present.
    /// Documents the breaking change.
    #[tokio::test]
    async fn promote_args_secure_default_no_filter_no_promotion() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("would-be-real".to_string()), echo_grants());
        // No filter on the rule.
        let cmd = echo_cmd_with_filter(None);
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["-H".to_string(), format!("Bearer {}", nonce)],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(
            !resp.stdout.contains("would-be-real"),
            "no promotion expected with secure default, got: {:?}",
            resp.stdout
        );
        assert!(
            resp.stdout.contains("nono_"),
            "literal nonce must survive, got: {:?}",
            resp.stdout
        );
    }

    /// Test 9: an `env`-only filter (no `args` sub-field) still gets the
    /// secure-default argv behaviour — no argv slot promotes.
    #[tokio::test]
    async fn promote_args_env_only_filter_no_argv_promotion() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("real-tok".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "env": { "name_matches": "^AUTH_HEADER$" }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["-H".to_string(), format!("Bearer {}", nonce)],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(
            !resp.stdout.contains("real-tok"),
            "env-only filter must NOT enable argv promotion, got: {:?}",
            resp.stdout
        );
    }

    /// Test 10: empty `any_of: []` never promotes — defensive lock test.
    #[tokio::test]
    async fn promote_args_empty_any_of_never_promotes() {
        let broker = Arc::new(TokenBroker::new());
        let nonce = broker.issue(Zeroizing::new("lock".to_string()), echo_grants());
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": { "any_of": [] }
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["-H".to_string(), format!("Bearer {}", nonce)],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(!resp.stdout.contains("lock"));
    }

    /// Test 11: filter × grant interaction — if the grant rejects the
    /// consumer, the filter is irrelevant. Grant gate stays primary.
    #[tokio::test]
    async fn promote_args_grant_rejection_overrides_admitting_filter() {
        let broker = Arc::new(TokenBroker::new());
        // Issue a nonce whose grant excludes the echo.filtered consumer.
        let other_grants = GrantSet::Allow(vec![GrantDescriptor {
            command: "other".to_string(),
            intercept_id: "default".to_string(),
        }]);
        let nonce = broker.issue(Zeroizing::new("never-leak".to_string()), other_grants);
        let cmd = echo_cmd_with_filter(Some(compile(serde_json::json!({
            "args": { "self_matches": ".*" } // admit every slot
        }))));
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec![format!("Bearer {}", nonce)],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) = apply_capture(req, &[cmd], broker, &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        // Filter admits, but grant denies → nonce stays literal.
        assert!(
            !resp.stdout.contains("never-leak"),
            "grant must reject regardless of filter, got: {:?}",
            resp.stdout
        );
        assert!(
            resp.stdout.contains("nono_"),
            "literal nonce must survive, got: {:?}",
            resp.stdout
        );
    }

    /// Per-intercept `sandbox` overrides the command-level `sandbox` for a
    /// single `Allow` invocation. The matching intercept here carries a
    /// tight sandbox (`network.block = true`); the command-level sandbox is
    /// permissive (default). The exec target `/bin/echo` does not touch the
    /// network, so the test cannot directly observe which sandbox was
    /// applied — but it verifies that the wiring compiles and runs without
    /// error. An end-to-end test that observes the per-intercept proxy
    /// starting (`test_per_intercept_sandbox_starts_proxy`) is the follow-up.
    #[tokio::test]
    async fn test_allow_uses_per_intercept_sandbox() {
        use crate::mediation::{CommandSandbox, NetworkConfig};

        let tight = CommandSandbox {
            network: NetworkConfig {
                block: true,
                allowed_hosts: vec![],
            },
            ..CommandSandbox::default()
        };

        let cmd = ResolvedCommand {
            name: "echo".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![ResolvedIntercept {
                id: None,
                matcher: crate::mediation::matcher::ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                sandbox: ResolvedSandboxBinding::Explicit(tight.clone()),
                promote_filter: None,
            }],
            sandbox: Some(CommandSandbox::default()), // permissive
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["ok".to_string()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(resp.stdout.contains("ok"));
    }

    /// Extracts the HTTPS_PROXY value from a printenv/env stdout dump.
    fn extract_https_proxy(stdout: &str) -> Option<String> {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix("HTTPS_PROXY=").map(str::to_string))
    }

    /// End-to-end mirror of `test_allowed_hosts_injects_https_proxy`, except
    /// the `allowed_hosts` policy lives on the matched intercept's `sandbox`,
    /// not on the command-level `sandbox`. This exercises the per-intercept
    /// override path: `cmd.sandbox` is `None`, so it is the intercept's
    /// sandbox that causes the proxy to start.
    #[tokio::test]
    async fn test_per_intercept_sandbox_starts_proxy() {
        use crate::mediation::{CommandSandbox, NetworkConfig};

        let intercept_sandbox = CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["example.com".to_string()],
            },
            ..CommandSandbox::default()
        };

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![ResolvedIntercept {
                id: None,
                matcher: ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                sandbox: ResolvedSandboxBinding::Explicit(intercept_sandbox),
                promote_filter: None,
            }],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        let req = ShimRequest {
            command: "testcmd".to_string(),
            // `env` with no args prints its environment; we grep for HTTPS_PROXY.
            args: vec![],
            session_token: String::new(),
            ..Default::default()
        };

        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        let proxy = extract_https_proxy(&resp.stdout).unwrap_or_else(|| {
            panic!(
                "expected HTTPS_PROXY to be injected by per-intercept sandbox, got: {}",
                resp.stdout
            )
        });
        assert!(
            proxy.starts_with("http://nono:") || proxy.starts_with("http://127.0.0.1:"),
            "HTTPS_PROXY should point at the per-intercept proxy, got: {}",
            proxy
        );
        assert!(
            resp.stdout.contains("127.0.0.1"),
            "proxy addr not 127.0.0.1: {}",
            resp.stdout
        );
    }

    /// Two intercept rules on the same command, each with its own `sandbox`
    /// that enables a different `allowed_hosts` proxy. Driving an invocation
    /// matching rule A produces one `HTTPS_PROXY` URL; driving one matching
    /// rule B produces a different URL. This proves the broker spun up two
    /// distinct per-intercept proxies for the same command.
    #[tokio::test]
    async fn test_two_intercepts_select_different_sandboxes() {
        use crate::mediation::matcher::compile_args_matcher;
        use crate::mediation::{CommandSandbox, NetworkConfig};

        let sandbox_a = CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["a.example".to_string()],
            },
            ..CommandSandbox::default()
        };
        let sandbox_b = CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["b.example".to_string()],
            },
            ..CommandSandbox::default()
        };

        // Matcher A: argv[1] == "MARKER_A". Matcher B: argv[1] == "MARKER_B".
        // We invoke `/usr/bin/env -u MARKER_<x> /usr/bin/printenv` so the
        // marker arrives as argv[1] (after `-u`) and is consumed by env
        // (a no-op unset of a never-defined name); printenv then dumps the
        // environment so the test can grep for HTTPS_PROXY.
        let matcher_a = compile_args_matcher(
            &serde_json::from_value(serde_json::json!({
                "nth_arg_matches": 1,
                "regex": "^MARKER_A$"
            }))
            .unwrap(),
            "test",
        )
        .unwrap();
        let matcher_b = compile_args_matcher(
            &serde_json::from_value(serde_json::json!({
                "nth_arg_matches": 1,
                "regex": "^MARKER_B$"
            }))
            .unwrap(),
            "test",
        )
        .unwrap();

        let cmd = ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/env"),

            pin: real_pin(&PathBuf::from("/usr/bin/env")),
            intercepts: vec![
                ResolvedIntercept {
                    id: None,
                    matcher: matcher_a,
                    action: ResolvedAction::Allow { script: None },
                    admin: false,
                    sandbox: ResolvedSandboxBinding::Explicit(sandbox_a),
                    promote_filter: None,
                },
                ResolvedIntercept {
                    id: None,
                    matcher: matcher_b,
                    action: ResolvedAction::Allow { script: None },
                    admin: false,
                    sandbox: ResolvedSandboxBinding::Explicit(sandbox_b),
                    promote_filter: None,
                },
            ],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };

        // Drive intercept A.
        let req_a = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "-u".to_string(),
                "MARKER_A".to_string(),
                "/usr/bin/printenv".to_string(),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp_a, action_a) = apply_capture(
            req_a,
            std::slice::from_ref(&cmd),
            make_broker(),
            &ctx(),
            always_allow(),
        )
        .await;
        assert_eq!(action_a, "allow");
        assert_eq!(resp_a.exit_code, 0, "stderr A: {}", resp_a.stderr);
        let proxy_a = extract_https_proxy(&resp_a.stdout).unwrap_or_else(|| {
            panic!(
                "intercept A: expected HTTPS_PROXY in env, got: {}",
                resp_a.stdout
            )
        });

        // Drive intercept B.
        let req_b = ShimRequest {
            command: "testcmd".to_string(),
            args: vec![
                "-u".to_string(),
                "MARKER_B".to_string(),
                "/usr/bin/printenv".to_string(),
            ],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp_b, action_b) =
            apply_capture(req_b, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action_b, "allow");
        assert_eq!(resp_b.exit_code, 0, "stderr B: {}", resp_b.stderr);
        let proxy_b = extract_https_proxy(&resp_b.stdout).unwrap_or_else(|| {
            panic!(
                "intercept B: expected HTTPS_PROXY in env, got: {}",
                resp_b.stdout
            )
        });

        assert_ne!(
            proxy_a, proxy_b,
            "the two intercepts must have produced different proxy URLs (A={}, B={})",
            proxy_a, proxy_b
        );
    }

    /// `Allow` matched-intercept action streams the real binary the same way
    /// `Passthrough` does. The action_type label is `"allow"`.
    #[tokio::test]
    async fn test_allow_action_streams_real_binary() {
        let cmd = ResolvedCommand {
            name: "echo".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![ResolvedIntercept {
                id: None,
                matcher: crate::mediation::matcher::ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
                promote_filter: None,
            }],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["hello".into()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert!(resp.stdout.contains("hello"));
    }

    /// When `cmd.default` is set and no intercept matches, the default's
    /// action is dispatched instead of the legacy implicit fall-through.
    #[tokio::test]
    async fn test_default_action_allow_dispatched_when_no_intercept_matches() {
        let cmd = ResolvedCommand {
            name: "echo".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["default-dispatch".into()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "allow");
        assert!(resp.stdout.contains("default-dispatch"));
    }

    /// `Deny` carries stdout, stderr, AND a configurable `exit_code`.
    /// Profiles express "deny with a message" via
    /// `Deny { exit_code: 126, stderr: "..." }` instead of inventing a
    /// separate action variant. Regression for both the variant's `stderr`
    /// (Phase B Commit 1) and `exit_code` (which the default-dispatch arm
    /// previously hardcoded to 0).
    #[tokio::test]
    async fn test_default_deny_returns_stderr_and_exit_code() {
        let cmd = ResolvedCommand {
            name: "vault".to_string(),
            real_path: PathBuf::from("/usr/bin/false"),

            pin: real_pin(&PathBuf::from("/usr/bin/false")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Deny {
                    stdout: String::new(),
                    stderr: "vault not invokable\n".to_string(),
                    exit_code: 126,
                },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };
        let req = ShimRequest {
            command: "vault".to_string(),
            args: vec!["read".into(), "secret/foo".into()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "deny");
        assert!(
            resp.stderr.contains("vault not invokable"),
            "stderr should round-trip from Deny.stderr: {}",
            resp.stderr
        );
        assert_eq!(
            resp.exit_code, 126,
            "default-dispatch Deny must return the variant's configured exit_code, not 0"
        );
    }

    /// Companion regression for the matched-intercept Deny path: the
    /// variant's `exit_code` must reach the shim response (not be dropped
    /// or hardcoded). Pairs with `test_default_deny_returns_stderr_and_exit_code`
    /// which covers the default-dispatch path.
    #[tokio::test]
    async fn test_matched_intercept_deny_returns_configured_exit_code() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            id: None,
            matcher: ResolvedArgsMatcher::All(vec![]), // match anything
            action: ResolvedAction::Deny {
                stdout: String::new(),
                stderr: "blocked\n".to_string(),
                exit_code: 42,
            },
            admin: false,
            sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
            promote_filter: None,
        }]);
        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["read".into()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, action) =
            apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(action, "deny");
        assert_eq!(
            resp.exit_code, 42,
            "matched-intercept Deny must return the variant's exit_code, got {}",
            resp.exit_code
        );
        assert!(resp.stderr.contains("blocked"));
    }

    /// A.5: when an intercept rule binds an `Explicit` sandbox, that sandbox
    /// is the one applied at exec time — the command-level `cmd.sandbox` does
    /// NOT override the rule's binding. We can't easily assert the effective
    /// sandbox from inside the test (it's collapsed deep inside
    /// `exec_passthrough`), but exercising the matched-Allow path with
    /// `Explicit` confirms the binding resolves cleanly and the child still
    /// executes the real binary.
    #[tokio::test]
    async fn test_sandbox_binding_explicit_overrides_default() {
        use crate::mediation::{CommandSandbox, NetworkConfig};
        let tight = CommandSandbox {
            network: NetworkConfig {
                block: true,
                allowed_hosts: vec![],
            },
            ..CommandSandbox::default()
        };
        let cmd = ResolvedCommand {
            name: "echo".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![ResolvedIntercept {
                matcher: crate::mediation::matcher::ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                id: Some("test".to_string()),
                sandbox: ResolvedSandboxBinding::Explicit(tight.clone()),
                promote_filter: None,
            }],
            sandbox: Some(CommandSandbox::default()), // permissive command-level
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["ok".into()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _) = apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(resp.exit_code, 0);
        assert!(resp.stdout.contains("ok"));
    }

    /// A.5: when an intercept rule's sandbox binding is
    /// `InheritFromDefault`, the effective sandbox comes from
    /// `cmd.default.sandbox` (preferred over the legacy `cmd.sandbox`).
    /// Same caveat as above re: directly observing the effective sandbox.
    #[tokio::test]
    async fn test_sandbox_binding_inherits_from_default_sandbox() {
        use crate::mediation::CommandSandbox;
        let default_sb = CommandSandbox::default();
        let cmd = ResolvedCommand {
            name: "echo".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![ResolvedIntercept {
                matcher: crate::mediation::matcher::ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                id: Some("test".to_string()),
                sandbox: ResolvedSandboxBinding::InheritFromDefault,
                promote_filter: None,
            }],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: Some(default_sb.clone()),
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        };
        let req = ShimRequest {
            command: "echo".to_string(),
            args: vec!["inherited".into()],
            session_token: String::new(),
            ..Default::default()
        };
        let (resp, _) = apply_capture(req, &[cmd], make_broker(), &ctx(), always_allow()).await;
        assert_eq!(resp.exit_code, 0);
        assert!(resp.stdout.contains("inherited"));
    }

    // ------------------------------------------------------------------
    // from-map dispatch tests
    // ------------------------------------------------------------------

    /// `from[kubectl] = passthrough` — a kubectl-invoked ddtool should skip
    /// capture intercepts and return real output (not a nonce string).
    #[tokio::test]
    async fn from_passthrough_skips_intercepts() {
        use crate::mediation::session::ResolvedCallerBinding;
        use crate::mediation::CallerAction;

        // ddtool with a Capture intercept that would return a nonce if fired.
        let ddtool_cmd = ResolvedCommand {
            name: "ddtool".to_string(),
            real_path: PathBuf::from("/bin/echo"),

            pin: real_pin(&PathBuf::from("/bin/echo")),
            intercepts: vec![ResolvedIntercept {
                id: None,
                matcher: crate::mediation::matcher::ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Capture {
                    script: None,
                    grants: test_grants(),
                },
                admin: false,
                sandbox: ResolvedSandboxBinding::ExplicitlyUnsandboxed,
                promote_filter: None,
            }],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: {
                let mut m = std::collections::BTreeMap::new();
                m.insert(
                    "kubectl".to_string(),
                    ResolvedCallerBinding::Bound {
                        action: CallerAction::Passthrough,
                        sandbox: None,
                    },
                );
                m
            },
        };

        // kubectl parent that has ddtool in its can_use.
        let kubectl_cmd = ResolvedCommand {
            name: "kubectl".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),

            pin: real_pin(&PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec!["ddtool".to_string()],
            from: Default::default(),
        };

        let broker = make_broker();
        // Grant must match ConsumerContext { command: "ddtool", intercept_id: "default" }
        // which is how `apply` resolves the NONO_SANDBOX_CONTEXT nonce.
        let nonce = broker.issue(
            Zeroizing::new("kubectl".to_string()),
            GrantSet::Allow(vec![GrantDescriptor {
                command: "ddtool".to_string(),
                intercept_id: "default".to_string(),
            }]),
        );
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "ddtool".to_string(),
            args: vec!["auth".to_string(), "github".to_string(), "token".to_string()],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };

        let (resp, action) = apply_capture(
            req,
            &[ddtool_cmd, kubectl_cmd],
            broker,
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["ddtool".to_string()],
            },
            always_allow(),
        )
        .await;

        assert_eq!(resp.exit_code, 0, "stderr: {}", resp.stderr);
        assert_eq!(action, "passthrough");
        // Real output from /bin/echo — must NOT be a nonce.
        assert!(
            !resp.stdout.trim().starts_with("nono_"),
            "expected real output, got nonce: {}",
            resp.stdout
        );
    }

    /// `from[cron] = deny` — a cron-invoked ssh returns exit 126.
    #[tokio::test]
    async fn from_deny_blocks_invocation() {
        use crate::mediation::session::ResolvedCallerBinding;

        let ssh_cmd = ResolvedCommand {
            name: "ssh".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),

            pin: real_pin(&PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: {
                let mut m = std::collections::BTreeMap::new();
                m.insert("cron".to_string(), ResolvedCallerBinding::Deny);
                m
            },
        };

        // cron parent that has ssh in its can_use.
        let cron_cmd = ResolvedCommand {
            name: "cron".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),

            pin: real_pin(&PathBuf::from("/usr/bin/true")),
            intercepts: vec![],
            sandbox: None,
            default: ResolvedDefault {
                action: ResolvedAction::Allow { script: None },
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec!["ssh".to_string()],
            from: Default::default(),
        };

        let broker = make_broker();
        // Grant must match ConsumerContext { command: "ssh", intercept_id: "default" }.
        let nonce = broker.issue(
            Zeroizing::new("cron".to_string()),
            GrantSet::Allow(vec![GrantDescriptor {
                command: "ssh".to_string(),
                intercept_id: "default".to_string(),
            }]),
        );
        let mut env = HashMap::new();
        env.insert("NONO_SANDBOX_CONTEXT".to_string(), nonce);

        let req = ShimRequest {
            command: "ssh".to_string(),
            args: vec![],
            session_token: String::new(),
            env,
            pid: 0,
            cwd: None,
        };

        let (resp, action) = apply_capture(
            req,
            &[ssh_cmd, cron_cmd],
            broker,
            &SessionCtx {
                shim_dir: std::path::Path::new("/tmp"),
                socket_path: std::path::Path::new("/tmp/test.sock"),
                session_token: "test_token",
                workdir: std::path::Path::new("/tmp"),
                session_can_use: vec!["ssh".to_string()],
            },
            always_allow(),
        )
        .await;

        assert_eq!(action, "denied");
        assert_eq!(resp.exit_code, 126);
        assert!(
            resp.stderr.contains("ssh"),
            "stderr should name the denied command: {}",
            resp.stderr
        );
    }
}
