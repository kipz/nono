//! Pre-sandbox session setup for command mediation.
//!
//! `setup()` is called before the sandbox is applied. It:
//! 1. Resolves each configured command name to an absolute path via `which`.
//! 2. Creates `/tmp/nono-session-{pid}/shims/` and symlinks `nono-shim` for each command.
//! 3. Starts the mediation server on a Unix socket.
//! 4. Returns a `SessionHandle` that keeps the server alive and exposes the
//!    paths/env needed by the rest of the startup sequence.

use super::admin::AdminState;
use super::approval::NativeApprovalGate;
use super::broker::{GrantDescriptor, GrantSet, TokenBroker};
use super::{CommandEntry, CommandSandbox, InterceptAction, MediationConfig, SessionAuditInfo};
use nix::libc;
use nono::{NonoError, Result};
use sha2::Digest;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tracing::{debug, info};
use zeroize::Zeroizing;

/// Identity snapshot of a resolved binary, captured at session start.
#[derive(Clone, Debug)]
pub struct PinnedBinary {
    pub dev: u64,
    pub ino: u64,
    pub size: u64,
    pub mtime_nanos: i128,
    pub sha256: String,
}

#[cfg(test)]
impl PinnedBinary {
    pub fn dummy() -> Self {
        PinnedBinary {
            dev: 0,
            ino: 0,
            size: 0,
            mtime_nanos: 0,
            sha256: String::new(),
        }
    }
}

/// Open `path` with O_NOFOLLOW|O_RDONLY, fstat it, and hash its contents.
pub(super) fn pin_binary(path: &std::path::Path) -> Result<PinnedBinary> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| NonoError::SandboxInit("mediation: binary path contains NUL".into()))?;
    let raw = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(NonoError::SandboxInit(format!(
            "mediation: cannot open binary for pinning {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(AsRawFd::as_raw_fd(&fd), &mut st) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "mediation: fstat failed pinning {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let mtime_nanos = (st.st_mtime as i128)
        .saturating_mul(1_000_000_000)
        .saturating_add(st.st_mtime_nsec as i128);
    let mut file = std::fs::File::from(fd);
    let mut hasher = sha2::Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| NonoError::SandboxInit(format!("mediation: binary read for hash: {e}")))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let sha256 = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
    Ok(PinnedBinary {
        dev: st.st_dev as u64,
        ino: st.st_ino as u64,
        size: st.st_size as u64,
        mtime_nanos,
        sha256,
    })
}

/// Re-open the binary O_NOFOLLOW and confirm its stat tuple matches the pin.
/// Cheap (no hashing) per the caching decision; a mismatch fails closed.
pub(super) fn verify_pin(path: &std::path::Path, pin: &PinnedBinary) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;

    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| NonoError::SandboxInit("mediation: binary path contains NUL".into()))?;
    let raw = unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(NonoError::SandboxInit(format!(
            "mediation: binary vanished or is a symlink at exec: {}",
            path.display()
        )));
    }
    let fd: OwnedFd = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(NonoError::SandboxInit(format!(
            "mediation: fstat failed at exec: {}",
            path.display()
        )));
    }
    let mtime_nanos = (st.st_mtime as i128)
        .saturating_mul(1_000_000_000)
        .saturating_add(st.st_mtime_nsec as i128);
    if st.st_dev as u64 != pin.dev
        || st.st_ino as u64 != pin.ino
        || st.st_size as u64 != pin.size
        || mtime_nanos != pin.mtime_nanos
    {
        return Err(NonoError::SandboxInit(format!(
            "mediation: binary identity changed since session start: {}",
            path.display()
        )));
    }
    Ok(())
}

/// The action stored in a resolved intercept rule.
#[derive(Clone, Debug)]
pub enum ResolvedAction {
    Deny {
        stdout: String,
        stderr: String,
        exit_code: i32,
    },
    Capture {
        script: Option<String>,
        grants: GrantSet,
    },
    Allow {
        script: Option<String>,
    },
}

/// A resolved intercept rule ready for the mediation server.
#[derive(Clone, Debug)]
pub struct ResolvedIntercept {
    /// Optional identifier carried over from the profile rule. When set,
    /// this is the redemption-site identifier other rules can reference
    /// via `Capture.grant_to = ["<command>.<id>"]`.
    pub id: Option<String>,
    /// Compiled predicate against the invocation's argv.
    pub matcher: crate::mediation::matcher::ResolvedArgsMatcher,
    pub action: ResolvedAction,
    /// If true, requires user authentication before the action executes.
    pub admin: bool,
    /// Tri-state binding resolved from the profile's `SandboxBinding`. At
    /// exec time, `policy::apply` collapses this to `Option<CommandSandbox>`:
    /// `Explicit` → use the rule's sandbox; `ExplicitlyUnsandboxed` → None;
    /// `InheritFromDefault` → `cmd.default.sandbox` if set, else legacy
    /// `cmd.sandbox`.
    pub sandbox: ResolvedSandboxBinding,
    /// Compiled per-rule nonce-promotion filter. `None` means the profile
    /// did not declare `promote_in` for this rule — argv promotion is
    /// suppressed and env promotion falls back to the built-in safe-shape
    /// allowlist.
    pub promote_filter: Option<crate::mediation::promote::ResolvedPromoteFilter>,
}

/// Resolved counterpart of `mediation::SandboxBinding`. The tri-state is
/// preserved through profile load so `policy::apply` can decide what to
/// inherit from at exec time.
#[derive(Clone, Debug)]
pub enum ResolvedSandboxBinding {
    InheritFromDefault,
    ExplicitlyUnsandboxed,
    Explicit(crate::mediation::CommandSandbox),
}

/// Resolved counterpart of `mediation::CallerBinding`.
#[derive(Clone, Debug)]
pub enum ResolvedCallerBinding {
    Deny,
    Bound {
        action: crate::mediation::CallerAction,
        sandbox: Option<crate::mediation::CommandSandbox>,
    },
}

/// A fully resolved command entry ready for the mediation server.
#[derive(Clone)]
pub struct ResolvedCommand {
    pub name: String,
    /// Absolute path to the real binary (to exec on passthrough).
    pub real_path: PathBuf,
    /// Identity snapshot of the binary at session start. Verified before each
    /// spawn to detect binary swaps (TOCTOU mitigation).
    pub pin: PinnedBinary,
    pub intercepts: Vec<ResolvedIntercept>,
    /// Optional sandbox profile to apply when exec-ing the real binary.
    pub sandbox: Option<CommandSandbox>,
    /// Default entry dispatched when no intercept matches.
    pub default: ResolvedDefault,
    /// Commands this command may invoke (authorization graph). Carried from
    /// `CommandEntry::can_use`.
    pub can_use: Vec<String>,
    /// Per-caller behaviour map, resolved from `CommandEntry::from`.
    pub from: std::collections::BTreeMap<String, ResolvedCallerBinding>,
}

/// A resolved default entry. When present on `ResolvedCommand`, dispatched
/// after the intercept loop completes without a match — replaces the legacy
/// implicit fall-through.
#[derive(Clone, Debug)]
pub struct ResolvedDefault {
    pub action: ResolvedAction,
    pub sandbox: Option<crate::mediation::CommandSandbox>,
    /// Compiled per-default nonce-promotion filter. Same secure defaults
    /// as `ResolvedIntercept::promote_filter`. Intercepts do NOT inherit
    /// this — each rule's filter is independent.
    pub promote_filter: Option<crate::mediation::promote::ResolvedPromoteFilter>,
}

/// Handle returned by `setup()`. Dropping this shuts down the runtime.
pub struct SessionHandle {
    /// Directory containing shim symlinks (must be prepended to child PATH).
    pub shim_dir: PathBuf,
    /// Real path of the nono-shim binary (needed for sandbox file-read allow rules).
    pub shim_binary: PathBuf,
    /// Path of the Unix socket the mediation server listens on.
    pub socket_path: PathBuf,
    /// Session temp directory (cleaned up on drop).
    pub session_dir: PathBuf,
    /// Resolved real paths of mediated commands (for seatbelt deny rules).
    pub blocked_binaries: Vec<PathBuf>,
    /// Env vars to strip from the child environment (from `mediation.env.block`).
    pub env_block: Vec<String>,
    /// 256-bit random session authentication token (hex). Injected into the child
    /// as `NONO_SESSION_TOKEN`; shims must include it in every request.
    pub session_token: Zeroizing<String>,
    /// Path of the control socket (used by external admin CLI/menu bar app).
    #[allow(dead_code)]
    pub control_socket_path: PathBuf,
    /// Shared admin mode state (for passing to admin_commands query).
    pub admin_state: AdminState,
    /// Latch set to the sandboxed process PID after the sandboxed process is forked.
    /// Callers must call `latch.set(sandboxed_pid)` in their post-fork callback.
    pub sandboxed_pid_latch: Arc<OnceLock<u32>>,
    // Tokio runtime kept alive so the server task continues running in the parent.
    _runtime: tokio::runtime::Runtime,
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        // Log if admin mode was active when the session ended.
        if self.admin_state.subscribe().borrow().is_active() {
            tracing::warn!("admin mode was active when mediation session ended");
        }
        // Clean up the session directory on parent exit.
        let _ = std::fs::remove_dir_all(&self.session_dir);
        debug!(
            "Mediation session directory removed: {}",
            self.session_dir.display()
        );
        // Clean up the admin directory (contains session.json with control_token).
        let admin_dir = session_admin_dir_path(std::process::id());
        let _ = std::fs::remove_dir_all(&admin_dir);
        debug!("Mediation admin directory removed: {}", admin_dir.display());
    }
}

/// Set up a mediation session.
///
/// Returns `None` when `config.is_active()` is false (nothing to do).
///
/// # Errors
/// Returns an error if a command cannot be resolved, or the session directory /
/// symlinks cannot be created.
pub fn setup(
    config: &MediationConfig,
    workdir: PathBuf,
    audit_info: SessionAuditInfo,
) -> Result<Option<SessionHandle>> {
    if !config.is_active() {
        return Ok(None);
    }
    let sandboxed_pid_latch = Arc::clone(&audit_info.sandboxed_pid);
    let audit_info_arc = Arc::new(audit_info);

    cleanup_orphaned_sessions();

    // Find nono-shim next to the running nono binary.
    let shim_binary = find_shim_binary()?;

    let session_dir = session_dir_path();
    let shim_dir = session_dir.join("shims");
    let socket_path = session_dir.join("mediation.sock");
    let control_socket_path = session_dir.join("control.sock");

    std::fs::create_dir_all(&shim_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create shim dir {}: {}",
            shim_dir.display(),
            e
        ))
    })?;

    // Restrict session directory to owner-only so other local users cannot reach the socket.
    std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700)).map_err(
        |e| {
            NonoError::SandboxInit(format!(
                "mediation: failed to set session dir permissions {}: {}",
                session_dir.display(),
                e
            ))
        },
    )?;

    // -------------------------------------------------------------------------
    // Resolve commands
    // -------------------------------------------------------------------------
    let mut resolved_commands: Vec<ResolvedCommand> = Vec::new();
    let mut blocked_binaries: Vec<PathBuf> = Vec::new();

    for entry in &config.commands {
        let Some(resolved) = resolve_command(entry, &shim_dir, &shim_binary, &workdir)? else {
            continue;
        };
        // Push the as-found path (which::which may return a symlink).
        // Also push the canonicalized target so that exec via the real binary
        // path is blocked even when the agent bypasses the symlink.
        blocked_binaries.push(resolved.real_path.clone());
        if let Ok(canonical) = resolved.real_path.canonicalize()
            && canonical != resolved.real_path
        {
            blocked_binaries.push(canonical);
        }
        resolved_commands.push(resolved);
    }

    // -------------------------------------------------------------------------
    // Profile-load validation of can_use graph.
    // -------------------------------------------------------------------------
    validate_can_use_graph(config)?;

    // -------------------------------------------------------------------------
    // Profile-load validation of Capture grant_to references and default
    // actions. Every grant_to entry must resolve to a known
    // `<command>.default` or `<command>.<intercept-id>`. A command's default
    // action cannot be `capture` (no intercept id to anchor grants at).
    // -------------------------------------------------------------------------
    validate_grant_to_references(&resolved_commands)?;

    // -------------------------------------------------------------------------
    // Generate session authentication token and control token
    // -------------------------------------------------------------------------
    let session_token = {
        use rand::RngExt;
        let bytes: [u8; 32] = rand::rng().random();
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        Zeroizing::new(hex)
    };

    let control_token = super::control::generate_token();

    // -------------------------------------------------------------------------
    // Create token broker (session-scoped)
    // -------------------------------------------------------------------------
    let broker = Arc::new(TokenBroker::new());

    // -------------------------------------------------------------------------
    // Create admin state
    // -------------------------------------------------------------------------
    let admin_state = AdminState::new();

    // -------------------------------------------------------------------------
    // Write session.json (mode 0600) to admin dir outside sandbox-accessible path.
    // The child process can read the session dir (shims, sockets), so we keep
    // the control_token in a separate directory that is never in the sandbox's
    // fs_read allow list.
    // -------------------------------------------------------------------------
    let admin_dir = session_admin_dir_path(std::process::id());
    std::fs::create_dir_all(&admin_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create admin dir {}: {}",
            admin_dir.display(),
            e
        ))
    })?;
    std::fs::set_permissions(&admin_dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to set admin dir permissions {}: {}",
            admin_dir.display(),
            e
        ))
    })?;
    let session_json_path = admin_dir.join("session.json");
    let started_at = chrono::Utc::now().to_rfc3339();
    let session_info = serde_json::json!({
        "pid": std::process::id(),
        "control_socket": control_socket_path.to_string_lossy(),
        "control_token": control_token,
        "started_at": started_at,
    });
    let session_json_bytes = serde_json::to_vec(&session_info).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to serialize session.json: {}",
            e
        ))
    })?;
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&session_json_path)
            .and_then(|mut f| f.write_all(&session_json_bytes))
            .map_err(|e| {
                NonoError::SandboxInit(format!("mediation: failed to write session.json: {}", e))
            })?;
    }

    // -------------------------------------------------------------------------
    // Start the mediation server
    // -------------------------------------------------------------------------
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("nono-mediation")
        .build()
        .map_err(|e| {
            NonoError::SandboxInit(format!("mediation: failed to start runtime: {}", e))
        })?;

    let approval_gate: Arc<dyn super::approval::ApprovalGate + Send + Sync> =
        Arc::new(NativeApprovalGate);

    let sock = socket_path.clone();
    let cmds = resolved_commands.clone();
    let broker_clone = Arc::clone(&broker);
    let token_arc: Arc<str> = Arc::from(session_token.as_str());
    let shim_dir_clone = shim_dir.clone();
    let admin_clone = admin_state.clone();
    let gate_clone = Arc::clone(&approval_gate);
    let audit_log_dir = crate::session::ensure_sessions_dir()?;
    let audit_info_for_server = Arc::clone(&audit_info_arc);
    let session_can_use = config.session_can_use.clone();
    runtime.spawn(async move {
        if let Err(e) = super::server::run(
            sock,
            cmds,
            broker_clone,
            token_arc,
            shim_dir_clone,
            admin_clone,
            gate_clone,
            audit_log_dir,
            workdir,
            audit_info_for_server,
            session_can_use,
        )
        .await
        {
            tracing::error!("mediation server error: {}", e);
        }
    });

    // -------------------------------------------------------------------------
    // Start the control socket server
    // -------------------------------------------------------------------------
    let ctrl_sock = control_socket_path.clone();
    let ctrl_token = control_token;
    let ctrl_admin = admin_state.clone();
    let ctrl_sdir = session_dir.clone();
    runtime.spawn(async move {
        if let Err(e) =
            super::control::run_control_server(ctrl_sock, ctrl_token, ctrl_admin, ctrl_sdir).await
        {
            tracing::error!("control server error: {}", e);
        }
    });

    info!(
        "Mediation session started: socket={}, shims={}",
        socket_path.display(),
        shim_dir.display()
    );

    Ok(Some(SessionHandle {
        shim_dir,
        shim_binary,
        socket_path,
        session_dir,
        blocked_binaries,
        env_block: config.env.block.clone(),
        session_token,
        control_socket_path,
        admin_state,
        sandboxed_pid_latch,
        _runtime: runtime,
    }))
}

/// Resolve a command entry: find the real binary, create the shim symlink.
///
/// Returns `Ok(None)` when the command is not found on PATH and no explicit
/// `binary_path` was given. This lets callers silently skip entries for tools
/// that are not installed on this device.
fn resolve_command(
    entry: &CommandEntry,
    shim_dir: &Path,
    shim_binary: &Path,
    workdir: &Path,
) -> Result<Option<ResolvedCommand>> {
    let real_path = if let Some(ref bp) = entry.binary_path {
        // Expand `$VAR` / `~` tokens so profiles can point at user-specific
        // binaries (e.g. `$HOME/.local/bin/tool`) without hard-coding paths.
        let p = crate::profile::expand_vars(bp, workdir)?;
        if !p.is_file() {
            return Err(NonoError::SandboxInit(format!(
                "mediation: binary_path for '{}' does not exist or is not a file: {}",
                entry.name,
                p.display()
            )));
        }
        p
    } else {
        match which::which(&entry.name) {
            Ok(p) => p,
            Err(_) => {
                tracing::warn!(
                    "mediation: command '{}' not found on PATH, skipping",
                    entry.name
                );
                return Ok(None);
            }
        }
    };
    debug!(
        "Mediation: resolved '{}' -> {}",
        entry.name,
        real_path.display()
    );

    // Canonicalize so O_NOFOLLOW in pin_binary succeeds even when which/binary_path
    // returns a symlink (e.g. Homebrew shims under /opt/homebrew/bin).
    let pin_path = real_path.canonicalize().unwrap_or_else(|_| real_path.clone());
    let pin = pin_binary(&pin_path)?;

    // Create shim symlink (remove stale link if present)
    let shim_path = shim_dir.join(&entry.name);
    if shim_path.exists() || shim_path.symlink_metadata().is_ok() {
        std::fs::remove_file(&shim_path).map_err(|e| {
            NonoError::SandboxInit(format!(
                "mediation: failed to remove stale shim {}: {}",
                shim_path.display(),
                e
            ))
        })?;
    }
    std::os::unix::fs::symlink(shim_binary, &shim_path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create shim symlink {}: {}",
            shim_path.display(),
            e
        ))
    })?;

    // Convert intercept rules. Every rule carries a required `match` field
    // (a predicate tree). Profile load fails if the field is missing.
    let intercepts: Vec<ResolvedIntercept> = entry
        .intercept
        .iter()
        .map(|rule| -> Result<ResolvedIntercept> {
            if matches!(rule.id.as_deref(), Some("default")) {
                return Err(NonoError::SandboxInit(format!(
                    "mediation: command '{}': intercept id 'default' is reserved (it refers to the command's default entry)",
                    entry.name
                )));
            }
            let matcher =
                crate::mediation::matcher::compile_args_matcher(&rule.matcher, &entry.name)?;
            let action = resolve_intercept_action(&rule.action)?;
            let sandbox = match &rule.sandbox {
                crate::mediation::SandboxBinding::InheritFromDefault => {
                    ResolvedSandboxBinding::InheritFromDefault
                }
                crate::mediation::SandboxBinding::ExplicitlyUnsandboxed => {
                    ResolvedSandboxBinding::ExplicitlyUnsandboxed
                }
                crate::mediation::SandboxBinding::Explicit(sb) => {
                    ResolvedSandboxBinding::Explicit(sb.clone())
                }
            };
            let promote_filter = match &rule.promote_in {
                Some(p) => Some(crate::mediation::promote::compile_promote_filter(
                    p,
                    &entry.name,
                )?),
                None => None,
            };
            Ok(ResolvedIntercept {
                id: rule.id.clone(),
                matcher,
                action,
                admin: rule.admin,
                sandbox,
                promote_filter,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let default_action = resolve_intercept_action(&entry.default.action)?;
    let default_promote_filter = match &entry.default.promote_in {
        Some(p) => Some(crate::mediation::promote::compile_promote_filter(
            p,
            &entry.name,
        )?),
        None => None,
    };
    let default = ResolvedDefault {
        action: default_action,
        sandbox: entry.default.sandbox.clone(),
        promote_filter: default_promote_filter,
    };

    let from = entry
        .from
        .iter()
        .map(|(k, v)| {
            let resolved = match v {
                crate::mediation::CallerBinding::Deny(_) => ResolvedCallerBinding::Deny,
                crate::mediation::CallerBinding::Bound(b) => ResolvedCallerBinding::Bound {
                    action: b.action,
                    sandbox: b.sandbox.clone(),
                },
            };
            (k.clone(), resolved)
        })
        .collect();

    Ok(Some(ResolvedCommand {
        name: entry.name.clone(),
        real_path,
        pin,
        intercepts,
        sandbox: entry.sandbox.clone(),
        default,
        can_use: entry.can_use.clone(),
        from,
    }))
}

/// Validate every `Capture` rule's `grant_to` references and the default
/// action of every command. Called once after all commands are resolved.
///
/// Rejects:
/// - a `grant_to` entry that does not resolve to a known
///   `<command>.default` or `<command>.<intercept-id>` in the profile;
/// - a command whose `default.action` is `Capture` (there is no intercept
///   id to anchor grants at).
pub(super) fn validate_grant_to_references(commands: &[ResolvedCommand]) -> Result<()> {
    use std::collections::HashSet;

    let valid_descriptors: HashSet<GrantDescriptor> = commands
        .iter()
        .flat_map(|c| {
            let mut entries = vec![GrantDescriptor {
                command: c.name.clone(),
                intercept_id: "default".to_string(),
            }];
            for i in &c.intercepts {
                if let Some(id) = &i.id {
                    entries.push(GrantDescriptor {
                        command: c.name.clone(),
                        intercept_id: id.clone(),
                    });
                }
            }
            entries
        })
        .collect();

    for cmd in commands {
        for rule in &cmd.intercepts {
            if let ResolvedAction::Capture {
                grants: GrantSet::Allow(list),
                ..
            } = &rule.action
            {
                for d in list {
                    if !valid_descriptors.contains(d) {
                        return Err(NonoError::SandboxInit(format!(
                            "mediation: command '{}' capture rule: grant_to entry '{}.{}' does not resolve to any known intercept or default",
                            cmd.name, d.command, d.intercept_id
                        )));
                    }
                }
            }
        }
        if matches!(cmd.default.action, ResolvedAction::Capture { .. }) {
            return Err(NonoError::SandboxInit(format!(
                "mediation: command '{}': default.action cannot be 'capture'",
                cmd.name
            )));
        }
    }
    Ok(())
}

/// Validate the `can_use` graph at profile load.
///
/// Checks:
/// - Every entry in `session_can_use` names a command that exists in `commands`.
/// - For every command, every entry in `can_use` names a command that exists in `commands`.
/// - For every command `C` and every `(caller_name, binding)` in `C.from`:
///   - `caller_name` must be a defined command (dangling caller).
///   - If `binding != Deny`: `caller_name.can_use` must contain `C.name` (mutual consent).
///   - If `binding == Deny`: `caller_name.can_use` must NOT contain `C.name` (contradiction).
pub(super) fn validate_can_use_graph(config: &MediationConfig) -> Result<()> {
    use std::collections::HashSet;
    let defined: HashSet<&str> = config.commands.iter().map(|c| c.name.as_str()).collect();

    for c in &config.session_can_use {
        if !defined.contains(c.as_str()) {
            return Err(NonoError::SandboxInit(format!(
                "mediation: session_can_use references unknown command '{c}'"
            )));
        }
    }
    for cmd in &config.commands {
        for child in &cmd.can_use {
            if !defined.contains(child.as_str()) {
                return Err(NonoError::SandboxInit(format!(
                    "mediation: command '{}' can_use references unknown command '{}'",
                    cmd.name, child
                )));
            }
        }
        for (caller, binding) in &cmd.from {
            if !defined.contains(caller.as_str()) {
                return Err(NonoError::SandboxInit(format!(
                    "mediation: '{}'.from references unknown caller '{caller}'",
                    cmd.name
                )));
            }
            let parent_authorizes = config
                .commands
                .iter()
                .find(|c| c.name == *caller)
                .is_some_and(|p| p.can_use.iter().any(|x| x == &cmd.name));
            match binding {
                crate::mediation::CallerBinding::Deny(_) if parent_authorizes => {
                    return Err(NonoError::SandboxInit(format!(
                        "mediation: '{caller}'.can_use lists '{}' but '{}'.from['{caller}'] = deny (contradiction)",
                        cmd.name, cmd.name
                    )));
                }
                crate::mediation::CallerBinding::Bound(_) if !parent_authorizes => {
                    return Err(NonoError::SandboxInit(format!(
                        "mediation: '{}'.from['{caller}'] set but '{caller}'.can_use does not list '{}' (mutual consent required)",
                        cmd.name, cmd.name
                    )));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

/// Map a profile `InterceptAction` to a `ResolvedAction`. The `Deny`
/// variant carries its own `exit_code`, so resolution preserves it directly
/// on the variant rather than threading a separate rule-level field through
/// the policy dispatcher. Shared between intercept-rule resolution and
/// default-entry resolution.
fn resolve_intercept_action(action: &InterceptAction) -> Result<ResolvedAction> {
    match action {
        InterceptAction::Deny {
            stdout,
            stderr,
            exit_code,
        } => Ok(ResolvedAction::Deny {
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            exit_code: *exit_code,
        }),
        InterceptAction::Capture { script, grant_to } => {
            let grants = if grant_to.is_empty() {
                GrantSet::None
            } else {
                let mut descriptors = Vec::with_capacity(grant_to.len());
                for s in grant_to {
                    match GrantDescriptor::parse(s) {
                        Some(d) => descriptors.push(d),
                        None => {
                            return Err(NonoError::SandboxInit(format!(
                                "mediation: capture rule's grant_to entry '{}' is not in '<command>.<intercept-id>' form",
                                s
                            )));
                        }
                    }
                }
                GrantSet::Allow(descriptors)
            };
            Ok(ResolvedAction::Capture {
                script: script.clone(),
                grants,
            })
        }
        InterceptAction::Allow { script } => Ok(ResolvedAction::Allow {
            script: script.clone(),
        }),
    }
}

/// Find the nono-shim binary.
///
/// Looks next to the running `nono` executable first, then falls back to PATH.
fn find_shim_binary() -> Result<PathBuf> {
    // 1. Look next to current exe
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.with_file_name("nono-shim");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    // 2. Try PATH
    which::which("nono-shim").map_err(|_| {
        NonoError::SandboxInit(
            "mediation: nono-shim binary not found next to nono or on PATH. \
             Ensure nono-shim is installed alongside nono."
                .to_string(),
        )
    })
}

/// Remove session and admin directories left behind by crashed/killed nono processes.
///
/// Scans the temp directories for `nono-session-{pid}` and `nono-admin-{pid}`
/// entries. Any entry whose PID is no longer alive (checked via `kill(pid, 0)`)
/// is removed. The current process's directories are always skipped.
fn cleanup_orphaned_sessions() {
    let current_pid = std::process::id();

    #[cfg(target_os = "macos")]
    let session_tmp = PathBuf::from("/private/tmp");
    #[cfg(not(target_os = "macos"))]
    let session_tmp = std::env::temp_dir();

    cleanup_dirs_in(&session_tmp, "nono-session-", current_pid);

    let admin_tmp = std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    cleanup_dirs_in(&admin_tmp, "nono-admin-", current_pid);
}

/// Scan `dir` for entries matching `{prefix}{pid}` and remove those whose PID
/// is no longer alive.
fn cleanup_dirs_in(dir: &Path, prefix: &str, current_pid: u32) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Some(pid_str) = name_str.strip_prefix(prefix) else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid == current_pid {
            continue;
        }
        // kill(pid, 0) returns 0 if process is alive, -1 with ESRCH if not.
        let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if !alive {
            let _ = std::fs::remove_dir_all(entry.path());
            debug!(
                "Removed orphaned {} dir for dead pid {}",
                prefix.trim_end_matches('-'),
                pid
            );
        }
    }
}

/// Compute the session directory path for this process.
fn session_dir_path() -> PathBuf {
    // Use /private/tmp on macOS (canonical form of /tmp symlink) so Seatbelt
    // rules that use literal paths match correctly.
    #[cfg(target_os = "macos")]
    let tmp = PathBuf::from("/private/tmp");
    #[cfg(not(target_os = "macos"))]
    let tmp = std::env::temp_dir();

    tmp.join(format!("nono-session-{}", std::process::id()))
}

/// Compute the admin directory path for a given PID.
///
/// The admin dir lives in `$TMPDIR` (on macOS: `/var/folders/.../T/`) rather
/// than `/private/tmp`, so it is never covered by the sandbox's `fs_read`
/// allow list and cannot be read by the child process.
pub fn session_admin_dir_path(pid: u32) -> PathBuf {
    // $TMPDIR on macOS expands to a user-specific temp dir under /var/folders,
    // which is not included in any profile's fs_read allow list.
    // Fall back to /tmp only if $TMPDIR is unset (non-macOS or unusual env).
    let tmp = std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));
    tmp.join(format!("nono-admin-{}", pid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::admin::AdminModeStatus;

    #[test]
    fn test_cleanup_orphaned_sessions_skips_live_pid() {
        let tmp = tempfile::tempdir().expect("create temp dir");
        let current_pid = std::process::id();

        // Create a dir for the current (live) PID — must not be removed.
        let live_dir = tmp.path().join(format!("nono-session-{}", current_pid));
        std::fs::create_dir_all(&live_dir).expect("create live dir");

        // Create a dir for a PID that is certainly dead.
        // i32::MAX as u32 stays positive when cast back to pid_t, so kill(pid, 0)
        // returns ESRCH — no process can ever have such a high PID.
        let dead_pid: u32 = i32::MAX as u32;
        let dead_dir = tmp.path().join(format!("nono-session-{}", dead_pid));
        std::fs::create_dir_all(&dead_dir).expect("create dead dir");

        cleanup_dirs_in(tmp.path(), "nono-session-", current_pid);

        assert!(live_dir.exists(), "live PID dir must not be removed");
        assert!(!dead_dir.exists(), "dead PID dir must be removed");
    }

    #[test]
    fn test_session_admin_dir_path_has_pid() {
        let pid = std::process::id();
        let path = session_admin_dir_path(pid);
        assert!(path.to_string_lossy().contains(&pid.to_string()));
        assert!(path.to_string_lossy().contains("nono-admin-"));
    }

    #[test]
    fn test_admin_dir_differs_from_session_dir() {
        let pid = std::process::id();
        let session_dir = session_dir_path();
        let admin_dir = session_admin_dir_path(pid);
        assert_ne!(
            session_dir, admin_dir,
            "admin dir must not be the same as session dir"
        );
        // Admin dir must not be under the session dir.
        assert!(
            !admin_dir.starts_with(&session_dir),
            "admin dir must not be inside session dir"
        );
    }

    #[test]
    fn test_setup_returns_none_when_inactive() {
        let config = MediationConfig::default();
        let dummy_audit = crate::mediation::SessionAuditInfo {
            session_id: String::new(),
            session_name: None,
            nono_pid: std::process::id(),
            sandboxed_pid: std::sync::Arc::new(std::sync::OnceLock::new()),
        };
        let result = setup(&config, PathBuf::from("/tmp"), dummy_audit)
            .expect("setup should not fail for inactive config");
        assert!(result.is_none());
    }

    #[test]
    fn test_session_dir_path_has_pid() {
        let path = session_dir_path();
        assert!(
            path.to_string_lossy()
                .contains(&std::process::id().to_string())
        );
    }

    #[test]
    fn test_admin_state_initial_disabled() {
        // Verify a freshly constructed AdminState starts in Disabled mode.
        let state = AdminState::new();
        let rx = state.subscribe();
        assert!(
            !rx.borrow().is_active(),
            "admin mode should be disabled by default"
        );
        assert!(matches!(*rx.borrow(), AdminModeStatus::Disabled));
    }

    /// A.5: the intercept `id` field cannot be `"default"` — that name is
    /// reserved for the command's default entry. `resolve_command` returns
    /// `SandboxInit` for any rule that claims it.
    #[test]
    fn intercept_id_default_is_rejected_at_profile_load() {
        use crate::mediation::{
            ArgsMatcher, CommandEntry, DefaultEntry, InterceptAction, InterceptRule,
        };

        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_binary = tmp.path().join("fake-cmd");
        std::fs::write(&fake_binary, b"#!/bin/sh\nexit 0\n").expect("write binary");
        let shim_dir = tmp.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        let fake_shim_binary = tmp.path().join("fake-shim");
        std::fs::write(&fake_shim_binary, b"").expect("write shim");

        let entry = CommandEntry {
            name: "fake-cmd".to_string(),
            binary_path: Some(fake_binary.to_string_lossy().into_owned()),
            default: DefaultEntry {
                id: "default".to_string(),
                action: InterceptAction::Allow { script: None },
                sandbox: None,
                promote_in: None,
            },
            intercept: vec![InterceptRule {
                id: Some("default".to_string()),
                matcher: ArgsMatcher::All { all: vec![] },
                admin: false,
                action: InterceptAction::Deny {
                    stdout: String::new(),
                    stderr: String::new(),
                    exit_code: 0,
                },
                sandbox: crate::mediation::SandboxBinding::InheritFromDefault,
                promote_in: None,
            }],
            sandbox: None,
            can_use: Vec::new(),
            from: Default::default(),
        };

        let err = match resolve_command(&entry, &shim_dir, &fake_shim_binary, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("id='default' must be rejected at profile load"),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("intercept id 'default' is reserved"),
            "unexpected error: {msg}"
        );
    }

    /// A bad `promote_in` regex on an intercept rule surfaces at profile
    /// load with a `SandboxInit` error keyed by command name. Validates the
    /// resolve-time compile path.
    #[test]
    fn intercept_promote_in_regex_error_surfaces_at_profile_load() {
        use crate::mediation::{
            ArgPredicate, ArgsMatcher, CommandEntry, DefaultEntry, InterceptAction, InterceptRule,
            PromoteFilter,
        };

        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_binary = tmp.path().join("fake-cmd");
        std::fs::write(&fake_binary, b"#!/bin/sh\nexit 0\n").expect("write binary");
        let shim_dir = tmp.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        let fake_shim_binary = tmp.path().join("fake-shim");
        std::fs::write(&fake_shim_binary, b"").expect("write shim");

        let entry = CommandEntry {
            name: "fake-cmd".to_string(),
            binary_path: Some(fake_binary.to_string_lossy().into_owned()),
            default: DefaultEntry {
                id: "default".to_string(),
                action: InterceptAction::Allow { script: None },
                sandbox: None,
                promote_in: None,
            },
            intercept: vec![InterceptRule {
                id: Some("bad-rule".to_string()),
                matcher: ArgsMatcher::All { all: vec![] },
                admin: false,
                action: InterceptAction::Allow { script: None },
                sandbox: crate::mediation::SandboxBinding::InheritFromDefault,
                promote_in: Some(PromoteFilter {
                    args: Some(ArgPredicate::SelfMatches {
                        self_matches: "(unclosed".to_string(),
                    }),
                    env: None,
                }),
            }],
            sandbox: None,
            can_use: Vec::new(),
            from: Default::default(),
        };

        let err = match resolve_command(&entry, &shim_dir, &fake_shim_binary, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("bad regex must fail profile load"),
        };
        let msg = err.to_string();
        assert!(msg.contains("fake-cmd"), "msg should name command: {msg}");
        assert!(
            msg.contains("promote_in"),
            "msg should mention promote_in: {msg}"
        );
        assert!(
            msg.contains("(unclosed"),
            "msg should include the bad pattern: {msg}"
        );
    }

    /// Same regex-error surfacing applies to the default entry's
    /// `promote_in` field.
    #[test]
    fn default_promote_in_regex_error_surfaces_at_profile_load() {
        use crate::mediation::{
            CommandEntry, DefaultEntry, EnvPredicate, InterceptAction, PromoteFilter,
        };

        let tmp = tempfile::tempdir().expect("tmpdir");
        let fake_binary = tmp.path().join("fake-cmd");
        std::fs::write(&fake_binary, b"#!/bin/sh\nexit 0\n").expect("write binary");
        let shim_dir = tmp.path().join("shims");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        let fake_shim_binary = tmp.path().join("fake-shim");
        std::fs::write(&fake_shim_binary, b"").expect("write shim");

        let entry = CommandEntry {
            name: "fake-cmd".to_string(),
            binary_path: Some(fake_binary.to_string_lossy().into_owned()),
            default: DefaultEntry {
                id: "default".to_string(),
                action: InterceptAction::Allow { script: None },
                sandbox: None,
                promote_in: Some(PromoteFilter {
                    args: None,
                    env: Some(EnvPredicate::NameMatches {
                        name_matches: "(*)".to_string(),
                    }),
                }),
            },
            intercept: vec![],
            sandbox: None,
            can_use: Vec::new(),
            from: Default::default(),
        };

        let err = match resolve_command(&entry, &shim_dir, &fake_shim_binary, tmp.path()) {
            Err(e) => e,
            Ok(_) => panic!("bad regex on default must fail profile load"),
        };
        assert!(err.to_string().contains("fake-cmd"));
    }

    /// Build a minimal `ResolvedCommand` for the validation unit tests.
    /// `validate_grant_to_references` only inspects names, intercept ids,
    /// and actions — it does not touch the filesystem or sandbox fields.
    fn validation_command(
        name: &str,
        intercept_ids: &[&str],
        capture_rules: Vec<(Option<&str>, GrantSet)>,
        default_action: ResolvedAction,
    ) -> ResolvedCommand {
        use crate::mediation::matcher::ResolvedArgsMatcher;
        let mut intercepts: Vec<ResolvedIntercept> = intercept_ids
            .iter()
            .map(|id| ResolvedIntercept {
                id: Some((*id).to_string()),
                matcher: ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Allow { script: None },
                admin: false,
                sandbox: ResolvedSandboxBinding::InheritFromDefault,
                promote_filter: None,
            })
            .collect();
        for (id, grants) in capture_rules {
            intercepts.push(ResolvedIntercept {
                id: id.map(str::to_string),
                matcher: ResolvedArgsMatcher::All(vec![]),
                action: ResolvedAction::Capture {
                    script: None,
                    grants,
                },
                admin: false,
                sandbox: ResolvedSandboxBinding::InheritFromDefault,
                promote_filter: None,
            });
        }
        ResolvedCommand {
            name: name.to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            pin: PinnedBinary::dummy(),
            intercepts,
            sandbox: None,
            default: ResolvedDefault {
                action: default_action,
                sandbox: None,
                promote_filter: None,
            },
            can_use: vec![],
            from: Default::default(),
        }
    }

    /// A capture rule's `grant_to` may reference a known intercept's id.
    #[test]
    fn validate_grant_to_accepts_known_intercept_id() {
        let curl = validation_command(
            "curl",
            &["gitlab"],
            vec![],
            ResolvedAction::Allow { script: None },
        );
        let ddtool = validation_command(
            "ddtool",
            &[],
            vec![(
                Some("gitlab-token"),
                GrantSet::Allow(vec![GrantDescriptor {
                    command: "curl".to_string(),
                    intercept_id: "gitlab".to_string(),
                }]),
            )],
            ResolvedAction::Allow { script: None },
        );
        validate_grant_to_references(&[curl, ddtool]).expect("known intercept must validate");
    }

    /// A capture rule's `grant_to` may reference `<command>.default`.
    #[test]
    fn validate_grant_to_accepts_command_default() {
        let curl = validation_command("curl", &[], vec![], ResolvedAction::Allow { script: None });
        let ddtool = validation_command(
            "ddtool",
            &[],
            vec![(
                Some("any-token"),
                GrantSet::Allow(vec![GrantDescriptor {
                    command: "curl".to_string(),
                    intercept_id: "default".to_string(),
                }]),
            )],
            ResolvedAction::Allow { script: None },
        );
        validate_grant_to_references(&[curl, ddtool]).expect("<command>.default must validate");
    }

    /// `grant_to` referring to a non-existent command is rejected with
    /// a profile-friendly error naming both the capture command and the
    /// unresolved descriptor.
    #[test]
    fn validate_grant_to_rejects_unknown_command() {
        let ddtool = validation_command(
            "ddtool",
            &[],
            vec![(
                Some("token"),
                GrantSet::Allow(vec![GrantDescriptor {
                    command: "nosuchcmd".to_string(),
                    intercept_id: "default".to_string(),
                }]),
            )],
            ResolvedAction::Allow { script: None },
        );
        let err =
            validate_grant_to_references(&[ddtool]).expect_err("unknown command must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("ddtool"), "msg: {msg}");
        assert!(
            msg.contains("nosuchcmd.default"),
            "msg should name the unresolved descriptor: {msg}"
        );
    }

    /// `grant_to` referring to a known command but unknown intercept id is
    /// rejected.
    #[test]
    fn validate_grant_to_rejects_unknown_intercept_id() {
        let curl = validation_command(
            "curl",
            &["gitlab"],
            vec![],
            ResolvedAction::Allow { script: None },
        );
        let ddtool = validation_command(
            "ddtool",
            &[],
            vec![(
                Some("token"),
                GrantSet::Allow(vec![GrantDescriptor {
                    command: "curl".to_string(),
                    intercept_id: "no-such-id".to_string(),
                }]),
            )],
            ResolvedAction::Allow { script: None },
        );
        let err = validate_grant_to_references(&[curl, ddtool])
            .expect_err("unknown intercept id must be rejected");
        assert!(
            err.to_string().contains("curl.no-such-id"),
            "msg should name the unresolved descriptor: {err}"
        );
    }

    /// `Capture` is not allowed as a command's default action — there is
    /// no intercept id to anchor grants at.
    #[test]
    fn validate_rejects_capture_as_default_action() {
        let bad = validation_command(
            "ddtool",
            &[],
            vec![],
            ResolvedAction::Capture {
                script: None,
                grants: GrantSet::None,
            },
        );
        let err =
            validate_grant_to_references(&[bad]).expect_err("Capture as default must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("ddtool"), "msg: {msg}");
        assert!(
            msg.contains("default.action cannot be 'capture'"),
            "msg: {msg}"
        );
    }

    #[test]
    fn test_control_socket_path_in_session_dir() {
        // The control socket path should be derived from the session directory.
        let session_dir = session_dir_path();
        let expected = session_dir.join("control.sock");
        // Re-derive using the same logic as setup()
        let derived = session_dir_path().join("control.sock");
        assert_eq!(expected, derived);
    }

    // ---------------------------------------------------------------------------
    // validate_can_use_graph tests
    // ---------------------------------------------------------------------------

    fn minimal_command_entry(name: &str) -> CommandEntry {
        use crate::mediation::InterceptAction;
        CommandEntry {
            name: name.to_string(),
            binary_path: None,
            default: crate::mediation::DefaultEntry {
                id: "default".to_string(),
                action: InterceptAction::Allow { script: None },
                sandbox: None,
                promote_in: None,
            },
            intercept: vec![],
            sandbox: None,
            can_use: vec![],
            from: Default::default(),
        }
    }

    #[test]
    fn validate_rejects_dangling_session_can_use() {
        let cfg = MediationConfig {
            session_can_use: vec!["nope".into()],
            ..Default::default()
        };
        let err = validate_can_use_graph(&cfg)
            .expect_err("dangling session_can_use must be rejected");
        assert!(
            err.to_string().contains("nope"),
            "error should name the unknown command: {err}"
        );
    }

    #[test]
    fn validate_rejects_dangling_cmd_can_use() {
        let mut git = minimal_command_entry("git");
        git.can_use = vec!["nope".into()];
        let cfg = MediationConfig {
            commands: vec![git],
            ..Default::default()
        };
        let err = validate_can_use_graph(&cfg)
            .expect_err("dangling cmd.can_use must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("git"),
            "error should name the command with dangling can_use: {msg}"
        );
        assert!(
            msg.contains("nope"),
            "error should name the unknown can_use target: {msg}"
        );
    }

    #[test]
    fn validate_accepts_consistent_graph() {
        // git.can_use=["ssh"], "ssh" defined
        let mut git = minimal_command_entry("git");
        git.can_use = vec!["ssh".into()];
        let ssh = minimal_command_entry("ssh");
        let cfg = MediationConfig {
            commands: vec![git, ssh],
            session_can_use: vec!["git".into()],
            ..Default::default()
        };
        validate_can_use_graph(&cfg).expect("consistent graph must validate");
    }

    // --- Mutual-consent validation tests ---

    #[test]
    fn validate_rejects_from_without_can_use() {
        use crate::mediation::{CallerBinding, CallerBindingEntry, CallerAction};
        // "ddtool" has from["claude"] = passthrough, but "claude".can_use does not list "ddtool"
        let mut ddtool = minimal_command_entry("ddtool");
        ddtool.from.insert(
            "claude".to_string(),
            CallerBinding::Bound(CallerBindingEntry {
                action: CallerAction::Passthrough,
                sandbox: None,
            }),
        );
        let claude = minimal_command_entry("claude");
        let cfg = MediationConfig {
            commands: vec![ddtool, claude],
            ..Default::default()
        };
        let err = validate_can_use_graph(&cfg)
            .expect_err("from without can_use must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("ddtool"), "msg should name the callee: {msg}");
        assert!(msg.contains("claude"), "msg should name the caller: {msg}");
        assert!(msg.contains("mutual consent"), "msg should mention mutual consent: {msg}");
    }

    #[test]
    fn validate_rejects_deny_with_can_use_contradiction() {
        use crate::mediation::{CallerBinding, DenyKeyword};
        // "ddtool" has from["claude"] = deny, but "claude".can_use lists "ddtool" — contradiction
        let mut ddtool = minimal_command_entry("ddtool");
        ddtool.from.insert(
            "claude".to_string(),
            CallerBinding::Deny(DenyKeyword),
        );
        let mut claude = minimal_command_entry("claude");
        claude.can_use = vec!["ddtool".into()];
        let cfg = MediationConfig {
            commands: vec![ddtool, claude],
            ..Default::default()
        };
        let err = validate_can_use_graph(&cfg)
            .expect_err("deny contradicting can_use must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("contradiction"), "msg should mention contradiction: {msg}");
    }

    #[test]
    fn validate_rejects_from_with_unknown_caller() {
        use crate::mediation::{CallerBinding, CallerBindingEntry, CallerAction};
        let mut ddtool = minimal_command_entry("ddtool");
        ddtool.from.insert(
            "nobody".to_string(),
            CallerBinding::Bound(CallerBindingEntry {
                action: CallerAction::Allow,
                sandbox: None,
            }),
        );
        let cfg = MediationConfig {
            commands: vec![ddtool],
            ..Default::default()
        };
        let err = validate_can_use_graph(&cfg)
            .expect_err("dangling caller must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("nobody"), "msg should name the unknown caller: {msg}");
    }

    #[test]
    fn validate_accepts_from_with_mutual_can_use() {
        use crate::mediation::{CallerBinding, CallerBindingEntry, CallerAction};
        // "ddtool" from["claude"] = passthrough; "claude".can_use = ["ddtool"]
        let mut ddtool = minimal_command_entry("ddtool");
        ddtool.from.insert(
            "claude".to_string(),
            CallerBinding::Bound(CallerBindingEntry {
                action: CallerAction::Passthrough,
                sandbox: None,
            }),
        );
        let mut claude = minimal_command_entry("claude");
        claude.can_use = vec!["ddtool".into()];
        let cfg = MediationConfig {
            commands: vec![ddtool, claude],
            session_can_use: vec!["claude".into()],
            ..Default::default()
        };
        validate_can_use_graph(&cfg).expect("consistent from+can_use must validate");
    }

    #[test]
    fn validate_rejects_passthrough_without_can_use() {
        use crate::mediation::{CallerBinding, CallerBindingEntry, CallerAction};
        // security.from["gh"] = passthrough, but gh.can_use does not list "security"
        // Should fail: mutual consent not satisfied
        let mut security = minimal_command_entry("security");
        security.from.insert(
            "gh".to_string(),
            CallerBinding::Bound(CallerBindingEntry {
                action: CallerAction::Passthrough,
                sandbox: None,
            }),
        );
        let gh = minimal_command_entry("gh"); // can_use is empty — does not list "security"
        let cfg = MediationConfig {
            commands: vec![security, gh],
            ..Default::default()
        };
        let err = validate_can_use_graph(&cfg)
            .expect_err("passthrough from without can_use must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("security"), "msg should name the callee: {msg}");
        assert!(msg.contains("gh"), "msg should name the caller: {msg}");
        assert!(msg.contains("mutual consent"), "msg should mention mutual consent: {msg}");
    }

    #[test]
    fn validate_accepts_passthrough_with_can_use() {
        use crate::mediation::{CallerBinding, CallerBindingEntry, CallerAction};
        // security.from["gh"] = passthrough, AND gh.can_use lists "security"
        // Should pass: mutual consent satisfied
        let mut security = minimal_command_entry("security");
        security.from.insert(
            "gh".to_string(),
            CallerBinding::Bound(CallerBindingEntry {
                action: CallerAction::Passthrough,
                sandbox: None,
            }),
        );
        let mut gh = minimal_command_entry("gh");
        gh.can_use = vec!["security".into()];
        let cfg = MediationConfig {
            commands: vec![security, gh],
            session_can_use: vec!["gh".into()],
            ..Default::default()
        };
        validate_can_use_graph(&cfg).expect("passthrough with mutual can_use must validate");
    }

    // ---------------------------------------------------------------------------
    // pin_binary / verify_pin tests
    // ---------------------------------------------------------------------------

    #[test]
    fn pin_binary_captures_identity() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tool");
        std::fs::write(&p, b"#!/bin/sh\necho hi\n").unwrap();
        let pin = pin_binary(&p).expect("pins");
        assert_eq!(pin.size, 18);
        assert_eq!(pin.sha256.len(), 64);
    }

    #[test]
    fn verify_pin_fails_on_swap() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tool");
        std::fs::write(&p, b"original").unwrap();
        let pin = pin_binary(&p).unwrap();
        std::fs::write(&p, b"swapped-larger-content").unwrap();
        assert!(
            verify_pin(&p, &pin).is_err(),
            "swapped binary must fail verification"
        );
    }

    #[test]
    fn verify_pin_passes_when_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tool");
        std::fs::write(&p, b"original").unwrap();
        let pin = pin_binary(&p).unwrap();
        verify_pin(&p, &pin).expect("unchanged binary must verify");
    }
}
