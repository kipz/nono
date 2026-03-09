//! Pre-sandbox session setup for command mediation.
//!
//! `setup()` is called before the sandbox is applied. It:
//! 1. Resolves each configured command name to an absolute path via `which`.
//! 2. Creates `/tmp/nono-session-{pid}/shims/` and symlinks `nono-shim` for each command.
//! 3. Starts the mediation server on a Unix socket.
//! 4. Returns a `SessionHandle` that keeps the server alive and exposes the
//!    paths/env needed by the rest of the startup sequence.

use super::{CommandEntry, CommandSandbox, InterceptAction, MediationConfig};
use super::broker::TokenBroker;
use nono::{NonoError, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info};

/// The action stored in a resolved intercept rule.
#[derive(Clone, Debug)]
pub enum ResolvedAction {
    Respond { stdout: String },
    Capture { script: Option<String> },
}

/// A resolved intercept rule ready for the mediation server.
#[derive(Clone, Debug)]
pub struct ResolvedIntercept {
    pub args_prefix: Vec<String>,
    pub action: ResolvedAction,
    pub exit_code: i32,
}

/// A fully resolved command entry ready for the mediation server.
#[derive(Clone)]
pub struct ResolvedCommand {
    pub name: String,
    /// Absolute path to the real binary (to exec on passthrough).
    pub real_path: PathBuf,
    pub intercepts: Vec<ResolvedIntercept>,
    /// Optional sandbox profile to apply when exec-ing the real binary.
    pub sandbox: Option<CommandSandbox>,
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
    // Tokio runtime kept alive so the server task continues running in the parent.
    _runtime: tokio::runtime::Runtime,
}

impl Drop for SessionHandle {
    fn drop(&mut self) {
        // Clean up the session directory on parent exit.
        let _ = std::fs::remove_dir_all(&self.session_dir);
        debug!("Mediation session directory removed: {}", self.session_dir.display());
    }
}

/// Set up a mediation session.
///
/// Returns `None` when `config.is_active()` is false (nothing to do).
///
/// # Errors
/// Returns an error if a command cannot be resolved, or the session directory /
/// symlinks cannot be created.
pub fn setup(config: &MediationConfig) -> Result<Option<SessionHandle>> {
    if !config.is_active() {
        return Ok(None);
    }

    // Find nono-shim next to the running nono binary.
    let shim_binary = find_shim_binary()?;

    let session_dir = session_dir_path();
    let shim_dir = session_dir.join("shims");
    let socket_path = session_dir.join("mediation.sock");

    std::fs::create_dir_all(&shim_dir).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: failed to create shim dir {}: {}",
            shim_dir.display(),
            e
        ))
    })?;

    // -------------------------------------------------------------------------
    // Resolve commands
    // -------------------------------------------------------------------------
    let mut resolved_commands: Vec<ResolvedCommand> = Vec::new();
    let mut blocked_binaries: Vec<PathBuf> = Vec::new();

    for entry in &config.commands {
        let resolved = resolve_command(entry, &shim_dir, &shim_binary)?;
        blocked_binaries.push(resolved.real_path.clone());
        resolved_commands.push(resolved);
    }

    // -------------------------------------------------------------------------
    // Create token broker (session-scoped)
    // -------------------------------------------------------------------------
    let broker = Arc::new(TokenBroker::new());

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

    let sock = socket_path.clone();
    let cmds = resolved_commands.clone();
    let broker_clone = Arc::clone(&broker);
    runtime.spawn(async move {
        if let Err(e) = super::server::run(sock, cmds, broker_clone).await {
            tracing::error!("mediation server error: {}", e);
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
        _runtime: runtime,
    }))
}

/// Resolve a command entry: find the real binary, create the shim symlink.
fn resolve_command(
    entry: &CommandEntry,
    shim_dir: &Path,
    shim_binary: &Path,
) -> Result<ResolvedCommand> {
    let real_path = if let Some(ref bp) = entry.binary_path {
        let p = PathBuf::from(bp);
        if !p.is_file() {
            return Err(NonoError::SandboxInit(format!(
                "mediation: binary_path for '{}' does not exist or is not a file: {}",
                entry.name, bp
            )));
        }
        p
    } else {
        which::which(&entry.name).map_err(|e| {
            NonoError::SandboxInit(format!(
                "mediation: command '{}' not found on PATH: {}",
                entry.name, e
            ))
        })?
    };
    debug!(
        "Mediation: resolved '{}' -> {}",
        entry.name,
        real_path.display()
    );

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

    // Convert intercept rules
    let intercepts = entry
        .intercept
        .iter()
        .map(|rule| {
            let (action, exit_code) = match &rule.action {
                InterceptAction::Respond { stdout, exit_code } => (
                    ResolvedAction::Respond {
                        stdout: stdout.clone(),
                    },
                    *exit_code,
                ),
                InterceptAction::Capture { script } => (
                    ResolvedAction::Capture {
                        script: script.clone(),
                    },
                    0,
                ),
            };
            ResolvedIntercept {
                args_prefix: rule.args_prefix.clone(),
                action,
                exit_code,
            }
        })
        .collect();

    Ok(ResolvedCommand {
        name: entry.name.clone(),
        real_path,
        intercepts,
        sandbox: entry.sandbox.clone(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_returns_none_when_inactive() {
        let config = MediationConfig::default();
        let result = setup(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_session_dir_path_has_pid() {
        let path = session_dir_path();
        assert!(path.to_string_lossy().contains(&std::process::id().to_string()));
    }
}
