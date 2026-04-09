//! Approval gate abstraction for admin-gated intercept rules.
//!
//! The `ApprovalGate` trait abstracts the mechanism used to obtain human
//! approval before executing a command guarded by `admin: true`.
//!
//! `NativeApprovalGate` spawns `nono-approve` (a separate binary that presents
//! a native macOS TouchID/password dialog). The gate is synchronous; callers
//! must wrap it in `tokio::task::spawn_blocking` when called from async code.
//!
//! `AlwaysAllow` and `AlwaysDeny` are test doubles.

use tracing::warn;

/// Synchronous gate that decides whether a command invocation is approved.
///
/// Implementations must be `Send + Sync` so they can be shared across tokio tasks.
pub trait ApprovalGate: Send + Sync {
    /// Returns `true` if the invocation is approved, `false` if denied.
    ///
    /// This method may block (e.g. waiting for user interaction). Callers from
    /// async contexts must use `tokio::task::spawn_blocking`.
    fn approve(&self, command: &str, args: &[String]) -> bool;
}

/// Production gate: spawns `nono-approve` and interprets its exit code.
pub struct NativeApprovalGate;

impl ApprovalGate for NativeApprovalGate {
    fn approve(&self, command: &str, args: &[String]) -> bool {
        let binary = match find_approve_binary() {
            Some(p) => p,
            None => {
                warn!(
                    "nono-approve binary not found; denying command '{}'",
                    command
                );
                return false;
            }
        };

        let status = std::process::Command::new(&binary)
            .arg(command)
            .args(args)
            .status();

        match status {
            Ok(s) => s.success(),
            Err(e) => {
                warn!(
                    "nono-approve: failed to spawn '{}': {}; denying command '{}'",
                    binary.display(),
                    e,
                    command
                );
                false
            }
        }
    }
}

/// Find the `nono-approve` binary.
///
/// Looks next to the running `nono` executable first, then falls back to PATH.
fn find_approve_binary() -> Option<std::path::PathBuf> {
    // 1. Look next to current exe
    if let Ok(exe) = std::env::current_exe() {
        let candidate = exe.with_file_name("nono-approve");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    // 2. Try PATH
    which::which("nono-approve").ok()
}

/// Test double: always approves.
#[cfg(test)]
pub struct AlwaysAllow;

#[cfg(test)]
impl ApprovalGate for AlwaysAllow {
    fn approve(&self, _command: &str, _args: &[String]) -> bool {
        true
    }
}

/// Test double: always denies.
#[cfg(test)]
pub struct AlwaysDeny;

#[cfg(test)]
impl ApprovalGate for AlwaysDeny {
    fn approve(&self, _command: &str, _args: &[String]) -> bool {
        false
    }
}
