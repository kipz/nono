//! Admin mode state for the mediation server.
//!
//! Admin mode is a per-session, time-limited override that bypasses all
//! mediation policy. When active, every shim request is forwarded as a raw
//! passthrough to the unsandboxed host — no intercept rules, no env var
//! filtering, no nonce promotion.
//!
//! State is shared via a `tokio::sync::watch` channel. The control socket
//! server is the sole writer; all `handle_connection` tasks subscribe.

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;
use tracing::warn;

/// Whether admin mode is currently active for this session.
#[derive(Clone, Debug)]
pub enum AdminModeStatus {
    Disabled,
    Active {
        expires_at: Instant,
        granted_by: String,
    },
}

impl AdminModeStatus {
    /// Returns true if admin mode is currently active and not yet expired.
    pub fn is_active(&self) -> bool {
        match self {
            Self::Disabled => false,
            Self::Active { expires_at, .. } => Instant::now() < *expires_at,
        }
    }
}

/// Shared admin mode state for a session.
#[derive(Clone)]
pub struct AdminState {
    tx: Arc<watch::Sender<AdminModeStatus>>,
}

impl AdminState {
    /// Create a new `AdminState` with admin mode disabled.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(AdminModeStatus::Disabled);
        Self { tx: Arc::new(tx) }
    }

    /// Subscribe to admin mode changes (for mediation server watch tasks).
    pub fn subscribe(&self) -> watch::Receiver<AdminModeStatus> {
        self.tx.subscribe()
    }

    /// Read the current admin mode status without creating a receiver.
    ///
    /// Prefer this over `subscribe().borrow()` for one-shot reads: it reads
    /// directly from the sender's stored value, which is always up-to-date
    /// regardless of whether any receivers exist.
    pub fn current(&self) -> AdminModeStatus {
        self.tx.borrow().clone()
    }

    /// Update admin mode status.
    pub fn set(&self, status: AdminModeStatus) {
        // send_replace stores the value even when there are no receivers.
        self.tx.send_replace(status);
    }
}

/// Append an event to the session's admin audit log.
///
/// The file is append-only JSONL. Errors are logged at warn level (audit
/// failure must not block the operation).
pub fn write_admin_audit(session_dir: &std::path::Path, event: &serde_json::Value) {
    use std::io::Write;

    let path = session_dir.join("admin_audit.jsonl");
    let line = match serde_json::to_string(event) {
        Ok(s) => s,
        Err(e) => {
            warn!("admin audit: failed to serialize event: {}", e);
            return;
        }
    };

    let mut file = match {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
    } {
        Ok(f) => f,
        Err(e) => {
            warn!("admin audit: failed to open {}: {}", path.display(), e);
            return;
        }
    };

    if let Err(e) = writeln!(file, "{}", line) {
        warn!("admin audit: failed to write to {}: {}", path.display(), e);
    }
}
