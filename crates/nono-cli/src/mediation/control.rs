//! Control socket server for admin mode.
//!
//! A second Unix socket (`control.sock`) in the session directory, alongside
//! `mediation.sock`. The control socket allows privileged processes (the native
//! menu bar app or `nono admin` CLI) to enable/disable admin mode.
//!
//! Authentication uses a separate `control_token` (256-bit random, hex-encoded)
//! that is written only to `session.json` (mode 600) and never passed to the
//! sandboxed child. This is distinct from the mediation `session_token` which
//! lives in the child's environment.
//!
//! Protocol (same framing as mediation socket):
//!   Request:  u32 big-endian length || JSON payload
//!   Response: u32 big-endian length || JSON payload

use super::admin::{write_admin_audit, AdminModeStatus, AdminState};
use nix::libc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, warn};

/// Generate a 256-bit random token, hex-encoded.
pub fn generate_token() -> String {
    use rand::RngExt;
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// A request to the control socket.
#[derive(Debug, Deserialize)]
pub struct ControlRequest {
    pub token: String,
    pub action: ControlAction,
    /// Seconds for admin mode to be active (used by `enable` only).
    #[serde(default = "default_duration_secs")]
    pub duration_secs: u64,
    /// Audit label for who granted/revoked access (e.g. "TouchID", "CLI").
    #[serde(default)]
    pub granted_by: String,
}

fn default_duration_secs() -> u64 {
    600
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    Enable,
    Disable,
    Status,
}

/// A response from the control socket.
#[derive(Debug, Serialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ControlResponse {
    fn ok_status(status: &str) -> Self {
        Self {
            ok: true,
            status: Some(status.to_string()),
            expires_at_unix: None,
            granted_by: None,
            error: None,
        }
    }

    fn err(msg: &str) -> Self {
        Self {
            ok: false,
            status: None,
            expires_at_unix: None,
            granted_by: None,
            error: Some(msg.to_string()),
        }
    }
}

const MAX_REQUEST_SIZE: u32 = 64 * 1024;

/// Run the control socket server.
///
/// Binds to `control_socket_path` and handles enable/disable/status requests.
/// Validates `control_token` with constant-time comparison before dispatching.
pub async fn run_control_server(
    control_socket_path: PathBuf,
    control_token: String,
    admin_state: AdminState,
    session_dir: PathBuf,
) -> std::io::Result<()> {
    let _ = std::fs::remove_file(&control_socket_path);

    let listener = bind_socket_owner_only(&control_socket_path)?;
    debug!(
        "Control server listening on {}",
        control_socket_path.display()
    );

    let token = Arc::new(control_token);
    let state = Arc::new(admin_state);
    let sdir = Arc::new(session_dir);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let t = Arc::clone(&token);
                let s = Arc::clone(&state);
                let sd = Arc::clone(&sdir);
                tokio::spawn(async move {
                    if let Err(e) = handle_control_connection(stream, &t, &s, &sd).await {
                        warn!("control: connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
}

async fn handle_control_connection(
    mut stream: tokio::net::UnixStream,
    control_token: &str,
    admin_state: &AdminState,
    session_dir: &Path,
) -> std::io::Result<()> {
    let len = stream.read_u32().await?;
    if len > MAX_REQUEST_SIZE {
        warn!(
            "control: rejected oversized request ({} bytes > {} limit)",
            len, MAX_REQUEST_SIZE
        );
        return Ok(());
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let req: ControlRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            warn!("control: failed to parse request: {}", e);
            let resp = ControlResponse::err("invalid request");
            write_control_response(&mut stream, &resp).await?;
            return Ok(());
        }
    };

    // Validate token with constant-time comparison
    {
        use subtle::ConstantTimeEq;
        let token_eq: bool = req.token.as_bytes().ct_eq(control_token.as_bytes()).into();
        if !token_eq {
            warn!("control: rejected connection with invalid control token");
            let resp = ControlResponse::err("unauthorized");
            write_control_response(&mut stream, &resp).await?;
            return Ok(());
        }
    }

    let resp = dispatch(req, admin_state, session_dir).await;
    write_control_response(&mut stream, &resp).await
}

async fn dispatch(
    req: ControlRequest,
    admin_state: &AdminState,
    session_dir: &Path,
) -> ControlResponse {
    match req.action {
        ControlAction::Status => {
            let status = admin_state.current();
            match &status {
                AdminModeStatus::Disabled => ControlResponse::ok_status("disabled"),
                AdminModeStatus::Active {
                    expires_at,
                    granted_by,
                } => {
                    if Instant::now() < *expires_at {
                        let secs_remaining = expires_at
                            .checked_duration_since(Instant::now())
                            .unwrap_or(Duration::ZERO)
                            .as_secs();
                        let expires_unix = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() + secs_remaining)
                            .unwrap_or(0);
                        ControlResponse {
                            ok: true,
                            status: Some("active".to_string()),
                            expires_at_unix: Some(expires_unix),
                            granted_by: Some(granted_by.clone()),
                            error: None,
                        }
                    } else {
                        ControlResponse::ok_status("disabled")
                    }
                }
            }
        }
        ControlAction::Enable => {
            let duration = Duration::from_secs(req.duration_secs);
            let expires_at = Instant::now() + duration;
            let expires_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() + req.duration_secs)
                .unwrap_or(0);

            let granted_by = req.granted_by.clone();
            let pid = std::process::id();
            warn!(
                "admin mode ENABLED granted_by=\"{}\" duration_secs={} session_pid={}",
                granted_by, req.duration_secs, pid
            );

            write_admin_audit(
                session_dir,
                &serde_json::json!({
                    "event": "enabled",
                    "granted_by": &granted_by,
                    "expires_at_unix": expires_unix,
                    "at": chrono::Utc::now().to_rfc3339(),
                }),
            );

            admin_state.set(AdminModeStatus::Active {
                expires_at,
                granted_by: granted_by.clone(),
            });

            // Spawn an expiry task that resets to Disabled when the timer fires.
            let state_clone = admin_state.clone();
            let sdir = session_dir.to_path_buf();
            let gb = granted_by.clone();
            tokio::spawn(async move {
                tokio::time::sleep(duration).await;
                // Only reset if still Active (might have been disabled manually)
                let current = state_clone.current();
                if current.is_active() {
                    warn!("admin mode EXPIRED session_pid={}", pid);
                    write_admin_audit(
                        &sdir,
                        &serde_json::json!({
                            "event": "expired",
                            "granted_by": &gb,
                            "at": chrono::Utc::now().to_rfc3339(),
                        }),
                    );
                    state_clone.set(AdminModeStatus::Disabled);
                }
            });

            ControlResponse {
                ok: true,
                status: Some("active".to_string()),
                expires_at_unix: Some(expires_unix),
                granted_by: Some(granted_by),
                error: None,
            }
        }
        ControlAction::Disable => {
            let current = admin_state.current();
            if !current.is_active() {
                return ControlResponse::err("already disabled");
            }

            let granted_by = if req.granted_by.is_empty() {
                "unknown".to_string()
            } else {
                req.granted_by.clone()
            };
            let pid = std::process::id();
            warn!(
                "admin mode DISABLED granted_by=\"{}\" session_pid={}",
                granted_by, pid
            );

            write_admin_audit(
                session_dir,
                &serde_json::json!({
                    "event": "disabled",
                    "granted_by": &granted_by,
                    "at": chrono::Utc::now().to_rfc3339(),
                }),
            );

            admin_state.set(AdminModeStatus::Disabled);
            ControlResponse::ok_status("disabled")
        }
    }
}

async fn write_control_response(
    stream: &mut tokio::net::UnixStream,
    resp: &ControlResponse,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(resp).map_err(std::io::Error::other)?;
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn bind_socket_owner_only(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    let lock = umask_guard();
    let _guard = lock.lock().map_err(|_| {
        std::io::Error::other("control: failed to acquire umask synchronization lock")
    })?;

    let old_umask = unsafe { libc::umask(0o077) };
    let std_listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
        unsafe { libc::umask(old_umask) };
        e
    });
    unsafe { libc::umask(old_umask) };

    let std_listener = std_listener?;
    std_listener.set_nonblocking(true)?;
    tokio::net::UnixListener::from_std(std_listener)
}

fn umask_guard() -> &'static Mutex<()> {
    static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    UMASK_LOCK.get_or_init(|| Mutex::new(()))
}
