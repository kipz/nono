//! Async Unix socket server for the mediation layer.
//!
//! Listens on a Unix socket in the unsandboxed parent process. Each connection
//! from a shim binary is handled concurrently: the framed JSON request is read,
//! dispatched to `policy::apply`, and the framed JSON response is written back.
//!
//! Protocol (same as nono-shim):
//!   Request:  u32 big-endian length || JSON payload
//!   Response: u32 big-endian length || JSON payload

use super::approval::ApprovalGate;
use super::broker::TokenBroker;
use super::policy::{apply, ShimRequest, ShimResponse};
use super::session::ResolvedCommand;
use nix::libc;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, warn};

/// Maximum request size: 1 MiB. Prevents a rogue same-user process from causing
/// a large allocation before the session token check can reject it.
const MAX_REQUEST_SIZE: u32 = 1024 * 1024;

/// Run the mediation server.
///
/// Binds to `socket_path` and accepts connections indefinitely. Each connection
/// is handled in its own `tokio::spawn` task. This function only returns if the
/// listener fails to bind or accept.
pub async fn run(
    socket_path: PathBuf,
    commands: Vec<ResolvedCommand>,
    broker: Arc<TokenBroker>,
    session_token: Arc<str>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
) -> std::io::Result<()> {
    // Remove stale socket file if present
    let _ = std::fs::remove_file(&socket_path);

    let listener = bind_socket_owner_only(&socket_path)?;
    debug!("Mediation server listening on {}", socket_path.display());

    let commands = Arc::new(commands);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let cmds = Arc::clone(&commands);
                let broker = Arc::clone(&broker);
                let token = Arc::clone(&session_token);
                let approval = Arc::clone(&approval);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &cmds, broker, token, approval).await
                    {
                        warn!("mediation: connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("mediation: accept error: {}", e);
                return Err(e);
            }
        }
    }
}

/// Handle a single shim connection: read request, apply policy, write response.
async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    commands: &[ResolvedCommand],
    broker: Arc<TokenBroker>,
    session_token: Arc<str>,
    approval: Arc<dyn ApprovalGate + Send + Sync>,
) -> std::io::Result<()> {
    // Read length-prefixed request. Reject oversized payloads before allocating
    // to prevent a rogue same-user process from causing a large allocation.
    let len = stream.read_u32().await?;
    if len > MAX_REQUEST_SIZE {
        warn!(
            "mediation: rejected oversized request ({} bytes > {} limit)",
            len, MAX_REQUEST_SIZE
        );
        return Ok(());
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let request: ShimRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            warn!("mediation: failed to parse request: {}", e);
            let err_resp = ShimResponse {
                stdout: String::new(),
                stderr: format!("nono-mediation: invalid request: {}\n", e),
                exit_code: 127,
            };
            write_response(&mut stream, &err_resp).await?;
            return Ok(());
        }
    };

    // Verify session token before processing. Silent reject — no response sent.
    // This blocks same-user rogue processes that can reach the socket but don't
    // know the session token injected into the child environment.
    if request.session_token != session_token.as_ref() {
        warn!("mediation: rejected connection with invalid session token");
        return Ok(());
    }

    debug!(
        "mediation: request command='{}' args={:?}",
        request.command, request.args
    );

    let response = apply(request, commands, broker, approval).await;

    write_response(&mut stream, &response).await
}

/// Write a length-prefixed JSON response.
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    response: &ShimResponse,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(std::io::Error::other)?;

    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

/// Bind a Unix socket with restrictive permissions from creation time (0o600).
///
/// Acquires a process-wide umask lock, sets umask to 0o077, binds the socket,
/// then restores the previous umask. This avoids a TOCTOU window where a freshly
/// bound socket could be accessible to other users before `set_permissions` runs.
fn bind_socket_owner_only(path: &Path) -> std::io::Result<tokio::net::UnixListener> {
    let lock = umask_guard();
    let _guard = lock.lock().map_err(|_| {
        std::io::Error::other("mediation: failed to acquire umask synchronization lock")
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
