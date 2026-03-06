//! Async Unix socket server for the mediation layer.
//!
//! Listens on a Unix socket in the unsandboxed parent process. Each connection
//! from a shim binary is handled concurrently: the framed JSON request is read,
//! dispatched to `policy::apply`, and the framed JSON response is written back.
//!
//! Protocol (same as nono-shim):
//!   Request:  u32 big-endian length || JSON payload
//!   Response: u32 big-endian length || JSON payload

use super::policy::{apply, ShimRequest, ShimResponse};
use super::session::ResolvedCommand;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tracing::{debug, error, warn};

/// Run the mediation server.
///
/// Binds to `socket_path` and accepts connections indefinitely. Each connection
/// is handled in its own `tokio::spawn` task. This function only returns if the
/// listener fails to bind or accept.
pub async fn run(socket_path: PathBuf, commands: Vec<ResolvedCommand>) -> std::io::Result<()> {
    // Remove stale socket file if present
    let _ = std::fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)?;
    debug!("Mediation server listening on {}", socket_path.display());

    let commands = Arc::new(commands);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let cmds = Arc::clone(&commands);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, &cmds).await {
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
) -> std::io::Result<()> {
    // Read length-prefixed request
    let len = stream.read_u32().await? as usize;
    let mut buf = vec![0u8; len];
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

    debug!(
        "mediation: request command='{}' args={:?}",
        request.command, request.args
    );

    let response = apply(request, commands).await;

    write_response(&mut stream, &response).await
}

/// Write a length-prefixed JSON response.
async fn write_response(
    stream: &mut tokio::net::UnixStream,
    response: &ShimResponse,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(response)
        .map_err(std::io::Error::other)?;

    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}
