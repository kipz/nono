//! nono-shim: mediated-command proxy for nono.
//!
//! This binary is invoked in place of a real command (via a shim symlink in
//! the sandbox PATH). It forwards the invocation to the nono mediation server
//! running in the unsandboxed parent process, which applies policy and either
//! returns a configured response or execs the real binary.
//!
//! The shim's own stdin/stdout/stderr are passed to the server via SCM_RIGHTS
//! so that the real binary, when it is exec'd, can stream binary data through
//! them directly (e.g. ssh/git over a binary pipe).
//!
//! Protocol:
//!   1. Request:  u32 (big-endian length) || JSON {"command":..., "args":..., ...}
//!   2. ACK:      1 byte (0x06) from server — confirms JSON was read, buffer is drained.
//!   3. One SCM_RIGHTS message — stdin/stdout/stderr fds together in one sendmsg.
//!   4. Response: u32 (big-endian length) || JSON {"stdout":..., "stderr":..., "exit_code":...}
//!
//! For passthrough cases the response's stdout/stderr are empty strings; the
//! real binary already streamed its output through the passed fds. For
//! buffered cases (Capture/Respond/Approve) the response carries the buffered
//! output and the shim writes it to its own stdout/stderr.
//!
//! The shim reads its own name from argv[0] to determine which command it
//! represents. The socket path is passed via `NONO_MEDIATION_SOCKET`. Zero
//! tool-specific logic lives here — all policy is in the mediation server.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

#[derive(Serialize)]
struct ShimRequest {
    command: String,
    args: Vec<String>,
    session_token: String,
    env: HashMap<String, String>,
    /// PID of this shim process — used by the server as `command_pid` in audit logs.
    pid: u32,
    /// Working directory of this shim process — the cwd the agent (or mediated
    /// parent) was in when it invoked the command. The server uses this to set
    /// the spawned binary's cwd, so commands like `git` resolve to the caller's
    /// directory rather than the mediation server's launch cwd. `None` (or an
    /// unreadable cwd) leaves the server's default behaviour in place.
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct ShimResponse {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

/// Send stdin, stdout, and stderr as a single SCM_RIGHTS message.
///
/// Batching all three fds into one `sendmsg` call avoids a macOS-specific
/// failure where sending multiple SCM_RIGHTS messages sequentially returns
/// EMSGSIZE when the socket receive buffer already holds a large JSON request
/// (as happens when `git` is invoked from within `gh`'s execution sandbox).
///
/// Inlined from the nono crate so the shim's dependency footprint stays minimal.
fn send_stdio_fds(
    sock_fd: RawFd,
    stdin: RawFd,
    stdout: RawFd,
    stderr: RawFd,
) -> std::io::Result<()> {
    let fds = [stdin, stdout, stderr];
    let fd_size = std::mem::size_of::<RawFd>();
    let payload_len = fds.len() * fd_size;

    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    // SAFETY: `CMSG_SPACE` and `CMSG_LEN` are pure libc size calculations.
    let cmsg_space = unsafe { libc::CMSG_SPACE(payload_len as u32) } as usize;
    let cmsg_len = unsafe { libc::CMSG_LEN(payload_len as u32) };

    let mut cmsg_buf = vec![0u8; cmsg_space];
    // SAFETY: `msghdr` is plain old data and will be fully initialized below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: `msg` references `cmsg_buf`, which is large enough for the header.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr as *mut libc::msghdr) };
    if cmsg.is_null() {
        return Err(std::io::Error::other(
            "Missing ancillary header for SCM_RIGHTS send",
        ));
    }

    // SAFETY: `cmsg` points into `cmsg_buf`, sized for the header + 3 fd payloads.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = cmsg_len as _;
        for (i, &fd) in fds.iter().enumerate() {
            std::ptr::copy_nonoverlapping(
                (&fd as *const RawFd).cast::<u8>(),
                libc::CMSG_DATA(cmsg).add(i * fd_size),
                fd_size,
            );
        }
    }

    // SAFETY: `sock_fd` is a valid Unix socket and `msg` points to live buffers.
    let sent = unsafe { libc::sendmsg(sock_fd, &msg, 0) };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

fn main() {
    let code = run();
    std::process::exit(code);
}

/// Derive the command name from argv[0] (basename only).
fn command_name() -> String {
    std::env::args()
        .next()
        .as_deref()
        .map(|a| {
            Path::new(a)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(a)
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string())
}

fn run() -> i32 {
    let name = command_name();
    let args: Vec<String> = std::env::args().skip(1).collect();
    run_mediated(&name, &args)
}

/// Forward the invocation to the mediation server via UDS, passing stdio fds
/// over SCM_RIGHTS so the server can stream binary data directly to/from the
/// real binary in passthrough cases without buffering.
fn run_mediated(command_name: &str, args: &[String]) -> i32 {
    let socket_path = match std::env::var("NONO_MEDIATION_SOCKET") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("nono-shim: NONO_MEDIATION_SOCKET not set");
            return 127;
        }
    };

    let session_token = match std::env::var("NONO_SESSION_TOKEN") {
        Ok(t) => t,
        Err(_) => {
            eprintln!("nono-shim: NONO_SESSION_TOKEN not set");
            return 127;
        }
    };

    let env: HashMap<String, String> = std::env::vars().collect();

    // Capture the shim's cwd. This is the agent's (or mediated parent's) cwd
    // at the moment of invocation — propagated to the server so the spawned
    // real binary runs in the caller's directory, not the server's launch cwd.
    // Failure to read or stringify the cwd is non-fatal: send None and the
    // server falls back to its default (its own cwd).
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.into_os_string().into_string().ok());

    let request = ShimRequest {
        command: command_name.to_string(),
        args: args.to_vec(),
        session_token,
        env,
        pid: std::process::id(),
        cwd,
    };

    let request_bytes = match serde_json::to_vec(&request) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("nono-shim: failed to serialize request: {}", e);
            return 127;
        }
    };

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nono-shim: failed to connect to {}: {}", socket_path, e);
            return 127;
        }
    };

    execute_on_stream(stream, request_bytes)
}

/// Run the shim protocol on an already-connected stream. Extracted for testability.
///
/// Sends the length-prefixed request, waits for the ACK, sends stdio fds via
/// SCM_RIGHTS, then reads and applies the length-prefixed response.
fn execute_on_stream(mut stream: UnixStream, request_bytes: Vec<u8>) -> i32 {
    // Send length-prefixed request
    let len = request_bytes.len() as u32;
    if stream.write_all(&len.to_be_bytes()).is_err() || stream.write_all(&request_bytes).is_err() {
        eprintln!("nono-shim: failed to send request");
        return 127;
    }

    // Wait for the server to acknowledge that it has read the JSON body.
    // The server sends a single ACK byte (0x06) once the socket receive buffer
    // is drained. Without this, the subsequent sendmsg with SCM_RIGHTS can fail
    // with EMSGSIZE on macOS when the JSON body is large enough to fill the
    // ~8 KB UDS receive buffer — there is then no contiguous space for the
    // ancillary control message even in a single sendmsg call.
    let mut ack = [0u8; 1];
    if stream.read_exact(&mut ack).is_err() || ack[0] != 0x06 {
        eprintln!("nono-shim: did not receive fd-send ACK from server");
        return 127;
    }

    // Pass stdin/stdout/stderr as a single SCM_RIGHTS message so the server
    // can wire them directly to the real binary in passthrough cases.
    let sock_fd = stream.as_raw_fd();
    if let Err(e) = send_stdio_fds(
        sock_fd,
        libc::STDIN_FILENO,
        libc::STDOUT_FILENO,
        libc::STDERR_FILENO,
    ) {
        eprintln!("nono-shim: failed to send stdio fds: {}", e);
        return 127;
    }

    // Read length-prefixed response
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        eprintln!("nono-shim: failed to read response length");
        return 127;
    }
    let resp_len = u32::from_be_bytes(len_buf) as usize;

    let mut resp_buf = vec![0u8; resp_len];
    if stream.read_exact(&mut resp_buf).is_err() {
        eprintln!("nono-shim: failed to read response body");
        return 127;
    }

    let response: ShimResponse = match serde_json::from_slice(&resp_buf) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("nono-shim: failed to parse response: {}", e);
            return 127;
        }
    };

    // For passthrough cases the real binary already wrote to our stdout/stderr
    // directly via the passed fds, so these strings are empty. Buffered cases
    // (Capture/Respond/Approve) carry the output here.
    if !response.stdout.is_empty() {
        let _ = std::io::stdout().write_all(response.stdout.as_bytes());
    }
    if !response.stderr.is_empty() {
        let _ = std::io::stderr().write_all(response.stderr.as_bytes());
    }

    response.exit_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Verify the ACK handshake: the shim must wait for the server's 0x06 ACK
    /// before sending stdio fds, and the full protocol must round-trip correctly.
    ///
    /// This guards against regressions where the shim sends fds before the server
    /// has drained the JSON from the socket buffer, causing EMSGSIZE on macOS.
    #[test]
    fn ack_handshake_round_trips() {
        let dir = std::env::temp_dir();
        let sock_path = dir.join(format!("nono-shim-test-{}.sock", std::process::id()));

        let listener = UnixListener::bind(&sock_path).expect("bind");

        // Minimal JSON request — small enough to fit in the buffer, but exercises
        // the full protocol including the ACK gate and SCM_RIGHTS transfer.
        let request = ShimRequest {
            command: "echo".to_string(),
            args: vec!["hello".to_string()],
            session_token: "test-token".to_string(),
            env: HashMap::new(),
            pid: std::process::id(),
            cwd: None,
        };
        let request_bytes = serde_json::to_vec(&request).unwrap();

        let mock_response = serde_json::to_vec(&ShimResponse {
            stdout: "hello\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        })
        .unwrap();

        // Server thread: verify protocol order and return a mock response.
        let server = std::thread::spawn({
            let mock_response = mock_response.clone();
            move || {
                let (mut conn, _) = listener.accept().unwrap();

                // 1. Read length-prefixed JSON
                let mut len_buf = [0u8; 4];
                conn.read_exact(&mut len_buf).unwrap();
                let len = u32::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                conn.read_exact(&mut body).unwrap();

                // 2. Send ACK — signals the shim it may now sendmsg the fds
                conn.write_all(&[0x06u8]).unwrap();
                conn.flush().unwrap();

                // 3. Receive the three stdio fds via SCM_RIGHTS
                let fd_size = std::mem::size_of::<RawFd>();
                let n: usize = 3;
                let payload_len = n * fd_size;
                let mut data = [0u8; 1];
                let mut iov = libc::iovec {
                    iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
                    iov_len: 1,
                };
                let cmsg_space = unsafe { libc::CMSG_SPACE(payload_len as u32) } as usize;
                let mut cmsg_buf = vec![0u8; cmsg_space];
                let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                msg.msg_iov = &mut iov as *mut libc::iovec;
                msg.msg_iovlen = 1;
                msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
                msg.msg_controllen = cmsg_space as _;
                let received = unsafe { libc::recvmsg(conn.as_raw_fd(), &mut msg, 0) };
                assert!(received >= 0, "recvmsg failed: {}", std::io::Error::last_os_error());
                assert_eq!(msg.msg_flags & libc::MSG_CTRUNC, 0, "ancillary data truncated");

                // 4. Send mock response
                let rlen = mock_response.len() as u32;
                conn.write_all(&rlen.to_be_bytes()).unwrap();
                conn.write_all(&mock_response).unwrap();
            }
        });

        let client = UnixStream::connect(&sock_path).unwrap();
        let exit_code = execute_on_stream(client, request_bytes);

        server.join().expect("server thread panicked");
        let _ = std::fs::remove_file(&sock_path);

        assert_eq!(exit_code, 0);
    }
}
