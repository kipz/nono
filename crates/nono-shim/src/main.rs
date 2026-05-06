//! nono-shim: universal command proxy for nono mediation.
//!
//! This binary is invoked in place of a real command (via a shim symlink in the
//! sandbox PATH). It operates in one of two modes:
//!
//! **Mediated mode** (command listed in `NONO_MEDIATED_COMMANDS`):
//! Forwards the invocation to the nono mediation server running in the
//! unsandboxed parent process, which applies policy and either returns a
//! configured response or execs the real binary. The shim's own
//! stdin/stdout/stderr are passed to the server via SCM_RIGHTS so that the
//! real binary, when it is exec'd, can stream binary data through them
//! directly (e.g. ssh/git over a binary pipe).
//!
//! **Audit mode** (all other commands):
//! Sends a fire-and-forget audit event via datagram to the audit socket,
//! then resolves the real binary (skipping the shim directory) and `execve`s
//! it directly. The command runs inside the sandbox with no mediation overhead.
//!
//! Mediated protocol:
//!   1. Request:  u32 (big-endian length) || JSON {"command":..., "args":..., ...}
//!   2. Three SCM_RIGHTS messages on the same socket — fds 0, 1, 2 in that order.
//!   3. Response: u32 (big-endian length) || JSON {"stdout":..., "stderr":..., "exit_code":...}
//!
//! For passthrough cases the response's stdout/stderr are empty strings; the
//! real binary already streamed its output through the passed fds. For
//! buffered cases (Capture/Respond/Approve) the response carries the buffered
//! output and the shim writes it to its own stdout/stderr.
//!
//! The shim reads its own name from argv[0] to determine which command it represents.
//! The socket path is passed via NONO_MEDIATION_SOCKET.
//! Zero tool-specific logic lives here — all policy is in the mediation server.

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

#[derive(Deserialize)]
struct ShimResponse {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

/// Fire-and-forget audit event (matches server-side `AuditEvent`).
#[derive(Serialize)]
struct AuditEvent {
    command: String,
    args: Vec<String>,
    ts: u64,
    exit_code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    action_type: Option<String>,
    /// PID of this shim process — the process that executed the logged command.
    command_pid: u32,
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

/// Check whether a command is in the mediated commands list.
fn is_mediated(name: &str) -> bool {
    if let Ok(list) = std::env::var("NONO_MEDIATED_COMMANDS") {
        list.split(',').any(|c| c == name)
    } else {
        // If the env var isn't set, fall back to treating everything as mediated
        // for backward compatibility with older nono versions.
        true
    }
}

fn run() -> i32 {
    let name = command_name();
    let args: Vec<String> = std::env::args().skip(1).collect();

    if is_mediated(&name) {
        run_mediated(&name, &args)
    } else {
        run_audit(&name, &args)
    }
}

/// Mediated mode: full request-response flow via the mediation server.
///
/// In addition to the JSON request, the shim sends its stdin/stdout/stderr
/// fds over SCM_RIGHTS so the server can stream binary data directly to/from
/// the real binary in passthrough cases without any buffering.
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

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("nono-shim: failed to connect to {}: {}", socket_path, e);
            return 127;
        }
    };

    // Send length-prefixed request
    let len = request_bytes.len() as u32;
    if stream.write_all(&len.to_be_bytes()).is_err() || stream.write_all(&request_bytes).is_err() {
        eprintln!("nono-shim: failed to send request");
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

/// Audit mode: fork+wait the real binary, then send completion audit event.
fn run_audit(command_name: &str, args: &[String]) -> i32 {
    // Resolve the real binary
    let real_binary = match resolve_real_binary(command_name) {
        Some(p) => p,
        None => {
            eprintln!("nono-shim: {}: command not found", command_name);
            return 127;
        }
    };

    // Fork+wait so we can capture the exit code for audit logging
    let exit_code = match std::process::Command::new(&real_binary).args(args).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => {
            eprintln!(
                "nono-shim: exec failed for {}: {}",
                real_binary.display(),
                e
            );
            127
        }
    };

    // Send audit event with exit code (best-effort, non-blocking)
    send_audit_event(command_name, args, exit_code);

    exit_code
}

/// Send a fire-and-forget audit event via datagram socket.
fn send_audit_event(command_name: &str, args: &[String], exit_code: i32) {
    let audit_socket = match std::env::var("NONO_AUDIT_SOCKET") {
        Ok(p) => p,
        Err(_) => return, // No audit socket — silently skip
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let event = AuditEvent {
        command: command_name.to_string(),
        args: args.to_vec(),
        ts,
        exit_code,
        action_type: None,
        command_pid: std::process::id(),
    };

    let bytes = match serde_json::to_vec(&event) {
        Ok(b) => b,
        Err(_) => return,
    };

    // Connect + send (fire-and-forget, no response expected)
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(&bytes, &audit_socket);
    }
}

fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    if !path.is_file() {
        return false;
    }
    match path.metadata() {
        Ok(meta) => meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

/// Resolve via the source sidecar written at session start. The session dir
/// holds `<NONO_SHIM_SOURCES_DIR>/<name>` containing the absolute path of the
/// real binary `name` resolved to when the shim was created. Reading this
/// avoids re-walking PATH at exec time, which can race with PATH manipulation
/// in nested shells (e.g. husky hooks) and miss user toolchain dirs that were
/// present at session start but stripped from the inner PATH.
fn resolve_from_sources_sidecar_at(
    sources_dir: Option<&str>,
    command_name: &str,
) -> Option<std::path::PathBuf> {
    let sources_dir = sources_dir?;
    let sidecar = Path::new(sources_dir).join(command_name);
    let recorded = std::fs::read_to_string(&sidecar).ok()?;
    let candidate = std::path::PathBuf::from(recorded.trim());
    if is_executable_file(&candidate) {
        Some(candidate)
    } else {
        None
    }
}

/// Walk PATH searching for `command_name`, skipping `shim_dir` to avoid
/// re-entering the shim. Used as a fallback when the sources sidecar is
/// missing or stale.
fn resolve_from_path_at(
    path_var: &str,
    shim_dir: Option<&str>,
    command_name: &str,
) -> Option<std::path::PathBuf> {
    for dir in path_var.split(':') {
        if let Some(sd) = shim_dir {
            if dir == sd {
                continue;
            }
        }
        let candidate = Path::new(dir).join(command_name);
        if is_executable_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Resolve the real binary for `command_name`. Prefers the source sidecar
/// recorded at session start; falls back to a PATH walk that skips the shim
/// directory.
fn resolve_real_binary(command_name: &str) -> Option<std::path::PathBuf> {
    let sources_dir = std::env::var("NONO_SHIM_SOURCES_DIR").ok();
    if let Some(p) = resolve_from_sources_sidecar_at(sources_dir.as_deref(), command_name) {
        return Some(p);
    }
    let shim_dir = std::env::var("NONO_SHIM_DIR").ok();
    let path_var = std::env::var("PATH").ok()?;
    resolve_from_path_at(&path_var, shim_dir.as_deref(), command_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write_executable(path: &Path, content: &[u8]) {
        std::fs::write(path, content).expect("write executable");
        let mut perms = std::fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("set perms");
    }

    #[test]
    fn sources_sidecar_returns_recorded_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin_dir = tmp.path().join("bin");
        let sources_dir = tmp.path().join("sources");
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        std::fs::create_dir_all(&sources_dir).expect("sources dir");

        let real = bin_dir.join("yarn");
        write_executable(&real, b"#!/bin/sh\necho real\n");
        std::fs::write(sources_dir.join("yarn"), real.display().to_string()).expect("sidecar");

        let resolved =
            resolve_from_sources_sidecar_at(Some(sources_dir.to_str().expect("path is utf-8")), "yarn");
        assert_eq!(resolved.as_deref(), Some(real.as_path()));
    }

    #[test]
    fn sources_sidecar_trims_trailing_newline() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin_dir = tmp.path().join("bin");
        let sources_dir = tmp.path().join("sources");
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        std::fs::create_dir_all(&sources_dir).expect("sources dir");

        let real = bin_dir.join("yarn");
        write_executable(&real, b"#!/bin/sh\n");
        std::fs::write(
            sources_dir.join("yarn"),
            format!("{}\n", real.display()),
        )
        .expect("sidecar");

        let resolved =
            resolve_from_sources_sidecar_at(Some(sources_dir.to_str().expect("path is utf-8")), "yarn");
        assert_eq!(resolved.as_deref(), Some(real.as_path()));
    }

    #[test]
    fn sources_sidecar_returns_none_when_recorded_path_is_gone() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sources_dir = tmp.path().join("sources");
        std::fs::create_dir_all(&sources_dir).expect("sources dir");
        std::fs::write(sources_dir.join("yarn"), "/nonexistent/yarn").expect("sidecar");

        let resolved =
            resolve_from_sources_sidecar_at(Some(sources_dir.to_str().expect("path is utf-8")), "yarn");
        assert!(resolved.is_none());
    }

    #[test]
    fn sources_sidecar_returns_none_when_recorded_path_is_not_executable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let bin_dir = tmp.path().join("bin");
        let sources_dir = tmp.path().join("sources");
        std::fs::create_dir_all(&bin_dir).expect("bin dir");
        std::fs::create_dir_all(&sources_dir).expect("sources dir");

        let real = bin_dir.join("yarn");
        std::fs::write(&real, b"data").expect("write file");
        let mut perms = std::fs::metadata(&real).expect("metadata").permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&real, perms).expect("set perms");

        std::fs::write(sources_dir.join("yarn"), real.display().to_string()).expect("sidecar");

        let resolved =
            resolve_from_sources_sidecar_at(Some(sources_dir.to_str().expect("path is utf-8")), "yarn");
        assert!(resolved.is_none());
    }

    #[test]
    fn sources_sidecar_returns_none_when_dir_unset() {
        let resolved = resolve_from_sources_sidecar_at(None, "yarn");
        assert!(resolved.is_none());
    }

    #[test]
    fn sources_sidecar_returns_none_when_sidecar_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let resolved =
            resolve_from_sources_sidecar_at(Some(tmp.path().to_str().expect("path is utf-8")), "yarn");
        assert!(resolved.is_none());
    }

    #[test]
    fn path_walk_skips_shim_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let shim_dir = tmp.path().join("shims");
        let real_dir = tmp.path().join("real");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        std::fs::create_dir_all(&real_dir).expect("real dir");

        write_executable(&shim_dir.join("yarn"), b"#!/bin/sh\necho shim\n");
        write_executable(&real_dir.join("yarn"), b"#!/bin/sh\necho real\n");

        let path_var = format!(
            "{}:{}",
            shim_dir.to_string_lossy(),
            real_dir.to_string_lossy()
        );
        let resolved =
            resolve_from_path_at(&path_var, Some(shim_dir.to_str().expect("path is utf-8")), "yarn");
        assert_eq!(resolved.as_deref(), Some(real_dir.join("yarn").as_path()));
    }

    #[test]
    fn path_walk_returns_none_when_no_match() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let resolved = resolve_from_path_at(
            tmp.path().to_str().expect("path is utf-8"),
            None,
            "definitely-not-a-real-command",
        );
        assert!(resolved.is_none());
    }
}
