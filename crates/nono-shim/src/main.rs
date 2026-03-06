//! nono-shim: universal command proxy for nono mediation.
//!
//! This binary is invoked in place of a real command (via a shim symlink in the
//! sandbox PATH). It forwards the invocation to the nono mediation server running
//! in the unsandboxed parent process, which applies policy and either returns a
//! configured response or execs the real binary.
//!
//! Protocol: length-prefixed JSON over a Unix stream socket.
//!   Request:  u32 (big-endian length) || JSON {"command":..., "args":..., "stdin":...}
//!   Response: u32 (big-endian length) || JSON {"stdout":..., "stderr":..., "exit_code":...}
//!
//! The shim reads its own name from argv[0] to determine which command it represents.
//! The socket path is passed via NONO_MEDIATION_SOCKET.
//! Zero tool-specific logic lives here — all policy is in the mediation server.

use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

#[derive(Serialize)]
struct ShimRequest {
    command: String,
    args: Vec<String>,
    stdin: String,
}

#[derive(Deserialize)]
struct ShimResponse {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let socket_path = match std::env::var("NONO_MEDIATION_SOCKET") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("nono-shim: NONO_MEDIATION_SOCKET not set");
            return 127;
        }
    };

    // Derive command name from argv[0] (basename only)
    let command_name = std::env::args()
        .next()
        .as_deref()
        .map(|a| {
            Path::new(a)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(a)
                .to_string()
        })
        .unwrap_or_else(|| "unknown".to_string());

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Read all of stdin
    let mut stdin_bytes = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut stdin_bytes);
    let stdin = String::from_utf8_lossy(&stdin_bytes).into_owned();

    let request = ShimRequest {
        command: command_name,
        args,
        stdin,
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
    if stream.write_all(&len.to_be_bytes()).is_err()
        || stream.write_all(&request_bytes).is_err()
    {
        eprintln!("nono-shim: failed to send request");
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

    let _ = std::io::stdout().write_all(response.stdout.as_bytes());
    let _ = std::io::stderr().write_all(response.stderr.as_bytes());

    response.exit_code
}
