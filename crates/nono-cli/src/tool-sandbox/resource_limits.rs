//! Dynamic sizing for tool-sandbox concurrency caps.
//!
//! Each in-flight shim connection or actively-launched child process holds a
//! handful of file descriptors (accepted socket / pipes plus stdio). A fixed
//! concurrency cap sized for a low default `RLIMIT_NOFILE` (e.g. macOS
//! launchd's 256) needlessly throttles callers under a raised limit, while a
//! cap sized for a high limit exhausts a low-limit host with EMFILE. Size
//! both caps from the process's actual soft `RLIMIT_NOFILE` at first use
//! instead of a hardcoded constant.

use nix::libc;
use std::sync::OnceLock;

/// fds consumed per in-flight unit: accepted socket/pipe plus stdin/stdout/stderr.
const FDS_PER_UNIT: usize = 4;
/// fds reserved for the host itself (listener sockets, logs, etc.).
const FD_HEADROOM: usize = 32;

fn soft_nofile_limit() -> usize {
    // SAFETY: rlimit is plain old data; getrlimit is async-signal-safe.
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    if ret == 0 && rl.rlim_cur != libc::RLIM_INFINITY {
        rl.rlim_cur as usize
    } else {
        256
    }
}

fn compute_limit(min: usize, max: usize) -> usize {
    let available = soft_nofile_limit().saturating_sub(FD_HEADROOM);
    (available / FDS_PER_UNIT).clamp(min, max)
}

/// Maximum shim requests queued for the accept loop before new connections
/// are dropped. Restores the sizing approach from the pre-tool-sandbox
/// mediation server (`compute_max_connections`), lost when mediation moved
/// into tool-sandbox.
pub(crate) fn max_queued_shim_requests() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| compute_limit(8, 512))
}

/// Maximum tool-sandbox child processes (credential captures, execs) active
/// at once.
pub(crate) fn max_active_tool_sandbox_children() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| compute_limit(8, 512))
}
