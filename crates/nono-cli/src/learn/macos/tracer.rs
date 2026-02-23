//! macOS DYLD interpose-based filesystem access tracer
//!
//! Launches the traced command with `DYLD_INSERT_LIBRARIES` pointing to
//! `fork_interpose.dylib`. That dylib intercepts file syscalls and writes
//! `PATH:R` or `PATH:W` lines to a pre-opened file descriptor (`NONO_TRACE_FD`).
//!
//! Child process tracking: the dylib sends `SIGSTOP` to forked children and
//! writes their PIDs to `NONO_COMM_FILE`. The Rust tracer polls that file and
//! sends `SIGCONT` to each stopped child.

use super::interpose::get_interpose_dylib;
use crate::cli::LearnArgs;
use crate::learn::common::FileAccess;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use nono::{NonoError, Result};
use std::collections::HashSet;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Run the DYLD-interpose tracer for the given command.
///
/// Returns the list of file accesses discovered during tracing.
pub fn run_tracer(args: &LearnArgs) -> Result<Vec<FileAccess>> {
    if args.command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let dylib_path = get_interpose_dylib()?;
    let cache_dir = tracer_cache_dir()?;
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to create tracer cache dir {}: {}",
            cache_dir.display(),
            e
        ))
    })?;

    let trace_path = cache_dir.join(format!("trace_{}.txt", std::process::id()));
    let comm_file = PathBuf::from(format!("{}.comm", trace_path.display()));

    // Clean up previous files
    let _ = std::fs::remove_file(&trace_path);
    let _ = std::fs::remove_file(&comm_file);

    // Create empty comm file so the dylib can append to it immediately
    std::fs::File::create(&comm_file).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to create comm file {}: {}",
            comm_file.display(),
            e
        ))
    })?;

    // Open trace file WITHOUT O_CLOEXEC so the FD is inherited by all child
    // processes (including those produced by fork/exec chains). Each process
    // that has the dylib injected will write its accesses to this same FD.
    let trace_file = open_trace_file_without_cloexec(&trace_path)?;
    let trace_fd = trace_file.as_raw_fd();

    // Append to existing DYLD_INSERT_LIBRARIES if already set
    let existing_dyld = std::env::var("DYLD_INSERT_LIBRARIES").unwrap_or_default();
    let dyld_value = if existing_dyld.is_empty() {
        dylib_path.to_string_lossy().into_owned()
    } else {
        format!("{}:{}", existing_dyld, dylib_path.to_string_lossy())
    };

    let mut cmd = Command::new(&args.command[0]);
    cmd.args(&args.command[1..])
        .env("NONO_TRACE_FD", trace_fd.to_string())
        .env("NONO_COMM_FILE", &comm_file)
        .env("STRACE_MACOS_CHILD_STOP", "1")
        .env("DYLD_INSERT_LIBRARIES", &dyld_value)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn().map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to spawn traced process '{}': {}",
            args.command[0], e
        ))
    })?;

    let deadline = args.timeout.map(|t| Instant::now() + Duration::from_secs(t));
    let mut seen_pids: HashSet<u32> = HashSet::new();
    seen_pids.insert(child.id());

    loop {
        if let Some(d) = deadline {
            if Instant::now() >= d {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
        }

        // Check comm file for child PIDs written by the dylib (after SIGSTOP)
        if let Ok(content) = std::fs::read_to_string(&comm_file) {
            for line in content.lines() {
                if let Ok(pid) = line.trim().parse::<u32>() {
                    if pid > 0 && seen_pids.insert(pid) {
                        // Resume the SIGSTOP'd child so it can continue running
                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGCONT);
                    }
                }
            }
        }

        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(e) => {
                return Err(NonoError::LearnError(format!(
                    "Error waiting for traced process: {}",
                    e
                )));
            }
        }

        std::thread::sleep(Duration::from_millis(50));
    }

    // Close the trace FD. The file stays on disk for parsing.
    drop(trace_file);

    let _ = std::fs::remove_file(&comm_file);

    parse_trace_file(&trace_path)
}

/// Open a file for writing without `O_CLOEXEC` so the FD survives `exec`.
///
/// Rust's `File::create` always sets `O_CLOEXEC`. This function uses `libc::open`
/// directly (without `O_CLOEXEC`) so forked and exec'd child processes inherit
/// the FD and can write their file access traces to it.
fn open_trace_file_without_cloexec(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::io::FromRawFd;

    let c_path = std::ffi::CString::new(
        path.to_str()
            .ok_or_else(|| NonoError::LearnError("trace path is not valid UTF-8".to_string()))?,
    )
    .map_err(|_| NonoError::LearnError("trace path contains a null byte".to_string()))?;

    // SAFETY: c_path is a valid NUL-terminated C string; libc::open is safe to call.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND,
            0o644_i32,
        )
    };
    if fd < 0 {
        return Err(NonoError::LearnError(format!(
            "Failed to open trace file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    // SAFETY: fd is a valid file descriptor we just opened.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Parse the trace output file into `FileAccess` records.
fn parse_trace_file(path: &Path) -> Result<Vec<FileAccess>> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to read trace file {}: {}",
            path.display(),
            e
        ))
    })?;

    let mut accesses = Vec::new();
    for line in content.lines() {
        if let Some(access) = parse_trace_line(line) {
            accesses.push(access);
        }
    }
    Ok(accesses)
}

/// Parse a single trace line: `/path/to/file:R` or `/path/to/file:W`
fn parse_trace_line(line: &str) -> Option<FileAccess> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    // The last ':' separates the path from the R/W marker
    let colon = line.rfind(':')?;
    let path_str = &line[..colon];
    let kind = &line[colon + 1..];

    if path_str.is_empty() || !path_str.starts_with('/') {
        return None;
    }

    let is_write = match kind {
        "W" => true,
        "R" => false,
        _ => return None,
    };

    Some(FileAccess {
        path: PathBuf::from(path_str),
        is_write,
    })
}

/// Cache directory for dylib and trace temp files.
fn tracer_cache_dir() -> Result<PathBuf> {
    Ok(std::env::temp_dir().join("nono_cache"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Line parsing (equivalent to Linux test_parse_strace_* tests) ---

    #[test]
    fn test_parse_trace_line_read() {
        let line = "/etc/hosts:R";
        let access = parse_trace_line(line).expect("should parse");
        assert_eq!(access.path, PathBuf::from("/etc/hosts"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_trace_line_write() {
        let line = "/tmp/foo/bar:W";
        let access = parse_trace_line(line).expect("should parse");
        assert_eq!(access.path, PathBuf::from("/tmp/foo/bar"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_trace_line_stat() {
        let line = "/usr/bin/bash:R";
        let access = parse_trace_line(line).expect("should parse stat-style access");
        assert_eq!(access.path, PathBuf::from("/usr/bin/bash"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_trace_line_execve() {
        let line = "/usr/bin/ls:R";
        let access = parse_trace_line(line).expect("should parse execve-style access");
        assert_eq!(access.path, PathBuf::from("/usr/bin/ls"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_trace_line_path_with_colon() {
        // Paths with colons: should use the LAST colon as separator
        let line = "/path/with:colon/file:R";
        let access = parse_trace_line(line).expect("should parse path with colon");
        assert_eq!(access.path, PathBuf::from("/path/with:colon/file"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_trace_line_empty() {
        assert!(parse_trace_line("").is_none());
        assert!(parse_trace_line("  ").is_none());
    }

    #[test]
    fn test_parse_trace_line_invalid_kind() {
        assert!(parse_trace_line("/path:X").is_none());
        assert!(parse_trace_line("/path:").is_none());
    }

    #[test]
    fn test_parse_trace_line_relative_path_ignored() {
        assert!(parse_trace_line("relative/path:R").is_none());
    }

    // --- File-level parsing ---

    #[test]
    fn test_parse_trace_file_multiple_entries() {
        let tmp = std::env::temp_dir().join(format!("nono_test_{}.txt", std::process::id()));
        let content = "/etc/hosts:R\n/tmp/output:W\n/usr/lib/libsystem.dylib:R\n";
        std::fs::write(&tmp, content).expect("write trace file");

        let accesses = parse_trace_file(&tmp).expect("should parse trace file");
        assert_eq!(accesses.len(), 3);
        assert_eq!(accesses[0].path, PathBuf::from("/etc/hosts"));
        assert!(!accesses[0].is_write);
        assert_eq!(accesses[1].path, PathBuf::from("/tmp/output"));
        assert!(accesses[1].is_write);
        assert_eq!(accesses[2].path, PathBuf::from("/usr/lib/libsystem.dylib"));
        assert!(!accesses[2].is_write);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_parse_trace_file_skips_blank_lines() {
        let tmp = std::env::temp_dir().join(format!("nono_test_blank_{}.txt", std::process::id()));
        let content = "/etc/hosts:R\n\n  \n/tmp/out:W\n";
        std::fs::write(&tmp, content).expect("write trace file");

        let accesses = parse_trace_file(&tmp).expect("should parse trace file");
        assert_eq!(accesses.len(), 2);

        let _ = std::fs::remove_file(&tmp);
    }

    // --- Interpose dylib invariants ---

    #[test]
    fn test_interpose_c_source_no_dlsym_rtld_next() {
        // The dylib must call file functions directly (self-exclusion rule),
        // NOT via dlsym(RTLD_NEXT, ...) which causes infinite recursion on macOS Sequoia.
        // The fork/vfork/posix_spawn wrappers use direct calls already.
        let src = super::super::interpose::FORK_INTERPOSE_C;
        // There should be no dlsym(RTLD_NEXT, "stat") or similar for file syscalls
        assert!(
            !src.contains("dlsym(RTLD_NEXT, \"stat\")"),
            "stat must not use dlsym(RTLD_NEXT) — causes infinite recursion on Sequoia"
        );
        assert!(
            !src.contains("dlsym(RTLD_NEXT, \"open\")"),
            "open must not use dlsym(RTLD_NEXT) — causes infinite recursion on Sequoia"
        );
    }

    #[test]
    fn test_interpose_c_source_uses_nono_trace_fd() {
        let src = super::super::interpose::FORK_INTERPOSE_C;
        assert!(
            src.contains("NONO_TRACE_FD"),
            "fork_interpose.c must use NONO_TRACE_FD for trace output"
        );
        assert!(
            src.contains("_write_trace"),
            "fork_interpose.c must have a _write_trace helper"
        );
    }

    #[test]
    fn test_interpose_c_source_write_syscalls_marked() {
        let src = super::super::interpose::FORK_INTERPOSE_C;
        assert!(src.contains("nono_mkdir"), "should interpose mkdir");
        assert!(src.contains("nono_unlink"), "should interpose unlink");
        assert!(src.contains("nono_rename"), "should interpose rename");
    }

    #[test]
    fn test_interpose_c_source_fork_tracking() {
        let src = super::super::interpose::FORK_INTERPOSE_C;
        assert!(src.contains("SIGSTOP"), "must SIGSTOP forked children");
        assert!(src.contains("NONO_COMM_FILE"), "must write child PIDs to comm file");
        assert!(src.contains("nono_fork"), "must interpose fork");
        assert!(src.contains("nono_posix_spawn"), "must interpose posix_spawn");
    }

    // --- Write access detection ---
    // The write detection logic lives in fork_interpose.c.
    // macOS open(2) flags differ from Linux:
    //   O_CREAT = 0x0200, O_TRUNC = 0x0400 (macOS)
    //   O_CREAT = 0100,   O_TRUNC = 01000  (Linux)

    #[test]
    fn test_interpose_c_source_macos_open_flags() {
        let src = super::super::interpose::FORK_INTERPOSE_C;
        assert!(
            src.contains("O_CREAT") && src.contains("O_TRUNC"),
            "must check O_CREAT and O_TRUNC for write detection"
        );
    }
}
