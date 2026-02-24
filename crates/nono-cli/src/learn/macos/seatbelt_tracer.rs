//! macOS Seatbelt report-mode filesystem access tracer
//!
//! Uses the `(allow (with report) default)` Seatbelt profile to observe all
//! file operations at the kernel level, then parses the kernel log for
//! `Sandbox: <proc>(<pid>) allow file-*` entries.
//!
//! Requirements:
//! - macOS 10.12+ (`log stream` command)
//! - User must be in the `admin` group (log stream requires admin on macOS 15+)
//! - Works for SIP-protected binaries (unlike DYLD interpose)
//! - Network and IPC are also logged but discarded (file ops only)
//!
//! The traced process runs completely unrestricted during learn;
//! the `(with report)` sandbox only observes, never denies.

use crate::cli::LearnArgs;
use crate::learn::common::FileAccess;
use nono::{NonoError, Result};
use std::ffi::CString;
use std::io::{BufRead, BufReader};
use std::os::raw::c_char;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

extern "C" {
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> i32;
    fn sandbox_free_error(errorbuf: *mut c_char);
}

/// Seatbelt profile that allows all operations but logs each one to the kernel log.
const REPORT_PROFILE: &str = "(version 1)(allow (with report) default)";

/// How long to keep reading the log stream after the child exits, to drain
/// any in-flight log entries from the kernel's async logging pipeline.
const LOG_DRAIN_MS: u64 = 100;

/// A parsed event from the kernel log stream.
#[derive(Debug)]
enum LogEvent {
    /// A file read or write operation
    FileOp { path: PathBuf, is_write: bool },
}

/// Run the Seatbelt report-mode tracer for the given command.
///
/// Returns the list of file accesses discovered during tracing.
pub fn run_seatbelt_tracer(args: &LearnArgs) -> Result<Vec<FileAccess>> {
    if args.command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    // Spawn the log stream before forking so no events are missed.
    let mut log_stream = spawn_log_stream()?;
    let log_stdout = log_stream
        .stdout
        .take()
        .ok_or_else(|| NonoError::LearnError("Failed to capture log stream stdout".to_string()))?;

    // Detect immediate failure (e.g., "Must be admin to run 'stream' command").
    // log stream exits within milliseconds if the user lacks admin rights.
    std::thread::sleep(Duration::from_millis(150));
    match log_stream.try_wait() {
        Ok(Some(_)) => {
            return Err(NonoError::LearnError(
                "'log stream' exited immediately. \
                 nono learn requires admin group membership on macOS to read kernel log events. \
                 Run as a user in the admin group, or use: sudo nono learn -- ..."
                    .to_string(),
            ));
        }
        Ok(None) => {} // still running — good
        Err(e) => {
            return Err(NonoError::LearnError(format!(
                "Failed to check log stream status: {}",
                e
            )));
        }
    }

    // Fork: parent tracks the child PID; child applies sandbox and execs.
    let child_pid = match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Parent { child }) => child.as_raw() as u32,
        Ok(nix::unistd::ForkResult::Child) => {
            // Apply the report-mode sandbox to ourselves, then exec.
            if apply_report_sandbox().is_err() {
                // SAFETY: _exit is async-signal-safe; used post-fork on error.
                unsafe { libc::_exit(1) };
            }
            exec_command(args);
            // exec_command only returns on failure.
            unsafe { libc::_exit(1) };
        }
        Err(e) => {
            let _ = log_stream.kill();
            return Err(NonoError::LearnError(format!("fork() failed: {}", e)));
        }
    };

    // PARENT: read log events in a background thread while polling for child exit.
    let (tx, rx) = mpsc::channel::<LogEvent>();
    let _reader = std::thread::spawn(move || {
        let reader = BufReader::new(log_stdout);
        for line_result in reader.lines() {
            let Ok(line) = line_result else { break };
            if let Some(event) = parse_log_line(&line) {
                if tx.send(event).is_err() {
                    break;
                }
            }
        }
    });

    let deadline = args
        .timeout
        .map(|t| Instant::now() + Duration::from_secs(t));
    let mut child_exited_at: Option<Instant> = None;
    let mut accesses: Vec<FileAccess> = Vec::new();

    loop {
        // Poll for child exit.
        if child_exited_at.is_none() {
            // SAFETY: waitpid with WNOHANG is safe to call from any thread.
            let r = unsafe {
                libc::waitpid(
                    child_pid as libc::pid_t,
                    std::ptr::null_mut(),
                    libc::WNOHANG,
                )
            };
            if r == child_pid as libc::pid_t || r < 0 {
                child_exited_at = Some(Instant::now());
            }
        }

        // Enforce timeout: kill child, mark as exited.
        if let Some(d) = deadline {
            if Instant::now() >= d && child_exited_at.is_none() {
                // SAFETY: kill and waitpid are safe to call at this point.
                unsafe {
                    libc::kill(child_pid as libc::c_int, libc::SIGKILL);
                    libc::waitpid(child_pid as libc::pid_t, std::ptr::null_mut(), 0);
                }
                child_exited_at = Some(Instant::now());
            }
        }

        // After the drain window, stop looping.
        if let Some(exit_time) = child_exited_at {
            if exit_time.elapsed() >= Duration::from_millis(LOG_DRAIN_MS) {
                break;
            }
        }

        // Drain any queued events (non-blocking).
        loop {
            match rx.try_recv() {
                Ok(LogEvent::FileOp { path, is_write, .. }) => {
                    accesses.push(FileAccess { path, is_write });
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // Reader thread exited (log stream closed).
                    if child_exited_at.is_none() {
                        child_exited_at = Some(Instant::now());
                    }
                    break;
                }
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    // Terminate and reap the log stream process.
    let _ = log_stream.kill();
    let _ = log_stream.wait();

    // Drain any remaining buffered events.
    while let Ok(LogEvent::FileOp { path, is_write, .. }) = rx.try_recv() {
        accesses.push(FileAccess { path, is_write });
    }

    Ok(accesses)
}

/// Spawn the `log stream` subprocess, filtered to kernel Sandbox file events.
fn spawn_log_stream() -> Result<Child> {
    Command::new("log")
        .args([
            "stream",
            "--level",
            "debug",
            "--predicate",
            r#"process == "kernel" AND message CONTAINS "Sandbox: " AND message CONTAINS " allow file-""#,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::LearnError(
                    "log command not found. macOS 10.12+ required for learn mode.".to_string(),
                )
            } else {
                NonoError::LearnError(format!("Failed to spawn log stream: {}", e))
            }
        })
}

/// Apply the Seatbelt report-mode sandbox to the current process.
///
/// Called in the child process between fork() and exec(). The profile
/// `(allow (with report) default)` logs every operation but never denies.
/// The sandbox is inherited across exec() by the target binary.
fn apply_report_sandbox() -> Result<()> {
    let profile = CString::new(REPORT_PROFILE).map_err(|_| {
        NonoError::LearnError("Report profile contains null byte (bug)".to_string())
    })?;
    let mut error_buf: *mut c_char = std::ptr::null_mut();

    // SAFETY: sandbox_init is a stable macOS API. We pass a valid null-terminated
    // C string for the profile, 0 for raw profile mode, and a pointer to receive
    // any error message. Called in the child process before exec().
    let result = unsafe { sandbox_init(profile.as_ptr(), 0, &mut error_buf) };

    if result != 0 {
        let msg = if !error_buf.is_null() {
            // SAFETY: sandbox_init sets error_buf to a valid C string on error.
            let s = unsafe {
                std::ffi::CStr::from_ptr(error_buf)
                    .to_string_lossy()
                    .into_owned()
            };
            // SAFETY: sandbox_free_error expects a pointer from sandbox_init.
            unsafe { sandbox_free_error(error_buf) };
            s
        } else {
            format!("sandbox_init returned {}", result)
        };
        return Err(NonoError::LearnError(format!(
            "Failed to apply report sandbox: {}",
            msg
        )));
    }

    Ok(())
}

/// Replace the current process image with the target command.
///
/// Called in the child process after applying the sandbox. `execvp` performs
/// PATH lookup, so the command name is resolved as a shell would. If exec
/// fails, this function returns; the caller must then exit immediately.
fn exec_command(args: &LearnArgs) {
    let Some(cmd) = CString::new(args.command[0].as_str()).ok() else {
        return;
    };
    let c_args: Vec<CString> = args
        .command
        .iter()
        .filter_map(|s| CString::new(s.as_str()).ok())
        .collect();
    let mut c_arg_ptrs: Vec<*const c_char> = c_args.iter().map(|s| s.as_ptr()).collect();
    c_arg_ptrs.push(std::ptr::null());

    // SAFETY: cmd is a valid NUL-terminated C string; c_arg_ptrs is a NULL-terminated
    // array of valid C string pointers that outlive this call. execvp replaces the
    // process image on success (no return); returns -1 on failure.
    unsafe { libc::execvp(cmd.as_ptr(), c_arg_ptrs.as_ptr()) };
}

/// Parse a single log line from `log stream` into a `LogEvent`.
///
/// Matches lines like:
/// ```text
/// kernel: (Sandbox) Sandbox: head(13546) allow file-read-data /etc/hosts
/// kernel: (Sandbox) 3 duplicate reports for Sandbox: head(9999) allow file-read-data /private/etc/hosts
/// ```
///
/// Returns `None` for non-matching lines (headers, unrelated events, etc.).
fn parse_log_line(line: &str) -> Option<LogEvent> {
    // Find the "Sandbox: " marker; handles duplicate-prefix lines transparently.
    let sandbox_pos = line.find("Sandbox: ")?;
    let after_sandbox = &line[sandbox_pos + "Sandbox: ".len()..];

    // Parse: <process_name>(<pid>) allow <operation> <path>
    let paren_open = after_sandbox.find('(')?;
    let paren_close = after_sandbox[paren_open..].find(')')? + paren_open;
    if paren_close <= paren_open {
        return None;
    }

    // Validate that the parenthesised field is a numeric PID (guards against
    // matching lines with non-sandbox parenthesised content). The value itself
    // is not used for filtering: all events in the report stream originate from
    // the sandboxed child tree, so every matching PID is relevant.
    if after_sandbox[paren_open + 1..paren_close]
        .parse::<u32>()
        .is_err()
    {
        return None;
    }

    let after_paren = &after_sandbox[paren_close + 1..];
    let allow_prefix = " allow ";
    if !after_paren.starts_with(allow_prefix) {
        return None;
    }
    let after_allow = &after_paren[allow_prefix.len()..];

    // Parse operation and path (separated by a space).
    let space_pos = after_allow.find(' ')?;
    let operation = &after_allow[..space_pos];
    let path_str = after_allow[space_pos + 1..].trim();

    // Only handle file-* operations.
    if !operation.starts_with("file-") {
        return None;
    }

    // Skip device nodes — not relevant for sandbox policy.
    if path_str.starts_with("/dev/") {
        return None;
    }

    // Must be an absolute path.
    if !path_str.starts_with('/') {
        return None;
    }

    // file-write-data and file-write-create indicate the process is creating
    // or modifying file content — these require write access in the policy.
    // Other operations (file-read-*, file-write-metadata, etc.) are treated as reads.
    let is_write = matches!(operation, "file-write-data" | "file-write-create");

    Some(LogEvent::FileOp {
        path: PathBuf::from(path_str),
        is_write,
    })
}

/// Parse a log line and return the PID of the reporting process, if any.
///
/// Exposed for testing only; the PID is not used for filtering in production
/// (all events in the report stream originate from the sandboxed child tree).
#[cfg(test)]
fn parse_log_line_pid(line: &str) -> Option<u32> {
    let sandbox_pos = line.find("Sandbox: ")?;
    let after_sandbox = &line[sandbox_pos + "Sandbox: ".len()..];
    let paren_open = after_sandbox.find('(')?;
    let paren_close = after_sandbox[paren_open..].find(')')? + paren_open;
    after_sandbox[paren_open + 1..paren_close].parse().ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // --- Log line parsing ---

    #[test]
    fn test_parse_log_line_file_read() {
        let line = "2024-01-01 00:00:00.000000-0000 0x1 Default 0x0 0 kernel: (Sandbox) Sandbox: head(13546) allow file-read-data /etc/hosts";
        let event = parse_log_line(line).expect("should parse");
        match event {
            LogEvent::FileOp { path, is_write } => {
                assert_eq!(path, PathBuf::from("/etc/hosts"));
                assert!(!is_write);
            }
        }
    }

    #[test]
    fn test_parse_log_line_file_write() {
        let line = "2024-01-01 00:00:00.000000-0000 0x1 Default 0x0 0 kernel: (Sandbox) Sandbox: gls(17577) allow file-write-data /tmp/out";
        let event = parse_log_line(line).expect("should parse");
        match event {
            LogEvent::FileOp { path, is_write } => {
                assert_eq!(path, PathBuf::from("/tmp/out"));
                assert!(is_write);
            }
        }
    }

    #[test]
    fn test_parse_log_line_file_write_create() {
        let line = "kernel: (Sandbox) Sandbox: cat(999) allow file-write-create /tmp/newfile";
        let event = parse_log_line(line).expect("should parse write-create");
        match event {
            LogEvent::FileOp { is_write, .. } => assert!(is_write),
        }
    }

    #[test]
    fn test_parse_log_line_file_read_metadata() {
        let line = "kernel: (Sandbox) Sandbox: ls(1234) allow file-read-metadata /usr/bin";
        let event = parse_log_line(line).expect("should parse metadata read");
        match event {
            LogEvent::FileOp { is_write, path } => {
                assert!(!is_write);
                assert_eq!(path, PathBuf::from("/usr/bin"));
            }
        }
    }

    #[test]
    fn test_parse_log_line_with_duplicate_prefix() {
        let line =
            "3 duplicate reports for Sandbox: head(9999) allow file-read-data /private/etc/hosts";
        let event = parse_log_line(line).expect("should parse with duplicate prefix");
        match event {
            LogEvent::FileOp { path, is_write } => {
                assert_eq!(path, PathBuf::from("/private/etc/hosts"));
                assert!(!is_write);
            }
        }
        // Verify PID is parsed correctly via the test helper.
        assert_eq!(parse_log_line_pid(line), Some(9999));
    }

    #[test]
    fn test_parse_log_line_skips_dev_paths() {
        let line = "kernel: (Sandbox) Sandbox: process(1) allow file-read-data /dev/null";
        assert!(parse_log_line(line).is_none());
    }

    #[test]
    fn test_parse_log_line_skips_non_file_ops() {
        let line = "kernel: (Sandbox) Sandbox: process(1) allow mach-lookup com.apple.service";
        assert!(parse_log_line(line).is_none());
    }

    #[test]
    fn test_parse_log_line_skips_relative_paths() {
        let line = "kernel: (Sandbox) Sandbox: process(1) allow file-read-data relative/path";
        assert!(parse_log_line(line).is_none());
    }

    #[test]
    fn test_parse_log_line_empty() {
        assert!(parse_log_line("").is_none());
        assert!(parse_log_line("no sandbox marker here").is_none());
    }

    // --- Write detection ---

    #[test]
    fn test_write_detection_file_write_data() {
        let line = "kernel: (Sandbox) Sandbox: proc(1) allow file-write-data /tmp/x";
        match parse_log_line(line).unwrap() {
            LogEvent::FileOp { is_write, .. } => assert!(is_write),
        }
    }

    #[test]
    fn test_write_detection_file_write_create() {
        let line = "kernel: (Sandbox) Sandbox: proc(1) allow file-write-create /tmp/new";
        match parse_log_line(line).unwrap() {
            LogEvent::FileOp { is_write, .. } => assert!(is_write),
        }
    }

    #[test]
    fn test_write_detection_file_read_data_is_read() {
        let line = "kernel: (Sandbox) Sandbox: proc(1) allow file-read-data /tmp/x";
        match parse_log_line(line).unwrap() {
            LogEvent::FileOp { is_write, .. } => assert!(!is_write),
        }
    }

    #[test]
    fn test_write_detection_file_read_metadata_is_read() {
        let line = "kernel: (Sandbox) Sandbox: proc(1) allow file-read-metadata /usr";
        match parse_log_line(line).unwrap() {
            LogEvent::FileOp { is_write, .. } => assert!(!is_write),
        }
    }

    #[test]
    fn test_write_detection_file_write_unlink_is_read() {
        // file-write-unlink is not data/create, so treated as read for policy purposes.
        let line = "kernel: (Sandbox) Sandbox: proc(1) allow file-write-unlink /tmp/x";
        match parse_log_line(line).unwrap() {
            LogEvent::FileOp { is_write, .. } => assert!(!is_write),
        }
    }

    #[test]
    fn test_write_detection_file_write_flags_is_read() {
        let line = "kernel: (Sandbox) Sandbox: proc(1) allow file-write-flags /tmp/x";
        match parse_log_line(line).unwrap() {
            LogEvent::FileOp { is_write, .. } => assert!(!is_write),
        }
    }

    // --- PID extraction ---

    #[test]
    fn test_parse_log_line_pid_extraction() {
        let line = "kernel: (Sandbox) Sandbox: bash(42000) allow file-read-data /bin/sh";
        assert!(parse_log_line(line).is_some());
        assert_eq!(parse_log_line_pid(line), Some(42000));
    }

    // --- Path extraction ---

    #[test]
    fn test_parse_log_line_path_with_spaces() {
        let line =
            "kernel: (Sandbox) Sandbox: proc(1) allow file-read-data /Users/test/my file.txt";
        match parse_log_line(line).unwrap() {
            LogEvent::FileOp { path, .. } => {
                assert_eq!(path, PathBuf::from("/Users/test/my file.txt"));
            }
        }
    }

    #[test]
    fn test_parse_log_line_sip_protected_binary() {
        // SIP-protected binaries ARE traceable via Seatbelt (unlike DYLD interpose).
        let line = "kernel: (Sandbox) Sandbox: head(13546) allow file-read-data /usr/bin/head";
        let event = parse_log_line(line).expect("SIP-protected binary must be parseable");
        match event {
            LogEvent::FileOp { path, .. } => {
                assert_eq!(path, PathBuf::from("/usr/bin/head"));
            }
        }
    }
}
