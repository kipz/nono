//! Linux learn mode implementation using strace

use super::common::{FileAccess, LearnResult};
use crate::cli::LearnArgs;
use crate::profile;
use nono::{NonoError, Result};
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Check if strace is available
fn check_strace() -> Result<()> {
    match Command::new("strace").arg("--version").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err(NonoError::LearnError(
            "strace not found. Install with: apt install strace".to_string(),
        )),
    }
}

/// Run learn mode (Linux implementation)
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    check_strace()?;

    // Load profile if specified
    let profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    // Run strace and collect paths
    let raw_accesses = run_strace(&args.command, args.timeout)?;

    // Process and categorize paths
    super::common::process_accesses(raw_accesses, profile.as_ref(), args.all)
}

/// Run strace on the command and collect file accesses
fn run_strace(command: &[String], timeout: Option<u64>) -> Result<Vec<FileAccess>> {
    if command.is_empty() {
        return Err(NonoError::NoCommand);
    }

    let mut strace_args = vec![
        "-f".to_string(), // Follow forks
        "-e".to_string(), // Trace these syscalls
        "openat,open,access,stat,lstat,readlink,execve,creat,mkdir,rename,unlink".to_string(),
        "-o".to_string(),
        "/dev/stderr".to_string(), // Output to stderr so we can capture it
        "--".to_string(),
    ];
    strace_args.extend(command.iter().cloned());

    info!("Running strace with args: {:?}", strace_args);

    let mut child = Command::new("strace")
        .args(&strace_args)
        .stdout(Stdio::inherit()) // Let command output go to terminal
        .stderr(Stdio::piped()) // Capture strace output
        .spawn()
        .map_err(|e| NonoError::LearnError(format!("Failed to spawn strace: {}", e)))?;

    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| NonoError::LearnError("Failed to capture strace stderr".to_string()))?;

    let start = Instant::now();
    let timeout_duration = timeout.map(Duration::from_secs);

    let mut accesses = Vec::new();
    let reader = BufReader::new(stderr);

    for line in reader.lines() {
        // Check timeout
        if let Some(timeout) = timeout_duration {
            if start.elapsed() > timeout {
                warn!("Timeout reached, killing child process");
                let _ = child.kill();
                break;
            }
        }

        let line = match line {
            Ok(l) => l,
            Err(e) => {
                debug!("Error reading strace line: {}", e);
                continue;
            }
        };

        // Parse strace output
        if let Some(access) = parse_strace_line(&line) {
            accesses.push(access);
        }
    }

    // Wait for child to finish
    let _ = child.wait();

    Ok(accesses)
}

/// Parse a single strace line to extract file access
fn parse_strace_line(line: &str) -> Option<FileAccess> {
    // strace output format examples:
    // openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3
    // openat(AT_FDCWD, "/tmp/foo", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
    // access("/etc/ld.so.preload", R_OK) = -1 ENOENT
    // stat("/usr/bin/bash", {st_mode=...) = 0
    // execve("/usr/bin/ls", ["ls"], ...) = 0

    // Skip lines that don't contain syscalls we care about
    let syscalls = [
        "openat", "open", "access", "stat", "lstat", "readlink", "execve", "creat", "mkdir",
        "rename", "unlink",
    ];

    let syscall = syscalls
        .iter()
        .find(|&s| line.contains(&format!("{}(", s)))?;

    // Extract the path from the syscall
    let path = extract_path_from_syscall(line, syscall)?;

    // Determine if this is a write access
    let is_write = is_write_access(line, syscall);

    // Filter out invalid paths
    if path.is_empty() || path == "." || path == ".." {
        return None;
    }

    Some(FileAccess {
        path: std::path::PathBuf::from(path),
        is_write,
    })
}

/// Extract path from strace syscall line
fn extract_path_from_syscall(line: &str, syscall: &str) -> Option<String> {
    // Find the opening paren after syscall
    let start_idx = line.find(&format!("{}(", syscall))?;
    let after_paren = &line[start_idx + syscall.len() + 1..];

    // For openat, skip AT_FDCWD
    let path_start = if syscall == "openat" {
        // Skip "AT_FDCWD, " or similar
        if let Some(comma_idx) = after_paren.find(',') {
            comma_idx + 2 // Skip ", "
        } else {
            return None;
        }
    } else {
        0
    };

    let remaining = &after_paren[path_start..];

    // Path should be in quotes
    if !remaining.starts_with('"') {
        return None;
    }

    // Find closing quote
    let end_quote = remaining[1..].find('"')?;
    let path = &remaining[1..end_quote + 1];

    // Unescape C-style escapes from strace output
    let path = unescape_strace_string(path);

    Some(path)
}

/// Unescape C-style escape sequences from strace output.
/// Handles: \n \t \r \\ \" \0 \xNN (hex) \NNN (octal)
///
/// Invalid or incomplete escape sequences are passed through literally
/// to avoid data loss.
fn unescape_strace_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('n') => {
                    chars.next();
                    result.push('\n');
                }
                Some('t') => {
                    chars.next();
                    result.push('\t');
                }
                Some('r') => {
                    chars.next();
                    result.push('\r');
                }
                Some('\\') => {
                    chars.next();
                    result.push('\\');
                }
                Some('"') => {
                    chars.next();
                    result.push('"');
                }
                Some(c) if ('0'..='7').contains(c) => {
                    // Octal escape \NNN (1-3 digits, including \0 for null)
                    let mut octal = String::new();
                    while octal.len() < 3 && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                        if let Some(c) = chars.next() {
                            octal.push(c);
                        }
                    }
                    if let Ok(val) = u8::from_str_radix(&octal, 8) {
                        result.push(val as char);
                    } else {
                        // Malformed octal - pass through literally
                        result.push('\\');
                        result.push_str(&octal);
                    }
                }
                Some('x') => {
                    chars.next(); // consume 'x'
                                  // Hex escape \xNN - must have exactly 2 hex digits
                    let mut hex = String::new();
                    for _ in 0..2 {
                        if chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                            if let Some(c) = chars.next() {
                                hex.push(c);
                            }
                        } else {
                            break;
                        }
                    }
                    if hex.len() == 2 {
                        if let Ok(val) = u8::from_str_radix(&hex, 16) {
                            result.push(val as char);
                        } else {
                            // Malformed hex - pass through literally
                            result.push('\\');
                            result.push('x');
                            result.push_str(&hex);
                        }
                    } else {
                        // Invalid/incomplete hex escape - pass through literally
                        result.push('\\');
                        result.push('x');
                        result.push_str(&hex);
                    }
                }
                _ => {
                    // Unknown escape, keep as-is
                    result.push('\\');
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

/// Determine if a syscall represents a write access
fn is_write_access(line: &str, syscall: &str) -> bool {
    match syscall {
        "creat" | "mkdir" | "unlink" | "rename" => true,
        "openat" | "open" => {
            // Check flags for write intent
            line.contains("O_WRONLY")
                || line.contains("O_RDWR")
                || line.contains("O_CREAT")
                || line.contains("O_TRUNC")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_strace_openat() {
        let line = r#"openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3"#;
        let access = parse_strace_line(line).expect("should parse");
        assert_eq!(access.path, std::path::PathBuf::from("/etc/passwd"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_openat_write() {
        let line = r#"openat(AT_FDCWD, "/tmp/test", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4"#;
        let access = parse_strace_line(line).expect("should parse");
        assert_eq!(access.path, std::path::PathBuf::from("/tmp/test"));
        assert!(access.is_write);
    }

    #[test]
    fn test_parse_strace_stat() {
        let line = r#"stat("/usr/bin/bash", {st_mode=S_IFREG|0755, ...}) = 0"#;
        let access = parse_strace_line(line).expect("should parse");
        assert_eq!(access.path, std::path::PathBuf::from("/usr/bin/bash"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_parse_strace_execve() {
        let line = r#"execve("/usr/bin/ls", ["ls", "-la"], 0x...) = 0"#;
        let access = parse_strace_line(line).expect("should parse");
        assert_eq!(access.path, std::path::PathBuf::from("/usr/bin/ls"));
        assert!(!access.is_write);
    }

    #[test]
    fn test_extract_path_from_openat() {
        let line = r#"openat(AT_FDCWD, "/some/path", O_RDONLY) = 3"#;
        let path = extract_path_from_syscall(line, "openat").expect("should extract");
        assert_eq!(path, "/some/path");
    }

    #[test]
    fn test_is_write_access() {
        assert!(is_write_access(
            "openat(..., O_WRONLY|O_CREAT, ...)",
            "openat"
        ));
        assert!(is_write_access("openat(..., O_RDWR, ...)", "openat"));
        assert!(!is_write_access("openat(..., O_RDONLY, ...)", "openat"));
        assert!(is_write_access("creat(...)", "creat"));
        assert!(is_write_access("mkdir(...)", "mkdir"));
    }

    #[test]
    fn test_unescape_simple() {
        assert_eq!(unescape_strace_string(r#"hello"#), "hello");
        assert_eq!(unescape_strace_string(r#"hello\nworld"#), "hello\nworld");
        assert_eq!(unescape_strace_string(r#"hello\tworld"#), "hello\tworld");
        assert_eq!(unescape_strace_string(r#"hello\\world"#), "hello\\world");
        assert_eq!(unescape_strace_string(r#"hello\"world"#), "hello\"world");
    }

    #[test]
    fn test_unescape_hex() {
        // \x41 = 'A'
        assert_eq!(unescape_strace_string(r#"\x41"#), "A");
        // \x2f = '/'
        assert_eq!(
            unescape_strace_string(r#"/path\x2fwith\x2fslash"#),
            "/path/with/slash"
        );
    }

    #[test]
    fn test_unescape_octal() {
        // \101 = 'A' (octal 101 = 65 decimal)
        assert_eq!(unescape_strace_string(r#"\101"#), "A");
        // \040 = ' ' (space)
        assert_eq!(unescape_strace_string(r#"hello\040world"#), "hello world");
    }

    #[test]
    fn test_unescape_null() {
        // \0 alone is null
        assert_eq!(unescape_strace_string(r#"hello\0world"#), "hello\0world");
    }

    #[test]
    fn test_unescape_incomplete_hex() {
        // Incomplete hex escape should be passed through literally
        assert_eq!(unescape_strace_string(r#"\x1"#), r#"\x1"#);
        // Note: \x1e would be valid (1e are both hex digits), so use \x1g instead
        assert_eq!(unescape_strace_string(r#"path\x1gnd"#), r#"path\x1gnd"#);
    }

    #[test]
    fn test_unescape_invalid_hex() {
        // Invalid hex digits should be passed through literally
        assert_eq!(unescape_strace_string(r#"\xZZ"#), r#"\xZZ"#);
        assert_eq!(unescape_strace_string(r#"\xGH"#), r#"\xGH"#);
    }

    #[test]
    fn test_unescape_invalid_octal() {
        // 8 and 9 are not valid octal digits
        // \18 should parse \1 as octal (= 0x01) and leave '8' as literal
        assert_eq!(unescape_strace_string(r#"\18"#), "\x018");
        // \19 should parse \1 as octal (= 0x01) and leave '9' as literal
        assert_eq!(unescape_strace_string(r#"\19"#), "\x019");
    }

    #[test]
    fn test_unescape_trailing_backslash() {
        // Trailing backslash should be passed through
        assert_eq!(unescape_strace_string(r#"hello\"#), r#"hello\"#);
    }
}
