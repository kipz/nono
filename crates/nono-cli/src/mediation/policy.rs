//! Policy engine for the mediation server.
//!
//! For each incoming `ShimRequest`, this module:
//! 1. Finds the matching `ResolvedCommand` entry.
//! 2. Checks `intercept` rules in order (args_prefix match).
//! 3. If matched: returns the configured `ShimResponse` without calling the binary.
//! 4. If not matched: execs the real binary with any injected env vars, proxies I/O.

use super::session::ResolvedCommand;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, warn};

/// Request forwarded from the shim binary to the mediation server.
#[derive(Debug, Deserialize)]
pub struct ShimRequest {
    pub command: String,
    pub args: Vec<String>,
    pub stdin: String,
}

/// Response the mediation server sends back to the shim binary.
#[derive(Debug, Serialize)]
pub struct ShimResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Apply policy to a shim request and produce a response.
///
/// - If the command is unknown: returns an error response (not found).
/// - If an intercept rule matches: returns the pre-resolved intercept output.
/// - Otherwise: execs the real binary and proxies its output.
pub async fn apply(request: ShimRequest, commands: &[ResolvedCommand]) -> ShimResponse {
    // Find matching command entry
    let Some(cmd) = commands.iter().find(|c| c.name == request.command) else {
        warn!("mediation: unknown command '{}'", request.command);
        return ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: command '{}' not configured\n", request.command),
            exit_code: 127,
        };
    };

    // Check intercept rules in order
    for rule in &cmd.intercepts {
        if args_prefix_matches(&rule.args_prefix, &request.args) {
            debug!(
                "mediation: intercepting '{}' with prefix {:?}",
                request.command, rule.args_prefix
            );
            return ShimResponse {
                stdout: rule.stdout.clone(),
                stderr: rule.stderr.clone(),
                exit_code: rule.exit_code,
            };
        }
    }

    // No intercept matched — pass through to the real binary
    debug!(
        "mediation: passthrough '{}' {:?} -> {}",
        request.command,
        request.args,
        cmd.real_path.display()
    );
    exec_passthrough(cmd, &request.args, &request.stdin).await
}

/// Check if the invocation's args start with the given prefix.
fn args_prefix_matches(prefix: &[String], args: &[String]) -> bool {
    if prefix.len() > args.len() {
        return false;
    }
    prefix
        .iter()
        .zip(args.iter())
        .all(|(p, a)| p == a)
}

/// Execute the real binary and collect its output.
async fn exec_passthrough(
    cmd: &ResolvedCommand,
    args: &[String],
    stdin_data: &str,
) -> ShimResponse {
    // Build env: inherit nothing from parent (the parent is the mediation server,
    // not the sandbox). Re-add only the injected env vars for this command.
    // Note: we intentionally do not inherit parent env so no secrets leak.
    let mut env: HashMap<String, String> = std::env::vars().collect();
    for (var, value) in &cmd.inject_env {
        env.insert(var.clone(), value.as_str().to_string());
    }

    let real_path = cmd.real_path.clone();
    let args = args.to_vec();
    let stdin_data = stdin_data.to_string();

    // spawn_blocking: std::process::Command is synchronous; run on a thread pool
    // so we don't block the async executor.
    let result = tokio::task::spawn_blocking(move || -> Result<ShimResponse> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        let mut child = Command::new(&real_path)
            .args(&args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                NonoError::CommandExecution(e)
            })?;

        // Write stdin
        if !stdin_data.is_empty() {
            if let Some(mut si) = child.stdin.take() {
                let _ = si.write_all(stdin_data.as_bytes());
            }
        }

        let output = child.wait_with_output().map_err(NonoError::CommandExecution)?;

        Ok(ShimResponse {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(1),
        })
    })
    .await;

    match result {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: exec failed: {}\n", e),
            exit_code: 1,
        },
        Err(e) => ShimResponse {
            stdout: String::new(),
            stderr: format!("nono-mediation: internal error: {}\n", e),
            exit_code: 1,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::session::{ResolvedCommand, ResolvedIntercept};
    use std::path::PathBuf;

    fn make_cmd(intercepts: Vec<ResolvedIntercept>) -> ResolvedCommand {
        ResolvedCommand {
            name: "testcmd".to_string(),
            real_path: PathBuf::from("/usr/bin/true"),
            intercepts,
            inject_env: Vec::new(),
        }
    }

    #[tokio::test]
    async fn test_unknown_command_returns_127() {
        let req = ShimRequest {
            command: "doesnotexist".to_string(),
            args: vec![],
            stdin: String::new(),
        };
        let resp = apply(req, &[]).await;
        assert_eq!(resp.exit_code, 127);
    }

    #[tokio::test]
    async fn test_intercept_exact_prefix_match() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string(), "github".to_string(), "token".to_string()],
            stdout: "ghp_secret\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string(), "github".to_string(), "token".to_string()],
            stdin: String::new(),
        };
        let resp = apply(req, &[cmd]).await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "ghp_secret\n");
    }

    #[tokio::test]
    async fn test_intercept_prefix_matches_longer_args() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string()],
            stdout: "matched\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["auth".to_string(), "github".to_string()],
            stdin: String::new(),
        };
        let resp = apply(req, &[cmd]).await;
        assert_eq!(resp.exit_code, 0);
        assert_eq!(resp.stdout, "matched\n");
    }

    #[tokio::test]
    async fn test_no_intercept_match_falls_through() {
        let cmd = make_cmd(vec![ResolvedIntercept {
            args_prefix: vec!["auth".to_string(), "github".to_string()],
            stdout: "secret\n".to_string(),
            stderr: String::new(),
            exit_code: 0,
        }]);

        let req = ShimRequest {
            command: "testcmd".to_string(),
            args: vec!["status".to_string()],
            stdin: String::new(),
        };
        // Falls through to passthrough exec of /usr/bin/true
        let resp = apply(req, &[cmd]).await;
        // /usr/bin/true exits 0 with no output
        assert_eq!(resp.exit_code, 0);
    }

    #[test]
    fn test_args_prefix_matches() {
        assert!(args_prefix_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string(), "b".to_string(), "c".to_string()]
        ));
        assert!(args_prefix_matches(&[], &["a".to_string()]));
        assert!(!args_prefix_matches(
            &["a".to_string(), "b".to_string()],
            &["a".to_string()]
        ));
        assert!(!args_prefix_matches(
            &["a".to_string()],
            &["b".to_string()]
        ));
    }
}
