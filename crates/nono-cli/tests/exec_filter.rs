//! Integration tests for the seccomp exec filter.
//!
//! Each test spawns a real `nono run` session with a minimal mediation
//! profile and exercises the feature end-to-end.
//!
//! The harness creates a per-test `HOME` + workdir + test binary under
//! tempdir, so tests are parallel-safe and do not leak state across runs.
//!
//! Linux-only: the exec filter is a seccomp-notify feature that does not
//! exist on macOS.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

// -------------------------------------------------------------------------
// Harness
// -------------------------------------------------------------------------

/// Fixture assembled for one integration test: per-test tempdir with a
/// home, workdir, and mediated test binary.
struct ExecFilterHarness {
    /// Owns the tempdir so it is cleaned up on drop.
    _tmp: tempfile::TempDir,
    /// `$HOME` override for the `nono run` invocation. Audit file lands
    /// at `home/.nono/sessions/audit.jsonl`.
    home: PathBuf,
    /// Working directory passed via `--workdir`.
    workdir: PathBuf,
    /// Absolute path to the test binary (shell script that prints
    /// `REAL_BINARY_RAN` when executed).
    testbin: PathBuf,
    /// Absolute path to the profile JSON passed via `--profile`.
    profile: PathBuf,
    /// Directory holding the test binary. Prepended to PATH so bash
    /// finds it during PATH-based invocations.
    bindir: PathBuf,
}

/// Marker text printed by the test binary when it actually executes.
/// Absence in stdout is the signal that the exec was blocked before the
/// binary ran.
const REAL_BINARY_RAN: &str = "REAL_BINARY_RAN";

/// Text returned by the mediation `respond` rule configured in the test
/// profile. Presence indicates the shim was invoked and the broker
/// served the rule.
const MEDIATED_RESPONSE: &str = "MEDIATED_RESPONSE";

impl ExecFilterHarness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let home = tmp.path().join("home");
        let workdir = tmp.path().join("workdir");
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&workdir).expect("create workdir");
        std::fs::create_dir_all(&bindir).expect("create bindir");

        let testbin = bindir.join("testbin");
        let mut f = std::fs::File::create(&testbin).expect("create testbin");
        writeln!(f, "#!/bin/sh").unwrap();
        writeln!(f, "echo {REAL_BINARY_RAN}").unwrap();
        drop(f);
        chmod_plus_x(&testbin);

        let profile = tmp.path().join("profile.json");
        std::fs::write(&profile, minimal_profile_json(&testbin)).expect("write profile");

        Self {
            _tmp: tmp,
            home,
            workdir,
            testbin,
            profile,
            bindir,
        }
    }

    /// Invoke `nono run --profile <p> -- <args>` with an isolated HOME.
    /// `args` is the command and its arguments to run inside the sandbox.
    fn run_nono(&self, args: &[&str]) -> NonoOutput {
        let nono = nono_binary();
        let path_with_bindir = format!(
            "{}:{}",
            self.bindir.display(),
            std::env::var("PATH").unwrap_or_default()
        );

        let mut cmd = Command::new(&nono);
        cmd.arg("run")
            .arg("--silent")
            .arg("--allow-cwd")
            .arg("--profile")
            .arg(&self.profile)
            .arg("--workdir")
            .arg(&self.workdir)
            .arg("--");
        for a in args {
            cmd.arg(a);
        }
        // Preserve a minimal env so nono can find its own resources but
        // isolate HOME so audit logs land in our tempdir.
        cmd.env_clear();
        cmd.env("HOME", &self.home);
        cmd.env("PATH", &path_with_bindir);
        cmd.env("TERM", "dumb");
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let output = cmd.output().expect("spawn nono");
        NonoOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code().unwrap_or(-1),
        }
    }

    /// Parse the session audit file into a vector of JSON values. Returns
    /// empty vec if the file does not exist (e.g., nono hasn't started
    /// a session yet or audit was disabled).
    fn read_audit_events(&self) -> Vec<serde_json::Value> {
        let path = self.home.join(".nono").join("sessions").join("audit.jsonl");
        let Ok(content) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        content
            .lines()
            .filter(|l| !l.is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

struct NonoOutput {
    stdout: String,
    stderr: String,
    exit_code: i32,
}

impl NonoOutput {
    fn combined(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.exit_code, self.stdout, self.stderr
        )
    }
}

fn nono_binary() -> PathBuf {
    ensure_nono_shim_built();
    PathBuf::from(env!("CARGO_BIN_EXE_nono"))
}

/// The mediation session needs the `nono-shim` binary next to `nono`.
/// Cargo only builds the current crate's bins for a test run, so we
/// invoke `cargo build -p nono-shim` once per test process. The build is
/// a no-op on subsequent calls if the artifact is already up to date.
fn ensure_nono_shim_built() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let nono_exe = PathBuf::from(env!("CARGO_BIN_EXE_nono"));
        let target_dir = nono_exe.parent().expect("nono exe has parent");
        let shim = target_dir.join("nono-shim");
        if shim.is_file() {
            return;
        }
        // Locate the workspace root from the manifest dir.
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest.parent().and_then(Path::parent).unwrap_or(&manifest);
        let status = Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("nono-shim")
            .arg("--bin")
            .arg("nono-shim")
            .current_dir(workspace)
            .status()
            .expect("spawn cargo to build nono-shim");
        assert!(
            status.success(),
            "cargo build -p nono-shim failed; shim is required for mediation sessions"
        );
        assert!(
            shim.is_file(),
            "nono-shim still missing at {} after successful build",
            shim.display()
        );
    });
}

fn chmod_plus_x(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .expect("stat script")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(path, perms).expect("chmod +x");
}

fn minimal_profile_json(testbin: &Path) -> String {
    // Minimal mediation profile. Grants are narrow:
    //  - The bindir holding testbin and the workdir: read + exec access
    //    so the agent can fork/exec and locate testbin.
    //  - Standard system dirs so bash and basic utilities work.
    //  - Crucially NOT the tempdir root itself: that would overlap with
    //    `~/.nono` (which lives under $HOME = <tmp>/home) and nono
    //    refuses to grant paths that overlap its own state roots.
    //
    // The profile lists testbin as a mediated command with an explicit
    // `binary_path` so resolution does not depend on the broker's PATH,
    // and a `respond` rule that returns MEDIATED_RESPONSE for any
    // invocation.
    let testbin_json = testbin.display().to_string().replace('\\', "\\\\");
    let bindir_json = testbin
        .parent()
        .expect("testbin has parent")
        .display()
        .to_string()
        .replace('\\', "\\\\");
    format!(
        r#"{{
  "meta": {{ "name": "exec-filter-test", "version": "1.0" }},
  "filesystem": {{
    "allow": ["{bindir_json}", "/usr", "/bin", "/lib", "/lib64", "/etc"]
  }},
  "network": {{ "block": false }},
  "workdir": {{ "access": "readwrite" }},
  "mediation": {{
    "commands": [
      {{
        "name": "testbin",
        "binary_path": "{testbin_json}",
        "intercept": [
          {{
            "args_prefix": [],
            "action": {{
              "type": "respond",
              "stdout": "{MEDIATED_RESPONSE}\n",
              "exit_code": 0
            }}
          }}
        ]
      }}
    ]
  }}
}}"#
    )
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

/// Core test (number 2 in the plan's integration-test list).
///
/// RED until Phase 3 installs the exec filter + supervisor classification.
/// Before the filter lands, a direct-path invocation of the mediated
/// binary runs it normally: stdout contains `REAL_BINARY_RAN` and exit is
/// 0. After Phase 3, the kernel traps the execve and the supervisor
/// responds EACCES; the shell reports a permission error and the binary
/// never runs.
#[test]
fn direct_path_mediated_invocation_is_denied() {
    let h = ExecFilterHarness::new();
    let testbin_path = h.testbin.display().to_string();
    // Wrap in sh -c so the resulting shell sees the full path and does
    // not do PATH lookup. This simulates what an agent bash would do
    // when given a literal `/absolute/path/to/testbin` command.
    let out = h.run_nono(&["sh", "-c", &format!("{} direct", testbin_path)]);

    assert!(
        !out.stdout.contains(REAL_BINARY_RAN),
        "real binary ran but should have been blocked by exec filter; {}",
        out.combined()
    );
    assert!(
        out.exit_code != 0,
        "expected non-zero exit (shell should propagate EACCES); {}",
        out.combined()
    );
    let stderr_lower = out.stderr.to_lowercase();
    assert!(
        stderr_lower.contains("permission denied")
            || stderr_lower.contains("eacces")
            || stderr_lower.contains("cannot execute"),
        "expected permission-denied-style message; {}",
        out.combined()
    );
}
