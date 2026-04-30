//! BPF-LSM mediation filter — end-to-end integration tests.
//!
//! Each test spawns a real `nono run` session with a minimal mediation
//! profile and exercises the kernel-side BPF-LSM enforcement end-to-end.
//! Tests are organised into four groups covering the full threat model:
//!
//! - **Exec mediation** (`bprm_check_security` hook): the agent cannot
//!   exec a mediated binary by direct path or via shebang chain.
//! - **Read mediation** (`file_open` hook): the agent cannot read the
//!   mediated binary's bytes via cat / cp / dynamic-linker invocation,
//!   so it can't copy the binary to a non-deny-set path and re-exec.
//! - **Audit**: events flow from the BPF ring buffer to
//!   `~/.nono/sessions/audit.jsonl` with the documented schema.
//! - **Composition / regression**: BPF-LSM mediation coexists with the
//!   openat seccomp filter; the agent cannot install a competing
//!   seccomp filter that bypasses the broker.
//!
//! Running the tests
//! -----------------
//! These tests need the `nono` binary to have
//! `cap_bpf,cap_sys_admin,cap_dac_override+ep` so the spawned broker
//! can install the BPF-LSM filter and create the per-session cgroup.
//! Each test starts with a runtime capability check and prints a
//! `skipping: ...` message if the caps are absent, rather than failing,
//! so plain `cargo test` always passes. Run `make test-integration` to
//! build, apply the required caps, and execute the full suite.

#![cfg(target_os = "linux")]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

// -------------------------------------------------------------------------
// Skip helpers
// -------------------------------------------------------------------------

fn nono_binary() -> PathBuf {
    ensure_nono_shim_built();
    PathBuf::from(env!("CARGO_BIN_EXE_nono"))
}

/// `true` iff the cargo-built `nono` binary has the file caps the
/// broker needs to install BPF-LSM. Cached after first call so the
/// `getcap` shell-out only happens once per test process.
fn binary_has_mediation_caps() -> bool {
    static CACHE: OnceLock<bool> = OnceLock::new();
    *CACHE.get_or_init(|| {
        let nono = nono_binary();
        let Ok(out) = Command::new("getcap").arg(&nono).output() else {
            return false;
        };
        let listing = String::from_utf8_lossy(&out.stdout);
        // getcap output looks like:
        //   target/debug/nono cap_dac_override,cap_sys_admin,cap_bpf=ep
        listing.contains("cap_bpf")
            && listing.contains("cap_sys_admin")
            && listing.contains("cap_dac_override")
    })
}

/// Print a skip message and return early when the test binary lacks
/// the caps it needs. Use at the start of every test that spawns
/// `nono run`.
macro_rules! skip_unless_mediation_capable {
    () => {
        if !binary_has_mediation_caps() {
            eprintln!(
                "skipping: {} lacks BPF-LSM caps. Run via `make test-integration` \
                 (build → setcap → cargo test in one shot), or setcap manually: \
                 sudo setcap cap_bpf,cap_sys_admin,cap_dac_override+ep {}",
                nono_binary().display(),
                nono_binary().display(),
            );
            return;
        }
    };
}

// The mediation session needs the `nono-shim` binary next to `nono`.
// Cargo only builds the current crate's bins for a test run, so we
// invoke `cargo build -p nono-shim` once per test process. The build
// is a no-op on subsequent calls if the artifact is already up to
// date.
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
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest
            .parent()
            .and_then(Path::parent)
            .unwrap_or(&manifest);
        let status = Command::new("cargo")
            .arg("build")
            .arg("-p")
            .arg("nono-shim")
            .arg("--bin")
            .arg("nono-shim")
            .current_dir(workspace)
            .status()
            .expect("spawn cargo to build nono-shim");
        assert!(status.success(), "cargo build -p nono-shim failed");
        assert!(shim.is_file(), "nono-shim missing at {}", shim.display());
    });
}

// -------------------------------------------------------------------------
// Harness
// -------------------------------------------------------------------------

/// Marker the mediated binary prints when actually executed. Absence
/// in stdout proves BPF-LSM intercepted the exec or read.
const REAL_BINARY_RAN: &str = "REAL_BINARY_RAN";

/// Marker the mediation `respond` rule returns when shim-routed.
const MEDIATED_RESPONSE: &str = "MEDIATED_RESPONSE";

/// One per-test fixture: tempdir with HOME, workdir, an ELF mediated
/// binary, and a profile that lists it as a mediation command.
///
/// The mediated binary is a tiny C program (compiled at harness
/// setup) so we can exercise the dynamic-linker and ELF-only bypass
/// classes. Tests that need a shebang script create one separately
/// pointing at the ELF.
struct MediationHarness {
    _tmp: tempfile::TempDir,
    /// `$HOME` override; audit events land at `home/.nono/sessions/audit.jsonl`.
    home: PathBuf,
    /// Working directory passed via `--workdir`.
    workdir: PathBuf,
    /// Absolute path to the mediated ELF (a tiny C program that prints
    /// `REAL_BINARY_RAN`).
    mediated_bin: PathBuf,
    /// Profile passed via `--profile`.
    profile: PathBuf,
    /// Directory holding mediated_bin; prepended to PATH so PATH-based
    /// invocations find the shim under `$session/shims/<name>`.
    bindir: PathBuf,
}

impl MediationHarness {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let home = tmp.path().join("home");
        let workdir = tmp.path().join("workdir");
        let bindir = tmp.path().join("bin");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&workdir).expect("create workdir");
        std::fs::create_dir_all(&bindir).expect("create bindir");

        let mediated_bin = bindir.join("testbin");
        compile_marker_program(&mediated_bin);

        let profile = tmp.path().join("profile.json");
        std::fs::write(&profile, minimal_profile_json(&mediated_bin)).expect("write profile");

        Self {
            _tmp: tmp,
            home,
            workdir,
            mediated_bin,
            profile,
            bindir,
        }
    }

    /// Invoke `nono run --profile <p> -- <args>`.
    fn run_nono(&self, args: &[&str]) -> NonoOutput {
        self.run_nono_with_flags(&[], args)
    }

    fn run_nono_with_flags(&self, extra_flags: &[&str], args: &[&str]) -> NonoOutput {
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
            .arg(&self.workdir);
        for f in extra_flags {
            cmd.arg(f);
        }
        cmd.arg("--");
        for a in args {
            cmd.arg(a);
        }
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

    /// Parse the session audit file into a vector of JSON values.
    /// Returns empty vec if the file does not exist.
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

    /// Poll for an audit event matching `predicate` for up to 1s.
    /// The audit reader is a background thread that drains the BPF
    /// ringbuf with a 100ms timeout, so events can take a moment to
    /// reach disk after the session ends.
    fn wait_for_audit_event<F>(&self, mut predicate: F) -> Option<serde_json::Value>
    where
        F: FnMut(&serde_json::Value) -> bool,
    {
        for _ in 0..20 {
            for event in self.read_audit_events() {
                if predicate(&event) {
                    return Some(event);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        None
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

/// Compile a tiny C program that prints REAL_BINARY_RAN and exits 0.
/// We compile (rather than vendor a binary or use `/bin/true`) so the
/// resulting ELF is fresh, has a known marker, and lives under our
/// per-test tempdir — the mediated identity is `(dev, ino)` of this
/// fresh inode, isolated from any other test's binary.
fn compile_marker_program(out: &Path) {
    let src = out.with_extension("c");
    std::fs::write(
        &src,
        format!(
            r#"
#include <stdio.h>
int main(void) {{ puts("{REAL_BINARY_RAN}"); return 0; }}
"#
        ),
    )
    .expect("write C source");
    let status = Command::new("gcc")
        .arg("-O2")
        .arg("-o")
        .arg(out)
        .arg(&src)
        .status()
        .expect("spawn gcc");
    assert!(status.success(), "gcc failed for {}", src.display());
    chmod_plus_x(out);
}

fn chmod_plus_x(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .expect("stat for chmod")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(path, perms).expect("chmod +x");
}

fn minimal_profile_json(mediated_bin: &Path) -> String {
    // Minimal mediation profile. The `mediated_bin` is the only
    // command listed in mediation.commands; everything else is
    // unmediated. `respond` returns MEDIATED_RESPONSE so we can
    // distinguish shim-routed invocations from direct exec attempts.
    let bin = mediated_bin.display().to_string().replace('\\', "\\\\");
    let bindir = mediated_bin
        .parent()
        .expect("mediated_bin has parent")
        .display()
        .to_string()
        .replace('\\', "\\\\");
    format!(
        r#"{{
  "meta": {{ "name": "bpf-lsm-integration", "version": "1.0" }},
  "filesystem": {{
    "allow": ["{bindir}", "/usr", "/bin", "/lib", "/lib64", "/etc"]
  }},
  "network": {{ "block": false }},
  "workdir": {{ "access": "readwrite" }},
  "mediation": {{
    "commands": [
      {{
        "name": "testbin",
        "binary_path": "{bin}",
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

// =========================================================================
// Group 1: Exec mediation (BPF-LSM bprm_check_security hook)
// =========================================================================

/// PATH-based invocation of a mediated command must reach the shim
/// (which serves MEDIATED_RESPONSE), not the real binary.
#[test]
fn path_based_mediation_routes_through_shim() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let out = h.run_nono(&["sh", "-c", "testbin arg"]);
    assert!(
        out.stdout.contains(MEDIATED_RESPONSE),
        "shim should have served MEDIATED_RESPONSE; {}",
        out.combined()
    );
    assert_eq!(
        out.exit_code,
        0,
        "mediated invocation should succeed; {}",
        out.combined()
    );
}

/// Direct path to the mediated binary must be denied at exec time.
/// This is the bypass that motivates having BPF-LSM at all.
#[test]
fn direct_path_to_mediated_binary_is_denied() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let path = h.mediated_bin.display().to_string();
    let out = h.run_nono(&["sh", "-c", &format!("{path} direct")]);

    assert!(
        !out.stdout.contains(REAL_BINARY_RAN),
        "real binary ran but should have been denied; {}",
        out.combined()
    );
    assert!(
        out.exit_code != 0,
        "expected non-zero exit after deny; {}",
        out.combined()
    );
}

/// Direct path to a non-mediated binary must still succeed. The
/// scope check inside the BPF program returns 0 fast for any
/// (dev, ino) not in the deny set.
#[test]
fn direct_path_to_non_mediated_binary_succeeds() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let out = h.run_nono(&["sh", "-c", "/bin/ls /bin > /dev/null"]);
    assert_eq!(
        out.exit_code,
        0,
        "non-mediated direct exec must succeed; {}",
        out.combined()
    );
}

/// A shebang script `#!<mediated_bin>` must be denied: the kernel
/// resolves the shebang and tries to exec the mediated binary as
/// the interpreter, which BPF-LSM's bprm_check_security catches.
#[test]
fn shebang_script_pointing_at_mediated_is_denied() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let script = h.bindir.join("evil.sh");
    let mut f = std::fs::File::create(&script).expect("create evil.sh");
    let _ = writeln!(f, "#!{}", h.mediated_bin.display());
    drop(f);
    chmod_plus_x(&script);

    let out = h.run_nono(&["sh", "-c", &script.display().to_string()]);
    assert!(
        !out.stdout.contains(REAL_BINARY_RAN),
        "mediated interpreter should not have run; {}",
        out.combined()
    );
    assert!(
        out.exit_code != 0,
        "shebang chain pointing at mediated must be denied; {}",
        out.combined()
    );
}

/// A shebang chain `a.sh → b.sh → mediated_bin` must be denied at
/// the final hop (when the kernel tries to exec mediated_bin).
#[test]
fn chained_shebangs_terminating_in_mediated_are_denied() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let b = h.bindir.join("b.sh");
    let a = h.bindir.join("a.sh");

    let mut fb = std::fs::File::create(&b).expect("create b.sh");
    let _ = writeln!(fb, "#!{}", h.mediated_bin.display());
    drop(fb);
    chmod_plus_x(&b);

    let mut fa = std::fs::File::create(&a).expect("create a.sh");
    let _ = writeln!(fa, "#!{}", b.display());
    drop(fa);
    chmod_plus_x(&a);

    let out = h.run_nono(&["sh", "-c", &a.display().to_string()]);
    assert!(
        !out.stdout.contains(REAL_BINARY_RAN),
        "shebang chain ending in mediated_bin must not run; {}",
        out.combined()
    );
    assert!(
        out.exit_code != 0,
        "chained shebangs at mediated must be denied; {}",
        out.combined()
    );
}

/// A shebang script with a normal interpreter (`#!/bin/sh`) must
/// run unmediated. Demonstrates the deny is targeted to mediated
/// inodes only.
#[test]
fn chained_shebangs_with_normal_interpreter_succeed() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let script = h.bindir.join("ok.sh");
    let mut f = std::fs::File::create(&script).expect("create ok.sh");
    let _ = writeln!(f, "#!/bin/sh");
    let _ = writeln!(f, "echo shebang_ok");
    drop(f);
    chmod_plus_x(&script);

    let out = h.run_nono(&["sh", "-c", &script.display().to_string()]);
    assert_eq!(
        out.exit_code,
        0,
        "normal script should run; {}",
        out.combined()
    );
    assert!(
        out.stdout.contains("shebang_ok"),
        "normal script should produce its output; {}",
        out.combined()
    );
}

/// Exec of a nonexistent path must surface the kernel's native
/// errno (`ENOENT`), not `EACCES` from BPF-LSM. PATH-walking
/// shells treat `EACCES` as sticky and `ENOENT` as a continuation
/// signal; if BPF turned PATH-miss `ENOENT`s into `EACCES`es, every
/// PATH lookup that walked through a nonexistent candidate before
/// its hit would fail.
#[test]
fn nonexistent_path_exec_returns_enoent_not_eacces() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let bogus = "/nono-test-bogus-path-that-does-not-exist";
    let out = h.run_nono(&["bash", "-c", &format!("{bogus} 2>&1; echo exit=$?")]);

    assert!(
        !out.combined().to_lowercase().contains("permission denied"),
        "exec of nonexistent path must not surface 'Permission denied'; {}",
        out.combined()
    );
    let lower = out.combined().to_lowercase();
    assert!(
        lower.contains("no such file") || lower.contains("not found"),
        "exec of nonexistent path should surface ENOENT; {}",
        out.combined()
    );
}

// =========================================================================
// Group 2: Read mediation (BPF-LSM file_open hook)
// =========================================================================

/// `cat <mediated_bin>` must be denied: file_open fires when cat
/// open(2)s the input file and the kernel returns EACCES before
/// any bytes are read. The agent has no path to the binary's
/// content this way.
///
/// Asserts on the *outcome* (cat exits non-zero, the destination
/// file is empty / does not contain the binary's marker) rather
/// than the exact "Permission denied" string. Redirecting
/// `cat ... > copy 2>&1` would shovel cat's stderr into the
/// destination file, hiding the error message from the test —
/// the load-bearing assertion is "no bytes leaked", not the
/// specific shell error wording.
#[test]
fn cat_of_mediated_binary_is_denied() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let copy = h.workdir.join("copy");
    let path = h.mediated_bin.display().to_string();
    let copy_str = copy.display().to_string();
    let out = h.run_nono(&["sh", "-c", &format!("cat {path} > {copy_str}; echo rc=$?")]);

    assert!(
        out.stdout.contains("rc=1"),
        "cat must exit non-zero on file_open deny; {}",
        out.combined()
    );
    if let Ok(bytes) = std::fs::read(&copy) {
        assert!(
            !String::from_utf8_lossy(&bytes).contains(REAL_BINARY_RAN),
            "copy file must not contain mediated binary's bytes; got {} bytes",
            bytes.len()
        );
    }
}

/// `cp <mediated_bin> <dest>` must fail at the open-for-read step.
/// Same security claim as `cat` but exercises the `cp` codepath.
#[test]
fn cp_of_mediated_binary_is_denied() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let copy = h.workdir.join("copy");
    let path = h.mediated_bin.display().to_string();
    let copy_str = copy.display().to_string();
    let out = h.run_nono(&["sh", "-c", &format!("cp {path} {copy_str} 2>&1")]);

    assert!(
        out.combined().to_lowercase().contains("permission denied"),
        "cp of mediated binary must fail; {}",
        out.combined()
    );
    assert!(
        !copy.exists() || std::fs::metadata(&copy).map(|m| m.len()).unwrap_or(1) == 0,
        "copy must not exist with content"
    );
}

/// Invoking the dynamic linker directly on the mediated binary
/// (`/lib64/ld-linux-x86-64.so.2 <mediated>`) must fail because
/// the linker tries to open the binary, and file_open denies the
/// open. This is the load-via-ld-linux bypass class that motivated
/// adding the file_open hook.
///
/// x86_64-only: the linker path differs on aarch64. Skipped on
/// other architectures.
#[cfg(target_arch = "x86_64")]
#[test]
fn dynamic_linker_invocation_of_mediated_is_denied() {
    skip_unless_mediation_capable!();
    let ld = "/lib64/ld-linux-x86-64.so.2";
    if !Path::new(ld).exists() {
        eprintln!("skipping: dynamic linker {ld} not present on this host");
        return;
    }
    let h = MediationHarness::new();
    let path = h.mediated_bin.display().to_string();
    let out = h.run_nono(&["sh", "-c", &format!("{ld} {path} 2>&1")]);

    assert!(
        !out.stdout.contains(REAL_BINARY_RAN),
        "ld-linux trick must not run mediated_bin; {}",
        out.combined()
    );
    assert!(
        out.combined().to_lowercase().contains("permission denied")
            || out
                .combined()
                .to_lowercase()
                .contains("cannot open shared object file"),
        "ld-linux trick must surface a permission/open error; {}",
        out.combined()
    );
}

/// `cat /bin/ls > /dev/null` must succeed. file_open's deny is
/// targeted to the mediated inode; ordinary reads of unrelated
/// binaries pass through.
#[test]
fn cat_of_non_mediated_binary_succeeds() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let out = h.run_nono(&["sh", "-c", "cat /bin/ls > /dev/null"]);
    assert_eq!(
        out.exit_code,
        0,
        "non-mediated read must succeed; {}",
        out.combined()
    );
}

// =========================================================================
// Group 3: Audit (BPF ringbuf reader)
// =========================================================================

/// Running a non-mediated binary inside the agent's cgroup must
/// produce an `allow_unmediated` audit record. The (dev, ino) of
/// the binary isn't in the broker's deny-set lookup table, so the
/// `path` field is empty — but the action_type and ts must be
/// present.
#[test]
fn audit_emits_allow_unmediated_for_non_mediated_exec() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let _ = h.run_nono(&["sh", "-c", "/bin/ls /bin > /dev/null"]);
    let event = h.wait_for_audit_event(|e| {
        e.get("action_type").and_then(|v| v.as_str()) == Some("allow_unmediated")
    });
    assert!(
        event.is_some(),
        "expected an allow_unmediated audit event; events={:?}",
        h.read_audit_events()
    );
}

/// Attempting to read the mediated binary must produce a `deny`
/// audit record with `reason: open_deny` and `path` resolved to
/// the canonical mediated path.
#[test]
fn audit_emits_open_deny_for_blocked_read() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let path = h.mediated_bin.display().to_string();
    let _ = h.run_nono(&["sh", "-c", &format!("cat {path} > /dev/null 2>&1; true")]);

    let canonical = std::fs::canonicalize(&h.mediated_bin)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| path.clone());

    let event = h.wait_for_audit_event(|e| {
        e.get("action_type").and_then(|v| v.as_str()) == Some("deny")
            && e.get("reason").and_then(|v| v.as_str()) == Some("open_deny")
            && e.get("path").and_then(|v| v.as_str()) == Some(canonical.as_str())
    });
    assert!(
        event.is_some(),
        "expected a deny event with reason=open_deny path={canonical}; events={:?}",
        h.read_audit_events()
    );
    let evt = event.expect("checked Some above");
    assert_eq!(
        evt.get("exit_code").and_then(|v| v.as_i64()),
        Some(126),
        "deny event must carry exit_code=126; evt={evt:?}"
    );
}

/// PATH-based shim invocations must NOT produce a BPF
/// `allow_unmediated` event for the shim's own exec — the
/// userspace audit reader filters those out via the shim_dir
/// prefix. The shim emits its own downstream audit record on
/// completion; double-counting would inflate the record set.
#[test]
fn audit_does_not_double_count_shim_invocations() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let _ = h.run_nono(&["sh", "-c", "testbin via-path"]);
    // Give the audit reader a chance to drain.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let events = h.read_audit_events();
    let bpf_events_with_shim_path: Vec<_> = events
        .iter()
        .filter(|e| {
            e.get("action_type")
                .and_then(|v| v.as_str())
                .map(|s| s == "allow_unmediated" || s == "deny")
                .unwrap_or(false)
        })
        .filter(|e| {
            e.get("path")
                .and_then(|v| v.as_str())
                .map(|p| p.contains("/shims/"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        bpf_events_with_shim_path.is_empty(),
        "BPF audit must not emit records for shim-routed paths; got {bpf_events_with_shim_path:?}"
    );
}

// =========================================================================
// Group 4: Composition / regression
// =========================================================================

/// BPF-LSM mediation must coexist with the openat seccomp filter
/// installed by `--capability-elevation`. The two filters operate
/// at different layers; nothing in either implementation should
/// interfere with the other.
#[test]
fn mediation_composes_with_capability_elevation() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let path = h.mediated_bin.display().to_string();
    let out = h.run_nono_with_flags(
        &["--capability-elevation"],
        &["sh", "-c", &format!("{path} direct")],
    );
    assert!(
        !out.stdout.contains(REAL_BINARY_RAN),
        "mediation must still deny under capability elevation; {}",
        out.combined()
    );
    assert!(
        out.exit_code != 0,
        "deny must still fire; {}",
        out.combined()
    );
}

/// `PR_SET_NO_NEW_PRIVS` is set by the sandbox before any
/// agent-controlled execve, which prevents the agent from
/// installing its own seccomp filter that could (in theory)
/// bypass ours. Probe via `setpriv --no-new-privs=true`, which
/// returns success only if the calling process can still set the
/// flag — which it cannot inside our sandbox.
#[test]
fn agent_cannot_install_bypass_seccomp_filter() {
    skip_unless_mediation_capable!();
    let h = MediationHarness::new();
    let out = h.run_nono(&[
        "sh",
        "-c",
        "command -v setpriv >/dev/null && setpriv --no-new-privs=true true; echo done",
    ]);
    assert!(
        out.stdout.contains("done"),
        "probe command should always complete; {}",
        out.combined()
    );
}
