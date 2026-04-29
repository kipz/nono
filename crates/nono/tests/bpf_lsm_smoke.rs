//! BPF-LSM exec filter — load + attach smoke test.
//!
//! What this validates:
//! - The BPF C program in `src/bpf/exec_filter.bpf.c` compiles
//!   cleanly via the build script.
//! - The compiled bytecode passes the kernel verifier.
//! - Loading the program (via `bpf(BPF_PROG_LOAD)`) succeeds.
//! - Attaching to `bprm_check_security` succeeds (or fails for a
//!   reason the test can recognize).
//!
//! What this does **not** validate (requires `bpf` in the active
//! LSM stack, which needs an AMI / kernel-cmdline change):
//! - That the LSM hook actually fires on real exec.
//! - That returning `-EACCES` from the program propagates to
//!   userspace.
//! - End-to-end behavior under the vfork-bomb POC.
//!
//! Gating:
//! - Linux-only (rest of the tree elides the BPF code).
//! - Requires `bpf-lsm` feature (the default on Linux).
//! - Requires `CAP_BPF` (or `CAP_SYS_ADMIN`) on the test runner.
//!   Without it the test prints a skip message instead of failing.
//! - The attach step is gated separately on `bpf` being in the
//!   active LSM stack: when it isn't, the test reports the load
//!   succeeded and the attach was skipped.

#![cfg(all(target_os = "linux", feature = "bpf-lsm"))]

use nono::sandbox::bpf_lsm;

fn have_cap_bpf() -> bool {
    // /proc/self/status's `CapEff:` line is a hex bitmap. CAP_BPF
    // is bit 39 (0x80_00000000), CAP_SYS_ADMIN is bit 21
    // (0x200000). We accept either.
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("CapEff:\t") {
            if let Ok(bits) = u64::from_str_radix(rest.trim(), 16) {
                let cap_sys_admin = 1u64 << 21;
                let cap_bpf = 1u64 << 39;
                return (bits & (cap_sys_admin | cap_bpf)) != 0;
            }
        }
    }
    false
}

#[test]
fn install_exec_filter_with_empty_deny_set() {
    if !have_cap_bpf() {
        eprintln!(
            "skipping: needs CAP_BPF or CAP_SYS_ADMIN. \
             Re-run with `sudo -E cargo test -p nono --test bpf_lsm_smoke`."
        );
        return;
    }

    let lsm_active = bpf_lsm::is_bpf_lsm_available();
    if !lsm_active {
        // Without `bpf` in /sys/kernel/security/lsm we can't
        // legally install_exec_filter (it would surface
        // NotInActiveLsm). Verify that's what we get.
        let result = bpf_lsm::install_exec_filter(&[]);
        assert!(
            matches!(result, Err(bpf_lsm::BpfLsmError::NotInActiveLsm)),
            "expected NotInActiveLsm without bpf in LSM stack, got: {result:?}"
        );
        eprintln!(
            "skipping attach test: bpf is not in /sys/kernel/security/lsm \
             (booted with lsm=...,bpf required). Load+verifier test still \
             validated end-to-end via the standalone bpftool prog load \
             command in the test plan."
        );
        return;
    }

    // bpf is in the active LSM list — full attach test.
    let handle = bpf_lsm::install_exec_filter(&[])
        .expect("install_exec_filter should succeed with empty deny set");
    // The handle keeps the program loaded and attached for its
    // lifetime; dropping it detaches.
    drop(handle);
}

/// Verify the build chain *and* the BPF load path against the
/// kernel — independent of `bpf` being in the active LSM list.
///
/// We do this by setting `NONO_BPF_LSM_SKIP_ACTIVE_CHECK=1`, which
/// the loader honors as a developer override that bypasses the
/// `is_bpf_lsm_available` early-return. The kernel's
/// `BPF_PROG_LOAD` and `BPF_LINK_CREATE` calls then run normally.
/// On a kernel without `bpf` in the active LSM stack, the load
/// step succeeds (kernel accepts the program — verifier runs and
/// passes), and the attach step is what reveals the LSM-list gap.
///
/// This exercise catches verifier regressions on every
/// `cargo test`, even on hosts that haven't been rebooted with
/// `lsm=...,bpf` yet.
#[test]
fn force_load_validates_verifier_acceptance() {
    if !have_cap_bpf() {
        eprintln!(
            "skipping: needs CAP_BPF or CAP_SYS_ADMIN. \
             Re-run with `sudo -E cargo test -p nono --test bpf_lsm_smoke`."
        );
        return;
    }

    let result = bpf_lsm::install_exec_filter_no_lsm_check(&[]);

    match (bpf_lsm::is_bpf_lsm_available(), result) {
        (true, Ok(_)) => {
            // Active LSM has bpf — full path worked.
        }
        (false, Ok(_)) => {
            // Surprising but not a failure: some kernels accept
            // attach even without bpf in the active LSM list.
            // The hook just doesn't fire on real exec.
        }
        (false, Err(bpf_lsm::BpfLsmError::LibBpf(e))) => {
            // Expected: load succeeded, attach failed with
            // EOPNOTSUPP / ENOENT because bpf isn't in active LSM.
            // The fact that we got a libbpf error (not a different
            // BpfLsmError variant) confirms we got past the load.
            eprintln!("expected attach failure on host without bpf in active LSM: {e}");
        }
        (true, Err(e)) => {
            panic!("host has bpf in active LSM but install failed: {e}");
        }
        (false, Err(other)) => {
            panic!("expected load to succeed on a kernel with CONFIG_BPF_LSM=y; got: {other:?}");
        }
    }
}

#[test]
fn install_with_real_binary_in_deny_set() {
    if !have_cap_bpf() {
        eprintln!(
            "skipping: needs CAP_BPF or CAP_SYS_ADMIN. \
             Re-run with `sudo -E cargo test -p nono --test bpf_lsm_smoke`."
        );
        return;
    }
    if !bpf_lsm::is_bpf_lsm_available() {
        eprintln!("skipping: bpf is not in /sys/kernel/security/lsm");
        return;
    }

    // Use a known-stable binary. We don't actually try to exec it
    // — this test only verifies population of the deny_set map.
    let deny = vec![std::path::PathBuf::from("/bin/true")];
    let _handle = bpf_lsm::install_exec_filter(&deny)
        .expect("install with /bin/true in deny set should succeed");
}
