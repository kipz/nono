//! BPF-LSM exec filter loader.
//!
//! Closes the seccomp-unotify TOCTOU bypass on the mediation shim
//! by mediating exec inside the kernel via the
//! `bprm_check_security` LSM hook. The hook runs after the kernel
//! has resolved the binary (`bprm->file` is the file the kernel
//! will actually load) and before exec is committed; returning
//! `-EACCES` from the BPF program atomically aborts the syscall,
//! with no race against any user-memory pointer the agent
//! controlled.
//!
//! The deny set is keyed by `(dev, ino)` rather than path. The
//! supervisor populates it at session start by canonicalizing each
//! `mediation.commands` real path, `stat`ing it, and inserting the
//! resulting `(st_dev, st_ino)` pair into the BPF map. Inode
//! identity also covers hardlinks the agent might create at
//! non-deny-set paths to evade a path-based check.
//!
//! Kernel requirements:
//! - `CONFIG_BPF_LSM=y` (Ubuntu 22.04 HWE 6.8 has this; verifiable
//!   via `grep bpf_lsm_bprm_check_security /proc/kallsyms`).
//! - `bpf` in the active LSM stack: `cat /sys/kernel/security/lsm`
//!   must include `bpf`. This is fixed at boot from the `lsm=`
//!   kernel cmdline parameter and cannot be changed at runtime.
//!   The workspaces AMI ships a `/etc/default/grub.d/99-bpf-lsm.cfg`
//!   that adds it (see dd-source `am/bpf-lsm-workspace-ami`).
//! - `CAP_BPF` (or `CAP_SYS_ADMIN`) on the loader process. Without
//!   it, the `bpf()` syscall fails with `EPERM` at program load.
//!
//! On hosts without `bpf` in the active LSM stack, this loader
//! refuses to install (returning [`BpfLsmError::NotInActiveLsm`])
//! so the caller falls back cleanly to the seccomp-unotify exec
//! filter. The fallback is racy against vfork-bomb but at least
//! not silently no-op'd.

#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
mod imp {
    use std::os::unix::fs::MetadataExt;

    // Skeleton generated at build time by `libbpf-cargo` from
    // `src/bpf/exec_filter.bpf.c`. Lives under `OUT_DIR` rather
    // than the source tree.
    //
    // libbpf-cargo's generator uses `unwrap()` and `expect()` in
    // its own boilerplate (raw-pointer null checks, fixed-size
    // buffer copies). The project's `clippy::unwrap_used` and
    // `clippy::expect_used` denies do not apply to generated code,
    // so the include is wrapped in a sub-module that locally
    // overrides those lints for the boilerplate. Hand-written
    // code in this file remains subject to the deny.
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::expect_used)]
    mod skel {
        include!(concat!(env!("OUT_DIR"), "/exec_filter.skel.rs"));
    }
    use skel::*;

    use std::mem::MaybeUninit;

    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use libbpf_rs::{Link, MapCore, MapFlags, OpenObject};

    /// Mirror of the `struct deny_key` declared in
    /// `src/bpf/exec_filter.bpf.c`. Layout must match exactly.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct DenyKey {
        dev: u64,
        ino: u64,
    }

    /// Errors specific to BPF-LSM exec filter installation.
    #[derive(Debug)]
    pub enum BpfLsmError {
        /// `/sys/kernel/security/lsm` does not include `bpf`. The
        /// active LSM stack is fixed at kernel boot via the
        /// `lsm=` cmdline parameter; this is unreachable until the
        /// host has been rebooted with an updated cmdline.
        NotInActiveLsm,
        /// Reading `/sys/kernel/security/lsm` failed.
        LsmFileUnreadable(std::io::Error),
        /// `stat()` on a deny-set path failed.
        Stat {
            path: std::path::PathBuf,
            error: std::io::Error,
        },
        /// `libbpf-rs` returned an error during open / load /
        /// attach. Usually `EPERM` (insufficient capability) or
        /// the kernel verifier rejecting the program.
        LibBpf(libbpf_rs::Error),
        /// More deny entries than the BPF map can hold (compile-time
        /// `MAX_DENY_ENTRIES` in `exec_filter.bpf.c`).
        TooManyDenyEntries { got: usize, max: usize },
    }

    impl std::fmt::Display for BpfLsmError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotInActiveLsm => write!(
                    f,
                    "bpf is not in /sys/kernel/security/lsm; \
                     reboot with lsm=...,bpf in the kernel cmdline"
                ),
                Self::LsmFileUnreadable(e) => {
                    write!(f, "could not read /sys/kernel/security/lsm: {e}")
                }
                Self::Stat { path, error } => {
                    write!(f, "stat({}) failed: {}", path.display(), error)
                }
                Self::LibBpf(e) => write!(f, "libbpf error: {e}"),
                Self::TooManyDenyEntries { got, max } => {
                    write!(f, "too many deny entries: {got} > {max}")
                }
            }
        }
    }

    impl std::error::Error for BpfLsmError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::LsmFileUnreadable(e) => Some(e),
                Self::Stat { error, .. } => Some(error),
                Self::LibBpf(e) => Some(e),
                Self::NotInActiveLsm | Self::TooManyDenyEntries { .. } => None,
            }
        }
    }

    impl From<libbpf_rs::Error> for BpfLsmError {
        fn from(value: libbpf_rs::Error) -> Self {
            Self::LibBpf(value)
        }
    }

    /// `true` if `bpf` is in the active LSM stack at
    /// `/sys/kernel/security/lsm`. The list is fixed at kernel boot
    /// from the `lsm=` cmdline parameter; this query is therefore
    /// stable for the life of the system.
    pub fn is_bpf_lsm_available() -> bool {
        match std::fs::read_to_string("/sys/kernel/security/lsm") {
            Ok(s) => s.split(',').any(|name| name.trim() == "bpf"),
            Err(_) => false,
        }
    }

    /// Live BPF-LSM exec filter. Holds the loaded BPF object and
    /// the attached link; dropping the handle detaches the program
    /// and frees the kernel-side resources.
    pub struct ExecFilterHandle {
        // The skeleton owns the BPF object; we hold both it and the
        // attach link so RAII tears them down in the right order
        // (link first, object second — libbpf-rs's Drop handles
        // ordering when these are stored as separate fields).
        _skel: ExecFilterSkel<'static>,
        _link: Link,
    }

    impl std::fmt::Debug for ExecFilterHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ExecFilterHandle").finish_non_exhaustive()
        }
    }

    /// Compile-time-known maximum number of entries in the
    /// `deny_set` BPF map. Mirrors `MAX_DENY_ENTRIES` in
    /// `src/bpf/exec_filter.bpf.c`. Bumping this requires a
    /// rebuild.
    pub const MAX_DENY_ENTRIES: usize = 256;

    /// Install the BPF-LSM exec filter and populate its deny set
    /// from `deny_paths`. Each path is canonicalized via
    /// `std::fs::canonicalize` and `stat`ed for `(st_dev, st_ino)`.
    /// Paths that don't exist are silently skipped (matching the
    /// canonicalize-fails-fast behavior of the seccomp filter); the
    /// kernel will surface its own `ENOENT` if the agent tries to
    /// exec one of them anyway.
    ///
    /// The handle must be kept alive for the duration of the
    /// session; dropping it detaches the program and the deny stops
    /// being enforced.
    pub fn install_exec_filter(
        deny_paths: &[std::path::PathBuf],
        agent_pid: u32,
    ) -> Result<ExecFilterHandle, BpfLsmError> {
        if !is_bpf_lsm_available() {
            return Err(BpfLsmError::NotInActiveLsm);
        }
        install_exec_filter_inner(deny_paths, agent_pid)
    }

    /// Install the filter without checking
    /// `/sys/kernel/security/lsm`. Exposed for the smoke test to
    /// validate the verifier+load+attach pipeline on hosts that
    /// haven't been rebooted with `lsm=...,bpf` yet. Production
    /// code should always go through [`install_exec_filter`]
    /// because attaching on a host without `bpf` in the active
    /// LSM stack succeeds but produces no enforcement — the BPF
    /// hook is registered, never fires.
    #[doc(hidden)]
    pub fn install_exec_filter_no_lsm_check(
        deny_paths: &[std::path::PathBuf],
        agent_pid: u32,
    ) -> Result<ExecFilterHandle, BpfLsmError> {
        install_exec_filter_inner(deny_paths, agent_pid)
    }

    fn install_exec_filter_inner(
        deny_paths: &[std::path::PathBuf],
        agent_pid: u32,
    ) -> Result<ExecFilterHandle, BpfLsmError> {
        // Canonicalize-and-stat the deny paths first so we surface
        // any I/O errors before touching the kernel. Map entries
        // that fail to canonicalize are dropped silently — they
        // cannot be reached through any path the kernel could
        // resolve, so they're not part of the threat surface.
        let mut entries: Vec<DenyKey> = Vec::with_capacity(deny_paths.len());
        for raw in deny_paths {
            let canonical = match std::fs::canonicalize(raw) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let meta = std::fs::metadata(&canonical).map_err(|e| BpfLsmError::Stat {
                path: canonical.clone(),
                error: e,
            })?;
            entries.push(DenyKey {
                dev: meta.dev(),
                ino: meta.ino(),
            });
        }

        if entries.len() > MAX_DENY_ENTRIES {
            return Err(BpfLsmError::TooManyDenyEntries {
                got: entries.len(),
                max: MAX_DENY_ENTRIES,
            });
        }

        // libbpf-rs's `SkelBuilder::open` borrows from an
        // `OpenObject` storage owned by the caller. The skeleton
        // and the link both reference this storage, so it has to
        // outlive the handle. We `Box::leak` it for a 'static
        // lifetime; the leak is bounded (one OpenObject per
        // session, ~hundreds of bytes) and is reclaimed when the
        // broker process exits. This is the canonical idiom for
        // long-lived skeletons in libbpf-rs 0.26.
        let storage: &'static mut MaybeUninit<OpenObject> =
            Box::leak(Box::new(MaybeUninit::uninit()));

        let builder = ExecFilterSkelBuilder::default();
        let open = builder.open(storage)?;
        // The skeleton's `open()` returns an `OpenExecFilterSkel`
        // — at this point the BPF object is in userspace memory
        // but not yet in the kernel. `load()` calls bpf() to
        // verify and install.
        let skel = open.load()?;

        // Populate the deny_set map. One bpf() per entry; with
        // MAX_DENY_ENTRIES = 256 this is bounded.
        let map = &skel.maps.deny_set;
        let one: u8 = 1;
        for entry in &entries {
            let key_bytes: [u8; std::mem::size_of::<DenyKey>()] =
                unsafe { std::mem::transmute(*entry) };
            map.update(&key_bytes, std::slice::from_ref(&one), MapFlags::ANY)?;
        }

        // Populate the scope map. The BPF program reads this and
        // walks each task's parent chain looking for `agent_pid`;
        // tasks not in the agent's tree (broker children, user
        // shells outside nono, system services) skip the deny
        // check entirely. Setting `agent_pid = 0` here means
        // "no scoping yet" and causes the program to allow every
        // exec — useful while the broker is mid-setup.
        let scope_map = &skel.maps.scope;
        let scope_key: u32 = 0;
        let scope_val: [u8; 4] = agent_pid.to_ne_bytes();
        scope_map.update(
            &scope_key.to_ne_bytes(),
            &scope_val,
            MapFlags::ANY,
        )?;

        // Attach to bprm_check_security. With `bpf` in the active
        // LSM list, the program now mediates every exec on the
        // host (subject to the deny_set membership check). On
        // hosts without `bpf` in the LSM list we'd never reach
        // here — the early `is_bpf_lsm_available` check returned
        // NotInActiveLsm.
        let link = skel.progs.check_exec.attach()?;

        Ok(ExecFilterHandle {
            _skel: skel,
            _link: link,
        })
    }

    /// Number of deny entries the loader observed when populating
    /// the map. Used by the supervisor to log the effective deny
    /// set size at session start.
    pub fn deny_entry_count(deny_paths: &[std::path::PathBuf]) -> usize {
        deny_paths
            .iter()
            .filter(|p| std::fs::canonicalize(p).is_ok())
            .count()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn deny_entry_count_skips_nonexistent() {
            let paths = vec![
                std::path::PathBuf::from("/bin/sh"),
                std::path::PathBuf::from("/this/does/not/exist"),
            ];
            // /bin/sh is canonicalizable on every Linux test runner;
            // /this/does/not/exist is not.
            assert!(deny_entry_count(&paths) <= 1);
        }

        #[test]
        fn is_bpf_lsm_available_does_not_panic() {
            // Behavior depends on the host kernel. The only thing
            // this guards is that the function doesn't throw on
            // any of the realistic /sys/kernel/security/lsm
            // contents.
            let _ = is_bpf_lsm_available();
        }

        // The actual install_exec_filter() test lives under
        // tests/bpf_lsm_smoke.rs; it requires `bpf` in the active
        // LSM stack and is gated behind an `NONO_BPF_LSM_TEST=1`
        // env var so it doesn't run on hosts that haven't picked
        // up the AMI change yet.
    }
}

#[cfg(not(all(target_os = "linux", feature = "bpf-lsm")))]
mod imp {
    /// Stub for non-Linux or when the `bpf-lsm` feature is off.
    #[derive(Debug)]
    pub enum BpfLsmError {
        Unsupported,
    }

    impl std::fmt::Display for BpfLsmError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "BPF-LSM is not compiled in (Linux + bpf-lsm feature required)"
            )
        }
    }

    impl std::error::Error for BpfLsmError {}

    /// Placeholder. Always returns false on platforms where
    /// BPF-LSM cannot exist.
    pub fn is_bpf_lsm_available() -> bool {
        false
    }

    /// Placeholder handle for the off-Linux build.
    #[derive(Debug)]
    pub struct ExecFilterHandle;

    pub const MAX_DENY_ENTRIES: usize = 0;

    pub fn install_exec_filter(
        _deny_paths: &[std::path::PathBuf],
        _agent_pid: u32,
    ) -> Result<ExecFilterHandle, BpfLsmError> {
        Err(BpfLsmError::Unsupported)
    }

    #[doc(hidden)]
    pub fn install_exec_filter_no_lsm_check(
        _deny_paths: &[std::path::PathBuf],
        _agent_pid: u32,
    ) -> Result<ExecFilterHandle, BpfLsmError> {
        Err(BpfLsmError::Unsupported)
    }

    pub fn deny_entry_count(_deny_paths: &[std::path::PathBuf]) -> usize {
        0
    }
}

pub use imp::*;
