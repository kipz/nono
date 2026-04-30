//! BPF-LSM mediation filter loader.
//!
//! Loads two LSM hooks that gate access to the mediated binaries
//! the broker lists in `mediation.commands`:
//!
//! - `bprm_check_security` — fires after the kernel has resolved
//!   the binary the call will actually load (`bprm->file`); a
//!   `-EACCES` return atomically aborts the exec.
//! - `file_open` — fires inside `do_filp_open` for every successful
//!   path resolution that yields a file descriptor; denying opens
//!   of mediated inodes prevents the agent from reading the
//!   binary's bytes at all (closes copy-the-binary, dynamic-linker
//!   trick, unprivileged-tmpfs, and shellcode bypasses in one step).
//!
//! Both hooks consult the same `(dev, ino)` deny map. The supervisor
//! populates it at session start by canonicalizing each
//! `mediation.commands` real path, `stat`ing it, and inserting the
//! resulting `(st_dev, st_ino)` pair. Inode identity also covers
//! hardlinks the agent might create at non-deny-set paths to evade
//! a path-based check.
//!
//! Kernel requirements:
//! - `CONFIG_BPF_LSM=y` (Ubuntu 22.04 HWE 6.8 has this; verifiable
//!   via `grep bpf_lsm_bprm_check_security /proc/kallsyms`).
//! - `bpf` in the active LSM stack: `cat /sys/kernel/security/lsm`
//!   must include `bpf`. This is fixed at boot from the `lsm=`
//!   kernel cmdline parameter and cannot be changed at runtime.
//!   The workspaces AMI ships a `/etc/default/grub.d/99-bpf-lsm.cfg`
//!   that adds it (see dd-source `am/bpf-lsm-workspace-ami`).
//! - `CAP_BPF` for the `bpf()` load, `CAP_SYS_ADMIN` for the
//!   per-session cgroup, and `CAP_DAC_OVERRIDE` when the cgroup
//!   parent is root-owned (cgroup v2 `mkdir` checks DAC before
//!   `CAP_SYS_ADMIN`). Recommended:
//!   `setcap cap_bpf,cap_sys_admin,cap_dac_override+ep /usr/bin/nono`.
//!
//! On hosts without `bpf` in the active LSM stack, this loader
//! returns [`BpfLsmError::NotInActiveLsm`] and the broker fails
//! the session at startup with an explicit error pointing at the
//! cmdline / AMI fix. There is no silent partial-enforcement
//! fallback — BPF-LSM is the sole enforcement path for mediated
//! commands.

#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
mod imp {
    use std::os::unix::fs::MetadataExt;

    // Skeleton generated at build time by `libbpf-cargo` from
    // `src/bpf/mediation.bpf.c`. Lives under `OUT_DIR` rather
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
        include!(concat!(env!("OUT_DIR"), "/mediation.skel.rs"));
    }
    use skel::*;

    use std::mem::MaybeUninit;

    use libbpf_rs::skel::{OpenSkel, SkelBuilder};
    use libbpf_rs::{Link, MapCore, MapFlags, OpenObject};

    /// Mirror of the `struct deny_key` declared in
    /// `src/bpf/mediation.bpf.c`. Layout must match exactly.
    #[repr(C)]
    #[derive(Copy, Clone)]
    struct DenyKey {
        dev: u64,
        ino: u64,
    }

    /// Errors specific to BPF-LSM mediation filter installation.
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
        /// `MAX_DENY_ENTRIES` in `mediation.bpf.c`).
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

    /// Live BPF-LSM exec/open filter. Holds the loaded BPF object
    /// and the attached links; dropping the handle detaches the
    /// programs and frees the kernel-side resources.
    pub struct MediationFilterHandle {
        // The skeleton owns the BPF object; we hold both it and
        // the attach links so RAII tears them down in the right
        // order (links first, object second — libbpf-rs's Drop
        // handles ordering when these are stored as separate
        // fields).
        _skel: MediationSkel<'static>,
        _exec_link: Link,
        _open_link: Link,
    }

    impl MediationFilterHandle {
        /// Reference to the audit ring buffer map. The lifetime
        /// is tied to `&self`, so callers must keep this handle
        /// alive while they're using the returned ref (typically
        /// by binding the audit reader and the handle in the
        /// same lexical scope, with the reader declared *after*
        /// the handle so it drops first).
        ///
        /// libbpf-rs's `RingBufferBuilder::build()` only borrows
        /// the map for the duration of `build`; the resulting
        /// `RingBuffer` does not retain a Rust-level borrow of
        /// the map after construction. So after the reader is
        /// built, the map ref's lifetime is effectively
        /// irrelevant — what keeps the underlying map fd alive
        /// is the skeleton this handle owns. The reader's Drop
        /// must run before the handle's Drop or the kernel-side
        /// ring buffer object is freed while polling.
        #[must_use]
        pub fn audit_ringbuf_map(&self) -> &dyn libbpf_rs::MapCore {
            &self._skel.maps.audit_rb
        }
    }

    impl std::fmt::Debug for MediationFilterHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MediationFilterHandle")
                .finish_non_exhaustive()
        }
    }

    /// Compile-time-known maximum number of entries in the
    /// `deny_set` BPF map. Mirrors `MAX_DENY_ENTRIES` in
    /// `src/bpf/mediation.bpf.c`. Bumping this requires a
    /// rebuild.
    pub const MAX_DENY_ENTRIES: usize = 256;

    /// Install the BPF-LSM mediation filter and populate its deny set
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
    pub fn install_mediation_filter(
        deny_paths: &[std::path::PathBuf],
        agent_cgroup_id: u64,
    ) -> Result<MediationFilterHandle, BpfLsmError> {
        if !is_bpf_lsm_available() {
            return Err(BpfLsmError::NotInActiveLsm);
        }
        install_mediation_filter_inner(deny_paths, agent_cgroup_id)
    }

    /// Install the filter without checking
    /// `/sys/kernel/security/lsm`. Exposed for the smoke test to
    /// validate the verifier+load+attach pipeline on hosts that
    /// haven't been rebooted with `lsm=...,bpf` yet. Production
    /// code should always go through [`install_mediation_filter`]
    /// because attaching on a host without `bpf` in the active
    /// LSM stack succeeds but produces no enforcement — the BPF
    /// hook is registered, never fires.
    #[doc(hidden)]
    pub fn install_mediation_filter_no_lsm_check(
        deny_paths: &[std::path::PathBuf],
        agent_cgroup_id: u64,
    ) -> Result<MediationFilterHandle, BpfLsmError> {
        install_mediation_filter_inner(deny_paths, agent_cgroup_id)
    }

    fn install_mediation_filter_inner(
        deny_paths: &[std::path::PathBuf],
        agent_cgroup_id: u64,
    ) -> Result<MediationFilterHandle, BpfLsmError> {
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

        let builder = MediationSkelBuilder::default();
        let open = builder.open(storage)?;
        // The skeleton's `open()` returns an `OpenMediationSkel`
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
        // checks `bpf_get_current_cgroup_id()` against
        // `agent_cgroup_id`; only tasks in the agent's per-session
        // cgroup are subject to the deny check. Cgroup membership
        // is inherited on fork() and unaffected by reparenting, so
        // daemonized agent descendants stay in the agent cgroup
        // and are still filtered. Broker-side per-command sandboxes
        // and unrelated host processes stay in different cgroups
        // and pass through. Setting `agent_cgroup_id = 0` here
        // means "no scoping yet" and causes the program to allow
        // every exec — useful while the broker is mid-setup.
        let scope_map = &skel.maps.scope;
        let scope_key: u32 = 0;
        let scope_val: [u8; 8] = agent_cgroup_id.to_ne_bytes();
        scope_map.update(&scope_key.to_ne_bytes(), &scope_val, MapFlags::ANY)?;

        // Attach both LSM hooks. With `bpf` in the active LSM
        // list, the programs now mediate every exec and every
        // open on the host (subject to the cgroup-scope check).
        // On hosts without `bpf` in the LSM list we'd never reach
        // here — the early `is_bpf_lsm_available` check returned
        // NotInActiveLsm.
        //
        // bprm_check_security closes direct-path execs of mediated
        // binaries. file_open closes the agent reading the binary
        // bytes through any other path (cp /usr/bin/gh /tmp/copy,
        // /lib/ld-linux mediated-bin, mmap copy, ...).
        let exec_link = skel.progs.check_exec.attach()?;
        let open_link = skel.progs.check_file_open.attach()?;

        Ok(MediationFilterHandle {
            _skel: skel,
            _exec_link: exec_link,
            _open_link: open_link,
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

    /// Per-session cgroup that scopes the BPF-LSM filter to the
    /// agent's process tree. Created by [`create_session_cgroup`];
    /// dropped on Drop, which unconditionally `rmdir`s the cgroup
    /// directory (best-effort — empty cgroups remove cleanly,
    /// non-empty fail with EBUSY which is logged and ignored). The
    /// caller is responsible for ensuring the cgroup is empty by
    /// the time it's dropped (typically: agent and all descendants
    /// have exited).
    #[derive(Debug)]
    pub struct SessionCgroup {
        path: std::path::PathBuf,
        cgroup_id: u64,
    }

    impl SessionCgroup {
        /// Numeric cgroup id (cgroup directory inode in v2). This
        /// is what `bpf_get_current_cgroup_id()` returns inside the
        /// BPF program, and what gets written into the scope map.
        #[must_use]
        pub fn cgroup_id(&self) -> u64 {
            self.cgroup_id
        }

        /// Filesystem path of the cgroup directory (`/sys/fs/cgroup/...`).
        /// Exposed for diagnostics; production callers should not
        /// poke at this directly.
        #[must_use]
        pub fn path(&self) -> &std::path::Path {
            &self.path
        }

        /// Place `pid` in this cgroup. Cgroup membership inherits
        /// on `fork()`, so children of the moved task automatically
        /// join the cgroup. Used by the broker post-fork in the
        /// child path: the child writes its own pid as the first
        /// action so all subsequent execs are scoped.
        ///
        /// Errors are bubbled as `io::Error` from the underlying
        /// `write` to `cgroup.procs` — typical failures are
        /// `EACCES` (cgroup write permission) or `ESRCH` (the
        /// target task has exited).
        pub fn add_pid(&self, pid: u32) -> std::io::Result<()> {
            let procs_path = self.path.join("cgroup.procs");
            std::fs::write(&procs_path, format!("{}\n", pid))
        }
    }

    impl Drop for SessionCgroup {
        fn drop(&mut self) {
            // cgroup v2 won't let us rmdir a non-empty cgroup
            // (EBUSY). Best-effort: read cgroup.procs and migrate
            // each pid back to the parent cgroup so the directory
            // can be removed. Bounded loop because forks can
            // populate the cgroup between our read and the
            // migrate, and we don't want a runaway here on a
            // misbehaving session.
            let parent = match self.path.parent() {
                Some(p) => p.to_path_buf(),
                None => return,
            };
            let parent_procs = parent.join("cgroup.procs");
            let our_procs = self.path.join("cgroup.procs");
            for _ in 0..16 {
                let pids: Vec<String> = match std::fs::read_to_string(&our_procs) {
                    Ok(s) => s
                        .lines()
                        .map(String::from)
                        .filter(|l| !l.is_empty())
                        .collect(),
                    Err(_) => break,
                };
                if pids.is_empty() {
                    break;
                }
                for pid in pids {
                    // Writes to cgroup.procs accept one pid per
                    // call. Most failures here are ESRCH (the
                    // task has since exited) — also fine, the
                    // empty cgroup is what we want.
                    let _ = std::fs::write(&parent_procs, format!("{}\n", pid));
                }
            }
            // Empty cgroups remove cleanly. Anything left at this
            // point is a real bug worth a debug log but not worth
            // panicking — the cgroup directory will be cleaned
            // up on host reboot in the worst case.
            if let Err(e) = std::fs::remove_dir(&self.path) {
                tracing::debug!(
                    "SessionCgroup::drop: rmdir({}) failed: {} \
                     (cgroup may have lingering tasks)",
                    self.path.display(),
                    e
                );
            }
        }
    }

    /// Errors specific to per-session cgroup creation.
    #[derive(Debug)]
    pub enum CgroupError {
        /// `/proc/self/cgroup` couldn't be read or didn't have the
        /// expected single-entry cgroup-v2 line. Possibly running
        /// on a kernel without cgroup-v2 unified hierarchy, or in
        /// a container with a non-standard cgroup mount.
        ReadProcSelfCgroup(std::io::Error),
        /// `/proc/self/cgroup`'s output wasn't recognisable cgroup
        /// v2 (single line of the form `0::/path`). Most commonly
        /// this means the system is on cgroup v1.
        UnrecognisedCgroupFormat(String),
        /// `mkdir` of the per-session cgroup directory failed.
        /// Usually `EACCES` because the parent cgroup is
        /// root-owned and the calling process has no
        /// `CAP_SYS_ADMIN`. The deployment story for nono with
        /// BPF-LSM requires either running as root, having
        /// `cap_sys_admin+ep` set on the binary, or running under
        /// a systemd unit with `Delegate=yes` so the user gets a
        /// writable cgroup.
        CreateCgroup {
            path: std::path::PathBuf,
            error: std::io::Error,
        },
        /// Writing the agent's pid to `cgroup.procs` failed.
        AddProcToCgroup {
            path: std::path::PathBuf,
            error: std::io::Error,
        },
        /// `stat` on the cgroup directory failed (used to derive
        /// the cgroup_id from the directory inode).
        StatCgroup {
            path: std::path::PathBuf,
            error: std::io::Error,
        },
    }

    impl std::fmt::Display for CgroupError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::ReadProcSelfCgroup(e) => {
                    write!(f, "could not read /proc/self/cgroup: {e}")
                }
                Self::UnrecognisedCgroupFormat(s) => {
                    write!(f, "unrecognised /proc/self/cgroup format: {s:?}")
                }
                Self::CreateCgroup { path, error } => {
                    write!(
                        f,
                        "mkdir({}) failed: {} \
                              (CAP_SYS_ADMIN or cgroup delegation required)",
                        path.display(),
                        error
                    )
                }
                Self::AddProcToCgroup { path, error } => {
                    write!(
                        f,
                        "write to {}/cgroup.procs failed: {}",
                        path.display(),
                        error
                    )
                }
                Self::StatCgroup { path, error } => {
                    write!(f, "stat({}) failed: {}", path.display(), error)
                }
            }
        }
    }

    impl std::error::Error for CgroupError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            match self {
                Self::ReadProcSelfCgroup(e) => Some(e),
                Self::CreateCgroup { error, .. }
                | Self::AddProcToCgroup { error, .. }
                | Self::StatCgroup { error, .. } => Some(error),
                Self::UnrecognisedCgroupFormat(_) => None,
            }
        }
    }

    /// Create a per-session cgroup as a child of the calling
    /// process's current cgroup, without placing any pids in it.
    /// Use [`SessionCgroup::add_pid`] to add tasks afterwards.
    ///
    /// Naming: the cgroup directory is named
    /// `nono-session-<broker-pid>` so concurrent nono sessions on
    /// the same host don't collide.
    ///
    /// Splitting create-dir from add-pid lets the broker mkdir the
    /// cgroup *before* `fork()` (so BPF-LSM can be installed with
    /// scope = cgroup_id pre-fork) and have the child join the
    /// cgroup as its first post-fork action. With this ordering,
    /// the agent never has a chance to `execve` outside the
    /// session cgroup's scope.
    ///
    /// Caveats:
    /// - Requires write access to the parent cgroup directory and
    ///   `CAP_SYS_ADMIN` over the cgroup namespace. On bare `/init`
    ///   (Docker default), the parent cgroup is root-owned, so
    ///   `CAP_DAC_OVERRIDE` is required as well — `setcap
    ///   cap_bpf,cap_sys_admin,cap_dac_override+ep`.
    pub fn create_session_cgroup_empty() -> Result<SessionCgroup, CgroupError> {
        use std::os::unix::fs::MetadataExt;

        let proc_self = std::fs::read_to_string("/proc/self/cgroup")
            .map_err(CgroupError::ReadProcSelfCgroup)?;
        let parent_path = proc_self
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("0::"))
            .map(str::trim)
            .ok_or_else(|| CgroupError::UnrecognisedCgroupFormat(proc_self.clone()))?;
        let cgroup_root = std::path::PathBuf::from("/sys/fs/cgroup");
        let parent_dir = if parent_path == "/" {
            cgroup_root
        } else {
            cgroup_root.join(parent_path.trim_start_matches('/'))
        };
        let session_dir = parent_dir.join(format!("nono-session-{}", std::process::id()));

        std::fs::create_dir(&session_dir).map_err(|e| CgroupError::CreateCgroup {
            path: session_dir.clone(),
            error: e,
        })?;

        let meta = std::fs::metadata(&session_dir).map_err(|e| CgroupError::StatCgroup {
            path: session_dir.clone(),
            error: e,
        })?;
        // In cgroup v2 the cgroup_id is the directory's inode —
        // bpf_get_current_cgroup_id() returns that same value.
        let cgroup_id = meta.ino();

        Ok(SessionCgroup {
            path: session_dir,
            cgroup_id,
        })
    }

    /// Create the session cgroup *and* place `agent_pid` in it.
    /// Convenience for tests and call sites that don't need the
    /// pre-fork install ordering.
    pub fn create_session_cgroup(agent_pid: u32) -> Result<SessionCgroup, CgroupError> {
        let cgroup = create_session_cgroup_empty()?;
        cgroup
            .add_pid(agent_pid)
            .map_err(|e| CgroupError::AddProcToCgroup {
                path: cgroup.path.clone(),
                error: e,
            })?;
        Ok(cgroup)
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

        // The actual install_mediation_filter() test lives under
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
    pub struct MediationFilterHandle;

    pub const MAX_DENY_ENTRIES: usize = 0;

    pub fn install_mediation_filter(
        _deny_paths: &[std::path::PathBuf],
        _agent_cgroup_id: u64,
    ) -> Result<MediationFilterHandle, BpfLsmError> {
        Err(BpfLsmError::Unsupported)
    }

    #[doc(hidden)]
    pub fn install_mediation_filter_no_lsm_check(
        _deny_paths: &[std::path::PathBuf],
        _agent_cgroup_id: u64,
    ) -> Result<MediationFilterHandle, BpfLsmError> {
        Err(BpfLsmError::Unsupported)
    }

    pub fn deny_entry_count(_deny_paths: &[std::path::PathBuf]) -> usize {
        0
    }

    /// Stub for non-Linux. Same shape as the real one so callers
    /// don't need cfg-gates around the type.
    #[derive(Debug)]
    pub struct SessionCgroup;

    impl SessionCgroup {
        #[must_use]
        pub fn cgroup_id(&self) -> u64 {
            0
        }

        #[must_use]
        pub fn path(&self) -> &std::path::Path {
            std::path::Path::new("")
        }

        pub fn add_pid(&self, _pid: u32) -> std::io::Result<()> {
            Err(std::io::Error::other(
                "cgroup-based scoping is not supported on this platform",
            ))
        }
    }

    /// Stub error type for non-Linux. The variants list is empty
    /// (this is unreachable) but the type exists for cfg
    /// symmetry.
    #[derive(Debug)]
    pub enum CgroupError {
        Unsupported,
    }

    impl std::fmt::Display for CgroupError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "cgroup-based scoping is not supported on this platform")
        }
    }

    impl std::error::Error for CgroupError {}

    pub fn create_session_cgroup(_agent_pid: u32) -> Result<SessionCgroup, CgroupError> {
        Err(CgroupError::Unsupported)
    }

    pub fn create_session_cgroup_empty() -> Result<SessionCgroup, CgroupError> {
        Err(CgroupError::Unsupported)
    }
}

pub use imp::*;
