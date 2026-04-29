//! Userspace audit reader for the BPF-LSM exec/open filter.
//!
//! The BPF program writes one [`AuditRecord`] per audit-worthy event
//! into a `BPF_MAP_TYPE_RINGBUF`. This module starts a background
//! poll loop that decodes records, formats them as
//! [`crate::sandbox::FilterAuditEvent`]-shaped JSONL lines, and
//! appends to `<audit_log_dir>/audit.jsonl` — the same file the
//! mediation shim writes its own audit events to.
//!
//! Lifecycle:
//! - [`AuditReader::start`] takes the skeleton's ring buffer map and
//!   the destination directory, spawns a polling thread, returns a
//!   handle that on Drop signals the thread to stop and joins.
//! - The thread polls with a small timeout and a shutdown flag;
//!   shutdown signals the loop to exit on the next tick.
//! - Records are best-effort: the BPF side already emitted before
//!   the kernel applied the verdict, so a failed audit write here
//!   does not affect enforcement. We log at debug-level on errors.
//!
//! Schema (Rust mirror of `struct audit_record` in
//! `src/bpf/exec_filter.bpf.c` — keep in sync):

#![cfg(all(target_os = "linux", feature = "bpf-lsm"))]

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use libbpf_rs::{MapCore, RingBufferBuilder};
use serde::{Deserialize, Serialize};

/// Source enum mirror — keep in sync with `AUDIT_SRC_*` in the BPF
/// program.
const SRC_BPRM: u8 = 0;

/// Verdict enum mirror.
const VERDICT_ALLOW: u8 = 0;
const VERDICT_DENY: u8 = 1;

/// Reason enum mirror.
const REASON_NONE: u8 = 0;
const REASON_EXEC_DENY: u8 = 1;
const REASON_OPEN_DENY: u8 = 2;

/// On-disk JSONL audit event. Mirrors the shape of
/// `crate::mediation::filter_audit::FilterAuditEvent` over in
/// `nono-cli`, but lives in the library because the audit reader
/// runs in the library's BPF code path. Serialised fields match
/// the legacy seccomp-era schema (Phase 3 schema): `action_type`
/// is one of `"allow_unmediated"` / `"deny"`; `reason` is
/// `"exec_deny"` / `"open_deny"` (only on deny).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterAuditEvent {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub ts: u64,
    pub action_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Wire-layout mirror of the BPF `struct audit_record`. Bytes
/// flow from the kernel's ring buffer to here unaltered. Layout
/// must match exactly — the BPF program reads/writes using
/// in-kernel C struct layout, so the Rust side is `#[repr(C)]`
/// with the same field order and padding.
///
/// Path resolution is userspace-side: the BPF program emits
/// (dev, ino) and the reader maps that to a canonical path via
/// the broker's deny set table.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct AuditRecord {
    ts_ns: u64,
    source: u8,
    verdict: u8,
    reason: u8,
    _pad: u8,
    pid: u32,
    dev: u64,
    ino: u64,
}

const AUDIT_RECORD_SIZE: usize = std::mem::size_of::<AuditRecord>();

/// Background ring-buffer reader. Drop signals the thread to stop
/// and joins it; the thread is bounded (no work after stop is
/// signalled), so Drop returns promptly.
pub struct AuditReader {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AuditReader {
    /// Start a polling task on the ring buffer. The map must be
    /// the `audit_rb` map from a loaded `ExecFilterSkel`; passing
    /// any other map type yields a [`libbpf_rs::Error`] from the
    /// builder.
    ///
    /// `audit_log_dir` is the directory where `audit.jsonl` lives
    /// (typically `~/.nono/sessions`). Created if missing; events
    /// are appended one JSON line at a time.
    ///
    /// `inode_to_path` lets the reader resolve a record's
    /// (dev, ino) pair back to the canonical path. The broker
    /// builds this from the `mediation.commands` deny set.
    /// Records whose (dev, ino) is unknown to the table get a
    /// `None` path field — typical for `allow_unmediated`
    /// records, where the agent ran a non-mediated binary that
    /// the broker doesn't have a path for.
    ///
    /// `shim_dir` is the per-session shim directory; if a `bprm`
    /// audit record's resolved path starts with this prefix, the
    /// event is suppressed (the shim emits its own downstream
    /// audit record). `None` disables the suppression.
    ///
    /// The map borrow is consumed by `RingBufferBuilder::build()`;
    /// the returned `AuditReader` does not retain a Rust-level
    /// reference to the map. What keeps the underlying ring
    /// buffer fd alive at runtime is whoever owns the BPF
    /// skeleton (callers must drop the audit reader before that
    /// owner drops, or the kernel-side ring buffer will be freed
    /// while the polling thread is still running).
    pub fn start(
        map: &dyn MapCore,
        audit_log_dir: PathBuf,
        shim_dir: Option<PathBuf>,
        inode_to_path: std::collections::HashMap<(u64, u64), PathBuf>,
    ) -> Result<Self, libbpf_rs::Error> {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let log_file = Arc::new(Mutex::new(open_audit_log(&audit_log_dir)));

        let thread_log = Arc::clone(&log_file);
        let thread_shim_dir = shim_dir;
        let thread_inode_to_path = Arc::new(inode_to_path);
        let cb_inode_to_path = Arc::clone(&thread_inode_to_path);

        let mut builder = RingBufferBuilder::new();
        builder.add(map, move |bytes: &[u8]| {
            handle_record(
                bytes,
                &thread_log,
                thread_shim_dir.as_deref(),
                &cb_inode_to_path,
            );
            0
        })?;
        let rb = builder.build()?;

        let thread = std::thread::Builder::new()
            .name("nono-audit".to_string())
            .spawn(move || {
                while !stop_for_thread.load(Ordering::Relaxed) {
                    // poll() with a small timeout so we check the
                    // stop flag promptly. Errors propagate up to a
                    // debug log; not fatal — failing audit reads
                    // don't affect kernel-side enforcement.
                    if let Err(e) = rb.poll(Duration::from_millis(100)) {
                        tracing::debug!("audit ringbuf poll: {}", e);
                    }
                }
            })
            .map_err(|e| libbpf_rs::Error::from(std::io::Error::other(e)))?;

        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for AuditReader {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            // Bounded join: the polling thread checks `stop` every
            // poll-tick, so this returns within the poll timeout
            // (100ms by default).
            let _ = handle.join();
        }
    }
}

/// Open `<dir>/audit.jsonl` for append. Creates parent dir if
/// missing. Returned `Option` lets the polling thread carry on
/// after a setup failure: subsequent records will silently drop
/// because there's nowhere to write them.
fn open_audit_log(dir: &Path) -> Option<std::fs::File> {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::debug!("audit reader: mkdir {} failed: {}", dir.display(), e);
        return None;
    }
    let path = dir.join("audit.jsonl");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::debug!("audit reader: open {} failed: {}", path.display(), e);
            None
        }
    }
}

/// Decode one record's bytes and append a JSONL line. Best-effort:
/// any failure (truncated record, unknown enum value, write error)
/// becomes a debug log and the record is dropped.
fn handle_record(
    bytes: &[u8],
    log: &Mutex<Option<std::fs::File>>,
    shim_dir: Option<&Path>,
    inode_to_path: &std::collections::HashMap<(u64, u64), PathBuf>,
) {
    if bytes.len() < AUDIT_RECORD_SIZE {
        tracing::debug!(
            "audit ringbuf: short record ({} bytes < {})",
            bytes.len(),
            AUDIT_RECORD_SIZE
        );
        return;
    }
    // SAFETY: ringbuf delivers fixed-size records that the BPF
    // program reserved as `sizeof(struct audit_record)`. The Rust
    // mirror has identical layout (#[repr(C)]). bytes' length is
    // checked above. We copy out by `read_unaligned` to avoid any
    // alignment assumption on the kernel-side reservation.
    let raw_record: AuditRecord =
        unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<AuditRecord>()) };

    // Resolve (dev, ino) → canonical path via the broker's deny
    // set table. `None` means the agent ran something the broker
    // doesn't know about (typical for allow_unmediated events).
    let resolved_path = inode_to_path
        .get(&(raw_record.dev, raw_record.ino))
        .cloned();
    let path_str = resolved_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default();

    // Suppress shim-routed bprm allows: the shim emits its own
    // post-completion audit record, and a kernel-side `allow` here
    // would double-count.
    if raw_record.source == SRC_BPRM
        && raw_record.verdict == VERDICT_ALLOW
        && shim_dir
            .map(|sd| !path_str.is_empty() && Path::new(&path_str).starts_with(sd))
            .unwrap_or(false)
    {
        return;
    }

    let action_type = match raw_record.verdict {
        VERDICT_ALLOW => "allow_unmediated",
        VERDICT_DENY => "deny",
        _ => return,
    };

    let reason = match raw_record.reason {
        REASON_EXEC_DENY => Some("exec_deny".to_string()),
        REASON_OPEN_DENY => Some("open_deny".to_string()),
        REASON_NONE => None,
        _ => None,
    };

    let exit_code = if raw_record.verdict == VERDICT_DENY {
        Some(126)
    } else {
        None
    };

    let command = resolved_path
        .as_deref()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();

    let event = FilterAuditEvent {
        command,
        args: Vec::new(),
        ts: ts_seconds_from_kernel_boot_ns(raw_record.ts_ns),
        action_type: action_type.to_string(),
        exit_code,
        reason,
        path: if path_str.is_empty() {
            None
        } else {
            Some(path_str)
        },
    };

    if let Ok(line) = serde_json::to_string(&event) {
        let mut guard = match log.lock() {
            Ok(g) => g,
            Err(_) => {
                tracing::debug!("audit reader: log mutex poisoned");
                return;
            }
        };
        if let Some(file) = guard.as_mut() {
            if let Err(e) = writeln!(file, "{line}") {
                tracing::debug!("audit reader: write {} failed: {}", line, e);
            }
        }
    }
}

/// Convert a kernel-boot-relative ns timestamp to a unix-seconds
/// timestamp by adding the system's wall-clock offset.
///
/// `bpf_ktime_get_ns` returns nanoseconds since boot, not a wall
/// clock. Userspace approximates the wall-clock value by reading
/// `CLOCK_REALTIME` once and computing the delta from the current
/// `CLOCK_BOOTTIME`. We use a one-off best-effort calculation per
/// call — drift over a session is small and we don't need
/// strictly monotonic alignment with shim audit events.
fn ts_seconds_from_kernel_boot_ns(boot_ns: u64) -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime takes a mutable pointer to a
    // pre-allocated timespec. Standard C API.
    let ok = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    let now_boot_ns = if ok == 0 {
        (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
    } else {
        // Fallback: just truncate the ns value to seconds. Better
        // than panicking; the consumer can correlate with other
        // events by ts-ordering.
        return boot_ns / 1_000_000_000;
    };
    let now_wall_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let elapsed_s_since_event = now_boot_ns.saturating_sub(boot_ns) / 1_000_000_000;
    now_wall_s.saturating_sub(elapsed_s_since_event)
}
