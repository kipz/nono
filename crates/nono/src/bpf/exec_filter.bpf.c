/* SPDX-License-Identifier: GPL-2.0 */
/*
 * exec_filter.bpf.c - BPF-LSM exec filter for nono mediation.
 *
 * Closes the seccomp-unotify TOCTOU bypass on the mediation shim by
 * mediating exec inside the kernel via the bprm_check_security LSM
 * hook. The hook fires after the kernel has resolved the binary
 * (`bprm->file` is the file the kernel will actually load) and
 * before exec is committed; returning -EACCES atomically aborts the
 * syscall, with no race against any user-memory pointer the agent
 * controlled.
 *
 * The deny set is keyed by (dev, ino) instead of path. The
 * supervisor populates it at session start by stat()ing each
 * canonical real path of `mediation.commands`. Matching by inode
 * also covers hardlinks of a deny-set binary that the agent might
 * create at non-deny-set paths to evade a path-based check.
 *
 * Per-session scoping
 * -------------------
 * The LSM hook is global once attached: every exec on the host is
 * fed through this program. Without scoping, the broker's own
 * per-command sandbox spawns (which legitimately exec mediated
 * binaries) would be denied. We scope by walking each task's
 * `real_parent` chain looking for the agent root pid the broker
 * registered at session start. Only execs from inside the agent's
 * process tree get the deny check; everything else (broker
 * children, user shells outside nono, system services, …) passes
 * through.
 *
 * Residual: a task that daemonizes (double-fork + reparent to
 * init) loses its parent-chain link to the agent, so a
 * daemonized descendant can exec a deny-set binary without being
 * caught. Agents in scope (claude, codex, etc.) don't daemonize
 * themselves; documented as a known hole, fixable later by
 * cgroup-based scoping.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EACCES 13

/* Maximum mediated commands per session. mediation.commands lists
 * are typically a handful (gh, ddtool, kubectl, ...); 256 leaves
 * generous headroom and bounds map memory. */
#define MAX_DENY_ENTRIES 256

/* Maximum depth the parent-chain scope walker will descend. Real
 * agent process trees are usually 5–15 levels deep (shell →
 * subshell → tool → tool's helpers); 32 leaves margin and is well
 * under the BPF instruction-count budget. */
#define MAX_PARENT_DEPTH 32

char LICENSE[] SEC("license") = "GPL";

/* Identity key for a binary's underlying inode. */
struct deny_key {
    __u64 dev;
    __u64 ino;
};

/* Deny set map. Userspace inserts one entry per mediated command
 * canonical path; value is `1` (presence is what matters, the byte
 * is just a non-zero marker). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_ENTRIES);
    __type(key, struct deny_key);
    __type(value, __u8);
} deny_set SEC(".maps");

/* Single-entry config map carrying the agent's root pid. The
 * broker writes this immediately after `fork()` returns the
 * agent's pid, before signalling the agent to proceed past its
 * pre-exec sync point. A pid of 0 signals "not configured" and
 * causes the program to allow every exec — fail-open is
 * deliberate during setup, so we never deny exec on the
 * not-yet-initialised path. */
struct scope_config {
    __u32 agent_pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scope_config);
} scope SEC(".maps");

/* Walk `current`'s `real_parent` chain looking for `target_pid`.
 * Returns 1 if found within MAX_PARENT_DEPTH ancestors, 0
 * otherwise. The bound is required by the BPF verifier (no
 * unbounded loops) and is also a soft DoS guard — a pathological
 * deeply nested process tree can't hang the LSM hook. */
static __always_inline int has_ancestor_pid(__u32 target_pid)
{
    if (target_pid == 0) {
        return 0;
    }

    struct task_struct *task = bpf_get_current_task_btf();

    #pragma unroll
    for (int i = 0; i < MAX_PARENT_DEPTH; i++) {
        if (!task) {
            return 0;
        }
        __u32 tgid = BPF_CORE_READ(task, tgid);
        if (tgid == target_pid) {
            return 1;
        }
        /* init's pid is 1; once we reach it the chain has no
         * more useful ancestors (init's real_parent is init
         * itself in some kernels, NULL in others). */
        if (tgid == 1) {
            return 0;
        }
        task = BPF_CORE_READ(task, real_parent);
    }
    return 0;
}

/* LSM hook for exec.
 *
 * Signature: int bprm_check_security(struct linux_binprm *bprm)
 * — `ret` is the accumulated return value from earlier LSMs in the
 * stack; with `lsm=...,bpf` (bpf last) `ret == 0` means every prior
 * LSM allowed the exec.
 *
 * Returning a negative errno aborts the exec with that errno;
 * returning 0 lets the kernel proceed. We propagate `ret` for any
 * non-zero value other than our own deny so we don't override an
 * earlier LSM's verdict.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm, int ret)
{
    /* If a prior LSM has already denied, propagate. */
    if (ret != 0) {
        return ret;
    }

    /* Scope: only execs from inside the agent's process tree are
     * subject to the deny check. */
    __u32 zero = 0;
    struct scope_config *cfg = bpf_map_lookup_elem(&scope, &zero);
    if (!cfg || cfg->agent_pid == 0) {
        return 0;
    }
    if (!has_ancestor_pid(cfg->agent_pid)) {
        return 0;
    }

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file) {
        return 0;
    }

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode) {
        return 0;
    }

    struct deny_key key = {};
    key.ino = BPF_CORE_READ(inode, i_ino);
    key.dev = BPF_CORE_READ(inode, i_sb, s_dev);

    __u8 *val = bpf_map_lookup_elem(&deny_set, &key);
    if (val) {
        return -EACCES;
    }

    return 0;
}
