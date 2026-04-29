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
 * binaries) would be denied. We scope by **cgroup ancestry**: the
 * broker creates a per-session cgroup at session start, places the
 * agent in it (children inherit on fork), and writes the cgroup id
 * into the program's scope map. The hook walks current's cgroup
 * ancestor chain via `bpf_get_current_ancestor_cgroup_id()` and
 * applies the deny check whenever the session cgroup id appears at
 * any level above current.
 *
 * Cgroup membership is structural, not parental: it's inherited on
 * fork() and unaffected by reparenting. A task that double-forks
 * and gets reparented to init (or to the broker as
 * PR_SET_CHILD_SUBREAPER) keeps its agent-cgroup membership and
 * still trips the filter — closes the daemonize bypass.
 *
 * Ancestry (not equality) is what closes the sub-cgroup-escape
 * bypass: the agent owns the session cgroup directory (mkdir runs
 * with the broker's uid even when the broker has CAP_SYS_ADMIN),
 * so the agent could `mkdir nono-session-X/sub` and move into it
 * to get a different `bpf_get_current_cgroup_id()`. The ancestor
 * walk catches that — the session cgroup is still in the chain.
 * The agent can't escape *upward* because all parent cgroups are
 * root-owned and the kernel rejects writes to their `cgroup.procs`.
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

/* Maximum cgroup-tree depth the scope ancestor-walk will descend
 * into. Real cgroup trees are usually 4–8 levels (one or two
 * slices, a unit, a session). 64 is a generous cap that's well
 * inside BPF's instruction-count budget after unrolling, and
 * survives an attacker who creates `mkdir`-spam children of the
 * session cgroup. The walker exits early as soon as
 * bpf_get_current_ancestor_cgroup_id returns 0 (level beyond
 * current's depth), so the typical-case cost is ~current_depth
 * iterations, not 64. */
#define MAX_CGROUP_DEPTH 64

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

/* Single-entry config map carrying the agent's cgroup id. The
 * broker writes this immediately after creating the per-session
 * cgroup and adding the agent to it, before signalling the agent
 * to proceed past its pre-exec sync point. A cgroup_id of 0
 * signals "not configured" and causes the program to allow every
 * exec — fail-open is deliberate during setup, so we never deny
 * exec on the not-yet-initialised path. */
struct scope_config {
    __u64 agent_cgroup_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scope_config);
} scope SEC(".maps");

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

    /* Scope: only execs from inside the agent's per-session cgroup
     * (or any descendant of it) are subject to the deny check. */
    __u32 zero = 0;
    struct scope_config *cfg = bpf_map_lookup_elem(&scope, &zero);
    if (!cfg || cfg->agent_cgroup_id == 0) {
        return 0;
    }

    /* Walk current's cgroup-ancestor chain looking for the
     * session cgroup id. Levels are root-down: level 0 is the
     * root cgroup, level == current's depth is current itself,
     * deeper levels return 0. Iterate until we find the session
     * cgroup or run off the end. Bounded loop because the BPF
     * verifier rejects unbounded loops. */
    __u64 agent_cgid = cfg->agent_cgroup_id;
    __u8 in_scope = 0;
    #pragma unroll
    for (int level = 0; level < MAX_CGROUP_DEPTH; level++) {
        __u64 ancestor_cgid = bpf_get_current_ancestor_cgroup_id(level);
        if (ancestor_cgid == 0) {
            /* Past current's depth — no further ancestors. */
            break;
        }
        if (ancestor_cgid == agent_cgid) {
            in_scope = 1;
            break;
        }
    }
    if (!in_scope) {
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
