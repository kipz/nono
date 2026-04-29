/* SPDX-License-Identifier: GPL-2.0 */
/*
 * exec_filter.bpf.c - BPF-LSM exec + open filter for nono mediation.
 *
 * Two LSM hooks consult a single (dev, ino) deny map and a shared
 * cgroup-ancestor scope check:
 *
 *   bprm_check_security  Fires after the kernel has resolved the
 *                        binary the call will actually load
 *                        (`bprm->file`). Returning -EACCES atomically
 *                        aborts the exec syscall, with no race
 *                        against any user-memory pointer the agent
 *                        controlled. Closes direct-path mediated-
 *                        binary execs.
 *
 *   file_open            Fires on every successful path resolution
 *                        that yields a file descriptor. Denying open
 *                        of a deny-set inode prevents the agent from
 *                        reading the mediated binary's bytes at all,
 *                        which closes copy-the-binary, dynamic-linker
 *                        trick, unprivileged-tmpfs, and shellcode
 *                        bypasses in one step (each of those needs
 *                        an open of the mediated binary somewhere).
 *
 * Identity model: (dev, ino) of the underlying inode. Userspace
 * stat()s each canonical real path in `mediation.commands` and
 * inserts the result. Inode identity catches hardlinks of a
 * mediated binary at non-deny-set paths automatically.
 *
 * Per-session scoping
 * -------------------
 * The LSM hooks are global once attached: every exec/open on the
 * host is fed through the program. Without scoping, mediated-
 * binary access would be denied system-wide, breaking the broker's
 * own per-command sandbox spawns and any non-agent process the
 * operator runs.
 *
 * Scope by cgroup ancestry: the broker creates a per-session
 * cgroup, the agent joins it post-fork (children inherit on
 * fork), and the cgroup id is written into the program's scope
 * map. Each hook walks current's cgroup ancestor chain looking
 * for the session cgroup id; if found, the deny check applies.
 *
 * Cgroup membership is structural, not parental: it's inherited
 * on fork() and unaffected by reparenting (closes the daemonize
 * bypass). Using ancestry rather than equality also closes the
 * sub-cgroup-escape: an agent that mkdirs a child cgroup of the
 * session and moves into it still has the session cgroup in its
 * ancestor chain.
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
 * into. Real cgroup trees are usually 4–8 levels. 64 is a generous
 * cap inside BPF's instruction-count budget. The walker exits
 * early when bpf_get_current_ancestor_cgroup_id returns 0 (level
 * beyond current's depth), so typical-case cost is ~current_depth
 * iterations. */
#define MAX_CGROUP_DEPTH 64

char LICENSE[] SEC("license") = "GPL";

/* Identity key for a binary's underlying inode. */
struct deny_key {
    __u64 dev;
    __u64 ino;
};

/* Deny set map. Userspace inserts one entry per mediated command
 * canonical path; value is `1` (presence is what matters). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_DENY_ENTRIES);
    __type(key, struct deny_key);
    __type(value, __u8);
} deny_set SEC(".maps");

/* Single-entry config map carrying the agent's cgroup id. A value
 * of 0 means "not configured" and causes the program to allow
 * every event — fail-open is deliberate during setup, so we never
 * deny on the not-yet-initialised path. */
struct scope_config {
    __u64 agent_cgroup_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct scope_config);
} scope SEC(".maps");

/* Returns 1 if current task is in (or descended from) the session
 * cgroup, else 0. Bounded loop satisfies the BPF verifier;
 * bpf_get_current_ancestor_cgroup_id returns 0 past current's
 * depth so the loop exits early in practice. */
static __always_inline int in_session_cgroup(void)
{
    __u32 zero = 0;
    struct scope_config *cfg = bpf_map_lookup_elem(&scope, &zero);
    if (!cfg || cfg->agent_cgroup_id == 0) {
        return 0;
    }
    __u64 agent_cgid = cfg->agent_cgroup_id;
    #pragma unroll
    for (int level = 0; level < MAX_CGROUP_DEPTH; level++) {
        __u64 ancestor_cgid = bpf_get_current_ancestor_cgroup_id(level);
        if (ancestor_cgid == 0) {
            break;
        }
        if (ancestor_cgid == agent_cgid) {
            return 1;
        }
    }
    return 0;
}

/* Returns 1 if `file`'s (dev, ino) is in the deny set, else 0. */
static __always_inline int file_in_deny_set(struct file *file)
{
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
    return val ? 1 : 0;
}

/* LSM hook for exec.
 *
 * Returning a negative errno aborts the exec with that errno;
 * returning 0 lets the kernel proceed. Propagate `ret` for any
 * non-zero value other than our own deny so we don't override an
 * earlier LSM's verdict.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(check_exec, struct linux_binprm *bprm, int ret)
{
    if (ret != 0) {
        return ret;
    }
    if (!in_session_cgroup()) {
        return 0;
    }
    struct file *file = BPF_CORE_READ(bprm, file);
    if (file_in_deny_set(file)) {
        return -EACCES;
    }
    return 0;
}

/* LSM hook for file open.
 *
 * Fires inside `do_filp_open` for every successful path resolution
 * that yields a file descriptor — every `open`, `openat`,
 * `openat2`, exec-time `open_exec`, and the open phase of `mmap`
 * (when MAP_PRIVATE/MAP_SHARED) flow through it. Denying reads of
 * deny-set inodes cuts off every code path the agent could use to
 * get the mediated binary's bytes into its address space.
 *
 * `ret` is the accumulated return value from earlier LSMs in the
 * stack. Propagate any non-zero ret unchanged (don't override a
 * prior LSM's verdict).
 */
SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file, int ret)
{
    if (ret != 0) {
        return ret;
    }
    if (!in_session_cgroup()) {
        return 0;
    }
    if (file_in_deny_set(file)) {
        return -EACCES;
    }
    return 0;
}
