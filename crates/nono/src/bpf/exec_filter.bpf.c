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
