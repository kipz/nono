# Linux exec filter: command mediation via BPF-LSM

## Summary

Mediate command execution on Linux by attaching a BPF-LSM
program to the kernel's `bprm_check_security` and `file_open`
hooks. The program is scoped to the agent's process tree by
cgroup membership and gates two things:

- **Exec of a mediated binary.** Via `bprm_check_security`,
  which fires after the kernel has resolved the binary the
  call will actually load. Returning `-EACCES` from the BPF
  program atomically aborts the syscall.
- **Read of a mediated binary's bytes.** Via `file_open`, which
  fires on every file open in the agent's tree. Denying these
  reads prevents the agent from copying a mediated binary's
  contents anywhere it could later run from.

A small ring buffer carries audit records to a userspace
reader that appends them to the existing
`~/.nono/sessions/audit.jsonl` log.

This design supersedes a previous seccomp-unotify-based
approach. The seccomp design had two structural weaknesses:
the decision point was in userspace (the broker reading
the path from `/proc/<tid>/mem` and responding to the
kernel), which exposed a TOCTOU race a sibling thread
sharing the trapped task's memory map could exploit; and
seccomp can only intercept syscalls, so indirect-execution
paths that load a binary's code without going through
`execve` (e.g., the dynamic linker invoked directly on the
binary) were invisible. Both weaknesses are addressed here
by moving the decision into the kernel and hooking at LSM
points that fire on the kernel-resolved file rather than on
syscall arguments.

## How it works at a glance

A side-by-side of the per-event flows makes the shift
concrete.

**Previous design — broker decides per event:**

```
Agent calls execve("/usr/bin/gh")
   ↓
Kernel seccomp filter triggers, suspends the calling thread
   ↓
Kernel notifies the broker via the seccomp listener fd
   ↓
Broker reads path from /proc/<tid>/mem, classifies, and
responds (CONTINUE or errno) through the listener fd
   ↓
Kernel resumes the syscall with the broker's verdict
```

Every `execve` in the agent's tree round-trips through
userspace. The broker is the decision-maker. Between
classification and the kernel's eventual action, a sibling
thread can mutate the path the kernel re-reads — that's the
TOCTOU race.

**Current design — kernel decides from a pre-loaded map:**

```
Agent calls execve("/usr/bin/gh")
   ↓
Kernel resolves bprm->file (the actual binary it will load)
   ↓
Kernel reaches bprm_check_security LSM hook
   ↓
BPF program (in the kernel) reads (dev, ino) from
bprm->file, looks it up in the deny map, returns 0 or
-EACCES
   ↓
Kernel acts on the BPF program's return immediately
```

The decision happens in the kernel against state the agent
can't mutate (the kernel-resolved `bprm->file`), in the
same kernel function call as the action. No userspace
round-trip on the hot path. No race.

The broker still has a role, but it's all setup and
observation — never enforcement:

- **Setup, once at session start:** stat each
  `mediation.commands` entry, populate the BPF deny map
  with the resulting `(dev, ino)` pairs, create the
  per-session cgroup and place the agent in it, write the
  cgroup id into the BPF scope map, attach the BPF program
  to the LSM hooks. After this, the broker doesn't touch
  the deny path again for the rest of the session.
- **Observation, in the background:** a polling task
  reads from a BPF ring buffer where the program emits an
  audit record on each event worth logging. The reader
  formats records as `FilterAuditEvent` JSON and appends
  to the existing audit log. This is purely after-the-fact
  reporting; the kernel's decision has already been
  applied by the time the audit reader sees it.
- **Other supervisor duties unchanged:** the broker
  continues to handle the shim IPC for routed commands
  (`capture` / `respond` / `approve`), per-command
  sandbox spawns, the mediation socket, etc. None of
  those features are affected by this work.

### Why BPF-LSM specifically

Three options were considered:

- **Plain seccomp filter (no userspace handler).** BPF runs
  in the kernel and can return ALLOW/DENY/errno based on
  syscall register values. Cannot dereference user pointers
  to read the path. Useless for path- or inode-based
  decisions.
- **Seccomp-unotify (BPF + userspace handler).** The
  approach we're moving away from. Decision happens in
  userspace; sees user-memory pointers; subject to TOCTOU.
  Only intercepts syscalls; can't see kernel-resolved
  state like the binary the kernel actually loads after
  binfmt resolution.
- **BPF-LSM.** BPF runs in the kernel at LSM hook points,
  which fire on semantic kernel events with kernel-resolved
  arguments. Decision is in-kernel, atomic, and against
  state the user can't mutate.

BPF-LSM wins on both axes the seccomp approach failed:
moves the decision out of userspace (closing the TOCTOU
race) and hooks at points that see the kernel's view of
what's about to happen (closing the indirect-execution
bypasses where the agent loads code without traversing
`execve`).

## Problem statement

The mediation feature wants every invocation of a configured
sensitive command (e.g., `gh`, `ddtool`) by the agent to flow
through nono's shim infrastructure, where the broker can
decide whether to capture, rewrite, approve, or deny it.
Bypasses break the security guarantee of the entire
mediation system.

The bypass classes the kernel-side design must close:

1. **Direct path bypass.** Agent invokes the mediated binary
   by absolute path (`/usr/bin/gh ...`) instead of through
   the shim'd PATH lookup. The shim is never involved.
2. **TOCTOU on user-memory paths.** A multithreaded process
   sharing memory with the trapped task swaps the path
   buffer between the supervisor's classification and the
   kernel's actual exec, substituting a denied path the
   supervisor approved. (Includes the vfork-bomb variant
   where the swap thread is in the parent of a vfork
   child.)
3. **Copy the binary.** The agent reads the mediated binary's
   bytes and writes them to a path the operator hasn't
   listed (e.g., `/tmp/my-gh`). The copy has a different
   inode but the same code, so it can do everything the
   original could.
4. **Indirect load via the dynamic linker.** The agent
   invokes the dynamic linker directly with the mediated
   binary as its argument (`/lib/ld-linux-x86-64.so.2
   /usr/bin/gh ...`). The kernel only execs the dynamic
   linker; the linker loads the mediated binary into memory
   itself, never going through `execve`.
5. **Unprivileged tmpfs.** The agent enters a user namespace,
   mounts tmpfs (which it can do unprivilegedly), copies the
   mediated binary's bytes to the tmpfs, and execs the copy
   from there. Same as (3) but with a fresh `dev` as well as
   inode.
6. **Shellcode.** The agent reads the mediated binary's
   bytes, copies them into anonymous memory, marks the page
   `PROT_EXEC`, and jumps to it. No file involvement at
   exec time.

All six are real on Ubuntu's 6.8 HWE kernel and exploitable
under the agent's threat model below.

## Threat model

The agent **can**:

- Read any world-readable file on the host. Mediated binaries
  live in canonical locations (`/usr/bin/gh`, etc.) with mode
  0755; they are world-readable.
- Write to its workspace, `/tmp`, and any path Landlock
  permits write on.
- Compile and execute arbitrary code (compilers and the
  toolchain are available).
- Create unprivileged user namespaces and mount filesystems
  inside them.
- Do anything else POSIX permits an unprivileged user holding
  no capabilities.

The agent **cannot**:

- Modify root-owned files outside Landlock-allowed write
  paths. Mediated binaries are root-owned and outside the
  agent's write set.
- Hold capabilities in its effective set after `execve` —
  the broker sets `PR_SET_NO_NEW_PRIVS=1` on the agent's
  pre-exec, which disables setcap'd file capabilities on
  any binary the agent execs.
- ptrace-attach a process owned by the same user that has
  been marked non-dumpable.
- Forge cryptographic-strength content equivalence.

## Design

### One mechanism, two hooks

The kernel's LSM framework runs registered checks at well-
defined points in syscall paths. Two of those points cover
every way the agent could reach a mediated binary's code:

- **`bprm_check_security`** fires inside `do_execve` after
  the kernel has resolved the target binary into a
  `struct linux_binprm`. By that point, `bprm->file` is the
  `struct file *` the kernel will actually load, with all
  symlinks followed and binfmt resolution (e.g., shebang
  scripts redirected to their interpreter) complete.
  Returning a negative errno from the LSM aborts the exec
  before any user code in the new image runs.
- **`file_open`** fires inside `do_filp_open` for every
  successful path resolution that yields a file descriptor.
  Every `open`, `openat`, exec-time `open_exec`, and the
  open phase of `mmap` flows through it.

A single BPF program keyed on `(dev, ino)` consults a deny
map at both points. At `bprm_check_security` the check
prevents direct execs of mediated binaries (closes the
direct-path bypass). At `file_open` the check prevents the
agent from reading mediated-binary bytes at all, which
closes the copy-the-binary, indirect-load-via-dynamic-
linker, unprivileged-tmpfs, and shellcode bypasses in one
step: each requires reading the mediated binary's bytes
through some `open` call that fires the hook.

The TOCTOU race that motivated moving away from
seccomp-unotify is structurally absent here. Both hooks see
the kernel's resolved `struct file *`, not a user-memory
pointer; there is no value the agent can swap mid-decision.

### Identity model: `(dev, ino)`

The deny map is keyed by `(dev, ino)` of the mediated
binary's underlying inode. At session start the broker
canonicalizes each `mediation.commands` entry, `stat`s it,
and inserts the resulting pair into the BPF map.

Inode identity automatically catches:

- **Hardlinks.** A hardlink shares the underlying inode of
  the original. Same `(dev, ino)`. Caught.
- **Bind mounts.** Bind mounts expose the same inode through
  a different path. Caught.

It does *not* catch separately-installed copies of a
mediated binary at different inodes (e.g., `/usr/bin/gh`
*and* `/usr/local/bin/gh` as distinct files). Listing every
relevant path in `mediation.commands` is the operator's
responsibility, exactly as it was for the seccomp-era
deny set. The runtime path doesn't need to discover copies
on the host because the agent cannot create new copies (the
`file_open` hook denies the read).

This is why content-based identity (hashing the binary's
bytes) is not part of the design. Content-hashing was the
right answer when runtime copies were possible. With
`file_open` denying the read, the agent has no way to put
the mediated binary's bytes anywhere new, so the inode
present at session start is the only identity that matters
at runtime.

### Scoping: per-session cgroup with ancestor walk

The LSM hook is global once attached: it runs on every exec
and every file open *on the host*, not just in the agent's
process tree. Without a scope check the BPF program would
deny mediated-binary reads system-wide, breaking the
broker's own per-command sandbox spawns (which legitimately
exec mediated binaries on the agent's behalf) and any
non-agent process the operator runs.

The broker creates a per-session cgroup at session start
and places the agent in it. Children inherit the cgroup
membership on `fork()`. Two properties of cgroup v2 make
this the right scope primitive:

- **Inherited on fork, unaffected by reparenting.** A
  process that double-forks and gets reparented to init or
  the broker (which is `PR_SET_CHILD_SUBREAPER`) keeps its
  cgroup membership. This is what makes cgroup scoping
  robust against the daemonize bypass that would defeat any
  parent-chain-based identity.
- **Bounded by file ownership.** The agent can move into a
  destination cgroup only if it has write access to that
  cgroup's `cgroup.procs`. All cgroups outside the
  per-session subtree are root-owned; the agent cannot
  escape upward.

The agent *can* create child cgroups *inside* the session
cgroup (the session cgroup directory is owned by the broker
process's uid because `mkdir` runs with that uid even when
`CAP_SYS_ADMIN` is held as a capability). To handle this the
BPF program walks the calling task's cgroup ancestor chain
rather than checking only the immediate cgroup id. If the
session cgroup id appears anywhere among the ancestors, the
task is in the session subtree and the deny check applies.
The agent gains nothing by sub-nesting: the session cgroup
is still in their ancestor chain.

Cgroup namespace virtualization (`unshare(CLONE_NEWCGROUP)`)
doesn't affect this — `bpf_get_current_ancestor_cgroup_id`
returns the kernel's view, not the namespaced view.

### Audit

Mediation events are visible to operators through
`~/.nono/sessions/audit.jsonl`. The BPF program emits an
audit record into a `BPF_MAP_TYPE_RINGBUF` for every event
worth logging:

- A non-shim `bprm_check_security` allow that wasn't shim-
  routed (`allow_unmediated` — agent ran some non-mediated
  binary directly).
- A `bprm_check_security` deny (defense-in-depth case; this
  hook only ever sees a deny inode if `file_open` somehow
  let the open through, which shouldn't happen in normal
  operation).
- A `file_open` deny (the agent attempted to read a mediated
  binary).

The supervisor runs a polling task on the ring buffer fd
that reads each record and appends a JSONL line to
`audit.jsonl`. The output schema is identical in shape to
the existing filter audit format:

```rust
struct FilterAuditEvent {
    command: String,           // basename of the resolved binary
    args: Vec<String>,         // argv without argv[0], when available
    ts: u64,                   // unix seconds
    action_type: String,       // "allow_unmediated" | "deny"
    exit_code: Option<i32>,    // Some(126) on deny, None on allow
    reason: Option<String>,    // "open_deny" | "exec_deny" — only on deny
    path: Option<String>,      // canonical resolved path of the binary
}
```

Compared to the previous seccomp-era schema this drops the
`exec_filter_` prefix on `action_type` (the prefix named the
implementation, not the event), drops the
`interpreter_chain` field (no longer relevant — the kernel
resolves shebang chains internally and the BPF program
sees the actually-loaded binary directly), and drops the
obsolete `reason` values that named seccomp-specific
mechanisms (`multi_threaded_unsafe`, `shebang_chain`,
`post_exec_deny`, `ptrace_seize_failed`). Consumers
dispatching on `action_type` continue to work after a
substring change.

What's intentionally **not** audited:

- `file_open` allows. These fire on every file open in the
  agent's tree — too high-volume to audit, and they don't
  represent a security event.
- Shim-routed exec allows. The shim emits its own audit
  record downstream (`capture` / `respond` / `approve`)
  when the command completes; a kernel-side record would
  double-count. The userspace reader detects shim
  invocations by checking whether `bprm->filename` (the
  path the user passed to `execve`) starts with the
  per-session shim directory prefix and suppresses the
  emit.

### Required deployment invariants

The design's correctness reduces to four invariants. Each
is enforced by existing code or AMI configuration; each is
verifiable at session start, with the supervisor surfacing
a clear error if any fails. There are no silent failure
modes.

**A. `bpf` is in the active LSM stack.** `bprm_check_security`
and `file_open` only invoke BPF programs when the LSM
framework has `bpf` registered. The LSM stack is fixed at
kernel boot from the `lsm=` cmdline parameter; verifiable
via `/sys/kernel/security/lsm`. The workspaces AMI ships a
grub.d drop-in that sets `lsm=...,bpf`. If the host doesn't
have it (e.g., AMI rollout incomplete), the broker fails
session start with an explicit error pointing at the AMI
update — no silent fallback to a known-incomplete
mechanism.

**B. The broker holds `cap_bpf`, `cap_sys_admin`, and
`cap_dac_override`.** Required for: loading the BPF program
(`cap_bpf`); creating the per-session cgroup, which is a
namespace-privileged operation (`cap_sys_admin`); and
passing the VFS DAC check on the cgroup-parent directory
when the parent is root-owned (`cap_dac_override` — the
cgroup `mkdir` goes through normal VFS permission checks
before the cgroup-namespace privilege check, and
`cap_sys_admin` does not subsume DAC). The deployment
configures these via `setcap cap_bpf,cap_sys_admin,
cap_dac_override+ep /usr/bin/nono` at install time.

**C. Per-command-sandbox processes are non-dumpable.** The
broker's per-command sandboxes legitimately read mediated
binaries — that's their whole purpose. After exec, gh's
bytes are in the PCS process's address space. If the PCS
were dumpable, the agent could `ptrace`-attach (same uid +
dumpable suffices for `ptrace_may_access` under the
workspace's `kernel.yama.ptrace_scope=1`) and recover the
bytes from `/proc/<pcs>/mem`. Dumpability is preserved
across `execve` only when `PR_SET_NO_NEW_PRIVS=1` is set
before the exec. Already enforced by nono's per-command
sandbox setup; the broker also asserts `Dumpable: 0` post-
exec at PCS spawn and fails the session if the assertion
doesn't hold.

**D. The agent runs with empty effective capabilities.** The
broker sets `PR_SET_NO_NEW_PRIVS=1` on the agent's pre-exec.
This disables file capabilities at the agent's `execve`,
which prevents the agent from gaining `CAP_SYS_ADMIN` (or
any other capability) by execing a setcap'd binary it
placed in a writable directory. Without this invariant
the agent could escape the cgroup scope check via
`unshare(CLONE_NEWCGROUP)` with sufficient privilege.
Already in place; the agent's session-start log line
includes `CapEff: 0` from `/proc/self/status` as an
explicit assertion.

If any of A–D doesn't hold, the design has a documented
failure mode that the supervisor's startup-time assertion
makes visible. Operators see the failure; the session
either refuses to start or runs with the specific
invariant violated. There is no silent partial enforcement.

### Edge cases

This subsection enumerates non-obvious paths to "the agent
runs the mediated binary's code" and traces each through
the design.

**Hardlink to mediated binary.** Same `(dev, ino)`. Either
hook fires for either path. Closed.

**Bind mount of the mediated binary at a different path.**
Bind mounts share inode through the mountpoint. Either
hook fires. Closed.

**`fexecve` / `execveat` with `O_PATH` fd /
`/proc/self/fd/N`.** All resolve to the same `bprm->file`
inode. Closed.

**Read via `splice` from an open fd.** Requires the open in
the first place; `file_open` denies it. Closed.

**Read from another process's memory via `/proc/<pid>/mem`.**
Requires `ptrace_may_access`, which requires the tracee
to be dumpable. The broker (`PR_SET_DUMPABLE=0`),
per-command sandboxes (Invariant C), and the shim
(`nono-shim` — agent doesn't typically read its memory but
shim doesn't have mediated binary mapped anyway) are all
non-dumpable. Closed.

**Execute via the dynamic linker.** Kernel execs the
linker; the linker calls `open` on the mediated binary;
`file_open` denies. Closed.

**Execute via a custom ELF interpreter (PT_INTERP).** The
custom interpreter has to read the mediated binary's
bytes from somewhere. Either the kernel does it during
`binfmt_elf` setup (which sets `bprm->file` to whatever
the interpreter resolves and fires `bprm_check_security`)
or the userland interpreter calls `open` (which fires
`file_open`). Closed.

**Mount an overlay over the mediated binary's path.**
Requires source bytes for the overlay. Reading the
mediated binary fires `file_open`. Closed.

**`io_uring` `IORING_OP_OPENAT`.** Goes through the same
VFS path; `security_file_open` fires. Closed.

**Read via the kernel's pagecache through `/proc/kcore` or
similar.** Requires `CAP_SYS_RAWIO`, which the agent
doesn't have (Invariant D). Closed.

**Network-side: agent downloads the mediated binary's
bytes from outside the host.** Out of scope for exec
mediation; this is a different threat (network-policy
gap) and a different layer.

**Capability-equivalent: agent reimplements the mediated
binary's logic from scratch.** Not in scope. The exec
filter mediates *identity* of binaries that run; it does
not mediate behavior. An agent that can compile arbitrary
code can in principle replicate any binary's externally
observable behavior. Mediating *that* requires a
syscall-level capability filter, not an exec filter.

### Performance

Per `bprm_check_security` invocation: cgroup-ancestor walk
(~32 ancestor lookups in the worst case, ~8 in practice) +
one map lookup. Roughly 200–400 ns. `bprm_check_security`
fires once per `execve`; a build with 10 000 forks pays
2–4 ms total. Imperceptible.

Per `file_open` invocation: cgroup-ancestor walk + one map
lookup. Same ~200–400 ns. `file_open` fires on every file
open in the agent's tree, so this is the higher-volume
hook. A typical agent task with 1 000 file opens per tick
adds 200–400 µs per tick. Still imperceptible.

Pre-warm at session start: `stat` each `mediation.commands`
entry, populate the BPF map. Roughly one syscall per entry,
microseconds. The agent's `pre_exec` wait absorbs this; it
does not appear as latency to the agent's actual work.

Memory: BPF deny map is ~20 bytes per entry; mediation
profiles list a handful of commands; total <1 KB. Ring
buffer is 64 KiB by default; sized to hold a burst of
audit events without backpressure.

## Deployment requirements

- **Kernel.** Ubuntu 22.04 HWE 6.8 or newer with
  `CONFIG_BPF_LSM=y`. Verifiable via
  `grep bpf_lsm_bprm_check_security /proc/kallsyms`.
- **Active LSM stack.** `lsm=...,bpf` in the kernel cmdline.
  Verifiable via `cat /sys/kernel/security/lsm`.
- **Broker capabilities.** `setcap
  cap_bpf,cap_sys_admin,cap_dac_override+ep /usr/bin/nono`
  applied at install time. The broker drops what it
  doesn't need post-cgroup-create.
- **Profile.** `mediation.commands` lists every canonical
  path of every mediated binary on the host. Deployments
  with multiple installed copies of the same binary list
  all of them (this matched the seccomp-era deny set
  requirement).

## Implementation plan

Phases are sized so each leaves the tree in a buildable,
testable state.

### Phase 1 — drop the seccomp-unotify exec filter

Remove the seccomp filter installed in the agent's
pre-exec (`install_seccomp_exec_filter`), the supervisor
handler (`handle_exec_notification`), the
`multi_threaded_unsafe`/shebang-chain/shim-prefix logic,
and the path-resolution helpers used only by it. The
seccomp filters for `openat` (capability elevation) and
`connect`/`bind` (network proxy) stay — different
features.

After this phase the BPF-LSM hook on
`bprm_check_security` is the only enforcement and the only
audit source. Any host without `bpf` in the active LSM
stack fails session start.

### Phase 2 — `file_open` hook

Add the `lsm/file_open` BPF program with the same
cgroup-ancestor scope check and deny-inode map lookup as
the existing `bprm_check_security` program. Both share one
map.

Tests:
- session denies `cat /usr/bin/gh` from inside the agent
  cgroup, allows it from the broker.
- session denies `/lib/ld-linux-x86-64.so.2 /usr/bin/gh
  ...` (the dynamic linker can't open gh).
- session denies `cp /usr/bin/gh /tmp/copy` (the cp
  syscall's open of `/usr/bin/gh` fails).

### Phase 3 — BPF audit ring buffer

Add a `BPF_MAP_TYPE_RINGBUF` to the BPF program and emit a
record from each hook on the audit-worthy paths. Add a
broker-side polling task that reads the ring buffer,
classifies each record (suppress shim-routed allows),
formats as `FilterAuditEvent`, and appends to the audit
log.

The schema change (drop `exec_filter_` prefix, drop
`interpreter_chain`, new `reason` values) lands in this
phase.

### Phase 4 — invariant assertions

Session-start checks:
- `CapEff` is empty on the agent post-exec.
- `Dumpable: 0` on each per-command sandbox post-exec.
- `bpf` is in the active LSM stack.
- The broker successfully created the session cgroup.

Each assertion logs an explicit `info!` on success or
fails the session with a specific error code on
violation.

### Phase 5 — documentation and rollout

This document becomes the authoritative design doc,
replacing `docs/linux-exec-filter-plan.md`. The decisions
log (`docs/linux-exec-filter-vfork-decisions.md`) stays as
the historical record of how we got here. PR #20's
description is updated to point at the new doc.

## What this design does not address

- **Capability-based mediation.** An agent that can compile
  arbitrary code can reimplement what a mediated binary
  does. Closing that requires syscall-level capability
  filtering, which is a different feature with a different
  deployment shape.
- **Multi-tenant hosts.** The cgroup scope check assumes one
  agent's process tree per session. Concurrent sessions on
  the same host work (each gets its own cgroup) but a
  multi-tenant container shared by multiple agents would
  need additional design work to scope per-agent.
- **macOS.** This document covers Linux only; the macOS
  Seatbelt-based implementation is in a separate design.

## References

- Decisions log:
  `docs/linux-exec-filter-vfork-decisions.md` — chronicles
  the seccomp-unotify iterations, the userspace ptrace
  experiments that didn't work, and the migration to
  BPF-LSM.
- Workspace AMI change:
  dd-source `am/bpf-lsm-workspace-ami` — adds
  `lsm=...,bpf` to the kernel cmdline.
- Kernel docs:
  `Documentation/bpf/bpf_lsm.rst`,
  `Documentation/userspace-api/cgroup-v2.rst`,
  `include/linux/binfmts.h`.
- Mediation profile schema:
  `crates/nono/schema/capability-manifest.schema.json`
  (`mediation.commands`).
