# Linux command mediation via BPF-LSM

> **Note on naming:** earlier drafts of this document used the term
> "exec filter" (inherited from the seccomp-unotify approach this work
> replaced). The current implementation mediates both exec
> (`bprm_check_security`) and file reads (`file_open`) of mediated
> binaries, so the code uses the broader term "mediation filter".
> The "exec filter" framing in the implementation-plan sections below
> predates that rename; current code uses `install_mediation_filter` /
> `MediationFilterHandle` / `src/bpf/mediation.bpf.c`.

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

This section is written for an engineer (human or AI agent)
picking the work up cold. It captures everything you need
to know that isn't in the rest of the doc: where things
live in the codebase, what idioms the existing BPF-LSM code
uses, what tribal knowledge accumulated during the
preceding iterations, and what the verification flow looks
like at each step. **Use TDD throughout** — every phase
specifies tests to write *before* the implementation, so
the test runs RED first and goes GREEN as you complete the
work. If you cannot write a failing test for a piece of
behavior, the behavior is probably underspecified.

The five phases are sized so each leaves the tree in a
buildable, lint-clean, test-passing state. You can stop
between phases for review; nothing requires landing them
together.

### 0. Repository orientation

Branch: **`am/linux-exec-filter-bpf-lsm`** on the
`drewmchugh/nono` fork. Clone target: `~/dd/nono` on
workspaces (matches the validation workspace's existing
checkout — keep the path consistent).

Crate layout:

| Crate | Role | Key files for this work |
|---|---|---|
| `crates/nono` | Library: sandbox primitives, BPF-LSM loader | `src/sandbox/{linux.rs,bpf_lsm.rs}`, `src/bpf/{exec_filter.bpf.c,vmlinux.h}`, `build.rs`, `tests/bpf_lsm_smoke.rs` |
| `crates/nono-cli` | CLI binary: exec strategy, supervisor loop | `src/exec_strategy.rs`, `src/exec_strategy/supervisor_linux.rs`, `src/mediation/{filter_audit.rs,shebang.rs}`, `tests/exec_filter.rs` |
| `crates/nono-shim` | Shim binary that the agent execs | unchanged by this work |

`crates/nono/src/sandbox/linux.rs` is large (~3 k lines) and
holds *all* of the existing seccomp-unotify infrastructure:
filter install, BPF program builders, sockaddr parsing,
notify recv/respond primitives, the path-read helpers.
Phase 1 deletes the exec-filter portions of this file but
leaves the openat (capability elevation) and connect/bind
(network proxy) portions intact — they're independent
features.

Existing BPF-LSM scaffolding:

- `crates/nono/src/bpf/exec_filter.bpf.c` is the BPF C
  source. Currently has the `bprm_check_security` program
  with cgroup-ancestor walk and `(dev, ino)` deny check.
- `crates/nono/src/bpf/vmlinux.h` is the vendored kernel
  type header (3 MB; do not regenerate unless the BPF
  program needs a new struct field).
- `crates/nono/build.rs` invokes `libbpf-cargo`'s
  `SkeletonBuilder` to compile the BPF C and emit a Rust
  skeleton at `OUT_DIR/exec_filter.skel.rs`.
- `crates/nono/src/sandbox/bpf_lsm.rs` is the loader. It
  has `install_exec_filter(deny_paths, agent_cgroup_id)`,
  `create_session_cgroup(agent_pid)`, `is_bpf_lsm_available()`,
  the `ExecFilterHandle` and `SessionCgroup` RAII types,
  and a `mod skel { include!(...); } use skel::*;` wrapper
  that suppresses clippy lints on the libbpf-cargo-
  generated boilerplate.

The current broker integration is in
`crates/nono-cli/src/exec_strategy.rs` around the
post-fork parent branch (~line 1165), inside the
`#[cfg(target_os = "linux")]` block that creates the
session cgroup, calls `install_exec_filter`, and binds the
result into a let-binding kept alive for the supervisor
loop. The seccomp-unotify exec filter — the thing being
deleted in Phase 1 — is also wired here: child sends an
`exec_notify_fd` over the socketpair, parent receives it,
parent's poll loop calls `handle_exec_notification` on
each event.

### 0.1 Build and validation environment

A fresh workspace booted from the `am/bpf-lsm-workspace-ami`
AMI has:

- `cat /sys/kernel/security/lsm` includes `bpf`. Verify
  before doing anything.
- Kernel `6.8.0-1052-aws` or newer with `CONFIG_BPF_LSM=y`.
  Verify via `grep bpf_lsm_bprm_check_security /proc/kallsyms`.
- Standard Ubuntu user / docker container layout (see the
  decisions log for the recon details).

To build for the first time on a fresh workspace:

```
sudo apt-get install -y \
    libdbus-1-dev libelf-dev clang build-essential pkg-config
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable
source $HOME/.cargo/env
cd ~/dd/nono
make build-release
sudo setcap cap_bpf,cap_sys_admin,cap_dac_override+ep \
    target/release/nono
```

Re-run `setcap` after every release build — `cargo build`
overwrites the binary and drops file capabilities.

POC sources for end-to-end validation:

```
git clone --depth 1 -b kipz/pr20-toctou-poc \
    https://github.com/kipz/nono.git /tmp/kipz-poc
mkdir -p /tmp/exec-filter-poc
cp /tmp/kipz-poc/poc/{attacker.c,vfork_attacker.c,run_test.sh} \
    /tmp/exec-filter-poc/
chmod +x /tmp/exec-filter-poc/run_test.sh
```

Harness usage:

```
NONO=$(pwd)/target/release/nono \
SHIM=$(pwd)/target/release/nono-shim \
ATTEMPTS=600 \
ATTACKER_SRC=vfork_attacker.c \
LABEL=phase-X \
bash /tmp/exec-filter-poc/run_test.sh
```

Set `ATTACKER_SRC=attacker.c` for the pthread variant.
Both should report `BYPASS_COUNT=0` after every phase.

### 0.2 Tribal knowledge from prior iterations

Things you'd waste time rediscovering otherwise:

- **`(dev, ino)` byte layout** between Rust and BPF must
  match exactly. The Rust loader has `#[repr(C)] struct
  DenyKey { dev: u64, ino: u64 }` and the BPF program has
  the parallel C definition. If you change one, change the
  other and re-run the smoke test to catch verifier
  rejection.
- **`MaybeUninit<OpenObject>` lifetime.** `libbpf-rs`
  `SkelBuilder::open` borrows from caller-owned storage
  for the BPF object. The loader uses `Box::leak` to give
  the storage a `'static` lifetime so the
  `ExecFilterHandle` can own the resulting skeleton. The
  leak is bounded (one OpenObject per session) and
  reclaimed when the broker exits.
- **Clippy on generated code.** `libbpf-cargo` emits
  `unwrap()` and `expect()` in its boilerplate. Wrapping
  the `include!` in a `mod skel { ... }` with
  `#[allow(clippy::unwrap_used)]` and
  `#[allow(clippy::expect_used)]` suppresses lints on the
  generated code only; hand-written code in the same file
  remains under the project's strict deny.
- **`bpf_get_current_ancestor_cgroup_id(level)` returns 0
  past current's depth.** The cgroup-ancestor walk loop
  exits early on a 0 return, so the typical-case cost is
  `~current_depth` iterations rather than `MAX_CGROUP_DEPTH`.
- **Cgroup `Drop` migrates procs back to parent before
  rmdir.** The `SessionCgroup::drop` impl reads
  `cgroup.procs`, writes each pid to the parent cgroup's
  `cgroup.procs`, and loops up to 16 times in case forks
  happen during the migration. Without this, `rmdir` fails
  with `EBUSY` on a non-empty cgroup and the directory
  leaks.
- **`PR_SET_NO_NEW_PRIVS=1` disables file caps at exec.**
  The agent's `pre_exec` sets this; that's why setcap'd
  binaries the agent might place in writable directories
  don't grant capabilities. Don't break this — it's load-
  bearing for Invariant D.
- **`/proc/<pid>/comm` is the kernel-resolved binary
  basename;** `/proc/<pid>/cmdline` is the user-passed
  argv as it stood at the time of `execve` — for shebang
  scripts these differ (the kernel's binary is the
  interpreter; argv[1] is the script path). The BPF
  program sees the kernel's view via `bprm->file`; the
  audit code sees user-passed view via `bprm->filename`.
  Don't conflate them.
- **`make ci` has pre-existing failures on this branch**
  in `crates/nono-cli/tests/exec_filter.rs` and
  `crates/nono-cli/src/mediation/{filter_audit,shebang}.rs`
  (test code with `unwrap()`). Phase 1 deletes most of
  these files; what remains should clear `make ci` after
  Phase 1 lands.

### Phase 1 — drop the seccomp-unotify exec filter

**Goal.** Remove all userspace exec-decision code. After
this phase, the only enforcement path for mediated commands
is the BPF-LSM hook on `bprm_check_security`. Any host
without `bpf` in the active LSM stack fails session start
loudly. Other seccomp filters (openat for capability
elevation, connect/bind for network proxy) stay — they're
unrelated features.

#### 1.1 Tests to write FIRST (TDD red)

These tests should fail before any deletion happens — they
encode the post-Phase-1 behavior we're implementing toward.

In `crates/nono-cli/tests/exec_filter.rs`:

- `pre_exec_does_not_install_seccomp_exec_filter` — fork a
  child that does what the agent's pre-exec does
  (configure caps, etc.) but verify no seccomp filter on
  `execve` is installed. Easiest check: in the child,
  attempt to `execve` a non-deny binary and trace the
  syscall path; the seccomp-unotify trap should never
  fire because the filter doesn't exist. (You can prove
  absence of the filter via `prctl(PR_GET_SECCOMP)` or
  by checking `/proc/<pid>/status`'s `Seccomp:` field —
  it should still show `0` for "no seccomp" or `2` for
  "filter mode" if other filters are installed; what
  matters is the count of installed filters via
  `seccomp(SECCOMP_GET_NOTIF_SIZES, ...)` doesn't list
  an exec-trapping one).
- `mediation_active_without_bpf_lsm_fails_loudly` —
  mock or condition-skip on a system where `bpf` isn't in
  `/sys/kernel/security/lsm`. Run `nono` with a profile
  containing `mediation.commands`. Expect non-zero exit
  with an error message naming "BPF-LSM" and
  "lsm=...,bpf". Skip on workspaces where bpf *is* active
  (the validation workspace).

In `crates/nono/tests/bpf_lsm_smoke.rs`:

- The existing 4 smoke tests stay GREEN through this
  phase. No new ones for Phase 1.

In a new file `crates/nono-cli/tests/no_seccomp_exec.rs`
(or alongside the existing exec_filter tests, depending on
organization):

- `seccomp_exec_filter_module_does_not_exist` — a
  compile-time guard: `use nono::sandbox::{
  install_seccomp_exec_filter, SYS_EXECVE, SYS_EXECVEAT };`
  should fail to compile after deletion. Encode this as a
  doc-test or a `compile_fail` test in a build script.

#### 1.2 What to delete

Code to remove (everything specific to the seccomp exec
filter; leave the openat/proxy filters alone):

- `crates/nono/src/sandbox/linux.rs`:
  - `install_seccomp_exec_filter` function and its BPF
    program builder.
  - `SYS_EXECVE`, `SYS_EXECVEAT` constants (move to
    libc-only references if anything else needs them; in
    practice nothing will after Phase 1).
- `crates/nono/src/sandbox/mod.rs`: drop the re-exports of
  `install_seccomp_exec_filter`, `SYS_EXECVE`,
  `SYS_EXECVEAT`.
- `crates/nono-cli/src/exec_strategy.rs`:
  - `install_exec_filter` config field on `ExecConfig`.
  - The pre_exec child-side install code that called
    `install_seccomp_exec_filter` and sent the fd.
  - The parent-side `exec_notify_fd: Option<OwnedFd>`
    receive code.
  - The supervisor poll-loop branch that dispatched to
    `handle_exec_notification`.
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`:
  - `handle_exec_notification` function.
  - `classify_exec_path` and its `ExecDecision` enum.
  - `read_path_at`, `read_execve_argv_at` helpers.
  - `count_threads`, `read_tgid` (still used by the openat
    handler? — verify; if so, leave them). Actually
    `read_tgid` is shared with the openat handler — keep
    it. `count_threads` is exec-filter-only — delete.
  - The exec_filter test module at the bottom of the file.
- `crates/nono-cli/src/mediation/shebang.rs`: delete
  entirely.
- `crates/nono-cli/src/mediation/mod.rs`: drop the `pub
  mod shebang;` declaration.
- `crates/nono-cli/src/mediation/filter_audit.rs`: keep
  the file but simplify per Phase 3 (or do the schema
  change here in Phase 1; either is fine — pick one and
  stick with it). For now: drop the obsolete `reason`
  constants (`SHEBANG_CHAIN`, `MULTI_THREADED_UNSAFE`,
  `POST_EXEC_DENY`, `PTRACE_SEIZE_FAILED`); keep
  `DENY_SET` for the BPF-LSM `bprm_check_security` deny
  case (rename to `EXEC_DENY` for clarity).
- `crates/nono-cli/tests/exec_filter.rs`: most tests in
  this file test seccomp-specific behavior. Delete the
  ones that exercise multi-threaded denial, shebang
  chains, or shim-prefix logic. Keep tests that exercise
  the still-relevant audit shape (rewrite to use
  `bpf_lsm_smoke`-style harness if needed).

#### 1.3 What to add

- `BpfLsmError::ActiveLsmRequired` variant on
  `crates/nono/src/sandbox/bpf_lsm.rs::BpfLsmError`. The
  loader should return this rather than the existing
  `NotInActiveLsm` when the *broker* (not just BPF-LSM
  diagnostics) needs to fail. They might be the same — pick
  one consistently.
- `crates/nono-cli/src/exec_strategy.rs`: replace the
  current "warn-and-fall-back-on-`NotInActiveLsm`" branch
  with `return Err(NonoError::SandboxInit(format!("BPF-LSM
  is required for mediation but is not in the active LSM
  stack. The host kernel must boot with lsm=...,bpf in
  the cmdline. See drewmchugh/nono#3.")))`.
- Same for the cgroup-create failure branch and the
  generic `LibBpf` errors: hard-fail rather than fall
  back.

#### 1.4 Verification

```
cargo build -p nono-cli --release
sudo setcap cap_bpf,cap_sys_admin,cap_dac_override+ep \
    target/release/nono
cargo test -p nono --lib                  # 629+ tests pass
cargo test -p nono --test bpf_lsm_smoke   # 4 tests pass
sudo -E cargo test -p nono --test bpf_lsm_smoke  # 4 tests pass with caps
make ci                                   # clean
```

End-to-end POCs (must remain 0/600 from prior validation):

```
ATTACKER_SRC=attacker.c    LABEL=phase1-pthread bash /tmp/exec-filter-poc/run_test.sh
ATTACKER_SRC=vfork_attacker.c LABEL=phase1-vfork bash /tmp/exec-filter-poc/run_test.sh
```

#### 1.5 Acceptance criteria

- All existing BPF-LSM smoke tests still pass.
- POC results: pthread 0/600, vfork 0/600.
- `grep -r install_seccomp_exec_filter crates/` returns
  nothing.
- `grep -r handle_exec_notification crates/` returns
  nothing.
- `grep -r SYS_EXECVE crates/` returns nothing (or only
  in irrelevant comments).
- `make ci` clean (or has only pre-existing failures
  unrelated to this work — note them in the commit
  message).

#### 1.6 Commit

```
Phase 1: drop seccomp-unotify exec filter; BPF-LSM is sole enforcement
```

Reference the design doc and the decisions log in the
body. Include `Signed-off-by:` per the project's DCO rule.

### Phase 2 — `file_open` BPF-LSM hook

**Goal.** Add the `file_open` LSM hook that denies the
agent's tree from reading mediated-binary bytes. Closes
copy-the-binary, ld-linux trick, unprivileged tmpfs, and
shellcode bypass classes in one step.

#### 2.1 Tests to write FIRST (TDD red)

In `crates/nono-cli/tests/file_open_deny.rs` (new file),
each test should:
1. Set up a session with `mediation.commands` listing a
   test binary that exists at a known path under the test
   harness's tmp directory.
2. Run an action inside the agent's session that exercises
   the bypass.
3. Assert the action fails with `EACCES` and the agent
   never gets the binary's bytes.

Tests:

- `cat_of_mediated_binary_from_inside_agent_fails` —
  `bash -c "cat /path/to/mediated-binary > /tmp/copy"`.
  Expect non-zero exit. Expect `/tmp/copy` to not contain
  the mediated binary's bytes.
- `cp_of_mediated_binary_from_inside_agent_fails` — same
  but with `cp`.
- `dynamic_linker_invocation_of_mediated_binary_fails`
  — `bash -c "/lib/ld-linux-x86-64.so.2 /path/to/binary"`
  (use `arch=x86_64`-conditional path; on aarch64 the
  linker is `/lib/ld-linux-aarch64.so.1`). Expect
  non-zero exit; expect the binary's marker output never
  appears.
- `cat_of_mediated_binary_from_broker_succeeds` — same
  binary, but the cat is run *outside* the agent's
  cgroup (e.g., directly from the test harness without a
  nono session). Expect success. Demonstrates the scope
  check works.
- `cat_of_non_mediated_binary_from_inside_agent_succeeds`
  — `bash -c "cat /bin/ls > /dev/null"`. Expect success.
  Demonstrates the deny is targeted.

In `crates/nono/tests/bpf_lsm_smoke.rs`:

- Add `file_open_hook_attaches` — verifies the new BPF
  program section is present in the loaded skeleton and
  that `attach()` succeeds.
- Update `force_load_validates_verifier_acceptance` to
  exercise both hooks loading.

In `crates/nono-cli/tests/exec_filter.rs` (or wherever the
audit tests live after Phase 1):

- Add `audit_emits_open_deny_when_agent_reads_mediated_binary`
  — verify a JSONL entry appears in `audit.jsonl` with
  `action_type = "deny"`, `reason = "open_deny"`,
  `path = <canonical>`. (May need to defer assertion to
  Phase 3 if audit emission is per-phase ordered.)

#### 2.2 BPF program changes

In `crates/nono/src/bpf/exec_filter.bpf.c`, add a second
program after the existing `bprm_check_security`:

```c
SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file)
{
    if (!in_session_cgroup_via_ancestor_walk()) {
        return 0;
    }
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct deny_key key = {
        .dev = BPF_CORE_READ(inode, i_sb, s_dev),
        .ino = BPF_CORE_READ(inode, i_ino),
    };
    if (bpf_map_lookup_elem(&deny_set, &key)) {
        return -EACCES;
    }
    return 0;
}
```

Factor the cgroup-ancestor walk into a `static
__always_inline` helper if the existing program inlines
it directly — both programs need it.

#### 2.3 Loader changes

`crates/nono/src/sandbox/bpf_lsm.rs`:

- The `ExecFilterHandle` already holds `_skel` and
  `_link`. Add a second link field, `_open_link`, for the
  `file_open` program's attachment. RAII teardown order
  matters — the link drops *before* the skel does.
- In `install_exec_filter_inner`, after the existing
  `skel.progs.check_exec.attach()`, also call
  `skel.progs.check_file_open.attach()` and store the
  result. The skeleton names come from libbpf-cargo's
  generation rule (program function name → field name on
  `skel.progs`).

#### 2.4 Verification

```
cargo build -p nono-cli --release
sudo setcap cap_bpf,cap_sys_admin,cap_dac_override+ep \
    target/release/nono
sudo -E cargo test -p nono --test bpf_lsm_smoke
cargo test -p nono-cli --test file_open_deny
```

End-to-end on the validation workspace:

```
# Existing POCs still pass
ATTACKER_SRC=attacker.c       bash /tmp/exec-filter-poc/run_test.sh
ATTACKER_SRC=vfork_attacker.c bash /tmp/exec-filter-poc/run_test.sh

# Add a copy-attack POC: bash script that
# (a) cps mediated-binary to /tmp/copy and execs it,
# (b) runs /lib/ld-linux mediated-binary,
# (c) unshares user-ns, mounts tmpfs, copies bytes, execs.
# All three must fail with EACCES at the cp/cat step
# (i.e., the bytes never get to the writable location).
```

Author the new POCs under `/tmp/exec-filter-poc/copy_attacker.sh`
etc. They don't need to be checked into the repo; they're
validation artifacts on the workspace.

#### 2.5 Acceptance criteria

- All Phase 1 tests still pass.
- New `file_open_deny` tests pass.
- Smoke test confirms the new program loads and attaches.
- Empirical: copy-attack, ld-linux trick, and tmpfs trick
  all fail at the read step.

### Phase 3 — BPF audit ring buffer + userspace reader

**Goal.** Restore the audit feature lost when Phase 1
removed the seccomp supervisor's audit-emission code.
Audit records flow from the BPF program through a
`BPF_MAP_TYPE_RINGBUF` to a broker-side polling task, which
formats them and appends to `~/.nono/sessions/audit.jsonl`.

#### 3.1 Tests to write FIRST (TDD red)

In `crates/nono-cli/tests/audit_ringbuf.rs` (new):

- `audit_emits_allow_unmediated_for_non_mediated_exec` —
  agent execs `/bin/ls`. Expect a JSONL entry with
  `action_type = "allow_unmediated"`, `command = "ls"`,
  `path = "/bin/ls"`.
- `audit_emits_deny_for_blocked_open` — agent tries to
  `cat` a mediated binary. Expect a JSONL entry with
  `action_type = "deny"`, `reason = "open_deny"`,
  `exit_code = 126`.
- `audit_does_not_emit_for_shim_invocations` — agent runs
  the shim path (which the broker mediates normally).
  Expect no `exec_filter`-shaped entry from the BPF
  audit; the shim downstream emits its own normal
  audit record.
- `audit_does_not_emit_for_open_allows` — agent does many
  `open` calls on non-mediated files. Expect zero
  emissions in the kernel audit channel from those.
- `audit_record_has_argv_for_bprm_events` — agent runs
  `/bin/ls -la /tmp`. Expect the JSONL entry's `args` to
  be `["-la", "/tmp"]` (argv without argv[0]).

In `crates/nono/tests/bpf_lsm_smoke.rs`:

- `ringbuf_map_is_present_in_skeleton` — assert the
  generated skeleton exposes the audit ringbuf.
- `audit_reader_polls_without_panicking` — start a
  reader, immediately stop, no panic.

#### 3.2 BPF program changes

Add a ring buffer map:

```c
struct audit_record {
    __u64 ts_ns;            /* bpf_ktime_get_ns */
    __u8  source;           /* 0 = bprm, 1 = file_open */
    __u8  verdict;          /* 0 = allow_unmediated, 1 = deny */
    __u8  reason;           /* 0 = none, 1 = exec_deny, 2 = open_deny */
    __u8  _pad;
    __u32 pid;
    __u64 dev;
    __u64 ino;
    char  path[256];
    /* For bprm only: argv as a single \0-separated buffer.
     * argc inferred at userspace by counting nulls. */
    __u32 argv_len;
    char  argv[1024];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);  /* 1 MB */
} audit_rb SEC(".maps");
```

In each hook, on audit-worthy paths, reserve a slot, fill
it, submit:

```c
struct audit_record *r = bpf_ringbuf_reserve(&audit_rb,
                                              sizeof(*r), 0);
if (!r) return /* fall through, don't fail closed on
                  audit-side issues */;
r->ts_ns = bpf_ktime_get_ns();
r->source = SOURCE_BPRM;  /* or SOURCE_FILE_OPEN */
r->verdict = ...;
r->reason = ...;
r->pid = bpf_get_current_pid_tgid() >> 32;
r->dev = key.dev;
r->ino = key.ino;
bpf_d_path(&file->f_path, r->path, sizeof(r->path));
/* For bprm only: */
bpf_probe_read_user_str(r->argv, sizeof(r->argv),
                         BPF_CORE_READ(bprm, argv));
bpf_ringbuf_submit(r, 0);
```

Audit-worthy paths:
- `bprm_check_security` allow when current is in agent
  cgroup AND path doesn't start with the shim_dir prefix
  → `allow_unmediated`. Suppress for shim paths in
  userspace based on the recorded `path`.
- `bprm_check_security` deny → `exec_deny` (defense-in-
  depth; should be rare).
- `file_open` deny → `open_deny`.
- `file_open` allow → **don't emit**, would be too noisy.

#### 3.3 Userspace reader

New file `crates/nono/src/sandbox/bpf_audit.rs`:

- `pub struct AuditReader { ... }` with `start(...) -> Self`
  that spawns a polling task on the ring buffer fd. Use
  `libbpf-rs::RingBufferBuilder`'s callback API: register
  a closure that decodes each record and writes to the
  audit log.
- The ring buffer fd lives on the loaded skeleton's
  `maps.audit_rb`. Pass it to the reader at construction.
- Reader holds `Arc<Mutex<File>>` for the audit log so
  multiple ring-buffer events can be appended without
  reopening.
- Reader's `Drop` stops the polling task cleanly (use a
  cancellation token / atomic bool checked in the poll
  loop).

In `crates/nono-cli/src/exec_strategy.rs`, the broker
constructs the `AuditReader` after `install_exec_filter`
returns and binds it into the same scope that holds the
`ExecFilterHandle`. Drop order: reader drops first
(stops polling), then the filter handle (detaches BPF).

#### 3.4 Schema change

`crates/nono-cli/src/mediation/filter_audit.rs`:

- `FilterAuditEvent::action_type`: `"allow_unmediated"` |
  `"deny"`.
- `reason` (Option<String>): `"open_deny"` | `"exec_deny"`
  on deny; absent on allow.
- Drop `interpreter_chain` field entirely.
- `exit_code: Some(126)` on deny; `None` on allow.
- All other fields unchanged.

The shim-side `AuditEvent` (in `mediation/server.rs` or
similar) is not touched; consumers of `audit.jsonl` see
both shapes interleaved as today.

#### 3.5 Verification

```
cargo build -p nono-cli --release
sudo setcap cap_bpf,cap_sys_admin,cap_dac_override+ep target/release/nono
cargo test -p nono-cli --test audit_ringbuf
sudo -E cargo test -p nono --test bpf_lsm_smoke
```

Manual end-to-end:
1. Start a session with mediation.
2. Inside, run `ls /`, `cat /bin/ls > /dev/null`, attempt
   to cat a mediated binary (expect EACCES).
3. Inspect `~/.nono/sessions/audit.jsonl`. Expect
   `allow_unmediated` entries for `ls`, `cat`. Expect a
   `deny` entry with `reason: open_deny` for the cat
   attempt on the mediated binary. No entry for the
   shim-routed mediated invocation (shim emits its own
   record, not via the BPF ring buffer).

#### 3.6 Acceptance criteria

- All Phase 1 + 2 tests pass.
- New audit_ringbuf tests pass.
- Audit log has the expected entries for a representative
  session.
- Audit reader survives session teardown without
  hanging.

### Phase 4 — invariant assertions

**Goal.** Every deployment invariant the design depends on
gets a session-start verification with a clear error
message. No silent failure modes.

#### 4.1 Tests to write FIRST (TDD red)

In `crates/nono-cli/tests/invariants.rs` (new):

- `agent_capeff_is_zero` — start a session, assert the
  agent's `/proc/<pid>/status`'s `CapEff:` line is all
  zeros.
- `pcs_is_non_dumpable` — start a session, trigger a
  per-command sandbox spawn, assert
  `/proc/<pcs_pid>/status`'s `Dumpable:` is 0.
- `session_fails_loudly_when_bpf_not_in_lsm_stack` —
  condition-skip on workspaces that do have bpf;
  otherwise verify nono exits with the specific error
  message.

#### 4.2 Implementation

`crates/nono-cli/src/exec_strategy.rs`:

- After fork + setup of agent's pre-exec, but before
  agent runs user code, the broker reads
  `/proc/<agent>/status` and verifies `CapEff: 0`. If
  non-zero, log error and abort the session.
- For per-command sandboxes: in the spawn path
  (`crates/nono-cli/src/mediation/policy.rs:611`-ish),
  after `exec`, read `/proc/<pcs>/status`, verify
  `Dumpable: 0`, kill PCS and surface error if not.
- Session-start log: emit an `info!` line listing each
  invariant and PASS/FAIL, plus the resolved deny inodes.
  Operators auditing the log see explicitly what was
  enforced.

#### 4.3 Acceptance criteria

- All previous tests pass.
- Invariant assertion tests pass.
- Session-start log includes a structured invariants
  block.

### Phase 5 — doc reorg (done)

This file *is* the new `docs/linux-bpf-lsm-mediation.md`. The
old seccomp-era plan lives at
`docs/archive/linux-exec-filter-plan-seccomp-era.md`.

The autonomous-session decisions log lives alongside this file
at `docs/linux-exec-filter-bpf-lsm-impl-decisions.md`; the
older vfork-iteration decisions log at
`docs/linux-exec-filter-vfork-decisions.md` chronicles the
iterations that didn't land.

## What this design does not address

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
