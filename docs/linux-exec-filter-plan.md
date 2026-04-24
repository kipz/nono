# Linux exec filter for mediation

## Summary

Add a `seccomp-unotify` filter that traps `execve` and `execveat` in the agent's
process tree, so that every attempt to run a program is visible to the broker.
Use it to close the full-path exec bypass: on Linux, the agent can invoke the
real binary of a mediated command directly (e.g. `/home/user/.local/bin/gh`)
and never touch the shim farm, because Landlock cannot deny a specific file
inside an allowed directory. The filter makes the broker the choke point for
every `execve`, forces invocations of mediated binaries to go through the shim,
and also covers shebang-based bypasses that the kernel handles internally
without issuing a second `execve`.

The feature is additive: no changes to the shim, the broker's mediation
dispatch, per-command sandboxes, or the Landlock policy. All of the `seccomp-unotify`
infrastructure the filter relies on already exists in the fork for unrelated
features (capability elevation, network proxy fallback), so this work composes
with that plumbing rather than introducing new primitives.

## Problem

### How mediation's shim farm is supposed to work

When `nono run --profile X.json -- claude` starts, the broker (unsandboxed
parent) creates `/tmp/nono-session-<pid>/shims/` and populates it with symlinks
named after real commands (`ddtool`, `gh`, `git`, ...) all pointing at the
`nono-shim` binary. That directory is prepended to the agent's `PATH`. When
the agent's bash runs `ddtool auth token foo`, PATH lookup finds the shim
first, execs it; the shim opens a Unix-socket connection to the broker; the
broker applies the command's mediation rule (`respond`, `capture`, `approve`,
or `passthrough`) and returns a result to the shim, which returns it to the
agent. For capture-style rules, the broker runs the real binary in a tight
per-command sandbox out-of-band, stashes the sensitive output under a random
`nono_<hex>` handle, and returns the handle — the agent never holds raw
secrets.

The mediation architecture is intended to be a complete choke point: every
invocation of a sensitive command goes through the broker.

### The bypass

That choke point depends on the agent's bash doing PATH lookup. Bash skips
PATH lookup when the command contains a `/` — it just execs the literal path
given. So an agent can bypass the shim with:

```
/home/user/.local/bin/gh auth token
```

On macOS, Seatbelt can be configured to deny reads of that specific file even
though its enclosing directory is readable; direct-path exec of a mediated
binary fails at the read step. On Linux, Landlock's only primitive is a
directory-level allow (`LANDLOCK_ACCESS_FS_EXECUTE` on a `PathBeneath` rule).
There is no carve-out operation. If `~/.local/bin` is exec-granted (and it has
to be, because the agent legitimately needs to run lots of tools there), every
file under it is exec-granted, including the ones we've shimmed. The kernel
happily execs the real binary; the shim is never involved; the broker never
learns the invocation happened.

### Why this is a general problem, not a one-binary problem

The bypass applies uniformly to every entry in `mediation.commands`. Whether
the consequence is severe depends on what the bypassed binary does inside the
outer agent sandbox:

- For binaries whose sensitive action is a filesystem read that the outer
  Landlock already denies (e.g., `ddtool` reading `~/.password-store`,
  `gh` reading `~/.config/gh`), the direct-path invocation reaches the binary
  but fails at its sensitive operation. Bypass fizzles.
- For binaries whose sensitive action isn't gated by the outer Landlock — most
  notably `AF_UNIX connect()` to a privileged daemon socket, which Landlock ABI
  v4 does not filter — the bypass succeeds end-to-end.

This design solves the general problem: make the shim unavoidable for every mediated 
binary, regardless of the binary's semantics.

## Goals

- Close the full-path exec bypass for every entry in `mediation.commands`.
- Close the shebang bypass (script files whose `#!` line names a mediated
  binary, which the kernel follows internally without issuing a second
  `execve`).
- Preserve the current audit stream as a superset: shim events continue to
  emit as they do today, and the filter adds records for direct-path
  invocations (allowed and denied) that currently produce no audit
  anywhere. Net coverage is strictly greater than today's; existing
  consumers see unchanged events for shim-routed invocations.
- Be additive to the existing fork. No changes to the shim, the broker's
  mediation dispatch, per-command sandboxes, or the Landlock policy.

## Non-goals

- Landlock ABI v5/v6 features (`LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` etc.).
  Require kernel ≥ 6.10 / 6.12; workspace fleet is on 6.8.

## Threat model

The filter defends against a prompt-injected or misbehaving agent that:

- Has shell access inside its sandbox.
- Can read and write files inside its allowed workspace directories.
- Can compile and run code (compilers are present on the workspace).
- Does not have privileges outside the sandbox; cannot install kernel modules
  or modify kernel state.

The filter does **not** defend against an attacker who:

- Has already gained a concurrent code-execution primitive that can issue raw
  syscalls and race seccomp-notify's post-CONTINUE re-read. This is an
  explicit residual, documented below.
- Controls the broker itself. The filter is a mediation primitive; the broker
  is part of the trust base, as it is today.

## Design

### Mechanism: seccomp-unotify on `execve` and `execveat`

**What seccomp-unotify is.** seccomp is a Linux feature that runs a small
kernel-evaluated program (a BPF filter) on every syscall a process makes. The
filter can allow the syscall, kill the process, return an errno, or — the
mode we use — pause the thread and deliver a notification to a supervisor
process holding a listener file descriptor. The supervisor reads the child's
memory to examine the arguments and tells the kernel how to respond.

**Why trap these two syscalls.** They are the only syscalls that launch a new
program image. Every libc `exec*` function, every shell invocation, every
language runtime's subprocess primitive compiles down to one or the other.
Trapping them catches every exec attempt; trapping other syscalls would not
close the bypass we are targeting.

**Where the filter is installed.** In the agent child, after the existing
Landlock `restrict_self`, before the agent's own `execve`. The existing
capability-elevation code path installs its openat filter at the same point
(see `crates/nono-cli/src/exec_strategy.rs` around the pre_exec closure). Our
filter goes alongside.

**Compatibility with existing filters.** The fork already installs seccomp-unotify
filters for two features: capability elevation (traps `openat`/`openat2`) and
the network proxy fallback (traps `connect`/`bind`). Multiple seccomp filters
can coexist in a single process; the kernel evaluates them in installation
order and takes the strongest response. Our filter, being narrow (only two
syscalls), does not interact with the other two's syscall sets. The BPF
programs of both existing filters were read to confirm they `RET_ALLOW` for
syscalls outside their trap set; findings are documented in Phase 0 below.

**`PR_SET_NO_NEW_PRIVS` is already set.** The kernel requires either
`CAP_SYS_ADMIN` or `NO_NEW_PRIVS` before an unprivileged process may install a
seccomp filter. `install_seccomp_notify` in `crates/nono/src/sandbox/linux.rs`
already calls `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)`. The flag is one-way and
inherited across `fork`/`exec`, so every descendant of the agent is subject to
the filter, and nothing can disable the filter or install a replacement.

### Three-way classification in the supervisor

For each trapped `execve`/`execveat`, the supervisor classifies the target
path into exactly one of three buckets:

1. **`allow_shim`**: the resolved path lexically sits under the session's shim
   directory (`/tmp/nono-session-<broker-pid>/shims/`). This is the intended
   shim route; allow the exec to proceed so the shim can take over.
2. **`deny`**: the canonical path is a member of the deny set, which is
   derived implicitly at session start from the canonical real paths of every
   entry in `mediation.commands`, regardless of action type (`respond`,
   `capture`, `approve`, or `passthrough`). Deny with `EACCES`.
3. **`allow_unmediated`**: anything else. The agent is permitted to run this
   binary freely; the supervisor lets the exec proceed.

**Check order.** Shim-prefix check first (against the pre-canonical resolved
path), then deny check (against the canonical path), then fall through to
allow. Shim-first keeps the happy path fast and unambiguous; it also avoids a
pathological case where a shim path might collide with a deny-set entry after
canonicalization.

**Why the deny set is derived implicitly.** `mediation.commands` already
enumerates every command the profile author wants mediated; adding a parallel
`deny_exec` field would be redundant and easy to forget to sync. The broker
already resolves each command's real path at session start (it uses those
paths to exec the binary inside per-command sandboxes), so the same resolution
produces the deny set as a side effect with no additional profile surface.

### Canonicalization rules

**Deny set canonicalization.** Each `mediation.commands` entry's real path is
canonicalized once at session start (`std::fs::canonicalize`, which follows
symlinks and normalizes `..`/`//`). The canonical form is stored in a set for
O(1) lookup.

**Notification path canonicalization.** At trap time, the supervisor:

1. Reads the raw path string from the child's memory via `/proc/<tid>/mem` at
   the pointer address provided by the BPF filter.
2. Resolves dirfd and cwd semantics to produce an absolute resolved path (see
   execveat variants below).
3. Canonicalizes the resolved path for the deny-set check.

**Shim-prefix check uses the pre-canonical resolved path.** This is a
deliberate split. The shim directory contains symlinks to the `nono-shim`
binary; canonicalizing `/tmp/nono-session-<pid>/shims/ddtool` follows the
symlink to the shim binary's real path, which is no longer under the shim
directory. Checking the pre-canonical path preserves the shim-prefix match.
Security-wise this is fine: files under the shim directory were put there by
the broker and are trusted by construction.

**Failure handling.** Path resolution and canonicalization failures
(nonexistent path, permission error on a component) respond `CONTINUE`
and emit no audit event. The kernel re-runs its own resolution after
`CONTINUE` and returns the native errno (typically `ENOENT`, sometimes
`EACCES` / `ELOOP` / `ENAMETOOLONG` / `EISDIR` / `ENOTDIR`).
Synthesizing `EACCES` here would corrupt PATH-walking shells: glibc's
`execvp` treats `EACCES` as sticky and `ENOENT` as "try the next PATH
entry," so turning PATH-miss `ENOENT`s into `EACCES`es would break
every command bash finds later on PATH after a miss. Every `bash -c
'<cmd>'` invocation walks PATH and routinely hits nonexistent
candidates before its real one.

### Shebang handling

The bypass extends past `execve`'s direct path argument: when `execve` is
called on a file whose first bytes are `#!/interpreter`, the Linux kernel
replaces the process image with the interpreter internally, without issuing a
second `execve` syscall. Our filter sees the script's path but not the
interpreter. An agent can write a script whose `#!` line names a mediated
binary and exec the script to reach the binary unobserved.

**In-handler shebang read.** After a path has been canonicalized and placed
into `allow_unmediated`, the supervisor opens the canonical target and reads
the first 256 bytes (matching the kernel's `BINPRM_BUF_SIZE` constant from
`include/linux/binfmts.h`). If the file starts with `#!`, it parses the
interpreter path (the token up to the first whitespace or newline after
`#!`), canonicalizes it, and checks the result against the deny set. If the
interpreter is in the deny set, flip the decision to `deny`. The walker is
not run on `allow_shim` decisions: the shim binary is a known ELF executable,
never a script, so opening and reading it on every PATH-routed mediated
invocation is pure overhead.

**Recursion up to a named bound.** The Linux kernel chains shebangs up to
`BINPRM_MAX_RECURSION` levels (currently 5, defined in
`include/linux/binfmts.h`). If we checked only the first shebang level, an
agent could chain scripts (`script1.sh` → `#!/tmp/script2.sh`, `script2.sh` →
`#!/home/user/.local/bin/ddtool`) and slip through. The handler recurses the
check up to a `MAX_SHEBANG_RECURSION` constant, set to 8 for margin above the
kernel's current value. The kernel limit is a compile-time constant not
exposed to userspace; the margin absorbs a kernel bump without immediately
opening a hole. A unit test asserts that `MAX_SHEBANG_RECURSION` is at least
as large as the kernel value we believe to be in effect, so a future kernel
bump is noticed.

**What we do not have to chase.** Shebangs that name a real interpreter
(`#!/bin/bash`, `#!/usr/bin/env python`) don't need special handling. The
kernel loads the interpreter internally; the interpreter then performs its
own `execve` for any subcommand it wants to run, and those `execve`s trap our
filter normally. Only the direct chain of script-to-script-to-mediated-binary
shebangs is invisible to normal filter coverage; that's the chain we recurse
to catch.

**ELF `.interp` section.** In principle the agent could write an ELF binary
whose dynamic-linker interpreter names a mediated binary. In practice the
interpreter has to be a dynamic linker format (`/lib64/ld-linux-x86-64.so.2`),
and none of the binaries under mediation are dynamic linkers. Out of scope;
not pursued unless the mediation list grows to include linker-shaped binaries.

### TOCTOU mitigation: double-read

**The race.** seccomp-unotify traps only the thread that made the syscall;
sibling threads in the same process continue to run. If the supervisor
responds CONTINUE (allow), the kernel re-reads the pathname from the child's
memory before actually performing the exec. A cooperating sibling thread can
modify the pathname buffer between our check and the kernel's re-read,
substituting a deny-set path the supervisor already approved. The same race
applies to the file content we read for shebang handling: the agent can write
a benign file, let us read it, swap it to a malicious shebang, and have the
kernel load the swapped version.

**Mitigation.** Before responding CONTINUE on an `allow_unmediated`
decision, the supervisor performs a second read of the pathname from the
same user-memory address and compares against the first read; if it
differs bytewise, flip the response to `deny`. This does not close the
race — after we respond CONTINUE, the kernel still performs its own
re-read — but it collapses the vulnerable window from "full
classification + canonicalization + shebang traversal" down to "single
ioctl round-trip," which defeats naive spin-flip exploits and forces any
attack to synchronize with opaque kernel timing.

**Single-open `/proc/<tid>/mem`.** Both the initial read and the
TOCTOU re-read use the same `/proc/<tid>/mem` file descriptor, opened
once at the start of the handler. The kernel runs `ptrace_may_access`
at `open()` time, not on each `read()`; sharing one fd avoids a
re-check that fails when the trapped task gets reparented to init
mid-handler under Yama `ptrace_scope=1` (the daemonize double-fork
pattern: a process forks, second-forks, the intermediate exits, and
the orphan grandchild's `execve` traps after the supervisor has lost
its descendant relationship). The byte-comparison guarantee is
preserved because each `read()` still copies from the target's current
address space — the fd share is a permission optimization, not a
content snapshot.

The re-read is skipped on `allow_shim` decisions: the shim path is a
known location and the kernel's post-CONTINUE re-read against it is
benign. It is also skipped on `execveat(..., AT_EMPTY_PATH)`, which
resolves through a stable fd link rather than a user-memory pathname.

**Shebang content not re-read.** The shebang interpreter chain is read
once, during classification. A shebang content swap (benign script →
mediated-binary shebang, raced between our read and the kernel's load)
falls under the multi-threaded residual below and is not separately
mitigated.

**Residual, stated honestly.** A multi-threaded binary with tight
synchronization against the kernel's post-CONTINUE re-read remains a
theoretical bypass. The agent can compile such a binary (compilers are
available inside the sandbox). We do not close this residual in v1.
Justification: the threat profile this feature targets is a prompt-injected
agent executing shell commands and well-known tools, not one producing
tailored race-exploit binaries. Closing the residual requires `ptrace`-freezing
every sibling thread for the duration of each exec trap, which is a
significant performance, complexity, and compatibility cost (see "TOCTOU
residual" in Trade-offs). The filter design does not foreclose adding this
later if the threat changes.

### Audit

**Scope — what the filter emits and what it does not.** The filter's audit
events are complementary to the existing shim-emitted events, not a
replacement. For each of the three classifications:

- **`allow_shim` — no filter event.** The shim downstream from this decision
  emits the existing-format audit event itself, after the command completes,
  with the real `exit_code` and (when relevant) `action_type`. Having the
  filter also emit at trap time would double-count every shim invocation.
  The filter stays silent and lets the shim's existing path do its job.
- **`allow_unmediated` — filter emits.** These are direct-path invocations
  that bypass the shim entirely (e.g., `/bin/ls`, `/usr/bin/jq`). Today they
  produce no audit record anywhere on either macOS or Linux. The filter is
  the only observer.
- **`deny` — filter emits.** The command never runs, so no shim event will
  follow. Only the filter records it.

**Net coverage.** Existing shim events are unchanged. Previously-invisible
direct-path invocations (allowed and denied) now produce filter events.
Result: a strict superset of current audit coverage, without
double-counting.

**Record shape.** Filter events are conceptually a distinct class from
shim events — kernel-trap decisions vs post-execution completions — and
use their own struct, `FilterAuditEvent`. The existing shim `AuditEvent`
is untouched; shim events continue to emit as they do today. Both event
shapes land in the same `~/.nono/sessions/audit.jsonl`, distinguished by
the `action_type` field (shim events use `"capture"` / `"respond"` /
`"approve"` or omit it for audit-only; filter events use values prefixed
with `exec_filter_`). Downstream consumers that already dispatch on
`action_type` extend with two new prefixes; consumers that ignore
`action_type` see additional events with a slightly different field
shape.

`FilterAuditEvent` fields:

- `command` (`String`): basename of the canonical target. E.g., `"gh"`
  for a direct-path exec of `/opt/homebrew/bin/gh`; for shebang-chain
  denies, the basename of the script the agent tried to exec.
- `args` (`Vec<String>`): argv without argv[0], same semantics as the
  shim's audit events.
- `ts` (`u64`): unix seconds, same type as the shim's.
- `action_type` (`String`, required): either
  `"exec_filter_allow_unmediated"` or `"exec_filter_deny"`. Unlike the
  shim's `Option<String>`, this is always present on filter events — the
  discriminator is load-bearing.
- `exit_code` (`Option<i32>`): `Some(126)` on `exec_filter_deny`,
  matching the existing mediation-denied convention at
  `crates/nono-cli/src/mediation/policy.rs:169`
  (`exit_code: 126` for "command invoked cannot execute"). `None` on
  `exec_filter_allow_unmediated`: the command ran, but the supervisor
  responded CONTINUE at trap time and does not track the process to
  completion, so no exit code is observable from the filter's vantage
  point. Serialized with `skip_serializing_if = "Option::is_none"` so
  absence is represented by field omission, not `null`.
- `reason` (`Option<String>`): present only on `exec_filter_deny`. One
  of `"deny_set"`, `"shebang_chain"`, `"toctou_mismatch"`. Absent on
  allow events.
- `path` (`Option<String>`): canonical resolved path of the target.
  Present on all filter events (the basename `command` field doesn't
  preserve path context, which is load-bearing on direct-path events).
  Absent on shim events.
- `interpreter_chain` (`Option<Vec<String>>`): only on shebang-driven
  denies, the list of interpreter paths the filter chased (outermost
  first). Absent otherwise.

Explicitly not included on `FilterAuditEvent`: `pid` / `tid` / `syscall`
(forensic detail with no current consumer; additive later if needed).

Examples:

```json
{"command":"jq","args":["-r",".items[]"],"ts":1776973803,"action_type":"exec_filter_allow_unmediated","path":"/usr/bin/jq"}
```

```json
{"command":"gh","args":["auth","token"],"ts":1776973803,"action_type":"exec_filter_deny","exit_code":126,"reason":"deny_set","path":"/opt/homebrew/bin/gh"}
```

```json
{"command":"evil.sh","args":[],"ts":1776973803,"action_type":"exec_filter_deny","exit_code":126,"reason":"shebang_chain","path":"/tmp/evil.sh","interpreter_chain":["/opt/homebrew/bin/gh"]}
```

**Writer.** Filter events are emitted by the supervisor in-process (no
shim socket round-trip) and written to the same `audit.jsonl` file the
shim already writes to. A new helper function serializes
`FilterAuditEvent` and appends a line; no new file, no new socket, no
new rotation logic. The existing `append_audit_log` helper in
`crates/nono-cli/src/mediation/server.rs` is typed on the shim's
`AuditEvent` and won't be reused directly, but the file-open / append /
mode-0600 pattern is copied for the filter writer.

**Volume expectation.** Volume is bounded by the number of direct-path
exec attempts plus denials — a small minority of total execs on a normal
developer session. A `bzl build` that uses only PATH-based invocations of
compilers and shells produces zero filter events; every execve still
produces a shim event as today. Direct-path-heavy workloads (e.g. an
agent scripted to full-path every command) would produce more filter
events, but those are exactly the events we want to record.

### `execveat` variants

`execveat(dirfd, pathname, argv, envp, flags)` has four resolution cases. All
four are handled by reusing helpers already present in the fork for the
equivalent `openat`/`openat2` dirfd resolution:

1. **Absolute pathname.** `args[1]` is an absolute C string; ignore `dirfd`.
   Canonicalize the path as given.
2. **Relative pathname, `dirfd == AT_FDCWD`.** Resolve the relative path
   against `/proc/<tid>/cwd` (a kernel-maintained symlink to the thread's
   current working directory).
3. **Relative pathname, `dirfd` is a real fd.** Resolve the relative path
   against `/proc/<tid>/fd/<dirfd>` (a kernel-maintained symlink to whatever
   file or directory the fd points at).
4. **`AT_EMPTY_PATH` flag and empty pathname.** The target is whatever
   `/proc/<tid>/fd/<dirfd>` points at directly. No pathname parsing required.

Helpers `read_notif_path`, `resolve_notif_path`, and the `/proc/<tid>/fd/*`
resolution already exist (`crates/nono-cli/src/exec_strategy/supervisor_linux.rs`
uses them today for openat dirfd resolution). Case 4 is the only one that
isn't already expressed in existing code paths, and it's a few lines.

### Profile schema

**No new explicit field.** The deny set is derived implicitly at session start
from the canonical real paths of `mediation.commands` entries. Profile
authors declare which commands are mediated; the filter inherits that set.

**Feature activation.** The filter is only installed when
`mediation.commands` is non-empty (i.e., the deny set has at least one
entry). Plain `nono run` sessions without mediation install no
additional seccomp filter. Profiles that set only `mediation.env.block`
(env-stripping with no mediated commands) also do not install the
filter: the deny set would be empty, every execve would classify as
`allow_unmediated`, and the supervisor would emit an audit event for
every program the agent runs — overhead and audit noise for no
security benefit.

## Trade-offs and residuals

### TOCTOU residual (post-CONTINUE race)

The race window between the supervisor's pre-response read and the kernel's
post-response re-read remains exploitable by a multi-threaded binary with
tight synchronization. The double-read mitigation tightens the window but does
not close it. Closing it would require `ptrace`-freezing every sibling thread
for the duration of each exec trap, which we rejected as disproportionate for
reasons summarized here:

- **Performance**: per-exec cost grows from microseconds to milliseconds as
  the number of `PTRACE_SEIZE`/`PTRACE_INTERRUPT`/`waitpid`/`PTRACE_DETACH`
  syscalls scales with thread count.
- **Tracer exclusivity**: a `ptrace`-traced process cannot be simultaneously
  traced by another tool (gdb, strace, perf in some modes), which matters on
  a developer workspace where debugging sessions are a normal workflow.
- **Bug surface**: ptrace's interaction with signal-stops, group-stops, and
  `clone3` is famously subtle; every existing seccomp-notify supervisor in
  production (Docker, Firefox, Chromium renderer, systemd-nspawn) has
  deliberately chosen not to combine ptrace with seccomp-notify for this
  reason.

The design does not foreclose adding ptrace-freeze later if we observe the
residual being exploited in practice.

### Performance

Every `execve` in the agent's process tree round-trips to the broker-side
supervisor. Round-trip cost is on the order of microseconds. Heavy build
workloads (e.g., `bzl build` forking tens of thousands of subprocesses) add at
most a low-hundreds-of-milliseconds overhead across a full build — not
perceptible relative to the builds' own runtime. No fast-path optimization
(e.g., BPF pre-filtering on path prefix) is attempted in v1.

### Audit volume

Filter events are emitted only on `allow_unmediated` and `deny`
decisions; `allow_shim` invocations continue to produce their single
existing shim event and no filter event. The filter therefore adds
volume proportional to direct-path and denied execs rather than to total
exec activity. A session using only PATH-based invocations (the normal
case for most developer workloads, including `bzl build`) adds zero
filter events on top of existing shim events. A session using
direct-path invocations or triggering denies adds one filter event per
such invocation. If filter-event volume becomes a concern in practice,
the `allow_unmediated` bucket is amenable to sampling or per-binary
rollup; neither is proposed for v1.

### Upstream fit

The feature is additive, gated on `mediation.commands` being non-empty, and
reuses existing seccomp-unotify infrastructure. It does not change any public
CLI surface or profile schema field. We expect this to be mergeable into
`kipz/nono` upstream; the Datadog team's fallback is to carry the feature
downstream, though upstream fit is the preferred outcome.

## Platform requirements

- **Kernel ≥ 5.19** for `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` (already
  used by the existing filters; not an additional requirement). Older kernels
  are supported via the existing fallback path.
- **seccomp user notification** (kernel ≥ 5.0). Same infrastructure the fork
  already uses.
- **`PR_SET_NO_NEW_PRIVS`** (kernel ≥ 3.5). Already set by the existing
  filter-install path.

No Landlock ABI bump is required; the filter works on Landlock ABI v4 and
above. It also works on systems with no Landlock at all, though such systems
lose the broader sandboxing nono provides.

## Implementation plan

### Phase 0 (completed): verified assumptions

The three assumptions the design rests on were verified by reading the fork's
code on the `release` branch before writing the rest of this plan. Line
numbers below are provided so reviewers can reproduce the verification
without re-doing the investigation.

1. **Filter composition — verified.** Both existing seccomp-unotify filters
   `RET_ALLOW` syscalls outside their trap set, so a third filter trapping
   `execve`/`execveat` composes cleanly without restructuring the others.
   - `install_seccomp_notify` in `crates/nono/src/sandbox/linux.rs:892`:
     BPF program traps `SYS_openat` / `SYS_openat2` at instructions 1–2 and
     falls through to `SECCOMP_RET_ALLOW` at instruction 3 for every other
     syscall, including `execve` / `execveat`.
   - `build_seccomp_proxy_filter` in `crates/nono/src/sandbox/linux.rs:1620`:
     BPF program dispatches on `SYS_SOCKET` / `SYS_CONNECT` / `SYS_BIND` /
     `SYS_SOCKETPAIR` / `SYS_IO_URING_SETUP` at instructions 1–5; syscalls
     outside that set fall through to `SECCOMP_RET_ALLOW` at instruction 6.

2. **SCM_RIGHTS fd transfer — verified.** Each listener fd is sent as a
   separate, ordered `send_fd_via_socket` / `recv_fd` pair on the supervisor
   socket; the protocol is not packet-structured. Adding a third listener
   fd is purely additive.
   - Child-side sends: `crates/nono-cli/src/exec_strategy.rs:793` (openat
     filter fd, gated on `config.capability_elevation`);
     `crates/nono-cli/src/exec_strategy.rs:853` (proxy filter fd, gated on
     `config.seccomp_proxy_fallback`).
   - Parent-side receives: `crates/nono-cli/src/exec_strategy.rs:1036`
     (openat fd); `crates/nono-cli/src/exec_strategy.rs:1059` (proxy fd).
   - The Linux supervisor loop at
     `crates/nono-cli/src/exec_strategy.rs:1870` builds its `pollfd`
     vector dynamically from `Option<&OwnedFd>` parameters (`seccomp_fd`,
     `proxy_seccomp_fd`) and dispatches by index. A third
     `exec_notify_fd: Option<&OwnedFd>` parameter slots into the same
     pattern without restructuring the loop.

3. **Per-command sandbox inheritance — verified.** Per-command sandboxes
   are forked from the broker process, not from the agent, and therefore
   do not inherit the agent's seccomp exec filter. The broker can freely
   exec real mediated binaries inside per-command sandboxes without
   triggering our filter.
   - `crates/nono-cli/src/mediation/policy.rs:611` runs
     `tokio::task::spawn_blocking(...)` inside the broker process; inside
     that closure, `Command::new(&real_path).spawn()` at `policy.rs:734`
     forks the per-command child from the broker. The broker is the
     unsandboxed parent and has no seccomp filter installed on itself.
   - The per-command sandbox is applied via a `pre_exec` closure at
     `policy.rs:725` that calls `nono::Sandbox::apply(&caps)` with a fresh
     capability set (Landlock on Linux, Seatbelt on macOS). No seccomp
     filter is installed in this closure.
   - The agent child is a separate, earlier fork from the broker (at the
     `exec_strategy` fork point). The exec filter is installed only in
     the agent's `pre_exec` and is scoped to the agent's process tree by
     normal filter inheritance.

### Phase 1: write the test suite (RED before implementation)

Before writing any filter code, commit a test suite that describes the
feature's behavior from the outside. Every test in this phase is RED
against today's binary. Later phases flip them GREEN in deliberate order;
each phase below names which tests it closes, so progress is measurable
against a concrete target.

**Integration tests.** Land in a new integration-test file
(suggested: `crates/nono-cli/tests/exec_filter.rs`) and share a minimal
fixture:

- A test binary at `tests/fixtures/exec_filter/testbin` — an executable
  shell script that prints the marker `REAL_BINARY_RAN`.
- A test profile that extends `claude-code` and lists `testbin` in
  `mediation.commands` with a `respond` rule returning `MEDIATED_RESPONSE`
  on stdout.
- Helpers: `run_nono_with(profile, cmd, args)` returning
  `(stdout, stderr, exit_code)`, and `read_audit_events(session_pid)`
  parsing the session's `audit.jsonl` into a `Vec<serde_json::Value>`.

Integration tests:

1. `path_based_mediated_invocation_goes_through_shim` — invoke `testbin
   arg` via `PATH`. Expect stdout `MEDIATED_RESPONSE`. Regression guard;
   stays GREEN throughout.
2. `direct_path_mediated_invocation_is_denied` — invoke
   `/absolute/path/to/testbin arg` directly. Expect non-zero exit,
   `"permission denied"` on stderr, `REAL_BINARY_RAN` absent from stdout.
   **Core test.**
3. `direct_path_non_mediated_invocation_succeeds` — invoke `/bin/ls /`
   directly. Expect exit 0.
4. `shebang_script_pointing_at_mediated_binary_is_denied` — write
   `/tmp/evil.sh` with first line `#!/absolute/path/to/testbin`. Exec it.
   Expect non-zero exit; `REAL_BINARY_RAN` absent.
5. `shebang_chain_terminates_in_deny` — `/tmp/a.sh` starts `#!/tmp/b.sh`;
   `/tmp/b.sh` starts `#!/absolute/path/to/testbin`. Exec `/tmp/a.sh`.
   Expect non-zero exit.
6. `shebang_chain_with_real_interpreter_allowed` — `/tmp/normal.sh` starts
   `#!/bin/bash` followed by `echo hi`. Exec it. Expect stdout `hi`.
   Guards against over-aggressive shebang denial.
7. `filter_emits_audit_for_allow_unmediated` — direct-path `/bin/ls /`;
   audit file contains an event with
   `action_type == "exec_filter_allow_unmediated"`. The `exit_code:
   None` → field-omission behavior is covered by `FilterAuditEvent`'s
   serialization unit tests, not asserted again here.
8. `filter_emits_audit_for_deny` — direct-path testbin; audit file
   contains an event with `action_type == "exec_filter_deny"`,
   `exit_code == 126`, `reason == "deny_set"`, `path ==` canonical real
   path of testbin.
9. `shim_invocation_does_not_double_emit` — PATH-invoke testbin; audit
   file contains exactly one event for this invocation and no event whose
   `action_type` starts with `exec_filter_`. Regression guard against
   later emitting filter events on `allow_shim`.
10. `filter_composes_with_capability_elevation` — profile enables
    capability elevation (openat filter) in addition to mediation; tests 1
    and 2 still behave as above.
11. `agent_cannot_install_bypass_seccomp_filter` — from inside the
    sandbox, a `seccomp(SECCOMP_SET_MODE_FILTER, ...)` install attempt
    fails. Validates the `PR_SET_NO_NEW_PRIVS` + existing-filter
    guarantee.
12. `filter_audit_args_reflect_execed_command_not_calling_shell` — when
    `bash -c '<testbin> alpha bravo charlie'` exec's testbin, the deny
    audit event records `args = ["alpha", "bravo", "charlie"]` (the
    target's argv minus argv[0]), not the shell's `["-c", ...]`. Guards
    that we read argv from the syscall, not `/proc/<tid>/cmdline`.
13. `nonexistent_path_exec_returns_kernel_errno_not_eacces` — exec of a
    nonexistent absolute path surfaces the kernel's native ENOENT-class
    error to bash, not `EACCES`, and emits no audit event. Guards
    against synthesizing `EACCES` on resolution failure (which would
    break PATH-walking shells).

`execveat` is implemented and exercised through `classify_exec_path`
unit tests and the shared path-resolution helpers, but not through
dedicated integration tests: every Rust/shell exec primitive available
to a test compiles down to `execve`, so testing `execveat` would need
a small harness binary that calls the raw syscall. That harness
isn't in scope for v1; if `execveat`-specific bugs emerge they will be
addressed alongside the helper.

**Unit tests.** Land alongside the modules they cover; write module
skeletons with `todo!()` bodies so the tests compile.

- `parse_shebang(bytes)` table-driven:
  - `b"#!/bin/bash\n"` → `Some("/bin/bash")`.
  - `b"#!/usr/bin/env python\n"` → `Some("/usr/bin/env")`.
  - `b"not a shebang"` → `None`.
  - `b"#!"` alone → `None`.
  - `b"#!/long/interpreter"` followed by 256+ bytes without a newline →
    truncation behavior matches kernel (explicit decision in the test).
- `MAX_SHEBANG_RECURSION` sanity: `assert!(MAX_SHEBANG_RECURSION >= 5)`
  with a comment pointing at `include/linux/binfmts.h`'s
  `BINPRM_MAX_RECURSION`. Failing this test is the CI signal that the
  kernel bumped its value and our margin needs reconsideration.
- `check_shebang_chain` termination: mock reader that returns
  `"#!/self\n"` forever; function returns at `MAX_SHEBANG_RECURSION`
  without stack-overflowing.
- Deny-set canonical lookup: hits on canonical path, hits via symlink that
  resolves into the set, misses, nonexistent paths.
- BPF program structure for the exec filter: static assertion that the
  instruction sequence traps `SYS_execve` and `SYS_execveat` and falls
  through to `RET_ALLOW` for every other syscall. Pattern mirrors the
  existing openat and proxy filter tests at `linux.rs:2786`.
- `FilterAuditEvent` serialization: construct, serialize to JSON, parse
  back; verify field presence/absence per schema (`exit_code` present as
  `126` on deny, absent on allow_unmediated; `reason` present only on
  deny; `interpreter_chain` present only on shebang denies; `command` is
  the basename of `path`; `action_type` always present).

**Stubs written alongside the tests so the crate compiles.** Each stub is
a real function/type signature with a `todo!()` body that will be filled
in during a later phase.

- New module `crates/nono-cli/src/mediation/shebang.rs`:
  - `pub const MAX_SHEBANG_RECURSION: usize = 8;`
  - `pub fn parse_shebang(bytes: &[u8]) -> Option<&str>`
  - `pub enum ShebangResult { NotScript, Deny(Vec<PathBuf>) }`
  - `pub fn check_shebang_chain(path: &Path, depth: usize, deny_set: &DenySet) -> ShebangResult`
- `crates/nono/src/sandbox/linux.rs`:
  - `pub fn install_seccomp_exec_filter() -> Result<OwnedFd>`
- `FilterAuditEvent` struct (new type) in the mediation audit module,
  with fields per the Audit design section above. `todo!()`-returning
  constructor helpers if convenient, or just plain struct literal
  construction at call sites.

After this phase, `cargo test` compiles cleanly; every integration test
fails at runtime because the binary has no filter; every unit test that
references a `todo!()` stub fails at runtime with a panic. The suite is
RED in a legible way — test names describe the feature's behavior, and
the panics / failures give a concrete punch-list for the phases below.

### Phase 2: BPF filter and fd plumbing

Add `install_seccomp_exec_filter() -> Result<OwnedFd>` to
`crates/nono/src/sandbox/linux.rs`, mirroring the shape of
`install_seccomp_proxy_filter`:

- BPF program: two `JEQ` instructions for `SYS_execve` and `SYS_execveat`;
  everything else `RET_ALLOW`; matches `RET_USER_NOTIF`.
- Install as a separate filter (not merged with the existing openat or proxy
  filters), so the three filters compose independently and each has its own
  listener fd.
- Export from `crates/nono/src/sandbox/mod.rs` alongside the existing
  primitives.

Extend the child-side install site in
`crates/nono-cli/src/exec_strategy.rs` to call the new install function when
the session's profile has `mediation.commands` non-empty. Send the new
listener fd to the parent via the existing SCM_RIGHTS transfer, adding one
more slot to the protocol. Gate all of this behind the same mediation-active
check.

**Tests flipped GREEN by this phase:** none by itself. Installing the BPF
filter without a handler leaves every trapped `execve` blocked forever
(the kernel queues a notification; nothing ever responds). This phase is
a prerequisite for Phase 3 and is not independently deployable. Phase 2
lands together with Phase 3 from a reviewability standpoint; they're
numbered separately only to keep the code diffs digestible.

### Phase 3: supervisor handler + three-way classification

Add `handle_exec_notification` in
`crates/nono-cli/src/exec_strategy/supervisor_linux.rs`, mirroring the shape
of the existing openat handler:

- `recv_notif` on the exec listener fd.
- Extract path arguments per syscall:
  - `SYS_execve`: path from `args[0]`.
  - `SYS_execveat`: path from `args[1]`, dirfd from `args[0]`, flags from
    `args[4]`. Dispatch the four variants (absolute, `AT_FDCWD`-relative,
    real-dirfd-relative, `AT_EMPTY_PATH`).
- Liveness check via `notif_id_valid` twice — once after the path read
  and dirfd resolution, once before responding. Matches the openat
  handler's existing pattern; catches notifications that became
  invalid because the child was killed.
- Resolve the raw path into an absolute resolved path via existing
  `resolve_notif_path` helpers and (for the `AT_EMPTY_PATH` case) direct
  `/proc/<tid>/fd/<dirfd>` readlink.
- Shim-prefix check on the pre-canonical resolved path.
- Otherwise canonicalize and check against the deny set.
- Respond with `continue_notif` for allow decisions and
  `respond_notif_errno(EACCES)` for deny.

Extend the supervisor's `poll`/event-loop in the same file to poll the new
listener fd in addition to the existing openat and proxy fds. Dispatch by fd,
not by syscall number.

Build the deny set at session start from the resolved real paths of
`mediation.commands`, canonicalize each, and make it accessible to the
handler.

**Tests flipped GREEN by this phase:** 2, 3, 6, 10, 11. Test 1 was
already GREEN. Tests 4, 5, 7, 8, 9 remain RED (awaiting shebang
handling and audit integration). After Phase 3, the direct-path exec
bypass is closed for simple direct invocations and `execveat` variants.

### Phase 4: shebang handling

Replace the `todo!()` in `check_shebang_chain` (and `parse_shebang`) with
the real implementation:

- In the handler, after a decision of `allow_unmediated` (the shim is
  never a script): open the canonical target, read the first 256
  bytes, check for `#!`, parse the interpreter token up to the first
  whitespace.
- Canonicalize the interpreter; check against the deny set. On hit, flip
  the decision to `deny` with reason `shebang_chain` and record the
  interpreter chain for the audit record.
- Otherwise recurse into the interpreter's file with `depth + 1`;
  terminate at `MAX_SHEBANG_RECURSION` with `ShebangResult::NotScript`
  (safe default: accept the outer decision so far).

**Tests flipped GREEN by this phase:** 4, 5. The `check_shebang_chain`
termination and `parse_shebang` unit tests also flip GREEN.

### Phase 5: TOCTOU double-read

In the handler, immediately before responding `CONTINUE`:

- Re-read the raw path string from the same `/proc/<tid>/mem` address,
  reusing the fd opened at the start of the handler (not re-opening).
  If the bytes differ from the first read, flip the decision to deny
  with reason `toctou_mismatch`. The shared fd avoids a re-trip
  through `ptrace_may_access` that fails under Yama
  `ptrace_scope=1` when the trapped task has been reparented mid-handler.

Deny decisions skip the double-read (they already fail the syscall; no
re-read happens kernel-side).

**Tests flipped GREEN by this phase:** none. The mitigation is internal
robustness against a race that the Phase 1 integration list doesn't
attempt to reproduce end-to-end, and a unit test would require
restructuring the handler around a mock user-memory reader (out of
scope for v1). A targeted multi-threaded end-to-end test is possible
but also out of scope.

### Phase 6: audit integration

Emit a `FilterAuditEvent` on `allow_unmediated` and `deny` decisions,
serializing it as JSONL to the same `~/.nono/sessions/audit.jsonl` file
the shim already writes to. Skip emission on `allow_shim` — the shim
downstream emits its own `AuditEvent` when the command completes, and a
filter-side record there would double-count. A new helper function in
the mediation audit module handles the append; no new file, no new
socket, no rotation changes. Populate fields per the Audit design
section above: `exit_code = Some(126)` on deny, `exit_code = None` on
allow_unmediated (matches existing `policy.rs:169` convention for
denied mediation), `reason` populated only on deny, `path` populated on
every filter event, `interpreter_chain` populated only on shebang-driven
denies.

**Tests flipped GREEN by this phase:** 7, 8. Test 9 was already GREEN
because no filter events existed; it stays GREEN because we deliberately
skip emission on `allow_shim`. After this phase, all 13 tests in the
Phase 1 suite are GREEN and the feature is complete.

### Phase 7: documentation and PR

- Update `CHANGELOG.md`.
- PR description summarizes this plan, links to it, and calls out the
  mechanical verification done in Phase 0 (with line numbers) so reviewers can
  confirm the design's assumptions without re-doing the investigation.

## Rollout

The feature is session-local and opt-in via the profile's `mediation.commands`.
Profiles that don't use mediation are unaffected. Profiles that use mediation
today will automatically pick up the exec filter once merged and upgraded.
There is no runtime toggle and no migration; the filter is either installed
for a given session or not, based on whether mediation is active.

For the Datadog workspaces distribution specifically (out of scope for this
PR but relevant to rollout timing): the Linux shadowfax profile enables
mediation by default, so the feature activates as soon as the nono binary
shipped by the workspaces AMI picks up this change. That rollout is governed
by the separate workspaces-side distribution mechanism (`update-tool` or
equivalent) and does not affect this PR's scope.

## Out of scope

- Landlock ABI v5/v6 features.
- ptrace-freeze TOCTOU closure.
- Fast-path BPF optimizations for the allow bucket. Not needed pending
  measurement.

## References

- [kipz/nono PR #17](https://github.com/kipz/nono/pull/17) (Linux porting fixes — prerequisite for building this
  work on Linux).
- `Documentation/userspace-api/seccomp_filter.rst` (kernel doc on seccomp
  user notification).
- `Documentation/userspace-api/landlock.rst` (kernel doc on Landlock ABI
  versions and what each adds).
- `include/linux/binfmts.h` (`BINPRM_BUF_SIZE`, `BINPRM_MAX_RECURSION`).
- `crates/nono/src/sandbox/linux.rs`: `install_seccomp_notify`,
  `install_seccomp_proxy_filter`, `recv_notif`, `deny_notif`,
  `continue_notif`, `respond_notif_errno`, `notif_id_valid`,
  `read_notif_path`, `resolve_notif_path`.
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`:
  `handle_seccomp_notification` (openat handler template for the new exec
  handler).
- `crates/nono-cli/src/mediation/session.rs`: universal audit shim creation
  (current audit scope we are matching).
- `crates/nono-shim/src/main.rs`: shim audit-event emission
  (`send_audit_event`).
