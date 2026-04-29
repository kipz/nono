# vfork-bomb residual: investigation & decisions log

Working log for closing the vfork-bomb TOCTOU residual on PR kipz/nono#20.

## Context (start of investigation)

- PR #20 ships a seccomp-unotify exec filter that traps `execve`/`execveat` and
  classifies into `allow_shim` / `deny` / `allow_unmediated`.
- Comment 4337852261 → commit `05b26c8` added a `Threads>1` denial in the
  supervisor: if the trapped tgid has more than one thread, refuse to CONTINUE
  because a sibling can swap the path buffer between supervisor classification
  and the kernel's post-CONTINUE re-read.
- Comment 4342769948 demonstrates that this is bypassed by **vfork-bomb**:
  the parent has many threads, but the parent calls `vfork()` → child runs
  in a new tgid (Threads=1) yet shares the parent's address space. The
  swap thread lives in the *parent* tgid; the supervisor's `Threads` check
  only looks at the *child* tgid and misses it. 6/300 → 22/300 bypasses
  observed.

## Constraints from issue 3

- Workspace AMI today does NOT enable BPF-LSM (`/sys/kernel/security/lsm` =
  `lockdown,capability,landlock,yama,apparmor`).
- BPF-LSM is the structural fix but requires a workspaces-team AMI change
  to add `lsm=...,bpf` to the boot cmdline. Out of scope for a same-day fix.
- Userspace closure path A (block vfork/clone(CLONE_VM,!CLONE_THREAD)/clone3
  at seccomp) and path B (deny execve when MM is shared via kcmp(KCMP_VM))
  both break Go runtime / glibc 2.34+ posix_spawn → break bazel / gh /
  kubectl / terraform.

## Goal of this session

Close the vfork residual on the **userspace path** (current PR), in a way
that:
- Does not regress on Go programs / posix_spawn / Bun / Node / etc.
- Does not require any AMI/kernel change (so it ships in this PR).
- Is robust to attackers using vfork or clone(CLONE_VM, !CLONE_THREAD).

If that's impossible, fall back to BPF-LSM and accept the AMI dependency.

---

## Decisions and findings (chronological)

### 2026-04-29 — environment recon

- Workspace LSM stack: `lockdown,capability,landlock,yama,apparmor` (no `bpf`).
- Kernel: 6.8.0-1051-aws, x86_64.
- `/proc/sys/kernel/yama/ptrace_scope` = 1 → tracer must be ancestor of tracee.
- `/proc/sys/kernel/seccomp/actions_avail` includes `user_notif`.
- Container caps include `cap_bpf`, `cap_sys_admin`, `cap_perfmon`. User `bits`
  has empty effective caps but NOPASSWD sudo.
- `/usr/bin/nono` is a regular root-owned exe with no file caps.

### 2026-04-29 — reproduced vfork bypass

Built `target/release/nono` from current `am/linux-exec-filter` (post-6c006fb,
multi-threaded check in place). Ran
`ATTACKER_SRC=vfork_attacker.c ATTEMPTS=300 run_test.sh`:

- BYPASS: 29/300 (~10%)
- Mediated/Denied: 32
- Other/error: 239 (mostly stderr noise from subprocesses with no
  NONO_MEDIATION_SOCKET — not a problem with the test harness, just chatty)

So the vfork bypass is empirically real on this branch.

### 2026-04-29 — fix options considered

| Option | Verdict | Reason |
|---|---|---|
| A. seccomp-deny vfork/clone(CLONE_VM,!CLONE_THREAD)/clone3 | rejected | Breaks Go's `syscall.ForkExec` and glibc 2.34+ `posix_spawn`. End-to-end break of bazel/gh/kubectl/terraform on the workspace. |
| B. kcmp(KCMP_VM) deny on shared MM | rejected | Same population as (A) — every legit Go subprocess shares MM with parent during vfork window. Breaks the same fleet of tooling. |
| C. BPF-LSM @ bprm_check_security | rejected for now | Right structural fix, but requires `lsm=...,bpf` in kernel cmdline. Not present on the workspace AMI. Out of scope without an AMI change. |
| D. ptrace-freeze siblings during the trap | rejected by design doc | Per-exec cost scales with thread count; tracer exclusivity; bug surface. Same objections still apply. |
| E. Multi-read detection of attacker swap | rejected | Probabilistic, not structural. Does nothing for the kernel's post-CONTINUE re-read window. |
| **F. ptrace `PTRACE_O_TRACEEXEC` on the trapped tid; verify `/proc/<tid>/exe` post-exec; SIGKILL on deny** | **chosen** | Structural. Trapped tid is paused at the kernel's exec trace event *before* the new image executes any user code. `/proc/<tid>/exe` reflects what the kernel actually loaded, regardless of the user-memory race. Per-exec cost is ~5 syscalls (seize, setopts, waitpid, readlink, detach), independent of thread count. Tracer exclusivity is bounded to microseconds and only on the trapped tid. Bug surface is just `PTRACE_O_TRACEEXEC` which is widely used. |

### 2026-04-29 — design F in detail

#### Why TRACEEXEC closes the race structurally

The seccomp-notify TOCTOU comes from the kernel re-reading `args[0]` from
user memory *after* the supervisor returns CONTINUE. By the time the kernel
hits `bprm_check_security` and (later) the `ptrace_event(PTRACE_EVENT_EXEC,
…)` stop, the kernel has already done `getname()` and resolved the binary
into `bprm->file`. Whatever the kernel actually loaded is reflected in
`/proc/<tid>/exe` at the TRACEEXEC stop. The new image has not started
executing yet — `ptrace_event(PTRACE_EVENT_EXEC, …)` fires inside
`exec_binprm` *before* `start_thread()` transfers control to the new
binary's entry point.

So at the TRACEEXEC stop:
- `/proc/<tid>/exe` is the kernel's authoritative answer to "what binary
  did this exec actually load."
- The new image has executed zero user instructions — SIGKILL at this
  point is an atomic, no-side-effect cancellation.
- The user-memory race on `args[0]` is irrelevant because we aren't
  trusting it anymore; we're trusting `/proc/<tid>/exe`.

#### Sequence

1. Trap fires. Supervisor reads notification, reads path from
   `/proc/<tid>/mem`, classifies (existing logic).
2. If decision is `Deny`: respond `EACCES` immediately (existing path).
3. If decision is `Allow*`:
   a. `PTRACE_SEIZE(tid, options=PTRACE_O_TRACEEXEC)`.
   b. Respond `CONTINUE` to seccomp.
   c. `waitpid(tid, …, __WALL)` until either:
      - `PTRACE_EVENT_EXEC` stop → readlink `/proc/<tid>/exe`,
        canonicalize, check against deny set. If in deny set,
        `kill(tid, SIGKILL)` and emit a deny audit event with reason
        `post_exec_deny`. Otherwise `PTRACE_DETACH`.
      - exit/signal-death → no exec happened (or the task died);
        nothing to do.
      - bounded timeout (failed exec leaves no event) →
        `PTRACE_INTERRUPT`, drain the resulting stop, then `PTRACE_DETACH`.

#### Privilege check

- The supervisor (broker) runs as the same user as the agent. Same UID
  → ptrace_may_access permits attach.
- Yama `ptrace_scope=1` requires tracer to be an ancestor of tracee.
  The broker is a direct ancestor of every sandbox descendant. ✓
- The broker has `PR_SET_CHILD_SUBREAPER` already; sub-reaping isn't
  needed for ptrace but ensures we see exit status of orphaned
  descendants.

#### Why this isn't the design doc's rejected "ptrace-freeze siblings"

The design doc's objections were to a scheme that ptrace-freezes every
sibling thread sharing the MM, scaling per-exec cost with thread count
and creating a long ptrace window. This scheme:

- Attaches to **one** tid (the trapped one), not its siblings.
- Holds the attachment for **microseconds** — just long enough to see
  the TRACEEXEC stop and decide.
- Adds `~5` syscalls per exec, constant, independent of thread count.

#### What about `multi_threaded_unsafe`?

The existing `Threads > 1` check in commit 6c006fb stays. It denies the
classic pthread-attack pattern fast, before we even reach the seize
step. With TRACEEXEC the post-exec check would also catch the pthread
case (the swapped target is whatever the kernel loaded, and we'd kill
on deny). But the early-deny is cheap and matches a structurally
suspicious pattern, so keeping it is defense-in-depth at zero cost.

### 2026-04-29 — userspace ptrace approach has irreducible kill race; switching to BPF-LSM

Tried four variants of post-exec kill at the `PTRACE_EVENT_EXEC` stop:

| Variant | Result on 50-attempt vfork POC |
|---|---|
| `ptrace::detach(trapped, SIGKILL)` (single call) | 5–9/50 bypasses; tracee state goes from `t (tracing stop)` → `R (running)` after the detach call, and runs user code in the new image before the queued `SIGKILL` is processed |
| `kill(SIGKILL)` then `ptrace::detach(None)` | 0/N bypasses on the deny path, **but** the natural parent's `wait4(child)` hangs forever because the death event is consumed by the ptracer (us); the agent's process tree deadlocks |
| Skip the post-exec kill entirely (just detach) | 100% of races bypass (back to baseline) |
| Multiple polls + `PTRACE_INTERRUPT` fallback | Same as variant 1: tracee runs after detach, queued kill arrives too late |

**Why this is structurally hard.** `PTRACE_EVENT_EXEC` fires inside
`exec_binprm` after `search_binary_handler` has resolved the binary
but before `execve` returns to user mode. The tracee is in
`TASK_TRACED`, paused. Two things can happen on tracer's response:

- **Detach with signal**: the kernel sets `child->exit_code = sig` and
  calls `__ptrace_detach`, which `signal_wake_up`s the tracee. Tracee
  resumes from the `schedule()` inside `ptrace_stop`, runs the
  remainder of `exec_binprm`, returns from the syscall. Empirically on
  Linux 6.8 the queued `SIGKILL` is **not** delivered before the
  tracee returns to user mode for at least some scheduling outcomes —
  the tracee runs the new image's first instructions and races our
  kill.
- **Kill while traced + detach**: `SIGKILL` reliably kills the tracee
  (it's "magic" — bypasses ptrace), but the death notification routes
  to the tracer, not the natural parent. The natural parent's
  `wait4` hangs in `do_wait`. Detaching after the kill is too late;
  the task is already in `EXIT_ZOMBIE` and `__ptrace_unlink`'s
  re-parent step happens after the death event has already been
  consumed by the tracer.

The race is in the kernel's `ptrace_stop` resumption logic; it isn't
fixable from userspace without one side of the trade-off.

**Switching to BPF-LSM.** The user has confirmed AMI changes are
acceptable. BPF-LSM at `bprm_check_security` runs **inside** the
kernel's exec path, after the binary is resolved (`bprm->file`,
`bprm->filename` populated) and before exec is committed. Returning
`-EACCES` from the LSM program causes `do_execveat_common` to fail
with `EACCES` and the syscall returns to userspace with that errno
— no race, no separate kill, no detach dance, the natural parent's
`wait4` sees a normal `execve` failure (not a death).

Confirmed availability on this workspace:

- `CONFIG_BPF_LSM=y`: yes — `bpf_lsm_bprm_check_security` symbol is in
  `/proc/kallsyms`.
- `/sys/kernel/security/lsm` active list: `lockdown,capability,
  landlock,yama,apparmor` — **does not include `bpf`**. To activate,
  the kernel cmdline needs `lsm=...,bpf`. The active LSM list is
  immutable after boot, so this needs an AMI build + new workspace
  (or a host reboot with an updated grub config).

#### Iteration 1 → 17/300 bypasses (vs. 29/300 baseline) — shebang gap

First implementation checked only `/proc/<tid>/exe` against the deny set
at the TRACEEXEC stop. Bypasses dropped but didn't go to zero. Cause:
when the kernel resolves a `#!`-script, the loaded image is the
**interpreter** (`/bin/sh`), not the script. `/proc/<tid>/exe` →
`/bin/sh`, which isn't in the deny set, so we let the kernel run it,
and the interpreter then runs the script body — the deny target
ran.

The vfork POC's `testbin` is a shebang script (`#!/bin/sh\necho
REAL_BINARY_RAN`). Bypass mechanism: attacker swaps `args[0]` to the
script path during the kernel's post-CONTINUE re-read; kernel
resolves the script through `binfmt_script`, loads `/bin/sh`,
TRACEEXEC fires for `/bin/sh`. We need to also consult the
**original execve filename** the kernel actually used (not the
interpreter).

Fix: read `/proc/<tid>/auxv` at TRACEEXEC, find the `AT_EXECFN` entry,
dereference its pointer via `/proc/<tid>/mem`. `AT_EXECFN` is set to
`bprm->filename`, which is the **original `getname()` result** — the
path the kernel actually resolved post-race, not the interpreter
that `binfmt_script` chained to. Check the canonicalized AT_EXECFN
against the deny set in addition to `/proc/<tid>/exe`. Both checks
are robust to vfork tampering: by the time TRACEEXEC fires, the
kernel has called `flush_old_exec` → child has a private MM — vfork
parent's threads can no longer write to AT_EXECFN's storage.

#### Non-goals / explicit residuals

- Hardlink evasion: deny set stores canonical paths; hardlinking a
  deny-set binary at a different path bypasses the canonical-path
  comparison. Inherited from the pre-fix exec filter; not addressed
  here. Future fix: deny set keyed by `(dev, ino)` instead of path.
- Kernel exec failures (file exists, canonicalize succeeds, but
  `exec_binprm` fails for arch/format reasons): no TRACEEXEC fires.
  Falls through to the bounded timeout + `PTRACE_INTERRUPT` path.
  Adds a few hundred ms of supervisor stall on these (rare) cases;
  acceptable.


---

### 2026-04-29 — BPF-LSM implementation landed (Phases 7 + 8)

Phase 7 (`bdcfce0`): library scaffold.
- BPF C program at `crates/nono/src/bpf/exec_filter.bpf.c`.
- libbpf-cargo build pipeline in `crates/nono/build.rs`.
- Loader API in `crates/nono/src/sandbox/bpf_lsm.rs`:
  `is_bpf_lsm_available()`, `install_exec_filter(deny_paths,
  agent_pid)`, RAII `ExecFilterHandle`.
- Smoke test at `crates/nono/tests/bpf_lsm_smoke.rs`. Validates
  load + verifier path on every `cargo test`. Attach validation
  is gated on `bpf` being in the active LSM stack.

Phase 8 (`9dc64fb` + `6896e63`): broker integration.
- Broker installs the BPF-LSM filter immediately after `fork()`,
  scoped to the agent's process tree by writing the agent's pid
  into the program's scope map.
- Falls back silently to seccomp-unotify-only when BPF-LSM is
  unreachable. Emits a warn-level log line distinguishing
  `NotInActiveLsm` (reboot needed) from other errors (CAP_BPF
  needed).
- nono-cli's `bpf-lsm` Cargo feature propagates to nono; both
  default-on for Linux.

What's been validated locally (workspace without `bpf` in active
LSM list):
- BPF program compiles, passes verifier.
- Loader returns `NotInActiveLsm` on this kernel as expected.
- Smoke test forces past the LSM-list check and confirms the
  load+attach pipeline succeeds at the kernel level.
- Existing seccomp filter still active (vfork POC bypass count
  unchanged at 1/10 — the vfork residual continues to leak on
  this kernel until the AMI rolls out).

Pending end-to-end validation, queued for the new workspace
booted from `am/bpf-lsm-workspace-ami` (dd-source):
- `cat /sys/kernel/security/lsm` includes `bpf`.
- `setcap cap_bpf+ep /usr/bin/nono` (or run via sudo) for the
  BPF program load.
- Smoke test runs the full attach path:
  `sudo -E cargo test -p nono --test bpf_lsm_smoke`.
- vfork POC: `ATTACKER_SRC=vfork_attacker.c ATTEMPTS=600
  bash run_test.sh` — target 0/600.
- pthread POC: same but ATTACKER_SRC=attacker.c — must remain
  0/N (multi-threaded check still active).

## Testing procedure on the new workspace

Once the new workspace boots from the AMI with `bpf` in the
active LSM list:

```bash
# 1. Verify kernel cmdline picked up the change.
cat /proc/cmdline | grep -o 'lsm=[^ ]*'
# expect: lsm=lockdown,capability,landlock,yama,apparmor,bpf

cat /sys/kernel/security/lsm
# expect: lockdown,capability,landlock,yama,apparmor,bpf

# 2. Pull the nono branch.
cd ~/go/src/github.com/DataDog/nono
git fetch drewmchugh am/linux-exec-filter
git checkout drewmchugh/am/linux-exec-filter

# 3. Build.
make build-cli

# 4. Give the binary CAP_BPF (one-time, requires root).
sudo setcap cap_bpf+ep target/release/nono

# 5. Run smoke test (full attach path now reachable).
cargo test -p nono --test bpf_lsm_smoke -- --nocapture
# expect: 3 passed, including the attach test.

# 6. Run vfork POC.
NONO=$(pwd)/target/release/nono \
    SHIM=$(pwd)/target/release/nono-shim \
    ATTEMPTS=600 \
    ATTACKER_SRC=vfork_attacker.c \
    LABEL=bpf-lsm-vfork \
    bash /tmp/exec-filter-poc/run_test.sh
# target: BYPASS_COUNT=0

# 7. Run pthread POC (regression check).
ATTACKER_SRC=attacker.c LABEL=bpf-lsm-pthread \
    NONO=$(pwd)/target/release/nono \
    SHIM=$(pwd)/target/release/nono-shim \
    ATTEMPTS=600 \
    bash /tmp/exec-filter-poc/run_test.sh
# target: BYPASS_COUNT=0 (multi-threaded check still active)
```

If step 6 hits BYPASS_COUNT > 0, debug with the
`NONO_EXEC_FILTER_DEBUG_LOG=/tmp/dbg.log` env var (carried over
from the userspace-iteration debugging — Phase 7 didn't remove
it) and inspect what `/proc/<tid>/exe` and AT_EXECFN looked like
at the bypass moment.


---

### 2026-04-29 — closed daemonize residual via cgroup-based scoping

The first BPF-LSM cut (commits `bdcfce0`–`6896e63`) scoped the
deny check by walking each task's `real_parent` chain looking
for the agent's pid. That left a real bypass: an agent
descendant that double-forks and reparents to the broker
(which is `PR_SET_CHILD_SUBREAPER`) severs the chain to the
agent, and the daemonized grandchild can then exec a deny-set
binary unfiltered. Same severity as the vfork-bomb the BPF-LSM
work was supposed to close — wrong to ship that way.

Switched scoping from parent-chain walk to **cgroup
membership**. The broker creates a per-session cgroup
(`/sys/fs/cgroup/<self>/nono-session-<broker-pid>`) at session
start, places the agent in it via `cgroup.procs`, and writes the
cgroup's id (cgroup directory inode in v2) into the BPF
program's scope map. The hook now calls
`bpf_get_current_cgroup_id()` and only applies the deny check
when current is in the agent's cgroup.

Why this closes daemonize: cgroup membership is **inherited on
fork()** and **unaffected by reparenting**. A daemonized
grandchild stays in the agent's cgroup regardless of who its
parent currently is, so the BPF check still fires.

Implementation:
- `crates/nono/src/bpf/exec_filter.bpf.c`: replaced
  `has_ancestor_pid` with a single
  `bpf_get_current_cgroup_id()` call against the scope map.
- `crates/nono/src/sandbox/bpf_lsm.rs`: new
  `SessionCgroup` RAII type and `create_session_cgroup(pid)`
  helper. `install_exec_filter` signature changed:
  `(deny_paths, agent_cgroup_id: u64)` instead of
  `(deny_paths, agent_pid: u32)`.
- `crates/nono-cli/src/exec_strategy.rs`: broker integration
  creates the cgroup before installing the filter, holds both
  handles for the lifetime of the supervisor loop, drops them
  in the right order on session end.
- Smoke test gains a `create_session_cgroup_roundtrip` case
  that creates + verifies + removes a real cgroup (skipped
  cleanly when run without CAP_SYS_ADMIN).

Privilege impact: cgroup creation requires write access to the
parent cgroup. On the workspace's `/init` cgroup (root-owned,
no delegation), this needs `CAP_SYS_ADMIN`. So the deployment
story now requires `setcap cap_bpf,cap_sys_admin+ep
/usr/bin/nono` (or running via sudo). Documented in the warn
log emitted on cgroup-create failure.

Cleanup: `SessionCgroup`'s `Drop` impl migrates remaining tasks
back to the parent cgroup (`cgroup.procs` writes one pid at a
time, looped to handle forks during migration), then `rmdir`s
the session cgroup. Bounded loop (16 iterations) so a runaway
session can't pin the broker on shutdown.

---

### 2026-04-29 — end-to-end validation on the BPF-LSM workspace

Workspace: AMI booted from `am/bpf-lsm-workspace-ami`, kernel
`6.8.0-1052-aws`. `/sys/kernel/security/lsm` =
`lockdown,capability,landlock,yama,apparmor,bpf` ✓.

Build: `make build-release` from `am/linux-exec-filter-bpf-lsm`
@ `c957e11` succeeds after installing `libdbus-1-dev`. No other
system-lib gaps surface on this AMI.

Smoke test (`sudo -E cargo test -p nono --test bpf_lsm_smoke -- --nocapture`):

```
test create_session_cgroup_roundtrip ... ok
test install_with_real_binary_in_deny_set ... ok
test force_load_validates_verifier_acceptance ... ok
test install_exec_filter_with_empty_deny_set ... ok
test result: ok. 4 passed; 0 failed
```

All four pass, including the cgroup-roundtrip and full
attach-validation paths that were skipped on the prior
workspace. So the load + attach pipeline works end-to-end on
this kernel.

#### Caps surprise: cap_dac_override is needed too

`setcap cap_bpf,cap_sys_admin+ep target/release/nono` was
not enough on this AMI. First POC run with that cap set:

```
 Attack 2 (vfork): BYPASS (49 hits) — residual confirmed ✗
```

Broker log explained why:

```
WARN BPF-LSM exec filter unavailable: per-session cgroup
creation failed (mkdir(/sys/fs/cgroup/init/nono-session-22653)
failed: Permission denied (os error 13) (CAP_SYS_ADMIN or
cgroup delegation required))
```

Root cause: this AMI's parent cgroup is root-owned with mode
`0755` and no delegation. cgroup v2 `mkdir` goes through normal
VFS DAC checks before the cgroup-namespace `CAP_SYS_ADMIN`
check. `CAP_SYS_ADMIN` does **not** override DAC — only
`CAP_DAC_OVERRIDE` (or `CAP_DAC_READ_SEARCH` for read paths)
does. So with cap_bpf+cap_sys_admin only, mkdir EACCES'd, the
cgroup-create branch fell through to the fallback (warn-and-
continue with seccomp-only), and the vfork-bomb residual was
right back at the unmediated rate.

Re-ran with:

```
sudo setcap cap_bpf,cap_sys_admin,cap_dac_override+ep \
    target/release/nono
```

Broker now logs `BPF-LSM exec filter active: agent_pid=…
cgroup_id=… deny_entries=1 (vfork-bomb residual closed via
kernel-side hook; daemonize residual closed via cgroup
scoping)` at session start, and the POC results flip to
target:

```
 Attack 1 (pthread): BLOCKED (0 hits)  — Threads>1 check working ✓
 Attack 2 (vfork):   not observed in 600 attempts
```

Vfork run detail: 0 bypasses / 83 denied / 517 other (the
"other" bucket is timing variance in the attacker — wrong-
observation-point classifications, not bypasses; what matters
is that the kernel never loaded the deny-target image, which
is what BYPASS=0 measures).

#### Action items from the validation

1. Fix the broker's warn message and the smoke-test docstring
   to recommend `cap_bpf,cap_sys_admin,cap_dac_override+ep`
   on AMIs that don't delegate the agent's parent cgroup.
   The current message ("typically setcap cap_sys_admin+ep")
   is misleading — operators on this AMI will follow it and
   silently end up on the seccomp-only path, undoing the
   whole BPF-LSM landing.
2. Update README/install docs with the same correction.
3. Longer-term: consider a kernel-level cgroup delegation
   path (systemd unit with `Delegate=yes`) so the broker can
   create sub-cgroups without DAC override, narrowing the
   privilege footprint.

#### Validation summary

| Check | Result |
|---|---|
| `bpf` in active LSM list | ✓ |
| `make build-release` (after `apt install libdbus-1-dev`) | ✓ |
| Smoke test (4 cases, sudo) | ✓ 4/4 |
| BPF-LSM activation log at session start | ✓ (after cap_dac_override) |
| Pthread POC, 600 attempts | ✓ 0 bypass / 600 denied |
| Vfork POC, 600 attempts | ✓ 0 bypass / 83 denied / 517 other |
| Vfork POC w/o cap_dac_override (sanity) | ✗ 49 bypass / 54 denied — fallback to seccomp-only confirmed |

The BPF-LSM landing closes the vfork-bomb residual on this
kernel as designed. Only blocker for shipping is the caps
documentation correction above.
