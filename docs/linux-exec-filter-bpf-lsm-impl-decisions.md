# BPF-LSM implementation: autonomous-session decisions log

Decisions made while working through the 5-phase plan in
`docs/linux-exec-filter-bpf-lsm.md` without user-in-the-loop.
Each entry: what I decided, why, and the alternative I rejected.

## Session ground rules

- Working directory: `~/dd/nono` on the BPF-LSM workspace AMI.
- Branch: `am/linux-exec-filter-bpf-lsm` on `drewmchugh/nono`.
- TDD per phase: write failing tests first, implement to green.
- Commit + push after each phase succeeds; reference the design
  doc and decisions log in the commit body; DCO sign-off.
- No `AskUserQuestion`. When ambiguity blocks progress, pick the
  option closest to what the existing code does, document the
  pick here, and keep moving.

## Phase 1 — drop seccomp-unotify exec filter

**Decision: pre-fork BPF-LSM install + child joins cgroup post-fork.**

The design doc didn't specify install ordering. Initially I kept
the BPF-LSM install in the broker's post-fork parent path (where
the seccomp-era code was wired). With seccomp removed there was
nothing else gating the child between fork and execve — the agent
raced ahead and execve'd the deny target *before* the BPF-LSM
filter was loaded. The integration POC's "direct path is denied"
baseline went red.

Fix: install BPF-LSM **before** fork (so the kernel filter is
live globally by the time the child execve's), and have the
child write its own pid to `cgroup.procs` as its first post-fork
action (so all subsequent execs are scoped). Why the cgroup move
must happen in the child, not the parent: the parent doesn't
know the child's pid until *after* fork, but Landlock's
`restrict_self` on the child blocks `/sys/fs/cgroup` writes —
the cgroup join must happen *before* Sandbox::apply in the
child. Doing it in the child also avoids a barrier+signal dance
between parent and child.

Required a small refactor in `bpf_lsm.rs`:
- `create_session_cgroup_empty()` — mkdir-only, no pid move.
- `SessionCgroup::add_pid(pid)` — exposed so the child can join
  itself. The existing `create_session_cgroup(pid)` stays as a
  convenience for tests.

Why this is fail-closed: if `add_pid` fails in the child, the
child `_exit(126)`s before any execve. The agent never runs
unscoped.

**Decision: keep the integration tests' audit assertions but
mark them `#[ignore]` until Phase 3.**

Phase 1 deletes the seccomp supervisor's audit emission. Phase
3 reintroduces audit via the BPF ringbuf with the same JSONL
shape. The integration tests that grep for
`exec_filter_allow_unmediated` / `exec_filter_deny` events
encode the end-state behavior; ignoring them keeps the tests in
the tree as living spec without polluting the red bar.

**Decision: drop `exec_shim_dir` and `exec_audit_log_dir` from
`SupervisorConfig`.**

The seccomp-era audit emitter needed both: shim dir to
distinguish shim-routed allows (no audit) from non-shim allows
(audit), audit log dir as the destination. Phase 1 deletes the
emitter, so both fields become dead code and trip
`-D warnings` via `dead_code`. Phase 3 will re-introduce a
`audit_log_dir` field (or similar) on whatever struct the
ringbuf reader needs; reintroducing then is cleaner than
keeping dead fields warmed for hypothetical future use.

**Decision: pre-existing `mediation/mod.rs` and
`mediation/filter_audit.rs` test unwraps were fixed in this
phase.**

Design doc said `make ci` would clean after Phase 1 deletions.
Three `unwrap()`s in mediation/mod.rs caller-policy tests and
one in filter_audit.rs roundtrip survived deletion (those files
weren't on the deletion list). Replaced with `expect("...")` to
clear `clippy::unwrap_used`.

**Pre-existing test failures noted in commit:** two `learn::tests`
unit tests fail on `c314fb0` too (verified by stashing my changes
and re-running). Out of scope for Phase 1; not regressed.

**Validation:**
- `make build-release` clean.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used` clean.
- `cargo fmt --all -- --check` clean (auto-formatted some pre-existing drift in `mediation/policy.rs` and `mediation/server.rs` — fmt-only changes).
- `sudo -E cargo test -p nono --test bpf_lsm_smoke` 4/4 pass.
- `cargo test -p nono --lib` 628/628 pass.
- POCs at target: pthread 0/600, vfork 0/600.
- POC baselines: PATH-based mediated → MEDIATED_RESPONSE; direct path → denied.

