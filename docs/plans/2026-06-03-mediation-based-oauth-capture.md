# Mediation-Based OAuth Capture

**Date:** 2026-06-03
**Status:** Draft
**Context:** Replaces the keychain-rewrite approach in PR 40 ("upstream-tls-intercept-with-oauth-capture") with a mediation-shim-based design that does not modify the macOS keychain.

---

## Summary

PR 40 protects Anthropic OAuth tokens from prompt-injected agents by rewriting
the `Claude Code-credentials` keychain entry to hold `nono_<hex>` nonces
instead of real `sk-ant-…` bearers, persisting real tokens in a separate
nono-owned keychain entry. The proxy's TLS-intercept layer translates nonces
back to real tokens on egress to Anthropic-controlled hosts.

This design has produced two operational problems:

1. **Keychain ACL pain.** The nono-only ACL on the broker entry is keyed to
   the binary's code signature. For unsigned local builds this is a content
   hash, so every `cargo build` invalidates the trust grant and re-prompts.
   The rewrite of claude's own entry similarly trips a modify-access prompt.
2. **Profile conflict.** Shadowfax's `claude.json` profile mediates
   `security find-generic-password Claude Code-credentials` with an `approve`
   action so MCP plugins can read their own credentials out of the same
   JSON envelope (see "Keychain envelope structure" below). PR 40's
   rewrite changes the shape of `claudeAiOauth.*` in that envelope. The
   non-`claudeAiOauth` subtrees (which is where every current MCP plugin
   actually keeps its tokens) survive PR 40's rewrite, but the design
   couples nono's protection mechanism to the envelope's exact schema —
   any future Claude Code release that moves Anthropic tokens to a new
   path silently breaks the protection.

This document proposes moving the nonce substitution from the keychain
itself to the nono mediation shim. The keychain entry stays untouched, real
tokens never leave it via subprocess access, and the shim returns a
nonce-substituted JSON to any sandboxed caller of `security`.

The protection model is preserved for the agent-driven threat
(subprocess-based keychain reads). The implementation is substantially
smaller, eliminates the ACL prompts, and composes with profile mediation
rather than fighting it.

---

## Goals

- A prompt-injected agent reading `Claude Code-credentials` via
  `/usr/bin/security` sees `nono_<hex>` nonces in place of real Anthropic
  OAuth tokens.
- Every other field in the JSON envelope (`mcpOAuth.*`, future top-level
  keys, future per-server entries under `mcpOAuth`) passes through
  unchanged so any MCP plugin's own credentials continue to work without
  per-plugin profile rules.
- API calls bearing the substituted nonces against Anthropic hosts
  continue to work via the existing proxy translation path.
- No keychain rewrites. No `cargo build` re-prompts. No broker keychain
  entry.

## Non-goals

- macOS only. Linux is explicitly out of scope for this change.
- Closing the Mach-IPC gap. A plugin that reads the keychain via direct
  `SecItemCopyMatching()` (e.g., the npm `keytar` package) bypasses the
  mediation shim and gets real tokens. Accepted as a known limitation;
  no evidence of any current plugin doing this.
- Protecting tokens against prompt injection of `claude` itself. Claude is
  the host process and necessarily holds working credentials in memory at
  some point; durable on-disk representation is not the meaningful boundary
  here.

---

## Keychain envelope structure (validated)

Strings inspection of Claude Code 2.1.123 confirms the
`Claude Code-credentials` entry stores a JSON envelope with these
top-level structures relevant to auth:

```json
{
  "claudeAiOauth": {
    "accessToken": "sk-ant-oat01-…",
    "refreshToken": "sk-ant-ort01-…",
    "expiresAt": 1234567890000,
    "scopes": [...],
    "subscriptionType": "max",
    ...
  },
  "mcpOAuth": {
    "<server-key-hash>": {
      "serverName": "slack",
      "serverUrl": "https://mcp.slack.com/mcp",
      "accessToken": "<slack-oauth-bearer>",
      "refreshToken": "...",
      "expiresAt": ...,
      ...
    }
  }
}
```

- `claudeAiOauth` is the Anthropic identity. This is the only subtree
  this design rewrites.
- `mcpOAuth` is a map keyed by a server-config hash (function `SP` in the
  Claude binary). Each entry holds OAuth state for a *remote MCP server*
  Claude Code authenticated against on the user's behalf. Slack today
  lives here; every additional remote-MCP plugin Claude Code ships
  (Atlassian, Linear, etc.) will land in this same structure under its
  own key. None of these entries are touched by the design.

This validates the protection scope: nono shields the agent from the
Anthropic bearer without affecting any MCP plugin's credentials —
present or future — because plugins keep their credentials in
`mcpOAuth.*`, not in `claudeAiOauth.*`.

---

## Design

### Profile schema — extend `capture`

`capture` today runs the real binary, stores its stdout in the in-memory
token broker, and returns a single `nono_<hex>` nonce to the sandbox. Two
optional fields extend it for structured envelopes:

| Field          | Type            | Default | Description                                                                                                                                                                                            |
| -------------- | --------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `format`       | `"json"`        | absent  | Treat stdout as JSON. When set, `secret_paths` is required.                                                                                                                                            |
| `secret_paths` | array of string | absent  | Dotted JSON paths whose values are minted as separate nonces and substituted back into the envelope before returning to the sandbox. Each path must resolve to a string. Missing paths silently no-op. |

Without `format`, `capture` behaves identically to today: opaque stdout,
one nonce, env-var promotion at subsequent command exec.

With `format: "json"`, the shim parses stdout, mints a nonce per path,
registers each `(nonce, real_value)` pair in the same in-memory broker the
proxy already uses, substitutes nonces back into the JSON, and returns the
modified JSON as stdout. Other JSON fields pass through unchanged.

#### Example: protecting Anthropic OAuth fields in `Claude Code-credentials`

```json
{
  "name": "security",
  "intercept": [
    {
      "args_prefix": ["find-generic-password", "$USER", "Claude Code-credentials"],
      "action": {
        "type": "capture",
        "format": "json",
        "secret_paths": [
          "claudeAiOauth.accessToken",
          "claudeAiOauth.refreshToken"
        ]
      }
    },
    {
      "args_prefix": ["find-generic-password", "Claude Code-credentials", "$USER"],
      "action": {
        "type": "capture",
        "format": "json",
        "secret_paths": [
          "claudeAiOauth.accessToken",
          "claudeAiOauth.refreshToken"
        ]
      }
    }
  ]
}
```

The two rules cover the username-first and service-first argument
orderings shadowfax already had to support (PR 307).

### How the nonces are consumed downstream

`capture` today supports env-var promotion: a sandboxed program running
`GH_TOKEN=nono_abc gh issue list` triggers the shim to replace the nonce
with the real value before exec'ing `gh`. That path stays.

For the JSON-format case, the nonces leave the sandbox embedded in a
JSON envelope. Their downstream consumption is via HTTP — the proxy's
existing TLS-intercept layer translates `Authorization: Bearer nono_<hex>`
to the real bearer on egress to the three Anthropic OAuth-capture routes
(`api.anthropic.com`, `claude.ai`, `platform.claude.com`). Any
non-Anthropic destination receives a literal `nono_<hex>` and returns 401.

### Broker lifecycle

The in-memory `TokenBroker` in `crates/nono-cli/src/mediation/broker.rs`
is the single source of truth. Capture's `format: "json"` path mints
nonces via `broker.issue()` exactly as the regular path does; no new
broker primitives are needed.

Persistence is dropped. With the keychain rewrite gone, there is no need
for the broker to remember mappings across sessions: claude's keychain
always holds real tokens, the shim always re-mints fresh nonces on each
read, and the proxy's nonce table is rebuilt from those reads.

### What gets deleted from PR 40

| File / module                                                       | Change                                                                                                                                                                                                              |
| ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `crates/nono-cli/src/oauth_preflight.rs`                            | Delete `rewrite_keychain_oauth_entry` and all macOS keychain rewrite code. Keep API-key fail-closed detection. Linux paths in this module are out of scope.                                                          |
| `crates/nono-cli/src/mediation/broker_store.rs`                     | Delete in full. No durable broker store; broker is in-memory only.                                                                                                                                                  |
| `crates/nono-cli/src/proxy_runtime.rs` `build_broker()`             | Simplify to `TokenBroker::new()` — no `with_store` branch.                                                                                                                                                          |
| `crates/nono-cli/src/mediation/broker.rs` `TokenBroker::with_store` | Delete; `new()` is the only constructor.                                                                                                                                                                            |
| `crates/nono-cli/src/sandbox_prepare.rs` `read_keychain_item`       | Already converted to in-process API in the working tree. Keep — `should_auto_enable_claude_launch_services` still needs to detect whether claude has any auth state; that read continues to use the keychain entry. |

Approximate impact: ~500 lines deleted, ~100 lines added for the
`capture` extension.

---

## Implementation plan

### Phase 1 — nono changes (this branch)

1. Extend `mediation/policy.rs` capture-action schema to accept optional
   `format` and `secret_paths` fields. Update JSON-schema validation.
2. Implement `format: "json"` branch in the capture handler in
   `mediation/server.rs` (or wherever capture runs today): parse stdout,
   extract values at `secret_paths`, mint nonces, substitute, return.
3. Delete `oauth_preflight::rewrite_keychain_oauth_entry`, all of
   `mediation/broker_store.rs`, and the `with_store` path in `TokenBroker`.
4. Update `proxy_runtime::build_broker` to use the in-memory constructor.
5. Run unit tests, add coverage for the JSON path (matched paths,
   missing paths, non-string values, malformed JSON).

### Phase 2 — shadowfax profile change (coordinated PR)

Swap the existing `approve` rules in `deployments/darwin/profiles/claude.json`
(and `pi.json`) for the new `capture` + `format: "json"` rules. Land
this only after Phase 1 ships in nono — the rule references syntax that
older nono builds reject.

---

## Trade-offs and known limitations

### Mach-IPC gap (accepted)

A plugin that reads the keychain via direct Mach IPC (`SecItemCopyMatching`,
typically through the npm `keytar` native binding) bypasses the shim.
That plugin would see real tokens. Mitigations are limited:

- Seatbelt cannot filter Mach messages by content, so a per-service deny
  rule isn't expressible.
- A blanket Mach-lookup deny on `com.apple.SecurityServer` would break
  claude itself.
- Defense in depth: if such a plugin is identified in practice,
  shadowfax can add a process-level deny on its binary path.

No evidence of any plugin doing this today; both bundled
`claude-agent-sdk` and Slack MCP use subprocess access.

### Durable on-disk representation (accepted)

PR 40 keeps the durable on-disk representation of the OAuth tokens as
nonces. Direction B keeps it as real tokens. Whoever can read claude's
keychain entry with sufficient privilege (the user themselves, with
admin password, via Keychain Access.app or `security` outside any
sandbox) sees real tokens.

This is consistent with the user's existing trust model — the keychain
is the legitimate store for these credentials, the user has unrestricted
access to their own keychain, and the agent does not.

### Promotion semantics within the shim

The shim must handle the JSON-format case differently from the
existing capture path on the *promote* side. Today, promotion replaces
a nonce in an env var with the real value before exec. For the JSON
case there is no promotion — the nonces are consumed by the proxy at
HTTP egress, not by command exec.

Implementation: the broker stores `(nonce, real_value)` pairs
identically regardless of source. The env-var promotion path and the
proxy HTTP translation path both look up the same broker independently.
No coupling between them.

### Argument-ordering coverage

`security find-generic-password` accepts several argument orderings.
Shadowfax's existing rules handle two (username-first and service-first
positional). We should audit whether any other shape is in use — a
single missed ordering means the agent could fetch the entry through
the unmediated `approve` fallback. Action: add a regression test that
enumerates the orderings and verifies each routes to the JSON capture.

---

## Testing plan

### Unit

- `capture` with `format: "json"` and resolvable paths: mints nonces,
  substitutes, returns modified JSON.
- Missing path: silently no-ops on that path; other paths still
  substituted; non-string values left unchanged.
- Malformed JSON stdout: fails closed with an error to the sandbox
  (don't return raw stdout, which could leak the real value).
- Idempotence: running the same intercept twice on the same input
  produces two *different* nonces (broker mints fresh each call) but
  the same JSON shape.

### Integration

- Sandboxed program runs `security find-generic-password ... Claude Code-credentials`,
  parses the JSON, extracts `claudeAiOauth.accessToken`, makes an HTTPS
  GET to `api.anthropic.com/v1/me` with `Authorization: Bearer <token>`.
  Verify the proxy translates the nonce and the request succeeds.
- Same flow against a non-Anthropic host (e.g., `httpbin.org/headers`).
  Verify the request egresses with a literal `nono_<hex>` value and
  no real token is leaked.
- MCP plugin coexistence: a hand-crafted JSON envelope shaped like the
  validated structure above (`claudeAiOauth` + `mcpOAuth["<key>"]` with a
  realistic Slack-style entry) is returned by the shim with only
  `claudeAiOauth.{accessToken,refreshToken}` substituted; the entire
  `mcpOAuth` subtree — including `accessToken` fields *within* it —
  passes through unchanged. This regression-tests the field-path matching
  rules: `mcpOAuth.foo.accessToken` must not collide with the
  `claudeAiOauth.accessToken` pattern.

### Manual

- End-to-end `claude /login` inside nono with the new profile rules in
  place: capture should fire on the post-login keychain read.
- Already-authenticated user (real tokens in keychain before nono
  starts): no preflight rewrite required, but any sandboxed
  `security` call still returns nonces.
- `cargo build` between sessions: verify no keychain dialogs reappear
  (the ACL machinery that caused them is gone).

---

## Open questions

1. **Shadowfax PR sequencing.** The nono change and the profile change
   must land in a specific order: nono first (older shadowfax profiles
   continue to work because the new fields are additive), profile
   change after. Owner on the shadowfax side TBD; coordination cost is
   acknowledged as acceptable.
2. **Argument-ordering audit.** Confirm via shadowfax that the two
   orderings (`["find-generic-password", "$USER", "Claude Code-credentials"]`
   and `["find-generic-password", "Claude Code-credentials", "$USER"]`)
   are the only forms used in practice. Anything else routes to the
   unmediated fallback and leaks.
