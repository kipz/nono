# Design: `proxy_provisioned_credential` capture type

**Status:** v1 implementation landed in `christine.le/gateway-mediation` (PR D).
**Date:** 2026-06-11

## Motivation

`credential_routes` had two capture types:

- **`oauth_intercept`** — claude runs an OAuth `/login` flow; the proxy
  TLS-intercepts the response, mints `nono_<hex>` nonces, substitutes them
  into the response body. Claude caches the nonce; on every API call the
  proxy resolves it back to the real OAuth bearer at egress.
- **`helper_command`** — claude runs an `apiKeyHelper`-style command in
  the sandbox; the mediation shim intercepts in the parent, runs the
  real binary there, mints a nonce, returns the nonce to claude. Same
  egress resolution pattern.

Both rely on claude being the actor: claude triggers the credential
fetch, claude holds the nonce, the proxy resolves the nonce. That works
but couples nono's design to claude's auth resolution order (apiKeyHelper
beats OAuth keychain, etc.) and forces the user to maintain agent-side
configuration that aligns with the proxy's expectations.

The new capture type **`proxy_provisioned_credential`** inverts the
relationship: **the proxy itself fetches the credential in its parent
process, caches it, and substitutes it on egress.** The agent's
credential surface becomes irrelevant — the proxy is authoritative.

This generalises to other providers (Codex with OpenAI, internal
gateways with arbitrary tokens) without per-provider scaffolding in
either the agent or nono. The provider declares one
`credential_routes` entry; the rest is plumbing nono already has.

## Design (v1, shipped)

### Schema

```rust
enum CredentialRouteCapture {
    OauthIntercept { token_url_match, refresh_url_match },
    HelperCommand  { command, args_prefix },
    ProxyProvisionedCredential {
        source: ProvisionSource,
    },
}

enum ProvisionSource {
    Command {
        command: String,
        args: Vec<String>,
        env: BTreeMap<String, String>,
    },
}
```

`source` is a discriminated union to leave room for future sources
without renaming the variant. v1 only ships `command`.

### Lifecycle

1. **Schema resolution** (CLI). At sandbox prep, `resolve_credential_routes`
   collects all `proxy_provisioned_credential` routes. The CLI synthesises
   one `nono_proxy::config::RouteConfig` per entry, sets
   `provisioned_credential_route: Some(name)` so the proxy egress path
   knows to substitute, and translates the CLI's `ProvisionSource` into
   the proxy's `nono_proxy::provisioned::ProvisionSource` (different
   crates, identical shape).

2. **Auto-injection of mediation rule** (CLI). For each
   `proxy_provisioned_credential` route, the CLI auto-injects a `respond`
   mediation rule on the route's `source.command` (matching args_prefix).
   The rule returns `nono_provisioned_DO_NOT_USE_proxy_handles_egress\n`
   (hardcoded sentinel) with exit code 0. Three conflict cases:

   | Existing rule on same command | Outcome |
   |---|---|
   | None | Auto-inject |
   | `respond` rule with overlapping args | Skip; user's rule serves the same purpose |
   | `capture` rule with overlapping args | **Refuse startup** — that would let claude actually run the helper in the sandbox |

3. **Provisioning at startup** (proxy). `start_proxy_runtime` calls
   `ProvisionedStore::provision_all` with a `HashMap<route_name, ProvisionSource>`.
   Each source runs its command in the proxy parent (unsandboxed) via
   `tokio::process::Command`, with a 30s timeout. Trimmed stdout becomes
   the cached credential, wrapped in `Zeroizing<String>`. Any failure
   (non-zero exit, empty stdout, timeout, spawn failure) fails proxy
   startup with a clear `ProxyError::Config`.

4. **Egress substitution** (proxy). When a request arrives at the proxy
   on a route with `provisioned_credential_route: Some(name)`:
   - `tls_intercept/handle.rs` and `reverse.rs` both consult
     `ProvisionedStore::get(name)`.
   - For `tls_intercept`: if the inbound bearer header is empty, return
     401 to the sandbox with a clear "no credential header" message
     (avoids silently authenticating an agent that didn't authenticate).
     Otherwise strip the inbound header, inject the provisioned
     credential formatted per `bearer.format`.
   - For `reverse.rs`: proxy-provisioned takes priority over the
     existing OAuth pass-through and static-credential paths. Inbound
     bearer is discarded; provisioned credential replaces it.

5. **Refresh on auth failure** (proxy, v1: fire-and-forget). When
   upstream returns 401 or 403 on a proxy-provisioned route,
   `tls_intercept/handle.rs` spawns a tokio task to call
   `ProvisionedStore::refresh(name)`. The current request still
   completes with the upstream's failure status; the next request on
   the same route sees the fresh credential.

   Refresh is debounced via a per-route `Mutex` so a burst of
   concurrent 401s doesn't spawn parallel helper subprocesses.

### Inbound auth gating

`tls_intercept/handle.rs` returns 401 to the sandbox when the inbound
bearer header (whatever the route declares) is empty AND
`replace_inbound` would otherwise apply. This catches mis-configured
agents (e.g. user removed `apiKeyHelper` from settings.json but kept
the credential route) at the most useful place — request time, with a
descriptive error message — instead of a startup-time
agent-specific preflight check that would tie nono to a particular
agent's auth model.

### Sentinel value

`nono_provisioned_DO_NOT_USE_proxy_handles_egress` is hardcoded in
`crate::profile::PROXY_PROVISIONED_SENTINEL`. Properties:
- Non-empty (so claude's apiKeyHelper code path treats it as a valid value)
- Obviously synthetic if leaked to logs
- Distinct from any real bearer format

The proxy doesn't actually inspect the inbound value when substituting —
it just replaces. The sentinel is for human observability, not for the
proxy's logic.

## What does NOT belong in this design

- **A startup preflight check that reads `~/.claude/settings.json`.**
  Earlier drafts had `RequireApiKeyHelper`. Dropped: it tied nono to
  claude-specific config. Request-time enforcement (return 401 if no
  inbound) is agent-agnostic.
- **A `shadow_in_sandbox` boolean.** Earlier drafts let users opt out
  of the mediation auto-injection. Dropped: there's no real use case
  for opting out. Always shadow.
- **A `replace_inbound` boolean on bearer.** Earlier drafts considered
  letting `proxy_provisioned_credential` skip substitution. Dropped:
  the whole point is to substitute. Replace_inbound is implicit per
  capture type.
- **A profile-level `refresh` config.** Earlier drafts considered
  `periodic_and_on_failure` with a tunable interval. Dropped: the
  agent has no useful TTL signal (claude's `apiKeyHelper` TTL applies
  to claude's own cache, not the proxy's). On-failure-refresh is the
  only signal that matters; hardcode it.

## Future extensions (deferred from initial PR)

### Additional credential sources

`ProvisionSource` is a discriminated union. Future variants share the
same caching, refresh-on-failure, and mediation-rule-shadowing
plumbing — only the actual `provision()` step differs:

- **`{ "type": "file", "path": "~/.dd/auth.json", "field": "access_token" }`**
  — Read credentials from a file the user maintains (e.g.
  `~/.aws/credentials`, `~/.dd/auth.json`). Useful when an external
  process (cron job, IDP daemon) rotates the credential and nono
  should just consume it. `provision()` is `fs::read_to_string` plus
  optional JSON path extraction.

- **`{ "type": "http", "url": "...", "headers": {...} }`** — Fetch from
  an internal IDP / metadata service endpoint. `provision()` is an
  HTTP GET via the proxy's existing TLS connector. Useful for
  metadata-server-based credentials (cloud workload identity).

- **`{ "type": "keychain", "service": "...", "account": "..." }`** — Read
  directly from macOS keychain (different entry from claude's
  `Claude Code-credentials`; this would be an arbitrary nono-managed
  entry). `provision()` is `security_framework::passwords::find_generic_password`.

Each variant adds ~50 lines of code. None require changes to the
schema (`source` is already a discriminated union) or to the
caching/refresh/shadowing logic.

### Retry-in-place on 401/403

v1 ships fire-and-forget refresh: the current request fails with 401,
the refresh kicks off, the next request succeeds. Users see one bad
response every ~2h (when the ddtool token expires).

The cleaner UX is retry-in-place: when upstream returns 401 on a
provisioned route, refresh synchronously, rebuild the request with
the fresh credential, send again, return the second response to the
sandbox. Claude never sees the 401.

Implementation cost: refactor `forward::forward_request` to buffer the
response body instead of streaming it directly to the inbound socket.
Then the caller can inspect status, decide to retry, and only stream
the chosen response. Memory cost: full response body buffered in
memory. For API requests, response bodies are small (typically <1 MB);
acceptable.

Deferred from v1 to keep the PR's scope tight. File an issue when the
2h-expiry UX becomes painful enough to justify the refactor.

### Proactive periodic refresh

Some credential sources have a known TTL (e.g. AWS STS tokens are 1h).
Refreshing slightly before expiry avoids the 401 entirely. Schema would
add an optional `refresh: { periodic_seconds: N }` field.

Deferred: requires per-source TTL knowledge. v1's on-failure model
works for unknown-TTL sources without configuration.

### Multi-source per route

A route could declare multiple credential sources (try X, fall back
to Y). Useful for "use the cached ~/.dd/auth.json if fresh, else
re-run ddtool." Schema would change `source: ProvisionSource` to
`sources: Vec<ProvisionSource>`.

Deferred: no real-world need yet.

## Open questions

- **`Direct` vs `Redirected` delivery for gateway routes.** Live testing
  (2026-06-12) showed that `Direct` delivery (agent dials real gateway
  hostname, proxy CONNECT-intercepts) causes Claude Code to drop some
  `ANTHROPIC_CUSTOM_HEADERS` entries (`org-id`, `provider`, `claude-code`)
  from the inner HTTP request. Only `source` arrived. The gateway
  requires `org-id` and returned `400 Missing required header: org-id`.
  Root cause is in Claude Code's HTTP stack: it sends fewer custom
  headers when making a TLS-direct connection vs. routing through a
  localhost proxy. `Redirected` delivery (proxy injects
  `ANTHROPIC_BASE_URL=http://127.0.0.1:PORT/__nono_gw_<name>`) routes the
  request through `reverse.rs`, which forwards all headers intact. The
  shipped profile uses `Redirected` delivery for this reason. Future work:
  investigate whether Claude Code's header filtering is intentional or a
  quirk of its CONNECT path.

- **What about Codex-style usage where the agent has env-var auth, not
  apiKeyHelper?** Today the auto-injected mediation rule covers the
  `apiKeyHelper` invocation. For env-var auth, the env var is in
  `mediation.env.block`, so the sandbox never sees it. The proxy
  substitutes on egress regardless. Net: Codex works the same way as
  Claude, no schema changes. Verified architecturally; haven't tested
  with Codex yet.

- **What's the upgrade path from `helper_command` to
  `proxy_provisioned_credential`?** They're not interchangeable — they
  encode different security models. Migration is a profile rewrite,
  not a code change. The legacy shim in `resolve_credential_routes`
  still synthesises `helper_command` routes from the legacy
  `apikey_gateway: {...}` field, so users on the legacy shape keep
  working.

- **Should `provisioned_command` shadow apiKeyHelper invocations on
  command names it doesn't itself declare?** Today it only shadows the
  exact command name in the route's source. If a user has
  `apiKeyHelper: "different-helper foo"` AND a `proxy_provisioned_credential`
  route on `ddtool`, claude runs `different-helper foo` unsupervised
  (mediation rule doesn't match). `different-helper` could return any
  value claude then uses. Not a security issue (the proxy substitutes
  on egress regardless), but potentially confusing.

  Decision: leave as-is for v1. If a user has two unrelated helpers
  they're on their own to declare additional mediation rules.

## Files touched

- `crates/nono-cli/src/profile/mod.rs`: schema (`ProvisionSource`,
  `ProxyProvisionedCredential` variant), `PROXY_PROVISIONED_SENTINEL`
  constant, `inject_proxy_provisioned_respond_rules` helper, 4 new
  tests.
- `crates/nono-cli/src/sandbox_prepare.rs`: invoke auto-injection
  after `broker_protection::inject_into`.
- `crates/nono-cli/src/proxy_runtime.rs`: `extract_provisioned_sources`
  helper, run `ProvisionedStore::provision_all` at startup,
  populate the new field on synthesised `RouteConfig`s.
- `crates/nono-cli/src/network_policy.rs`: add new RouteConfig field.
- `crates/nono-cli/src/oauth_preflight.rs`: include
  `ProxyProvisionedCredential` in the silent-skip arm for
  `ClaudeCodeApiKeyHelperConfigured` preflight.
- `crates/nono-proxy/src/provisioned.rs`: new module —
  `ProvisionedStore`, `Slot`, `ProvisionSource`, 8 unit tests.
- `crates/nono-proxy/src/lib.rs`: export the new module.
- `crates/nono-proxy/src/config.rs`: add
  `provisioned_credential_route: Option<String>` to `RouteConfig`.
- `crates/nono-proxy/src/route.rs`: add
  `provisioned_credential_route` + `provisioned_inject_header` +
  `provisioned_inject_format` to `LoadedRoute`.
- `crates/nono-proxy/src/server.rs`: add `provisioned_store` to
  `ProxyRuntime` and `ProxyState`; thread into both contexts.
- `crates/nono-proxy/src/tls_intercept/handle.rs`: add
  `provisioned_store` field to `InterceptCtx`; substitution block
  before `forward_request`; fire-and-forget refresh on 401/403.
- `crates/nono-proxy/src/reverse.rs`: add `provisioned_store` field
  to `ReverseProxyCtx`; substitution block in the inject-credential
  switch.
- `crates/nono-proxy/src/credential.rs`: add new RouteConfig field to
  test fixture.

## Test profile (live verification target)

`claude-code-with-ddtool-gateway.json` shipped alongside this PR
defines both `oauth_intercept` (Anthropic /login) and
`proxy_provisioned_credential` (ddtool gateway) routes in one profile.
Live verification:

```bash
# Mode A — gateway path (default)
export ANTHROPIC_BASE_URL=https://ai-gateway.us1.ddbuild.io
~/.cargo/bin/nono run --profile $(pwd)/claude-code-with-ddtool-gateway.json -- \
  claude -p "What is 17 * 23?"
# Expected: 391, exit 0
# Proxy log: "provisioning credential for route 'ddtool_gateway' from ddtool"
# Proxy log: "substituted inbound 'x-api-key' with proxy-provisioned credential for route 'ddtool_gateway'"
# Proxy log: "POST /v1/messages?beta=true status=200" against ai-gateway.us1.ddbuild.io

# Mode B — direct /login (breakglass)
unset ANTHROPIC_BASE_URL
~/.cargo/bin/nono run --profile $(pwd)/claude-code-with-ddtool-gateway.json -- claude
# Inside REPL: /login, complete browser flow, then "What is 5 + 12?"
# Expected: 17
# Proxy log: oauth_intercept routes capture the OAuth response
# Proxy log: nonce-Bearer translation on egress to api.anthropic.com
```

## Future work

When you next touch this code, look at:

1. **Retry-in-place** (see Future Extensions above). The 401-then-next-request
   UX is acceptable for v1 but not great. A response-buffer refactor of
   `forward::forward_request` would let us do single-request retry.

2. **File-based provision source**. The smallest, cleanest second
   variant. Useful for any tool that maintains its own credentials
   file (`~/.aws/credentials`, `~/.dd/auth.json`,
   `~/.config/gcloud/access_tokens.db`, etc.).

3. **Codex live verification**. Architecture says this should work
   unchanged; needs a real Codex profile to confirm.
