# nono Profile Authoring Guide

This guide is designed for LLM agents helping users create custom nono profiles. It covers the full profile schema, common patterns, and validation workflow.

## 1. Profile File Location

User profiles live at `~/.config/nono/profiles/<name>.json`.

Profile names must be alphanumeric with hyphens only. No leading or trailing hyphens.

Valid: `my-agent`, `ci-build`, `dev2`
Invalid: `-leading`, `trailing-`, `has spaces`, `special_chars!`

User profiles take precedence over built-in profiles of the same name.

## 2. Minimal Profile Example

```json
{
  "meta": {
    "name": "my-agent",
    "description": "Profile for my agent"
  },
  "groups": {
    "include": []
  },
  "workdir": {
    "access": "readwrite"
  }
}
```

## 3. Section Reference

### meta

| Field         | Type   | Required | Description              |
|---------------|--------|----------|--------------------------|
| `name`        | string | yes      | Profile name             |
| `version`     | string | no       | Semver version string    |
| `description` | string | no       | Human-readable summary   |
| `author`      | string | no       | Author name              |

### extends

Inherit from another profile by name:

```json
{
  "extends": "default"
}
```

- Inheritance chain max depth: 10.
- Scalar fields: child overrides base.
- Array fields (`groups.include`, `groups.exclude`, `commands.allow`, `commands.deny`, `filesystem.*`, `allow_domain`, `open_port`, `listen_port`, `rollback.*`, `upstream_bypass`): child values are appended to base values and deduplicated. To remove inherited entries, use `groups.exclude` for groups; there is no mechanism to remove inherited filesystem paths. For `allow_domain` entries with endpoint rules, rules for the same domain are merged (appended) rather than replaced.
- Map fields (`env_credentials`, `hooks`, `custom_credentials`): child entries are merged into base; child keys override matching base keys.
- `network_profile` supports three-state inheritance via `InheritableValue`: absent = inherit base value, `null` = explicitly clear, string = override. This is the only field that supports null-clearing.
- `open_urls`: if the child provides the field (even as `{}`), it replaces the base entirely. If absent, the base value is inherited. Setting to `null` in JSON is equivalent to omitting it (both inherit the base).
- `workdir`: child overrides base unless child is `"none"` (which inherits the base value instead).

### groups

Controls which policy groups apply to the profile. Group definitions live in `policy.json`; list available groups with `nono profile groups`.

| Field     | Type            | Default | Description |
|-----------|-----------------|---------|-------------|
| `include` | array of string | `[]`    | Policy group names to apply. |
| `exclude` | array of string | `[]`    | Group names to remove from the resolved group set, including inherited defaults. |

### commands

Controls startup-time command gating. These checks run only at launch time and are not enforced on child processes — prefer path-based controls in `filesystem` for strong enforcement.

| Field   | Type            | Default | Description |
|---------|-----------------|---------|-------------|
| `allow` | array of string | `[]`    | Startup-only command allowlist. Deprecated in v0.33.0; retained for existing profiles. |
| `deny`  | array of string | `[]`    | Startup-only command denylist extension. Deprecated in v0.33.0; prefer `filesystem.deny` and narrower grants instead. |

### security

| Field                 | Type            | Default      | Description |
|-----------------------|-----------------|--------------|-------------|
| `signal_mode`         | string          | `"isolated"` | One of: `"isolated"`, `"allow_same_sandbox"`, `"allow_all"`. |
| `process_info_mode`   | string          | `"isolated"` | One of: `"isolated"`, `"allow_same_sandbox"`, `"allow_all"`. |
| `ipc_mode`            | string          | `"shared_memory_only"` | One of: `"shared_memory_only"`, `"full"`. Use `"full"` for multiprocessing (enables POSIX semaphores). macOS only. |
| `capability_elevation`| boolean         | `false`      | Enable runtime capability elevation via seccomp-notify. Linux only. |
| `wsl2_proxy_policy`  | string          | `"error"`    | WSL2 only. Controls behavior when proxy-only network mode cannot be kernel-enforced. `"error"`: refuse to run (fail-secure). `"insecure_proxy"`: allow degraded execution where credential proxy runs but child is not prevented from bypassing it. See [WSL2 docs](https://nono.sh/docs/cli/internals/wsl2). |

### filesystem

All filesystem grants, denials, and deny-rule exemptions live under this single section.

| Field               | Type            | Description |
|---------------------|-----------------|-------------|
| `allow`             | array of string | Directories with read+write access. |
| `read`              | array of string | Directories with read-only access. |
| `write`             | array of string | Directories with write-only access. |
| `allow_file`        | array of string | Single files with read+write access. |
| `read_file`         | array of string | Single files with read-only access. |
| `write_file`        | array of string | Single files with write-only access. |
| `deny`              | array of string | Paths denied filesystem access. |
| `bypass_protection` | array of string | Paths exempted from deny groups. **This flag does not implicitly grant access** — `bypass_protection` only removes the deny rule; each path must also appear in `filesystem.allow`, `filesystem.read`, or `filesystem.write` (or the matching `*_file` variant) to become accessible. |
| `ignore`            | array of string | Paths whose runtime denials should not be offered in save-profile prompts. Does not grant access or hide diagnostics. |

All path fields support variable expansion (see Section 6).

### workdir

| Field    | Type   | Default  | Description |
|----------|--------|----------|-------------|
| `access` | string | `"none"` | One of: `"none"`, `"read"`, `"write"`, `"readwrite"`. Controls automatic CWD sharing with the sandboxed process. |

### network

| Field                   | Type                              | Default  | Description |
|-------------------------|-----------------------------------|----------|-------------|
| `block`                 | boolean                           | `false`  | Block all network access. |
| `network_profile`       | string or null                    | inherit  | Name from `network-policy.json` for proxy filtering. Set to `null` to clear inherited value. |
| `allow_domain`          | array of string or object         | `[]`     | Additional domains to allow through the proxy. Entries can be plain strings (CONNECT tunnel) or objects with endpoint rules (TLS-intercepted L7 filtering). Aliases: `proxy_allow`, `allow_proxy`. |
| `credentials`           | array of string                   | `[]`     | Credential services to enable via reverse proxy. Alias: `proxy_credentials`. |
| `open_port`             | array of integer                  | `[]`     | Localhost TCP IPC. Aliases: `port_allow`, `allow_port`. Port **0**: macOS only (`localhost:*` outbound); Linux: explicit ports. |
| `listen_port`           | array of integer                  | `[]`     | TCP ports the sandboxed child may listen on. |
| `custom_credentials`    | map of string to credential def   | `{}`     | Custom credential route definitions (see below). |
| `upstream_proxy`        | string                            | `null`   | Enterprise proxy address (`host:port`). Alias: `external_proxy`. |
| `upstream_bypass`       | array of string                   | `[]`     | Hosts to bypass the upstream proxy. Supports `*.` wildcard suffixes. Alias: `external_proxy_bypass`. |

#### allow_domain with endpoint restrictions

When an `allow_domain` entry is an object with `endpoints`, the proxy performs TLS interception to enforce method+path restrictions (default-deny). This is useful for restricting access to specific API endpoints without credential injection:

```json
{
  "network": {
    "allow_domain": [
      "api.openai.com",
      {
        "domain": "api.github.com",
        "endpoints": [
          { "method": "GET", "path": "/repos/my-org/**" },
          { "method": "POST", "path": "/repos/my-org/*/issues" }
        ]
      }
    ]
  }
}
```

| Field       | Type   | Required | Description |
|-------------|--------|----------|-------------|
| `domain`    | string | yes      | Domain hostname (e.g., `"api.github.com"`). |
| `endpoints` | array  | yes      | L7 method+path rules. Only requests matching at least one rule are allowed. |

Each endpoint rule has `method` (HTTP method or `"*"` for any) and `path` (glob pattern: `*` = one segment, `**` = zero or more segments).

When profiles extend each other, endpoint rules for the same domain are **appended** (merged), not replaced. Proxy mode is automatically enabled when endpoint rules are present.

#### custom_credentials entry

Define a custom reverse proxy credential route for services not in `network-policy.json`:

```json
{
  "upstream": "https://api.example.com",
  "credential_key": "example_api_key",
  "inject_mode": "header",
  "inject_header": "Authorization",
  "credential_format": "Bearer {}",
  "proxy": {
    "inject_mode": "query_param",
    "query_param_name": "api_key"
  }
}
```

| Field               | Type            | Required    | Description |
|---------------------|-----------------|-------------|-------------|
| `upstream`          | string          | yes         | Upstream URL. Must be HTTPS (HTTP only for loopback). |
| `credential_key`    | string          | yes         | Keystore account name, `op://` URI, `bw://` URI, `apple-password://` URI, `file://` URI, or `env://` URI. |
| `inject_mode`       | string          | no          | One of: `"header"` (default), `"url_path"`, `"query_param"`, `"basic_auth"`. |
| `inject_header`     | string          | header mode | HTTP header name. Default: `"Authorization"`. |
| `credential_format` | string          | header mode | Format string with `{}` placeholder. Default: `"Bearer {}"`. |
| `path_pattern`      | string          | url_path    | Pattern to match in URL path. Use `{}` for placeholder. |
| `path_replacement`  | string          | url_path    | Replacement pattern. Defaults to `path_pattern`. |
| `query_param_name`  | string          | query_param | Query parameter name for credential injection. |
| `proxy`             | object          | no          | Optional proxy-side overrides for phantom token parsing. Omitted fields inherit from top-level values. |
| `env_var`           | string          | URI keys    | Environment variable name for SDK API key. Required when `credential_key` is `op://`, `bw://`, `apple-password://`, or `file://`. Optional for `env://`. |
| `endpoint_rules`    | array           | no          | L7 allow-list of `{"method": "GET", "path": "/**"}` rules. When non-empty, only matching requests are forwarded (default-deny). |
| `tls_ca`            | string (path)   | no          | Path to a PEM-encoded CA certificate. Use for upstreams with self-signed or private CA certs (e.g. a Kubernetes API server). |
| `tls_client_cert`   | string (path)   | no          | Path to a PEM-encoded client certificate for mutual TLS (mTLS). Must be set together with `tls_client_key`. |
| `tls_client_key`    | string (path)   | no          | Path to the PEM-encoded private key matching `tls_client_cert`. |

`proxy` overrides apply only to how the local proxy validates incoming phantom tokens from the sandboxed process. Outbound upstream credential injection continues to use top-level fields.

### env_credentials (alias: secrets)

Maps keystore account names to environment variable names. Secrets are loaded from the system keystore (macOS Keychain / Linux Secret Service) under the service name "nono".

```json
{
  "env_credentials": {
    "openai_api_key": "OPENAI_API_KEY",
    "op://vault/item/field": "ANTHROPIC_API_KEY"
  }
}
```

Supported key formats:
- Bare keystore account name: `"openai_api_key"`
- 1Password URI: `"op://vault/item/field"`
- Apple Passwords URI: `"apple-password://account/name"`
- Environment reference: `"env://EXISTING_VAR"`

### environment

Controls which environment variables are passed to the sandboxed process. When `allow_vars` is set, only the listed variables (and nono-injected credentials) are passed through. `set_vars` injects explicit values regardless of filtering.

```json
{
  "environment": {
    "allow_vars": ["PATH", "HOME", "TERM", "AWS_*"],
    "deny_vars": ["GH_TOKEN"],
    "set_vars": { "RUST_LOG": "debug", "XDG_CONFIG_HOME": "$HOME/.config" }
  }
}
```

| Field         | Type            | Default | Description |
|---------------|-----------------|---------|-------------|
| `allow_vars`  | array of string | `[]`    | Allow-list of environment variable names. Supports exact names (`"PATH"`) and prefix patterns ending with `*` (`"AWS_*"` matches `AWS_REGION`, `AWS_SECRET_ACCESS_KEY`, etc.). The `*` wildcard is only valid as a trailing suffix. When the `environment` section is omitted entirely, all variables are allowed. When present with an empty array, no inherited variables are passed (only nono-injected credentials). Nono-injected credentials always bypass this list. |
| `deny_vars`   | array of string | `[]`    | Deny-list of environment variable names stripped from the child. Same pattern syntax as `allow_vars` (exact names and trailing `*`). Denied vars are stripped even if they also match `allow_vars`. |
| `set_vars`    | object (string→string) | `{}` | Static environment variables injected after allow/deny filtering and before credential injection (injected credentials win on conflict). Values support the same expansion as profile paths (`$HOME`, `~`, `$WORKDIR`, `$TMPDIR`, `$XDG_*`, `$NONO_PACKAGES`); keys are not expanded. `PATH` and any `NONO_*` key are reserved and rejected at load time. Unlike inherited host vars, keys here are NOT subject to the dangerous-variable blocklist (`LD_PRELOAD`, `NODE_OPTIONS`, …) — setting one is an explicit operator decision. |

Inheritance: child `allow_vars` and `deny_vars` are appended to base values and deduplicated; `set_vars` merges as a map, with the child's value winning on key conflict.

### hooks

Map of application name to hook configuration:

```json
{
  "hooks": {
    "claude-code": {
      "event": "PostToolUseFailure",
      "matcher": "Read|Write|Edit|Bash",
      "script": "nono-hook.sh"
    }
  }
}
```

| Field     | Type   | Description |
|-----------|--------|-------------|
| `event`   | string | Trigger event name. |
| `matcher` | string | Regex for tool name matching. |
| `script`  | string | Script filename from embedded hooks. |

### mediation

Per-command interception of agent invocations. The mediation server runs in the unsandboxed supervisor parent; the sandbox's `PATH` resolves to a shim that forwards the invocation over a Unix socket. Each invocation is dispatched against the matching `CommandEntry`'s intercept list (first-match) and falls back to its required `default` action when no intercept fires.

```json
{
  "mediation": {
    "commands": [
      {
        "name": "gh",
        "default": {
          "action": { "type": "allow" },
          "sandbox": { "network": { "allowed_hosts": ["github.com", "*.github.com"] } }
        },
        "intercept": [
          {
            "id": "auth-token",
            "match": { "all": [
              { "nth_arg_matches": 0, "regex": "^auth$" },
              { "nth_arg_matches": 1, "regex": "^token$" }
            ]},
            "action": {
              "type": "capture",
              "grant_to": ["gh.default"]
            }
          }
        ]
      }
    ],
    "env": {
      "block": ["GH_TOKEN", "GITHUB_TOKEN"]
    }
  }
}
```

**Top-level `mediation` fields:**

| Field             | Type            | Required | Description |
|-------------------|-----------------|----------|-------------|
| `commands`        | array           | no       | Per-command mediation entries. |
| `env`             | EnvPolicy       | no       | Session-level env variable policy (e.g. block credential env vars). |
| `session_can_use` | array of string | no       | Commands the primary agent sandbox may invoke directly. A command absent from this list is denied (exit 126) when the agent tries to invoke it. Each name must match a defined `commands[].name`. |

#### commands[]

| Field           | Type            | Required | Description |
|-----------------|-----------------|----------|-------------|
| `name`          | string          | yes      | Command name as the agent invokes it (resolved via `which` at session start). |
| `binary_path`   | string          | no       | Absolute path to the real binary, bypassing `which`. Use when `which` resolves to a wrapper. |
| `default`       | DefaultEntry    | yes      | Dispatched when no intercept rule matches. Profile load fails if absent. |
| `intercept`     | array           | no       | Intercept rules. Checked in order; first match wins. |
| `sandbox`       | CommandSandbox  | no       | Legacy command-level sandbox. Falls back here when both the matched rule and `default` omit a sandbox. Prefer `default.sandbox`. |
| `can_use`       | array of string | no       | Commands this command is authorised to invoke. Any entry in `sandbox.allow_commands` must also appear here. |

#### default (required)

Every command needs a `default` block. It dispatches when no intercept matches and is referenced by capture grants as `<command>.default`.

| Field        | Type            | Required | Description |
|--------------|-----------------|----------|-------------|
| `action`     | InterceptAction | yes      | One of `deny`, `allow`, or `capture`. |
| `sandbox`    | CommandSandbox  | no       | Fallback sandbox. Intercept rules with no own `sandbox` inherit this. |
| `promote_in` | PromoteFilter   | no       | Per-default scoping of nonce promotion. See "Promotion scoping" below. |

Minimal default — let the call through unchanged:

```json
{ "default": { "action": { "type": "allow" } } }
```

Default with a sandbox that scopes every fall-through run:

```json
{
  "default": {
    "action": { "type": "allow" },
    "sandbox": {
      "network": { "allowed_hosts": ["github.com", "*.github.com"] },
      "keychain_access": true
    }
  }
}
```

#### intercept[]

```json
{
  "id": "gitlab-curl",
  "match": {
    "all": [
      { "any_arg_matches": "^https://gitlab\\.ddbuild\\.io" },
      { "not": { "any_arg_matches": "^-k$" } }
    ]
  },
  "admin": false,
  "action": { "type": "allow" },
  "sandbox": { "network": { "allowed_hosts": ["gitlab.ddbuild.io"] } }
}
```

| Field        | Type            | Required | Description |
|--------------|-----------------|----------|-------------|
| `id`         | string          | conditional | Identifier within the command's intercept list. Required when any `Capture.grant_to` references this rule as `<command>.<id>`. The id `"default"` is reserved for the default entry. |
| `match`      | ArgsMatcher     | yes      | Predicate tree against argv. See "Argv matchers" below. |
| `admin`      | boolean         | no       | Require user authentication before the action runs. Default: false. |
| `action`     | InterceptAction | yes      | One of `deny`, `allow`, or `capture`. |
| `sandbox`    | tri-state       | no       | Per-invocation sandbox binding. See "Sandbox inheritance" below. |
| `promote_in` | PromoteFilter   | no       | Per-rule scoping of nonce promotion. See "Promotion scoping" below. |

#### Argv matchers

`match` is a recursive predicate tree. Combinators compose leaves:

| Form                                 | Meaning |
|--------------------------------------|---------|
| `{ "all": [ ... ] }`                  | Conjunction. Empty list = vacuously true. |
| `{ "any": [ ... ] }`                  | Disjunction. Empty list = vacuously false. |
| `{ "not": <matcher> }`                | Logical NOT. |
| `{ "any_arg_matches": "<regex>" }`    | At least one argv element matches the regex. |
| `{ "all_args_match": "<regex>" }`     | Every argv element matches (or argv is empty). |
| `{ "nth_arg_matches": <n>, "regex": "<re>" }` | argv element at index `n` (0-based, counts flags) matches the regex. |

Regexes use the `regex` crate (linear time, no catastrophic backtracking). Inline flags such as `(?i)` and `(?m)` are supported. The matcher sees only argv — not env, cwd, or stdin.

#### action types

Tagged via `"type"`. Three variants:

| Type      | What it does |
|-----------|--------------|
| `deny`    | Return a static response without calling the real binary. Fields: `stdout`, `stderr`, `exit_code` (all optional with defaults). |
| `allow`   | Run the real binary, streaming stdio. Optional `script` field runs `sh -c "<script>"` instead. Sandboxed per the resolved binding. |
| `capture` | Run the real binary (or `script`) in the unsandboxed broker parent, capture trimmed stdout, mint a nonce, and return the nonce to the caller. Use for credential-fetching commands so raw tokens never reach the agent. |

```json
{ "action": { "type": "deny", "stdout": "", "stderr": "blocked", "exit_code": 1 } }
{ "action": { "type": "allow" } }
{ "action": { "type": "allow", "script": "exec git \"$@\"" } }
{ "action": { "type": "capture", "grant_to": ["gh.default", "git.default"] } }
{ "action": { "type": "capture", "script": "ddtool auth gitlab token", "grant_to": ["glab.default"] } }
```

#### capture grants

Every `capture` action must include `grant_to: [...]`. Each entry is the identifier of a consumer authorised to redeem the nonce, in the form `<command>.<intercept-id>`. Use `<command>.default` to reference the command's `default` block.

- `"grant_to": ["gh.default"]` — only `gh`'s default run may substitute the nonce for the real value.
- `"grant_to": []` — explicitly never redeemable. The nonce is minted but no consumer can decode it; use for defensive captures whose only purpose is to intercept and discard a credential.
- Field missing → profile load fails. There is no implicit "anywhere" grant.

Capture rules always run unsandboxed in the broker parent so credential helpers can reach the Keychain, OAuth flows, etc. The `sandbox` field on a `Capture` intercept is ignored.

#### sandbox inheritance

The `sandbox` field on an intercept rule is tri-state, distinguished by JSON presence:

| JSON                       | Meaning |
|----------------------------|---------|
| field absent               | Inherit. At exec time, falls back to `cmd.default.sandbox`, then the legacy `cmd.sandbox`, then no sandbox. |
| `"sandbox": null`           | Explicitly unsandboxed. Opts out of inheritance entirely; the rule runs with no per-command sandbox. |
| `"sandbox": { ... }`        | Explicit sandbox. Use this exact `CommandSandbox` for the matched call. |

Only `allow` rules honour this field. `capture` ignores it (always unsandboxed in the broker). `deny` ignores it (no exec happens).

#### CommandSandbox fields

| Field             | Type            | Description |
|-------------------|-----------------|-------------|
| `network`         | NetworkConfig   | `{ "block": bool, "allowed_hosts": [string] }`. If `allowed_hosts` is non-empty, a per-command proxy restricts outbound to those hosts. `block` and `allowed_hosts` are mutually exclusive. |
| `fs_read`         | array of string | Directories the command may read. |
| `fs_read_file`    | array of string | Individual files the command may read. |
| `fs_write`        | array of string | Directories the command may write. |
| `fs_write_file`   | array of string | Individual files the command may write. |
| `allow_commands`  | array of string | Commands the sandboxed binary may exec directly (real binary, not shim). |
| `keychain_access` | boolean         | macOS only. Grant read access to login/metadata keychain databases and skip default mach-lookup denies for security daemons. |

#### can_use

An explicit list of commands this command is authorised to invoke. The authorization graph gate checks this list before any intercept or sandbox logic:

- A command not listed in a parent's `can_use` is denied (exit 126) when that parent tries to invoke it.
- Any entry in `sandbox.allow_commands` or `default.sandbox.allow_commands` must also appear in `can_use` — profile load fails if the subset constraint is violated.

Session-level gating is controlled by `mediation.session_can_use` (the list of commands the primary agent sandbox may invoke directly). See the top-level `mediation` table.

#### Promotion scoping (`promote_in`)

When a mediated command exec'd via an `allow` intercept (or via the command's `default` action) receives nonces in its argv or env, the broker substitutes those `nono_<hex>` substrings with real credentials at exec time. `promote_in` declares which slots are admissible — defence-in-depth alongside the matcher's `not`-clauses and capture-side `grant_to`.

```jsonc
"promote_in": {
  "args": { /* ArgPredicate */ },
  "env":  { /* EnvPredicate  */ }
}
```

Both sub-fields are independently optional. **Defaults are secure**:

- `args` absent ⇒ **no argv slot promotes**. The redemption site must declare which positional slots may receive a credential. Closes the "credential lands in an unexpected argv slot" attack surface as a default posture.
- `env` absent ⇒ promotion uses the built-in safe-shape allowlist (case-insensitive): `AUTHORIZATION`, `*_TOKEN`, `*_HEADER`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIALS`, `*_AUTH`. Env names outside this set stay literal.

##### ArgPredicate (positional)

Evaluated per argv slot — each leaf answers "may this slot receive promotion?".

| Form                                  | Meaning |
|---------------------------------------|---------|
| `{ "self_matches": "<re>" }`           | argv[i] matches. Use for attached forms like `-Hnono_<hex>` or `--header=...`. |
| `{ "preceded_by_arg": "<re>" }`        | argv[i-1] matches. Use for separate-arg forms like `["-H", "Authorization: ..."]`. argv[0] always misses (no left neighbour). |
| `{ "at_index": <n> }`                  | Exact 0-based positional pin. |
| `{ "all_of": [ ... ] }`                | Conjunction. Empty list = always promote (vacuous). |
| `{ "any_of": [ ... ] }`                | Disjunction. Empty list = never promote (defensive lock). |
| `{ "not": <predicate> }`               | Logical NOT. |

##### EnvPredicate (name + value)

Env vars are stored as a name→value map; predicates key off var name and (rarely) value.

| Form                                  | Meaning |
|---------------------------------------|---------|
| `{ "name_matches": "<re>" }`           | The env var's name matches. |
| `{ "value_matches": "<re>" }`          | The env var's value matches. |
| `{ "all_of": [ ... ] }` / `{ "any_of": [ ... ] }` / `{ "not": <predicate> }` | Combinators with the same semantics as `ArgPredicate`. |

When an explicit `env` predicate is set, it **replaces** the built-in default. To keep the safe-shape allowlist and admit one extra name, union the default regex into a custom `any_of`:

```jsonc
"promote_in": {
  "env": {
    "any_of": [
      { "name_matches": "(?i-u)^(authorization|[A-Za-z0-9_]+_(token|header|key|secret|password|credentials|auth))$" },
      { "name_matches": "^MY_CUSTOM_NONCE_VAR$" }
    ]
  }
}
```

##### Worked example — `curl.gitlab`

A redemption-site intercept that handles `curl` to `gitlab.ddbuild.io`. Captured GitLab nonces are carried only in `-H "PRIVATE-TOKEN: nono_<hex>"` headers, so the filter admits exactly those slots:

```jsonc
{
  "id": "gitlab",
  "match": { "all": [
    { "any_arg_matches": "^https?://(gitlab\\.ddbuild\\.io)(:[0-9]+)?(/|$)" }
    /* plus any file-shape `not`-clauses */
  ]},
  "action": { "type": "allow" },
  "sandbox": { "network": { "allowed_hosts": ["gitlab.ddbuild.io"] } },
  "promote_in": {
    "args": {
      "any_of": [
        { "preceded_by_arg": "^(-H|--header)$" },
        { "self_matches":    "^(-H|--header=)" }
      ]
    }
  }
}
```

Effect: a `nono_<hex>` substring anywhere outside the header slots — body (`--data*`/`-d`), upload-file target (`-T`), multipart (`-F`, `=@`), config file (`-K`), cookie (`-b`) — stays literal even if the matcher's `not`-clauses ever miss a new variant. The upstream sees an unauthenticated request rather than a leaked credential.

##### Inheritance

Intercepts do **not** inherit `promote_in` from the command's `default`. Each rule's filter is independent, matching the per-rule scoping of `grant_to` and avoiding action-at-a-distance.

#### env

| Field   | Type            | Description |
|---------|-----------------|-------------|
| `block` | array of string | Environment variable names stripped from the sandboxed child. Use for raw credentials (e.g. `GH_TOKEN`, `GITLAB_TOKEN`) so they cannot bypass mediation. |

### rollback (alias: undo)

| Field              | Type            | Description |
|--------------------|-----------------|-------------|
| `exclude_patterns` | array of string | Path component patterns to exclude from snapshots. |
| `exclude_globs`    | array of string | Glob patterns for filename exclusion. |

### open_urls

Controls supervisor-delegated URL opening (e.g., OAuth2 login flows).

| Field             | Type            | Default | Description |
|-------------------|-----------------|---------|-------------|
| `allow_origins`   | array of string | `[]`    | Allowed URL origins (scheme + host, e.g., `"https://console.anthropic.com"`). |
| `allow_localhost`  | boolean         | `false` | Allow `http://localhost` and `http://127.0.0.1` URLs. |

To replace inherited URL-opening permissions, provide `open_urls` with an explicit empty object: `"open_urls": { "allow_origins": [], "allow_localhost": false }`. Omitting `open_urls` inherits the base profile's configuration.

## 4. Common Patterns

### Developer profile (extending default)

```json
{
  "extends": "default",
  "meta": {
    "name": "developer",
    "description": "General development"
  },
  "workdir": {
    "access": "readwrite"
  },
  "filesystem": {
    "read": ["$HOME/.config"]
  }
}
```

### CI profile (locked down)

```json
{
  "meta": {
    "name": "ci-build",
    "description": "CI build environment"
  },
  "groups": {
    "include": ["deny_credentials", "deny_ssh_keys"]
  },
  "workdir": {
    "access": "readwrite"
  },
  "network": {
    "block": true
  }
}
```

### Agent with API access

```json
{
  "extends": "default",
  "meta": {
    "name": "api-agent",
    "description": "Agent with API access"
  },
  "workdir": {
    "access": "readwrite"
  },
  "env_credentials": {
    "openai_api_key": "OPENAI_API_KEY"
  },
  "network": {
    "network_profile": "standard"
  }
}
```

### Linux host compatibility

On Linux, the built-in `default` profile keeps host runtime, sysfs, and shared temp reads out of the base policy. If your tool needs access to paths like `/run`, `/var/run`, `/sys`, or `/tmp`, extend the built-in compatibility preset:

```json
{
  "extends": "linux-host-compat",
  "meta": {
    "name": "linux-desktop-agent",
    "description": "Agent with Linux host runtime compatibility"
  },
  "workdir": {
    "access": "readwrite"
  }
}
```

### Profile with deny overrides

When a deny group blocks a path you need access to, use `filesystem.bypass_protection` together with an explicit grant. Remember: `bypass_protection` only removes the deny rule — it does not grant access on its own.

```json
{
  "extends": "default",
  "meta": {
    "name": "shell-config-reader",
    "description": "Needs to read shell configs"
  },
  "workdir": {
    "access": "readwrite"
  },
  "filesystem": {
    "read_file": ["$HOME/.bashrc", "$HOME/.zshrc"],
    "bypass_protection": ["$HOME/.bashrc", "$HOME/.zshrc"]
  }
}
```

### Suppress repeated save suggestions

Use `filesystem.suppress_save_prompt` for paths you intentionally do not want
to grant, but also do not want offered in the save-profile prompt every run:

```json
{
  "extends": "default",
  "meta": {
    "name": "copilot-local",
    "description": "Local prompt-suppression choices"
  },
  "filesystem": {
    "suppress_save_prompt": ["$HOME/.copilot/settings.json"]
  }
}
```

The sandbox still denies these paths. `filesystem.suppress_save_prompt` only
filters the save-profile suggestion. `filesystem.ignore` is accepted as an
alias, but new profiles should use the explicit suppress name so it is not
mistaken for an access grant.

### Denying specific project files

Block access to a file in the working directory while keeping the rest accessible. Use `$WORKDIR` to reference the current working directory — relative paths like `./` are not expanded:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-dotenv",
    "description": "Claude Code without .env access"
  },
  "filesystem": {
    "deny": ["$WORKDIR/.env"]
  }
}
```

**macOS**: This works directly. Seatbelt can deny a specific file within an allowed directory.

**Linux**: Landlock is strictly allow-list and cannot deny a child of an allowed parent. Use supervised mode instead, which intercepts file opens via seccomp-notify and checks them against the deny list before granting access:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-dotenv",
    "description": "Claude Code without .env access"
  },
  "security": {
    "capability_elevation": true
  },
  "filesystem": {
    "deny": ["$WORKDIR/.env"]
  }
}
```

With `capability_elevation` enabled, nono runs in supervised mode where every file access outside the initial grant set is trapped and evaluated. The deny list is checked before the supervisor prompts for approval, so denied paths are blocked regardless of platform.

### Blocking container access (Docker, Podman, kubectl)

Use `filesystem.deny` to prevent an agent from reaching the Docker daemon or similar container runtimes. `commands.deny` is deprecated startup-only gating and should not be relied on as enforcement:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "no-docker",
    "description": "Claude Code without Docker access"
  },
  "filesystem": {
    "deny": ["/var/run/docker.sock"]
  },
  "commands": {
    "deny": ["docker", "docker-compose", "podman", "kubectl"]
  }
}
```

On macOS, `filesystem.deny` on a socket path also emits a Seatbelt `network-outbound` deny — Seatbelt treats `connect(2)` as a network operation so a file deny alone won't block it. Prefer path- and network-based controls; `commands.deny` remains as deprecated startup-only compatibility behavior and is visible in `nono profile show` under the commands section.

### Allowing parent-of-protected-root grants (macOS only)

By default, granting a parent directory of `~/.nono` (e.g. `--allow ~`) is rejected because it would expose nono's internal state. On macOS, Seatbelt can express deny-within-allow rules, so this restriction can be relaxed when the profile opts in with `allow_parent_of_protected`:

```json
{
  "extends": "claude-code",
  "meta": {
    "name": "home-access",
    "description": "Claude Code with full home directory access"
  },
  "allow_parent_of_protected": true
}
```

When `allow_parent_of_protected` is `true` and the platform is macOS, nono permits the parent grant and emits Seatbelt deny rules that protect `~/.nono` from reads and writes. On Linux this field is ignored — Landlock cannot deny a child of an allowed parent, so the pre-flight check always rejects parent-of-protected grants.

### Profile with group exclusion

Remove an inherited deny group that is too restrictive for your use case:

```json
{
  "extends": "default",
  "meta": {
    "name": "browser-tool",
    "description": "Needs browser data access"
  },
  "workdir": {
    "access": "readwrite"
  },
  "groups": {
    "exclude": ["deny_browser_data_macos", "deny_browser_data_linux"]
  }
}
```

### Profile with custom credential routing

```json
{
  "extends": "default",
  "meta": {
    "name": "telegram-bot",
    "description": "Telegram bot with credential injection"
  },
  "workdir": {
    "access": "readwrite"
  },
  "network": {
    "custom_credentials": {
      "telegram": {
        "upstream": "https://api.telegram.org",
        "credential_key": "telegram_bot_token",
        "inject_mode": "url_path",
        "path_pattern": "/bot{}/",
        "path_replacement": "/bot{}/"
      }
    },
    "credentials": ["telegram"]
  }
}
```

## 5. Validation

Run these commands to verify a profile:

```
nono profile validate <path>      # Check a profile file for errors
nono profile show <name>          # Show the fully resolved profile (after inheritance)
nono profile groups               # List available security groups
nono profile diff <a> <b>         # Compare two profiles
```

## 6. Variable Expansion

The following variables are expanded in all path fields (`filesystem.*`, including `filesystem.allow`, `filesystem.read`, `filesystem.write`, `filesystem.deny`, `filesystem.bypass_protection`, and `filesystem.suppress_save_prompt`), in `command_args`, and in the values of `environment.set_vars`.

| Variable           | Expands to |
|--------------------|------------|
| `$HOME`            | User's home directory |
| `$WORKDIR`         | Working directory (from `--workdir` flag or cwd) |
| `$TMPDIR`          | System temporary directory |
| `$UID`             | Current user ID |
| `$XDG_CONFIG_HOME` | XDG config directory (default: `$HOME/.config`) |
| `$XDG_DATA_HOME`   | XDG data directory (default: `$HOME/.local/share`) |
| `$XDG_STATE_HOME`  | XDG state directory (default: `$HOME/.local/state`) |
| `$XDG_CACHE_HOME`  | XDG cache directory (default: `$HOME/.cache`) |
| `$XDG_RUNTIME_DIR` | XDG runtime directory (no default; left unexpanded when unset) |

Always use these variables instead of hardcoded absolute paths to keep profiles portable across machines and users.

## 7. Platform Predicates

Profile entries that list paths, group names, URL origins, or env credentials can be unconditional strings or conditional objects with `when`.

```json
{
  "groups": {
    "include": [
      "agent_common",
      { "name": "agent_linux", "when": "linux" },
      { "name": "agent_macos", "when": "macos" }
    ]
  },
  "filesystem": {
    "read": [
      "$HOME/.agent",
      { "path": "$HOME/Library/Application Support/Agent", "when": "macos" },
      { "path": "$XDG_CONFIG_HOME/agent", "when": "linux" }
    ]
  },
  "env_credentials": {
    "agent_key": { "env_var": "AGENT_API_KEY", "when": ["linux", "macos:>=15"] }
  }
}
```

Supported predicate forms include `linux`, `macos`, `linux:fedora`, `linux:rhel-like`, `linux:ubuntu:>=24.04`, `macos:>=15`, negation such as `!linux:nixos`, and arrays for any-of matching.

## 8. Key Rules

- A profile with no `groups.include` has no deny rules. Always include appropriate deny groups for untrusted workloads.
- `filesystem.bypass_protection` only removes the deny rule. It does not grant access. You must also add the path via `filesystem.allow`, `filesystem.read`, or `filesystem.write` (or the matching `*_file` variant).
- `filesystem.suppress_save_prompt` only suppresses save-profile suggestions. It does not grant access, remove deny rules, or hide diagnostics.
- `groups.exclude` removes groups from the resolved set. This weakens the sandbox. Use it only when you understand which protections you are removing.
- `extends` chains resolve recursively up to depth 10. Circular inheritance is an error.
- Prefer `when` predicates for package-specific platform differences. Put shared OS baseline paths in built-in policy groups instead.
- `network.block: true` blocks all network access. It cannot be combined with proxy settings.
- `custom_credentials` upstream URLs must use HTTPS. HTTP is only accepted for loopback addresses (localhost, 127.0.0.1, ::1).

## 9. Migration from previous schema

Issue [#594](https://github.com/always-further/nono/issues/594) restructured the profile JSON schema. The old `policy.*` namespace has been dissolved into `filesystem`, `groups`, and `commands`; `security.groups` and `security.allowed_commands` have moved to top-level `groups.include` and `commands.allow`.

Legacy keys still deserialize — profiles using the old names continue to load and emit a single deprecation warning — but they are scheduled for removal in **v1.0.0**. New profiles and edits should use the canonical keys below.

| OLD                          | NEW                             |
|------------------------------|---------------------------------|
| `security.groups`            | `groups.include`                |
| `security.allowed_commands`  | `commands.allow`                |
| `policy.add_allow_read`      | `filesystem.read`               |
| `policy.add_allow_write`     | `filesystem.write`              |
| `policy.add_allow_readwrite` | `filesystem.allow`              |
| `policy.add_deny_access`     | `filesystem.deny`               |
| `policy.add_deny_commands`   | `commands.deny`                 |
| `policy.override_deny`       | `filesystem.bypass_protection`  |
| `policy.exclude_groups`      | `groups.exclude`                |
| `--override-deny` (CLI)      | `--bypass-protection` (CLI)     |

Notes:
- The old `policy` key is no longer recognized as a top-level section. Its former fields now live directly under `filesystem`, `groups`, or `commands` as shown above.
- The CLI flag renamed from `--override-deny` to `--bypass-protection` for the same reason the JSON key was renamed: to make the "does not grant access" semantics explicit. The old flag remains as a deprecated alias until v1.0.0.
- When mechanically migrating a profile, move each `policy.*` entry up one level and rename per the table. Array values are preserved unchanged.
