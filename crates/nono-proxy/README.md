# nono-proxy

Network filtering proxy for the [nono](https://crates.io/crates/nono) sandbox.

## Overview

`nono-proxy` provides host-level network filtering and credential injection for sandboxed processes. It runs **unsandboxed** in the supervisor process while the child is restricted to connecting only to the proxy's localhost port via `NetworkMode::ProxyOnly`.

## Proxy Modes

| Mode | Module | Description |
|------|--------|-------------|
| CONNECT tunnel | `connect` | Host-filtered HTTPS tunnelling. Validates the target host against an allowlist and cloud metadata deny list, then establishes a raw TCP tunnel. TLS is end-to-end. |
| TLS intercept | `tls_intercept` | MITM HTTPS tunnel using a per-session CA. Used by credential routes when the agent dials the real upstream hostname directly (`Direct` delivery) so the proxy can rewrite OAuth response bodies and translate bearer headers in-place. |
| Reverse proxy | `reverse` | Credential injection for API calls. Requests to `http://127.0.0.1:<port>/<service>/...` are forwarded upstream with the real API key, OAuth bearer, or provisioned credential injected as an HTTP header. |
| External proxy | `external` | Enterprise proxy passthrough. CONNECT requests are chained through a corporate proxy with cloud metadata endpoints still denied. |

## Credential Routes

Routes declared in the CLI's `credential_routes` profile field arrive here as `RouteConfig` entries and drive three capture mechanisms layered on top of the modes above:

- **OAuth response-body rewriting** (`oauth_rewrite`). On a TLS-intercepted OAuth token endpoint, the proxy parses the JSON response, hands the real `access_token` / `refresh_token` to a `TokenResolver` (typically a `TokenBroker`) which returns opaque `nono_<hex>` nonces, and substitutes the nonces into the response body before the sandbox sees it.
- **Bearer header translation.** On every subsequent egress request, both the CONNECT-tunnel TLS intercept path and the reverse-proxy path consult the same `TokenResolver` to swap `nono_<hex>` nonces in `Authorization` / `x-api-key` (or any configured header) for the real bearer immediately before the request leaves the proxy.
- **Provisioned credentials** (`provisioned`). For gateway-mediated routes, the proxy parent runs a credential-issuing command at startup, caches the result in `Zeroizing<String>`, substitutes it on every egress request to the route's upstream, and refreshes on 401 / 403. The sandbox sees only a hardcoded placeholder value flowing through its `apiKeyHelper`-style auth path.

Per-route `egress_headers` are injected on every outbound request for that route — useful for gateway-required metadata (e.g. `provider`, `org-id`) the agent does not always forward in CONNECT mode.

## Security Properties

- **Cloud metadata deny list is hardcoded** -- Cloud metadata hostnames (169.254.169.254, metadata.google.internal, metadata.azure.internal) are always blocked regardless of allowlist configuration. Private network addresses (RFC1918) are allowed to support enterprise environments.
- **DNS rebinding protection** -- The proxy resolves DNS, checks all resolved IPs against the link-local range (169.254.0.0/16, fe80::/10), and connects to resolved addresses (not re-resolved hostnames). This prevents DNS rebinding attacks targeting cloud metadata.
- **Session token authentication** -- Each session generates a 256-bit random token. CONNECT requests use `Proxy-Authorization` (Basic or Bearer); reverse proxy requests use `X-Nono-Token`.
- **Credential isolation** -- API keys are loaded from the OS keyring, stored in `Zeroizing<String>`, injected at the HTTP header level, and never exposed to the sandboxed process.
- **Broker-mediated nonce resolution** -- For OAuth-capture and gateway routes, real bearers are held by a `TokenBroker` running in the unsandboxed parent. The sandbox only ever sees `nono_<hex>` nonces or a fixed placeholder. Nonce → real-token resolution happens at egress, after the proxy has authenticated the inbound request.
- **Constant-time token comparison** -- Prevents timing side-channel attacks on session token validation.

## Usage

```rust
use nono_proxy::{ProxyConfig, start, ProxyHandle};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ProxyConfig {
        allowed_hosts: vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
        ],
        ..Default::default()
    };

    let handle: ProxyHandle = start(config).await?;

    // Set these in the child process environment
    let env_vars = handle.env_vars();
    // HTTP_PROXY, HTTPS_PROXY, NONO_PROXY_TOKEN, etc.

    // Shutdown when done
    handle.shutdown();
    Ok(())
}
```

## Module Structure

| Module | Purpose |
|--------|---------|
| `server` | TCP listener, connection dispatch, lifecycle |
| `filter` | Async host filtering with DNS resolution |
| `connect` | CONNECT tunnel handler |
| `tls_intercept` | TLS MITM handler for credential-route intercepts; bearer translation on egress |
| `reverse` | Reverse proxy with credential injection and broker-mediated nonce resolution |
| `forward` | Shared request-forwarding plumbing, including optional response-body rewriting |
| `external` | External proxy passthrough |
| `oauth_rewrite` | OAuth response-body parsing and nonce substitution |
| `broker` | `TokenResolver` trait — the seam between proxy and the CLI's `TokenBroker` |
| `provisioned` | In-memory cache of proxy-provisioned credentials; refresh-on-failure logic |
| `route` | `RouteConfig` parsing, prefix matching, per-route state |
| `credential` | Keyring-backed credential store |
| `token` | Session token generation and validation |
| `config` | Configuration types |
| `audit` | Connection audit logging |
| `error` | Error types |

## License

Apache-2.0
