use crate::cli::SandboxArgs;
use crate::launch_runtime::ProxyLaunchOptions;
use crate::mediation::broker::TokenBroker;
use crate::network_policy;
use crate::oauth_preflight;
use crate::sandbox_prepare::{PreparedSandbox, validate_external_proxy_bypass};
#[cfg(not(target_os = "macos"))]
use nono::AccessMode;
use nono::{CapabilitySet, NonoError, Result};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Prefix used for `OauthIntercept`-capture routes targeting the
/// Anthropic OAuth hostnames. Sits in the reserved `__nono_`
/// namespace (see [`nono_proxy::RESERVED_PREFIX_NAMESPACE`]) so user
/// profiles cannot declare a colliding prefix and silently shadow the
/// capture path. Suffixed at synthesis time with the route name to
/// keep prefixes unique across multiple OAuth-intercept routes (e.g.
/// Anthropic + Codex OAuth both active in the same session).
const RESERVED_PREFIX: &str = "__nono_";

/// The three hostnames the legacy Anthropic `OauthIntercept` capture
/// always synthesised intercepts for. Binary analysis
/// (`strings claude | grep TOKEN_URL`) confirms `TOKEN_URL =
/// "https://platform.claude.com/v1/oauth/token"`, but Claude Code
/// also talks to `claude.ai` and `api.anthropic.com` — intercepting
/// all three catches the exchange regardless of which OAuth server
/// handles it.
///
/// Kept here as a hard-coded set rather than driving it off
/// `CredentialRouteCapture::OauthIntercept { ... }` because the three
/// hostnames are fundamentally an Anthropic-OAuth implementation
/// detail. A future Codex or other-provider OAuth-intercept entry
/// would either (a) add a parallel constant for that provider's
/// hostname triad, or (b) extend the schema to declare hostnames
/// explicitly. For now, `OauthIntercept` capture means "Anthropic".
const OAUTH_ANTHROPIC_HOSTS: [&str; 3] = [
    "https://api.anthropic.com",
    "https://claude.ai",
    "https://platform.claude.com",
];

/// Sentinel URL-match strings used for `HelperCommand`-capture routes
/// (no response-body capture happens here — the credential enters the
/// broker via the mediation shim, not via TLS-intercept rewriting).
/// Containing a non-URL character (space) further guarantees no
/// well-formed client request can match.
///
/// We reuse `InjectMode::OauthCapture` for these routes because it's
/// the only `RouteConfig` variant that sets
/// `LoadedRoute::oauth_capture_match = Some(_)`, which is the gate
/// the reverse-proxy passthrough block in `reverse.rs` checks to
/// decide whether to resolve `nono_<hex>` bearers via the
/// `TokenResolver`. Sentinels guarantee the response-side capture
/// stays dormant; the broker-resolution gate is the only behavior
/// we want from `OauthCapture` here.
const HELPER_CAPTURE_SENTINEL: &str = "__nono_helper_capture sentinel — no response capture";

/// Synthesise one or more `nono_proxy::config::RouteConfig` entries
/// for a single [`crate::profile::ManagedCredentialRoute`].
///
/// `OauthIntercept` capture expands to three intercept routes (one
/// per Anthropic OAuth hostname); `HelperCommand` capture expands to
/// a single broker-backed reverse-proxy route at the route's
/// `upstream`. Per-route prefix uses the route's `name` field —
/// callers ensure uniqueness across routes.
fn synthesize_proxy_routes(
    route: &crate::profile::ManagedCredentialRoute,
) -> Vec<nono_proxy::config::RouteConfig> {
    use crate::profile::CredentialRouteCapture;
    use nono_proxy::config::{InjectMode, RouteConfig};

    let bearer_header = &route.bearer.header;
    let bearer_format = &route.bearer.format;
    let make = |prefix: String,
                upstream: String,
                inject_mode: InjectMode|
     -> RouteConfig {
        RouteConfig {
            prefix,
            upstream,
            credential_key: None,
            inject_mode,
            inject_header: bearer_header.clone(),
            credential_format: Some(bearer_format.clone()),
            path_pattern: None,
            path_replacement: None,
            query_param_name: None,
            proxy: None,
            env_var: None,
            endpoint_rules: vec![],
            tls_ca: None,
            tls_client_cert: None,
            tls_client_key: None,
            oauth2: None,
        }
    };

    match &route.capture {
        CredentialRouteCapture::OauthIntercept {
            token_url_match,
            refresh_url_match,
        } => OAUTH_ANTHROPIC_HOSTS
            .iter()
            .map(|host| {
                let host_slug = host
                    .trim_start_matches("https://")
                    .replace('.', "_");
                make(
                    format!("{}oauth_{}_{}", RESERVED_PREFIX, host_slug, route.name),
                    (*host).to_string(),
                    InjectMode::OauthCapture {
                        token_url_match: token_url_match.clone(),
                        refresh_url_match: refresh_url_match.clone(),
                    },
                )
            })
            .collect(),
        CredentialRouteCapture::HelperCommand { .. } => {
            // For `Direct` delivery, the agent hits `upstream`
            // directly and the proxy CONNECT-intercepts. For
            // `Redirected` delivery, the env-override is applied
            // elsewhere (`apply_delivery_env_overrides`) and the
            // route's `prefix` is what the agent's overridden base
            // URL resolves to.
            let _ = &route.delivery; // delivery is applied separately
            vec![make(
                format!("{}gw_{}", RESERVED_PREFIX, route.name),
                route.upstream.clone(),
                InjectMode::OauthCapture {
                    token_url_match: HELPER_CAPTURE_SENTINEL.to_string(),
                    refresh_url_match: HELPER_CAPTURE_SENTINEL.to_string(),
                },
            )]
        }
    }
}

/// Build the env-var overrides this route applies to the sandboxed
/// child. For `Direct` delivery, returns nothing. For `Redirected`
/// delivery, expands the `$ROUTE_BASE_URL` sentinel in each override
/// value to the per-route base URL the proxy serves.
fn build_route_env_overrides(
    route: &crate::profile::ManagedCredentialRoute,
    proxy_port: u16,
) -> Vec<(String, String)> {
    use crate::profile::CredentialRouteDelivery;

    match &route.delivery {
        CredentialRouteDelivery::Direct => Vec::new(),
        CredentialRouteDelivery::Redirected { env_overrides } => {
            let proxy_routes = synthesize_proxy_routes(route);
            // For `HelperCommand` we synthesise exactly one route; for
            // `OauthIntercept` we synthesise three but `Redirected`
            // doesn't make sense there (the agent dials the real
            // hostname). Pick the first prefix — the only one a
            // sensible `Redirected` config produces.
            let prefix = proxy_routes
                .first()
                .map(|r| r.prefix.as_str())
                .unwrap_or("");
            let base_url = format!("http://127.0.0.1:{}/{}", proxy_port, prefix);
            env_overrides
                .iter()
                .map(|o| (o.name.clone(), o.value.replace("$ROUTE_BASE_URL", &base_url)))
                .collect()
        }
    }
}

/// Returns true if any route in the list uses `OauthIntercept`
/// capture — used to decide whether to inject the broker-protection
/// mediation rule and other OAuth-specific bits.
fn any_oauth_intercept(routes: &[crate::profile::ManagedCredentialRoute]) -> bool {
    use crate::profile::CredentialRouteCapture;
    routes
        .iter()
        .any(|r| matches!(r.capture, CredentialRouteCapture::OauthIntercept { .. }))
}

pub(crate) struct ActiveProxyRuntime {
    pub(crate) env_vars: Vec<(String, String)>,
    pub(crate) handle: Option<nono_proxy::server::ProxyHandle>,
    /// The session-scoped `TokenBroker` shared with the proxy as
    /// `Arc<dyn TokenResolver>`. When `Some`, the mediation server
    /// MUST be initialised with this same Arc (rather than a fresh
    /// `TokenBroker::new()`), otherwise nonces minted by the mediation
    /// shim's `capture` action live in a different map than the one
    /// the proxy queries on egress, and resolution silently fails with
    /// a 401 on every request. See `start_proxy_runtime` for the build
    /// site and `execution_runtime::run` for the hand-off into mediation.
    pub(crate) broker: Option<Arc<TokenBroker>>,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct EffectiveProxySettings {
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<crate::profile::AllowDomainEntry>,
    pub(crate) credentials: Vec<String>,
}

pub(crate) fn prepare_proxy_launch_options(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
    silent: bool,
) -> Result<ProxyLaunchOptions> {
    validate_external_proxy_bypass(args, prepared)?;

    let effective_proxy = resolve_effective_proxy_settings(args, prepared);
    let network_profile = effective_proxy.network_profile;
    let allow_domain = effective_proxy.allow_domain;
    let credentials = effective_proxy.credentials;
    let allow_bind_ports = merge_dedup_ports(&prepared.listen_ports, &args.allow_bind);

    let upstream_proxy = if args.allow_net {
        None
    } else {
        args.external_proxy
            .clone()
            .or_else(|| prepared.upstream_proxy.clone())
    };

    let upstream_bypass = if args.allow_net {
        Vec::new()
    } else if args.external_proxy.is_some() {
        args.external_proxy_bypass.clone()
    } else {
        let mut bypass = prepared.upstream_bypass.clone();
        bypass.extend(args.external_proxy_bypass.clone());
        bypass
    };

    let active = if matches!(prepared.caps.network_mode(), nono::NetworkMode::Blocked) {
        if !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
        {
            warn!(
                "--block-net is active; ignoring proxy configuration \
                 that would re-enable network access"
            );
            if !silent {
                eprintln!(
                    "  [nono] Warning: --block-net overrides proxy/credential settings. \
                     Network remains fully blocked."
                );
            }
        }
        false
    } else {
        matches!(
            prepared.caps.network_mode(),
            nono::NetworkMode::ProxyOnly { .. }
        ) || !credentials.is_empty()
            || network_profile.is_some()
            || !allow_domain.is_empty()
            || upstream_proxy.is_some()
    };

    Ok(ProxyLaunchOptions {
        active,
        network_profile,
        allow_domain,
        credentials,
        custom_credentials: prepared.custom_credentials.clone(),
        upstream_proxy,
        upstream_bypass,
        allow_bind_ports,
        proxy_port: args.proxy_port,
        open_url_origins: prepared.open_url_origins.clone(),
        open_url_allow_localhost: prepared.open_url_allow_localhost,
        allow_launch_services_active: prepared.allow_launch_services_active,
        credential_routes: prepared.credential_routes.clone(),
        mediation: prepared.mediation.clone(),
        denied_env_vars: prepared.denied_env_vars.clone(),
        #[cfg(target_os = "macos")]
        trust_proxy_ca: args.trust_proxy_ca,
        proxy_ca_validity: args
            .proxy_ca_validity
            .map(|days| std::time::Duration::from_secs(u64::from(days) * 24 * 60 * 60)),
    })
}

pub(crate) fn resolve_effective_proxy_settings(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> EffectiveProxySettings {
    if args.allow_net {
        return EffectiveProxySettings {
            network_profile: None,
            allow_domain: Vec::new(),
            credentials: Vec::new(),
        };
    }

    let network_profile = args
        .network_profile
        .clone()
        .or_else(|| prepared.network_profile.clone());
    let mut allow_domain = prepared.allow_domain.clone();
    allow_domain.extend(args.allow_proxy.iter().map(|s| parse_allow_domain_arg(s)));
    let mut credentials = prepared.credentials.clone();
    credentials.extend(args.proxy_credential.clone());

    EffectiveProxySettings {
        network_profile,
        allow_domain,
        credentials,
    }
}

/// Parse a `--allow-domain` CLI argument into an `AllowDomainEntry`.
///
/// Accepts either:
/// - A plain hostname: `github.com` → `Plain("github.com")`
/// - A URL with a path pattern: `https://github.com/atko-cic/**` →
///   `WithEndpoints { domain: "github.com", endpoints: [{method: "*", path: "/atko-cic/**"}] }`
fn parse_allow_domain_arg(input: &str) -> crate::profile::AllowDomainEntry {
    if let Ok(parsed) = url::Url::parse(input) {
        let domain = parsed.host_str().unwrap_or(input).to_string();
        let path = parsed.path();
        if path.is_empty() || path == "/" {
            crate::profile::AllowDomainEntry::Plain(domain)
        } else {
            crate::profile::AllowDomainEntry::WithEndpoints {
                domain,
                endpoints: vec![nono_proxy::config::EndpointRule {
                    method: "*".to_string(),
                    path: path.to_string(),
                }],
            }
        }
    } else {
        crate::profile::AllowDomainEntry::Plain(input.to_string())
    }
}

pub(crate) fn merge_dedup_ports(a: &[u16], b: &[u16]) -> Vec<u16> {
    let mut ports = a.to_vec();
    ports.extend_from_slice(b);
    ports.sort_unstable();
    ports.dedup();
    ports
}

pub(crate) fn build_proxy_config_from_flags(
    proxy: &ProxyLaunchOptions,
    workdir: &std::path::Path,
) -> Result<nono_proxy::config::ProxyConfig> {
    let net_policy_json = crate::config::embedded::embedded_network_policy_json();
    let net_policy = network_policy::load_network_policy(net_policy_json)?;

    let mut resolved = if let Some(ref profile_name) = proxy.network_profile {
        network_policy::resolve_network_profile(&net_policy, profile_name)?
    } else {
        network_policy::ResolvedNetworkPolicy {
            hosts: Vec::new(),
            suffixes: Vec::new(),
            routes: Vec::new(),
            profile_credentials: Vec::new(),
        }
    };

    let mut all_credentials = resolved.profile_credentials.clone();
    for cred in &proxy.credentials {
        if !all_credentials.contains(cred) {
            all_credentials.push(cred.clone());
        }
    }

    let mut routes = network_policy::resolve_credentials(
        &net_policy,
        &all_credentials,
        &proxy.custom_credentials,
        workdir,
    )?;

    let (mut plain_hosts, endpoint_routes) =
        network_policy::partition_allow_domain(&net_policy, &proxy.allow_domain)?;
    // Endpoint-restricted domains need filter allowlist access so the proxy
    // can reach upstream after TLS interception (h2 checks the filter at
    // connection setup, before per-stream route matching).
    for route in &endpoint_routes {
        if let Some(ref hp) = route.upstream.strip_prefix("https://") {
            plain_hosts.push(hp.to_string());
        } else if let Some(ref hp) = route.upstream.strip_prefix("http://") {
            plain_hosts.push(hp.to_string());
        }
    }
    routes.extend(endpoint_routes);
    resolved.routes = routes;

    let mut proxy_config = network_policy::build_proxy_config(&resolved, &plain_hosts);

    if let Some(ref addr) = proxy.upstream_proxy {
        proxy_config.external_proxy = Some(nono_proxy::config::ExternalProxyConfig {
            address: addr.clone(),
            auth: None,
            bypass_hosts: proxy.upstream_bypass.clone(),
        });
    }

    if let Some(port) = proxy.proxy_port {
        proxy_config.bind_port = port;
    }

    proxy_config.ca_validity = proxy.proxy_ca_validity;

    Ok(proxy_config)
}

pub(crate) fn start_proxy_runtime(
    proxy: &ProxyLaunchOptions,
    caps: &mut CapabilitySet,
    workdir: &std::path::Path,
    program: &OsStr,
) -> Result<ActiveProxyRuntime> {
    if !proxy.active {
        return Ok(ActiveProxyRuntime {
            env_vars: Vec::new(),
            handle: None,
            broker: None,
        });
    }

    let mut proxy_config = build_proxy_config_from_flags(proxy, workdir)?;
    proxy_config.direct_connect_ports = caps.tcp_connect_ports().to_vec();

    // Wire up TLS interception: pick a session-scoped directory for the
    // ephemeral CA bundle and merge any parent `SSL_CERT_FILE` so corporate
    // trust survives our env-var override.
    if let Some(dir) = prepare_intercept_ca_dir()? {
        proxy_config.intercept_ca_dir = Some(dir);
        proxy_config.intercept_parent_ca_pems = read_parent_ssl_cert_file();
    }

    // Unified credential-route wiring. The legacy per-feature paths
    // (`oauth_capture: true`, `apikey_gateway: {...}`) have already
    // been folded into `proxy.credential_routes` by
    // `crate::profile::resolve_credential_routes`. From here on we
    // iterate the unified representation: each entry expands to one
    // or more proxy routes (via `synthesize_proxy_routes`) and zero or
    // more env-var overrides applied to the child (via
    // `build_route_env_overrides`).
    //
    // CA materialisation and `NODE_EXTRA_CA_CERTS` env injection are
    // handled by upstream's `intercept_ca_dir` +
    // `ProxyHandle::env_vars()` whenever any route trips
    // `requires_intercept` — this block only adds the broker-specific
    // bits: synthetic routes and a session-scoped `TokenBroker`
    // handed to the proxy as `Arc<dyn TokenResolver>`.
    let broker_required = !proxy.credential_routes.is_empty();
    let has_oauth_intercept_route = any_oauth_intercept(&proxy.credential_routes);
    let (proxy_runtime, shared_broker_for_mediation): (
        nono_proxy::ProxyRuntime,
        Option<Arc<TokenBroker>>,
    ) = if broker_required {
        for route in &proxy.credential_routes {
            for synthesised in synthesize_proxy_routes(route) {
                // Idempotent: skip any prefix already declared (the
                // operator may have wired it via raw network-policy
                // routes; conflict-free reuse is fine).
                if !proxy_config
                    .routes
                    .iter()
                    .any(|r| r.prefix == synthesised.prefix)
                {
                    proxy_config.routes.push(synthesised);
                }
            }
        }
        let broker = Arc::new(build_broker());
        // Pre-flight: fail closed on any preconditions the routes
        // declared (no static API-key surface, apiKeyHelper coverage,
        // etc.).
        oauth_preflight::run_credential_routes_preflight(
            broker.as_ref(),
            program,
            proxy.denied_env_vars.as_deref(),
            &proxy.credential_routes,
            &proxy.mediation,
        )?;
        // Two clones of the same broker `Arc`: the proxy holds it as
        // `Arc<dyn TokenResolver>` (trait object, opaque); the mediation
        // server needs `Arc<TokenBroker>` (concrete, for `issue` /
        // `capture_oauth_pair` direct calls). They MUST point at the same
        // underlying broker — otherwise nonces minted by the mediation
        // shim's `capture` action live in a different map than the one
        // the proxy queries on egress, and resolution silently fails.
        // (Found the hard way: 401s on every gateway request even when
        // mediation appeared to mint nonces successfully — see the
        // 2026-06-11 apikey_gateway debug session.)
        let shared_broker: Arc<TokenBroker> = Arc::clone(&broker);
        let resolver: Arc<dyn nono_proxy::TokenResolver> = broker;
        info!(
            "Credential routes wired: {} entries, TokenBroker shared with mediation",
            proxy.credential_routes.len()
        );
        (
            nono_proxy::ProxyRuntime {
                token_resolver: Some(resolver),
            },
            Some(shared_broker),
        )
    } else {
        (nono_proxy::ProxyRuntime::default(), None)
    };
    #[cfg(target_os = "macos")]
    if proxy.trust_proxy_ca {
        if proxy_config.intercept_ca_dir.is_some() {
            let validity = proxy
                .proxy_ca_validity
                .unwrap_or(nono_proxy::tls_intercept::ca::CA_VALIDITY_DEFAULT);
            proxy_config.preloaded_ca = crate::macos_trust::load_or_generate_proxy_ca(validity);
        } else {
            tracing::warn!(
                "--trust-proxy-ca has no effect without TLS-intercepting credential routes"
            );
        }
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy runtime: {}", e)))?;
    let handle = rt
        .block_on(async {
            nono_proxy::server::start_with_runtime(proxy_config.clone(), proxy_runtime).await
        })
        .map_err(|e| NonoError::SandboxInit(format!("Failed to start proxy: {}", e)))?;

    let port = handle.port;
    if proxy.allow_bind_ports.is_empty() {
        info!("Network proxy started on localhost:{}", port);
    } else {
        info!(
            "Network proxy started on localhost:{}, bind ports: {:?}",
            port, proxy.allow_bind_ports
        );
    }

    // Per-route diagnostic banner. Lifts credential resolution status —
    // including misses — to the user-visible info level so the silent
    // "WARN at debug" failure mode (issue #797) becomes immediately
    // discoverable.
    let route_rows = handle.route_diagnostics(&proxy_config);
    if !route_rows.is_empty() {
        info!("Proxy routes:");
        for (prefix, summary) in &route_rows {
            info!("  /{}  {}", prefix, summary);
        }
        if handle.intercept_ca_path().is_some() {
            info!(
                "TLS interception trust bundle: {}",
                handle
                    .intercept_ca_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default()
            );
        }
    }
    // OAuth-intercept capture requires the sandboxed child to bind a
    // localhost port for the browser-redirect callback server (Claude
    // Code 2.1.x spawns one for the OAuth `/login` flow). Inject a
    // sentinel bind port (0) when any OAuth-intercept route is active
    // and the operator hasn't already granted one. On macOS, Seatbelt's
    // `(allow network-bind)` is blanket — it can't filter by port — so
    // any non-empty bind_ports list suffices to enable bind() at all.
    // `HelperCommand` capture has no `/login` flow and doesn't need this.
    let bind_ports = if has_oauth_intercept_route && proxy.allow_bind_ports.is_empty() {
        vec![0]
    } else {
        proxy.allow_bind_ports.clone()
    };
    caps.set_network_mode_mut(nono::NetworkMode::ProxyOnly { port, bind_ports });

    // Grant the sandboxed child a read capability on the ephemeral
    // trust bundle so `SSL_CERT_FILE` etc. are actually openable after
    // the sandbox is applied. Only when interception is active.
    //
    // The bundle lives under `~/.nono/sessions/...`, which the protected-root
    // deny rules (`emit_protected_root_deny_rules`) cover with
    // `(deny file-read-data (subpath "~/.nono"))`. On macOS, action specificity
    // beats path specificity in Seatbelt: a `file-read*` allow on a literal
    // path is shadowed by an action-specific `file-read-data` deny on a
    // containing subpath. To override, emit action-matching `file-read-data`
    // and `file-read-metadata` allows as platform rules, which are appended
    // after the deny and win by both action specificity and last-match.
    //
    // On Linux, Landlock cannot express deny-within-allow, so the protected-
    // root rules don't shadow the grant; a plain FS cap is sufficient.
    if let Some(ca_path) = handle.intercept_ca_path() {
        #[cfg(target_os = "macos")]
        {
            let path_str = crate::policy::path_to_utf8(ca_path)?;
            let escaped = crate::policy::escape_seatbelt_path(path_str)?;
            caps.add_platform_rule(format!("(allow file-read-data (literal \"{}\"))", escaped))?;
            caps.add_platform_rule(format!(
                "(allow file-read-metadata (literal \"{}\"))",
                escaped
            ))?;
        }
        #[cfg(not(target_os = "macos"))]
        {
            caps.allow_file_mut(ca_path, AccessMode::Read)
                .map_err(|e| {
                    NonoError::SandboxInit(format!(
                        "Failed to grant read capability on TLS-intercept bundle '{}': {}",
                        ca_path.display(),
                        e
                    ))
                })?;
        }
        debug!(
            "Granted sandboxed child read access to TLS-intercept trust bundle: {}",
            ca_path.display()
        );
    }

    let mut env_vars: Vec<(String, String)> = Vec::new();
    for (key, value) in handle.env_vars() {
        env_vars.push((key, value));
    }

    for (key, value) in handle.credential_env_vars(&proxy_config) {
        env_vars.push((key, value));
    }

    // Per-credential-route env-var overrides (e.g.
    // `ANTHROPIC_BASE_URL` for the legacy `apikey_gateway` path,
    // `OPENAI_BASE_URL` for an OpenAI gateway, etc.). Pushed AFTER
    // `credential_env_vars` so any auto-emitted `<PREFIX>_BASE_URL`
    // from the route iteration is shadowed by the credential-route's
    // explicit override (env var assembly uses last-write-wins
    // downstream). Routes with `Direct` delivery contribute nothing
    // here — the agent already targets the real hostname.
    for route in &proxy.credential_routes {
        for (key, value) in build_route_env_overrides(route, port) {
            env_vars.push((key, value));
        }
    }

    std::mem::forget(rt);

    Ok(ActiveProxyRuntime {
        env_vars,
        handle: Some(handle),
        broker: shared_broker_for_mediation,
    })
}

/// Choose the directory the proxy will write the TLS-intercept trust bundle
/// into. Conventionally `~/.nono/sessions/<random>/`, kept owner-only.
///
/// Returns `Ok(None)` if no `HOME` is set (rare edge cases like CI). We log
/// a warning rather than failing because TLS interception is opt-in: a
/// missing directory just means CONNECTs to L7-bearing routes will get the
/// usual 403, which is a coherent fallback rather than a hard error.
fn prepare_intercept_ca_dir() -> Result<Option<PathBuf>> {
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => {
            warn!(
                "no $HOME found; skipping TLS-intercept setup (CONNECTs to L7-bearing routes \
                 will be denied with 403)"
            );
            return Ok(None);
        }
    };
    // PID + start-time-nanos disambiguates concurrent invocations without
    // pulling in a randomness dep. Cryptographic uniqueness isn't the
    // goal; we just need two `nono` processes started at the same second
    // not to share a directory.
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let suffix = format!("{}-{:09}", pid, nanos);
    let dir = home
        .join(".nono")
        .join("sessions")
        .join(format!("intercept-{}", suffix));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        warn!(
            "failed to create TLS-intercept dir '{}': {}; skipping interception",
            dir.display(),
            e
        );
        return Ok(None);
    }
    set_intercept_ca_dir_permissions(&dir)?;
    Ok(Some(dir))
}

/// Construct the OAuth-capture broker.
///
/// On macOS, attempts to back the broker with a code-signed-ACL keychain
/// entry under `service="nono", account="claude_oauth_broker"` so the
/// captured `(access, refresh)` pair survives across nono sessions and a
/// returning user does not have to `/login` again for every new session.
/// If keystore init or load fails (locked keychain over SSH, ACL
/// mismatch after a `cargo install` reinstall, etc.), falls back to an
/// in-memory broker with a warning rather than refusing to start.
///
/// On non-macOS platforms, returns an in-memory-only broker. Linux's
/// keyring backends have no per-entry ACL so persisting real OAuth
/// tokens there would expose them to any same-user process, defeating
/// the protection model.
fn build_broker() -> TokenBroker {
    #[cfg(target_os = "macos")]
    {
        use crate::mediation::broker_store::{KeystoreBrokerStore, current_claude_access_token};
        let store = std::sync::Arc::new(KeystoreBrokerStore::default_for_claude_oauth());
        // Pass the production reader so `with_store_and_reader` can
        // detect orphaned broker records (e.g. user `/logout`-ed
        // inside claude but our persisted record still holds the
        // real refresh token).
        match TokenBroker::with_store_and_reader(store, Box::new(current_claude_access_token)) {
            Ok(broker) => return broker,
            Err(e) => {
                tracing::warn!(
                    "OAuth broker keystore unavailable, falling back to in-memory only \
                     (cross-session resume will not work this run): {e}"
                );
            }
        }
    }
    TokenBroker::new()
}

#[cfg(unix)]
fn set_intercept_ca_dir_permissions(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        NonoError::SandboxInit(format!(
            "failed to set owner-only permissions on TLS-intercept dir '{}': {e}",
            dir.display()
        ))
    })
}

#[cfg(not(unix))]
fn set_intercept_ca_dir_permissions(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Read the parent process's `SSL_CERT_FILE`, if set, so any corporate
/// CAs configured on the host are merged into the intercept trust bundle.
///
/// On any read failure we log at warn and return `None` — the proxy will
/// continue without merging, and the agent may lose trust for corp hosts.
/// Aborting feels too aggressive: nono is opt-in, and TLS interception is
/// opt-in within nono, so a corp-trust mismatch is a recoverable misconfig
/// not a security failure.
fn read_parent_ssl_cert_file() -> Option<Vec<u8>> {
    let path = std::env::var_os("SSL_CERT_FILE")?;
    match std::fs::read(&path) {
        Ok(bytes) => {
            debug!(
                "merging parent SSL_CERT_FILE '{}' ({} bytes) into TLS-intercept trust bundle",
                std::path::Path::new(&path).display(),
                bytes.len()
            );
            Some(bytes)
        }
        Err(e) => {
            warn!(
                "could not read parent SSL_CERT_FILE '{}': {} — corporate CAs configured on \
                 the host will not be trusted by the sandboxed child",
                std::path::Path::new(&path).display(),
                e
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn set_intercept_ca_dir_permissions_fails_closed() -> Result<()> {
        let tmp = tempfile::tempdir().map_err(NonoError::Io)?;
        let missing = tmp.path().join("missing");

        let err = set_intercept_ca_dir_permissions(&missing)
            .err()
            .ok_or_else(|| {
                NonoError::SandboxInit("expected missing intercept dir to fail".to_string())
            })?;

        assert!(matches!(err, NonoError::SandboxInit(_)));
        assert!(err.to_string().contains("TLS-intercept dir"));
        Ok(())
    }

    pub(super) fn oauth_intercept_route() -> crate::profile::ManagedCredentialRoute {
        use crate::profile::{
            CredentialRouteBearer, CredentialRouteCapture, CredentialRouteDelivery,
            ManagedCredentialRoute,
        };
        ManagedCredentialRoute {
            name: "test_anthropic".to_string(),
            upstream: "https://api.anthropic.com".to_string(),
            capture: CredentialRouteCapture::OauthIntercept {
                token_url_match: "/v1/oauth/token".to_string(),
                refresh_url_match: "/v1/oauth/token".to_string(),
            },
            delivery: CredentialRouteDelivery::Direct,
            bearer: CredentialRouteBearer {
                header: "authorization".to_string(),
                format: "Bearer {}".to_string(),
            },
            preflight: vec![],
        }
    }

    #[test]
    fn synthesize_oauth_intercept_targets_three_hosts() {
        // Binary analysis of Claude Code 2.1.x shows the OAuth code-
        // exchange `TOKEN_URL` lives at platform.claude.com, but the
        // agent also talks to api.anthropic.com and claude.ai. All
        // three must have OAuth-capture routes so capture fires
        // regardless of which host the client picks.
        let route = oauth_intercept_route();
        let routes = synthesize_proxy_routes(&route);
        let upstreams: Vec<&str> = routes.iter().map(|r| r.upstream.as_str()).collect();
        assert!(upstreams.contains(&"https://api.anthropic.com"));
        assert!(upstreams.contains(&"https://claude.ai"));
        assert!(upstreams.contains(&"https://platform.claude.com"));
        assert_eq!(routes.len(), 3);
    }

    #[test]
    fn synthesize_oauth_intercept_uses_inject_mode_oauth_capture() {
        // Every synthesised route must carry the OauthCapture inject
        // mode so `LoadedRoute::requires_intercept` trips and the
        // dispatcher TLS-terminates the CONNECT for these hosts.
        let route = oauth_intercept_route();
        for proxy_route in synthesize_proxy_routes(&route) {
            assert!(
                matches!(
                    proxy_route.inject_mode,
                    nono_proxy::config::InjectMode::OauthCapture { .. }
                ),
                "route '{}' must use OauthCapture inject_mode",
                proxy_route.prefix
            );
            assert!(
                proxy_route.credential_key.is_none(),
                "OauthCapture routes carry no pre-loaded credential"
            );
        }
    }

    #[test]
    fn test_parse_allow_domain_arg_plain_hostname() {
        let entry = parse_allow_domain_arg("github.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("github.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_with_path() {
        let entry = parse_allow_domain_arg("https://github.com/atko-cic/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints.len(), 1);
                assert_eq!(endpoints[0].method, "*");
                assert_eq!(endpoints[0].path, "/atko-cic/**");
            }
            _ => panic!("expected WithEndpoints, got: {:?}", entry),
        }
    }

    #[test]
    fn test_parse_allow_domain_arg_url_root_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com/");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_url_no_path_is_plain() {
        let entry = parse_allow_domain_arg("https://api.example.com");
        assert_eq!(
            entry,
            crate::profile::AllowDomainEntry::Plain("api.example.com".to_string())
        );
    }

    #[test]
    fn test_parse_allow_domain_arg_deep_path() {
        let entry = parse_allow_domain_arg("https://github.com/org/repo/tree/**");
        match entry {
            crate::profile::AllowDomainEntry::WithEndpoints { domain, endpoints } => {
                assert_eq!(domain, "github.com");
                assert_eq!(endpoints[0].path, "/org/repo/tree/**");
            }
            _ => panic!("expected WithEndpoints"),
        }
    }
}

#[cfg(test)]
mod credential_route_synthesis_tests {
    use super::tests::*;
    use super::*;

    #[test]
    fn oauth_intercept_routes_use_reserved_namespace() {
        // Sanity-check: every injected route sits in the reserved
        // namespace so a user route with the same prefix is rejected at
        // config load and cannot shadow a capture route.
        let route = oauth_intercept_route();
        for proxy_route in synthesize_proxy_routes(&route) {
            assert!(
                nono_proxy::is_reserved_prefix(&proxy_route.prefix),
                "OAuth-capture route prefix {:?} must use the reserved namespace",
                proxy_route.prefix
            );
        }
    }

    #[test]
    fn oauth_intercept_routes_distinct_prefixes() {
        let route = oauth_intercept_route();
        let routes = synthesize_proxy_routes(&route);
        let mut prefixes: Vec<_> = routes.iter().map(|r| r.prefix.clone()).collect();
        prefixes.sort();
        prefixes.dedup();
        assert_eq!(
            prefixes.len(),
            routes.len(),
            "every OAuth-capture route should have a distinct prefix"
        );
    }
}
