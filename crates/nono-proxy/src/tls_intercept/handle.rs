//! CONNECT-intercept entry point.
//!
//! Terminates TLS from the agent, reads the inner HTTP/1.1 request, and
//! dispatches it via [`crate::forward::forward_request`].
//!
//! Route selection for each inner request:
//!   - **1 match** — inject that route's managed credential.
//!   - **0 matches** — forward without credentials (passthrough).
//!   - **2+ matches** — reject as ambiguous (403).
//!
//! Auth is validated on the outer CONNECT `Proxy-Authorization` only;
//! inner requests are not required to carry a token.

use crate::audit;
use crate::config::InjectMode;
use crate::credential::CredentialStore;
use crate::error::{ProxyError, Result};
use crate::filter::ProxyFilter;
use crate::forward::{self, AuditCtx, UpstreamScheme, UpstreamSpec, UpstreamStrategy};
use crate::reverse;
use crate::route::RouteStore;
use crate::tls_intercept::acceptor;
use crate::tls_intercept::cert_cache::CertCache;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Header byte cap matching the outer proxy's `MAX_HEADER_SIZE` to keep the
/// memory ceiling consistent.
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Per-connection context passed to [`handle_intercept_connect`].
pub struct InterceptCtx<'a> {
    pub route_id: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub route_store: &'a RouteStore,
    pub credential_store: &'a CredentialStore,
    pub session_token: &'a Zeroizing<String>,
    pub cert_cache: Arc<CertCache>,
    pub tls_connector: &'a tokio_rustls::TlsConnector,
    pub filter: &'a ProxyFilter,
    pub audit_log: Option<&'a audit::SharedAuditLog>,
    /// Optional in-process credential broker used by OAuth-capture
    /// routes. `None` when OAuth capture is not configured for this
    /// proxy session; the capture path is then inert.
    pub token_resolver: Option<&'a Arc<dyn crate::broker::TokenResolver>>,
    /// Optional proxy-provisioned credential store. `None` when no
    /// route uses `proxy_provisioned_credential` capture; the
    /// substitution path is then inert. When `Some`, routes carrying
    /// `LoadedRoute::provisioned_credential_route = Some(name)` look
    /// up `name` here on egress and replace the inbound bearer.
    pub provisioned_store: Option<&'a Arc<crate::provisioned::ProvisionedStore>>,
}

/// Handle a CONNECT request that matched a route requiring L7 visibility.
///
/// Caller responsibilities (already enforced in `server.rs`):
/// * Validate strict OUTER `Proxy-Authorization` against the session token.
/// * Confirm `route_store.has_intercept_route(host, port)`.
pub async fn handle_intercept_connect(stream: &mut TcpStream, ctx: InterceptCtx<'_>) -> Result<()> {
    debug!(
        "tls_intercept: accepting CONNECT to {}:{} for L7 inspection",
        ctx.host, ctx.port
    );

    // 200 to the agent before the inner TLS handshake.
    let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    stream.write_all(response).await?;
    stream.flush().await?;

    let server_config = acceptor::build_server_config(Arc::clone(&ctx.cert_cache))?;
    let tls_acceptor = TlsAcceptor::from(server_config);

    let mut tls_stream = match tls_acceptor.accept(&mut *stream).await {
        Ok(s) => s,
        Err(e) => {
            // Hard fail: never silently degrade. Agent sees a TLS error,
            // we record the failure with a sanitized rustls Display string.
            let reason = format!("tls handshake failed: {}", e);
            warn!(
                "tls_intercept: handshake failed for {}:{} — {}. \
                 Agent likely pins certs or carries a hard-coded trust list. \
                 Remove endpoint_rules / credential_key from the route to fall \
                 back to a transparent CONNECT tunnel.",
                ctx.host, ctx.port, e
            );
            audit::log_denied(
                ctx.audit_log,
                audit::ProxyMode::ConnectIntercept,
                &audit::EventContext {
                    route_id: ctx.route_id,
                    auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
                    auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
                    denial_category: Some(
                        nono::undo::NetworkAuditDenialCategory::InterceptHandshakeFailed,
                    ),
                    ..audit::EventContext::default()
                },
                ctx.host,
                ctx.port,
                &reason,
            );
            return Ok(());
        }
    };

    // Acceptance event: the inner TLS handshake completed. Per-request L7
    // events are emitted by `forward_request` once we hand off below.
    audit::log_allowed(
        ctx.audit_log,
        audit::ProxyMode::ConnectIntercept,
        &audit::EventContext {
            route_id: ctx.route_id,
            auth_mechanism: Some(nono::undo::NetworkAuditAuthMechanism::ProxyAuthorization),
            auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Succeeded),
            ..audit::EventContext::default()
        },
        ctx.host,
        ctx.port,
        "CONNECT",
    );

    if let Err(e) = forward_inner_request(&mut tls_stream, &ctx).await {
        debug!(
            "tls_intercept: inner-request handling failed for {}:{}: {}",
            ctx.host, ctx.port, e
        );
    }
    Ok(())
}

/// Read one inner HTTP/1.1 request, select the matching route, inject
/// credentials if matched, and forward upstream.
async fn forward_inner_request<S>(tls_stream: &mut S, ctx: &InterceptCtx<'_>) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // --- Parse the inner request line + headers ---
    let mut buf_reader = BufReader::new(&mut *tls_stream);
    let mut first_line = String::new();
    buf_reader.read_line(&mut first_line).await?;
    if first_line.is_empty() {
        return Ok(());
    }

    let mut header_bytes = Vec::new();
    loop {
        let mut line = String::new();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 || line.trim().is_empty() {
            break;
        }
        header_bytes.extend_from_slice(line.as_bytes());
        if header_bytes.len() > MAX_HEADER_SIZE {
            // Mirror the outer proxy's behaviour. We have to write into the
            // BufReader's inner stream — release it first.
            let buffered = buf_reader.buffer().to_vec();
            drop(buf_reader);
            tls_stream
                .write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n")
                .await?;
            let _ = buffered;
            return Ok(());
        }
    }
    let buffered = buf_reader.buffer().to_vec();
    drop(buf_reader);

    let first_line = first_line.trim_end();
    let (method, path, version) = parse_request_line(first_line)?;
    debug!("tls_intercept: inner request {} {}", method, path);

    // Route selection: 1 match → cred, 0 → passthrough, 2+ → 403.
    let host_port = format!("{}:{}", ctx.host.to_lowercase(), ctx.port);
    let candidates = ctx.route_store.lookup_all_by_upstream(&host_port);
    if candidates.is_empty() {
        warn!(
            "tls_intercept: no route for {} after intercept handshake",
            host_port
        );
        reverse::send_error_generic(tls_stream, 502, "Bad Gateway").await?;
        return Ok(());
    }

    let mut matches: Vec<(&str, &crate::route::LoadedRoute)> = Vec::new();
    let mut catch_all: Option<(&str, &crate::route::LoadedRoute)> = None;
    let mut has_endpoint_only_route = false;
    let mut endpoint_authorized = false;
    for (prefix, route) in &candidates {
        if route.endpoint_rules.is_empty() {
            if catch_all.is_none() {
                catch_all = Some((prefix, route));
            }
        } else if route.endpoint_rules.is_allowed(&method, &path) {
            matches.push((prefix, route));
            if !route.requires_managed_credential {
                endpoint_authorized = true;
            }
        } else if !route.requires_managed_credential {
            has_endpoint_only_route = true;
        }
    }

    // Endpoint-only authorization layer (from allow_domain with endpoints):
    // if any _ep_ route exists for this upstream, the request must match at
    // least one of their endpoint rules. This gates access BEFORE credential
    // selection — a credential catch-all cannot bypass endpoint restrictions.
    if has_endpoint_only_route && !endpoint_authorized {
        let reason = format!(
            "endpoint rules denied {} {}: no rule matched on {}:{}",
            method, path, ctx.host, ctx.port
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                ..audit::EventContext::default()
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // Ambiguous route check only applies to credential-injection routes.
    // Multiple endpoint-only authorization routes matching the same request
    // is fine (they all just allow it); ambiguity is a problem only when the
    // proxy must choose which credential to inject.
    let credential_matches: Vec<_> = matches
        .iter()
        .filter(|(_, route)| route.requires_managed_credential)
        .collect();
    if credential_matches.len() > 1 {
        let names: Vec<_> = credential_matches.iter().map(|(p, _)| *p).collect();
        let reason = format!(
            "ambiguous route: {} {} matched {} credential routes: {:?}. \
             Narrow endpoint_rules so each request matches exactly one route.",
            method,
            path,
            credential_matches.len(),
            names
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::EndpointPolicy),
                ..audit::EventContext::default()
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // Prefer the credential route over endpoint-only authorization routes.
    let selected = matches
        .iter()
        .find(|(_, route)| route.requires_managed_credential)
        .or(matches.first())
        .copied()
        .or(catch_all);
    let service: Option<&str> = selected.map(|(s, _)| s);
    let route: Option<&crate::route::LoadedRoute> = selected.map(|(_, r)| r);
    match service {
        Some(svc) => debug!(
            "tls_intercept: selected route '{}' for {} {}",
            svc, method, path
        ),
        None => debug!(
            "tls_intercept: no endpoint_rules matched {} {}, forwarding without credentials",
            method, path
        ),
    }

    let cred = service.and_then(|s| ctx.credential_store.get(s));
    let oauth2_route = service.and_then(|s| ctx.credential_store.get_oauth2(s));

    if let Some(rt) = route
        && rt.missing_managed_credential(cred.is_some(), oauth2_route.is_some())
    {
        let svc = service.unwrap_or("unknown");
        let reason = format!(
            "managed credential unavailable for route '{}': intercepted request requires proxy-supplied auth",
            svc
        );
        warn!("tls_intercept: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                route_id: service,
                auth_mechanism: rt.managed_auth_mechanism.clone(),
                auth_outcome: Some(nono::undo::NetworkAuditAuthOutcome::Failed),
                managed_credential_active: Some(false),
                injection_mode: rt.managed_injection_mode.clone(),
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::ManagedCredentialUnavailable,
                ),
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 503, "Service Unavailable").await?;
        return Ok(());
    }

    // --- Path / credential transformation ---
    let transformed_path = if let Some(cred) = cred {
        let cleaned = reverse::strip_proxy_artifacts(
            &path,
            &cred.proxy_inject_mode,
            &cred.inject_mode,
            cred.proxy_path_pattern.as_deref(),
            cred.proxy_query_param_name.as_deref(),
        );
        reverse::transform_path_for_mode(
            &cred.inject_mode,
            &cleaned,
            cred.path_pattern.as_deref(),
            cred.path_replacement.as_deref(),
            cred.query_param_name.as_deref(),
            &cred.raw_credential,
        )?
    } else {
        path.clone()
    };

    // --- Resolve upstream IPs (DNS-rebind-safe via filter) ---
    let check = ctx.filter.check_host(ctx.host, ctx.port).await?;
    if !check.result.is_allowed() {
        let reason = check.result.reason();
        warn!("tls_intercept: upstream host denied by filter: {}", reason);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                route_id: service,
                managed_credential_active: Some(cred.is_some() || oauth2_route.is_some()),
                injection_mode: cred.map(|c| match c.inject_mode {
                    InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
                    InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
                    InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
                    InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
                    // OauthCapture is response-side and shouldn't reach
                    // here; plan step 17 audit hardening adds the proper
                    // variant.
                    InjectMode::OauthCapture { .. } => {
                        nono::undo::NetworkAuditInjectionMode::Header
                    }
                }),
                denial_category: Some(nono::undo::NetworkAuditDenialCategory::HostDenied),
                ..audit::EventContext::default()
            },
            ctx.host,
            ctx.port,
            &reason,
        );
        reverse::send_error_generic(tls_stream, 403, "Forbidden").await?;
        return Ok(());
    }

    // --- Detect OAuth capture (Layer 1 response-body rewrite) ---
    //
    // Route flagged with `InjectMode::OauthCapture` + inbound path
    // matches one of the configured token/refresh URLs + the proxy
    // session was started with a `TokenResolver`. When all three hold,
    // we set up `oauth_capture_active` so:
    //   1. Accept-Encoding is stripped from the upstream request (so the
    //      upstream returns plaintext JSON we can parse), and
    //   2. a response-body rewriter is supplied to `forward_request`
    //      which swaps `access_token` / `refresh_token` for nonces
    //      minted by the broker.
    let oauth_capture_active = match (route, ctx.token_resolver) {
        (Some(rt), Some(_resolver)) => rt
            .oauth_capture_match
            .as_ref()
            .is_some_and(|oc| path == oc.token_url_match || path == oc.refresh_url_match),
        _ => false,
    };

    // --- Read body (Content-Length only; chunked is rare in API requests
    // and matches the existing reverse-proxy contract). ---
    let strip_header = cred.map(|c| c.proxy_header_name.as_str()).unwrap_or("");
    let mut filtered_headers = reverse::filter_headers(&header_bytes, strip_header);
    if oauth_capture_active {
        // Force identity encoding so the OAuth-rewriter sees plaintext
        // JSON rather than gzip/br/etc. Pass-through-on-error keeps
        // /login working if the upstream returns non-JSON anyway.
        filtered_headers.retain(|(name, _)| !name.eq_ignore_ascii_case("accept-encoding"));
    }
    // Layer 1.2: nonce → real Bearer translation inside the CONNECT
    // tunnel. The Layer 1 response rewriter swaps real OAuth tokens
    // for `nono_<hex>` nonces in the OAuth callback body, so the
    // sandboxed client subsequently uses nonces. The Anthropic Console
    // flow's immediate follow-up `POST /api/oauth/claude_cli/create_api_key`
    // travels through this same CONNECT tunnel — it'd reach Anthropic
    // with the nonce as Authorization and get 401. Translate to the
    // real bearer here, gated on the route being OAuth-capture-enabled.
    // Note this fires on *any* path within the tunnel (not just the
    // configured token URLs), since the client may send authenticated
    // API calls to many paths and they all need translation.
    if let (Some(_), Some(resolver)) = (
        &route.and_then(|r| r.oauth_capture_match.as_ref()),
        ctx.token_resolver,
    ) {
        rewrite_bearer_header(&mut filtered_headers, resolver.as_ref());
    }

    // Proxy-provisioned credential substitution. When the route is
    // configured with `provisioned_credential_route: Some(name)`, the
    // egress credential is sourced from the `ProvisionedStore` (not
    // from any header the agent sent) and replaces the inbound bearer
    // header entirely. Mutually exclusive with nonce resolution above
    // — proxy-provisioned routes don't have nonces because the agent
    // never sees the real credential and the auto-injected `respond`
    // mediation rule returns a hardcoded sentinel that we discard
    // here.
    //
    // If the route requires a provisioned credential but the inbound
    // request has no value in the configured bearer header, return a
    // 401 to the sandbox. This catches mis-configured agents that
    // haven't been told to send anything (e.g. no apiKeyHelper set)
    // — without it, we'd silently inject a credential the agent did
    // not authenticate to use.
    if let Some(route) = route
        && let Some(route_name) = route.provisioned_credential_route.as_deref()
    {
        let bearer_header_name = route.provisioned_inject_header.as_str();
        let format_template = route.provisioned_inject_format.as_str();
        let inbound_present = filtered_headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case(bearer_header_name) && !v.is_empty());
        if !inbound_present {
            warn!(
                "proxy-provisioned route '{}' requires inbound '{}' header from agent \
                 so the proxy has an auth shape to substitute; agent sent nothing. \
                 Returning 401 to sandbox.",
                route_name, bearer_header_name
            );
            reverse::send_error_generic(
                tls_stream,
                401,
                "nono proxy: agent did not send a credential header for this route",
            )
            .await?;
            return Ok(());
        }
        if let Some(store) = ctx.provisioned_store {
            if let Some(real) = store.get(route_name).await {
                let outbound_value = format_template.replace("{}", real.as_str());
                // Replace existing header(s) with the same name
                filtered_headers.retain(|(n, _)| !n.eq_ignore_ascii_case(bearer_header_name));
                filtered_headers.push((bearer_header_name.to_string(), outbound_value));
                debug!(
                    "tls_intercept: substituted inbound '{}' with proxy-provisioned credential for route '{}'",
                    bearer_header_name, route_name
                );
            } else {
                warn!(
                    "tls_intercept: route '{}' provisioned-credential lookup missed (store entry absent); forwarding inbound header as-is",
                    route_name
                );
            }
        } else {
            warn!(
                "tls_intercept: route '{}' is provisioned but ProvisionedStore is None; forwarding inbound header as-is",
                route_name
            );
        }

        // Inject egress_headers declared on the route (e.g. org-id,
        // provider). These are injected after the provisioned-credential
        // substitution so the profile can supply gateway-specific
        // metadata the agent may not forward in CONNECT mode.
        for (hdr_name, hdr_value) in &route.egress_headers {
            filtered_headers.retain(|(n, _)| !n.eq_ignore_ascii_case(hdr_name));
            filtered_headers.push((hdr_name.clone(), hdr_value.clone()));
        }
    }

    // Also inject egress_headers for non-provisioned routes (e.g.
    // OAuth-intercept routes may also need gateway metadata injected).
    if let Some(route) = route
        && route.provisioned_credential_route.is_none()
        && !route.egress_headers.is_empty()
    {
        for (hdr_name, hdr_value) in &route.egress_headers {
            filtered_headers.retain(|(n, _)| !n.eq_ignore_ascii_case(hdr_name));
            filtered_headers.push((hdr_name.clone(), hdr_value.clone()));
        }
    }

    let content_length = reverse::extract_content_length(&header_bytes);
    let body = match reverse::read_request_body(tls_stream, content_length, &buffered).await? {
        Some(b) => b,
        None => return Ok(()),
    };

    // --- Build upstream request bytes ---
    let upstream_authority = reverse::format_host_header(UpstreamScheme::Https, ctx.host, ctx.port);
    let mut request = Zeroizing::new(format!(
        "{} {} {}\r\nHost: {}\r\n",
        method, transformed_path, version, upstream_authority
    ));
    if let Some(cred) = cred {
        reverse::inject_credential_for_mode(cred, &mut request);
    }
    let auth_header_lower = cred.map(|c| c.header_name.to_lowercase());
    for (name, value) in &filtered_headers {
        if let (Some(cred), Some(hdr)) = (cred, auth_header_lower.as_ref())
            && matches!(cred.inject_mode, InjectMode::Header | InjectMode::BasicAuth)
            && name.to_lowercase() == *hdr
        {
            continue;
        }
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("Connection: close\r\n");
    if !body.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");

    // --- Forward via shared pipeline ---
    let connector = route
        .and_then(|r| r.tls_connector.as_ref())
        .unwrap_or(ctx.tls_connector);
    let upstream_spec = UpstreamSpec {
        scheme: UpstreamScheme::Https,
        host: ctx.host,
        port: ctx.port,
        strategy: UpstreamStrategy::Direct {
            resolved_addrs: &check.resolved_addrs,
        },
        tls_connector: connector,
    };
    let audit_ctx = AuditCtx {
        log: ctx.audit_log,
        mode: audit::ProxyMode::ConnectIntercept,
        event_ctx: audit::EventContext {
            route_id: service,
            auth_mechanism: cred.map(|c| match c.proxy_inject_mode {
                InjectMode::Header | InjectMode::BasicAuth => {
                    nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                }
                InjectMode::UrlPath => nono::undo::NetworkAuditAuthMechanism::PhantomPath,
                InjectMode::QueryParam => nono::undo::NetworkAuditAuthMechanism::PhantomQuery,
                // OauthCapture is response-side; defensive default
                // until plan step 17 adds a dedicated variant.
                InjectMode::OauthCapture { .. } => {
                    nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                }
            }),
            auth_outcome: cred.map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded),
            managed_credential_active: Some(cred.is_some() || oauth2_route.is_some()),
            injection_mode: cred.map(|c| match c.inject_mode {
                InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
                InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
                InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
                InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
                // OauthCapture is response-side; see comment on the
                // deeper-indented arm above.
                InjectMode::OauthCapture { .. } => nono::undo::NetworkAuditInjectionMode::Header,
            }),
            denial_category: None,
        },
        target: ctx.host,
        method: &method,
        path: &path,
    };

    // Build the OAuth response hook if capture is active. The closure
    // owns an `Arc<dyn TokenResolver>` clone so it can mint nonces
    // when the upstream response arrives. Pass-through-on-error: when
    // `rewrite_oauth_json_body` returns `NotJson` or `NoTokenFields`,
    // the hook returns `None` and `forward_request` forwards the
    // original bytes unchanged.
    //
    // Audit logging of capture events (step 17 / commit `6df85cc`) is
    // wired through `audit::log_oauth_capture` from within this hook
    // so each successful rewrite emits an `OAUTH_CAPTURE substituted=N`
    // event into the ring buffer (with no token/nonce material).
    let response_hook: Option<forward::ResponseBodyRewriter<'_>> = if oauth_capture_active {
        ctx.token_resolver.map(|resolver| {
            let resolver = Arc::clone(resolver);
            let audit_log_clone = ctx.audit_log.cloned();
            let host_for_audit = ctx.host.to_string();
            let port_for_audit = ctx.port;
            let hook: forward::ResponseBodyRewriter<'_> = Box::new(move |body: &[u8]| {
                match crate::oauth_rewrite::rewrite_oauth_json_body(body, resolver.as_ref()) {
                    crate::oauth_rewrite::OauthRewriteOutcome::Rewritten { bytes, substituted } => {
                        audit::log_oauth_capture(
                            audit_log_clone.as_ref(),
                            audit::ProxyMode::ConnectIntercept,
                            &host_for_audit,
                            port_for_audit,
                            substituted,
                        );
                        Some(bytes.to_vec())
                    }
                    crate::oauth_rewrite::OauthRewriteOutcome::NotJson => {
                        warn!(
                            "oauth-capture (tls_intercept): response not JSON; forwarding unchanged"
                        );
                        None
                    }
                    crate::oauth_rewrite::OauthRewriteOutcome::NoTokenFields => {
                        debug!(
                            "oauth-capture (tls_intercept): no token fields; forwarding unchanged"
                        );
                        None
                    }
                }
            });
            hook
        })
    } else {
        None
    };

    // Capture the response status so we can trigger a fire-and-forget
    // refresh of the proxy-provisioned credential if upstream rejected
    // with 401/403. The current request still completes with the
    // upstream's failure status (no in-place retry in v1 — see design
    // doc), but the next request on this route will see the fresh
    // credential. With a typical short-lived token (e.g. ~2h TTL), this
    // means the user sees one failed request per token expiry;
    // subsequent prompts succeed.
    let forward_result = forward::forward_request(
        tls_stream,
        request.as_bytes(),
        &body,
        upstream_spec,
        audit_ctx,
        response_hook,
    )
    .await;
    if let Ok(status) = forward_result
        && (status == 401 || status == 403)
        && let Some(route) = route
        && let Some(route_name) = route.provisioned_credential_route.as_deref()
        && let Some(store) = ctx.provisioned_store
    {
        let store = Arc::clone(store);
        let route_name = route_name.to_string();
        debug!(
            "tls_intercept: upstream returned {} for proxy-provisioned route '{}'; \
             triggering fire-and-forget credential refresh (next request will see fresh value)",
            status, route_name
        );
        tokio::spawn(async move {
            if let Err(e) = store.refresh(&route_name).await {
                warn!(
                    "tls_intercept: post-{} refresh of provisioned credential for route '{}' failed: {}",
                    status, route_name, e
                );
            }
        });
    }
    if let Err(e) = forward_result {
        warn!("tls_intercept: upstream forwarding failed: {}", e);
        audit::log_denied(
            ctx.audit_log,
            audit::ProxyMode::ConnectIntercept,
            &audit::EventContext {
                route_id: service,
                auth_mechanism: cred.map(|c| match c.proxy_inject_mode {
                    InjectMode::Header | InjectMode::BasicAuth => {
                        nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                    }
                    InjectMode::UrlPath => nono::undo::NetworkAuditAuthMechanism::PhantomPath,
                    InjectMode::QueryParam => nono::undo::NetworkAuditAuthMechanism::PhantomQuery,
                    // OauthCapture is response-side; see comment on the
                    // shallower-indented arm above.
                    InjectMode::OauthCapture { .. } => {
                        nono::undo::NetworkAuditAuthMechanism::PhantomHeader
                    }
                }),
                auth_outcome: cred.map(|_| nono::undo::NetworkAuditAuthOutcome::Succeeded),
                managed_credential_active: Some(cred.is_some() || oauth2_route.is_some()),
                injection_mode: cred.map(|c| match c.inject_mode {
                    InjectMode::Header => nono::undo::NetworkAuditInjectionMode::Header,
                    InjectMode::UrlPath => nono::undo::NetworkAuditInjectionMode::UrlPath,
                    InjectMode::QueryParam => nono::undo::NetworkAuditInjectionMode::QueryParam,
                    InjectMode::BasicAuth => nono::undo::NetworkAuditInjectionMode::BasicAuth,
                    // OauthCapture is response-side and shouldn't reach
                    // here; plan step 17 audit hardening adds the proper
                    // variant.
                    InjectMode::OauthCapture { .. } => {
                        nono::undo::NetworkAuditInjectionMode::Header
                    }
                }),
                denial_category: Some(
                    nono::undo::NetworkAuditDenialCategory::UpstreamConnectFailed,
                ),
            },
            ctx.host,
            ctx.port,
            &e.to_string(),
        );
        let _ = reverse::send_error_generic(tls_stream, 502, "Bad Gateway").await;
    }
    Ok(())
}

/// Parse a request line into (method, path, version).
fn parse_request_line(line: &str) -> Result<(String, String, String)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(ProxyError::HttpParse(format!(
            "malformed inner request line: {}",
            line
        )));
    }
    Ok((
        parts[0].to_string(),
        parts[1].to_string(),
        parts[2].to_string(),
    ))
}

/// Translate a `Bearer nono_<hex>` Authorization value in `filtered_headers`
/// to the broker-resolved real bearer. Mirrors the resolver-then-Bearer-
/// prefix logic the reverse proxy already does at its own egress
/// boundary (`reverse.rs` Layer 2); the TLS intercept is the second
/// egress and needs the same treatment for follow-up API calls that
/// travel inside the same CONNECT tunnel.
///
/// No-op when:
/// - no Authorization header is present
/// - the value is not a `Bearer ` token (other auth schemes)
/// - the token does not begin with `nono_` (real bearers pass through)
/// - the broker doesn't know the nonce (cross-session, broker cleared)
fn rewrite_bearer_header(
    filtered_headers: &mut [(String, String)],
    resolver: &(dyn crate::broker::TokenResolver + 'static),
) {
    for (name, value) in filtered_headers.iter_mut() {
        if !name.eq_ignore_ascii_case("authorization") {
            continue;
        }
        let token = match value
            .strip_prefix("Bearer ")
            .or_else(|| value.strip_prefix("bearer "))
        {
            Some(t) => t.trim().to_string(),
            None => return,
        };
        if !token.starts_with("nono_") {
            return;
        }
        let resolved = match resolver.resolve(&token) {
            Some(real) => real,
            None => {
                debug!(
                    "tls_intercept: nonce {}... not in broker; forwarding raw",
                    &token[..12.min(token.len())]
                );
                return;
            }
        };
        *value = format!("Bearer {}", resolved.as_str());
        debug!("tls_intercept: translated nonce Bearer to real upstream token");
        return;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_line_extracts_components() {
        let (m, p, v) = parse_request_line("GET /v1/models HTTP/1.1").unwrap();
        assert_eq!(m, "GET");
        assert_eq!(p, "/v1/models");
        assert_eq!(v, "HTTP/1.1");
    }

    #[test]
    fn parse_request_line_rejects_malformed() {
        assert!(parse_request_line("malformed").is_err());
        assert!(parse_request_line("").is_err());
    }

    /// Test fake `TokenResolver` with a fixed nonce → real mapping.
    /// Avoids constructing a full `TokenBroker` for these unit tests.
    struct FakeResolver {
        nonce: &'static str,
        real: &'static str,
    }
    impl crate::broker::TokenResolver for FakeResolver {
        fn issue(&self, _: zeroize::Zeroizing<String>) -> String {
            unreachable!("not used by these tests")
        }
        fn resolve(&self, nonce: &str) -> Option<zeroize::Zeroizing<String>> {
            if nonce == self.nonce {
                Some(zeroize::Zeroizing::new(self.real.to_string()))
            } else {
                None
            }
        }
    }

    #[test]
    fn rewrite_bearer_header_translates_nonce_to_real() {
        let resolver = FakeResolver {
            nonce: "nono_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            real: "sk-ant-oat01-deadbeef",
        };
        let mut headers = vec![(
            "Authorization".to_string(),
            "Bearer nono_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        )];
        rewrite_bearer_header(&mut headers, &resolver);
        assert_eq!(headers[0].1, "Bearer sk-ant-oat01-deadbeef");
    }

    #[test]
    fn rewrite_bearer_header_passes_through_unknown_nonce() {
        // Unknown nonce (broker cleared, cross-session, etc.) — leave
        // untouched so the upstream's own auth error surfaces verbatim.
        let resolver = FakeResolver {
            nonce: "nono_known",
            real: "real",
        };
        let original = "Bearer nono_unknown_nonce_value";
        let mut headers = vec![("Authorization".to_string(), original.to_string())];
        rewrite_bearer_header(&mut headers, &resolver);
        assert_eq!(headers[0].1, original);
    }

    #[test]
    fn rewrite_bearer_header_leaves_real_tokens_alone() {
        // Real OAuth bearers (no `nono_` prefix) must pass through —
        // e.g. when a route is OAuth-capture-configured but a client
        // happens to have a non-broker token.
        let resolver = FakeResolver {
            nonce: "nono_x",
            real: "real_x",
        };
        let original = "Bearer sk-ant-oat01-realtoken";
        let mut headers = vec![("Authorization".to_string(), original.to_string())];
        rewrite_bearer_header(&mut headers, &resolver);
        assert_eq!(headers[0].1, original);
    }

    #[test]
    fn rewrite_bearer_header_no_authorization_header_is_noop() {
        let resolver = FakeResolver {
            nonce: "nono_x",
            real: "real_x",
        };
        let mut headers: Vec<(String, String)> =
            vec![("Content-Type".to_string(), "application/json".to_string())];
        rewrite_bearer_header(&mut headers, &resolver);
        assert_eq!(headers[0].1, "application/json");
    }

    #[test]
    fn rewrite_bearer_header_handles_lowercase_bearer() {
        // HTTP allows mixed-case scheme tokens; the helper must
        // normalise to canonical `Bearer ` on output.
        let resolver = FakeResolver {
            nonce: "nono_lc",
            real: "real_lc",
        };
        let mut headers = vec![("Authorization".to_string(), "bearer nono_lc".to_string())];
        rewrite_bearer_header(&mut headers, &resolver);
        assert_eq!(headers[0].1, "Bearer real_lc");
    }

    #[test]
    fn rewrite_bearer_header_case_insensitive_header_name() {
        // Some clients send the Authorization header in lowercase
        // ("authorization:") — must still match.
        let resolver = FakeResolver {
            nonce: "nono_x",
            real: "real_x",
        };
        let mut headers = vec![("authorization".to_string(), "Bearer nono_x".to_string())];
        rewrite_bearer_header(&mut headers, &resolver);
        assert_eq!(headers[0].1, "Bearer real_x");
    }
}
