//! Shared L7 upstream-forwarding pipeline.
//!
//! Used by both the reverse-proxy path ([`crate::reverse`]) and the
//! TLS-intercept CONNECT path ([`crate::tls_intercept`]). The two callers
//! differ in how they parse the inbound request, look up the route, and
//! transform/inject credentials, but converge on the same wire-level
//! upstream operation:
//!
//! 1. Establish an upstream byte stream — direct TCP (with optional TLS)
//!    or chained CONNECT through an enterprise proxy (then TLS).
//! 2. Write the pre-built HTTP/1.1 request bytes + body.
//! 3. Stream the response back into the inbound sink.
//! 4. Emit one L7 audit event with the response status.
//!
//! ## Why pre-built request bytes
//!
//! Each caller has its own rules for header filtering, credential
//! injection, and path transformation. Asking this module to handle that
//! would mean smuggling all of that policy through a parameter struct.
//! Instead, the caller hands in finished bytes: a clean separation
//! between "build the request" and "speak it on the wire".

use crate::audit;
use crate::error::{ProxyError, Result};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Timeout for upstream TCP connect (matches the historical reverse-proxy value).
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_REWRITE_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Scheme of the upstream connection. `Http` is only legal for loopback
/// targets; the caller is responsible for enforcing that invariant
/// (`reverse.rs` does so via `validate_http_upstream_target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamScheme {
    Http,
    Https,
}

/// How the upstream byte stream is established.
pub enum UpstreamStrategy<'a> {
    /// Connect directly to one of `resolved_addrs` (DNS rebinding-safe:
    /// the addresses must already have been validated by the host filter).
    Direct { resolved_addrs: &'a [SocketAddr] },
    /// Chain a CONNECT through an enterprise proxy. `proxy_addr` is the
    /// `host:port` of the corporate proxy; `proxy_auth_header` is the literal
    /// value to send in `Proxy-Authorization` (e.g. `"Basic …"`), or `None`
    /// for unauthenticated proxies.
    ExternalProxy {
        proxy_addr: &'a str,
        proxy_auth_header: Option<&'a str>,
    },
}

/// Description of the upstream the caller wants to reach.
pub struct UpstreamSpec<'a> {
    pub scheme: UpstreamScheme,
    pub host: &'a str,
    pub port: u16,
    pub strategy: UpstreamStrategy<'a>,
    /// TLS connector to use for an `Https` scheme. Reverse-proxy callers
    /// pass either the route's per-route connector (custom CA / mTLS) or
    /// the shared default; intercept callers do the same.
    pub tls_connector: &'a TlsConnector,
}

/// Audit-emission context.
pub struct AuditCtx<'a> {
    pub log: Option<&'a audit::SharedAuditLog>,
    pub mode: audit::ProxyMode,
    pub event_ctx: audit::EventContext<'a>,
    /// Logical target string (route prefix for reverse, hostname for intercept).
    pub target: &'a str,
    pub method: &'a str,
    /// Path as it should appear in the audit log (the *inbound* path before
    /// any rewriting — e.g. `/v1/chat/completions`, not the upstream URL).
    pub path: &'a str,
}

/// Optional HTTP/1.1 response body rewrite hook.
///
/// Used for OAuth token capture, where the proxy must buffer a token endpoint
/// response, replace real token fields with phantoms, and only then release the
/// response to the sandboxed client.
pub type ResponseRewrite<'a> =
    &'a (dyn Fn(u16, &[(String, String)], &[u8]) -> Result<Vec<u8>> + Send + Sync);

/// Connect to the upstream, write `request_bytes + body`, stream the
/// response back into `inbound`, and emit the L7 audit event.
///
/// Returns the response status code (or 502 if the upstream sent something
/// unparseable).
pub async fn forward_request<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: &[u8],
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    forward_request_with_response_rewrite(inbound, request_bytes, body, upstream, audit, None).await
}

pub async fn forward_request_with_response_rewrite<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: &[u8],
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
    response_rewrite: Option<ResponseRewrite<'_>>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let status = match upstream.scheme {
        UpstreamScheme::Https => {
            let mut tls_stream = open_https_upstream(&upstream).await?;
            write_request(&mut tls_stream, request_bytes, body).await?;
            stream_or_rewrite_response(&mut tls_stream, inbound, response_rewrite).await?
        }
        UpstreamScheme::Http => {
            let mut tcp_stream = open_http_upstream(&upstream).await?;
            write_request(&mut tcp_stream, request_bytes, body).await?;
            stream_or_rewrite_response(&mut tcp_stream, inbound, response_rewrite).await?
        }
    };

    audit::log_l7_request(
        audit.log,
        audit.mode,
        &audit.event_ctx,
        audit.target,
        audit.method,
        audit.path,
        status,
    );
    Ok(status)
}

async fn stream_or_rewrite_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    response_rewrite: Option<ResponseRewrite<'_>>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    match response_rewrite {
        Some(rewrite) => buffer_rewrite_response(upstream, inbound, rewrite).await,
        None => stream_response(upstream, inbound).await,
    }
}

/// Cap on the WebSocket upgrade response head we buffer before the `101`.
const MAX_WS_HEAD_BYTES: usize = 64 * 1024;

/// Forward a WebSocket upgrade handshake and, on `101 Switching Protocols`,
/// splice client and upstream into a bidirectional byte relay.
///
/// The caller may inject a credential into the handshake request (e.g.
/// `Authorization: Bearer`), but once upgraded the connection is an opaque
/// tunnel to the already-endpoint-authorized upstream — nono does not inspect
/// post-upgrade frames, mirroring how a forward proxy treats CONNECT. A
/// non-`101` response (e.g. `426`, `401`) is relayed unchanged so the client
/// can react (clients commonly fall back to plain HTTP on `426`).
pub async fn forward_websocket<S>(
    inbound: &mut S,
    request_bytes: &[u8],
    body: &[u8],
    upstream: UpstreamSpec<'_>,
    audit: AuditCtx<'_>,
) -> Result<u16>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let status = match upstream.scheme {
        UpstreamScheme::Https => {
            let mut up = open_https_upstream(&upstream).await?;
            write_request(&mut up, request_bytes, body).await?;
            relay_websocket(&mut up, inbound).await?
        }
        UpstreamScheme::Http => {
            let mut up = open_http_upstream(&upstream).await?;
            write_request(&mut up, request_bytes, body).await?;
            relay_websocket(&mut up, inbound).await?
        }
    };

    audit::log_l7_request(
        audit.log,
        audit.mode,
        &audit.event_ctx,
        audit.target,
        audit.method,
        audit.path,
        status,
    );
    Ok(status)
}

/// Read the upstream response head, forward it to the client, then either run a
/// bidirectional copy (on `101`) or relay the rest of a non-upgrade response.
///
/// Bytes read past the header terminator are already forwarded to the client
/// before the bidirectional copy (or body relay) starts, so no frame or body
/// data is lost.
async fn relay_websocket<U, I>(upstream: &mut U, inbound: &mut I) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    let mut saw_head_end = false;
    loop {
        // An upstream that accepts the connection but never sends anything
        // (or never finishes the header block) must not hang this relay
        // forever either.
        let n = match tokio::time::timeout(UPSTREAM_REWRITE_READ_TIMEOUT, upstream.read(&mut chunk))
            .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("WebSocket upstream read error before head complete: {}", e);
                break;
            }
            Err(_) => {
                debug!("WebSocket upstream response head timed out");
                break;
            }
        };
        head.extend_from_slice(&chunk[..n]);
        // Check the size cap before the terminator: otherwise a single read
        // that both crosses the limit and contains `\r\n\r\n` would find the
        // terminator first and let an oversized header through unchecked.
        if head.len() > MAX_WS_HEAD_BYTES {
            return Err(ProxyError::HttpParse(
                "WebSocket upgrade response head exceeded limit".to_string(),
            ));
        }
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            saw_head_end = true;
            break;
        }
    }

    // The upstream closed, errored, or timed out before sending a complete
    // response head — there is no valid response to relay, so this must
    // surface as an error rather than a fabricated status code.
    if !saw_head_end {
        return Err(ProxyError::HttpParse(
            "WebSocket upgrade response closed before headers were complete".to_string(),
        ));
    }

    // Safe: `saw_head_end` is only set once this position is found.
    let header_end = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(head.len())
        + 4;
    let header_part_len = header_end;
    let leftover = head.len() - header_part_len;
    let status = parse_response_status(&head[..header_part_len]);
    let content_length = crate::reverse::extract_content_length(&head[..header_part_len]);

    // How much of what we already read is safe to forward as-is. For a
    // non-101 response with a declared Content-Length, cap it there: bytes
    // beyond that boundary belong to a subsequent message on the upstream
    // connection (which this proxy never reuses across requests) and must
    // never be relayed to the client as if they were part of this response.
    // A 101 response has no body semantics, so its leftover bytes (the
    // start of the frame stream) are always forwarded in full.
    let forwarded_body_len = if status == 101 {
        leftover
    } else {
        match content_length {
            Some(total) => leftover.min(total),
            None => leftover,
        }
    };
    inbound
        .write_all(&head[..header_part_len + forwarded_body_len])
        .await?;
    inbound.flush().await?;

    if status == 101 {
        // Opaque bidirectional relay until either side closes. Most errors
        // here are ordinary teardown (a broken pipe when one side hangs up),
        // but logging unconditionally means a genuine relay failure is at
        // least visible in debug logs instead of vanishing silently.
        if let Err(e) = tokio::io::copy_bidirectional(inbound, upstream).await {
            debug!("WebSocket bidirectional relay ended: {}", e);
        }
    } else {
        // Not an upgrade — relay the remainder of the response unchanged,
        // bounded by the declared Content-Length so a keep-alive upstream
        // that never closes the connection can't hang this task forever.
        relay_remaining_response_body(upstream, inbound, content_length, forwarded_body_len)
            .await?;
    }
    Ok(status)
}

/// Relay the remainder of a non-upgrade response body already partially
/// consumed into the head buffer (`already_forwarded` bytes of it).
///
/// When `content_length` is known, reads exactly the remaining declared
/// bytes and stops — this is what prevents a hang on a keep-alive upstream
/// that never closes the connection. When it is unknown (e.g. chunked or
/// close-delimited), relays whatever arrives next, but each read is bounded
/// by [`UPSTREAM_REWRITE_READ_TIMEOUT`] so a connection that neither sends a
/// body nor closes still can't hang indefinitely.
async fn relay_remaining_response_body<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    content_length: Option<usize>,
    already_forwarded: usize,
) -> Result<()>
where
    U: AsyncRead + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut chunk = [0u8; 8192];
    match content_length {
        Some(total) => {
            let mut remaining = total.saturating_sub(already_forwarded);
            while remaining > 0 {
                let want = remaining.min(chunk.len());
                // A declared Content-Length is only a bound on how many
                // bytes we'll accept, not a guarantee the upstream ever
                // sends them — bound each read too, so a connection that
                // stays open without completing the declared body can't
                // hang this task forever either.
                let n = match tokio::time::timeout(
                    UPSTREAM_REWRITE_READ_TIMEOUT,
                    upstream.read(&mut chunk[..want]),
                )
                .await
                {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        debug!("WebSocket non-upgrade response body read error: {}", e);
                        break;
                    }
                    Err(_) => {
                        debug!("WebSocket non-upgrade response body read timed out");
                        break;
                    }
                };
                inbound.write_all(&chunk[..n]).await?;
                inbound.flush().await?;
                remaining -= n;
            }
        }
        None => loop {
            let n = match tokio::time::timeout(
                UPSTREAM_REWRITE_READ_TIMEOUT,
                upstream.read(&mut chunk),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    debug!("WebSocket non-upgrade response body read error: {}", e);
                    break;
                }
                Err(_) => {
                    debug!("WebSocket non-upgrade response body read timed out");
                    break;
                }
            };
            inbound.write_all(&chunk[..n]).await?;
            inbound.flush().await?;
        },
    }
    Ok(())
}

/// Open an upstream HTTPS connection (Direct TLS or ExternalProxy + TLS).
async fn open_https_upstream(
    upstream: &UpstreamSpec<'_>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = open_tcp_upstream(upstream).await?;
    let server_name =
        rustls::pki_types::ServerName::try_from(upstream.host.to_string()).map_err(|_| {
            ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason: "invalid server name for TLS".to_string(),
            }
        })?;
    upstream
        .tls_connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| ProxyError::UpstreamConnect {
            host: upstream.host.to_string(),
            reason: format!("TLS handshake failed: {}", e),
        })
}

/// Open an upstream HTTP (plain) connection. Caller has already validated
/// that this is a loopback target.
async fn open_http_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    open_tcp_upstream(upstream).await
}

/// Establish the TCP layer of the upstream connection (without TLS).
pub(crate) async fn open_tcp_upstream(upstream: &UpstreamSpec<'_>) -> Result<TcpStream> {
    match upstream.strategy {
        UpstreamStrategy::Direct { resolved_addrs } => {
            if resolved_addrs.is_empty() {
                let addr = format!("{}:{}", upstream.host, upstream.port);
                match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(&addr))
                    .await
                {
                    Ok(Ok(s)) => Ok(s),
                    Ok(Err(e)) => Err(ProxyError::UpstreamConnect {
                        host: upstream.host.to_string(),
                        reason: e.to_string(),
                    }),
                    Err(_) => Err(ProxyError::UpstreamConnect {
                        host: upstream.host.to_string(),
                        reason: "connection timed out".to_string(),
                    }),
                }
            } else {
                connect_to_resolved(resolved_addrs, upstream.host).await
            }
        }
        UpstreamStrategy::ExternalProxy {
            proxy_addr,
            proxy_auth_header,
        } => crate::external::connect_via_proxy(
            proxy_addr,
            upstream.host,
            upstream.port,
            proxy_auth_header,
        )
        .await
        .map_err(|e| match e {
            ProxyError::ExternalProxy(reason) => ProxyError::UpstreamConnect {
                host: upstream.host.to_string(),
                reason,
            },
            other => other,
        }),
    }
}

/// Connect to one of the pre-resolved socket addresses with timeout.
///
/// Tries each address in order until one succeeds. Connecting to the IP
/// directly (not re-resolving the hostname) prevents DNS rebinding TOCTOU.
async fn connect_to_resolved(addrs: &[SocketAddr], host: &str) -> Result<TcpStream> {
    let mut last_err = None;
    for addr in addrs {
        match tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                debug!("Connect to {} failed: {}", addr, e);
                last_err = Some(e.to_string());
            }
            Err(_) => {
                debug!("Connect to {} timed out", addr);
                last_err = Some("connection timed out".to_string());
            }
        }
    }
    Err(ProxyError::UpstreamConnect {
        host: host.to_string(),
        reason: last_err.unwrap_or_else(|| "no addresses to connect to".to_string()),
    })
}

async fn write_request<S>(stream: &mut S, request: &[u8], body: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(request).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.flush().await?;
    Ok(())
}

/// Stream the upstream response back to the inbound sink.
///
/// Returns the HTTP status code parsed from the first chunk. Streams
/// chunked / SSE / HTTP-streaming bodies transparently because we never
/// buffer the body — each upstream read is mirrored to the inbound write.
async fn stream_response<U, I>(upstream: &mut U, inbound: &mut I) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut status_code: u16 = 502;
    let mut first_chunk = true;

    loop {
        let n = match upstream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                debug!("Upstream read error: {}", e);
                break;
            }
        };

        if first_chunk {
            status_code = parse_response_status(&buf[..n]);
            first_chunk = false;
        }

        inbound.write_all(&buf[..n]).await?;
        inbound.flush().await?;
    }

    Ok(status_code)
}

/// Parse HTTP status code from the first response chunk.
///
/// Returns 502 when the response doesn't contain a valid status line.
fn parse_response_status(data: &[u8]) -> u16 {
    let line_end = data
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(data.len());
    let first_line = &data[..line_end.min(64)];

    if let Ok(line) = std::str::from_utf8(first_line) {
        let mut parts = line.split_whitespace();
        if let Some(version) = parts.next()
            && version.starts_with("HTTP/")
            && let Some(code_str) = parts.next()
            && code_str.len() == 3
        {
            return code_str.parse().unwrap_or(502);
        }
    }
    502
}

const MAX_REWRITE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

async fn buffer_rewrite_response<U, I>(
    upstream: &mut U,
    inbound: &mut I,
    rewrite: ResponseRewrite<'_>,
) -> Result<u16>
where
    U: AsyncRead + AsyncWrite + Unpin,
    I: AsyncWrite + Unpin,
{
    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = match tokio::time::timeout(UPSTREAM_REWRITE_READ_TIMEOUT, upstream.read(&mut buf))
            .await
        {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                debug!("Upstream read error: {}", e);
                break;
            }
            Err(_) => {
                return Err(ProxyError::HttpParse(
                    "timed out reading response for OAuth capture rewrite".to_string(),
                ));
            }
        };
        raw.extend_from_slice(&buf[..n]);
        if raw.len() > MAX_REWRITE_RESPONSE_BYTES {
            return Err(ProxyError::HttpParse(
                "response too large for OAuth capture rewrite".to_string(),
            ));
        }
    }

    let rewritten = rewrite_http1_response(&raw, rewrite)?;
    let status = parse_response_status(&rewritten);
    inbound.write_all(&rewritten).await?;
    inbound.flush().await?;
    Ok(status)
}

fn rewrite_http1_response(raw: &[u8], rewrite: ResponseRewrite<'_>) -> Result<Vec<u8>> {
    let Some(header_end) = find_header_end(raw) else {
        return Err(ProxyError::HttpParse(
            "upstream response missing header terminator".to_string(),
        ));
    };
    let head = &raw[..header_end];
    let mut body = raw[header_end + 4..].to_vec();
    let head_str = std::str::from_utf8(head).map_err(|_| {
        ProxyError::HttpParse("upstream response headers are not UTF-8".to_string())
    })?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ProxyError::HttpParse("upstream response missing status".to_string()))?;
    let status = parse_response_status(raw);
    let mut headers = Vec::new();
    let mut chunked = false;
    let mut content_encoded = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_trimmed = name.trim().to_string();
        let value_trimmed = value.trim().to_string();
        if name_trimmed.eq_ignore_ascii_case("transfer-encoding")
            && value_trimmed
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        {
            chunked = true;
        }
        if name_trimmed.eq_ignore_ascii_case("content-encoding") && !value_trimmed.is_empty() {
            content_encoded = true;
        }
        headers.push((name_trimmed, value_trimmed));
    }

    if chunked {
        body = decode_chunked_body(&body)?;
    }
    if content_encoded {
        return Err(ProxyError::HttpParse(
            "cannot safely rewrite or inspect content-encoded OAuth capture response".to_string(),
        ));
    }

    let rewritten_body = rewrite(status, &headers, &body)?;
    let mut out = Vec::new();
    out.extend_from_slice(status_line.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(format!("Content-Length: {}\r\n", rewritten_body.len()).as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&rewritten_body);
    Ok(out)
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;
    let mut out = Vec::new();
    loop {
        let Some(line_end_rel) = body[pos..].windows(2).position(|w| w == b"\r\n") else {
            return Err(ProxyError::HttpParse(
                "malformed chunked response".to_string(),
            ));
        };
        let line_end = pos + line_end_rel;
        let size_line = std::str::from_utf8(&body[pos..line_end])
            .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let end = pos
            .checked_add(size)
            .ok_or_else(|| ProxyError::HttpParse("chunk size overflow".to_string()))?;
        if end + 2 > body.len() || &body[end..end + 2] != b"\r\n" {
            return Err(ProxyError::HttpParse(
                "malformed chunked response".to_string(),
            ));
        }
        out.extend_from_slice(&body[pos..end]);
        pos = end + 2;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_response_status_extracts_code() {
        assert_eq!(parse_response_status(b"HTTP/1.1 200 OK\r\n"), 200);
        assert_eq!(parse_response_status(b"HTTP/1.1 404 Not Found\r\n"), 404);
        assert_eq!(parse_response_status(b"HTTP/1.1 502 Bad Gateway\r\n"), 502);
    }

    #[test]
    fn parse_response_status_handles_garbage() {
        assert_eq!(parse_response_status(b""), 502);
        assert_eq!(parse_response_status(b"garbage"), 502);
        assert_eq!(parse_response_status(b"NOT-HTTP 200 OK"), 502);
    }

    #[test]
    fn rewrite_http1_response_decodes_chunked_body_before_rewrite() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n";
        let rewritten = rewrite_http1_response(raw, &|_, _, body| {
            assert_eq!(body, br#"{"a":1}"#);
            Ok(br#"{"b":2}"#.to_vec())
        })
        .unwrap();

        let text = std::str::from_utf8(&rewritten).unwrap();
        assert!(text.contains("Content-Length: 7"));
        assert!(!text.to_ascii_lowercase().contains("transfer-encoding"));
        assert!(text.ends_with(r#"{"b":2}"#));
    }

    #[test]
    fn rewrite_http1_response_rejects_content_encoded_body_for_all_statuses() {
        let raw =
            b"HTTP/1.1 400 Bad Request\r\nContent-Encoding: gzip\r\nContent-Length: 4\r\n\r\nxxxx";
        let err = rewrite_http1_response(raw, &|_, _, body| Ok(body.to_vec())).unwrap_err();

        assert!(
            err.to_string()
                .contains("content-encoded OAuth capture response"),
            "unexpected error: {err}"
        );
    }

    // Real WebSocket handshake + framing (masking, close frames) instead of
    // hand-rolled byte fixtures — byte fixtures missed the dropped-body and
    // non-101-keep-alive-hang bugs that these tests guard against.
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{Message, protocol::Role};
    use tokio_tungstenite::{WebSocketStream, accept_async};

    /// Read from `stream` until the `\r\n\r\n` header terminator, returning
    /// `(header_bytes_including_terminator, bytes_already_read_past_it)`.
    async fn read_http_response_head<S>(stream: &mut S) -> (Vec<u8>, Vec<u8>)
    where
        S: AsyncRead + Unpin,
    {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "stream closed before response head was complete");
            buf.extend_from_slice(&chunk[..n]);
            if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let split = idx + 4;
                return (buf[..split].to_vec(), buf[split..].to_vec());
            }
        }
    }

    #[tokio::test]
    async fn relay_websocket_splices_bidirectionally_on_101() {
        // upstream: proxy side <-> fake server side; inbound: proxy side <-> fake client side.
        let (mut up_proxy, up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, mut in_client) = tokio::io::duplex(4096);

        // A real client handshake request (RFC 6455 §1.3's example key).
        up_proxy
            .write_all(
                b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\
                  Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\
                  Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
            )
            .await
            .unwrap();

        let server = tokio::spawn(async move {
            // Genuine server-side handshake: parses the request above and
            // replies with a real 101 + computed Sec-WebSocket-Accept.
            let mut ws = accept_async(up_server).await.unwrap();
            ws.send(Message::text("hello from server")).await.unwrap();
            let msg = ws.next().await.unwrap().unwrap();
            assert_eq!(msg, Message::text("hello from client"));
            // Dropping `ws` here closes `up_server`, ending the
            // upstream->inbound half of the relay's bidirectional copy.
        });

        let relay =
            tokio::spawn(async move { relay_websocket(&mut up_proxy, &mut in_proxy).await });

        let (head, leftover) = read_http_response_head(&mut in_client).await;
        assert!(String::from_utf8_lossy(&head).contains("101 Switching Protocols"));

        // Wrap the remainder of the stream as real (masked) client frames —
        // proves the relay preserves frame boundaries and masking, not just
        // arbitrary bytes.
        let mut client_ws =
            WebSocketStream::from_partially_read(in_client, leftover, Role::Client, None).await;
        let msg = client_ws.next().await.unwrap().unwrap();
        assert_eq!(msg, Message::text("hello from server"));
        client_ws
            .send(Message::text("hello from client"))
            .await
            .unwrap();
        // Dropping `client_ws` closes `in_client`, ending the
        // inbound->upstream half of the relay's bidirectional copy.
        drop(client_ws);

        server.await.unwrap();
        let status = relay.await.unwrap().unwrap();
        assert_eq!(status, 101);
    }

    #[tokio::test]
    async fn relay_websocket_relays_non_upgrade_response() {
        let (mut up_proxy, mut up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, mut in_client) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            up_server
                .write_all(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\n\r\nno")
                .await
                .unwrap();
            drop(up_server);
        });

        let relay =
            tokio::spawn(async move { relay_websocket(&mut up_proxy, &mut in_proxy).await });

        let mut seen = Vec::new();
        loop {
            let mut buf = [0u8; 64];
            let n = in_client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n]);
        }

        let status = relay.await.unwrap().unwrap();
        assert_eq!(status, 426);
        assert!(String::from_utf8_lossy(&seen).contains("426 Upgrade Required"));
        assert!(seen.ends_with(b"no"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn relay_websocket_non_upgrade_keep_alive_does_not_hang() {
        // Regression test for the bug this fixes: a keep-alive upstream that
        // never closes the connection after rejecting the upgrade must not
        // hang the relay. The old non-101 branch read until EOF, which a
        // keep-alive connection never sends.
        let (mut up_proxy, mut up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, mut in_client) = tokio::io::duplex(4096);

        let _server = tokio::spawn(async move {
            up_server
                .write_all(b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\n\r\nno")
                .await
                .unwrap();
            // Never close or write again — the old code would block here
            // forever waiting for an EOF that never comes.
            std::future::pending::<()>().await;
        });

        let relay_task =
            tokio::spawn(async move { relay_websocket(&mut up_proxy, &mut in_proxy).await });
        let status = tokio::time::timeout(Duration::from_secs(2), relay_task)
            .await
            .expect(
                "relay must stop at Content-Length instead of hanging on a keep-alive connection",
            )
            .unwrap()
            .unwrap();
        assert_eq!(status, 426);

        let mut seen = Vec::new();
        in_client.read_to_end(&mut seen).await.unwrap();
        assert!(String::from_utf8_lossy(&seen).contains("426 Upgrade Required"));
        assert!(seen.ends_with(b"no"));
    }

    #[tokio::test]
    async fn relay_websocket_errors_when_head_incomplete() {
        let (mut up_proxy, mut up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, in_client) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            // Partial status line — the upstream closes before the header
            // block is ever completed.
            up_server.write_all(b"HTTP/1.1 101 Switch").await.unwrap();
            drop(up_server);
        });

        let err = relay_websocket(&mut up_proxy, &mut in_proxy)
            .await
            .expect_err("an upstream that closes mid-header must error, not fabricate a response");
        assert!(err.to_string().contains("headers were complete"));

        server.await.unwrap();
        drop(in_client);
    }

    #[tokio::test(start_paused = true)]
    async fn relay_websocket_errors_when_head_never_arrives() {
        // Regression test: an upstream that accepts the connection but never
        // sends anything (or never finishes the header block) must not hang
        // this relay forever — only the read-timeout fallback can end it.
        let (mut up_proxy, up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, in_client) = tokio::io::duplex(4096);

        // Keep `up_server` alive (captured here) and never write to it.
        let _server = tokio::spawn(async move {
            let _up_server = up_server;
            std::future::pending::<()>().await;
        });

        let err = relay_websocket(&mut up_proxy, &mut in_proxy)
            .await
            .expect_err("an upstream that never sends a head must time out, not hang forever");
        assert!(err.to_string().contains("headers were complete"));

        drop(in_client);
    }

    #[tokio::test]
    async fn relay_websocket_relays_close_delimited_body_without_content_length() {
        let (mut up_proxy, mut up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, mut in_client) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            up_server
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nBODYBYTES")
                .await
                .unwrap();
            drop(up_server);
        });

        let status = relay_websocket(&mut up_proxy, &mut in_proxy).await.unwrap();
        assert_eq!(status, 400);
        // Close the inbound handle so `read_to_end` below observes EOF
        // instead of waiting for bytes that will never arrive.
        drop(in_proxy);

        let mut seen = Vec::new();
        in_client.read_to_end(&mut seen).await.unwrap();
        assert!(seen.ends_with(b"BODYBYTES"));
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn relay_websocket_unknown_length_body_times_out_instead_of_hanging_forever() {
        let (mut up_proxy, mut up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, mut in_client) = tokio::io::duplex(4096);

        let _server = tokio::spawn(async move {
            up_server
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .unwrap();
            // No Content-Length, no chunked encoding, no close, no further
            // bytes: only the read-timeout fallback can end this relay.
            std::future::pending::<()>().await;
        });

        let status = relay_websocket(&mut up_proxy, &mut in_proxy).await.unwrap();
        assert_eq!(status, 400);
        // Close the inbound handle so `read_to_end` below observes EOF
        // instead of waiting for bytes that will never arrive.
        drop(in_proxy);

        let mut seen = Vec::new();
        in_client.read_to_end(&mut seen).await.unwrap();
        assert!(String::from_utf8_lossy(&seen).contains("400 Bad Request"));
    }

    #[tokio::test(start_paused = true)]
    async fn relay_websocket_content_length_body_times_out_instead_of_hanging_forever() {
        // A declared Content-Length is only a bound, not a promise: an
        // upstream that keeps the connection open without ever sending the
        // rest of the declared body must not hang the relay either.
        let (mut up_proxy, mut up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, mut in_client) = tokio::io::duplex(4096);

        let _server = tokio::spawn(async move {
            up_server
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 100\r\n\r\nshort")
                .await
                .unwrap();
            // Declared 100 bytes, sent 5, then never sends the rest and
            // never closes.
            std::future::pending::<()>().await;
        });

        let status = relay_websocket(&mut up_proxy, &mut in_proxy).await.unwrap();
        assert_eq!(status, 400);
        drop(in_proxy);

        let mut seen = Vec::new();
        in_client.read_to_end(&mut seen).await.unwrap();
        assert!(seen.ends_with(b"short"));
    }

    #[tokio::test]
    async fn relay_websocket_non_upgrade_never_forwards_bytes_past_content_length() {
        // Bytes past the declared Content-Length (e.g. because they arrived
        // in the same read as the header) belong to whatever the upstream
        // sends next on that connection, which this proxy never reuses
        // across requests — they must never be relayed to the client as if
        // they were part of this response.
        let (mut up_proxy, mut up_server) = tokio::io::duplex(4096);
        let (mut in_proxy, mut in_client) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            up_server
                .write_all(
                    b"HTTP/1.1 426 Upgrade Required\r\nContent-Length: 2\r\n\r\n\
                      noSURPLUS_BYTES_NOT_PART_OF_THIS_RESPONSE",
                )
                .await
                .unwrap();
            drop(up_server);
        });

        let status = relay_websocket(&mut up_proxy, &mut in_proxy).await.unwrap();
        assert_eq!(status, 426);
        drop(in_proxy);

        let mut seen = Vec::new();
        in_client.read_to_end(&mut seen).await.unwrap();
        assert!(
            seen.ends_with(b"no"),
            "must end at the Content-Length boundary"
        );
        assert!(
            !seen.windows(7).any(|w| w == b"SURPLUS"),
            "must not forward bytes past the declared Content-Length"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn write_request_includes_body_bytes() {
        // forward_websocket used to hardcode `&[]` here, silently dropping
        // any request body while still emitting its Content-Length header
        // upstream (the request would never complete).
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_request(
            &mut a,
            b"GET /ws HTTP/1.1\r\nContent-Length: 4\r\n\r\n",
            b"BODY",
        )
        .await
        .unwrap();
        drop(a);

        let mut received = Vec::new();
        b.read_to_end(&mut received).await.unwrap();
        assert!(received.ends_with(b"BODY"));
    }
}
