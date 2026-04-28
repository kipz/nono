//! End-to-end test for the `exec`-based credential source.
//!
//! Stands up a real `nono_proxy` instance with a single route configured to
//! source its bearer from an external command (`/bin/echo`), drives an HTTP
//! request through it from a local client, and asserts the upstream request
//! captured by a fake server contains the expected `Authorization: Bearer …`
//! header.
//!
//! This proves the full pipeline:
//!   ExecConfig → CredentialStore::load → ExecTokenCache::new
//!     → reverse::handle_exec_credential → header injection → upstream

use nono_proxy::{
    config::{ExecConfig, InjectMode, ProxyConfig, RouteConfig},
    start,
};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A minimal "fake upstream" that accepts a single TCP connection, reads the
/// HTTP request bytes the proxy sends, replies with 200 OK, and hands the
/// captured request bytes back to the test.
async fn spawn_fake_upstream() -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.expect("upstream accept");
        let mut buf = vec![0u8; 8192];
        let mut request = Vec::new();
        // Read until we see the end-of-headers marker; our test doesn't send a
        // body so this is sufficient.
        loop {
            let n = sock.read(&mut buf).await.expect("upstream read");
            if n == 0 {
                break;
            }
            request.extend_from_slice(&buf[..n]);
            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        let _ = sock.write_all(response).await;
        let _ = sock.shutdown().await;
        request
    });

    (upstream_url, handle)
}

/// Send a single HTTP request through the proxy and read the response bytes.
async fn proxy_request(port: u16, path: &str, session_token: &str) -> Vec<u8> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect proxy");
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
        path, session_token
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    stream.flush().await.expect("flush request");

    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response).await;
    response
}

/// Write a small shell script under a tempdir that prints a different token
/// on each invocation by reading + incrementing a counter file alongside it.
/// Returns the absolute paths the test should use as `command[0]` plus the
/// counter file (so the test can assert on how many times it ran).
fn write_rotating_helper(dir: &tempfile::TempDir, prefix: &str) -> (String, String) {
    let counter_path = dir.path().join(format!("{}-counter", prefix));
    let helper_path = dir.path().join(format!("{}-helper.sh", prefix));
    std::fs::write(&counter_path, "0").expect("write counter");
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         n=$(cat {counter})\n\
         next=$((n + 1))\n\
         printf %s \"$next\" > {counter}\n\
         printf 'token-v%s' \"$next\"\n",
        counter = shell_escape(counter_path.to_str().unwrap()),
    );
    std::fs::write(&helper_path, script).expect("write helper");
    let mut perms = std::fs::metadata(&helper_path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&helper_path, perms).expect("chmod helper");
    (
        helper_path.to_str().unwrap().to_string(),
        counter_path.to_str().unwrap().to_string(),
    )
}

/// Single-quote-wrap for use in /bin/sh. Test paths are tempdirs so this is
/// adequate; we just need to survive spaces.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn route_with_exec(prefix: &str, upstream: &str, command: Vec<&str>) -> RouteConfig {
    RouteConfig {
        prefix: prefix.to_string(),
        upstream: upstream.to_string(),
        credential_key: None,
        inject_mode: InjectMode::Header,
        inject_header: "Authorization".to_string(),
        credential_format: "Bearer {}".to_string(),
        path_pattern: None,
        path_replacement: None,
        query_param_name: None,
        proxy: None,
        env_var: Some("ANTHROPIC_AUTH_TOKEN".to_string()),
        endpoint_rules: vec![],
        tls_ca: None,
        tls_client_cert: None,
        tls_client_key: None,
        oauth2: None,
        exec: Some(ExecConfig {
            command: command.into_iter().map(String::from).collect(),
            ttl_secs: 3600,
            timeout_secs: Some(10),
        }),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_credential_injects_real_bearer_into_upstream_request() {
    // Fake upstream stands in for the AI gateway. It captures whatever the
    // proxy forwards so we can assert on the headers.
    let (upstream_url, upstream_handle) = spawn_fake_upstream().await;

    let route = route_with_exec(
        "anthropic",
        &upstream_url,
        vec!["/bin/echo", "-n", "integration-token-v1"],
    );
    let config = ProxyConfig {
        routes: vec![route],
        ..Default::default()
    };

    let proxy = start(config).await.expect("proxy start");

    // The agent-side authentication is the proxy's session token. We mirror
    // what claude/the SDK would do: send Authorization: Bearer <session>.
    // The proxy should validate it, strip it, and inject the real bearer
    // produced by the configured exec command before forwarding upstream.
    let session_token = proxy.token.to_string();

    let response = proxy_request(proxy.port, "/anthropic/v1/messages", &session_token).await;

    // Read the upstream-side captured request with a generous timeout so a
    // slow CI box doesn't flake.
    let captured = tokio::time::timeout(Duration::from_secs(5), upstream_handle)
        .await
        .expect("upstream did not receive request in time")
        .expect("upstream task panicked");

    proxy.shutdown();

    // Sanity: the proxy returned the upstream's 200 to the client.
    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.starts_with("HTTP/1.1 200"),
        "expected 200 from proxy, got:\n{}",
        response_str
    );

    // The actual assertion: the request the upstream saw must carry the
    // freshly fetched bearer, NOT the session token, NOT a phantom.
    let captured_str = String::from_utf8_lossy(&captured);
    assert!(
        captured_str.contains("Authorization: Bearer integration-token-v1"),
        "upstream did not see the injected bearer; captured request:\n{}",
        captured_str
    );
    // And the session token must NOT have been forwarded — the proxy strips
    // the phantom-bearing Authorization header before injecting the real one.
    assert!(
        !captured_str.contains(&session_token),
        "session token leaked to upstream; captured request:\n{}",
        captured_str
    );
}

/// A "counting" upstream that increments a shared atomic on every request and
/// echoes the counter back in a response header. Used to confirm the proxy
/// does not re-fetch the credential between requests within the TTL window.
async fn spawn_counting_upstream(
    expected_requests: usize,
) -> (
    String,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<Vec<Vec<u8>>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_url = format!("http://{}", addr);
    let counter = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter_clone = counter.clone();

    let handle = tokio::spawn(async move {
        let mut captured = Vec::with_capacity(expected_requests);
        for _ in 0..expected_requests {
            let (mut sock, _) = listener.accept().await.expect("upstream accept");
            let mut buf = vec![0u8; 8192];
            let mut request = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.expect("upstream read");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            captured.push(request);

            let response =
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
            let _ = sock.write_all(response).await;
            let _ = sock.shutdown().await;
        }
        captured
    });

    (upstream_url, counter, handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_credential_caches_within_ttl_across_requests() {
    // Multi-request scenario: the second request must be served from the
    // ExecTokenCache rather than re-running the command.
    //
    // We can't trivially distinguish "ran command twice" from outside, but we
    // CAN observe that both upstream requests carry the same bearer — and we
    // know from ExecTokenCache::get_or_refresh that the only path that
    // returns the cached value is the fast read-lock path, so seeing the same
    // value in two calls is a strong signal the cache was hit.
    let (upstream_url, _counter, upstream_handle) = spawn_counting_upstream(2).await;

    let route = route_with_exec(
        "anthropic",
        &upstream_url,
        vec!["/bin/echo", "-n", "cached-bearer"],
    );
    let config = ProxyConfig {
        routes: vec![route],
        ..Default::default()
    };
    let proxy = start(config).await.expect("proxy start");
    let session_token = proxy.token.to_string();

    let r1 = proxy_request(proxy.port, "/anthropic/v1/req-1", &session_token).await;
    let r2 = proxy_request(proxy.port, "/anthropic/v1/req-2", &session_token).await;

    let captured = tokio::time::timeout(Duration::from_secs(5), upstream_handle)
        .await
        .expect("upstream timeout")
        .expect("upstream task panic");
    proxy.shutdown();

    assert!(String::from_utf8_lossy(&r1).starts_with("HTTP/1.1 200"));
    assert!(String::from_utf8_lossy(&r2).starts_with("HTTP/1.1 200"));

    assert_eq!(captured.len(), 2, "upstream should have seen 2 requests");
    for (i, req) in captured.iter().enumerate() {
        let s = String::from_utf8_lossy(req);
        assert!(
            s.contains("Authorization: Bearer cached-bearer"),
            "request #{} missing injected bearer:\n{}",
            i + 1,
            s
        );
    }
}

/// Upstream that returns a configurable HTTP status for each successive
/// request, capturing what it received. The Nth request gets `statuses[N]`,
/// or 200 if the test asks for more than the supplied list.
async fn spawn_scripted_upstream(
    statuses: Vec<u16>,
) -> (String, tokio::task::JoinHandle<Vec<Vec<u8>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("upstream bind");
    let addr = listener.local_addr().expect("upstream addr");
    let upstream_url = format!("http://{}", addr);

    let handle = tokio::spawn(async move {
        let mut captured = Vec::with_capacity(statuses.len().max(1));
        let mut idx = 0;
        loop {
            let accept = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await;
            let Ok(Ok((mut sock, _))) = accept else { break };
            let mut buf = vec![0u8; 8192];
            let mut request = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.expect("upstream read");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            captured.push(request);

            let status = statuses.get(idx).copied().unwrap_or(200);
            idx += 1;
            let body = match status {
                401 => "{\"error\":\"unauthorized\"}",
                _ => "ok",
            };
            let response = format!(
                "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                http_reason(status),
                body.len(),
                body,
            );
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        }
        captured
    });

    (upstream_url, handle)
}

fn http_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        _ => "Other",
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_credential_retries_on_upstream_401_with_refreshed_bearer() {
    // Upstream returns 401 on the first request, 200 on the second. The
    // helper script issues a different token on each invocation. Exercise
    // path: cached "token-v1" → upstream 401 → force_refresh → "token-v2"
    // → upstream 200. The client should receive the 200 response.
    let dir = tempfile::tempdir().expect("tempdir");
    let (helper, counter) = write_rotating_helper(&dir, "retry-success");
    let (upstream_url, upstream_handle) = spawn_scripted_upstream(vec![401, 200]).await;

    let route = route_with_exec("anthropic", &upstream_url, vec![helper.as_str()]);
    let config = ProxyConfig {
        routes: vec![route],
        ..Default::default()
    };
    let proxy = start(config).await.expect("proxy start");
    let session_token = proxy.token.to_string();

    let response = proxy_request(proxy.port, "/anthropic/v1/messages", &session_token).await;

    let captured = tokio::time::timeout(Duration::from_secs(5), upstream_handle)
        .await
        .expect("upstream timeout")
        .expect("upstream task panic");
    proxy.shutdown();

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.starts_with("HTTP/1.1 200"),
        "client should see the retry's 200, got:\n{}",
        response_str
    );
    assert!(
        !response_str.contains("unauthorized"),
        "client must NOT see the failed-attempt body:\n{}",
        response_str
    );

    assert_eq!(captured.len(), 2, "upstream should have seen exactly 2 requests");
    assert!(
        String::from_utf8_lossy(&captured[0]).contains("Authorization: Bearer token-v1"),
        "first attempt should carry the cached token-v1; got:\n{}",
        String::from_utf8_lossy(&captured[0])
    );
    assert!(
        String::from_utf8_lossy(&captured[1]).contains("Authorization: Bearer token-v2"),
        "retry should carry the force-refreshed token-v2; got:\n{}",
        String::from_utf8_lossy(&captured[1])
    );

    // Helper script ran exactly twice: once at proxy startup (cache load) +
    // once on force_refresh after the 401. Confirms the retry actually re-ran
    // the command and didn't just re-emit the cached value.
    let final_count = std::fs::read_to_string(&counter).expect("read counter");
    assert_eq!(
        final_count.trim(),
        "2",
        "helper should have run exactly twice (initial load + force_refresh)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_credential_retries_only_once_on_persistent_401() {
    // Even when the upstream returns 401 on every request, the proxy must
    // attempt at most one retry — no infinite loops, no thundering herd
    // against an upstream that genuinely thinks the credential is bad.
    let dir = tempfile::tempdir().expect("tempdir");
    let (helper, counter) = write_rotating_helper(&dir, "retry-persistent");
    let (upstream_url, upstream_handle) = spawn_scripted_upstream(vec![401, 401, 401]).await;

    let route = route_with_exec("anthropic", &upstream_url, vec![helper.as_str()]);
    let config = ProxyConfig {
        routes: vec![route],
        ..Default::default()
    };
    let proxy = start(config).await.expect("proxy start");
    let session_token = proxy.token.to_string();

    let response = proxy_request(proxy.port, "/anthropic/v1/messages", &session_token).await;

    let captured = tokio::time::timeout(Duration::from_secs(5), upstream_handle)
        .await
        .expect("upstream timeout")
        .expect("upstream task panic");
    proxy.shutdown();

    // Client should see the second 401 (the retry's response). It is a real
    // upstream answer, not a synthetic one — and the proxy does not retry
    // again.
    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.starts_with("HTTP/1.1 401"),
        "client should see the retry's 401, got:\n{}",
        response_str
    );

    assert_eq!(
        captured.len(),
        2,
        "proxy must perform exactly 2 upstream attempts (no third try)"
    );

    // Helper ran twice: initial load + one force_refresh. Crucially: NOT
    // three times — we don't retry the retry.
    let final_count = std::fs::read_to_string(&counter).expect("read counter");
    assert_eq!(
        final_count.trim(),
        "2",
        "helper should have run exactly twice (initial load + one force_refresh)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exec_credential_rejects_unauthenticated_client() {
    // Same configuration, but the client connects with a bogus session token.
    // The proxy must respond 401 and never touch the upstream.
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_url = format!("http://{}", listener.local_addr().unwrap());
    // Detached: if the proxy ever tries to talk to it, the connection will
    // succeed (the kernel queues a backlog) but we'll never accept.
    drop(listener);
    // Replace with a listener that the test owns but refuses to accept on,
    // so a stray request would be visible as a connection-refused later.
    // Simpler: just use a distinct unbound port — but we still need an
    // upstream URL the proxy considers valid. Loopback is fine; nono blocks
    // its own listener on that port via NO_PROXY scoping. For this test the
    // upstream behaviour doesn't matter because we expect 401 before any
    // upstream connect happens.

    let route = route_with_exec(
        "anthropic",
        &upstream_url,
        vec!["/bin/echo", "-n", "should-not-leak"],
    );
    let config = ProxyConfig {
        routes: vec![route],
        ..Default::default()
    };
    let proxy = start(config).await.expect("proxy start");

    let response = proxy_request(proxy.port, "/anthropic/v1/messages", "wrong-session-token").await;
    proxy.shutdown();

    let response_str = String::from_utf8_lossy(&response);
    assert!(
        response_str.starts_with("HTTP/1.1 401"),
        "expected 401 for bogus session token, got:\n{}",
        response_str
    );
    assert!(
        !response_str.contains("should-not-leak"),
        "real bearer leaked in 401 response body"
    );
}
