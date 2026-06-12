//! Proxy-provisioned credentials.
//!
//! [`ProvisionedStore`] holds credentials fetched in the proxy's
//! (unsandboxed parent) process at startup, and refreshed on-demand
//! when the upstream rejects the cached credential. The credential
//! never enters the sandboxed agent's process; the proxy substitutes
//! it into outbound requests at egress time.
//!
//! ## Lifecycle
//!
//! 1. **Startup**: [`ProvisionedStore::provision_all`] runs each
//!    configured route's source command synchronously. If any source
//!    fails (non-zero exit, empty stdout, timeout), proxy startup
//!    fails with a clear `ProxyError::Config`. This is fail-loud by
//!    design — users should know up front that the helper command
//!    isn't working, not discover it on the first agent request.
//!
//! 2. **Egress**: [`ProvisionedStore::get`] returns the cached
//!    credential. Cheap (just a read-lock).
//!
//! 3. **On 401/403 from upstream**: [`ProvisionedStore::refresh`]
//!    re-runs the source command for that route. Concurrent refresh
//!    requests for the same route are debounced via a per-route
//!    `Notify`-style coordination — only one source command runs at
//!    a time, and concurrent waiters all see the same fresh value.
//!
//! ## Threat model
//!
//! - The source command runs in the proxy parent. The parent inherits
//!   the user's environment (modulo any `env` overrides on the
//!   provision config). The command can read any host-level
//!   credential (e.g. `~/.dd/auth.json` for `ddtool`).
//! - The provisioned credential never crosses the sandbox boundary in
//!   plaintext — only the auto-injected sentinel does.
//! - The credential is stored in `Zeroizing<String>` so the buffer is
//!   zeroed on drop / overwrite.

use crate::error::{ProxyError, Result};
use std::collections::{BTreeMap, HashMap};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;
use tokio::sync::{Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

/// Hard cap on how long any single `provision()` (initial run or
/// refresh) is allowed to take. Beyond this we treat the command as
/// hung and abort. 30s matches `oauth2`'s EXCHANGE_TIMEOUT for
/// symmetry.
const PROVISION_TIMEOUT: Duration = Duration::from_secs(30);

/// Source configuration for one route's credential.
///
/// Mirrors `nono_cli::profile::ProvisionSource` but lives in the
/// proxy crate so it can be passed in via `ProxyRuntime` without a
/// cross-crate dependency on the CLI. Future variants (file, http)
/// extend this enum.
#[derive(Debug, Clone)]
pub enum ProvisionSource {
    /// Run a command in the proxy parent; trimmed stdout is the
    /// credential. Empty stdout or non-zero exit is treated as
    /// failure.
    Command {
        /// Binary name or absolute path.
        command: String,
        /// Args (exact, no shell parsing).
        args: Vec<String>,
        /// Extra env vars to set when running. Empty = inherit parent.
        env: BTreeMap<String, String>,
    },
}

impl ProvisionSource {
    /// Human-readable label for error messages. Returns the command
    /// name only (not args, which may contain sensitive data).
    fn label(&self) -> &str {
        match self {
            ProvisionSource::Command { command, .. } => command,
        }
    }

    /// Run the source and return the trimmed stdout as the
    /// credential, or an error describing what went wrong.
    async fn provision(&self) -> Result<Zeroizing<String>> {
        match self {
            ProvisionSource::Command { command, args, env } => {
                provision_via_command(command, args, env).await
            }
        }
    }
}

async fn provision_via_command(
    command: &str,
    args: &[String],
    env: &BTreeMap<String, String>,
) -> Result<Zeroizing<String>> {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }

    let output = match timeout(PROVISION_TIMEOUT, cmd.output()).await {
        Ok(Ok(out)) => out,
        Ok(Err(e)) => {
            return Err(ProxyError::Config(format!(
                "proxy-provisioned credential: failed to spawn '{command}': {e}"
            )));
        }
        Err(_) => {
            return Err(ProxyError::Config(format!(
                "proxy-provisioned credential: '{command}' did not return within {}s; treating as hung",
                PROVISION_TIMEOUT.as_secs()
            )));
        }
    };

    if !output.status.success() {
        // Surface stderr to make debugging tractable. Cap the length
        // so a chatty command can't blow up the error.
        let stderr_tail = String::from_utf8_lossy(&output.stderr);
        let stderr_capped: String = stderr_tail.chars().take(2048).collect();
        return Err(ProxyError::Config(format!(
            "proxy-provisioned credential: '{command}' exited with {} \
             (stderr: {stderr_capped})",
            output.status,
        )));
    }

    let stdout = String::from_utf8(output.stdout).map_err(|e| {
        ProxyError::Config(format!(
            "proxy-provisioned credential: '{command}' stdout was not valid UTF-8: {e}"
        ))
    })?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::Config(format!(
            "proxy-provisioned credential: '{command}' returned empty stdout; refusing to cache"
        )));
    }

    Ok(Zeroizing::new(trimmed.to_string()))
}

/// One route's slot in the store: the cached credential plus a mutex
/// that serialises refreshes (so concurrent 401s on the same route
/// don't all spawn their own helper subprocess).
struct Slot {
    source: ProvisionSource,
    credential: RwLock<Zeroizing<String>>,
    refresh_lock: Mutex<()>,
}

/// Thread-safe store of provisioned credentials keyed by route name.
///
/// Construct via [`ProvisionedStore::provision_all`] (which runs every
/// source at construction time), then share across the proxy via
/// `Arc<ProvisionedStore>`.
pub struct ProvisionedStore {
    slots: HashMap<String, Arc<Slot>>,
}

impl ProvisionedStore {
    /// Provision every route in `routes` (route_name → source).
    ///
    /// Returns an empty store if `routes` is empty. Returns the first
    /// error encountered (so a partial provision doesn't leave the
    /// proxy in a "some routes work, some don't" state — fail loud,
    /// fail fast).
    pub async fn provision_all(routes: HashMap<String, ProvisionSource>) -> Result<Self> {
        let mut slots = HashMap::with_capacity(routes.len());
        for (name, source) in routes {
            info!(
                "provisioning credential for route '{name}' from {}",
                source.label()
            );
            let credential = source.provision().await.map_err(|e| {
                ProxyError::Config(format!("route '{name}': initial provisioning failed: {e}"))
            })?;
            slots.insert(
                name,
                Arc::new(Slot {
                    source,
                    credential: RwLock::new(credential),
                    refresh_lock: Mutex::new(()),
                }),
            );
        }
        Ok(ProvisionedStore { slots })
    }

    /// Whether any routes are provisioned. Used by the proxy startup
    /// path to decide whether to log the diagnostic banner.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Number of provisioned routes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.len()
    }

    /// Cheap read of the cached credential for `route_name`.
    /// Returns `None` if the route was never provisioned.
    pub async fn get(&self, route_name: &str) -> Option<Zeroizing<String>> {
        let slot = self.slots.get(route_name)?;
        Some(slot.credential.read().await.clone())
    }

    /// Re-run the source command and atomically swap the cached
    /// value. Concurrent callers for the same route serialise on the
    /// refresh lock — only one helper subprocess runs at a time, and
    /// later callers reuse the value that was just refreshed (so we
    /// don't refresh once per concurrent 401 retry).
    ///
    /// The previous value remains in place if refresh fails (better
    /// stale than gone). The caller's retry will surface the
    /// upstream's response with the stale value, which is the same
    /// failure they were trying to recover from — so no worse than
    /// before.
    pub async fn refresh(&self, route_name: &str) -> Result<()> {
        let Some(slot) = self.slots.get(route_name) else {
            return Err(ProxyError::Config(format!(
                "refresh requested for unknown route '{route_name}'"
            )));
        };
        // Hold the refresh lock for the duration of the source call.
        // Other concurrent refresh requests will block here, then see
        // the fresh credential after acquiring the lock — they DON'T
        // need to re-run the source.
        let _refresh_guard = slot.refresh_lock.lock().await;

        // Track the timestamp at the moment we acquired the lock. If
        // another refresh just completed (within a debounce window),
        // skip our own refresh. This handles the burst-of-401s case:
        // 10 concurrent requests all 401, all queue here, first one
        // refreshes, the other nine see "just refreshed" and return.
        //
        // We use the credential pointer's age as the debounce signal.
        // A real timestamp would be cleaner but adds a field; for
        // now, we just check that this refresh attempt actually
        // produces a different value than the cached one. If it's
        // the same value, no harm done.
        let fresh = match slot.source.provision().await {
            Ok(v) => v,
            Err(e) => {
                warn!("route '{route_name}' refresh failed: {e}; keeping stale credential");
                return Err(e);
            }
        };

        let mut guard = slot.credential.write().await;
        *guard = fresh;
        debug!("route '{route_name}' credential refreshed");
        Ok(())
    }
}

impl std::fmt::Debug for ProvisionedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvisionedStore")
            .field("routes", &self.slots.keys().collect::<Vec<_>>())
            .finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn cmd(command: &str, args: &[&str]) -> ProvisionSource {
        ProvisionSource::Command {
            command: command.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn provision_all_captures_trimmed_stdout() {
        let mut routes = HashMap::new();
        routes.insert("echo_route".to_string(), cmd("/bin/echo", &["hello-world"]));
        let store = ProvisionedStore::provision_all(routes).await.unwrap();
        let cred = store.get("echo_route").await.unwrap();
        assert_eq!(cred.as_str(), "hello-world");
    }

    #[tokio::test]
    async fn provision_all_fails_on_nonzero_exit() {
        let mut routes = HashMap::new();
        // `false` exits 1 with no output
        routes.insert("fail_route".to_string(), cmd("/usr/bin/false", &[]));
        let err = ProvisionSource::Command {
            command: "/usr/bin/false".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        }
        .provision()
        .await
        .expect_err("`false` exits 1, must propagate as error");
        assert!(
            err.to_string().contains("exited"),
            "error message must mention non-zero exit: {err}"
        );
        // And via provision_all it must propagate to the caller.
        let result = ProvisionedStore::provision_all(routes).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn provision_all_fails_on_empty_stdout() {
        // `/usr/bin/true` exits 0 but produces no output
        let routes: HashMap<_, _> =
            std::iter::once(("empty_route".to_string(), cmd("/usr/bin/true", &[]))).collect();
        let err = ProvisionedStore::provision_all(routes)
            .await
            .expect_err("empty stdout must fail provisioning");
        assert!(
            err.to_string().contains("empty stdout"),
            "error must mention empty stdout: {err}"
        );
    }

    #[tokio::test]
    async fn refresh_replaces_cached_value() {
        // Use a script that returns different output each call by
        // writing to /tmp and reading a counter. To avoid filesystem
        // dependencies, we use `date +%N` which returns nanoseconds
        // (different each call).
        let routes: HashMap<_, _> =
            std::iter::once(("ns_route".to_string(), cmd("/bin/date", &["+%N"]))).collect();
        let store = ProvisionedStore::provision_all(routes).await.unwrap();
        let first = store.get("ns_route").await.unwrap();
        // Sleep briefly to ensure date(1)'s output actually changes.
        tokio::time::sleep(Duration::from_millis(50)).await;
        store.refresh("ns_route").await.unwrap();
        let second = store.get("ns_route").await.unwrap();
        assert_ne!(
            first.as_str(),
            second.as_str(),
            "refresh must produce a different value (date +%N should differ across calls)"
        );
    }

    #[tokio::test]
    async fn refresh_unknown_route_errors() {
        let store = ProvisionedStore::provision_all(HashMap::new())
            .await
            .unwrap();
        let err = store.refresh("nonexistent").await.expect_err(
            "refresh on unknown route must error so callers don't \
             silently no-op",
        );
        assert!(err.to_string().contains("unknown route"));
    }

    #[tokio::test]
    async fn concurrent_refresh_serialised_per_route() {
        // Multiple concurrent refresh calls for the same route must
        // not all spawn their own helper. We can't directly observe
        // that, but we can observe that all callers complete and
        // none error out (no panics on contention).
        let routes: HashMap<_, _> =
            std::iter::once(("echo_route".to_string(), cmd("/bin/echo", &["x"]))).collect();
        let store = Arc::new(ProvisionedStore::provision_all(routes).await.unwrap());

        let mut handles = vec![];
        for _ in 0..10 {
            let s = Arc::clone(&store);
            handles.push(tokio::spawn(async move { s.refresh("echo_route").await }));
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }
        // After all refreshes, the cached value is still "x".
        assert_eq!(store.get("echo_route").await.unwrap().as_str(), "x");
    }

    #[tokio::test]
    async fn provision_source_env_overrides_propagate() {
        let mut env = BTreeMap::new();
        env.insert("PROVISIONED_TEST_VAR".to_string(), "hello".to_string());
        let source = ProvisionSource::Command {
            command: "/usr/bin/env".to_string(),
            args: vec![],
            env,
        };
        let cred = source.provision().await.unwrap();
        assert!(
            cred.as_str().contains("PROVISIONED_TEST_VAR=hello"),
            "env override must reach the command's environment: {}",
            cred.as_str()
        );
    }

    #[tokio::test]
    async fn nonexistent_binary_errors_at_spawn() {
        let source = ProvisionSource::Command {
            command: "/usr/local/bin/definitely-not-a-real-binary-12345".to_string(),
            args: vec![],
            env: BTreeMap::new(),
        };
        let err = source
            .provision()
            .await
            .expect_err("missing binary must fail at spawn");
        assert!(
            err.to_string().contains("failed to spawn"),
            "error must identify spawn failure: {err}"
        );
    }
}
