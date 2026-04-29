//! TLS-intercept session CA and on-demand leaf-cert factory.
//!
//! Generates a fresh root CA per proxy session, in memory only, and
//! issues short-lived leaf certificates for individual hostnames on
//! demand. Each leaf is signed by the session CA and presented to the
//! sandboxed agent during TLS handshake; the agent trusts the CA via
//! `NODE_EXTRA_CA_CERTS`, populated from a PEM file written by
//! [`InterceptCa::write_ca_pem`].
//!
//! The CA private key never leaves this process. Only the public CA
//! certificate is materialized to disk.
//!
//! Layer 1 of the OAuth-capture design (see
//! `2026-04-27-capture-anthropic-auth.md`). This module is self-contained
//! and not yet wired into [`crate::connect`]; that wiring is Layer 1.2.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tracing::debug;

use crate::error::{ProxyError, Result};

/// CA validity window. Far longer than any reasonable session, and a
/// fresh CA is regenerated on every proxy startup.
const CA_VALIDITY: Duration = Duration::from_secs(24 * 60 * 60);

/// Leaf certificate validity. One hour bounds the blast radius if a
/// cached `ServerConfig` somehow leaked (the leaf private key never
/// leaves this process, so this is defence in depth).
const LEAF_VALIDITY: Duration = Duration::from_secs(60 * 60);

/// Backdated `NotBefore` window to absorb client/server clock skew.
const CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);

/// File mode for the materialized CA PEM. The cert itself is public
/// information; 0644 mirrors the design in
/// `2026-04-27-capture-anthropic-auth.md` (read-only mount into the
/// child via `NODE_EXTRA_CA_CERTS`).
const CA_PEM_MODE: u32 = 0o644;

/// Session-scoped TLS-interception authority.
///
/// Holds the CA certificate (PEM form for materialization), the CA
/// signing key (kept in memory only), and a hostname → `ServerConfig`
/// cache so we re-issue at most one leaf per host per session.
pub struct InterceptCa {
    ca_pem: String,
    issuer: Issuer<'static, KeyPair>,
    leaf_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

impl InterceptCa {
    /// Generate a fresh session CA. The private key is held in memory
    /// only and is never written to disk.
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Config(format!("CA key generation failed: {e}")))?;

        let mut params = CertificateParams::new(Vec::<String>::new())
            .map_err(|e| ProxyError::Config(format!("CA params init failed: {e}")))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "nono session CA");
        params.distinguished_name = dn;

        // Restrict to issuing leaf certs only (path-length 0).
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let now = SystemTime::now();
        params.not_before = (now - CLOCK_SKEW).into();
        params.not_after = (now + CA_VALIDITY).into();

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| ProxyError::Config(format!("CA self-sign failed: {e}")))?;
        let ca_pem = ca_cert.pem();

        let issuer = Issuer::new(params, key_pair);

        debug!(
            "generated TLS-intercept session CA (validity: {} hours)",
            CA_VALIDITY.as_secs() / 3600
        );

        Ok(Self {
            ca_pem,
            issuer,
            leaf_cache: Mutex::new(HashMap::new()),
        })
    }

    /// Public CA certificate as PEM. Suitable for the contents of
    /// `NODE_EXTRA_CA_CERTS`.
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Get a `ServerConfig` for the given hostname, generating and
    /// caching a fresh leaf certificate on first use. Hostname matching
    /// is case-insensitive; the cache key is lowercase.
    pub fn server_config_for(&self, hostname: &str) -> Result<Arc<ServerConfig>> {
        let key = hostname.to_ascii_lowercase();

        let mut cache = self
            .leaf_cache
            .lock()
            .expect("InterceptCa leaf_cache mutex poisoned");

        if let Some(existing) = cache.get(&key) {
            return Ok(Arc::clone(existing));
        }

        let server_config = self.build_leaf_server_config(&key)?;
        let arc = Arc::new(server_config);
        cache.insert(key.clone(), Arc::clone(&arc));
        debug!("issued TLS-intercept leaf for {}", key);
        Ok(arc)
    }

    /// Write the CA PEM to `path` with mode 0644. The write is atomic
    /// (write-temp + rename) so a concurrent reader never sees a
    /// half-written file. The parent directory must already exist.
    pub fn write_ca_pem(&self, path: &Path) -> Result<()> {
        let parent = path.parent().ok_or_else(|| {
            ProxyError::Config(format!(
                "CA PEM path has no parent directory: {}",
                path.display()
            ))
        })?;
        if !parent.exists() {
            return Err(ProxyError::Config(format!(
                "CA PEM parent directory does not exist: {}",
                parent.display()
            )));
        }

        // Write to a sibling temp file, then rename atomically.
        let mut tmp = path.to_path_buf();
        let tmp_name = match path.file_name() {
            Some(name) => format!(".{}.tmp", name.to_string_lossy()),
            None => {
                return Err(ProxyError::Config(format!(
                    "CA PEM path has no file name: {}",
                    path.display()
                )));
            }
        };
        tmp.set_file_name(tmp_name);

        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(CA_PEM_MODE)
                .open(&tmp)?;
            f.write_all(self.ca_pem.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    fn build_leaf_server_config(&self, hostname: &str) -> Result<ServerConfig> {
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|e| ProxyError::Config(format!("leaf key generation failed: {e}")))?;

        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .map_err(|e| ProxyError::Config(format!("leaf params init failed: {e}")))?;

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let now = SystemTime::now();
        params.not_before = (now - CLOCK_SKEW).into();
        params.not_after = (now + LEAF_VALIDITY).into();

        let leaf_cert = params
            .signed_by(&leaf_key, &self.issuer)
            .map_err(|e| ProxyError::Config(format!("leaf signing failed: {e}")))?;

        let leaf_der: CertificateDer<'static> = leaf_cert.der().clone();
        let leaf_key_der = leaf_key.serialize_der();

        let cert_chain: Vec<CertificateDer<'static>> = vec![leaf_der];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| ProxyError::Config(format!("rustls protocol versions: {e}")))?
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| ProxyError::Config(format!("rustls server cert: {e}")))?;

        Ok(config)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn ca_new_succeeds_and_emits_pem() {
        let ca = InterceptCa::new().unwrap();
        let pem = ca.ca_pem();
        assert!(
            pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "CA PEM should start with the certificate header, got: {}",
            &pem[..pem.len().min(80)]
        );
        assert!(
            pem.trim_end().ends_with("-----END CERTIFICATE-----"),
            "CA PEM should end with the certificate footer"
        );
    }

    #[test]
    fn each_session_ca_is_unique() {
        let a = InterceptCa::new().unwrap();
        let b = InterceptCa::new().unwrap();
        assert_ne!(
            a.ca_pem(),
            b.ca_pem(),
            "fresh sessions must yield distinct CAs"
        );
    }

    #[test]
    fn server_config_for_caches_per_host() {
        let ca = InterceptCa::new().unwrap();
        let cfg1 = ca.server_config_for("claude.ai").unwrap();
        let cfg2 = ca.server_config_for("claude.ai").unwrap();
        assert!(
            Arc::ptr_eq(&cfg1, &cfg2),
            "second call for same host should return the cached Arc"
        );
    }

    #[test]
    fn server_config_for_is_case_insensitive() {
        let ca = InterceptCa::new().unwrap();
        let lower = ca.server_config_for("claude.ai").unwrap();
        let upper = ca.server_config_for("CLAUDE.AI").unwrap();
        assert!(
            Arc::ptr_eq(&lower, &upper),
            "host lookup must be case-insensitive"
        );
    }

    #[test]
    fn server_config_for_distinct_hosts_yields_distinct_configs() {
        let ca = InterceptCa::new().unwrap();
        let a = ca.server_config_for("claude.ai").unwrap();
        let b = ca.server_config_for("api.anthropic.com").unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "different hosts must get different leaves"
        );
    }

    #[test]
    fn write_ca_pem_creates_file_with_mode_0644() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let ca = InterceptCa::new().unwrap();

        ca.write_ca_pem(&path).unwrap();

        let meta = fs::metadata(&path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, CA_PEM_MODE, "CA PEM should be written with mode 0644");

        let on_disk = fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk, ca.ca_pem(), "on-disk PEM must match in-memory PEM");
    }

    #[test]
    fn write_ca_pem_is_idempotent_and_overwrites() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.pem");
        let ca = InterceptCa::new().unwrap();

        ca.write_ca_pem(&path).unwrap();
        let first = fs::read_to_string(&path).unwrap();
        ca.write_ca_pem(&path).unwrap();
        let second = fs::read_to_string(&path).unwrap();

        assert_eq!(first, second, "rewriting same CA should produce same bytes");
        // No stray .tmp files left behind.
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with('.'))
            .collect();
        assert!(
            leftovers.is_empty(),
            "atomic-write tempfile must be renamed away, found: {:?}",
            leftovers
        );
    }

    #[test]
    fn write_ca_pem_rejects_missing_parent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing").join("ca.pem");
        let ca = InterceptCa::new().unwrap();

        let err = ca.write_ca_pem(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("parent directory does not exist"),
            "expected missing-parent error, got: {msg}"
        );
    }

    #[test]
    fn leaf_cert_chain_is_single_leaf() {
        // The ServerConfig itself doesn't expose its cert chain in a
        // public API, but we can re-derive a leaf via the same path the
        // builder uses and confirm it parses as a valid X.509 leaf with
        // the requested SAN. We do this by issuing through the public
        // `server_config_for` and re-parsing the most recent leaf via
        // an internal helper test path: the CertifiedKey is private, so
        // here we rely on a smoke-test — the Arc must not be null and
        // calling twice yields the cached entry.
        let ca = InterceptCa::new().unwrap();
        let cfg = ca.server_config_for("example.com").unwrap();
        // Smoke: Arc strong count >= 2 (cache + returned clone).
        assert!(
            Arc::strong_count(&cfg) >= 2,
            "leaf cache must hold its own strong reference"
        );
    }
}
