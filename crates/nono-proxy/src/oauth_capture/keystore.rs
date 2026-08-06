//! OAuth-capture token store backend selection.
//!
//! Captured OAuth tokens are real, live credentials (e.g. provider refresh
//! tokens), so persisting them to a plaintext file is a standing secret
//! exposure. The OS keychain is the default backend on macOS. Linux
//! workspaces commonly have no Secret Service/D-Bus session available, so an
//! owner-only file remains the fallback there (the same constraint that
//! forces other credential tooling to file-based storage on Linux).
//!
//! Keychain access fails closed: a keychain read/write error is propagated
//! rather than silently falling back to the file backend, since that
//! fallback is exactly the plaintext exposure this module exists to avoid.

use super::StoredOAuthToken;
use super::persist::load_persisted_tokens_from_file;
#[cfg(feature = "system-keyring")]
use super::persist::{decode_tokens, encode_tokens};
use crate::error::{ProxyError, Result};
use std::collections::HashMap;
use std::path::PathBuf;

/// Service and account identifying the single OAuth capture keychain entry.
///
/// Deliberately not derived from `fallback_path`: the store's file-backed
/// location has always been a single fixed path under the user's XDG state
/// dir (see `crate::state_paths::user_state_dir`), never one path per
/// profile or session, so a single keychain entry preserves the same
/// one-store-per-user shape the file backend already had.
#[cfg(feature = "system-keyring")]
const KEYCHAIN_SERVICE: &str = "nono-oauth-capture";
#[cfg(feature = "system-keyring")]
const KEYCHAIN_ACCOUNT: &str = "providers";

/// Where the OAuth capture store persists.
///
/// Exactly one variant is constructed in production per target, so the other
/// trips `dead_code` on that target even though both are live across the
/// platform matrix. The `cfg_attr`s below scope the allow to precisely those
/// platform combinations rather than silencing the lint everywhere.
#[derive(Debug, Clone)]
pub(super) enum OAuthCaptureBackend {
    /// OS keychain (macOS Keychain) via the `keyring` crate.
    ///
    /// Not constructed off macOS: the Linux environments nono targets have no
    /// usable Secret Service/D-Bus session.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Keychain,
    /// Owner-only JSON file at the given path.
    ///
    /// On macOS this is constructed only by tests — production fails closed on
    /// keychain errors rather than downgrading to a plaintext file.
    #[cfg_attr(all(target_os = "macos", not(test)), allow(dead_code))]
    File(PathBuf),
}

impl OAuthCaptureBackend {
    /// Select the default backend for a given file-backed fallback path.
    ///
    /// There is deliberately no runtime override to force the file backend on
    /// macOS: such a knob would let callers downgrade to plaintext storage,
    /// which is the exposure this module exists to remove. Tests construct
    /// [`OAuthCaptureBackend::File`] directly instead.
    pub(super) fn default_for(fallback_path: PathBuf) -> Self {
        #[cfg(target_os = "macos")]
        {
            let _ = &fallback_path;
            Self::Keychain
        }
        #[cfg(not(target_os = "macos"))]
        {
            Self::File(fallback_path)
        }
    }

    pub(super) fn load(&self) -> Result<HashMap<String, StoredOAuthToken>> {
        match self {
            Self::Keychain => load_from_keychain(),
            Self::File(path) => load_persisted_tokens_from_file(path),
        }
    }

    pub(super) fn persist(&self, tokens: &HashMap<String, StoredOAuthToken>) -> Result<()> {
        match self {
            Self::Keychain => store_to_keychain(tokens),
            Self::File(path) => super::persist::persist_tokens_to_file(path, tokens),
        }
    }
}

/// The two `keyring::Entry` operations this module needs, behind a trait so
/// tests can inject failures without touching a real OS keychain.
#[cfg(feature = "system-keyring")]
trait KeychainEntry {
    fn get_password(&self) -> std::result::Result<String, keyring::Error>;
    fn set_password(&self, password: &str) -> std::result::Result<(), keyring::Error>;
}

#[cfg(feature = "system-keyring")]
impl KeychainEntry for keyring::Entry {
    fn get_password(&self) -> std::result::Result<String, keyring::Error> {
        keyring::Entry::get_password(self)
    }

    fn set_password(&self, password: &str) -> std::result::Result<(), keyring::Error> {
        keyring::Entry::set_password(self, password)
    }
}

#[cfg(feature = "system-keyring")]
fn load_from_keychain() -> Result<HashMap<String, StoredOAuthToken>> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|err| ProxyError::Credential(format!("failed to access keychain: {err}")))?;
    load_from_keychain_entry(&entry)
}

#[cfg(feature = "system-keyring")]
fn load_from_keychain_entry(
    entry: &dyn KeychainEntry,
) -> Result<HashMap<String, StoredOAuthToken>> {
    match entry.get_password() {
        Ok(raw) => decode_tokens(raw.as_bytes()),
        Err(keyring::Error::NoEntry) => Ok(HashMap::new()),
        Err(err) => Err(ProxyError::Credential(format!(
            "failed to load OAuth capture store from keychain: {err}"
        ))),
    }
}

#[cfg(not(feature = "system-keyring"))]
fn load_from_keychain() -> Result<HashMap<String, StoredOAuthToken>> {
    Err(ProxyError::Credential(
        "system keychain is not available (built without system-keyring feature); \
         cannot load OAuth capture store"
            .to_string(),
    ))
}

#[cfg(feature = "system-keyring")]
fn store_to_keychain(tokens: &HashMap<String, StoredOAuthToken>) -> Result<()> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
        .map_err(|err| ProxyError::Credential(format!("failed to access keychain: {err}")))?;
    store_to_keychain_entry(&entry, tokens)
}

#[cfg(feature = "system-keyring")]
fn store_to_keychain_entry(
    entry: &dyn KeychainEntry,
    tokens: &HashMap<String, StoredOAuthToken>,
) -> Result<()> {
    let raw = encode_tokens(tokens)?;
    let raw = std::str::from_utf8(&raw).map_err(|_| {
        ProxyError::Credential("OAuth capture store encoding is not UTF-8".to_string())
    })?;
    entry.set_password(raw).map_err(|err| {
        ProxyError::Credential(format!(
            "failed to store OAuth capture store in keychain: {err}"
        ))
    })
}

#[cfg(not(feature = "system-keyring"))]
fn store_to_keychain(_tokens: &HashMap<String, StoredOAuthToken>) -> Result<()> {
    Err(ProxyError::Credential(
        "system keychain is not available (built without system-keyring feature); \
         cannot store OAuth capture store"
            .to_string(),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use zeroize::Zeroizing;

    fn sample_tokens() -> HashMap<String, StoredOAuthToken> {
        let mut admitted = HashSet::new();
        admitted.insert("proxy.test".to_string());
        let mut tokens = HashMap::new();
        tokens.insert(
            "phantom".to_string(),
            StoredOAuthToken {
                real: Zeroizing::new(b"real-secret".to_vec()),
                admitted_consumers: admitted,
                created_at_secs: 0,
            },
        );
        tokens
    }

    #[test]
    fn file_backend_roundtrips_tokens() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("providers.json");
        let backend = OAuthCaptureBackend::File(path);

        let tokens = sample_tokens();
        backend.persist(&tokens).unwrap();
        let loaded = backend.load().unwrap();
        assert_eq!(
            loaded.get("phantom").unwrap().real.as_slice(),
            b"real-secret"
        );
    }

    /// The default backend must be the keychain on macOS and the owner-only
    /// file elsewhere. Asserting this pins the platform split so a future
    /// refactor cannot quietly start writing plaintext on macOS.
    #[test]
    fn default_backend_is_keychain_on_macos_and_file_elsewhere() {
        let backend = OAuthCaptureBackend::default_for(PathBuf::from("/tmp/does-not-matter.json"));

        if cfg!(target_os = "macos") {
            assert!(matches!(backend, OAuthCaptureBackend::Keychain));
        } else {
            assert!(matches!(backend, OAuthCaptureBackend::File(_)));
        }
    }

    /// Injectable stand-in for `keyring::Entry`, so the fail-closed
    /// keychain read/write paths can be exercised without a real OS
    /// keychain.
    #[cfg(feature = "system-keyring")]
    struct FakeKeychainEntry {
        get_result: std::cell::RefCell<Option<std::result::Result<String, keyring::Error>>>,
        set_result: std::cell::RefCell<Option<std::result::Result<(), keyring::Error>>>,
    }

    #[cfg(feature = "system-keyring")]
    impl KeychainEntry for FakeKeychainEntry {
        fn get_password(&self) -> std::result::Result<String, keyring::Error> {
            self.get_result
                .borrow_mut()
                .take()
                .expect("get_password called more than once")
        }

        fn set_password(&self, _password: &str) -> std::result::Result<(), keyring::Error> {
            self.set_result
                .borrow_mut()
                .take()
                .expect("set_password called more than once")
        }
    }

    #[cfg(feature = "system-keyring")]
    fn platform_failure() -> keyring::Error {
        keyring::Error::NoStorageAccess(Box::new(std::io::Error::other("keychain locked")))
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn load_from_keychain_entry_returns_empty_map_on_no_entry() {
        let entry = FakeKeychainEntry {
            get_result: std::cell::RefCell::new(Some(Err(keyring::Error::NoEntry))),
            set_result: std::cell::RefCell::new(None),
        };

        let tokens = load_from_keychain_entry(&entry).unwrap();
        assert!(tokens.is_empty());
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn load_from_keychain_entry_fails_closed_on_keychain_error() {
        let entry = FakeKeychainEntry {
            get_result: std::cell::RefCell::new(Some(Err(platform_failure()))),
            set_result: std::cell::RefCell::new(None),
        };

        let err = load_from_keychain_entry(&entry).expect_err("keychain error must propagate");
        assert!(matches!(err, ProxyError::Credential(_)));
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn load_from_keychain_entry_decodes_stored_tokens() {
        let raw = encode_tokens(&sample_tokens()).unwrap();
        let entry = FakeKeychainEntry {
            get_result: std::cell::RefCell::new(Some(Ok(
                String::from_utf8(raw).expect("encoded tokens are UTF-8")
            ))),
            set_result: std::cell::RefCell::new(None),
        };

        let tokens = load_from_keychain_entry(&entry).unwrap();
        assert_eq!(
            tokens.get("phantom").unwrap().real.as_slice(),
            b"real-secret"
        );
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn store_to_keychain_entry_fails_closed_on_keychain_error_without_writing_a_file() {
        let entry = FakeKeychainEntry {
            get_result: std::cell::RefCell::new(None),
            set_result: std::cell::RefCell::new(Some(Err(platform_failure()))),
        };

        let err = store_to_keychain_entry(&entry, &sample_tokens())
            .expect_err("keychain write error must propagate, not fall back to a file");
        assert!(matches!(err, ProxyError::Credential(_)));
    }

    #[cfg(feature = "system-keyring")]
    #[test]
    fn store_to_keychain_entry_succeeds_when_keychain_accepts_write() {
        let entry = FakeKeychainEntry {
            get_result: std::cell::RefCell::new(None),
            set_result: std::cell::RefCell::new(Some(Ok(()))),
        };

        store_to_keychain_entry(&entry, &sample_tokens()).unwrap();
    }
}
