//! Persistent storage for the OAuth token broker (macOS only).
//!
//! Layer 1 OAuth capture mints `nono_<hex>` nonces and substitutes them for
//! real `(access_token, refresh_token)` pairs in the response body claude
//! receives. Without persistence the mapping is destroyed when nono exits,
//! so the nonces written to `Claude Code-credentials` by the rewritten
//! OAuth response have nothing to resolve to in the next nono session —
//! the user would have to `/login` again every time.
//!
//! This module persists captured pairs to the macOS Keychain under service
//! [`SERVICE_NAME`] (shared with nono's credential-injection feature),
//! account [`CLAUDE_OAUTH_ACCOUNT`]. On startup the broker hydrates from
//! the persisted record and re-registers the same nonces it issued in the
//! previous session, so the keychain entry the sandboxed claude reads
//! continues to resolve.
//!
//! ## Keychain ACL
//!
//! The broker entry is created with a strict trusted-application ACL
//! listing only the nono binary by path. `securityd` enforces this by
//! code signature — any other process (the sandboxed claude, the
//! `security` CLI, plugins reading the keychain directly via
//! `SecItemCopyMatching`) gets denied silently. This is what makes
//! the persisted real tokens unreachable from the agent even though
//! shadowfax's profile grants the agent broad Mach IPC access to
//! securityd.
//!
//! All Security framework operations run in-process (the nono binary,
//! which is in the ACL). No `security` CLI subprocess is used, removing
//! both the argv-leak risk and the 128-byte `readpassphrase(3)` cap
//! that affected earlier iterations of this module (see
//! `2026-04-27-capture-anthropic-auth.md` bug history).
//!
//! ## Binary-path staleness
//!
//! The stored `nono_path` field in the JSON record records the absolute
//! path of the nono binary at save time. On load it is compared against
//! `current_exe()`. A mismatch (upgrade, reinstall to a different
//! prefix, `cargo install` rebuild) means the existing entry's ACL
//! is keyed to a binary that no longer matches the running nono, so
//! subsequent reads would prompt. The broker treats this as a stale
//! entry: it deletes the old record and returns `None`, which leaves
//! the broker empty until the next `claude /login` triggers a fresh
//! capture with the correct ACL.
//!
//! ## Linux
//!
//! Not supported. Linux's keyring backends (secret-service,
//! gnome-keyring via the `keyring` crate) have no per-entry ACL —
//! entries are readable by any process running as the same user,
//! defeating the protection model that motivates persistence in the
//! first place. Linux callers always get an in-memory-only broker
//! (see `proxy_runtime::build_broker`).

use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Keychain service name shared with nono's credential-injection feature.
/// New account names introduced here must not collide with documented
/// account names from that feature (e.g. `openai_api_key`,
/// `anthropic_api_key`, `github_token`).
pub const SERVICE_NAME: &str = nono::keystore::DEFAULT_SERVICE;

/// Account name for the OAuth-capture broker's persisted record.
///
/// Holds a JSON object with both broker-issued nonces and the real
/// upstream tokens. Distinct from any user-managed account names so
/// `security add-generic-password` for unrelated services never
/// overwrites it and vice versa.
pub const CLAUDE_OAUTH_ACCOUNT: &str = "claude_oauth_broker";

/// One captured OAuth credential pair.
///
/// `access_nonce` and `refresh_nonce` are the broker-issued
/// `nono_<hex>` strings that the sandboxed client reads from its
/// own credential file (macOS keychain `Claude Code-credentials`).
/// `access_token` and `refresh_token` are the real upstream secrets
/// the broker forwards to Anthropic on behalf of the client.
#[derive(Debug, Clone)]
pub struct PersistedRecord {
    pub access_nonce: String,
    pub refresh_nonce: String,
    pub access_token: Zeroizing<String>,
    pub refresh_token: Zeroizing<String>,
}

/// Persistence backend for the broker.
///
/// Implementations are responsible for storing exactly one record per
/// service+account pair. `save` overwrites any existing record; `clear`
/// removes it. `load` returns `None` if no record is stored.
pub trait BrokerStore: Send + Sync {
    fn load(&self) -> Result<Option<PersistedRecord>>;
    fn save(&self, record: &PersistedRecord) -> Result<()>;
    fn clear(&self) -> Result<()>;
}

/// On-disk JSON shape. Kept private so callers go through `BrokerStore`
/// and hold the secret as `Zeroizing<String>` once decoded.
///
/// `nono_path` records the absolute path of the nono binary at save
/// time. On load it is compared against `current_exe()` to detect
/// binary-path changes. A mismatch triggers deletion of the stale
/// record so a fresh capture can rebuild the ACL for the new path.
/// Entries written by older nono versions lack this field; they are
/// also treated as stale and deleted on first load.
#[derive(Serialize, Deserialize)]
struct PersistedJson {
    access_nonce: String,
    refresh_nonce: String,
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    nono_path: Option<String>,
}

impl PersistedJson {
    fn from_record(record: &PersistedRecord, nono_exe: &std::path::Path) -> Self {
        Self {
            access_nonce: record.access_nonce.clone(),
            refresh_nonce: record.refresh_nonce.clone(),
            access_token: record.access_token.as_str().to_string(),
            refresh_token: record.refresh_token.as_str().to_string(),
            nono_path: Some(nono_exe.to_string_lossy().into_owned()),
        }
    }

    fn into_record(self) -> PersistedRecord {
        PersistedRecord {
            access_nonce: self.access_nonce,
            refresh_nonce: self.refresh_nonce,
            access_token: Zeroizing::new(self.access_token),
            refresh_token: Zeroizing::new(self.refresh_token),
        }
    }
}

// ── macOS: in-process Security framework helpers ─────────────────────────────

/// FFI bindings for legacy Keychain Services ACL APIs not exposed by
/// `security-framework-sys`. Security.framework is already linked by that
/// crate's `lib.rs` `#[link]` attribute, so no additional link attribute
/// is needed here.
#[cfg(target_os = "macos")]
mod macos_ffi {
    use core_foundation_sys::array::CFArrayRef;
    use core_foundation_sys::base::OSStatus;
    use core_foundation_sys::string::CFStringRef;
    use security_framework_sys::base::SecAccessRef;

    /// Opaque CF type for a trusted-application reference.
    pub type SecTrustedApplicationRef = *mut std::ffi::c_void;

    unsafe extern "C" {
        /// Creates a `SecTrustedApplicationRef` for the binary at `path`.
        /// On success `*app` is set to a Create-rule CF reference.
        pub fn SecTrustedApplicationCreateFromPath(
            path: *const std::ffi::c_char,
            app: *mut SecTrustedApplicationRef,
        ) -> OSStatus;

        /// Creates a `SecAccessRef` with `trustedlist` as the only apps that
        /// may access the item silently. On success `*access` holds a
        /// Create-rule CF reference.
        pub fn SecAccessCreate(
            descriptor: CFStringRef,
            trustedlist: CFArrayRef,
            access: *mut SecAccessRef,
        ) -> OSStatus;

        /// Attribute key used with `SecItemAdd` to associate a `SecAccessRef`
        /// with a new keychain item (legacy macOS Keychain Services attribute).
        pub static kSecAttrAccess: CFStringRef;
    }
}

/// Build a `SecAccess` that only lists the nono binary as a trusted
/// application — `securityd` will silently deny any other caller.
#[cfg(target_os = "macos")]
fn create_nono_access(
    exe_path: &std::path::Path,
) -> Result<security_framework::os::macos::access::SecAccess> {
    use core_foundation::base::TCFType;
    use core_foundation_sys::array::{CFArrayCreate, kCFTypeArrayCallBacks};
    use core_foundation_sys::base::{CFRelease, kCFAllocatorDefault};
    use core_foundation_sys::string::{CFStringCreateWithBytes, kCFStringEncodingUTF8};
    use macos_ffi::{
        SecAccessCreate, SecTrustedApplicationCreateFromPath, SecTrustedApplicationRef,
    };
    use security_framework::os::macos::access::SecAccess;
    use security_framework_sys::base::SecAccessRef;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path_cstr = CString::new(exe_path.as_os_str().as_bytes()).map_err(|e| {
        NonoError::KeystoreAccess(format!("nono binary path has interior NUL: {e}"))
    })?;

    // SAFETY: path_cstr is a valid NUL-terminated C string. trusted_app
    // receives a Create-rule CF reference that we release after the array retains it.
    let mut trusted_app: SecTrustedApplicationRef = std::ptr::null_mut();
    let status =
        unsafe { SecTrustedApplicationCreateFromPath(path_cstr.as_ptr(), &mut trusted_app) };
    if status != 0 {
        return Err(NonoError::KeystoreAccess(format!(
            "SecTrustedApplicationCreateFromPath: OSStatus {status}"
        )));
    }

    // Wrap in a single-element CFArray. kCFTypeArrayCallBacks calls CFRetain
    // on insertion, so the array owns its own reference to trusted_app.
    // SAFETY: trusted_app is a valid non-null CF object from the call above.
    let items = [trusted_app as *const std::ffi::c_void];
    let array = unsafe {
        CFArrayCreate(
            kCFAllocatorDefault,
            items.as_ptr(),
            1,
            &kCFTypeArrayCallBacks,
        )
    };

    // Release our Create-rule reference; the array now owns the only reference.
    // SAFETY: trusted_app is a Create-rule reference (must be released exactly once).
    unsafe { CFRelease(trusted_app as *const _) };

    if array.is_null() {
        return Err(NonoError::KeystoreAccess(
            "CFArrayCreate for trusted-apps list returned null".to_string(),
        ));
    }

    // Descriptor string for the access object (shown in Keychain Access.app).
    // SAFETY: bytes are valid UTF-8; returns a Create-rule CFStringRef.
    let descriptor_bytes = b"nono oauth broker";
    let descriptor = unsafe {
        CFStringCreateWithBytes(
            kCFAllocatorDefault,
            descriptor_bytes.as_ptr(),
            descriptor_bytes.len() as isize,
            kCFStringEncodingUTF8,
            false as u8,
        )
    };
    if descriptor.is_null() {
        // SAFETY: array is a Create-rule reference from CFArrayCreate above.
        unsafe { CFRelease(array as *const _) };
        return Err(NonoError::KeystoreAccess(
            "CFStringCreateWithBytes for access descriptor returned null".to_string(),
        ));
    }

    let mut access_ref: SecAccessRef = std::ptr::null_mut();
    // SAFETY: descriptor and array are valid CF objects; access_ref receives
    // a Create-rule reference on success.
    let status = unsafe { SecAccessCreate(descriptor, array, &mut access_ref) };

    // Release temporaries regardless of outcome.
    // SAFETY: both are Create-rule references from above.
    unsafe {
        CFRelease(descriptor as *const _);
        CFRelease(array as *const _);
    }

    if status != 0 {
        if !access_ref.is_null() {
            // SAFETY: access_ref is a Create-rule reference from SecAccessCreate.
            unsafe { CFRelease(access_ref as *const _) };
        }
        return Err(NonoError::KeystoreAccess(format!(
            "SecAccessCreate: OSStatus {status}"
        )));
    }

    // SAFETY: access_ref is a non-null Create-rule reference; wrap_under_create_rule
    // takes ownership and will call CFRelease on drop.
    Ok(unsafe { SecAccess::wrap_under_create_rule(access_ref) })
}

/// Write the broker record to the keychain with a nono-only ACL.
///
/// Any existing entry for `service`/`account` is deleted first so that
/// the ACL on the new entry is always set correctly (rather than
/// inheriting the ACL from a prior write that might have used `-A`).
#[cfg(target_os = "macos")]
fn save_with_nono_acl(service: &str, account: &str, payload: &Zeroizing<String>) -> Result<()> {
    use core_foundation::base::TCFType;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFMutableDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::SecItemAdd;

    let exe_path = std::env::current_exe()
        .map_err(|e| NonoError::KeystoreAccess(format!("resolve nono binary path: {e}")))?;

    let access = create_nono_access(&exe_path)?;

    // Delete any pre-existing entry so the new one gets a fresh ACL.
    // Ignore "not found" — this is a best-effort cleanup.
    delete_broker_entry_in_process(service, account);

    let class_key = unsafe { CFString::wrap_under_get_rule(kSecClass) };
    let class_val = unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) };
    let svc_key = unsafe { CFString::wrap_under_get_rule(kSecAttrService) };
    let svc_val = CFString::from(service);
    let acct_key = unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) };
    let acct_val = CFString::from(account);
    let data_key = unsafe { CFString::wrap_under_get_rule(kSecValueData) };
    let data_val = CFData::from_buffer(payload.as_bytes());
    let access_key = unsafe { CFString::wrap_under_get_rule(macos_ffi::kSecAttrAccess) };

    let mut dict = CFMutableDictionary::from_CFType_pairs(&[]);
    dict.add(&class_key.as_CFTypeRef(), &class_val.as_CFTypeRef());
    dict.add(&svc_key.as_CFTypeRef(), &svc_val.as_CFTypeRef());
    dict.add(&acct_key.as_CFTypeRef(), &acct_val.as_CFTypeRef());
    dict.add(&data_key.as_CFTypeRef(), &data_val.as_CFTypeRef());
    dict.add(&access_key.as_CFTypeRef(), &access.as_CFTypeRef());

    // SAFETY: dict is a valid CFDictionaryRef.
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status != 0 {
        return Err(NonoError::KeystoreAccess(format!(
            "SecItemAdd for {service}/{account}: OSStatus {status}"
        )));
    }

    Ok(())
}

/// Load the raw JSON string for `service`/`account` using an in-process
/// Security framework call. Running in the nono process ensures the
/// nono-only ACL is satisfied silently — no `security` CLI subprocess,
/// no prompts.
#[cfg(target_os = "macos")]
fn load_in_process(service: &str, account: &str) -> Result<Option<String>> {
    use security_framework::os::macos::passwords::find_generic_password;

    match find_generic_password(None, service, account) {
        Ok((password_bytes, _item)) => {
            let s = std::str::from_utf8(password_bytes.as_ref()).map_err(|e| {
                NonoError::KeystoreAccess(format!(
                    "broker record at {service}/{account} contains non-UTF8 bytes: {e}"
                ))
            })?;
            Ok(Some(s.to_owned()))
        }
        Err(e) => {
            // errSecItemNotFound (-25300) → no entry yet; any other error is real.
            use security_framework_sys::base::errSecItemNotFound;
            if e.code() == errSecItemNotFound {
                Ok(None)
            } else {
                Err(NonoError::KeystoreAccess(format!(
                    "broker record load from {service}/{account}: {e}"
                )))
            }
        }
    }
}

/// Delete the broker keychain entry in-process. Errors (including
/// "item not found") are silently swallowed — callers use this as a
/// best-effort cleanup before writing a fresh entry.
#[cfg(target_os = "macos")]
fn delete_broker_entry_in_process(service: &str, account: &str) {
    use security_framework::os::macos::passwords::find_generic_password;

    if let Ok((_, item)) = find_generic_password(None, service, account) {
        item.delete();
    }
}

/// Read the `claudeAiOauth.accessToken` field from claude's own
/// `Claude Code-credentials` keychain entry, if present.
///
/// Used by [`super::broker::TokenBroker::with_store_and_reader`] to
/// detect stale broker records (the user `/logout`-ed inside claude
/// but our persisted record still holds the real refresh token).
///
/// All failure modes (keychain missing, locked, malformed JSON, no
/// access token in the envelope) collapse to `None` — the caller
/// treats both "no entry" and "couldn't read entry" identically:
/// drop the broker record and force a re-login. This is the
/// conservative choice: better to drop a live record than to leak a
/// real token because we couldn't tell.
#[cfg(target_os = "macos")]
pub fn current_claude_access_token() -> Option<String> {
    use security_framework::os::macos::passwords::find_generic_password;

    let account = std::env::var("USER").unwrap_or_else(|_| "claude-code-user".to_string());
    let service = claude_credentials_service_name()?;

    let (password_bytes, _item) = find_generic_password(None, &service, &account).ok()?;
    let raw = std::str::from_utf8(password_bytes.as_ref()).ok()?;
    let envelope: serde_json::Value = serde_json::from_str(raw).ok()?;
    envelope
        .get("claudeAiOauth")?
        .get("accessToken")?
        .as_str()
        .map(str::to_owned)
}

/// Derive the macOS keychain service name claude uses for its OAuth
/// credentials. Mirrors the `sandbox_prepare::claude_keychain_service_name`
/// logic (custom-oauth, staging/local toggles, explicit
/// `CLAUDE_CONFIG_DIR` hash suffix) so this module stays self-contained
/// without depending on `sandbox_prepare`.
#[cfg(target_os = "macos")]
fn claude_credentials_service_name() -> Option<String> {
    use sha2::{Digest, Sha256};

    let (config_dir, explicit) = if let Some(custom) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        (std::path::PathBuf::from(custom), true)
    } else {
        let home = std::env::var_os("HOME")?;
        (std::path::PathBuf::from(home).join(".claude"), false)
    };

    let suffix = claude_oauth_suffix();
    let dir_hash = if explicit {
        let digest = Sha256::digest(config_dir.to_string_lossy().as_bytes());
        let prefix = digest[..4]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("-{prefix}")
    } else {
        String::new()
    };
    Some(format!("Claude Code{suffix}-credentials{dir_hash}"))
}

#[cfg(target_os = "macos")]
fn claude_oauth_suffix() -> &'static str {
    if std::env::var_os("CLAUDE_CODE_CUSTOM_OAUTH_URL").is_some() {
        return "-custom-oauth";
    }
    if std::env::var("USER_TYPE").ok().as_deref() == Some("ant") {
        let truthy = |key: &str| {
            std::env::var(key).ok().is_some_and(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            })
        };
        if truthy("USE_LOCAL_OAUTH") {
            return "-local-oauth";
        }
        if truthy("USE_STAGING_OAUTH") {
            return "-staging-oauth";
        }
    }
    ""
}

// ── KeystoreBrokerStore ───────────────────────────────────────────────────────

/// macOS Keychain-backed store. Not available on other platforms.
#[cfg(target_os = "macos")]
pub struct KeystoreBrokerStore {
    service: String,
    account: String,
}

#[cfg(target_os = "macos")]
impl KeystoreBrokerStore {
    /// Construct a store keyed by `service` and `account`.
    pub fn new(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// Default store: nono's credential-injection service, OAuth account.
    pub fn default_for_claude_oauth() -> Self {
        Self::new(SERVICE_NAME, CLAUDE_OAUTH_ACCOUNT)
    }
}

#[cfg(target_os = "macos")]
impl BrokerStore for KeystoreBrokerStore {
    fn load(&self) -> Result<Option<PersistedRecord>> {
        let exe_path = std::env::current_exe()
            .map_err(|e| NonoError::KeystoreAccess(format!("resolve nono binary path: {e}")))?;

        let maybe_json = load_in_process(&self.service, &self.account)?;
        let json = match maybe_json {
            None => return Ok(None),
            Some(j) => j,
        };

        let parsed = serde_json::from_str::<PersistedJson>(&json).map_err(|e| {
            NonoError::KeystoreAccess(format!(
                "broker record at {}/{} is not valid JSON: {e}",
                self.service, self.account
            ))
        })?;

        // Validate the stored nono binary path. A mismatch means either an
        // upgrade changed the install location, or the entry pre-dates the
        // nono_path field. In both cases the ACL on the existing entry may
        // not match the current binary, so we delete it and return None —
        // the next OAuth capture will create a fresh entry with the correct ACL.
        let stored_path = match &parsed.nono_path {
            Some(p) => p.as_str(),
            None => {
                tracing::info!(
                    "broker record at {}/{} has no nono_path; deleting stale entry",
                    self.service,
                    self.account
                );
                delete_broker_entry_in_process(&self.service, &self.account);
                return Ok(None);
            }
        };

        if stored_path != exe_path.to_string_lossy().as_ref() as &str {
            tracing::info!(
                "nono binary path changed ({stored_path} → {}); deleting stale broker entry",
                exe_path.display()
            );
            delete_broker_entry_in_process(&self.service, &self.account);
            return Ok(None);
        }

        Ok(Some(parsed.into_record()))
    }

    fn save(&self, record: &PersistedRecord) -> Result<()> {
        let exe_path = std::env::current_exe()
            .map_err(|e| NonoError::KeystoreAccess(format!("resolve nono binary path: {e}")))?;

        let json: Zeroizing<String> = Zeroizing::new(
            serde_json::to_string(&PersistedJson::from_record(record, &exe_path))
                .map_err(|e| NonoError::KeystoreAccess(format!("broker record serialise: {e}")))?,
        );

        save_with_nono_acl(&self.service, &self.account, &json)
    }

    fn clear(&self) -> Result<()> {
        delete_broker_entry_in_process(&self.service, &self.account);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    //! In-memory `BrokerStore` for unit tests.

    use super::*;
    use std::sync::Mutex;

    pub struct MemoryBrokerStore {
        record: Mutex<Option<PersistedRecord>>,
    }

    impl MemoryBrokerStore {
        pub fn new() -> Self {
            Self {
                record: Mutex::new(None),
            }
        }

        pub fn preload(record: PersistedRecord) -> Self {
            Self {
                record: Mutex::new(Some(record)),
            }
        }

        pub fn current(&self) -> Option<PersistedRecord> {
            self.record
                .lock()
                .expect("MemoryBrokerStore poisoned")
                .clone()
        }
    }

    impl BrokerStore for MemoryBrokerStore {
        fn load(&self) -> Result<Option<PersistedRecord>> {
            Ok(self
                .record
                .lock()
                .expect("MemoryBrokerStore poisoned")
                .clone())
        }

        fn save(&self, record: &PersistedRecord) -> Result<()> {
            *self.record.lock().expect("MemoryBrokerStore poisoned") = Some(record.clone());
            Ok(())
        }

        fn clear(&self) -> Result<()> {
            *self.record.lock().expect("MemoryBrokerStore poisoned") = None;
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn persisted_json_payload_exceeds_readpassphrase_buffer() {
        // Regression guard: the macOS save path now uses SecItemAdd directly
        // (no `readpassphrase(3)` cap), but the serialised payload still
        // exceeds 128 bytes. If a future refactor reintroduces a
        // `security ... -w` (stdin-pipe to readpassphrase) backend, this test
        // makes the silent-truncation failure mode visible at build time —
        // see commit aa4e51af for the original incident.
        let exe_path = std::path::Path::new("/usr/local/bin/nono");
        let record = PersistedRecord {
            access_nonce: format!("nono_{}", "a".repeat(64)),
            refresh_nonce: format!("nono_{}", "b".repeat(64)),
            // Anthropic OAuth tokens are JWT-shaped, typically 150-300
            // bytes. Use a representative 200-byte string here.
            access_token: Zeroizing::new("sk-ant-oat01-".to_string() + &"x".repeat(187)),
            refresh_token: Zeroizing::new("sk-ant-ort01-".to_string() + &"y".repeat(187)),
        };
        let json = serde_json::to_string(&PersistedJson::from_record(&record, exe_path))
            .expect("serialise persisted json");
        assert!(
            json.len() > 128,
            "payload must exceed 128 bytes (got {} bytes); \
             update the test or verify the backend handles large values",
            json.len()
        );
    }

    #[test]
    fn nono_path_round_trips_through_json() {
        let exe_path = std::path::Path::new("/old/path/to/nono");
        let record = PersistedRecord {
            access_nonce: format!("nono_{}", "a".repeat(64)),
            refresh_nonce: format!("nono_{}", "b".repeat(64)),
            access_token: Zeroizing::new("real_access".to_string()),
            refresh_token: Zeroizing::new("real_refresh".to_string()),
        };
        let json = serde_json::to_string(&PersistedJson::from_record(&record, exe_path)).unwrap();
        let parsed: PersistedJson = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.nono_path.as_deref(), Some("/old/path/to/nono"));
    }

    #[test]
    fn missing_nono_path_deserialises_as_none() {
        // Entries written by older versions of nono omit the nono_path field.
        // `serde(default)` should deserialise them with `nono_path = None`,
        // which `KeystoreBrokerStore::load` treats as stale and deletes.
        let legacy_json = r#"{
            "access_nonce": "nono_aaaa",
            "refresh_nonce": "nono_bbbb",
            "access_token": "real_access",
            "refresh_token": "real_refresh"
        }"#;
        let parsed: PersistedJson = serde_json::from_str(legacy_json).unwrap();
        assert!(
            parsed.nono_path.is_none(),
            "legacy entries must deserialise with nono_path = None"
        );
    }

    #[test]
    fn memory_store_round_trips_save_load_clear() {
        use test_support::MemoryBrokerStore;
        let store = MemoryBrokerStore::new();
        assert!(store.load().unwrap().is_none(), "fresh store is empty");

        let record = PersistedRecord {
            access_nonce: "nono_a".to_string(),
            refresh_nonce: "nono_b".to_string(),
            access_token: Zeroizing::new("real_a".to_string()),
            refresh_token: Zeroizing::new("real_b".to_string()),
        };
        store.save(&record).unwrap();
        let loaded = store.load().unwrap().expect("save then load");
        assert_eq!(loaded.access_nonce, "nono_a");
        assert_eq!(loaded.access_token.as_str(), "real_a");

        store.clear().unwrap();
        assert!(store.load().unwrap().is_none(), "cleared store is empty");
    }
}
