use crate::trust_cmd;
use nono::trust;
use nono::undo::{AuditAttestationSummary, AuditIntegritySummary, ContentHash, SessionMetadata};
use nono::{NonoError, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

pub(crate) const AUDIT_ATTESTATION_BUNDLE_FILENAME: &str = "audit-attestation.bundle";
pub(crate) const AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA: &str =
    "https://nono.sh/attestation/audit-session/alpha";
const KEYSTORE_URI_PREFIX: &str = "keystore://";

/// Subject name for the mediation-log subject in multi-subject bundles.
///
/// Upstream audit-events streams use `audit-session:{id}`. Mediation streams
/// use this prefix instead so a single bundle can attest to multiple
/// side-by-side audit files without name collisions.
const MEDIATION_SUBJECT_NAME_PREFIX: &str = "mediation-log:";
const AUDIT_SUBJECT_NAME_PREFIX: &str = "audit-session:";

pub(crate) struct AuditSigner {
    key_pair: trust::KeyPair,
    pub(crate) key_id: String,
    pub(crate) public_key_b64: String,
}

#[cfg(test)]
pub(crate) fn signer_from_key_pair(key_pair: trust::KeyPair) -> Result<AuditSigner> {
    let key_id = trust::key_id_hex(&key_pair)?;
    let public_key = trust::export_public_key(&key_pair)?;
    Ok(AuditSigner {
        key_pair,
        key_id,
        public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
    })
}

#[derive(Serialize)]
pub(crate) struct AuditAttestationVerificationResult {
    pub(crate) present: bool,
    pub(crate) predicate_type: Option<String>,
    pub(crate) key_id: Option<String>,
    pub(crate) key_id_matches: bool,
    pub(crate) signature_verified: bool,
    pub(crate) merkle_root_matches: bool,
    pub(crate) session_id_matches: bool,
    pub(crate) expected_public_key_matches: Option<bool>,
    /// Whether a mediation-log subject was verified. `None` when no
    /// mediation integrity summary was supplied; `Some(true/false)`
    /// when one was and verification succeeded / failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mediation_merkle_root_matches: Option<bool>,
    pub(crate) verification_error: Option<String>,
}

#[derive(Serialize)]
struct AuditAttestationPredicate<'a> {
    version: u32,
    session_id: &'a str,
    started: &'a str,
    ended: &'a Option<String>,
    command: &'a [String],
    audit_log: AuditLogPredicate<'a>,
    /// Optional second audit stream covered by the same bundle.
    /// Absent when the session only has a single (capability-level)
    /// audit stream; present when a parallel per-command stream exists
    /// and the attestation should cover both.
    #[serde(skip_serializing_if = "Option::is_none")]
    mediation_log: Option<AuditLogPredicate<'a>>,
    signer: AuditSignerPredicate<'a>,
}

#[derive(Serialize)]
struct AuditLogPredicate<'a> {
    hash_algorithm: &'a str,
    event_count: u64,
    chain_head: &'a ContentHash,
    merkle_root: &'a ContentHash,
}

impl<'a> AuditLogPredicate<'a> {
    fn from_summary(summary: &'a AuditIntegritySummary) -> Self {
        Self {
            hash_algorithm: &summary.hash_algorithm,
            event_count: summary.event_count,
            chain_head: &summary.chain_head,
            merkle_root: &summary.merkle_root,
        }
    }
}

#[derive(Serialize)]
struct AuditSignerPredicate<'a> {
    kind: &'static str,
    key_id: &'a str,
}

pub(crate) fn prepare_audit_signer(secret_ref: Option<&str>) -> Result<Option<AuditSigner>> {
    let Some(secret_ref) = secret_ref.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };

    let normalized_ref = normalize_signing_secret_ref(secret_ref);
    let pkcs8_b64 = nono::load_secret_by_ref(trust_cmd::TRUST_SERVICE, &normalized_ref)?;
    let pkcs8_bytes =
        Zeroizing::new(trust_cmd::base64_decode(pkcs8_b64.as_str()).map_err(|e| {
            NonoError::TrustSigning {
                path: "<audit-sign-key>".to_string(),
                reason: format!("invalid base64 PKCS#8 signing key: {e}"),
            }
        })?);
    let key_pair = trust_cmd::reconstruct_key_pair(&pkcs8_bytes)?;
    let key_id = trust::key_id_hex(&key_pair)?;
    let public_key = trust::export_public_key(&key_pair)?;
    let public_key_b64 = trust::base64::base64_encode(public_key.as_bytes());

    Ok(Some(AuditSigner {
        key_pair,
        key_id,
        public_key_b64,
    }))
}

pub(crate) fn write_audit_attestation(
    session_dir: &Path,
    metadata: &SessionMetadata,
    signer: &AuditSigner,
    mediation_integrity: Option<&AuditIntegritySummary>,
) -> Result<AuditAttestationSummary> {
    let integrity = metadata
        .audit_integrity
        .as_ref()
        .ok_or_else(|| NonoError::TrustSigning {
            path: session_dir.display().to_string(),
            reason: "audit attestation requires audit integrity to be enabled".to_string(),
        })?;

    let predicate = serde_json::to_value(AuditAttestationPredicate {
        version: 1,
        session_id: &metadata.session_id,
        started: &metadata.started,
        ended: &metadata.ended,
        command: &metadata.command,
        audit_log: AuditLogPredicate::from_summary(integrity),
        mediation_log: mediation_integrity.map(AuditLogPredicate::from_summary),
        signer: AuditSignerPredicate {
            kind: "keyed",
            key_id: &signer.key_id,
        },
    })
    .map_err(|e| NonoError::TrustSigning {
        path: session_dir.display().to_string(),
        reason: format!("failed to serialize audit attestation predicate: {e}"),
    })?;

    let statement = build_audit_statement(
        &metadata.session_id,
        &integrity.merkle_root,
        mediation_integrity.map(|m| &m.merkle_root),
        predicate,
    );
    let bundle_json = trust::sign_statement_bundle(&statement, &signer.key_pair)?;
    let bundle_path = session_dir.join(AUDIT_ATTESTATION_BUNDLE_FILENAME);
    fs::write(&bundle_path, bundle_json).map_err(|e| NonoError::TrustSigning {
        path: bundle_path.display().to_string(),
        reason: format!("failed to write audit attestation bundle: {e}"),
    })?;

    Ok(AuditAttestationSummary {
        predicate_type: AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA.to_string(),
        key_id: signer.key_id.clone(),
        public_key: signer.public_key_b64.clone(),
        bundle_filename: AUDIT_ATTESTATION_BUNDLE_FILENAME.to_string(),
    })
}

/// Build an in-toto statement for the audit attestation bundle.
///
/// When `mediation_root` is `None`, the statement has a single `audit-session`
/// subject and is byte-identical to the form produced by `trust::new_statement`.
/// When `mediation_root` is `Some`, a second `mediation-log` subject is added.
fn build_audit_statement(
    session_id: &str,
    audit_root: &ContentHash,
    mediation_root: Option<&ContentHash>,
    predicate: serde_json::Value,
) -> trust::InTotoStatement {
    if mediation_root.is_none() {
        return trust::new_statement(
            &format!("{AUDIT_SUBJECT_NAME_PREFIX}{session_id}"),
            &audit_root.to_string(),
            predicate,
            AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA,
        );
    }

    let mut subjects = Vec::with_capacity(2);
    subjects.push(new_subject(
        &format!("{AUDIT_SUBJECT_NAME_PREFIX}{session_id}"),
        &audit_root.to_string(),
    ));
    if let Some(mediation) = mediation_root {
        subjects.push(new_subject(
            &format!("{MEDIATION_SUBJECT_NAME_PREFIX}{session_id}"),
            &mediation.to_string(),
        ));
    }
    trust::InTotoStatement {
        statement_type: trust::IN_TOTO_STATEMENT_TYPE.to_string(),
        subject: subjects,
        predicate_type: AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA.to_string(),
        predicate,
    }
}

fn new_subject(name: &str, sha256_digest: &str) -> trust::InTotoSubject {
    let mut digest = HashMap::new();
    digest.insert("sha256".to_string(), sha256_digest.to_string());
    trust::InTotoSubject {
        name: name.to_string(),
        digest,
    }
}

pub(crate) fn verify_audit_attestation(
    session_dir: &Path,
    metadata: &SessionMetadata,
    expected_public_key_file: Option<&Path>,
    mediation_integrity: Option<&AuditIntegritySummary>,
) -> Result<AuditAttestationVerificationResult> {
    let Some(summary) = metadata.audit_attestation.as_ref() else {
        return Ok(AuditAttestationVerificationResult {
            present: false,
            predicate_type: None,
            key_id: None,
            key_id_matches: false,
            signature_verified: false,
            merkle_root_matches: false,
            session_id_matches: false,
            expected_public_key_matches: expected_public_key_file.map(|_| false),
            mediation_merkle_root_matches: mediation_integrity.map(|_| false),
            verification_error: expected_public_key_file.map(|public_key_file| {
                format!(
                    "session has no audit attestation to verify against provided public key {}",
                    public_key_file.display()
                )
            }),
        });
    };

    let Some(integrity) = metadata.audit_integrity.as_ref() else {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            "session has audit attestation metadata but no audit integrity summary".to_string(),
        ));
    };
    let bundle_path = session_dir.join(&summary.bundle_filename);
    let bundle = match trust::load_bundle(&bundle_path) {
        Ok(bundle) => bundle,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                mediation_integrity.map(|_| false),
                err.to_string(),
            ))
        }
    };
    let predicate_type = match trust::extract_predicate_type(&bundle, &bundle_path) {
        Ok(predicate_type) => predicate_type,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                mediation_integrity.map(|_| false),
                err.to_string(),
            ))
        }
    };
    if predicate_type != AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            format!(
                "wrong bundle type: expected {}, got {}",
                AUDIT_ATTESTATION_PREDICATE_TYPE_ALPHA, predicate_type
            ),
        ));
    }

    let signer_identity = match trust::extract_signer_identity(&bundle, &bundle_path) {
        Ok(identity) => identity,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                mediation_integrity.map(|_| false),
                err.to_string(),
            ))
        }
    };
    let signer_key_id = match signer_identity {
        trust::SignerIdentity::Keyed { key_id } => key_id,
        trust::SignerIdentity::Keyless { .. } => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                mediation_integrity.map(|_| false),
                "audit attestation must be keyed".to_string(),
            ))
        }
    };
    let public_key_der = match trust::base64::base64_decode(&summary.public_key) {
        Ok(public_key_der) => public_key_der,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                mediation_integrity.map(|_| false),
                format!("invalid attested public key encoding: {err}"),
            ))
        }
    };
    let recomputed_key_id = trust::public_key_id_hex(&public_key_der);
    if recomputed_key_id != summary.key_id {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            format!(
                "audit attestation metadata key mismatch: expected {}, got {}",
                summary.key_id, recomputed_key_id
            ),
        ));
    }
    if signer_key_id != summary.key_id {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            format!(
                "audit attestation signer key mismatch: expected {}, got {}",
                summary.key_id, signer_key_id
            ),
        ));
    }
    if let Some(public_key_file) = expected_public_key_file {
        let expected_public_key = load_public_key_file(public_key_file)?;
        if expected_public_key != public_key_der {
            return Ok(attestation_failure(
                summary,
                Some(false),
                mediation_integrity.map(|_| false),
                "provided public key does not match the attested signer key".to_string(),
            ));
        }
    }
    if let Err(err) = trust::verify_keyed_signature(&bundle, &public_key_der, &bundle_path) {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            err.to_string(),
        ));
    }

    let attested_root = match trust::extract_bundle_digest(&bundle, &bundle_path) {
        Ok(attested_root) => attested_root,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                mediation_integrity.map(|_| false),
                err.to_string(),
            ))
        }
    };
    if attested_root != integrity.merkle_root.to_string() {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            "audit attestation Merkle root does not match session integrity summary".to_string(),
        ));
    }

    let statement = match extract_statement(&bundle) {
        Ok(statement) => statement,
        Err(err) => {
            return Ok(attestation_failure(
                summary,
                expected_public_key_file.map(|_| true),
                mediation_integrity.map(|_| false),
                err.to_string(),
            ))
        }
    };
    let Some(statement_session_id) = statement
        .predicate
        .get("session_id")
        .and_then(|value| value.as_str())
    else {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            "audit attestation predicate missing session_id".to_string(),
        ));
    };
    if statement_session_id != metadata.session_id {
        return Ok(attestation_failure(
            summary,
            expected_public_key_file.map(|_| true),
            mediation_integrity.map(|_| false),
            format!(
                "audit attestation session_id mismatch: expected {}, got {}",
                metadata.session_id, statement_session_id
            ),
        ));
    }

    // Optional second subject: mediation-log. Only verified when the caller
    // supplies a mediation integrity summary. The check pulls the sha256
    // digest from subject[1] and compares to the supplied Merkle root.
    let mediation_merkle_root_matches = match mediation_integrity {
        None => None,
        Some(mediation) => {
            let expected_name = format!("{MEDIATION_SUBJECT_NAME_PREFIX}{}", metadata.session_id);
            let expected_root = mediation.merkle_root.to_string();
            match verify_mediation_subject(&statement, &expected_name, &expected_root) {
                Ok(()) => Some(true),
                Err(err) => {
                    return Ok(attestation_failure(
                        summary,
                        expected_public_key_file.map(|_| true),
                        Some(false),
                        err,
                    ));
                }
            }
        }
    };

    Ok(AuditAttestationVerificationResult {
        present: true,
        predicate_type: Some(predicate_type),
        key_id: Some(summary.key_id.clone()),
        key_id_matches: true,
        signature_verified: true,
        merkle_root_matches: true,
        session_id_matches: true,
        expected_public_key_matches: expected_public_key_file.map(|_| true),
        mediation_merkle_root_matches,
        verification_error: None,
    })
}

/// Look up subject[1] (or any subject whose name matches) and verify its
/// sha256 digest matches `expected_root`.
fn verify_mediation_subject(
    statement: &trust::InTotoStatement,
    expected_name: &str,
    expected_root: &str,
) -> std::result::Result<(), String> {
    let subject = statement
        .subject
        .iter()
        .find(|s| s.name == expected_name)
        .ok_or_else(|| format!("audit attestation missing mediation subject '{expected_name}'"))?;
    let digest = subject.digest.get("sha256").ok_or_else(|| {
        format!("audit attestation mediation subject '{expected_name}' has no sha256 digest")
    })?;
    if digest != expected_root {
        return Err(format!(
            "audit attestation mediation Merkle root mismatch: expected {expected_root}, got {digest}"
        ));
    }
    Ok(())
}

fn attestation_failure(
    summary: &AuditAttestationSummary,
    expected_public_key_matches: Option<bool>,
    mediation_merkle_root_matches: Option<bool>,
    verification_error: String,
) -> AuditAttestationVerificationResult {
    AuditAttestationVerificationResult {
        present: true,
        predicate_type: Some(summary.predicate_type.clone()),
        key_id: Some(summary.key_id.clone()),
        key_id_matches: false,
        signature_verified: false,
        merkle_root_matches: false,
        session_id_matches: false,
        expected_public_key_matches,
        mediation_merkle_root_matches,
        verification_error: Some(verification_error),
    }
}

fn normalize_signing_secret_ref(secret_ref: &str) -> String {
    secret_ref
        .strip_prefix(KEYSTORE_URI_PREFIX)
        .unwrap_or(secret_ref)
        .to_string()
}

fn extract_statement(bundle: &trust::Bundle) -> Result<trust::InTotoStatement> {
    let bundle_json = bundle.to_json().map_err(|e| NonoError::TrustVerification {
        path: String::new(),
        reason: format!("failed to serialize audit attestation bundle: {e}"),
    })?;
    let bundle_value: serde_json::Value =
        serde_json::from_str(&bundle_json).map_err(|e| NonoError::TrustVerification {
            path: String::new(),
            reason: format!("invalid audit attestation bundle JSON: {e}"),
        })?;
    let envelope_value =
        bundle_value
            .get("dsseEnvelope")
            .ok_or_else(|| NonoError::TrustVerification {
                path: String::new(),
                reason: "audit attestation bundle missing dsseEnvelope".to_string(),
            })?;
    let envelope: trust::DsseEnvelope =
        serde_json::from_value(envelope_value.clone()).map_err(|e| {
            NonoError::TrustVerification {
                path: String::new(),
                reason: format!("invalid audit attestation DSSE envelope: {e}"),
            }
        })?;
    envelope.extract_statement()
}

fn load_public_key_file(path: &Path) -> Result<Vec<u8>> {
    let contents = fs::read_to_string(path).map_err(|e| NonoError::TrustVerification {
        path: path.display().to_string(),
        reason: format!("failed to read public key file: {e}"),
    })?;
    let trimmed = contents.trim();
    if trimmed.starts_with("-----BEGIN PUBLIC KEY-----") {
        let base64_body: String = trimmed
            .lines()
            .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
            .collect();
        trust::base64::base64_decode(&base64_body).map_err(|e| NonoError::TrustVerification {
            path: path.display().to_string(),
            reason: format!("invalid PEM public key: {e}"),
        })
    } else {
        trust::base64::base64_decode(trimmed).map_err(|e| NonoError::TrustVerification {
            path: path.display().to_string(),
            reason: format!("invalid base64 DER public key: {e}"),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use nono::undo::AuditIntegritySummary;
    use std::path::PathBuf;

    const TEST_SIGNING_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgskOkyJkTwlMZkm/L
eEleLY6bARaHFnqauYJqxNoJWvihRANCAASt6g2Zt0STlgF+wZ64JzdDRlpPeNr1
h56ZLEEqHfVWFhJWIKRSabtxYPV/VJyMv+lo3L0QwSKsouHs3dtF1zVQ
-----END PRIVATE KEY-----";

    fn sample_metadata() -> SessionMetadata {
        SessionMetadata {
            session_id: "sess-1".to_string(),
            started: "2026-04-22T12:00:00Z".to_string(),
            ended: Some("2026-04-22T12:00:01Z".to_string()),
            command: vec!["/bin/pwd".to_string()],
            executable_identity: None,
            tracked_paths: vec![PathBuf::from("/tmp/project")],
            snapshot_count: 0,
            exit_code: Some(0),
            merkle_roots: Vec::new(),
            network_events: Vec::new(),
            audit_event_count: 2,
            audit_integrity: Some(AuditIntegritySummary {
                hash_algorithm: "sha256".to_string(),
                event_count: 2,
                chain_head: ContentHash::from_bytes([0x11; 32]),
                merkle_root: ContentHash::from_bytes([0x22; 32]),
            }),
            mediation_integrity: None,
            audit_attestation: None,
        }
    }

    #[test]
    fn audit_attestation_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        let summary = write_audit_attestation(dir.path(), &metadata, &signer, None).unwrap();
        metadata.audit_attestation = Some(summary);

        let verified = verify_audit_attestation(dir.path(), &metadata, None, None).unwrap();
        assert!(verified.present);
        assert!(verified.key_id_matches);
        assert!(verified.signature_verified);
        assert!(verified.merkle_root_matches);
        assert!(verified.session_id_matches);
        assert_eq!(verified.expected_public_key_matches, None);
        assert!(verified.verification_error.is_none());
    }

    #[test]
    fn audit_attestation_file_uri_signer_loads() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("audit-signing-key.pk8.b64");
        let pkcs8_b64: String = TEST_SIGNING_KEY_PEM
            .lines()
            .filter(|line| !line.starts_with("-----BEGIN") && !line.starts_with("-----END"))
            .collect();
        fs::write(&key_file, pkcs8_b64).unwrap();

        let signer = prepare_audit_signer(Some(&format!("file://{}", key_file.display()))).unwrap();
        assert!(signer.is_some());
    }

    fn sample_mediation_integrity() -> AuditIntegritySummary {
        AuditIntegritySummary {
            hash_algorithm: "sha256".to_string(),
            event_count: 3,
            chain_head: ContentHash::from_bytes([0x33; 32]),
            merkle_root: ContentHash::from_bytes([0x44; 32]),
        }
    }

    #[test]
    fn audit_attestation_with_mediation_subject_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        let mediation = sample_mediation_integrity();

        let summary =
            write_audit_attestation(dir.path(), &metadata, &signer, Some(&mediation)).unwrap();
        metadata.audit_attestation = Some(summary);

        let verified =
            verify_audit_attestation(dir.path(), &metadata, None, Some(&mediation)).unwrap();
        assert!(verified.signature_verified);
        assert_eq!(verified.mediation_merkle_root_matches, Some(true));
        assert!(verified.verification_error.is_none());
    }

    #[test]
    fn audit_attestation_mediation_mismatch_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        let mediation = sample_mediation_integrity();
        let summary =
            write_audit_attestation(dir.path(), &metadata, &signer, Some(&mediation)).unwrap();
        metadata.audit_attestation = Some(summary);

        let mut tampered = mediation.clone();
        tampered.merkle_root = ContentHash::from_bytes([0x55; 32]);
        let verified =
            verify_audit_attestation(dir.path(), &metadata, None, Some(&tampered)).unwrap();
        assert_eq!(verified.mediation_merkle_root_matches, Some(false));
        assert!(verified.verification_error.is_some());
    }

    #[test]
    fn audit_attestation_without_mediation_is_byte_compatible_with_alpha() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let metadata = sample_metadata();

        write_audit_attestation(dir.path(), &metadata, &signer, None).unwrap();
        let bundle_path = dir.path().join(AUDIT_ATTESTATION_BUNDLE_FILENAME);
        let bundle_json = fs::read_to_string(&bundle_path).unwrap();
        // Bundle must NOT contain mediation-log field when no mediation integrity passed.
        assert!(!bundle_json.contains("mediation_log"));
        assert!(!bundle_json.contains("mediation-log:"));
    }

    #[test]
    fn audit_attestation_mismatch_is_reported_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let key_pair = trust::generate_signing_key().unwrap();
        let key_id = trust::key_id_hex(&key_pair).unwrap();
        let public_key = trust::export_public_key(&key_pair).unwrap();
        let signer = AuditSigner {
            key_pair,
            key_id,
            public_key_b64: trust::base64::base64_encode(public_key.as_bytes()),
        };
        let mut metadata = sample_metadata();
        let summary = write_audit_attestation(dir.path(), &metadata, &signer, None).unwrap();
        metadata.audit_attestation = Some(summary);
        metadata.session_id = "tampered-session".to_string();

        let verified = verify_audit_attestation(dir.path(), &metadata, None, None).unwrap();
        assert!(verified.present);
        assert!(!verified.signature_verified);
        assert!(verified.verification_error.is_some());
    }
}
