//! Skill manifest and verification for marketplace plugin integrity
//!
//! Provides types and verification logic for signed plugin directories.
//! A skill is a directory containing a `skill-manifest.json` that declares
//! all files, entry points, and hooks. The entire directory is signed as
//! a unit using a multi-subject in-toto attestation with a skill-specific
//! predicate type.
//!
//! # Verification Pipeline
//!
//! ```text
//! skill dir --> load manifest --> load bundle --> validate predicate type
//!   --> for each file: SHA-256 check --> directory walk: reject extra files
//!   --> signer identity extraction --> blocklist check --> publisher match
//!   --> cryptographic verification --> allow/deny
//! ```
//!
//! # Security Properties
//!
//! - **No TOFU**: skills must have valid signatures from trusted publishers
//! - **Predicate isolation**: skill bundles use `NONO_SKILL_PREDICATE_TYPE`
//! - **Directory completeness**: extra files on disk = rejection
//! - **Entry point containment**: paths must resolve within the skill directory
//! - **Symlink rejection**: symlinks pointing outside the skill directory are rejected

use crate::error::{NonoError, Result};
use crate::trust::types::{SignerIdentity, TrustPolicy, VerificationOutcome};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// The predicate type for nono skill attestations.
///
/// Distinct from instruction file and multi-file predicate types to prevent
/// cross-use of bundles between different attestation contexts.
pub const NONO_SKILL_PREDICATE_TYPE: &str = "https://nono.sh/attestation/skill/v1";

/// The expected filename for skill manifests within a plugin directory.
pub const SKILL_MANIFEST_FILENAME: &str = "skill-manifest.json";

/// The expected filename for skill signature bundles within a plugin directory.
pub const SKILL_BUNDLE_FILENAME: &str = ".nono-skill.bundle";

/// Maximum number of files allowed in a skill manifest.
const MAX_SKILL_FILES: usize = 10_000;

/// Maximum recursion depth for directory walking.
const MAX_WALK_DEPTH: u32 = 32;

/// Manifest declaring the contents of a signed skill/plugin directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    /// Human-readable skill name
    pub name: String,
    /// Semantic version (e.g., "1.2.3")
    pub version: String,
    /// Publisher name, must match a trust policy publisher name
    pub publisher: String,
    /// Relative paths of ALL files in the plugin (excluding the bundle itself)
    pub files: Vec<String>,
    /// Declared entry points (commands, agents, skills)
    #[serde(default)]
    pub entry_points: Vec<SkillEntryPoint>,
    /// Declared lifecycle hook scripts
    #[serde(default)]
    pub hooks: Vec<SkillHook>,
}

/// A named entry point within a skill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillEntryPoint {
    /// Entry point name
    pub name: String,
    /// Relative path to the command file (e.g., "commands/deploy.md")
    pub command: String,
}

/// A lifecycle hook declared by a skill.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillHook {
    /// Event name (e.g., "SessionStart", "PreToolUse")
    pub event: String,
    /// Relative path to the hook script
    pub command: String,
}

/// Result of verifying a skill directory.
#[derive(Debug, Clone)]
pub struct SkillVerificationResult {
    /// Skill name from manifest
    pub name: String,
    /// Skill version from manifest
    pub version: String,
    /// Verification outcome
    pub outcome: VerificationOutcome,
    /// The loaded manifest (available on success for capability extraction)
    pub manifest: Option<SkillManifest>,
}

/// Load and validate a skill manifest from a directory.
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` if the manifest is missing,
/// malformed, or structurally invalid.
pub fn load_skill_manifest(dir: &Path) -> Result<SkillManifest> {
    let manifest_path = dir.join(SKILL_MANIFEST_FILENAME);
    let content =
        std::fs::read_to_string(&manifest_path).map_err(|e| NonoError::TrustVerification {
            path: manifest_path.display().to_string(),
            reason: format!("failed to read skill manifest: {e}"),
        })?;

    let manifest: SkillManifest =
        serde_json::from_str(&content).map_err(|e| NonoError::TrustVerification {
            path: manifest_path.display().to_string(),
            reason: format!("invalid skill manifest: {e}"),
        })?;

    validate_manifest(&manifest, dir)?;
    Ok(manifest)
}

/// Validate structural integrity of a skill manifest.
fn validate_manifest(manifest: &SkillManifest, dir: &Path) -> Result<()> {
    if manifest.name.is_empty() {
        return Err(NonoError::TrustVerification {
            path: dir.display().to_string(),
            reason: "skill manifest has empty name".to_string(),
        });
    }
    if manifest.version.is_empty() {
        return Err(NonoError::TrustVerification {
            path: dir.display().to_string(),
            reason: "skill manifest has empty version".to_string(),
        });
    }
    if manifest.publisher.is_empty() {
        return Err(NonoError::TrustVerification {
            path: dir.display().to_string(),
            reason: "skill manifest has empty publisher".to_string(),
        });
    }
    if manifest.files.is_empty() {
        return Err(NonoError::TrustVerification {
            path: dir.display().to_string(),
            reason: "skill manifest has no files".to_string(),
        });
    }
    if manifest.files.len() > MAX_SKILL_FILES {
        return Err(NonoError::TrustVerification {
            path: dir.display().to_string(),
            reason: format!(
                "skill manifest has {} files (max {})",
                manifest.files.len(),
                MAX_SKILL_FILES
            ),
        });
    }

    // The manifest itself must be listed in the files array
    if !manifest
        .files
        .contains(&SKILL_MANIFEST_FILENAME.to_string())
    {
        return Err(NonoError::TrustVerification {
            path: dir.display().to_string(),
            reason: format!(
                "skill manifest must list itself ({SKILL_MANIFEST_FILENAME}) in files array"
            ),
        });
    }

    // Validate all paths are relative and don't escape the directory
    for file_path in &manifest.files {
        validate_relative_path(file_path, dir)?;
    }
    for ep in &manifest.entry_points {
        validate_relative_path(&ep.command, dir)?;
    }
    for hook in &manifest.hooks {
        validate_relative_path(&hook.command, dir)?;
    }

    Ok(())
}

/// Validate that a path is relative and does not escape the skill directory.
///
/// Rejects absolute paths, `..` components, and symlinks that resolve outside
/// the skill directory.
fn validate_relative_path(rel_path: &str, dir: &Path) -> Result<()> {
    let path = Path::new(rel_path);

    // Reject absolute paths
    if path.is_absolute() {
        return Err(NonoError::TrustVerification {
            path: dir.display().to_string(),
            reason: format!("skill manifest contains absolute path: {rel_path}"),
        });
    }

    // Reject paths with .. components
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(NonoError::TrustVerification {
                path: dir.display().to_string(),
                reason: format!("skill manifest contains path with '..' component: {rel_path}"),
            });
        }
    }

    // If the file exists on disk, verify symlinks don't escape
    let full_path = dir.join(rel_path);
    if full_path.exists() {
        let canonical =
            std::fs::canonicalize(&full_path).map_err(|e| NonoError::TrustVerification {
                path: full_path.display().to_string(),
                reason: format!("failed to canonicalize: {e}"),
            })?;
        let canonical_dir =
            std::fs::canonicalize(dir).map_err(|e| NonoError::TrustVerification {
                path: dir.display().to_string(),
                reason: format!("failed to canonicalize skill dir: {e}"),
            })?;
        if !canonical.starts_with(&canonical_dir) {
            return Err(NonoError::TrustVerification {
                path: full_path.display().to_string(),
                reason: format!(
                    "symlink escape: {} resolves to {} which is outside {}",
                    rel_path,
                    canonical.display(),
                    canonical_dir.display()
                ),
            });
        }
    }

    Ok(())
}

/// Verify a skill directory against the trust policy.
///
/// Performs the full verification pipeline:
/// 1. Load skill manifest
/// 2. Load skill bundle
/// 3. Validate predicate type
/// 4. Verify each file's SHA-256 against bundle subjects
/// 5. Walk directory to detect extra files (tampering)
/// 6. Extract signer identity, check blocklist, match publishers
/// 7. Cryptographic signature verification
///
/// # Errors
///
/// Returns `NonoError::TrustVerification` on any verification failure.
pub fn verify_skill(policy: &TrustPolicy, skill_dir: &Path) -> Result<SkillVerificationResult> {
    // Step 1: Load manifest
    let manifest = load_skill_manifest(skill_dir)?;

    // Step 2: Load bundle
    let bundle_path = skill_dir.join(SKILL_BUNDLE_FILENAME);
    let bundle = crate::trust::bundle::load_bundle(&bundle_path).map_err(|e| {
        NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: format!("failed to load skill bundle: {e}"),
        }
    })?;

    // Step 3: Validate predicate type
    let predicate_type = crate::trust::bundle::extract_predicate_type(&bundle, &bundle_path)
        .map_err(|e| NonoError::TrustVerification {
            path: bundle_path.display().to_string(),
            reason: format!("failed to extract predicate type: {e}"),
        })?;
    if predicate_type != NONO_SKILL_PREDICATE_TYPE {
        return Ok(SkillVerificationResult {
            name: manifest.name,
            version: manifest.version,
            outcome: VerificationOutcome::InvalidSignature {
                detail: format!(
                    "wrong predicate type: expected {NONO_SKILL_PREDICATE_TYPE}, got {predicate_type}"
                ),
            },
            manifest: None,
        });
    }

    // Step 4: Extract subjects from bundle and verify each file's digest
    let subjects =
        crate::trust::bundle::extract_all_subjects(&bundle, &bundle_path).map_err(|e| {
            NonoError::TrustVerification {
                path: bundle_path.display().to_string(),
                reason: format!("failed to extract subjects: {e}"),
            }
        })?;

    let subject_map: std::collections::HashMap<&str, &str> = subjects
        .iter()
        .map(|(name, digest)| (name.as_str(), digest.as_str()))
        .collect();

    for file_rel in &manifest.files {
        let file_path = skill_dir.join(file_rel);
        let actual_digest = crate::trust::digest::file_digest(&file_path).map_err(|e| {
            NonoError::TrustVerification {
                path: file_path.display().to_string(),
                reason: format!("failed to compute digest: {e}"),
            }
        })?;

        match subject_map.get(file_rel.as_str()) {
            Some(expected_digest) => {
                if actual_digest != *expected_digest {
                    return Ok(SkillVerificationResult {
                        name: manifest.name,
                        version: manifest.version,
                        outcome: VerificationOutcome::DigestMismatch {
                            expected: expected_digest.to_string(),
                            actual: actual_digest,
                        },
                        manifest: None,
                    });
                }
            }
            None => {
                return Ok(SkillVerificationResult {
                    name: manifest.name,
                    version: manifest.version,
                    outcome: VerificationOutcome::InvalidSignature {
                        detail: format!(
                            "file '{file_rel}' listed in manifest but not in bundle subjects"
                        ),
                    },
                    manifest: None,
                });
            }
        }
    }

    // Step 5: Walk directory to detect extra files not in manifest
    let manifest_files: HashSet<&str> = manifest.files.iter().map(String::as_str).collect();
    let disk_files = walk_skill_directory(skill_dir)?;

    for disk_file in &disk_files {
        if !manifest_files.contains(disk_file.as_str()) {
            return Ok(SkillVerificationResult {
                name: manifest.name,
                version: manifest.version,
                outcome: VerificationOutcome::InvalidSignature {
                    detail: format!(
                        "extra file on disk not in manifest: '{disk_file}' (possible tampering)"
                    ),
                },
                manifest: None,
            });
        }
    }

    // Step 6: Extract signer identity
    let identity =
        crate::trust::bundle::extract_signer_identity(&bundle, &bundle_path).map_err(|e| {
            NonoError::TrustVerification {
                path: bundle_path.display().to_string(),
                reason: format!("no signer identity: {e}"),
            }
        })?;

    // Check blocklist (by manifest digest — use the manifest file's digest)
    let manifest_path = skill_dir.join(SKILL_MANIFEST_FILENAME);
    let manifest_digest = crate::trust::digest::file_digest(&manifest_path).map_err(|e| {
        NonoError::TrustVerification {
            path: manifest_path.display().to_string(),
            reason: format!("failed to compute manifest digest: {e}"),
        }
    })?;
    if let Some(entry) = policy.check_blocklist(&manifest_digest) {
        return Ok(SkillVerificationResult {
            name: manifest.name,
            version: manifest.version,
            outcome: VerificationOutcome::Blocked {
                reason: entry.description.clone(),
            },
            manifest: None,
        });
    }

    // Publisher matching
    let matching = policy.matching_publishers(&identity);
    if matching.is_empty() {
        return Ok(SkillVerificationResult {
            name: manifest.name,
            version: manifest.version,
            outcome: VerificationOutcome::UntrustedPublisher {
                identity: identity.clone(),
            },
            manifest: None,
        });
    }

    // Step 7: Cryptographic verification
    match &identity {
        SignerIdentity::Keyed { .. } => match matching.iter().find_map(|p| p.public_key.as_ref()) {
            Some(b64) => {
                let key_bytes = crate::trust::base64::base64_decode(b64).map_err(|_| {
                    NonoError::TrustVerification {
                        path: bundle_path.display().to_string(),
                        reason: "invalid base64 in publisher public_key".to_string(),
                    }
                })?;
                crate::trust::bundle::verify_keyed_signature(&bundle, &key_bytes, &bundle_path)
                    .map_err(|e| NonoError::TrustVerification {
                        path: bundle_path.display().to_string(),
                        reason: format!("signature verification failed: {e}"),
                    })?;
            }
            None => {
                return Ok(SkillVerificationResult {
                    name: manifest.name,
                    version: manifest.version,
                    outcome: VerificationOutcome::InvalidSignature {
                        detail: "keyed bundle but no public_key in matching publisher".to_string(),
                    },
                    manifest: None,
                });
            }
        },
        SignerIdentity::Keyless { .. } => {
            // Use the first subject's digest for Sigstore verification
            let first_digest = subjects.first().map(|(_, d)| d.as_str()).ok_or_else(|| {
                NonoError::TrustVerification {
                    path: bundle_path.display().to_string(),
                    reason: "no subjects in bundle".to_string(),
                }
            })?;
            let trusted_root =
                crate::trust::bundle::load_production_trusted_root().map_err(|e| {
                    NonoError::TrustVerification {
                        path: bundle_path.display().to_string(),
                        reason: format!("failed to load Sigstore trusted root: {e}"),
                    }
                })?;
            let sigstore_policy = crate::trust::bundle::VerificationPolicy::default();
            crate::trust::bundle::verify_bundle_with_digest(
                first_digest,
                &bundle,
                &trusted_root,
                &sigstore_policy,
                &bundle_path,
            )
            .map_err(|e| NonoError::TrustVerification {
                path: bundle_path.display().to_string(),
                reason: format!("Sigstore verification failed: {e}"),
            })?;
        }
    }

    Ok(SkillVerificationResult {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        outcome: VerificationOutcome::Verified {
            publisher: matching[0].name.clone(),
        },
        manifest: Some(manifest),
    })
}

/// Walk a skill directory and return all relative file paths.
///
/// Excludes the bundle file itself. Returns paths relative to the skill root.
fn walk_skill_directory(dir: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    walk_recursive(dir, dir, &mut files, 0)?;
    Ok(files)
}

fn walk_recursive(root: &Path, current: &Path, files: &mut Vec<String>, depth: u32) -> Result<()> {
    if depth > MAX_WALK_DEPTH {
        return Err(NonoError::TrustVerification {
            path: current.display().to_string(),
            reason: "skill directory exceeds maximum depth".to_string(),
        });
    }

    let entries = std::fs::read_dir(current).map_err(|e| NonoError::TrustVerification {
        path: current.display().to_string(),
        reason: format!("failed to read directory: {e}"),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| NonoError::TrustVerification {
            path: current.display().to_string(),
            reason: format!("directory entry error: {e}"),
        })?;
        let path = entry.path();
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => continue, // dangling symlink
        };

        if meta.is_dir() {
            walk_recursive(root, &path, files, depth.saturating_add(1))?;
        } else if meta.is_file() {
            if let Ok(relative) = path.strip_prefix(root) {
                let rel_str = relative.to_string_lossy().to_string();
                // Skip the bundle file itself
                if rel_str != SKILL_BUNDLE_FILENAME {
                    files.push(rel_str);
                }
            }
        }
    }

    Ok(())
}

/// Find directories containing a skill manifest under the given roots.
///
/// Searches one level deep under each root for directories containing
/// `skill-manifest.json`.
pub fn find_skill_directories(roots: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        let entries = std::fs::read_dir(root).map_err(NonoError::Io)?;
        for entry in entries {
            let entry = entry.map_err(NonoError::Io)?;
            let path = entry.path();
            if path.is_dir() {
                let manifest = path.join(SKILL_MANIFEST_FILENAME);
                if manifest.exists() {
                    result.push(path);
                }
            }
        }
    }
    Ok(result)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;

    fn create_test_skill(dir: &Path) -> SkillManifest {
        let manifest = SkillManifest {
            name: "test-skill".to_string(),
            version: "1.0.0".to_string(),
            publisher: "test-publisher".to_string(),
            files: vec![
                SKILL_MANIFEST_FILENAME.to_string(),
                "commands/deploy.md".to_string(),
                "scripts/hook.sh".to_string(),
            ],
            entry_points: vec![SkillEntryPoint {
                name: "deploy".to_string(),
                command: "commands/deploy.md".to_string(),
            }],
            hooks: vec![SkillHook {
                event: "SessionStart".to_string(),
                command: "scripts/hook.sh".to_string(),
            }],
        };

        fs::create_dir_all(dir.join("commands")).unwrap();
        fs::create_dir_all(dir.join("scripts")).unwrap();
        fs::write(dir.join("commands/deploy.md"), "# Deploy command").unwrap();
        fs::write(dir.join("scripts/hook.sh"), "#!/bin/sh\necho hello").unwrap();

        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        fs::write(dir.join(SKILL_MANIFEST_FILENAME), &manifest_json).unwrap();

        manifest
    }

    // -----------------------------------------------------------------------
    // SkillManifest serde
    // -----------------------------------------------------------------------

    #[test]
    fn manifest_serde_roundtrip() {
        let manifest = SkillManifest {
            name: "my-skill".to_string(),
            version: "2.0.0".to_string(),
            publisher: "pub".to_string(),
            files: vec![SKILL_MANIFEST_FILENAME.to_string(), "a.md".to_string()],
            entry_points: vec![],
            hooks: vec![],
        };
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: SkillManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "my-skill");
        assert_eq!(parsed.version, "2.0.0");
        assert_eq!(parsed.files.len(), 2);
    }

    // -----------------------------------------------------------------------
    // load_skill_manifest
    // -----------------------------------------------------------------------

    #[test]
    fn load_manifest_success() {
        let dir = tempfile::tempdir().unwrap();
        create_test_skill(dir.path());
        let manifest = load_skill_manifest(dir.path()).unwrap();
        assert_eq!(manifest.name, "test-skill");
        assert_eq!(manifest.files.len(), 3);
        assert_eq!(manifest.entry_points.len(), 1);
        assert_eq!(manifest.hooks.len(), 1);
    }

    #[test]
    fn load_manifest_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_skill_manifest(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_manifest_invalid_json() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(SKILL_MANIFEST_FILENAME), "not json").unwrap();
        let result = load_skill_manifest(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn load_manifest_empty_name_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "name": "",
            "version": "1.0.0",
            "publisher": "pub",
            "files": [SKILL_MANIFEST_FILENAME]
        });
        fs::write(
            dir.path().join(SKILL_MANIFEST_FILENAME),
            manifest.to_string(),
        )
        .unwrap();
        let result = load_skill_manifest(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty name"));
    }

    #[test]
    fn load_manifest_empty_files_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "name": "test",
            "version": "1.0.0",
            "publisher": "pub",
            "files": []
        });
        fs::write(
            dir.path().join(SKILL_MANIFEST_FILENAME),
            manifest.to_string(),
        )
        .unwrap();
        let result = load_skill_manifest(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no files"));
    }

    #[test]
    fn load_manifest_must_list_itself() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = serde_json::json!({
            "name": "test",
            "version": "1.0.0",
            "publisher": "pub",
            "files": ["other.md"]
        });
        fs::write(
            dir.path().join(SKILL_MANIFEST_FILENAME),
            manifest.to_string(),
        )
        .unwrap();
        fs::write(dir.path().join("other.md"), "content").unwrap();
        let result = load_skill_manifest(dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must list itself"));
    }

    // -----------------------------------------------------------------------
    // validate_relative_path
    // -----------------------------------------------------------------------

    #[test]
    fn validate_relative_path_rejects_absolute() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_relative_path("/etc/passwd", dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("absolute path"));
    }

    #[test]
    fn validate_relative_path_rejects_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_relative_path("../escape.md", dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'..'"));
    }

    #[test]
    fn validate_relative_path_accepts_valid() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/file.md"), "ok").unwrap();
        assert!(validate_relative_path("sub/file.md", dir.path()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn validate_relative_path_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("secret.md"), "secret").unwrap();
        std::os::unix::fs::symlink(
            target.path().join("secret.md"),
            dir.path().join("escape.md"),
        )
        .unwrap();
        let result = validate_relative_path("escape.md", dir.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("symlink escape"));
    }

    // -----------------------------------------------------------------------
    // walk_skill_directory
    // -----------------------------------------------------------------------

    #[test]
    fn walk_finds_all_files() {
        let dir = tempfile::tempdir().unwrap();
        create_test_skill(dir.path());
        let files = walk_skill_directory(dir.path()).unwrap();
        assert!(files.contains(&SKILL_MANIFEST_FILENAME.to_string()));
        assert!(files.contains(&"commands/deploy.md".to_string()));
        assert!(files.contains(&"scripts/hook.sh".to_string()));
    }

    #[test]
    fn walk_excludes_bundle_file() {
        let dir = tempfile::tempdir().unwrap();
        create_test_skill(dir.path());
        fs::write(dir.path().join(SKILL_BUNDLE_FILENAME), "bundle").unwrap();
        let files = walk_skill_directory(dir.path()).unwrap();
        assert!(!files.contains(&SKILL_BUNDLE_FILENAME.to_string()));
    }

    // -----------------------------------------------------------------------
    // find_skill_directories
    // -----------------------------------------------------------------------

    #[test]
    fn find_skill_directories_discovers_plugins() {
        let root = tempfile::tempdir().unwrap();
        let plugin1 = root.path().join("plugin-a");
        let plugin2 = root.path().join("plugin-b");
        let not_plugin = root.path().join("not-a-plugin");

        fs::create_dir_all(&plugin1).unwrap();
        fs::create_dir_all(&plugin2).unwrap();
        fs::create_dir_all(&not_plugin).unwrap();

        fs::write(plugin1.join(SKILL_MANIFEST_FILENAME), "{}").unwrap();
        fs::write(plugin2.join(SKILL_MANIFEST_FILENAME), "{}").unwrap();
        fs::write(not_plugin.join("README.md"), "not a skill").unwrap();

        let dirs = find_skill_directories(&[root.path().to_path_buf()]).unwrap();
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn find_skill_directories_ignores_missing_roots() {
        let dirs = find_skill_directories(&[PathBuf::from("/nonexistent/path")]).unwrap();
        assert!(dirs.is_empty());
    }

    // -----------------------------------------------------------------------
    // predicate type constant
    // -----------------------------------------------------------------------

    #[test]
    fn skill_predicate_type_is_unique() {
        assert_ne!(
            NONO_SKILL_PREDICATE_TYPE,
            crate::trust::dsse::NONO_PREDICATE_TYPE
        );
        assert_ne!(
            NONO_SKILL_PREDICATE_TYPE,
            crate::trust::dsse::NONO_POLICY_PREDICATE_TYPE
        );
        assert_ne!(
            NONO_SKILL_PREDICATE_TYPE,
            crate::trust::dsse::NONO_MULTI_SUBJECT_PREDICATE_TYPE
        );
    }
}
