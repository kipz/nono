//! Runtime skill verification gate
//!
//! When a file-read or command execution request falls within a known
//! skill/plugin directory, the `SkillInterceptor` checks whether the skill
//! has a valid signature. Unverified skills are denied access.
//!
//! Verification results are cached by skill directory with invalidation
//! on manifest file metadata changes (inode + mtime + size).

use nono::trust::{self, TrustPolicy, VerificationOutcome};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Cached skill verification result.
#[derive(Debug, Clone)]
struct SkillCacheEntry {
    /// Manifest inode at verification time
    inode: u64,
    /// Manifest modification time (nanoseconds since epoch)
    mtime_nanos: u128,
    /// Manifest file size
    size: u64,
    /// Verification outcome
    outcome: CachedSkillOutcome,
}

/// Cached skill verification outcome.
#[derive(Debug, Clone)]
enum CachedSkillOutcome {
    /// Verified successfully
    Verified {
        publisher: String,
        name: String,
        version: String,
    },
    /// Failed verification
    Failed { reason: String },
}

/// Successful skill verification result.
#[derive(Debug, Clone)]
pub struct SkillVerified {
    /// Publisher name that matched the trust policy
    pub publisher: String,
    /// Skill name from manifest
    pub name: String,
    /// Skill version from manifest
    pub version: String,
}

/// Runtime skill verification interceptor.
///
/// Checks whether file paths fall within known skill directories and verifies
/// those skills on first access. Results are cached per-directory.
pub struct SkillInterceptor {
    /// Trust policy for evaluation
    policy: TrustPolicy,
    /// Verification result cache keyed by skill directory
    cache: HashMap<PathBuf, SkillCacheEntry>,
    /// Root directories to search for skills (e.g., `~/.claude/plugins/`)
    skill_roots: Vec<PathBuf>,
    /// Discovered skill directories (populated on first access)
    discovered: Option<Vec<PathBuf>>,
}

impl SkillInterceptor {
    /// Create a new skill interceptor.
    ///
    /// `skill_roots` are the directories under which plugins are installed
    /// (e.g., `~/.claude/plugins/`). Each subdirectory containing a
    /// `skill-manifest.json` is treated as a skill directory.
    #[must_use]
    pub fn new(policy: TrustPolicy, skill_roots: Vec<PathBuf>) -> Self {
        Self {
            policy,
            cache: HashMap::new(),
            skill_roots,
            discovered: None,
        }
    }

    /// Check if a path falls within a skill directory that requires verification.
    ///
    /// Returns `None` if the path is not within any known skill directory.
    /// Returns `Some(Ok(info))` if the skill is verified.
    /// Returns `Some(Err(reason))` if the skill fails verification.
    pub fn check_path(
        &mut self,
        path: &Path,
    ) -> Option<std::result::Result<SkillVerified, String>> {
        let skill_dir = self.find_skill_dir_for_path(path)?;

        // Check cache
        if let Some(cached) = self.check_cache(&skill_dir) {
            return Some(cached);
        }

        // Verify the skill
        let result = self.verify_and_cache(&skill_dir);
        Some(result)
    }

    /// Return the list of verified skill directories.
    ///
    /// Only includes skills that have been checked and verified.
    #[cfg(test)]
    fn verified_skill_dirs(&self) -> Vec<PathBuf> {
        self.cache
            .iter()
            .filter_map(|(dir, entry)| match &entry.outcome {
                CachedSkillOutcome::Verified { .. } => Some(dir.clone()),
                CachedSkillOutcome::Failed { .. } => None,
            })
            .collect()
    }

    /// Return the list of unverified/failed skill directories.
    #[cfg(test)]
    fn unverified_skill_dirs(&self) -> Vec<PathBuf> {
        self.cache
            .iter()
            .filter_map(|(dir, entry)| match &entry.outcome {
                CachedSkillOutcome::Verified { .. } => None,
                CachedSkillOutcome::Failed { .. } => Some(dir.clone()),
            })
            .collect()
    }

    /// Discover skill directories and return them.
    fn ensure_discovered(&mut self) -> &[PathBuf] {
        if self.discovered.is_none() {
            self.discovered =
                Some(trust::find_skill_directories(&self.skill_roots).unwrap_or_default());
        }
        self.discovered.as_deref().unwrap_or(&[])
    }

    /// Find which skill directory (if any) contains the given path.
    fn find_skill_dir_for_path(&mut self, path: &Path) -> Option<PathBuf> {
        // First check cached directories
        for dir in self.cache.keys() {
            if path.starts_with(dir) {
                return Some(dir.clone());
            }
        }

        // Check discovered directories
        let dirs: Vec<PathBuf> = self.ensure_discovered().to_vec();
        for dir in &dirs {
            if path.starts_with(dir) {
                return Some(dir.clone());
            }
        }

        None
    }

    /// Check if a skill directory has a valid cached result.
    fn check_cache(&self, skill_dir: &Path) -> Option<std::result::Result<SkillVerified, String>> {
        let entry = self.cache.get(skill_dir)?;

        // Validate cache by checking manifest metadata
        let manifest_path = skill_dir.join(trust::SKILL_MANIFEST_FILENAME);
        let meta = std::fs::metadata(&manifest_path).ok()?;

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        };
        #[cfg(not(unix))]
        let inode = 0u64;

        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let size = meta.len();

        if entry.inode != inode || entry.mtime_nanos != mtime_nanos || entry.size != size {
            debug!(
                "Skill interceptor: cache invalidated for {}",
                skill_dir.display()
            );
            return None;
        }

        debug!("Skill interceptor: cache hit for {}", skill_dir.display());
        match &entry.outcome {
            CachedSkillOutcome::Verified {
                publisher,
                name,
                version,
            } => Some(Ok(SkillVerified {
                publisher: publisher.clone(),
                name: name.clone(),
                version: version.clone(),
            })),
            CachedSkillOutcome::Failed { reason } => Some(Err(reason.clone())),
        }
    }

    /// Verify a skill and store the result in the cache.
    fn verify_and_cache(&mut self, skill_dir: &Path) -> std::result::Result<SkillVerified, String> {
        match trust::verify_skill(&self.policy, skill_dir) {
            Ok(result) => match &result.outcome {
                VerificationOutcome::Verified { publisher } => {
                    let verified = SkillVerified {
                        publisher: publisher.clone(),
                        name: result.name.clone(),
                        version: result.version.clone(),
                    };
                    self.store_cache(
                        skill_dir,
                        CachedSkillOutcome::Verified {
                            publisher: publisher.clone(),
                            name: result.name,
                            version: result.version,
                        },
                    );
                    debug!(
                        "Skill interceptor: verified {} (publisher: {})",
                        skill_dir.display(),
                        verified.publisher
                    );
                    Ok(verified)
                }
                outcome => {
                    let reason = format_skill_outcome(outcome);
                    self.store_cache(
                        skill_dir,
                        CachedSkillOutcome::Failed {
                            reason: reason.clone(),
                        },
                    );
                    warn!(
                        "Skill interceptor: blocking {} ({})",
                        skill_dir.display(),
                        reason
                    );
                    Err(reason)
                }
            },
            Err(e) => {
                let reason = format!("verification error: {e}");
                self.store_cache(
                    skill_dir,
                    CachedSkillOutcome::Failed {
                        reason: reason.clone(),
                    },
                );
                warn!(
                    "Skill interceptor: error verifying {}: {}",
                    skill_dir.display(),
                    reason
                );
                Err(reason)
            }
        }
    }

    /// Store a verification result in the cache.
    fn store_cache(&mut self, skill_dir: &Path, outcome: CachedSkillOutcome) {
        let manifest_path = skill_dir.join(trust::SKILL_MANIFEST_FILENAME);
        let meta = match std::fs::metadata(&manifest_path) {
            Ok(m) => m,
            Err(_) => return,
        };

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            meta.ino()
        };
        #[cfg(not(unix))]
        let inode = 0u64;

        let mtime_nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let size = meta.len();

        self.cache.insert(
            skill_dir.to_path_buf(),
            SkillCacheEntry {
                inode,
                mtime_nanos,
                size,
                outcome,
            },
        );
    }
}

fn format_skill_outcome(outcome: &VerificationOutcome) -> String {
    match outcome {
        VerificationOutcome::Verified { publisher } => format!("verified ({publisher})"),
        VerificationOutcome::Blocked { reason } => format!("blocklisted: {reason}"),
        VerificationOutcome::Unsigned => "unsigned (no bundle)".to_string(),
        VerificationOutcome::InvalidSignature { detail } => format!("invalid: {detail}"),
        VerificationOutcome::UntrustedPublisher { identity } => {
            format!("untrusted publisher: {identity:?}")
        }
        VerificationOutcome::DigestMismatch { .. } => {
            "file content does not match bundle".to_string()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn interceptor_returns_none_for_non_skill_paths() {
        let dir = tempfile::tempdir().unwrap();
        let policy = TrustPolicy::default();
        let mut interceptor = SkillInterceptor::new(policy, vec![dir.path().to_path_buf()]);

        assert!(interceptor
            .check_path(Path::new("/tmp/random/file.txt"))
            .is_none());
    }

    #[test]
    fn interceptor_detects_skill_directories() {
        let root = tempfile::tempdir().unwrap();
        let plugin_dir = root.path().join("my-plugin");
        std::fs::create_dir_all(&plugin_dir).unwrap();
        std::fs::write(plugin_dir.join(trust::SKILL_MANIFEST_FILENAME), "{}").unwrap();

        let policy = TrustPolicy::default();
        let mut interceptor = SkillInterceptor::new(policy, vec![root.path().to_path_buf()]);

        // A path within the plugin dir should trigger verification
        let result = interceptor.check_path(&plugin_dir.join("commands/deploy.md"));
        // Should return Some (it is within a skill dir), but will fail
        // verification because the manifest is invalid
        assert!(result.is_some());
        assert!(result.unwrap().is_err());
    }

    #[test]
    fn verified_and_unverified_dirs_tracking() {
        let interceptor = SkillInterceptor::new(TrustPolicy::default(), vec![]);
        assert!(interceptor.verified_skill_dirs().is_empty());
        assert!(interceptor.unverified_skill_dirs().is_empty());
    }

    #[test]
    fn format_outcome_variants() {
        assert!(format_skill_outcome(&VerificationOutcome::Unsigned).contains("unsigned"));
        assert!(format_skill_outcome(&VerificationOutcome::Blocked {
            reason: "evil".to_string()
        })
        .contains("blocklisted"));
    }
}
