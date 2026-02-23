//! Shared types and helpers for learn mode (platform-agnostic)

use crate::config;
use crate::profile::Profile;
use nono::Result;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

/// Represents a file access discovered during tracing
#[derive(Debug, Clone)]
pub struct FileAccess {
    pub path: PathBuf,
    pub is_write: bool,
}

/// Result of learning file access patterns
#[derive(Debug)]
pub struct LearnResult {
    /// Paths that need read access
    pub read_paths: BTreeSet<PathBuf>,
    /// Paths that need write access
    pub write_paths: BTreeSet<PathBuf>,
    /// Paths that need read+write access
    pub readwrite_paths: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by system paths
    pub system_covered: BTreeSet<PathBuf>,
    /// Paths that were accessed but are already covered by profile
    pub profile_covered: BTreeSet<PathBuf>,
}

impl LearnResult {
    pub fn new() -> Self {
        Self {
            read_paths: BTreeSet::new(),
            write_paths: BTreeSet::new(),
            readwrite_paths: BTreeSet::new(),
            system_covered: BTreeSet::new(),
            profile_covered: BTreeSet::new(),
        }
    }

    /// Check if any paths were discovered
    pub fn has_paths(&self) -> bool {
        !self.read_paths.is_empty()
            || !self.write_paths.is_empty()
            || !self.readwrite_paths.is_empty()
    }

    /// Format as JSON fragment for profile
    pub fn to_json(&self) -> String {
        let allow: Vec<String> = self
            .readwrite_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let read: Vec<String> = self
            .read_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        let write: Vec<String> = self
            .write_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();

        let fragment = serde_json::json!({
            "filesystem": {
                "allow": allow,
                "read": read,
                "write": write
            }
        });

        serde_json::to_string_pretty(&fragment).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as human-readable summary
    pub fn to_summary(&self) -> String {
        let mut lines = Vec::new();

        if !self.read_paths.is_empty() {
            lines.push("Read access needed:".to_string());
            for path in &self.read_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.write_paths.is_empty() {
            lines.push("Write access needed:".to_string());
            for path in &self.write_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.readwrite_paths.is_empty() {
            lines.push("Read+Write access needed:".to_string());
            for path in &self.readwrite_paths {
                lines.push(format!("  {}", path.display()));
            }
        }

        if !self.system_covered.is_empty() {
            lines.push(format!(
                "\n({} paths already covered by system defaults)",
                self.system_covered.len()
            ));
        }

        if !self.profile_covered.is_empty() {
            lines.push(format!(
                "({} paths already covered by profile)",
                self.profile_covered.len()
            ));
        }

        if lines.is_empty() {
            lines.push("No additional paths needed.".to_string());
        }

        lines.join("\n")
    }
}

/// Process raw file accesses into a categorized LearnResult.
///
/// Filters out system-covered and profile-covered paths, deduplicates,
/// collapses files to their parent directories, and categorizes by access type.
pub fn process_accesses(
    accesses: Vec<FileAccess>,
    profile: Option<&Profile>,
    show_all: bool,
) -> Result<LearnResult> {
    let mut result = LearnResult::new();

    // Get system paths that are already allowed (from policy.json groups)
    let loaded_policy = crate::policy::load_embedded_policy()?;
    let system_read_paths = crate::policy::get_system_read_paths(&loaded_policy);
    let system_read_set: HashSet<&str> = system_read_paths.iter().map(|s| s.as_str()).collect();

    // Get profile paths if available
    let profile_paths: HashSet<String> = if let Some(prof) = profile {
        let mut paths = HashSet::new();
        paths.extend(prof.filesystem.allow.iter().cloned());
        paths.extend(prof.filesystem.read.iter().cloned());
        paths.extend(prof.filesystem.write.iter().cloned());
        paths
    } else {
        HashSet::new()
    };

    // Track unique paths (canonicalized where possible)
    let mut seen_paths: HashSet<PathBuf> = HashSet::new();

    for access in accesses {
        // Try to canonicalize, fall back to original
        let canonical = access.path.canonicalize().unwrap_or(access.path.clone());

        // Skip if we've seen this path
        if seen_paths.contains(&canonical) {
            continue;
        }
        seen_paths.insert(canonical.clone());

        // Check if covered by system paths
        if is_covered_by_set(&canonical, &system_read_set)? {
            if show_all {
                result.system_covered.insert(canonical);
            }
            continue;
        }

        // Check if covered by profile
        if is_covered_by_profile(&canonical, &profile_paths)? {
            if show_all {
                result.profile_covered.insert(canonical);
            }
            continue;
        }

        // Categorize by access type
        // Collapse to parent directories for cleaner output
        let collapsed = collapse_to_parent(&canonical);

        if access.is_write {
            // Check if already in read, upgrade to readwrite
            if result.read_paths.contains(&collapsed) {
                result.read_paths.remove(&collapsed);
                result.readwrite_paths.insert(collapsed);
            } else if !result.readwrite_paths.contains(&collapsed) {
                result.write_paths.insert(collapsed);
            }
        } else {
            // Read access
            if result.write_paths.contains(&collapsed) {
                result.write_paths.remove(&collapsed);
                result.readwrite_paths.insert(collapsed);
            } else if !result.readwrite_paths.contains(&collapsed) {
                result.read_paths.insert(collapsed);
            }
        }
    }

    Ok(result)
}

/// Check if a path is covered by a set of allowed paths
pub fn is_covered_by_set(path: &Path, allowed: &HashSet<&str>) -> Result<bool> {
    for allowed_path in allowed {
        let allowed_expanded = expand_home(allowed_path)?;
        if let Ok(allowed_canonical) = std::fs::canonicalize(&allowed_expanded) {
            if path.starts_with(&allowed_canonical) {
                return Ok(true);
            }
        }
        // Also check without canonicalization for paths that may not exist
        let allowed_path_buf = PathBuf::from(&allowed_expanded);
        if path.starts_with(&allowed_path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Check if a path is covered by profile paths
pub fn is_covered_by_profile(path: &Path, profile_paths: &HashSet<String>) -> Result<bool> {
    for profile_path in profile_paths {
        let expanded = expand_home(profile_path)?;
        if let Ok(canonical) = std::fs::canonicalize(&expanded) {
            if path.starts_with(&canonical) {
                return Ok(true);
            }
        }
        let path_buf = PathBuf::from(&expanded);
        if path.starts_with(&path_buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Expand ~ to home directory
pub fn expand_home(path: &str) -> Result<String> {
    if path.starts_with('~') {
        let home = config::validated_home()?;
        return Ok(path.replacen('~', &home, 1));
    }
    if path.starts_with("$HOME") {
        let home = config::validated_home()?;
        return Ok(path.replacen("$HOME", &home, 1));
    }
    Ok(path.to_string())
}

/// Collapse a file path to its parent directory for cleaner output
pub fn collapse_to_parent(path: &Path) -> PathBuf {
    // Don't collapse if it's already a directory
    if path.is_dir() {
        return path.to_path_buf();
    }

    // Collapse files to their parent directory
    path.parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| path.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_home() {
        std::env::set_var("HOME", "/home/test");
        assert_eq!(expand_home("~/foo").expect("valid home"), "/home/test/foo");
        assert_eq!(
            expand_home("$HOME/bar").expect("valid home"),
            "/home/test/bar"
        );
        assert_eq!(
            expand_home("/absolute/path").expect("no expansion needed"),
            "/absolute/path"
        );
    }

    #[test]
    fn test_collapse_to_parent() {
        // For a file that doesn't exist, collapse to parent
        let path = PathBuf::from("/some/dir/file.txt");
        let collapsed = collapse_to_parent(&path);
        assert_eq!(collapsed, PathBuf::from("/some/dir"));
    }

    #[test]
    fn test_learn_result_to_json() {
        let mut result = LearnResult::new();
        result.read_paths.insert(PathBuf::from("/some/read/path"));
        result.write_paths.insert(PathBuf::from("/some/write/path"));

        let json = result.to_json();
        assert!(json.contains("filesystem"));
        assert!(json.contains("/some/read/path"));
        assert!(json.contains("/some/write/path"));
    }

    #[test]
    fn test_learn_result_has_paths() {
        let mut result = LearnResult::new();
        assert!(!result.has_paths());
        result.read_paths.insert(PathBuf::from("/some/path"));
        assert!(result.has_paths());
    }
}
