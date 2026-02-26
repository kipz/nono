//! Shared types and helpers for learn mode (platform-agnostic)

use crate::config;
use crate::profile::Profile;
use nono::Result;
use std::collections::{BTreeSet, HashMap, HashSet};
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

    /// Format as a composed profile JSON.
    ///
    /// Emits only the newly learned paths plus an `"extends"` reference to the
    /// named base profile. At load time, `load_profile_from_path` resolves the
    /// base and overlays these paths on top — no data is inlined here.
    ///
    /// This is the preferred output when `--profile P --output-file F` are both
    /// supplied to `nono learn`.
    pub fn to_composed_profile_json(&self, base_profile_name: &str) -> String {
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
            "extends": base_profile_name,
            "filesystem": {
                "allow": allow,
                "read": read,
                "write": write,
            }
        });

        serde_json::to_string_pretty(&fragment).unwrap_or_else(|_| "{}".to_string())
    }

    /// Remove all paths that fall under any of the given prefixes.
    ///
    /// Applied before collapse so that excluded paths do not inflate sibling
    /// counts and incorrectly trigger directory-level grants. The typical use
    /// case is stripping the working directory, which is already granted at
    /// run time via `--allow "$PWD"`.
    #[must_use]
    pub fn without_paths(mut self, exclude: &[PathBuf]) -> Self {
        if exclude.is_empty() {
            return self;
        }
        let canonical_excludes: Vec<PathBuf> = exclude
            .iter()
            .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
            .collect();
        let filter = |paths: BTreeSet<PathBuf>| -> BTreeSet<PathBuf> {
            paths
                .into_iter()
                .filter(|p| {
                    let cp = p.canonicalize().unwrap_or_else(|_| p.clone());
                    !canonical_excludes.iter().any(|ex| cp.starts_with(ex))
                })
                .collect()
        };
        self.read_paths = filter(self.read_paths);
        self.write_paths = filter(self.write_paths);
        self.readwrite_paths = filter(self.readwrite_paths);
        self
    }

    /// Collapse over-specific paths to parent directories.
    ///
    /// If a parent directory has >= `threshold` direct children in a path set,
    /// all those children are replaced by the parent. Applied iteratively per
    /// set (read, write, readwrite independently) until stable.
    ///
    /// `min_depth` is the minimum component count a parent must have to be a
    /// valid collapse target (e.g. 4 prevents collapsing to `/Users/name` on
    /// macOS, which has 3 components).
    ///
    /// A threshold of 0 is a no-op. Paths that become descendants of a newly
    /// introduced parent are pruned automatically.
    #[must_use]
    pub fn collapse(mut self, threshold: usize, min_depth: usize) -> Self {
        if threshold == 0 {
            return self;
        }
        self.read_paths = collapse_path_set(self.read_paths, threshold, min_depth);
        self.write_paths = collapse_path_set(self.write_paths, threshold, min_depth);
        self.readwrite_paths = collapse_path_set(self.readwrite_paths, threshold, min_depth);
        self
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

/// Remove paths that are descendants of another path already in the set.
///
/// Only paths with at least `min_depth` components are used as anchors.
/// This prevents a shallow path like `~/` (depth 3 on macOS) from subsuming
/// deeper, more specific paths like `~/scm/project` (depth 5).
///
/// Example with min_depth=4: `/foo` (depth 2) is *not* used as an anchor,
/// so `/foo/bar/baz` survives even if `/foo` is also in the set.
fn remove_descendant_paths(paths: BTreeSet<PathBuf>, min_depth: usize) -> BTreeSet<PathBuf> {
    let anchors: Vec<&PathBuf> = paths.iter().collect();
    paths
        .iter()
        .filter(|p| {
            !anchors.iter().any(|other| {
                *other != *p && p.starts_with(other) && other.components().count() >= min_depth
            })
        })
        .cloned()
        .collect()
}

/// Remove paths at exactly `min_depth` that have more specific descendants.
///
/// When a process stats a directory (e.g. reading `/Users/name/scm` while
/// listing its contents), the seatbelt tracer logs the directory itself.
/// That shallow, incidental access must not subsume the more specific paths
/// that were the real purpose of the operation (e.g. `/Users/name/scm/project`).
///
/// Only paths at exactly `min_depth` are candidates for removal — they sit at
/// the policy floor and granting them would be too broad. Deeper paths are
/// left for `remove_descendant_paths` to handle.
fn prefer_specific_paths(paths: BTreeSet<PathBuf>, min_depth: usize) -> BTreeSet<PathBuf> {
    let all: Vec<&PathBuf> = paths.iter().collect();
    paths
        .iter()
        .filter(|p| {
            if p.components().count() != min_depth {
                return true;
            }
            // Keep only if no more-specific descendant exists in the set.
            !all.iter().any(|other| *other != *p && other.starts_with(*p))
        })
        .cloned()
        .collect()
}

/// Collapse a set of paths by replacing any parent that has >= `threshold`
/// direct children with that parent. Applied iteratively until stable.
///
/// `min_depth` is the minimum number of path components the *parent* must
/// have to be a valid collapse target (counted including the root component,
/// so `/a/b` has 3 components). This prevents cascading all the way up to
/// shallow roots like `/Users` or `/home`.
///
/// After each collapse pass, descendant paths made redundant by a newly
/// added parent are pruned.
fn collapse_path_set(
    paths: BTreeSet<PathBuf>,
    threshold: usize,
    min_depth: usize,
) -> BTreeSet<PathBuf> {
    let paths = prefer_specific_paths(paths, min_depth);
    let mut current = remove_descendant_paths(paths, min_depth);
    loop {
        // Count direct children per parent
        let mut child_count: HashMap<PathBuf, usize> = HashMap::new();
        for path in &current {
            if let Some(parent) = path.parent() {
                let depth = parent.components().count();
                // Never collapse to filesystem root or shallower than min_depth
                if depth > 1 && depth > min_depth {
                    *child_count.entry(parent.to_path_buf()).or_insert(0) += 1;
                }
            }
        }

        // Parents with enough children to justify collapsing
        let collapse_to: HashSet<PathBuf> = child_count
            .into_iter()
            .filter(|(_, count)| *count >= threshold)
            .map(|(p, _)| p)
            .collect();

        if collapse_to.is_empty() {
            break;
        }

        // Drop children whose parent is being collapsed; keep everything else
        let mut next: BTreeSet<PathBuf> = current
            .into_iter()
            .filter(|p| {
                !p.parent()
                    .map(|par| collapse_to.contains(par))
                    .unwrap_or(false)
            })
            .collect();
        next.extend(collapse_to);
        current = remove_descendant_paths(next, min_depth);
    }

    // Drop any paths still shallower than min_depth. These arise when
    // collapse_to_parent folds a dotfile in ~ to ~ itself; that broad path
    // is unusable (blocked by protected_paths) and must not subsume the more
    // specific deep paths that survived the loop.
    current
        .into_iter()
        .filter(|p| p.components().count() >= min_depth)
        .collect()
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

    #[test]
    fn test_to_composed_profile_json() {
        let mut result = LearnResult::new();
        result
            .readwrite_paths
            .insert(PathBuf::from("/tmp/project/src"));
        result.read_paths.insert(PathBuf::from("/some/read/path"));

        let json = result.to_composed_profile_json("claude-code");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");

        // extends reference is set
        assert_eq!(parsed["extends"], "claude-code");

        // Only learned paths are present — base profile paths are NOT inlined
        let allow = parsed["filesystem"]["allow"].as_array().expect("allow arr");
        let allow_strs: Vec<&str> = allow.iter().filter_map(|v| v.as_str()).collect();
        assert!(allow_strs.contains(&"/tmp/project/src"));
        assert!(
            !allow_strs.contains(&"$HOME/.claude"),
            "base profile paths should not be inlined"
        );

        let read = parsed["filesystem"]["read"].as_array().expect("read arr");
        let read_strs: Vec<&str> = read.iter().filter_map(|v| v.as_str()).collect();
        assert!(read_strs.contains(&"/some/read/path"));

        // No settings from the base profile are inlined
        assert!(parsed["workdir"].is_null());
        assert!(parsed["interactive"].is_null());
        assert!(parsed["hooks"].is_null());
    }

    #[test]
    fn test_without_paths_removes_cwd() {
        let mut result = LearnResult::new();
        // CWD paths — should be excluded
        result
            .read_paths
            .insert(PathBuf::from("/Users/name/project/src"));
        result
            .write_paths
            .insert(PathBuf::from("/Users/name/project/out"));
        // External path — should survive
        result
            .read_paths
            .insert(PathBuf::from("/Users/name/.config/git"));

        let result = result.without_paths(&[PathBuf::from("/Users/name/project")]);

        assert!(
            !result.read_paths.contains(&PathBuf::from("/Users/name/project/src")),
            "CWD read path should be removed"
        );
        assert!(
            !result.write_paths.contains(&PathBuf::from("/Users/name/project/out")),
            "CWD write path should be removed"
        );
        assert!(
            result.read_paths.contains(&PathBuf::from("/Users/name/.config/git")),
            "external read path should survive"
        );
    }

    #[test]
    fn test_without_paths_empty_exclude_is_noop() {
        let mut result = LearnResult::new();
        result.read_paths.insert(PathBuf::from("/some/path"));
        let before_count = result.read_paths.len();
        let result = result.without_paths(&[]);
        assert_eq!(result.read_paths.len(), before_count);
    }

    #[test]
    fn test_prefer_specific_drops_incidental_parent_stat() {
        // /Users/name/scm (depth 4 = min_depth) was stat'd as a side-effect of
        // listing /Users/name/scm/dd-attest. The specific path should survive.
        let paths: BTreeSet<PathBuf> = [
            "/Users/name/scm",
            "/Users/name/scm/dd-attest",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        let result = collapse_path_set(paths, 2, 4);
        assert_eq!(
            result,
            BTreeSet::from([PathBuf::from("/Users/name/scm/dd-attest")])
        );
    }

    #[test]
    fn test_prefer_specific_keeps_min_depth_when_no_descendants() {
        // If nothing more specific exists, the min_depth path is kept.
        let paths: BTreeSet<PathBuf> = ["/Users/name/scm"].iter().map(PathBuf::from).collect();
        let result = collapse_path_set(paths.clone(), 2, 4);
        assert_eq!(result, paths);
    }

    #[test]
    fn test_prefer_specific_does_not_affect_deeper_paths() {
        // A path deeper than min_depth is never removed by prefer_specific.
        let paths: BTreeSet<PathBuf> = [
            "/Users/name/scm/proj",      // depth 5
            "/Users/name/scm/proj/src",  // depth 6
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        // prefer_specific only acts on depth==min_depth (4); depth-5 paths untouched.
        // remove_descendant_paths then drops proj/src (covered by proj).
        let result = collapse_path_set(paths, 2, 4);
        assert_eq!(
            result,
            BTreeSet::from([PathBuf::from("/Users/name/scm/proj")])
        );
    }

    #[test]
    fn test_collapse_siblings_to_parent() {
        let paths: BTreeSet<PathBuf> = ["/foo/a", "/foo/b", "/foo/c"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let collapsed = collapse_path_set(paths, 3, 0);
        assert_eq!(collapsed, BTreeSet::from([PathBuf::from("/foo")]));
    }

    #[test]
    fn test_collapse_below_threshold_unchanged() {
        let paths: BTreeSet<PathBuf> = ["/foo/a", "/foo/b"].iter().map(PathBuf::from).collect();
        let collapsed = collapse_path_set(paths.clone(), 3, 0);
        assert_eq!(collapsed, paths);
    }

    #[test]
    fn test_collapse_iterative_grandparent() {
        // /foo/a, /foo/b, /foo/c → /foo; then /foo + /bar → not enough at /
        let paths: BTreeSet<PathBuf> = ["/foo/a", "/foo/b", "/foo/c", "/bar/x"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let collapsed = collapse_path_set(paths, 3, 0);
        assert_eq!(
            collapsed,
            BTreeSet::from([PathBuf::from("/foo"), PathBuf::from("/bar/x")])
        );
    }

    #[test]
    fn test_collapse_two_levels() {
        // With threshold=2: /foo/a, /foo/b → /foo; /bar/x, /bar/y → /bar;
        // then /foo + /bar → 2 children of / but / is skipped → stays as /foo, /bar
        let paths: BTreeSet<PathBuf> = ["/foo/a", "/foo/b", "/bar/x", "/bar/y"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let collapsed = collapse_path_set(paths, 2, 0);
        assert_eq!(
            collapsed,
            BTreeSet::from([PathBuf::from("/foo"), PathBuf::from("/bar")])
        );
    }

    #[test]
    fn test_collapse_removes_descendants() {
        // If /foo is added by collapsing, /foo/bar/baz should be pruned
        let paths: BTreeSet<PathBuf> = ["/foo/a", "/foo/b", "/foo/bar/baz"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let collapsed = collapse_path_set(paths, 2, 0);
        // /foo/a and /foo/b → /foo; then /foo/bar/baz is a descendant of /foo → removed
        assert_eq!(collapsed, BTreeSet::from([PathBuf::from("/foo")]));
    }

    #[test]
    fn test_collapse_min_depth_stops_cascade() {
        // With threshold=1 and no min_depth, a single path cascades to depth 2
        let paths: BTreeSet<PathBuf> = ["/a/b/c/d"].iter().map(PathBuf::from).collect();
        let collapsed = collapse_path_set(paths.clone(), 1, 0);
        assert_eq!(collapsed, BTreeSet::from([PathBuf::from("/a")]));

        // With min_depth=3, collapse stops at the first parent whose depth is
        // NOT > min_depth (i.e. depth == 3). /a/b/c/d → /a/b/c (parent depth 4
        // > 3) → then /a/b (depth 3, NOT > 3) stops the cascade.
        let collapsed = collapse_path_set(paths, 1, 3);
        assert_eq!(collapsed, BTreeSet::from([PathBuf::from("/a/b/c")]));
    }

    #[test]
    fn test_collapse_min_depth_prevents_broad_grants() {
        // Simulates macOS home dir situation: min_depth=4 prevents collapsing
        // to /Users/name (depth 3) or above, and the strict > check prevents
        // collapsing to /Users/name/scm (depth 4 = min_depth) too.
        let paths: BTreeSet<PathBuf> = [
            "/Users/name/scm/proj/src/foo",
            "/Users/name/scm/proj/src/bar",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        // threshold=1, min_depth=4:
        // /Users/name/scm/proj/src → parent /Users/name/scm/proj (depth 5 > 4) → collapse
        // /Users/name/scm/proj → parent /Users/name/scm (depth 4, NOT > 4) → STOP
        let collapsed = collapse_path_set(paths, 1, 4);
        assert_eq!(
            collapsed,
            BTreeSet::from([PathBuf::from("/Users/name/scm/proj")])
        );
    }

    #[test]
    fn test_collapse_zero_threshold_is_noop() {
        let mut result = LearnResult::new();
        result.read_paths.insert(PathBuf::from("/a/b/c"));
        result.read_paths.insert(PathBuf::from("/a/b/d"));
        result.read_paths.insert(PathBuf::from("/a/b/e"));
        let before_count = result.read_paths.len();
        let result = result.collapse(0, 4);
        assert_eq!(result.read_paths.len(), before_count);
    }

    #[test]
    fn test_collapse_learn_result_per_category() {
        let mut result = LearnResult::new();
        // 3 read siblings → should collapse
        result.read_paths.insert(PathBuf::from("/proj/src/a.rs"));
        result.read_paths.insert(PathBuf::from("/proj/src/b.rs"));
        result.read_paths.insert(PathBuf::from("/proj/src/c.rs"));
        // Only 1 write → should not collapse
        result.write_paths.insert(PathBuf::from("/proj/out/result"));

        let result = result.collapse(3, 0);

        assert_eq!(
            result.read_paths,
            BTreeSet::from([PathBuf::from("/proj/src")])
        );
        assert_eq!(result.write_paths.len(), 1);
    }

    #[test]
    fn test_remove_descendant_paths() {
        let paths: BTreeSet<PathBuf> = ["/foo", "/foo/bar", "/foo/bar/baz", "/other"]
            .iter()
            .map(PathBuf::from)
            .collect();
        // min_depth=0: /foo (depth 2 >= 0) is used as anchor → /foo/bar, /foo/bar/baz removed
        let pruned = remove_descendant_paths(paths, 0);
        assert_eq!(
            pruned,
            BTreeSet::from([PathBuf::from("/foo"), PathBuf::from("/other")])
        );
    }

    #[test]
    fn test_remove_descendant_paths_respects_min_depth() {
        // /home (depth 2) should NOT subsume /home/user/project when min_depth=3
        let paths: BTreeSet<PathBuf> = ["/home", "/home/user/project"]
            .iter()
            .map(PathBuf::from)
            .collect();
        let pruned = remove_descendant_paths(paths.clone(), 3);
        // /home has depth 2 < 3, not used as anchor → both survive
        assert_eq!(pruned, paths);

        // With min_depth=2: /home (depth 2 >= 2) IS used → /home/user/project removed
        let pruned = remove_descendant_paths(paths, 2);
        assert_eq!(pruned, BTreeSet::from([PathBuf::from("/home")]));
    }

    #[test]
    fn test_collapse_shallow_residuals_filtered() {
        // Simulates a dotfile in ~ collapsing to ~, which should not subsume
        // deeper project paths and should be dropped from the final result.
        // Input: ~ (from a dotfile) + ~/scm/project/src (from project files)
        let paths: BTreeSet<PathBuf> = ["/Users/name", "/Users/name/scm/project/src/foo.rs"]
            .iter()
            .map(PathBuf::from)
            .collect();
        // threshold=1, min_depth=4:
        // - remove_descendant_paths: /Users/name (depth 3 < 4) not used as anchor
        //   → /Users/name/scm/project/src/foo.rs survives
        // - collapse loop: /Users/name/scm/project/src/foo.rs →
        //     parent /Users/name/scm/project/src (depth 6 > 4) → collapse
        //   → /Users/name/scm/project/src →
        //     parent /Users/name/scm/project (depth 5 > 4) → collapse
        //   → /Users/name/scm/project →
        //     parent /Users/name/scm (depth 4, NOT > 4) → STOP
        // - final filter: /Users/name (depth 3 < 4) dropped
        // - result: /Users/name/scm/project
        let collapsed = collapse_path_set(paths, 1, 4);
        assert_eq!(
            collapsed,
            BTreeSet::from([PathBuf::from("/Users/name/scm/project")])
        );
    }
}
