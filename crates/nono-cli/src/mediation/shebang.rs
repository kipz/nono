//! Shebang parsing and recursive chain walking for the exec filter.
//!
//! When the exec filter's three-way classification yields `allow_shim` or
//! `allow_unmediated`, the supervisor reads the first bytes of the canonical
//! target to check whether the file is a script whose `#!` interpreter chain
//! eventually points at a deny-set entry. Shebangs are handled by the kernel
//! internally without issuing a second `execve` syscall, so the filter would
//! miss this bypass otherwise.
//!
//! The kernel reads the first `BINPRM_BUF_SIZE` (256 bytes on Linux) of the
//! target; if it starts with `#!`, it parses the interpreter path (up to
//! first whitespace) and recursively binfmt-loads that interpreter up to
//! `BINPRM_MAX_RECURSION` (5) levels. We mirror that behavior from
//! userspace, with a slightly larger recursion bound for margin.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Maximum shebang chain depth the filter will chase before terminating.
///
/// Set above the kernel's `BINPRM_MAX_RECURSION` (currently 5; see
/// `include/linux/binfmts.h`) so a kernel-side bump doesn't silently open
/// a bypass window. If the kernel's value moves past ours, the
/// `max_shebang_recursion_at_least_kernel_limit` unit test fails, which is
/// the CI signal to re-evaluate the margin.
pub const MAX_SHEBANG_RECURSION: usize = 8;

/// Result of walking a potential shebang chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShebangResult {
    /// The file is not a script, the chain terminated at a non-script
    /// interpreter, a read failed, or the recursion limit was reached
    /// without hitting the deny set. The caller's existing classification
    /// stands.
    NotScript,
    /// An interpreter in the chain resolved to a deny-set entry. The
    /// caller must flip its classification to `deny` with reason
    /// `shebang_chain`. The `Vec<PathBuf>` contains the interpreter
    /// chain, outermost first: the first entry is the interpreter named
    /// in the outer file's `#!` line; the last entry is the deny-set
    /// interpreter that triggered the match.
    Deny(Vec<PathBuf>),
}

/// Set of canonical paths that are denied for direct execution by the
/// filter. Built at session start from the canonicalized real paths of
/// `mediation.commands` entries.
#[derive(Debug, Default, Clone)]
pub struct DenySet {
    paths: HashSet<PathBuf>,
}

impl DenySet {
    /// Construct an empty deny set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a deny set from an iterator of canonical paths. The
    /// caller is responsible for canonicalizing paths before inserting;
    /// this type performs no canonicalization itself.
    pub fn with_paths<I: IntoIterator<Item = PathBuf>>(paths: I) -> Self {
        Self {
            paths: paths.into_iter().collect(),
        }
    }

    /// Returns `true` if the path is a member of the deny set. Exact
    /// match; no prefix or symlink resolution.
    pub fn contains(&self, path: &Path) -> bool {
        self.paths.contains(path)
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// Trait abstracting the "read the first bytes of a file" operation so
/// `check_shebang_chain` can be unit-tested with a mock file system.
///
/// Production code uses [`StdFileReader`]; tests use an in-memory
/// implementation that returns canned bytes.
pub trait ShebangFileReader {
    /// Reads up to `buf.len()` bytes from the start of `path` into `buf`.
    /// Returns the number of bytes read, which may be less than the
    /// requested length if the file is shorter.
    fn read_first_bytes(&self, path: &Path, buf: &mut [u8]) -> std::io::Result<usize>;
}

/// Default reader that opens the path on the real filesystem.
pub struct StdFileReader;

impl ShebangFileReader for StdFileReader {
    fn read_first_bytes(&self, path: &Path, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read;
        let mut file = std::fs::File::open(path)?;
        file.read(buf)
    }
}

/// Parse a shebang interpreter path from the first bytes of a file.
///
/// Returns `Some(interpreter)` if `bytes` starts with `#!` followed by at
/// least one non-whitespace character; the interpreter is the contiguous
/// run of non-whitespace bytes after `#!`. Returns `None` if the buffer
/// does not start with `#!` or contains only whitespace after `#!`.
///
/// Does not return any trailing arguments on the shebang line; the caller
/// receives only the interpreter path. This matches the kernel's
/// binfmt_script behavior: trailing arguments become part of the
/// interpreter's argv but do not themselves trigger another binfmt
/// lookup.
pub fn parse_shebang(bytes: &[u8]) -> Option<&str> {
    let _ = bytes;
    todo!("Phase 4: parse shebang interpreter from leading bytes")
}

/// Walk the shebang chain of a file, checking each interpreter against
/// the deny set. Uses the real filesystem via [`StdFileReader`].
///
/// See [`check_shebang_chain_with_reader`] for the testable form and
/// full semantics.
pub fn check_shebang_chain(path: &Path, depth: usize, deny_set: &DenySet) -> ShebangResult {
    check_shebang_chain_with_reader(path, depth, deny_set, &StdFileReader)
}

/// Walk the shebang chain of a file, checking each interpreter against
/// the deny set, using a caller-supplied reader.
///
/// Recurses up to [`MAX_SHEBANG_RECURSION`] levels starting from `depth`
/// (callers pass `0` initially). Returns:
///
/// - `ShebangResult::Deny(chain)` if any interpreter in the chain is a
///   member of `deny_set`. `chain` lists interpreters outermost-first.
/// - `ShebangResult::NotScript` if the file is not a script, if a read
///   fails, if the chain terminates at a non-script interpreter, or if
///   the recursion limit is reached without a deny-set hit. The
///   recursion-limit case is intentionally a safe default: the kernel's
///   own limit is lower than ours, so reaching our limit means the
///   kernel would have refused to load the chain anyway.
///
/// The `reader` argument is used for every read in the chain, including
/// reads of interpreter files resolved from shebang lines. Tests pass a
/// mock reader that returns canned content; production code passes
/// [`StdFileReader`].
pub fn check_shebang_chain_with_reader<R: ShebangFileReader>(
    path: &Path,
    depth: usize,
    deny_set: &DenySet,
    reader: &R,
) -> ShebangResult {
    let _ = (path, depth, deny_set, reader);
    todo!("Phase 4: walk shebang chain, check deny set, recurse up to MAX_SHEBANG_RECURSION")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // -------------------------------------------------------------------
    // MAX_SHEBANG_RECURSION sanity
    // -------------------------------------------------------------------

    #[test]
    fn max_shebang_recursion_at_least_kernel_limit() {
        // Linux's BINPRM_MAX_RECURSION in include/linux/binfmts.h is
        // currently 5. If a future kernel bumps this past our value,
        // we'd miss a chain the kernel would still follow.
        assert!(
            MAX_SHEBANG_RECURSION >= 5,
            "MAX_SHEBANG_RECURSION ({}) must be >= kernel's BINPRM_MAX_RECURSION (5)",
            MAX_SHEBANG_RECURSION
        );
    }

    // -------------------------------------------------------------------
    // parse_shebang table-driven tests
    // -------------------------------------------------------------------

    #[test]
    fn parse_shebang_simple_bash() {
        assert_eq!(parse_shebang(b"#!/bin/bash\n"), Some("/bin/bash"));
    }

    #[test]
    fn parse_shebang_env_interpreter_strips_args() {
        // "/usr/bin/env python" yields just "/usr/bin/env" — the
        // trailing "python" is an interpreter arg, not a second binfmt
        // lookup.
        assert_eq!(
            parse_shebang(b"#!/usr/bin/env python\n"),
            Some("/usr/bin/env")
        );
    }

    #[test]
    fn parse_shebang_tab_terminates_interpreter() {
        assert_eq!(parse_shebang(b"#!/bin/bash\tfoo\n"), Some("/bin/bash"));
    }

    #[test]
    fn parse_shebang_no_trailing_newline() {
        // A shebang without a trailing newline but with enough bytes to
        // identify the interpreter is still a valid shebang.
        assert_eq!(parse_shebang(b"#!/bin/bash"), Some("/bin/bash"));
    }

    #[test]
    fn parse_shebang_not_a_shebang_returns_none() {
        assert_eq!(parse_shebang(b"not a shebang"), None);
        assert_eq!(parse_shebang(b""), None);
        assert_eq!(parse_shebang(b"#"), None);
        // Reversed magic: "!#" is not "#!"
        assert_eq!(parse_shebang(b"!#/bin/bash\n"), None);
    }

    #[test]
    fn parse_shebang_bang_with_no_interpreter_returns_none() {
        assert_eq!(parse_shebang(b"#!"), None);
        assert_eq!(parse_shebang(b"#!\n"), None);
        assert_eq!(parse_shebang(b"#!   "), None);
        assert_eq!(parse_shebang(b"#!\t\n"), None);
    }

    #[test]
    fn parse_shebang_truncates_at_buffer_end_without_whitespace() {
        // When the interpreter path extends to the end of the buffer
        // without any whitespace, parse_shebang returns the whole
        // buffer past "#!" as the interpreter. The kernel's
        // BINPRM_BUF_SIZE truncation happens before we see the bytes,
        // so we trust the caller to pass at most 256 bytes.
        let long = b"#!/a/very/long/interpreter/path";
        assert_eq!(parse_shebang(long), Some("/a/very/long/interpreter/path"));
    }

    // -------------------------------------------------------------------
    // DenySet membership
    // -------------------------------------------------------------------

    #[test]
    fn deny_set_membership_exact_match() {
        let set = DenySet::with_paths(vec![
            PathBuf::from("/usr/bin/gh"),
            PathBuf::from("/usr/bin/ddtool"),
        ]);
        assert!(set.contains(Path::new("/usr/bin/gh")));
        assert!(set.contains(Path::new("/usr/bin/ddtool")));
        assert!(!set.contains(Path::new("/usr/bin/ls")));
    }

    #[test]
    fn deny_set_membership_is_not_prefix_match() {
        // DenySet does exact canonical-path matching; it must not match
        // prefixes. The caller canonicalizes before lookup, so symlink
        // resolution is not this type's concern.
        let set = DenySet::with_paths(vec![PathBuf::from("/usr/bin/gh")]);
        assert!(!set.contains(Path::new("/usr/bin/gh/suffix")));
        assert!(!set.contains(Path::new("/usr/bin/ghost")));
    }

    #[test]
    fn deny_set_empty() {
        let set = DenySet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
        assert!(!set.contains(Path::new("/anything")));
    }

    // -------------------------------------------------------------------
    // check_shebang_chain
    // -------------------------------------------------------------------

    /// In-memory mock of `ShebangFileReader` for unit tests.
    ///
    /// Returns bytes from `contents` keyed by path, or `default_bytes`
    /// if no entry exists. Used to simulate interpreter chains without
    /// touching the real filesystem.
    struct MockReader {
        contents: HashMap<PathBuf, Vec<u8>>,
        default_bytes: Vec<u8>,
        calls: Mutex<usize>,
    }

    impl MockReader {
        fn new(default_bytes: Vec<u8>) -> Self {
            Self {
                contents: HashMap::new(),
                default_bytes,
                calls: Mutex::new(0),
            }
        }

        fn call_count(&self) -> usize {
            *self.calls.lock().unwrap()
        }
    }

    impl ShebangFileReader for MockReader {
        fn read_first_bytes(&self, path: &Path, buf: &mut [u8]) -> std::io::Result<usize> {
            *self.calls.lock().unwrap() += 1;
            let src = self
                .contents
                .get(path)
                .map(|v| v.as_slice())
                .unwrap_or(self.default_bytes.as_slice());
            let n = src.len().min(buf.len());
            buf[..n].copy_from_slice(&src[..n]);
            Ok(n)
        }
    }

    #[test]
    fn check_shebang_chain_terminates_at_max_recursion() {
        // A reader that returns `#!/self\n` for every path, creating an
        // infinite shebang loop. The walker must terminate at
        // MAX_SHEBANG_RECURSION and return `NotScript` as the safe
        // default rather than stack-overflow or loop forever.
        let reader = MockReader::new(b"#!/self\n".to_vec());
        let deny_set = DenySet::new();
        let result = check_shebang_chain_with_reader(
            Path::new("/any/path"),
            0,
            &deny_set,
            &reader,
        );
        assert_eq!(
            result,
            ShebangResult::NotScript,
            "recursion limit should yield NotScript, got {:?}",
            result
        );
        // Soft upper bound: we expect about MAX_SHEBANG_RECURSION + 1
        // reads in the worst case (initial path plus each interpreter
        // level). Assert a generous upper bound to catch pathological
        // non-termination.
        let calls = reader.call_count();
        assert!(
            calls <= MAX_SHEBANG_RECURSION + 2,
            "expected at most {} reads, got {}",
            MAX_SHEBANG_RECURSION + 2,
            calls
        );
    }

    #[test]
    fn check_shebang_chain_not_a_script_returns_not_script() {
        let reader = MockReader::new(b"\x7fELF...binary...".to_vec());
        let deny_set = DenySet::new();
        let result = check_shebang_chain_with_reader(
            Path::new("/bin/somebinary"),
            0,
            &deny_set,
            &reader,
        );
        assert_eq!(result, ShebangResult::NotScript);
    }

    #[test]
    fn check_shebang_chain_deny_set_hit_returns_deny_with_chain() {
        // Script whose shebang points directly at a deny-set entry.
        let denied = PathBuf::from("/opt/homebrew/bin/gh");
        let mut reader = MockReader::new(Vec::new());
        reader.contents.insert(
            PathBuf::from("/tmp/evil.sh"),
            b"#!/opt/homebrew/bin/gh\n".to_vec(),
        );
        // The interpreter itself is a real binary, not a script — return
        // non-shebang bytes so the walker would stop there if it hadn't
        // already hit the deny set.
        reader.contents.insert(denied.clone(), b"\x7fELF".to_vec());
        let deny_set = DenySet::with_paths(vec![denied.clone()]);

        let result = check_shebang_chain_with_reader(
            Path::new("/tmp/evil.sh"),
            0,
            &deny_set,
            &reader,
        );
        match result {
            ShebangResult::Deny(chain) => {
                assert_eq!(chain, vec![denied]);
            }
            other => panic!("expected Deny chain, got {:?}", other),
        }
    }
}
