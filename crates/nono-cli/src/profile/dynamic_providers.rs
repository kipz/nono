//! Dynamic token expansion in profile path lists.
//!
//! Profile authors can place a sentinel like `@<provider>:<query>` in any
//! path-list field (top-level `filesystem.*` or per-command
//! `mediation.commands[].sandbox.*`). At profile finalize time, the token
//! is replaced with one or more concrete paths produced by the named
//! provider — letting profiles cover user-specific state (e.g. paths
//! referenced by the user's git config) without enumerating every
//! per-user dotfile location in the shipped profile.
//!
//! Token format: `@<provider>:<query>`.
//! - `<provider>` is a lowercase alphanumeric identifier (no `:` or spaces).
//! - `<query>` is provider-specific and may contain hyphens, slashes, etc.
//! - Anything not starting with `@` is left untouched.
//! - `@` strings without a `:` are passed through as literal paths.

use nono::{NonoError, Result};

use crate::profile::Profile;

/// Parse a profile path entry as a dynamic-provider token.
///
/// Returns `Some((provider, query))` for strings of the shape
/// `@<provider>:<query>`. Returns `None` for everything else, including
/// `@` strings that lack a `:` (treated as literal paths).
fn parse_token(s: &str) -> Option<(&str, &str)> {
    let rest = s.strip_prefix('@')?;
    let (provider, query) = rest.split_once(':')?;
    Some((provider, query))
}

pub(crate) mod git {
    use std::path::Path;
    use std::process::Command;

    use nono::{NonoError, Result};

    /// Invoke `git config --list --show-origin --show-scope` and parse
    /// the result via [`read_paths_from_stdout`], which keeps only the
    /// lines tagged with the `global` or `system` scope.
    ///
    /// The scope filter happens in the parser (not via git's
    /// `--global`/`--system` CLI flags) because the CLI flags disable
    /// `include.path` traversal under that scope — and `include.path`
    /// is the main reason this provider exists (covering the common
    /// `~/.gitconfig` → `~/.gitconfig-work` pattern without enumerating
    /// every per-user dotfile in the shipped profile).
    ///
    /// `local` and `worktree` scopes are dropped: they come from
    /// per-repo `.git/config`, which is attacker-controlled in the
    /// clone-and-run threat model. A malicious clone that sets
    /// `core.attributesFile=/etc/passwd` in its local config would
    /// otherwise widen the sandbox at session start.
    ///
    /// Returns an empty list if `git` is absent or exits non-zero —
    /// both are treated as "no expansion possible" rather than
    /// profile-load failures, since the provider's job is to add
    /// helpful read access on top of whatever the profile already
    /// grants.
    pub(crate) fn read_paths() -> Result<Vec<String>> {
        run(None, None)
    }

    /// Test seam: run the provider against a fixed global config path.
    /// Sets `GIT_CONFIG_GLOBAL` (overrides `~/.gitconfig`) and
    /// `GIT_CONFIG_SYSTEM=/dev/null` (suppresses /etc/gitconfig noise
    /// that varies per host) so tests can pin the output to a known
    /// fixture.
    #[cfg(test)]
    pub(super) fn read_paths_with_global(global_config: &Path) -> Result<Vec<String>> {
        run(None, Some(global_config))
    }

    /// Test seam: run the provider with both a specific cwd and a fixed
    /// global config path. Used to verify per-repo `.git/config` cannot
    /// influence the expansion.
    #[cfg(test)]
    pub(super) fn read_paths_in(cwd: &Path, global_config: Option<&Path>) -> Result<Vec<String>> {
        run(Some(cwd), global_config)
    }

    fn run(cwd: Option<&Path>, global_config_override: Option<&Path>) -> Result<Vec<String>> {
        let mut cmd = Command::new("git");
        // `--show-scope` tags every line with the scope it came from
        // (`system` / `global` / `local` / `worktree` / `command`). The
        // parser keeps `global` and `system` lines and drops `local` /
        // `worktree` so an attacker-controlled per-repo .git/config
        // cannot widen the sandbox via the provider. `--global` as a
        // CLI scope filter would do the same job at the input boundary
        // but it disables include.path traversal under that scope (see
        // the regression test), losing the main reason this provider
        // exists.
        cmd.args(["config", "--list", "--show-origin", "--show-scope"]);
        if let Some(d) = cwd {
            cmd.current_dir(d);
        }
        if let Some(path) = global_config_override {
            cmd.env("GIT_CONFIG_GLOBAL", path);
            cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
        }
        let output = match cmd.output() {
            Ok(o) => o,
            // git missing or otherwise unspawnable: silently return empty.
            // The sandbox keeps whatever static paths the profile declares.
            Err(_) => return Ok(Vec::new()),
        };
        if !output.status.success() {
            return Ok(Vec::new());
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|e| NonoError::ProfileParse(format!("git config produced non-UTF-8: {e}")))?;
        Ok(read_paths_from_stdout(&stdout))
    }

    /// Parse the stdout of `git config --list --show-origin --show-scope`
    /// into the set of paths whose contents the git binary needs to read.
    ///
    /// Returns deduplicated absolute paths drawn from two sources:
    /// 1. `file:<path>` origins — every config file that contributed to
    ///    the effective config (including transitively-included files).
    /// 2. Values of well-known path-valued config keys (`core.attributesFile`,
    ///    `core.excludesFile`, `core.hooksPath`, `commit.template`) — these
    ///    point at files git itself opens at startup but which live outside
    ///    the config-file chain.
    ///
    /// Only lines tagged with the `global` or `system` scope are considered.
    /// `local` and `worktree` scopes are dropped because they come from
    /// per-repo `.git/config`, which is attacker-controlled in the
    /// clone-and-run threat model — a malicious clone could otherwise
    /// inject paths (`core.attributesFile=/etc/passwd`) and widen the
    /// sandbox.
    ///
    /// Non-`file:` origins (`cmdline:`, `blob:HEAD:…`, `standard input:`)
    /// are skipped — there is no filesystem path to grant. Path values
    /// are passed through verbatim so callers can resolve `~`/`$VAR` later
    /// via the usual profile expansion pipeline.
    pub(super) fn read_paths_from_stdout(stdout: &str) -> Vec<String> {
        use std::collections::BTreeSet;

        const PATH_VALUED_KEYS: &[&str] = &[
            "core.attributesfile",
            "core.excludesfile",
            "core.hookspath",
            "commit.template",
        ];
        const TRUSTED_SCOPES: &[&str] = &["global", "system"];

        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        let mut push = |path: String| {
            if !path.is_empty() && seen.insert(path.clone()) {
                out.push(path);
            }
        };

        for line in stdout.lines() {
            // Line shape: `<scope>\t<origin>\t<key>=<value>` (from
            // `--show-scope --show-origin`). Drop lines from untrusted
            // scopes (`local`, `worktree`, `command`) before doing
            // anything else.
            let Some((scope, after_scope)) = line.split_once('\t') else {
                continue;
            };
            if !TRUSTED_SCOPES.contains(&scope) {
                continue;
            }
            let Some((origin, rest)) = after_scope.split_once('\t') else {
                continue;
            };
            // Origin is one of `file:<path>`, `cmdline:`, `blob:<rev>:<path>`,
            // or `standard input:`. Only `file:` origins reference a path
            // we can grant read access to.
            if let Some(path) = origin.strip_prefix("file:") {
                push(path.to_string());
            }

            let Some((key, value)) = rest.split_once('=') else {
                continue;
            };
            // git config keys are case-insensitive on the section/name
            // portion. Normalize to lowercase for the comparison so user
            // configs that write `core.attributesFile` mixed-case still
            // match.
            if PATH_VALUED_KEYS.contains(&key.to_lowercase().as_str()) {
                push(value.to_string());
            }
        }
        out
    }
}

/// Built-in dispatcher: route `(provider, query)` to the appropriate
/// provider implementation. Returns an error for unknown providers so
/// typos and stale profile entries surface during finalize rather than
/// silently producing no paths.
fn dispatch_token(provider: &str, query: &str) -> Result<Vec<String>> {
    match provider {
        "git" => match query {
            "config-paths" => git::read_paths(),
            other => Err(NonoError::ProfileParse(format!(
                "unknown git provider query '{other}'"
            ))),
        },
        other => Err(NonoError::ProfileParse(format!(
            "unknown dynamic-token provider '{other}'"
        ))),
    }
}

/// Expand every dynamic-provider token across all access-granting path
/// lists in a profile, in place. Test seam: callers supply their own
/// resolver. Production code calls [`expand_profile_tokens`].
///
/// Fields walked: top-level `filesystem.{allow,read,write,allow_file,read_file,write_file}`
/// and per-command `mediation.commands[].sandbox.{fs_read,fs_read_file,fs_write,fs_write_file}`.
/// `deny`, `bypass_protection`, and `suppress_save_prompt` are deliberately
/// excluded — fanning a token out into deny rules has confusing
/// semantics (a single typo could deny a wide swath of the home dir);
/// `bypass_protection` / `suppress_save_prompt` are bookkeeping flags,
/// not capability grants.
fn expand_profile_tokens_with<F>(profile: &mut Profile, mut resolver: F) -> Result<()>
where
    F: FnMut(&str, &str) -> Result<Vec<String>>,
{
    let fs = &mut profile.filesystem;
    fs.allow = expand_path_list_with(&fs.allow, &mut resolver)?;
    fs.read = expand_path_list_with(&fs.read, &mut resolver)?;
    fs.write = expand_path_list_with(&fs.write, &mut resolver)?;
    fs.allow_file = expand_path_list_with(&fs.allow_file, &mut resolver)?;
    fs.read_file = expand_path_list_with(&fs.read_file, &mut resolver)?;
    fs.write_file = expand_path_list_with(&fs.write_file, &mut resolver)?;

    for cmd in &mut profile.mediation.commands {
        if let Some(sandbox) = cmd.sandbox.as_mut() {
            sandbox.fs_read = expand_path_list_with(&sandbox.fs_read, &mut resolver)?;
            sandbox.fs_read_file = expand_path_list_with(&sandbox.fs_read_file, &mut resolver)?;
            sandbox.fs_write = expand_path_list_with(&sandbox.fs_write, &mut resolver)?;
            sandbox.fs_write_file = expand_path_list_with(&sandbox.fs_write_file, &mut resolver)?;
        }
    }
    Ok(())
}

/// Expand every dynamic-provider token across all access-granting path
/// lists in a profile, in place, using the built-in providers.
pub(crate) fn expand_profile_tokens(profile: &mut Profile) -> Result<()> {
    expand_profile_tokens_with(profile, dispatch_token)
}

/// Expand a list of profile paths, replacing dynamic-provider tokens
/// inline with the expansion returned by `resolve`.
///
/// Literal paths pass through unchanged. Tokens are detected via
/// [`parse_token`]; each token is passed to `resolve(provider, query)` and
/// the returned paths are spliced into the output in place of the token.
/// The relative order of literal paths and per-token expansions is
/// preserved.
fn expand_path_list_with<F>(paths: &[String], mut resolve: F) -> Result<Vec<String>>
where
    F: FnMut(&str, &str) -> Result<Vec<String>>,
{
    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        match parse_token(path) {
            Some((provider, query)) => out.extend(resolve(provider, query)?),
            None => out.push(path.clone()),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_token_recognises_at_provider_colon_query() {
        assert_eq!(
            parse_token("@git:config-paths"),
            Some(("git", "config-paths"))
        );
    }

    #[test]
    fn parse_token_returns_none_for_literal_paths() {
        assert_eq!(parse_token("~/.gitconfig"), None);
        assert_eq!(parse_token("/etc/passwd"), None);
        assert_eq!(parse_token("$HOME/.gitconfig"), None);
    }

    #[test]
    fn parse_token_returns_none_for_at_without_colon() {
        // `@something` is unusual but treated as a literal path, not a token.
        assert_eq!(parse_token("@something"), None);
    }

    #[test]
    fn parse_token_returns_none_for_empty_string() {
        assert_eq!(parse_token(""), None);
    }

    #[test]
    fn expand_path_list_passes_literal_paths_through_unchanged() {
        let input = vec!["~/.gitconfig".to_string(), "/etc/static".to_string()];
        let out = expand_path_list_with(&input, |_, _| {
            panic!("resolver must not be called for literal paths")
        })
        .expect("literal pass-through");
        assert_eq!(out, vec!["~/.gitconfig", "/etc/static"]);
    }

    #[test]
    fn expand_path_list_splices_provider_output_in_place() {
        let input = vec![
            "~/.gitconfig".to_string(),
            "@git:config-paths".to_string(),
            "/etc/static".to_string(),
        ];
        let out = expand_path_list_with(&input, |provider, query| {
            assert_eq!(provider, "git");
            assert_eq!(query, "config-paths");
            Ok(vec!["/a".to_string(), "/b".to_string()])
        })
        .expect("expansion");
        assert_eq!(out, vec!["~/.gitconfig", "/a", "/b", "/etc/static"]);
    }

    #[test]
    fn git_read_paths_from_stdout_extracts_config_file_paths() {
        let stdout = "\
global\tfile:/home/u/.gitconfig\tuser.name=Alice
global\tfile:/home/u/.gitconfig\tuser.email=alice@example.com
global\tfile:/home/u/.gitconfig-work\tcommit.template=/tmp/template
command\tcmdline:\tcore.editor=vim
global\tfile:/home/u/.gitconfig\tinclude.path=~/.gitconfig-work
";
        let out = git::read_paths_from_stdout(stdout);
        assert!(out.contains(&"/home/u/.gitconfig".to_string()));
        assert!(out.contains(&"/home/u/.gitconfig-work".to_string()));
    }

    #[test]
    fn git_read_paths_from_stdout_dedupes_repeated_file_origins() {
        let stdout = "\
global\tfile:/home/u/.gitconfig\tuser.name=Alice
global\tfile:/home/u/.gitconfig\tuser.email=alice@example.com
global\tfile:/home/u/.gitconfig\tcore.editor=vim
";
        let out = git::read_paths_from_stdout(stdout);
        let count = out.iter().filter(|p| *p == "/home/u/.gitconfig").count();
        assert_eq!(count, 1, "got {:?}", out);
    }

    #[test]
    fn git_read_paths_from_stdout_ignores_non_file_origins() {
        // cmdline:, blob:, standard input — none of these are filesystem
        // paths we can grant read access to.
        let stdout = "\
command\tcmdline:\tcore.editor=vim
local\tblob:HEAD:.gitmodules\tsubmodule.foo.url=x
global\tstandard input:\tuser.name=Alice
";
        let out = git::read_paths_from_stdout(stdout);
        assert!(out.is_empty(), "got {:?}", out);
    }

    #[test]
    fn git_read_paths_from_stdout_drops_local_and_worktree_scopes() {
        // Threat model: attacker-controlled per-repo .git/config (scope
        // `local`) or per-worktree config (scope `worktree`) should
        // never widen the sandbox. Only `global` and `system` scopes
        // contribute paths.
        let stdout = "\
global\tfile:/home/u/.gitconfig\tcore.attributesFile=/home/u/.gitattributes
local\tfile:/repo/.git/config\tcore.attributesFile=/etc/passwd
worktree\tfile:/repo/.git/config.worktree\tcore.hooksPath=/etc/sudoers.d
system\tfile:/etc/gitconfig\tcommit.template=/etc/git-template
";
        let out = git::read_paths_from_stdout(stdout);
        assert!(out.contains(&"/home/u/.gitattributes".to_string()));
        assert!(out.contains(&"/etc/git-template".to_string()));
        assert!(out.contains(&"/home/u/.gitconfig".to_string()));
        assert!(out.contains(&"/etc/gitconfig".to_string()));
        assert!(
            !out.iter().any(|p| p == "/etc/passwd"),
            "local-scope path leaked: {out:?}"
        );
        assert!(
            !out.iter().any(|p| p == "/etc/sudoers.d"),
            "worktree-scope path leaked: {out:?}"
        );
        assert!(
            !out.iter().any(|p| p == "/repo/.git/config"),
            "local-scope origin leaked: {out:?}"
        );
    }

    #[test]
    fn git_read_paths_with_global_returns_config_file_and_path_values() {
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = tmp.path().join("gitconfig");
        {
            let mut f = std::fs::File::create(&cfg).expect("create gitconfig");
            writeln!(f, "[user]\n\tname = Test").expect("write user");
            writeln!(f, "[core]\n\tattributesFile = ~/.gitattributes-test")
                .expect("write attributesFile");
        }

        let paths = git::read_paths_with_global(&cfg).expect("git config");

        let cfg_str = cfg.to_str().expect("utf8 tempdir");
        assert!(
            paths.iter().any(|p| p == cfg_str),
            "expected gitconfig path {cfg_str} in output, got {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p == "~/.gitattributes-test"),
            "expected attributesFile value in output, got {paths:?}"
        );
    }

    #[test]
    fn git_read_paths_excludes_per_repo_local_config_overrides() {
        // Threat model: a malicious repo's .git/config could set
        // core.attributesFile=/etc/passwd (or include.path=/etc/shadow)
        // to widen the sandbox on a victim who runs the agent inside the
        // repo. The provider must restrict itself to global+system scope
        // so per-repo state cannot influence the expansion.
        use std::io::Write;
        use std::process::Command;

        let tmp = tempfile::tempdir().expect("tempdir");
        let global_cfg = tmp.path().join("global-gitconfig");
        let global_attrs = "/tmp/global-attributes-trusted";
        let evil_attrs = "/etc/passwd";

        {
            let mut f = std::fs::File::create(&global_cfg).expect("create global");
            writeln!(f, "[user]\n\tname = Test").expect("write user");
            writeln!(f, "[core]\n\tattributesFile = {global_attrs}").expect("write attrs");
        }

        // Hostile repo with a .git/config that tries to inject a path
        // outside the user's home directory. cwd here would be the
        // attacker-controlled clone.
        let repo = tmp.path().join("hostile-repo");
        std::fs::create_dir(&repo).expect("mkdir repo");
        let status = Command::new("git")
            .arg("init")
            .arg("--quiet")
            .current_dir(&repo)
            .status()
            .expect("git init");
        assert!(status.success(), "git init failed");
        let status = Command::new("git")
            .args(["config", "core.attributesFile", evil_attrs])
            .current_dir(&repo)
            .status()
            .expect("git config local");
        assert!(status.success(), "git config local failed");

        // Run the provider from inside the hostile repo with the trusted
        // global config in scope. Switching cwd directly is racy in tests,
        // so we use a thin shell-out helper that takes a cwd and uses the
        // same env-var test seam.
        let paths = git::read_paths_in(&repo, Some(&global_cfg)).expect("git config provider");

        assert!(
            paths.iter().any(|p| p == global_attrs),
            "global attributesFile missing, got {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p == evil_attrs),
            "per-repo attributesFile leaked into provider output (sandbox bypass), got {paths:?}"
        );
    }

    #[test]
    fn git_read_paths_with_global_walks_include_chain() {
        use std::io::Write;
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg = tmp.path().join("gitconfig");
        let work = tmp.path().join("gitconfig-work");
        {
            let mut f = std::fs::File::create(&work).expect("create work");
            writeln!(f, "[user]\n\temail = work@example.com").expect("write work");
        }
        {
            let mut f = std::fs::File::create(&cfg).expect("create main");
            writeln!(f, "[user]\n\tname = Test").expect("write user");
            writeln!(f, "[include]\n\tpath = {}", work.display()).expect("write include");
        }

        let paths = git::read_paths_with_global(&cfg).expect("git config");

        let cfg_str = cfg.to_str().expect("utf8");
        let work_str = work.to_str().expect("utf8");
        assert!(
            paths.iter().any(|p| p == cfg_str),
            "main gitconfig missing, got {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p == work_str),
            "included gitconfig-work missing, got {paths:?}"
        );
    }

    #[test]
    fn git_read_paths_from_stdout_extracts_path_valued_keys() {
        // core.attributesFile and friends point at files git itself wants
        // to read at startup. They live wherever the user puts them, and
        // missing entries from the sandbox cause "Operation not permitted"
        // warnings.
        let stdout = "\
global\tfile:/home/u/.gitconfig\tcore.attributesFile=~/.gitattributes
global\tfile:/home/u/.gitconfig\tcore.excludesFile=~/.gitexcludes
global\tfile:/home/u/.gitconfig\tcore.hooksPath=~/.githooks
global\tfile:/home/u/.gitconfig\tcommit.template=~/.gitmessage
global\tfile:/home/u/.gitconfig\tuser.name=Alice
";
        let out = git::read_paths_from_stdout(stdout);
        assert!(out.contains(&"~/.gitattributes".to_string()));
        assert!(out.contains(&"~/.gitexcludes".to_string()));
        assert!(out.contains(&"~/.githooks".to_string()));
        assert!(out.contains(&"~/.gitmessage".to_string()));
    }

    #[test]
    fn dispatch_token_errors_on_unknown_provider() {
        let err = dispatch_token("unknown", "anything").expect_err("expected unknown-provider");
        let msg = format!("{err}");
        assert!(
            msg.contains("unknown") && msg.contains("provider"),
            "error should name the unknown provider, got: {msg}"
        );
    }

    #[test]
    fn dispatch_token_errors_on_unknown_git_query() {
        let err = dispatch_token("git", "nonsense").expect_err("expected unknown-query");
        let msg = format!("{err}");
        assert!(
            msg.contains("git") && msg.contains("nonsense"),
            "error should name the unknown query, got: {msg}"
        );
    }

    #[test]
    fn expand_profile_tokens_walks_filesystem_read_file() {
        let mut profile = Profile::default();
        profile.filesystem.read_file =
            vec!["~/.gitconfig".to_string(), "@git:config-paths".to_string()];
        expand_profile_tokens_with(&mut profile, |_, _| Ok(vec!["/expanded/path".to_string()]))
            .expect("profile token expansion");
        assert_eq!(
            profile.filesystem.read_file,
            vec!["~/.gitconfig", "/expanded/path"]
        );
    }

    #[test]
    fn expand_profile_tokens_walks_per_command_sandbox_fs_read_file() {
        let mut profile = Profile::default();
        profile
            .mediation
            .commands
            .push(crate::mediation::CommandEntry {
                name: "git".to_string(),
                binary_path: None,
                intercept: vec![],
                sandbox: Some(crate::mediation::CommandSandbox {
                    fs_read_file: vec!["@git:config-paths".to_string()],
                    ..Default::default()
                }),
                caller_policy: Default::default(),
            });
        expand_profile_tokens_with(&mut profile, |_, _| Ok(vec!["/x".to_string()]))
            .expect("per-command expansion");
        let sandbox = profile.mediation.commands[0]
            .sandbox
            .as_ref()
            .expect("sandbox preserved after expansion");
        assert_eq!(sandbox.fs_read_file, vec!["/x"]);
    }

    #[test]
    fn expand_path_list_propagates_resolver_errors() {
        let input = vec!["@git:config-paths".to_string()];
        let err = expand_path_list_with(&input, |_, _| {
            Err(nono::NonoError::ProfileParse("boom".to_string()))
        })
        .expect_err("resolver error must propagate");
        assert!(format!("{err}").contains("boom"));
    }
}
