//! Compiled form of `ArgsMatcher`.
//!
//! Profile load compiles every regex in the matcher tree once via
//! `compile_args_matcher`. The hot path then walks the tree per invocation
//! and matches argv via `ResolvedArgsMatcher::matches`. Errors at compile
//! time surface as `NonoError::SandboxInit` so a bad profile fails fast.

use crate::mediation::ArgsMatcher;
use nono::{NonoError, Result};
use regex::Regex;

/// Compiled predicate tree. Each `Regex` is built once at session start.
#[derive(Clone, Debug)]
pub enum ResolvedArgsMatcher {
    All(Vec<ResolvedArgsMatcher>),
    Any(Vec<ResolvedArgsMatcher>),
    Not(Box<ResolvedArgsMatcher>),
    AnyArgMatches(Regex),
    AllArgsMatch(Regex),
    NthArgMatches { index: usize, regex: Regex },
}

impl ResolvedArgsMatcher {
    /// Evaluate against an invocation's argv. Argv slots include flags.
    pub fn matches(&self, args: &[String]) -> bool {
        match self {
            Self::All(children) => children.iter().all(|c| c.matches(args)),
            Self::Any(children) => children.iter().any(|c| c.matches(args)),
            Self::Not(child) => !child.matches(args),
            Self::AnyArgMatches(re) => args.iter().any(|a| re.is_match(a)),
            Self::AllArgsMatch(re) => args.iter().all(|a| re.is_match(a)),
            Self::NthArgMatches { index, regex } => args
                .get(*index)
                .map(|a| regex.is_match(a))
                .unwrap_or(false),
        }
    }
}

/// Compile a parsed `ArgsMatcher` into its resolved form. Regex compile
/// errors surface as `NonoError::SandboxInit` with a profile-friendly message.
pub fn compile_args_matcher(m: &ArgsMatcher, command: &str) -> Result<ResolvedArgsMatcher> {
    Ok(match m {
        ArgsMatcher::All { all } => ResolvedArgsMatcher::All(
            all.iter()
                .map(|c| compile_args_matcher(c, command))
                .collect::<Result<Vec<_>>>()?,
        ),
        ArgsMatcher::Any { any } => ResolvedArgsMatcher::Any(
            any.iter()
                .map(|c| compile_args_matcher(c, command))
                .collect::<Result<Vec<_>>>()?,
        ),
        ArgsMatcher::Not { not } => {
            ResolvedArgsMatcher::Not(Box::new(compile_args_matcher(not, command)?))
        }
        ArgsMatcher::AnyArgMatches { any_arg_matches } => {
            ResolvedArgsMatcher::AnyArgMatches(compile_re(any_arg_matches, command)?)
        }
        ArgsMatcher::AllArgsMatch { all_args_match } => {
            ResolvedArgsMatcher::AllArgsMatch(compile_re(all_args_match, command)?)
        }
        ArgsMatcher::NthArgMatches {
            nth_arg_matches,
            regex,
        } => ResolvedArgsMatcher::NthArgMatches {
            index: *nth_arg_matches,
            regex: compile_re(regex, command)?,
        },
    })
}

fn compile_re(pattern: &str, command: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: command '{}': invalid regex '{}': {}",
            command, pattern, e
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::ArgsMatcher;
    use serde_json::json;

    fn matcher(value: serde_json::Value) -> ResolvedArgsMatcher {
        let m: ArgsMatcher = serde_json::from_value(value).expect("parse");
        compile_args_matcher(&m, "test").expect("compile")
    }

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn any_arg_matches_finds_match_anywhere() {
        let m = matcher(json!({ "any_arg_matches": "^https://example\\.com" }));
        assert!(m.matches(&args(&["-X", "GET", "https://example.com/foo"])));
        assert!(!m.matches(&args(&["-X", "GET", "https://evil.com/foo"])));
    }

    #[test]
    fn nth_arg_matches_uses_zero_based_index() {
        let m = matcher(json!({ "nth_arg_matches": 0, "regex": "^-X$" }));
        assert!(m.matches(&args(&["-X", "GET"])));
        assert!(!m.matches(&args(&["GET", "-X"])));
    }

    #[test]
    fn nth_arg_out_of_range_does_not_match() {
        let m = matcher(json!({ "nth_arg_matches": 9, "regex": "anything" }));
        assert!(!m.matches(&args(&["one"])));
    }

    #[test]
    fn all_combines_children_with_and() {
        let m = matcher(json!({
            "all": [
                { "any_arg_matches": "^https://" },
                { "not": { "any_arg_matches": "--insecure" } }
            ]
        }));
        assert!(m.matches(&args(&["https://x"])));
        assert!(!m.matches(&args(&["https://x", "--insecure"])));
        assert!(!m.matches(&args(&["http://x"])));
    }

    #[test]
    fn any_combines_children_with_or() {
        let m = matcher(json!({
            "any": [
                { "nth_arg_matches": 0, "regex": "^pull$" },
                { "nth_arg_matches": 0, "regex": "^push$" }
            ]
        }));
        assert!(m.matches(&args(&["pull"])));
        assert!(m.matches(&args(&["push"])));
        assert!(!m.matches(&args(&["fetch"])));
    }

    #[test]
    fn empty_all_is_vacuously_true_empty_any_is_vacuously_false() {
        assert!(matcher(json!({ "all": [] })).matches(&[]));
        assert!(!matcher(json!({ "any": [] })).matches(&[]));
    }

    #[test]
    fn perl_character_classes_compile_and_match() {
        // \s, \d, \w require the unicode-perl regex feature. Without it,
        // Regex::new() returns an error at profile-load time, silently
        // breaking any intercept rule that uses these patterns.
        let m = matcher(json!({ "any_arg_matches": r"^\s*--flag\s*$" }));
        assert!(m.matches(&args(&["  --flag  "])));
        assert!(!m.matches(&args(&["--flag-extra"])));

        let m = matcher(json!({ "any_arg_matches": r"^\d+$" }));
        assert!(m.matches(&args(&["123"])));
        assert!(!m.matches(&args(&["abc"])));

        let m = matcher(json!({ "any_arg_matches": r"^\w+$" }));
        assert!(m.matches(&args(&["hello_world"])));
        assert!(!m.matches(&args(&["hello world"])));
    }

    #[test]
    fn compile_reports_bad_regex_with_command_name() {
        let m: ArgsMatcher =
            serde_json::from_value(json!({ "any_arg_matches": "(unclosed" })).unwrap();
        let err = compile_args_matcher(&m, "curl").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("curl"), "msg: {}", msg);
        assert!(msg.contains("(unclosed"), "msg: {}", msg);
    }

}
