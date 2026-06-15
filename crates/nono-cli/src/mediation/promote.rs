//! Compiled form of `PromoteFilter`.
//!
//! Profile load compiles every regex in the predicate tree once via
//! `compile_promote_filter`. The hot path then walks the tree per slot:
//! `ResolvedPromoteFilter::allows_arg(args, i)` for argv slots and
//! `ResolvedPromoteFilter::allows_env(name, value)` for env entries. Errors
//! at compile time surface as `NonoError::SandboxInit` so a bad profile
//! fails fast.
//!
//! Defaults are secure: when the filter is absent (or its `args` sub-field
//! is absent), no argv slot is admitted for promotion — profile authors
//! must declare which argv slots may receive a credential. When the env
//! sub-field is absent, the built-in safe-shape allowlist
//! ([`PROMOTE_ENV_DEFAULT_NAMES`]) decides.

use crate::mediation::{ArgPredicate, EnvPredicate, PromoteFilter};
use nono::{NonoError, Result};
use regex::Regex;
use std::sync::OnceLock;

/// Built-in safe-shape env var name allowlist used when `PromoteFilter::env`
/// is absent.
///
/// Case-insensitive (ASCII). The `(?i-u)` flag turns on case-insensitive
/// matching with Unicode mode disabled — nono builds its `regex` crate
/// without the `unicode-case` feature, and these names are ASCII
/// conventions anyway (`AUTHORIZATION`, `*_TOKEN`, etc.). The prefix
/// class is restricted to `[A-Za-z0-9_]+` so the regex engine does not
/// see a wildcard that could match invalid UTF-8 bytes in non-Unicode
/// mode. Profiles that need a wider window declare a custom
/// `EnvPredicate` that unions this regex with their additional names.
pub const PROMOTE_ENV_DEFAULT_NAMES: &str =
    r"(?i-u)^(authorization|[A-Za-z0-9_]+_(token|header|key|secret|password|credentials|auth))$";

/// Compiled `ArgPredicate`. Each `Regex` is built once at session start.
#[derive(Clone, Debug)]
pub enum ResolvedArgPredicate {
    AllOf(Vec<ResolvedArgPredicate>),
    AnyOf(Vec<ResolvedArgPredicate>),
    Not(Box<ResolvedArgPredicate>),
    SelfMatches(Regex),
    PrecededByArg(Regex),
    AtIndex(usize),
}

impl ResolvedArgPredicate {
    /// Evaluate this predicate against argv slot `i`.
    fn matches(&self, args: &[String], i: usize) -> bool {
        match self {
            Self::AllOf(children) => children.iter().all(|c| c.matches(args, i)),
            Self::AnyOf(children) => children.iter().any(|c| c.matches(args, i)),
            Self::Not(child) => !child.matches(args, i),
            Self::SelfMatches(re) => args.get(i).map(|a| re.is_match(a)).unwrap_or(false),
            Self::PrecededByArg(re) => {
                if i == 0 {
                    return false;
                }
                args.get(i - 1).map(|a| re.is_match(a)).unwrap_or(false)
            }
            Self::AtIndex(idx) => i == *idx,
        }
    }
}

/// Compiled `EnvPredicate`.
#[derive(Clone, Debug)]
pub enum ResolvedEnvPredicate {
    AllOf(Vec<ResolvedEnvPredicate>),
    AnyOf(Vec<ResolvedEnvPredicate>),
    Not(Box<ResolvedEnvPredicate>),
    NameMatches(Regex),
    ValueMatches(Regex),
}

impl ResolvedEnvPredicate {
    fn matches(&self, name: &str, value: &str) -> bool {
        match self {
            Self::AllOf(children) => children.iter().all(|c| c.matches(name, value)),
            Self::AnyOf(children) => children.iter().any(|c| c.matches(name, value)),
            Self::Not(child) => !child.matches(name, value),
            Self::NameMatches(re) => re.is_match(name),
            Self::ValueMatches(re) => re.is_match(value),
        }
    }
}

/// Compiled `PromoteFilter`. Either sub-predicate may be `None`; absent =
/// fall through to the secure default for that scope.
#[derive(Clone, Debug)]
pub struct ResolvedPromoteFilter {
    pub args: Option<ResolvedArgPredicate>,
    pub env: Option<ResolvedEnvPredicate>,
}

impl ResolvedPromoteFilter {
    /// Decide whether argv slot `i` is admissible for nonce promotion.
    ///
    /// Static-style: takes an `Option<&Self>` so the "no filter declared"
    /// case can be handled in one place. The secure default is no
    /// promotion — every argv slot stays literal until the profile says
    /// otherwise.
    pub fn allows_arg(filter: Option<&Self>, args: &[String], i: usize) -> bool {
        match filter.and_then(|f| f.args.as_ref()) {
            Some(p) => p.matches(args, i),
            None => false,
        }
    }

    /// Decide whether an env var (`name`, `value`) is admissible for nonce
    /// promotion.
    ///
    /// Static-style for symmetry with `allows_arg`. When the filter or its
    /// `env` sub-predicate is absent the built-in safe-shape allowlist
    /// ([`PROMOTE_ENV_DEFAULT_NAMES`]) decides — names that match flow
    /// promotion, names that don't stay literal.
    pub fn allows_env(filter: Option<&Self>, name: &str, value: &str) -> bool {
        match filter.and_then(|f| f.env.as_ref()) {
            Some(p) => p.matches(name, value),
            None => default_env_regex().is_match(name),
        }
    }
}

/// Compile a parsed `PromoteFilter` into its resolved form. Regex compile
/// errors surface as `NonoError::SandboxInit` with a profile-friendly
/// message keyed by command name.
pub fn compile_promote_filter(
    p: &PromoteFilter,
    command: &str,
) -> Result<ResolvedPromoteFilter> {
    let args = match &p.args {
        Some(a) => Some(compile_arg_predicate(a, command)?),
        None => None,
    };
    let env = match &p.env {
        Some(e) => Some(compile_env_predicate(e, command)?),
        None => None,
    };
    Ok(ResolvedPromoteFilter { args, env })
}

fn compile_arg_predicate(p: &ArgPredicate, command: &str) -> Result<ResolvedArgPredicate> {
    Ok(match p {
        ArgPredicate::AllOf { all_of } => ResolvedArgPredicate::AllOf(
            all_of
                .iter()
                .map(|c| compile_arg_predicate(c, command))
                .collect::<Result<Vec<_>>>()?,
        ),
        ArgPredicate::AnyOf { any_of } => ResolvedArgPredicate::AnyOf(
            any_of
                .iter()
                .map(|c| compile_arg_predicate(c, command))
                .collect::<Result<Vec<_>>>()?,
        ),
        ArgPredicate::Not { not } => {
            ResolvedArgPredicate::Not(Box::new(compile_arg_predicate(not, command)?))
        }
        ArgPredicate::SelfMatches { self_matches } => {
            ResolvedArgPredicate::SelfMatches(compile_re(self_matches, command)?)
        }
        ArgPredicate::PrecededByArg { preceded_by_arg } => {
            ResolvedArgPredicate::PrecededByArg(compile_re(preceded_by_arg, command)?)
        }
        ArgPredicate::AtIndex { at_index } => ResolvedArgPredicate::AtIndex(*at_index),
    })
}

fn compile_env_predicate(p: &EnvPredicate, command: &str) -> Result<ResolvedEnvPredicate> {
    Ok(match p {
        EnvPredicate::AllOf { all_of } => ResolvedEnvPredicate::AllOf(
            all_of
                .iter()
                .map(|c| compile_env_predicate(c, command))
                .collect::<Result<Vec<_>>>()?,
        ),
        EnvPredicate::AnyOf { any_of } => ResolvedEnvPredicate::AnyOf(
            any_of
                .iter()
                .map(|c| compile_env_predicate(c, command))
                .collect::<Result<Vec<_>>>()?,
        ),
        EnvPredicate::Not { not } => {
            ResolvedEnvPredicate::Not(Box::new(compile_env_predicate(not, command)?))
        }
        EnvPredicate::NameMatches { name_matches } => {
            ResolvedEnvPredicate::NameMatches(compile_re(name_matches, command)?)
        }
        EnvPredicate::ValueMatches { value_matches } => {
            ResolvedEnvPredicate::ValueMatches(compile_re(value_matches, command)?)
        }
    })
}

fn compile_re(pattern: &str, command: &str) -> Result<Regex> {
    Regex::new(pattern).map_err(|e| {
        NonoError::SandboxInit(format!(
            "mediation: command '{}' promote_in: invalid regex '{}': {}",
            command, pattern, e
        ))
    })
}

fn default_env_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(PROMOTE_ENV_DEFAULT_NAMES)
            .expect("PROMOTE_ENV_DEFAULT_NAMES must be a valid regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediation::PromoteFilter;
    use serde_json::json;

    fn filter(value: serde_json::Value) -> ResolvedPromoteFilter {
        let p: PromoteFilter = serde_json::from_value(value).expect("parse");
        compile_promote_filter(&p, "test").expect("compile")
    }

    fn args(strs: &[&str]) -> Vec<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }

    // ---- ArgPredicate leaves ----

    #[test]
    fn self_matches_admits_matching_slot_only() {
        let f = filter(json!({ "args": { "self_matches": "^-H" } }));
        let argv = args(&["-Hnono_x", "https://x"]);
        assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 0));
        assert!(!ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 1));
    }

    #[test]
    fn preceded_by_arg_admits_slot_after_match() {
        let f = filter(json!({ "args": { "preceded_by_arg": "^(-H|--header)$" } }));
        let argv = args(&["-H", "Authorization: Bearer X"]);
        assert!(!ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 0));
        assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 1));
    }

    #[test]
    fn preceded_by_arg_index_zero_does_not_panic_or_match() {
        // argv[0] has no left neighbour. Must return false rather than
        // attempt to read args[-1].
        let f = filter(json!({ "args": { "preceded_by_arg": "anything" } }));
        let argv = args(&["only"]);
        assert!(!ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 0));
    }

    #[test]
    fn at_index_pins_exact_position() {
        let f = filter(json!({ "args": { "at_index": 3 } }));
        let argv = args(&["a", "b", "c", "d", "e"]);
        for i in 0..argv.len() {
            assert_eq!(
                ResolvedPromoteFilter::allows_arg(Some(&f), &argv, i),
                i == 3,
                "i={}",
                i
            );
        }
    }

    // ---- ArgPredicate combinators ----

    #[test]
    fn any_of_unions_children() {
        let f = filter(json!({
            "args": {
                "any_of": [
                    { "preceded_by_arg": "^-H$" },
                    { "self_matches": "^-H" }
                ]
            }
        }));
        // Attached form: -Hnono_x at slot 0 matches via self_matches.
        let attached = args(&["-Hnono_x"]);
        assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &attached, 0));
        // Separate form: ["-H", "Authorization: ..."] matches at slot 1 via
        // preceded_by_arg and at slot 0 via self_matches (`-H` itself).
        let separate = args(&["-H", "Authorization: Bearer X"]);
        assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &separate, 0));
        assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &separate, 1));
    }

    #[test]
    fn all_of_intersects_children() {
        let f = filter(json!({
            "args": {
                "all_of": [
                    { "self_matches": "^Authorization:" },
                    { "preceded_by_arg": "^-H$" }
                ]
            }
        }));
        let argv = args(&["-H", "Authorization: Bearer X", "Authorization: Bearer Y"]);
        // Slot 1 matches both.
        assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 1));
        // Slot 2 matches self_matches but its predecessor is the
        // previous header value, not `-H` — fails the all_of.
        assert!(!ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 2));
    }

    #[test]
    fn not_inverts_inner() {
        let f = filter(json!({
            "args": { "not": { "preceded_by_arg": "^(-d|--data-binary)$" } }
        }));
        let argv = args(&["--data-binary", "X: nono", "-H", "Authorization"]);
        // Slot 1 is after --data-binary → inner true → not = false.
        assert!(!ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 1));
        // Slot 3 is after -H → inner false → not = true.
        assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &argv, 3));
    }

    #[test]
    fn empty_any_of_never_promotes() {
        // Defensive lock: an explicit empty any_of: [] should never admit
        // any slot. Same outcome as absent args, distinct DSL path.
        let f = filter(json!({ "args": { "any_of": [] } }));
        let argv = args(&["any", "args", "here"]);
        for i in 0..argv.len() {
            assert!(!ResolvedPromoteFilter::allows_arg(Some(&f), &argv, i));
        }
    }

    #[test]
    fn empty_all_of_always_promotes_vacuously() {
        let f = filter(json!({ "args": { "all_of": [] } }));
        let argv = args(&["any", "args"]);
        for i in 0..argv.len() {
            assert!(ResolvedPromoteFilter::allows_arg(Some(&f), &argv, i));
        }
    }

    // ---- Secure defaults for args ----

    #[test]
    fn no_filter_admits_no_argv_slot() {
        // Secure default: an intercept without any promote_in field gets
        // no argv promotion at all.
        let argv = args(&["-H", "Authorization: Bearer nono_x"]);
        for i in 0..argv.len() {
            assert!(!ResolvedPromoteFilter::allows_arg(None, &argv, i));
        }
    }

    #[test]
    fn env_only_filter_admits_no_argv_slot() {
        // A promote_in that declares only env config still leaves argv at
        // the secure default (no promotion).
        let f = filter(json!({
            "env": { "name_matches": "^AUTH_HEADER$" }
        }));
        let argv = args(&["-H", "Authorization: Bearer nono_x"]);
        for i in 0..argv.len() {
            assert!(!ResolvedPromoteFilter::allows_arg(Some(&f), &argv, i));
        }
    }

    // ---- EnvPredicate ----

    #[test]
    fn explicit_env_name_predicate_admits_matching_name() {
        let f = filter(json!({
            "env": { "name_matches": "^MY_VAR$" }
        }));
        // Replaces the default — AUTH_HEADER no longer promotes.
        assert!(!ResolvedPromoteFilter::allows_env(
            Some(&f),
            "AUTH_HEADER",
            "Bearer X"
        ));
        assert!(ResolvedPromoteFilter::allows_env(
            Some(&f),
            "MY_VAR",
            "anything"
        ));
    }

    #[test]
    fn explicit_env_union_widens_default() {
        // Documented widening pattern: union the default regex with a
        // custom name to keep the safe-shape allowlist AND admit a
        // bespoke env var.
        let f = filter(json!({
            "env": {
                "any_of": [
                    { "name_matches": PROMOTE_ENV_DEFAULT_NAMES },
                    { "name_matches": "^MY_CUSTOM_NONCE_VAR$" }
                ]
            }
        }));
        assert!(ResolvedPromoteFilter::allows_env(
            Some(&f),
            "AUTH_HEADER",
            "Bearer X"
        ));
        assert!(ResolvedPromoteFilter::allows_env(
            Some(&f),
            "MY_CUSTOM_NONCE_VAR",
            "nono_y"
        ));
        assert!(!ResolvedPromoteFilter::allows_env(
            Some(&f),
            "RANDOM_NAME",
            "nono_z"
        ));
    }

    #[test]
    fn env_not_inverts_inner() {
        let f = filter(json!({
            "env": { "not": { "name_matches": "^DD_API_KEY$" } }
        }));
        assert!(!ResolvedPromoteFilter::allows_env(
            Some(&f),
            "DD_API_KEY",
            "raw"
        ));
        assert!(ResolvedPromoteFilter::allows_env(
            Some(&f),
            "ANYTHING_ELSE",
            "raw"
        ));
    }

    #[test]
    fn env_value_matches_checks_value() {
        let f = filter(json!({
            "env": { "value_matches": "^Bearer " }
        }));
        assert!(ResolvedPromoteFilter::allows_env(
            Some(&f),
            "ANY_NAME",
            "Bearer nono_x"
        ));
        assert!(!ResolvedPromoteFilter::allows_env(
            Some(&f),
            "ANY_NAME",
            "plain text"
        ));
    }

    // ---- Built-in env default ----

    #[test]
    fn no_filter_uses_builtin_env_default() {
        // AUTH_HEADER matches the default's `.+_header` pattern.
        assert!(ResolvedPromoteFilter::allows_env(
            None,
            "AUTH_HEADER",
            "Bearer X"
        ));
        // MY_VAR does not.
        assert!(!ResolvedPromoteFilter::allows_env(
            None, "MY_VAR", "Bearer X"
        ));
    }

    #[test]
    fn args_only_filter_still_uses_builtin_env_default() {
        let f = filter(json!({
            "args": { "self_matches": "^-H" }
        }));
        assert!(ResolvedPromoteFilter::allows_env(
            Some(&f),
            "AUTH_HEADER",
            "X"
        ));
        assert!(!ResolvedPromoteFilter::allows_env(
            Some(&f),
            "MY_VAR",
            "X"
        ));
    }

    #[test]
    fn builtin_env_default_is_case_insensitive() {
        assert!(ResolvedPromoteFilter::allows_env(
            None,
            "authorization",
            "Bearer X"
        ));
        assert!(ResolvedPromoteFilter::allows_env(
            None, "Foo_Token", "X"
        ));
    }

    #[test]
    fn builtin_env_default_admits_canonical_shapes() {
        for name in [
            "AUTHORIZATION",
            "FOO_TOKEN",
            "X_HEADER",
            "BAR_KEY",
            "BAZ_SECRET",
            "QUX_PASSWORD",
            "FOO_CREDENTIALS",
            "BAR_AUTH",
        ] {
            assert!(
                ResolvedPromoteFilter::allows_env(None, name, "x"),
                "expected default to admit {}",
                name
            );
        }
    }

    #[test]
    fn builtin_env_default_rejects_unanchored_or_prefixed_shapes() {
        for name in ["MY_VAR", "RANDOM_NAME", "TOKEN_PREFIX"] {
            assert!(
                !ResolvedPromoteFilter::allows_env(None, name, "x"),
                "expected default to reject {}",
                name
            );
        }
    }

    // ---- Compile-error surface ----

    #[test]
    fn malformed_arg_self_matches_regex_surfaces_command_name() {
        let p: PromoteFilter = serde_json::from_value(json!({
            "args": { "self_matches": "(unclosed" }
        }))
        .unwrap();
        let err = compile_promote_filter(&p, "curl").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("curl"), "msg: {}", msg);
        assert!(msg.contains("(unclosed"), "msg: {}", msg);
        assert!(msg.contains("promote_in"), "msg: {}", msg);
    }

    #[test]
    fn malformed_arg_preceded_by_arg_regex_surfaces_command_name() {
        let p: PromoteFilter = serde_json::from_value(json!({
            "args": { "preceded_by_arg": "[unclosed" }
        }))
        .unwrap();
        let err = compile_promote_filter(&p, "git").unwrap_err();
        assert!(format!("{}", err).contains("git"));
    }

    #[test]
    fn malformed_env_name_regex_surfaces_command_name() {
        let p: PromoteFilter = serde_json::from_value(json!({
            "env": { "name_matches": "(*)" }
        }))
        .unwrap();
        let err = compile_promote_filter(&p, "glab").unwrap_err();
        assert!(format!("{}", err).contains("glab"));
    }

    // ---- Public constant ----

    #[test]
    fn promote_env_default_names_regex_compiles() {
        let _ = Regex::new(PROMOTE_ENV_DEFAULT_NAMES).expect("must compile");
    }
}
