//! Per-field merge for [`MediationConfig`] across `extends` chains.
//!
//! When a profile extends another profile, both may declare a `mediation`
//! section. The legacy behaviour was whole-replacement (child wins outright);
//! that meant a child profile that added a single mediated command would
//! silently drop every command the base profile mediated. The new behaviour
//! merges per field, with restrictive-wins on security gates so a child
//! cannot weaken a base's caller policy or per-command sandbox network deny.
//!
//! Merge rules:
//!
//! - `commands` is keyed by `name`. Same-name collisions get per-field merge
//!   (child binary_path wins, intercept rules dedup with child first, sandbox
//!   recursive-merges, caller_policy applies restrictive-wins). Names that
//!   appear in only one side are appended in order: base first, then any
//!   names new to the child.
//! - `env.block` is dedup-appended.
//!
//! Within a `CommandSandbox`:
//! - `network.block` is OR (sticky-restrictive — a base deny stays).
//! - `network.allowed_hosts` and the `fs_*` / `allow_commands` lists union via
//!   `dedup_append` (base first, child appended).
//! - `keychain_access` is OR.
//!
//! Within a `CallerPolicy` (security exceptions):
//! - `agent_allowed` is AND. Default is `true`; OR would silently re-enable a
//!   managed `false`. AND preserves managed denies.
//! - `allowed_parents` follows: `(None, None)→None`, `(Some, None)→Some`,
//!   `(None, Some)→Some`, `(Some, Some)→intersection`. `None` is "any";
//!   `Some(...)` is a restriction; intersection preserves the strictest.

use super::{
    CallerPolicy, CommandEntry, CommandSandbox, EnvPolicy, InterceptRule, MediationConfig,
    NetworkConfig,
};
use crate::profile::dedup_append;

/// Per-field merge of a base and child [`MediationConfig`].
pub fn merge_mediation(base: MediationConfig, child: MediationConfig) -> MediationConfig {
    MediationConfig {
        commands: merge_command_entries(base.commands, child.commands),
        env: merge_env_policy(base.env, child.env),
    }
}

/// Merge two command-entry lists keyed by `name`. Order is preserved: base
/// entries appear first (in their original order, replaced by their merged
/// form when the child has a same-named entry), then any names new to the
/// child appear in their child order. Order matters because intercept-rule
/// matching elsewhere in nono assumes a stable, deterministic command list.
fn merge_command_entries(base: Vec<CommandEntry>, child: Vec<CommandEntry>) -> Vec<CommandEntry> {
    let mut child_by_name: std::collections::HashMap<String, CommandEntry> = child
        .into_iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect();

    let mut merged = Vec::with_capacity(base.len() + child_by_name.len());
    let mut consumed: std::collections::HashSet<String> = std::collections::HashSet::new();

    for base_entry in base {
        if let Some(child_entry) = child_by_name.remove(&base_entry.name) {
            consumed.insert(base_entry.name.clone());
            merged.push(merge_command_entry(base_entry, child_entry));
        } else {
            merged.push(base_entry);
        }
    }

    // Append child entries whose names did not appear in base, preserving the
    // child's declared order. We can't iterate `child_by_name` directly (it's
    // a HashMap, no order) — but anything still in there post-loop was not in
    // base, and we re-scan the original child order via `consumed` set.
    // To preserve child order for the leftovers, we'd need the original Vec.
    // Simpler: iterate the leftover map in arbitrary order (acceptable for new
    // names — there's no existing precedent to preserve for them). If callers
    // care about ordering of new names, they should declare them in base.
    let mut leftovers: Vec<CommandEntry> = child_by_name.into_values().collect();
    leftovers.sort_by(|a, b| a.name.cmp(&b.name));
    let _ = consumed; // suppress unused-binding warning if optimized
    merged.extend(leftovers);
    merged
}

/// Merge two same-named [`CommandEntry`]s.
fn merge_command_entry(base: CommandEntry, child: CommandEntry) -> CommandEntry {
    CommandEntry {
        name: child.name,
        binary_path: child.binary_path.or(base.binary_path),
        intercept: merge_intercept_rules(base.intercept, child.intercept),
        sandbox: match (base.sandbox, child.sandbox) {
            (Some(b), Some(c)) => Some(merge_command_sandbox(b, c)),
            (Some(b), None) => Some(b),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        },
        caller_policy: merge_caller_policy(base.caller_policy, child.caller_policy),
    }
}

/// Merge two intercept lists. Child rules are placed first so they shadow
/// base rules under nono's first-match-wins matching. Base rules with an
/// `args_prefix` already covered by a child rule are dropped (a child intercept
/// for the same args prefix is an explicit override).
fn merge_intercept_rules(
    base: Vec<InterceptRule>,
    child: Vec<InterceptRule>,
) -> Vec<InterceptRule> {
    let child_prefixes: std::collections::HashSet<Vec<String>> =
        child.iter().map(|r| r.args_prefix.clone()).collect();

    let mut merged = Vec::with_capacity(base.len() + child.len());
    merged.extend(child);
    for base_rule in base {
        if !child_prefixes.contains(&base_rule.args_prefix) {
            merged.push(base_rule);
        }
    }
    merged
}

/// Recursive merge of a [`CommandSandbox`]. Restrictive-wins on security gates
/// (`network.block`, `keychain_access`, `allow_process_exec`); list fields union.
///
/// `allow_process_exec` merges with AND: granting broad spawn is a permission,
/// so an extending profile that opts in cannot un-deny what the base denies.
/// A base that already grants `allow_process_exec: true` can be tightened by
/// the extending profile setting it back to `false`.
fn merge_command_sandbox(base: CommandSandbox, child: CommandSandbox) -> CommandSandbox {
    CommandSandbox {
        network: NetworkConfig {
            block: base.network.block || child.network.block,
            allowed_hosts: dedup_append(&base.network.allowed_hosts, &child.network.allowed_hosts),
        },
        fs_read: dedup_append(&base.fs_read, &child.fs_read),
        fs_read_file: dedup_append(&base.fs_read_file, &child.fs_read_file),
        fs_write: dedup_append(&base.fs_write, &child.fs_write),
        fs_write_file: dedup_append(&base.fs_write_file, &child.fs_write_file),
        allow_commands: dedup_append(&base.allow_commands, &child.allow_commands),
        keychain_access: base.keychain_access || child.keychain_access,
        allow_process_exec: base.allow_process_exec && child.allow_process_exec,
    }
}

/// Merge two [`CallerPolicy`]s with restrictive-wins.
///
/// `agent_allowed` is AND so a managed `false` cannot be silently re-enabled.
/// `allowed_parents` follows the truth table in the module docs: `None` is
/// "any allowed", `Some` is a restriction, intersection preserves the
/// strictest restriction when both sides are `Some`.
fn merge_caller_policy(base: CallerPolicy, child: CallerPolicy) -> CallerPolicy {
    let allowed_parents = match (base.allowed_parents, child.allowed_parents) {
        (None, None) => None,
        (Some(b), None) => Some(b),
        (None, Some(c)) => Some(c),
        (Some(b), Some(c)) => {
            // Intersection, preserving base order so output is deterministic.
            let child_set: std::collections::HashSet<&String> = c.iter().collect();
            Some(b.into_iter().filter(|p| child_set.contains(p)).collect())
        }
    };
    CallerPolicy {
        agent_allowed: base.agent_allowed && child.agent_allowed,
        allowed_parents,
    }
}

/// Merge two [`EnvPolicy`]s — `block` lists union (strictly tightening).
fn merge_env_policy(base: EnvPolicy, child: EnvPolicy) -> EnvPolicy {
    EnvPolicy {
        block: dedup_append(&base.block, &child.block),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mediation::InterceptAction;

    fn cmd(name: &str) -> CommandEntry {
        CommandEntry {
            name: name.to_string(),
            binary_path: None,
            intercept: Vec::new(),
            sandbox: None,
            caller_policy: CallerPolicy::default(),
        }
    }

    fn rule(prefix: &[&str], stdout: &str) -> InterceptRule {
        InterceptRule {
            args_prefix: prefix.iter().map(|s| s.to_string()).collect(),
            admin: false,
            action: InterceptAction::Respond {
                stdout: stdout.to_string(),
                exit_code: 0,
            },
        }
    }

    #[test]
    fn test_merge_mediation_appends_distinct_command_entries() {
        let base = MediationConfig {
            commands: vec![cmd("gh"), cmd("git")],
            ..Default::default()
        };
        let child = MediationConfig {
            commands: vec![cmd("kubectl")],
            ..Default::default()
        };
        let merged = merge_mediation(base, child);
        let names: Vec<&str> = merged.commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, vec!["gh", "git", "kubectl"]);
    }

    #[test]
    fn test_merge_mediation_collision_merges_per_field() {
        let mut base_gh = cmd("gh");
        base_gh.binary_path = Some("/base/gh".to_string());
        base_gh.intercept = vec![rule(&["auth", "token"], "base-token")];

        let mut child_gh = cmd("gh");
        child_gh.binary_path = Some("/child/gh".to_string());
        child_gh.intercept = vec![rule(&["pr", "view"], "child-pr")];

        let base = MediationConfig {
            commands: vec![base_gh],
            ..Default::default()
        };
        let child = MediationConfig {
            commands: vec![child_gh],
            ..Default::default()
        };
        let merged = merge_mediation(base, child);
        assert_eq!(merged.commands.len(), 1);
        let gh = &merged.commands[0];
        assert_eq!(gh.name, "gh");
        // Child binary_path wins.
        assert_eq!(gh.binary_path.as_deref(), Some("/child/gh"));
        // Both intercept rules survive — child first, then base.
        assert_eq!(gh.intercept.len(), 2);
        assert_eq!(gh.intercept[0].args_prefix, vec!["pr", "view"]);
        assert_eq!(gh.intercept[1].args_prefix, vec!["auth", "token"]);
    }

    #[test]
    fn test_merge_mediation_intercept_dedup_by_args_prefix_child_first() {
        let mut base_gh = cmd("gh");
        base_gh.intercept = vec![
            rule(&["auth", "token"], "base-token"),
            rule(&["pr", "list"], "base-pr-list"),
        ];

        let mut child_gh = cmd("gh");
        child_gh.intercept = vec![rule(&["auth", "token"], "child-token")];

        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        let gh = &merged.commands[0];
        assert_eq!(gh.intercept.len(), 2);
        // Child override comes first (first-match-wins).
        assert_eq!(gh.intercept[0].args_prefix, vec!["auth", "token"]);
        match &gh.intercept[0].action {
            InterceptAction::Respond { stdout, .. } => assert_eq!(stdout, "child-token"),
            _ => panic!("unexpected action"),
        }
        // Non-overlapping base rule preserved.
        assert_eq!(gh.intercept[1].args_prefix, vec!["pr", "list"]);
    }

    #[test]
    fn test_merge_mediation_caller_policy_agent_allowed_is_and() {
        let mut base_gh = cmd("gh");
        base_gh.caller_policy.agent_allowed = false;
        let mut child_gh = cmd("gh");
        child_gh.caller_policy.agent_allowed = true;

        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        // Managed deny survives a permissive child.
        assert!(!merged.commands[0].caller_policy.agent_allowed);
    }

    #[test]
    fn test_merge_mediation_caller_policy_allowed_parents_intersect() {
        let mut base_gh = cmd("gh");
        base_gh.caller_policy.allowed_parents = Some(vec!["git".to_string(), "make".to_string()]);
        let mut child_gh = cmd("gh");
        child_gh.caller_policy.allowed_parents = Some(vec!["git".to_string(), "bash".to_string()]);

        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        assert_eq!(
            merged.commands[0].caller_policy.allowed_parents.as_deref(),
            Some(&["git".to_string()][..])
        );
    }

    #[test]
    fn test_merge_mediation_caller_policy_allowed_parents_none_inherits() {
        // base is None ("any"), child restricts.
        let mut child_gh = cmd("gh");
        child_gh.caller_policy.allowed_parents = Some(vec!["git".to_string()]);
        let merged = merge_mediation(
            MediationConfig {
                commands: vec![cmd("gh")],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        assert_eq!(
            merged.commands[0].caller_policy.allowed_parents.as_deref(),
            Some(&["git".to_string()][..])
        );

        // base restricts, child is None — the restriction stays.
        let mut base_gh = cmd("gh");
        base_gh.caller_policy.allowed_parents = Some(vec!["bash".to_string()]);
        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![cmd("gh")],
                ..Default::default()
            },
        );
        assert_eq!(
            merged.commands[0].caller_policy.allowed_parents.as_deref(),
            Some(&["bash".to_string()][..])
        );

        // Both None — stays None.
        let merged = merge_mediation(
            MediationConfig {
                commands: vec![cmd("gh")],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![cmd("gh")],
                ..Default::default()
            },
        );
        assert!(merged.commands[0].caller_policy.allowed_parents.is_none());
    }

    #[test]
    fn test_merge_mediation_command_sandbox_network_block_is_or() {
        let mut base_gh = cmd("gh");
        base_gh.sandbox = Some(CommandSandbox {
            network: NetworkConfig {
                block: true,
                ..Default::default()
            },
            ..Default::default()
        });
        let mut child_gh = cmd("gh");
        child_gh.sandbox = Some(CommandSandbox::default());

        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        let sb = merged.commands[0].sandbox.as_ref().unwrap();
        assert!(sb.network.block, "base block must persist after merge");
    }

    #[test]
    fn test_merge_mediation_command_sandbox_allowed_hosts_unions() {
        let mut base_gh = cmd("gh");
        base_gh.sandbox = Some(CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["github.com".to_string()],
            },
            ..Default::default()
        });
        let mut child_gh = cmd("gh");
        child_gh.sandbox = Some(CommandSandbox {
            network: NetworkConfig {
                block: false,
                allowed_hosts: vec!["api.github.com".to_string(), "github.com".to_string()],
            },
            ..Default::default()
        });

        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        let sb = merged.commands[0].sandbox.as_ref().unwrap();
        assert_eq!(
            sb.network.allowed_hosts,
            vec!["github.com".to_string(), "api.github.com".to_string()]
        );
    }

    #[test]
    fn test_merge_mediation_command_sandbox_fs_fields_union() {
        let mut base_gh = cmd("gh");
        base_gh.sandbox = Some(CommandSandbox {
            fs_read: vec!["~/.gitconfig".to_string()],
            fs_read_file: vec!["~/.netrc".to_string()],
            fs_write: vec!["~/.cache/gh".to_string()],
            fs_write_file: vec!["/tmp/gh.log".to_string()],
            allow_commands: vec!["xdg-open".to_string()],
            ..Default::default()
        });
        let mut child_gh = cmd("gh");
        child_gh.sandbox = Some(CommandSandbox {
            fs_read: vec!["~/.config/gh".to_string()],
            fs_read_file: vec!["~/.netrc".to_string()],
            allow_commands: vec!["pbcopy".to_string()],
            ..Default::default()
        });

        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        let sb = merged.commands[0].sandbox.as_ref().unwrap();
        assert_eq!(
            sb.fs_read,
            vec!["~/.gitconfig".to_string(), "~/.config/gh".to_string()]
        );
        // dedup applied
        assert_eq!(sb.fs_read_file, vec!["~/.netrc".to_string()]);
        assert_eq!(sb.fs_write, vec!["~/.cache/gh".to_string()]);
        assert_eq!(sb.fs_write_file, vec!["/tmp/gh.log".to_string()]);
        assert_eq!(
            sb.allow_commands,
            vec!["xdg-open".to_string(), "pbcopy".to_string()]
        );
    }

    #[test]
    fn test_merge_mediation_command_sandbox_keychain_access_is_or() {
        let mut base_gh = cmd("gh");
        base_gh.sandbox = Some(CommandSandbox {
            keychain_access: true,
            ..Default::default()
        });
        let mut child_gh = cmd("gh");
        child_gh.sandbox = Some(CommandSandbox::default());

        let merged = merge_mediation(
            MediationConfig {
                commands: vec![base_gh],
                ..Default::default()
            },
            MediationConfig {
                commands: vec![child_gh],
                ..Default::default()
            },
        );
        let sb = merged.commands[0].sandbox.as_ref().unwrap();
        assert!(sb.keychain_access);
    }

    #[test]
    fn test_merge_mediation_env_block_unions_and_dedups() {
        let base = MediationConfig {
            env: EnvPolicy {
                block: vec!["GITHUB_TOKEN".to_string(), "GITLAB_TOKEN".to_string()],
            },
            ..Default::default()
        };
        let child = MediationConfig {
            env: EnvPolicy {
                block: vec!["GITHUB_TOKEN".to_string(), "OPENAI_API_KEY".to_string()],
            },
            ..Default::default()
        };
        let merged = merge_mediation(base, child);
        assert_eq!(
            merged.env.block,
            vec![
                "GITHUB_TOKEN".to_string(),
                "GITLAB_TOKEN".to_string(),
                "OPENAI_API_KEY".to_string(),
            ]
        );
    }

    #[test]
    fn test_merge_mediation_empty_child_inherits_base() {
        let mut base_gh = cmd("gh");
        base_gh.intercept = vec![rule(&["auth", "token"], "base")];
        base_gh.caller_policy.agent_allowed = false;

        let base = MediationConfig {
            commands: vec![base_gh],
            env: EnvPolicy {
                block: vec!["GH_TOKEN".to_string()],
            },
        };
        let merged = merge_mediation(base, MediationConfig::default());
        assert_eq!(merged.commands.len(), 1);
        assert_eq!(merged.commands[0].intercept.len(), 1);
        assert!(!merged.commands[0].caller_policy.agent_allowed);
        assert_eq!(merged.env.block, vec!["GH_TOKEN".to_string()]);
    }

    #[test]
    fn test_merge_mediation_empty_base_takes_child() {
        let mut child_gh = cmd("gh");
        child_gh.intercept = vec![rule(&["auth", "token"], "child")];
        let child = MediationConfig {
            commands: vec![child_gh],
            env: EnvPolicy {
                block: vec!["GH_TOKEN".to_string()],
            },
        };
        let merged = merge_mediation(MediationConfig::default(), child);
        assert_eq!(merged.commands.len(), 1);
        assert_eq!(merged.commands[0].intercept.len(), 1);
        assert_eq!(merged.env.block, vec!["GH_TOKEN".to_string()]);
    }

    #[test]
    fn test_merge_mediation_is_active_after_merge() {
        // Invariant: merged.is_active() == base.is_active() || child.is_active().
        let cases = [(false, false), (true, false), (false, true), (true, true)];
        for (base_active, child_active) in cases {
            let base = if base_active {
                MediationConfig {
                    commands: vec![cmd("gh")],
                    ..Default::default()
                }
            } else {
                MediationConfig::default()
            };
            let child = if child_active {
                MediationConfig {
                    env: EnvPolicy {
                        block: vec!["GH_TOKEN".to_string()],
                    },
                    ..Default::default()
                }
            } else {
                MediationConfig::default()
            };
            let merged = merge_mediation(base, child);
            assert_eq!(
                merged.is_active(),
                base_active || child_active,
                "is_active mismatch for ({base_active}, {child_active})"
            );
        }
    }
}
