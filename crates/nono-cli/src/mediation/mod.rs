//! Command mediation: policy-driven command interception and credential injection.
//!
//! The mediation layer sits between the sandboxed AI agent and real tool binaries.
//! Instead of running `ddtool auth github token` directly, the sandbox's PATH
//! resolves to a shim that forwards the invocation over a Unix socket to this
//! server running in the unsandboxed parent.
//!
//! All policy (which commands to intercept, what to return, which env vars to
//! block/inject) lives in the profile's `mediation` section. The nono core has
//! no tool-specific knowledge.

pub mod policy;
pub mod server;
pub mod session;

use serde::Deserialize;

/// Top-level mediation configuration from a profile's `mediation` section.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct MediationConfig {
    /// Commands to mediate (intercept or inject env into).
    #[serde(default)]
    pub commands: Vec<CommandEntry>,
    /// Environment variable policy for the sandboxed child.
    #[serde(default)]
    pub env: EnvPolicy,
}

impl MediationConfig {
    /// Returns true if there is any mediation configuration to apply.
    pub fn is_active(&self) -> bool {
        !self.commands.is_empty()
            || !self.env.block.is_empty()
            || !self.env.inject.is_empty()
    }
}

/// Per-command mediation entry.
#[derive(Debug, Clone, Deserialize)]
pub struct CommandEntry {
    /// The command name to mediate (resolved via `which` at session start).
    pub name: String,
    /// Arg-prefix intercept rules. Checked in order; first match wins.
    #[serde(default)]
    pub intercept: Vec<InterceptRule>,
    /// Environment variables to inject when passing through to the real binary.
    #[serde(default)]
    pub inject_env: Vec<EnvInject>,
}

/// An intercept rule: if `args_prefix` matches the invocation's args, return
/// the configured response without calling the real binary.
#[derive(Debug, Clone, Deserialize)]
pub struct InterceptRule {
    /// The leading args that must match (e.g. `["auth", "github", "token"]`).
    pub args_prefix: Vec<String>,
    /// What to respond with when this rule matches.
    pub respond: RespondConfig,
}

/// The response emitted when an intercept rule fires.
#[derive(Debug, Clone, Deserialize)]
pub struct RespondConfig {
    /// Credential to load and substitute into `output_template`.
    /// Uses the keystore URI scheme: `keychain:account`, `op://vault/item/field`,
    /// or `env://VAR_NAME`. Optional — if absent, `output_template` is used as-is.
    #[serde(default)]
    pub credential_source: Option<String>,
    /// Template for stdout. Use `{credential}` as the substitution placeholder.
    pub output_template: String,
    /// Exit code to return to the caller (default: 0).
    #[serde(default)]
    pub exit_code: i32,
}

/// An environment variable to inject (either into a command's env or the
/// sandbox's global env).
#[derive(Debug, Clone, Deserialize)]
pub struct EnvInject {
    /// The environment variable name to set.
    pub var: String,
    /// Credential source URI: `keychain:account`, `op://...`, or `env://VAR`.
    pub source: String,
}

/// Environment variable policy for the sandboxed child process.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EnvPolicy {
    /// Env var names to strip from the child environment (credential leakage prevention).
    /// Complements the hardcoded injection-vector blocklist in `env_sanitization.rs`.
    #[serde(default)]
    pub block: Vec<String>,
    /// Credentials to load and inject as env vars in the child environment.
    #[serde(default)]
    pub inject: Vec<EnvInject>,
}
