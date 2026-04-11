use crate::capability_ext::{self, CapabilitySetExt};
use crate::cli::SandboxArgs;
#[cfg(target_os = "linux")]
use crate::config;
use crate::credential_runtime::load_env_credentials;
use crate::profile;
use crate::profile::WorkdirAccess;
use crate::profile_runtime::prepare_profile;
use crate::{output, policy, protected_paths, sandbox_state};
use crate::{DETACHED_CWD_PROMPT_RESPONSE_ENV, DETACHED_LAUNCH_ENV};
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, FsCapability, NonoError, Result, Sandbox};
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

fn collect_missing_cli_requested_paths(args: &SandboxArgs) -> Vec<String> {
    let mut missing = Vec::new();

    for path in &args.allow {
        if !path.exists() {
            missing.push(format!("--allow {}", path.display()));
        }
    }
    for path in &args.read {
        if !path.exists() {
            missing.push(format!("--read {}", path.display()));
        }
    }
    for path in &args.write {
        if !path.exists() {
            missing.push(format!("--write {}", path.display()));
        }
    }
    for path in &args.allow_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--allow-file {}", path.display()));
        }
    }
    for path in &args.read_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--read-file {}", path.display()));
        }
    }
    for path in &args.write_file {
        if !path.exists() && !capability_ext::retains_missing_exact_file_grants() {
            missing.push(format!("--write-file {}", path.display()));
        }
    }

    missing
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetachedCwdPromptResponse {
    Allow,
    Deny,
}

impl DetachedCwdPromptResponse {
    pub(crate) const fn as_env_value(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    fn from_env_value(value: &str) -> Option<Self> {
        match value {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingCwdAccessRequest {
    cwd_canonical: PathBuf,
    access: AccessMode,
}

/// Result of sandbox preparation.
pub(crate) struct PreparedSandbox {
    pub(crate) caps: CapabilitySet,
    pub(crate) secrets: Vec<nono::LoadedSecret>,
    pub(crate) rollback_exclude_patterns: Vec<String>,
    pub(crate) rollback_exclude_globs: Vec<String>,
    pub(crate) network_profile: Option<String>,
    pub(crate) allow_domain: Vec<String>,
    pub(crate) credentials: Vec<String>,
    pub(crate) custom_credentials: HashMap<String, profile::CustomCredentialDef>,
    pub(crate) upstream_proxy: Option<String>,
    pub(crate) upstream_bypass: Vec<String>,
    pub(crate) listen_ports: Vec<u16>,
    pub(crate) capability_elevation: bool,
    #[cfg(target_os = "linux")]
    pub(crate) wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy,
    pub(crate) allow_launch_services_active: bool,
    pub(crate) allow_gpu_active: bool,
    pub(crate) open_url_origins: Vec<String>,
    pub(crate) open_url_allow_localhost: bool,
    pub(crate) override_deny_paths: Vec<PathBuf>,
}

fn resolved_workdir(args: &SandboxArgs) -> PathBuf {
    args.workdir
        .clone()
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."))
}

fn cwd_access_requirement(profile_workdir_access: Option<&WorkdirAccess>) -> Option<AccessMode> {
    if let Some(access) = profile_workdir_access {
        match access {
            WorkdirAccess::Read => Some(AccessMode::Read),
            WorkdirAccess::Write => Some(AccessMode::Write),
            WorkdirAccess::ReadWrite => Some(AccessMode::ReadWrite),
            WorkdirAccess::None => None,
        }
    } else {
        Some(AccessMode::Read)
    }
}

fn pending_cwd_access_request(
    caps: &CapabilitySet,
    workdir: &Path,
    profile_workdir_access: Option<&WorkdirAccess>,
) -> Result<Option<PendingCwdAccessRequest>> {
    let Some(access) = cwd_access_requirement(profile_workdir_access) else {
        return Ok(None);
    };

    let cwd_canonical = workdir
        .canonicalize()
        .map_err(|e| NonoError::PathCanonicalization {
            path: workdir.to_path_buf(),
            source: e,
        })?;

    if caps.path_covered_with_access(&cwd_canonical, access) {
        Ok(None)
    } else {
        Ok(Some(PendingCwdAccessRequest {
            cwd_canonical,
            access,
        }))
    }
}

fn detached_cwd_prompt_response() -> Option<DetachedCwdPromptResponse> {
    std::env::var(DETACHED_CWD_PROMPT_RESPONSE_ENV)
        .ok()
        .as_deref()
        .and_then(DetachedCwdPromptResponse::from_env_value)
}

pub(crate) fn resolve_detached_cwd_prompt_response(
    args: &SandboxArgs,
    silent: bool,
) -> Result<Option<DetachedCwdPromptResponse>> {
    if silent || args.allow_cwd || args.config.is_some() {
        return Ok(None);
    }

    let workdir = resolved_workdir(args);
    let loaded_profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    let (caps, _) = if let Some(ref profile) = loaded_profile {
        CapabilitySet::from_profile(profile, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };

    let Some(request) = pending_cwd_access_request(
        &caps,
        &workdir,
        loaded_profile
            .as_ref()
            .map(|profile| &profile.workdir.access),
    )?
    else {
        return Ok(None);
    };

    let confirmed = output::prompt_cwd_sharing(&request.cwd_canonical, &request.access)?;
    Ok(Some(if confirmed {
        DetachedCwdPromptResponse::Allow
    } else {
        DetachedCwdPromptResponse::Deny
    }))
}

fn finalize_prepared_sandbox(
    prepared: PreparedSandbox,
    args: &SandboxArgs,
    silent: bool,
) -> Result<PreparedSandbox> {
    output::print_skipped_requested_paths(&collect_missing_cli_requested_paths(args), silent);
    output::print_capabilities(&prepared.caps, args.verbose, silent);

    #[cfg(target_os = "linux")]
    output::print_abi_info(silent);

    if !Sandbox::is_supported() {
        return Err(NonoError::SandboxInit(Sandbox::support_info().details));
    }

    info!("{}", Sandbox::support_info().details);

    Ok(prepared)
}

pub(crate) fn validate_external_proxy_bypass(
    args: &SandboxArgs,
    prepared: &PreparedSandbox,
) -> Result<()> {
    let has_bypass = !args.external_proxy_bypass.is_empty() || !prepared.upstream_bypass.is_empty();
    let has_external_proxy = args.external_proxy.is_some() || prepared.upstream_proxy.is_some();

    if has_bypass && !has_external_proxy {
        return Err(NonoError::ConfigParse(
            "--upstream-bypass requires --upstream-proxy \
             (or upstream_proxy in profile network config)"
                .to_string(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) fn maybe_enable_macos_launch_services(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
    open_url_origins: &[String],
    open_url_allow_localhost: bool,
) -> Result<bool> {
    if !cli_requested {
        return Ok(false);
    }

    if !profile_allowed {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires a profile that opts into allow_launch_services"
                .to_string(),
        ));
    }

    if open_url_origins.is_empty() && !open_url_allow_localhost {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services requires the selected profile to configure open_urls"
                .to_string(),
        ));
    }

    caps.add_platform_rule("(allow lsopen)")?;
    warn!("--allow-launch-services enabled: allowing direct LaunchServices opens on macOS");
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn maybe_enable_macos_launch_services(
    _caps: &mut CapabilitySet,
    cli_requested: bool,
    _profile_allowed: bool,
    _open_url_origins: &[String],
    _open_url_allow_localhost: bool,
) -> Result<bool> {
    if cli_requested {
        return Err(NonoError::ConfigParse(
            "--allow-launch-services is only supported on macOS".to_string(),
        ));
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
pub(crate) fn maybe_enable_macos_gpu(
    caps: &mut CapabilitySet,
    cli_requested: bool,
    profile_allowed: bool,
) -> Result<bool> {
    if !cli_requested {
        return Ok(false);
    }

    if !profile_allowed {
        return Err(NonoError::ConfigParse(
            "--allow-gpu requires the selected profile to opt into allow_gpu".to_string(),
        ));
    }

    // Minimal IOKit surface for Metal compute on Apple Silicon. Verified that
    // `AGXDeviceUserClient` and `IOSurfaceRootUserClient` are sufficient for
    // the full pipeline and offscreen rendering. `AGXSharedUserClient` is only
    // needed for cross process GPU resource sharing (such as WebKit's GPU
    // process). Adding `iokit-connection "IOGPU"` would cover more user
    // clients such as `IOGPUSurfaceMTL` and `IOGPUGLDrawableUserClient` which
    // are needed for display output and OpenGL. Intel Macs require
    // `IntelAccelerator`, `IOAccelerator`, and `AMDRadeonX*` classes which are
    // not yet supported.
    caps.add_platform_rule(
        "(allow iokit-open \
            (iokit-user-client-class \
                \"AGXDeviceUserClient\" \
                \"IOSurfaceRootUserClient\"))",
    )?;
    warn!("--allow-gpu enabled: allowing access to GPU");
    Ok(true)
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn maybe_enable_macos_gpu(
    _caps: &mut CapabilitySet,
    cli_requested: bool,
    _profile_allowed: bool,
) -> Result<bool> {
    if cli_requested {
        return Err(NonoError::ConfigParse(
            "--allow-gpu is only supported on macOS".to_string(),
        ));
    }
    Ok(false)
}

pub(crate) fn print_allow_gpu_warning(silent: bool) {
    if silent {
        return;
    }

    eprintln!(
        "  {}",
        "WARNING: --allow-gpu permits the sandboxed process to access the GPU.".yellow()
    );
    eprintln!("  GPU access may expose additional attack surface. Only use when your workload requires it.");
}

pub(crate) fn print_allow_launch_services_warning(silent: bool) {
    if silent {
        return;
    }

    eprintln!(
        "  {}",
        "WARNING: --allow-launch-services permits the sandboxed process to ask macOS \
         LaunchServices to open URLs, files, or apps."
            .yellow()
    );
    eprintln!("  Use this only for temporary login/setup flows, then exit and rerun without it.");
    eprintln!("  Prefer using it from a trusted directory, not inside an untrusted project.");
}

fn missing_cwd_prompt_must_fail(
    silent: bool,
    detached_launch: bool,
    detached_prompt_response: Option<DetachedCwdPromptResponse>,
) -> bool {
    silent || (detached_launch && detached_prompt_response.is_none())
}

pub(crate) fn prepare_sandbox(args: &SandboxArgs, silent: bool) -> Result<PreparedSandbox> {
    sandbox_state::cleanup_stale_state_files();
    let detached_launch = std::env::var_os(DETACHED_LAUNCH_ENV).is_some();
    let detached_prompt_response = detached_cwd_prompt_response();
    let workdir = resolved_workdir(args);

    if let Some(ref config_path) = args.config {
        let json = std::fs::read_to_string(config_path).map_err(|e| {
            NonoError::ConfigParse(format!(
                "failed to read manifest file '{}': {e}",
                config_path.display()
            ))
        })?;
        let mut manifest = nono::manifest::CapabilityManifest::from_json(&json)?;
        manifest.validate()?;

        if let Some(ref mut fs) = manifest.filesystem {
            for grant in &mut fs.grants {
                let expanded = profile::expand_vars(grant.path.as_str(), &workdir)?;
                grant.path = expanded
                    .to_string_lossy()
                    .parse()
                    .map_err(|e| NonoError::ConfigParse(format!("invalid path: {e}")))?;
            }
            for deny in &mut fs.deny {
                let expanded = profile::expand_vars(deny.path.as_str(), &workdir)?;
                deny.path = expanded
                    .to_string_lossy()
                    .parse()
                    .map_err(|e| NonoError::ConfigParse(format!("invalid path: {e}")))?;
            }
        }

        let caps = CapabilitySet::try_from(&manifest)?;
        let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
        protected_paths::validate_caps_against_protected_roots(&caps, protected_roots.as_paths())?;

        let (rollback_exclude_patterns, rollback_exclude_globs) =
            if let Some(ref rb) = manifest.rollback {
                (rb.exclude_patterns.clone(), rb.exclude_globs.clone())
            } else {
                (Vec::new(), Vec::new())
            };

        let allow_domain = manifest
            .network
            .as_ref()
            .map(|network| network.allow_domains.clone())
            .unwrap_or_default();
        let credentials = manifest
            .credentials
            .iter()
            .map(|credential| credential.name.as_str().to_string())
            .collect();

        return finalize_prepared_sandbox(
            PreparedSandbox {
                caps,
                secrets: Vec::new(),
                rollback_exclude_patterns,
                rollback_exclude_globs,
                network_profile: None,
                allow_domain,
                credentials,
                custom_credentials: HashMap::new(),
                upstream_proxy: None,
                upstream_bypass: Vec::new(),
                listen_ports: Vec::new(),
                capability_elevation: false,
                #[cfg(target_os = "linux")]
                wsl2_proxy_policy: crate::profile::Wsl2ProxyPolicy::default(),
                allow_launch_services_active: false,
                allow_gpu_active: false,
                open_url_origins: Vec::new(),
                open_url_allow_localhost: false,
                override_deny_paths: Vec::new(),
            },
            args,
            silent,
        );
    }

    let prepared_profile = prepare_profile(args, silent, &workdir)?;
    let crate::profile_runtime::PreparedProfile {
        loaded_profile,
        capability_elevation,
        #[cfg(target_os = "linux")]
        wsl2_proxy_policy,
        workdir_access: profile_workdir_access,
        rollback_exclude_patterns: profile_rollback_patterns,
        rollback_exclude_globs: profile_rollback_globs,
        network_profile: profile_network_profile,
        allow_domain: profile_allow_domain,
        credentials: profile_credentials,
        custom_credentials: profile_custom_credentials,
        upstream_proxy: profile_upstream_proxy,
        upstream_bypass: profile_upstream_bypass,
        listen_ports: profile_listen_ports,
        open_url_origins,
        open_url_allow_localhost,
        allow_launch_services: profile_allow_launch_services,
        allow_gpu: profile_allow_gpu,
        override_deny_paths,
    } = prepared_profile;

    #[cfg(target_os = "linux")]
    if args.profile.as_deref() == Some("claude-code") {
        let home = config::validated_home()?;
        let home_path = std::path::Path::new(&home);

        let precreate = |path: &std::path::Path, is_dir: bool| {
            let result = if is_dir {
                std::fs::create_dir_all(path)
            } else {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(path)
                    .map(|_| ())
            };
            if let Err(e) = result {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    warn!("Failed to pre-create {}: {}", path.display(), e);
                }
            }
        };

        precreate(&home_path.join(".claude.json.lock"), false);
        precreate(&home_path.join(".cache/claude-cli-nodejs"), true);
    }

    let (mut caps, needs_unlink_overrides) = if let Some(ref profile) = loaded_profile {
        CapabilitySet::from_profile(profile, &workdir, args)?
    } else {
        CapabilitySet::from_args(args)?
    };

    let allow_launch_services_active = maybe_enable_macos_launch_services(
        &mut caps,
        args.allow_launch_services,
        profile_allow_launch_services,
        &open_url_origins,
        open_url_allow_localhost,
    )?;

    let allow_gpu_active = maybe_enable_macos_gpu(
        &mut caps,
        args.allow_gpu,
        loaded_profile.is_none() || profile_allow_gpu,
    )?;

    if let Some(request) =
        pending_cwd_access_request(&caps, &workdir, profile_workdir_access.as_ref())?
    {
        if args.allow_cwd
            || matches!(
                detached_prompt_response,
                Some(DetachedCwdPromptResponse::Allow)
            )
        {
            let reason = if args.allow_cwd {
                "(--allow-cwd)"
            } else {
                "(detached launch preflight)"
            };
            info!(
                "Auto-including CWD with {} access {}",
                request.access, reason
            );
            let cap = FsCapability::new_dir(request.cwd_canonical.clone(), request.access)?;
            caps.add_fs(cap);
        } else if matches!(
            detached_prompt_response,
            Some(DetachedCwdPromptResponse::Deny)
        ) {
            info!("Detached launch declined CWD sharing. Continuing without automatic CWD access.");
        } else if missing_cwd_prompt_must_fail(silent, detached_launch, detached_prompt_response) {
            return Err(NonoError::CwdPromptRequired);
        } else {
            let confirmed = output::prompt_cwd_sharing(&request.cwd_canonical, &request.access)?;
            if confirmed {
                let cap = FsCapability::new_dir(request.cwd_canonical.clone(), request.access)?;
                caps.add_fs(cap);
            } else {
                info!("User declined CWD sharing. Continuing without automatic CWD access.");
            }
        }
        caps.deduplicate();
    }

    let active_groups = if let Some(profile) = loaded_profile
        .as_ref()
        .filter(|profile| !profile.security.groups.is_empty())
    {
        profile.security.groups.clone()
    } else {
        capability_ext::default_profile_groups()?
    };
    let loaded_policy = policy::load_embedded_policy()?;
    let deny_paths = policy::resolve_deny_paths_for_groups(&loaded_policy, &active_groups)?;
    policy::validate_deny_overlaps(&deny_paths, &caps)?;
    let protected_roots = protected_paths::ProtectedRoots::from_defaults()?;
    protected_paths::validate_caps_against_protected_roots(&caps, protected_roots.as_paths())?;

    if needs_unlink_overrides {
        policy::apply_unlink_overrides(&mut caps);
    }

    if !caps.has_fs() && caps.is_network_blocked() {
        return Err(NonoError::NoCapabilities);
    }

    let profile_secrets = loaded_profile
        .map(|profile| profile.env_credentials.mappings)
        .unwrap_or_default();
    let loaded_secrets = load_env_credentials(args, &profile_secrets, silent)?;

    finalize_prepared_sandbox(
        PreparedSandbox {
            caps,
            secrets: loaded_secrets,
            rollback_exclude_patterns: profile_rollback_patterns,
            rollback_exclude_globs: profile_rollback_globs,
            network_profile: profile_network_profile,
            allow_domain: profile_allow_domain,
            credentials: profile_credentials,
            custom_credentials: profile_custom_credentials,
            upstream_proxy: profile_upstream_proxy,
            upstream_bypass: profile_upstream_bypass,
            listen_ports: profile_listen_ports,
            capability_elevation,
            #[cfg(target_os = "linux")]
            wsl2_proxy_policy,
            allow_launch_services_active,
            allow_gpu_active,
            open_url_origins,
            open_url_allow_localhost,
            override_deny_paths,
        },
        args,
        silent,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(target_os = "macos")]
    #[test]
    fn missing_exact_file_cli_grants_are_not_reported_as_skipped() {
        let dir = tempdir().expect("tmpdir");
        let args = SandboxArgs {
            allow_file: vec![dir.path().join("future.lock")],
            ..SandboxArgs::default()
        };

        assert!(
            collect_missing_cli_requested_paths(&args).is_empty(),
            "macOS exact-file grants should not be reported as skipped when the file is absent"
        );
    }

    #[test]
    fn missing_directory_cli_grants_are_reported_as_skipped() {
        let dir = tempdir().expect("tmpdir");
        let args = SandboxArgs {
            allow: vec![dir.path().join("future-dir")],
            ..SandboxArgs::default()
        };

        assert_eq!(
            collect_missing_cli_requested_paths(&args),
            vec![format!(
                "--allow {}",
                dir.path().join("future-dir").display()
            )]
        );
    }

    #[test]
    fn missing_cwd_prompt_fails_in_silent_mode() {
        assert!(missing_cwd_prompt_must_fail(true, false, None));
    }

    #[test]
    fn missing_cwd_prompt_fails_for_unresolved_detached_launches() {
        assert!(missing_cwd_prompt_must_fail(false, true, None));
    }

    #[test]
    fn missing_cwd_prompt_does_not_fail_after_detached_preflight_decision() {
        assert!(!missing_cwd_prompt_must_fail(
            false,
            true,
            Some(DetachedCwdPromptResponse::Deny)
        ));
        assert!(!missing_cwd_prompt_must_fail(
            false,
            true,
            Some(DetachedCwdPromptResponse::Allow)
        ));
    }

    #[test]
    fn missing_cwd_prompt_can_interactively_prompt_when_attached() {
        assert!(!missing_cwd_prompt_must_fail(false, false, None));
    }

    #[test]
    fn pending_cwd_access_request_uses_default_read_access() {
        let dir = tempdir().expect("tmpdir");
        let caps = CapabilitySet::new();
        let request = pending_cwd_access_request(&caps, dir.path(), None)
            .expect("request should evaluate")
            .expect("request should be required");

        assert_eq!(
            request.cwd_canonical,
            dir.path().canonicalize().expect("canonical")
        );
        assert_eq!(request.access, AccessMode::Read);
    }

    #[test]
    fn pending_cwd_access_request_is_skipped_when_caps_cover_workdir() {
        let dir = tempdir().expect("tmpdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(
            FsCapability::new_dir(dir.path(), AccessMode::ReadWrite).expect("dir capability"),
        );

        assert!(pending_cwd_access_request(&caps, dir.path(), None)
            .expect("request should evaluate")
            .is_none());
    }

    #[test]
    fn detached_cwd_prompt_response_env_values_round_trip() {
        assert_eq!(
            DetachedCwdPromptResponse::from_env_value(
                DetachedCwdPromptResponse::Allow.as_env_value()
            ),
            Some(DetachedCwdPromptResponse::Allow)
        );
        assert_eq!(
            DetachedCwdPromptResponse::from_env_value(
                DetachedCwdPromptResponse::Deny.as_env_value()
            ),
            Some(DetachedCwdPromptResponse::Deny)
        );
    }
}
