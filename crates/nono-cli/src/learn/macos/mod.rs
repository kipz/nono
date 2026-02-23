//! macOS learn mode: DYLD interpose-based filesystem access tracer
//!
//! Injects a compiled C dylib via `DYLD_INSERT_LIBRARIES` that intercepts
//! file syscalls and writes `PATH:R` / `PATH:W` lines to a pre-opened FD.
//! Child processes are tracked via `SIGSTOP` / `SIGCONT` and the comm file.
//!
//! No root required. SIP-compatible. Requires clang (Xcode Command Line Tools).

mod interpose;
mod tracer;

use crate::cli::LearnArgs;
use crate::learn::common::LearnResult;
use crate::profile;
use nono::Result;

/// Run learn mode on macOS using the DYLD interpose tracer.
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    // Load profile if specified
    let profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    // Compile (or reuse cached) interpose dylib, then run the traced process
    let raw_accesses = tracer::run_tracer(args)?;

    if raw_accesses.is_empty() {
        return Ok(LearnResult::new());
    }

    crate::learn::common::process_accesses(raw_accesses, profile.as_ref(), args.all)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn test_interpose_dylib_compiles() {
        // Verifies the fork-interpose dylib can be compiled.
        // Skips gracefully if clang is not available.
        let result = interpose::get_interpose_dylib();
        if let Err(e) = &result {
            eprintln!("Note: could not compile interpose dylib: {}", e);
            return;
        }
        let dylib_path = result.expect("should have succeeded");
        assert!(
            dylib_path.exists(),
            "compiled dylib must exist at {:?}",
            dylib_path
        );
    }

    #[test]
    fn test_interpose_c_source_has_sigstop() {
        // The fork interpose source must SIGSTOP children for the tracer to
        // resume them after registering their PIDs.
        let src = interpose::FORK_INTERPOSE_C;
        assert!(src.contains("SIGSTOP"), "fork_interpose.c must use SIGSTOP");
        assert!(
            src.contains("__interpose"),
            "fork_interpose.c must contain DYLD interpose table"
        );
    }
}
