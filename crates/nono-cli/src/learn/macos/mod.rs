//! macOS learn mode: Seatbelt report-mode filesystem access tracer
//!
//! Applies `(allow (with report) default)` via Seatbelt so every file operation
//! is logged to the kernel log. Parses those entries to discover required paths.
//! Works for SIP-protected binaries. Requires macOS 10.12+ (`log stream`).

mod seatbelt_tracer;

use crate::cli::LearnArgs;
use crate::learn::common::LearnResult;
use crate::profile;
use nono::Result;

/// Run learn mode on macOS using the Seatbelt report-mode tracer.
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    let profile = if let Some(ref profile_name) = args.profile {
        Some(profile::load_profile(profile_name)?)
    } else {
        None
    };

    let raw_accesses = seatbelt_tracer::run_seatbelt_tracer(args)?;

    if raw_accesses.is_empty() {
        return Ok(LearnResult::new());
    }

    crate::learn::common::process_accesses(raw_accesses, profile.as_ref(), args.all)
}
