//! Learn mode: trace file accesses to discover required paths for sandbox profiles.
//!
//! Platform implementations:
//! - Linux: uses strace (`learn/linux.rs`)
//! - macOS: uses Seatbelt report-mode (`learn/macos/`)
//! - Other: unsupported

pub mod common;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

pub use common::LearnResult;

use crate::cli::LearnArgs;
use nono::Result;

/// Run learn mode — platform dispatch.
#[cfg(target_os = "linux")]
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    linux::run_learn(args)
}

/// Run learn mode — macOS Seatbelt report-mode implementation.
#[cfg(target_os = "macos")]
pub fn run_learn(args: &LearnArgs) -> Result<LearnResult> {
    macos::run_learn(args)
}

/// Run learn mode — unsupported platform stub.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn run_learn(_args: &LearnArgs) -> Result<LearnResult> {
    Err(nono::NonoError::LearnError(
        "nono learn is not available on this platform".to_string(),
    ))
}
