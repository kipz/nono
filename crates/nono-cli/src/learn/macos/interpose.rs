//! Runtime compilation of the fork-interpose dylib for macOS learn mode
//!
//! The fork_interpose.c source is embedded at build time and compiled to a
//! dylib at runtime (cached by mtime). This dylib is injected via
//! DYLD_INSERT_LIBRARIES to trace file syscalls and track child processes.

use nono::{NonoError, Result};
use std::path::PathBuf;
use std::process::Command;

/// Embedded C source for the fork interpose dylib
pub(super) const FORK_INTERPOSE_C: &str = include_str!("../../../data/fork_interpose.c");

/// Get (or compile) the fork interpose dylib, returning its path.
///
/// The dylib is cached in a temp directory. If the cached version is present,
/// it is reused. If not (or if the source has changed), it is recompiled.
pub fn get_interpose_dylib() -> Result<PathBuf> {
    let cache_dir = interpose_cache_dir()?;
    std::fs::create_dir_all(&cache_dir).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to create dylib cache directory {}: {}",
            cache_dir.display(),
            e
        ))
    })?;

    let dylib_path = cache_dir.join("libfork_interpose.dylib");
    let source_path = cache_dir.join("fork_interpose.c");

    // Write the embedded source to the cache dir (always, so we can recompile
    // if the binary is updated with a newer source version)
    std::fs::write(&source_path, FORK_INTERPOSE_C).map_err(|e| {
        NonoError::LearnError(format!(
            "Failed to write interpose source to {}: {}",
            source_path.display(),
            e
        ))
    })?;

    // Check if we can skip recompilation
    if dylib_path.exists() {
        let dylib_mtime = file_mtime(&dylib_path);
        let source_mtime = file_mtime(&source_path);
        if let (Some(dm), Some(sm)) = (dylib_mtime, source_mtime) {
            if dm >= sm {
                return Ok(dylib_path);
            }
        }
    }

    compile_interpose_dylib(&source_path, &dylib_path)?;
    Ok(dylib_path)
}

/// Compile fork_interpose.c for the current native architecture.
///
/// A universal (arm64 + x86_64) build would require `lipo` to merge slices,
/// which can fail in restricted environments. Building for the native arch avoids
/// this. Users can cross-compile manually if needed.
fn compile_interpose_dylib(source: &std::path::Path, output: &std::path::Path) -> Result<()> {
    let arch = std::env::consts::ARCH; // "aarch64" → "arm64", "x86_64" → "x86_64"
    let clang_arch = if arch == "aarch64" { "arm64" } else { arch };

    let status = Command::new("clang")
        .args([
            "-dynamiclib",
            "-arch",
            clang_arch,
            "-Wno-deprecated-declarations",
            "-o",
        ])
        .arg(output)
        .arg(source)
        .status()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NonoError::LearnError(
                    "clang not found. Install Xcode Command Line Tools with: xcode-select --install"
                        .to_string(),
                )
            } else {
                NonoError::LearnError(format!("Failed to run clang: {}", e))
            }
        })?;

    if !status.success() {
        return Err(NonoError::LearnError(format!(
            "clang failed to compile fork interpose dylib (exit code: {})",
            status.code().unwrap_or(-1)
        )));
    }

    Ok(())
}

/// Return the directory for caching compiled interpose dylibs.
fn interpose_cache_dir() -> Result<PathBuf> {
    let tmp = std::env::temp_dir();
    Ok(tmp.join("nono_cache"))
}

/// Get file modification time as seconds since epoch, or None on error.
fn file_mtime(path: &std::path::Path) -> Option<u64> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let duration = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(duration.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interpose_c_source_embedded() {
        // The embedded source must contain the key DYLD interpose table marker
        assert!(
            FORK_INTERPOSE_C.contains("__interpose"),
            "fork_interpose.c should contain the DYLD interpose section"
        );
        assert!(
            FORK_INTERPOSE_C.contains("SIGSTOP"),
            "fork_interpose.c should contain SIGSTOP logic"
        );
    }

    #[test]
    fn test_compile_interpose_dylib() {
        // This test requires clang to be installed (Xcode CLT)
        // Skip gracefully if clang is unavailable
        if Command::new("clang").arg("--version").output().is_err() {
            eprintln!("Skipping dylib compile test: clang not available");
            return;
        }

        let dylib = get_interpose_dylib().expect("should compile interpose dylib");
        assert!(dylib.exists(), "compiled dylib should exist at {:?}", dylib);
    }
}
