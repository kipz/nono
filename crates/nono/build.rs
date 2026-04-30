//! Build script for nono library.
//!
//! Two responsibilities, both producing files under `$OUT_DIR`:
//!
//! 1. Generate Rust types from the capability-manifest JSON Schema
//!    via typify (the schema is the source of truth).
//! 2. On Linux with the `bpf-lsm` feature enabled: compile
//!    `src/bpf/mediation.bpf.c` to BPF bytecode and emit a Rust
//!    skeleton module that embeds the bytecode and exposes
//!    type-safe map / program handles. The skeleton is loaded at
//!    runtime by `crate::sandbox::bpf_lsm`.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    generate_capability_manifest_types();

    #[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
    generate_mediation_skeleton();
}

fn generate_capability_manifest_types() {
    println!("cargo:rerun-if-changed=schema/capability-manifest.schema.json");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");

    let schema_str = include_str!("schema/capability-manifest.schema.json");
    let schema = serde_json::from_str::<serde_json::Value>(schema_str)
        .expect("capability-manifest.schema.json is not valid JSON");

    let mut type_space =
        typify::TypeSpace::new(typify::TypeSpaceSettings::default().with_struct_builder(true));

    type_space
        .add_root_schema(serde_json::from_value(schema).expect("schema is not valid JSON Schema"))
        .expect("failed to process capability manifest schema");

    let contents = prettyplease::unparse(
        &syn::parse2::<syn::File>(type_space.to_stream())
            .expect("failed to parse generated tokens"),
    );

    let out_path = Path::new(&out_dir).join("capability_manifest_types.rs");
    fs::write(&out_path, contents).expect("failed to write generated types");
}

#[cfg(all(target_os = "linux", feature = "bpf-lsm"))]
fn generate_mediation_skeleton() {
    use libbpf_cargo::SkeletonBuilder;

    println!("cargo:rerun-if-changed=src/bpf/mediation.bpf.c");
    println!("cargo:rerun-if-changed=src/bpf/vmlinux.h");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let skel_out = Path::new(&out_dir).join("mediation.skel.rs");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let bpf_dir = Path::new(&manifest_dir).join("src").join("bpf");

    SkeletonBuilder::new()
        .source(bpf_dir.join("mediation.bpf.c"))
        // -I <bpf_dir> so #include "vmlinux.h" resolves.
        // -mcpu=v3 enables the modern BPF instruction set (Linux 5.1+);
        // BPF-LSM requires 5.7+ so this is always available.
        .clang_args([
            std::ffi::OsString::from("-I"),
            bpf_dir.into_os_string(),
            std::ffi::OsString::from("-mcpu=v3"),
        ])
        .build_and_generate(&skel_out)
        .expect("failed to build BPF mediation skeleton");
}
