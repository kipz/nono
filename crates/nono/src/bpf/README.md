# BPF programs

BPF C source for the kernel-side exec filter. Compiled to BPF
bytecode at build time by `libbpf-cargo` (driven from `build.rs`)
and embedded into the `nono` library.

## Files

- `exec_filter.bpf.c` — LSM program at `bprm_check_security`.
  Denies exec when the binary's `(dev, ino)` is in the deny set.
  Loaded by `crate::sandbox::bpf_lsm::install_exec_filter`.

- `vmlinux.h` — vendored kernel-type header from
  `bpftool btf dump file /sys/kernel/btf/vmlinux format c`. Frozen
  at the moment of generation; CO-RE relocations at load time make
  the program compatible with kernels that have a different BTF
  layout, as long as the structs we use still exist.

  Regenerate with a recent bpftool (≥ 7.0 — Ubuntu 22.04's
  bpftool 5.15 cannot read 6.x BTF):

  ```
  sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c \
      > crates/nono/src/bpf/vmlinux.h
  ```

  Only worth regenerating if the BPF program adds field accesses
  on a struct that the current `vmlinux.h` doesn't declare.

## Build requirements

`libbpf-cargo` invokes `clang` with `-target bpf` and emits
`exec_filter.bpf.o` plus a Rust skeleton (`exec_filter.skel.rs`)
under `$OUT_DIR`. The skeleton embeds the bytecode via
`include_bytes!` so the compiled `nono` binary carries the BPF
program. No runtime dependency on libbpf-cargo.

The host needs:
- `clang` (any modern version; 14+ tested).
- That's it — `libbpf` itself is statically linked via
  `libbpf-sys`.

## Runtime requirements

- `CONFIG_BPF_LSM=y` in the running kernel.
- `bpf` in `/sys/kernel/security/lsm` (set via `lsm=...,bpf` on
  the kernel cmdline). The workspaces AMI ships a grub.d
  drop-in for this; see dd-source `am/bpf-lsm-workspace-ami`.
- `CAP_BPF` (or `CAP_SYS_ADMIN`) on the loader process.
