# BPF programs

BPF C source for the kernel-side mediation filter. Compiled to
BPF bytecode at build time by `libbpf-cargo` (driven from
`build.rs`) and embedded into the `nono` library.

## Files

- `mediation.bpf.c` — two LSM programs that share a `(dev, ino)`
  deny map and a cgroup-ancestor scope check, plus a ring buffer
  for audit records.

  - `lsm/bprm_check_security` — fires after the kernel has
    resolved the binary the exec will load (`bprm->file`).
    Returning `-EACCES` atomically aborts the syscall. Closes
    direct-path execs of mediated binaries.
  - `lsm/file_open` — fires inside `do_filp_open` for every
    successful path resolution that yields an fd. Denying opens
    of mediated inodes prevents the agent from reading the
    binary's bytes at all (closes copy / cp / `ld-linux <bin>` /
    tmpfs / shellcode bypasses in one step).

  Loaded by `crate::sandbox::bpf_lsm::install_mediation_filter`.
  Audit records flow through the `audit_rb` ring buffer, drained
  by `crate::sandbox::bpf_audit::AuditReader`.

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
`mediation.bpf.o` plus a Rust skeleton (`mediation.skel.rs`)
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
- `CAP_BPF` for the BPF program load, `CAP_SYS_ADMIN` for the
  per-session cgroup, and `CAP_DAC_OVERRIDE` when the cgroup
  parent is root-owned (cgroup v2 `mkdir` checks DAC before
  the cgroup-namespace privilege check). Recommended deployment:
  `setcap cap_bpf,cap_sys_admin,cap_dac_override+ep
  /usr/bin/nono`.
