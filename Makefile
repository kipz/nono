# nono - Makefile for library and CLI
#
# Usage:
#   make              Build everything
#   make test         Run all tests
#   make check        Run clippy and format check
#   make release      Build release binaries

# Local code-signing certificate name (created once with: make setup-signing-cert)
SIGN_CERT ?= nono-dev

.PHONY: all build build-lib build-cli build-approve build-ffi build-arm64 test test-lib test-cli test-approve test-ffi check clippy fmt clean install audit sign setup-signing-cert help

# Default target
all: build

# Build targets
build: build-lib build-cli build-approve

build-lib:
	cargo build -p nono

build-cli:
	cargo build -p nono-cli
	@$(MAKE) sign --no-print-directory 2>/dev/null || true

build-approve:
	cargo build -p nono-approve

build-ffi:
	cargo build -p nono-ffi

build-release:
	cargo build --release

build-release-lib:
	cargo build --release -p nono

build-release-cli:
	cargo build --release -p nono-cli

# Cross-compilation: Linux ARM64 (aarch64-unknown-linux-gnu)
# Uses `cross` which handles both native (ARM64) and cross-compilation (e.g. x86_64).
# On native Linux ARM64, you may need to install `libdbus-1-dev` and `pkg-config`.
# If `cross` fails with "may not be able to run on this system",
# install from git: cargo install cross --git https://github.com/cross-rs/cross
build-arm64:
	@cross build --release --target aarch64-unknown-linux-gnu -p nono-cli

# Test targets
test: test-lib test-cli test-approve test-ffi

test-lib:
	cargo test -p nono

test-cli:
	cargo test -p nono-cli

test-approve:
	cargo test -p nono-approve

test-ffi:
	cargo test -p nono-ffi

test-doc:
	cargo test --doc

# Integration tests for the BPF-LSM mediation filter. These spawn a
# real `nono run` session, which requires the test binary to have
# cap_bpf,cap_sys_admin,cap_dac_override+ep so the broker can install
# the BPF program and create the per-session cgroup.
#
# Cargo re-links `target/debug/nono` and clears file caps on every
# `cargo test`, so this target builds the binaries first, setcaps the
# `nono` binary, and only then runs the integration suite. Without
# the setcap step the tests self-skip with an informative message.
#
# Requires sudo for the setcap call. CI runs this; everyday `make
# ci` does not (it sticks to the no-sudo `cargo test` which leaves
# these tests in their self-skip mode).
test-integration:
	# Build everything the test profile needs (nono + nono-shim) but
	# don't run yet — we need a stable nono binary so setcap doesn't
	# get clobbered before the actual test invocation.
	cargo test --no-run -p nono-cli --test bpf_lsm_integration
	# `nono-shim` is built lazily by the test harness's first call,
	# but doing it here too ensures it lives next to nono before we
	# setcap (avoids any first-run interference).
	cargo build -p nono-shim --bin nono-shim
	# Apply file caps so the spawned broker can install BPF-LSM.
	# Subsequent `cargo test` is a no-op rebuild and preserves caps.
	sudo setcap cap_bpf,cap_sys_admin,cap_dac_override+ep target/debug/nono
	cargo test -p nono-cli --test bpf_lsm_integration -- --nocapture

# Check targets (lint + format)
check: clippy fmt-check

clippy:
	cargo clippy --workspace --all-targets --all-features -- -D warnings -D clippy::unwrap_used

clippy-fix:
	cargo clippy --fix --allow-dirty

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

# Clean
clean:
	cargo clean

# Install CLI to ~/.cargo/bin
install:
	cargo install --path crates/nono-cli

# Run the CLI (for quick testing)
run:
	cargo run -p nono-cli -- --help

run-setup:
	cargo run -p nono-cli -- setup --check-only

run-dry:
	cargo run -p nono-cli -- run --allow-cwd --dry-run -- echo "test"

# Development helpers
watch:
	cargo watch -x 'build -p nono-cli'

watch-test:
	cargo watch -x 'test'

# Documentation
doc:
	cargo doc --no-deps --open

doc-lib:
	cargo doc -p nono --no-deps --open

# Code signing — signs debug binaries so macOS Keychain "Always Allow" persists across rebuilds.
# Requires a local certificate created once with: make setup-signing-cert
sign:
	@if security find-certificate -c "$(SIGN_CERT)" ~/Library/Keychains/login.keychain-db >/dev/null 2>&1; then \
		codesign -f -s "$(SIGN_CERT)" target/debug/nono target/debug/nono-shim 2>/dev/null && \
		echo "Signed debug binaries with '$(SIGN_CERT)'"; \
	fi

# One-time setup: create a local self-signed code-signing certificate.
# After running this, 'make build' will automatically sign the binaries.
setup-signing-cert:
	@echo "Creating local code-signing certificate '$(SIGN_CERT)'..."
	@TMPD=$$(mktemp -d) && \
	printf '[req]\ndefault_bits=2048\nprompt=no\ndefault_md=sha256\ndistinguished_name=dn\nx509_extensions=v3\n[dn]\nCN=$(SIGN_CERT)\n[v3]\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,codeSigning\nbasicConstraints=CA:FALSE\n' > $$TMPD/cert.conf && \
	openssl req -x509 -newkey rsa:2048 -days 3650 -nodes -keyout $$TMPD/key.pem -out $$TMPD/cert.pem -config $$TMPD/cert.conf 2>/dev/null && \
	openssl pkcs12 -export -in $$TMPD/cert.pem -inkey $$TMPD/key.pem -out $$TMPD/cert.p12 -passout pass:nono -legacy -macalg SHA1 2>/dev/null && \
	security import $$TMPD/cert.p12 -k ~/Library/Keychains/login.keychain-db -P nono -T /usr/bin/codesign -A && \
	rm -rf $$TMPD && \
	echo "Done. Run 'make build' to sign binaries automatically."

# Security audit
audit:
	cargo audit

# CI simulation (what CI would run)
ci: check test audit
	@echo "CI checks passed"

# Help
help:
	@echo "nono Makefile targets:"
	@echo ""
	@echo "Build:"
	@echo "  make build          Build library and CLI (debug)"
	@echo "  make build-lib      Build library only"
	@echo "  make build-cli      Build CLI only"
	@echo "  make build-ffi      Build C FFI bindings"
	@echo "  make build-release  Build release binaries"
	@echo "  make build-arm64    Build CLI for Linux ARM64 (cargo on Linux ARM64; cross elsewhere)"
	@echo ""
	@echo "Test:"
	@echo "  make test           Run all tests"
	@echo "  make test-lib       Run library tests only"
	@echo "  make test-cli       Run CLI tests only"
	@echo "  make test-ffi       Run C FFI tests only"
	@echo "  make test-doc       Run doc tests only"
	@echo ""
	@echo "Check:"
	@echo "  make check          Run clippy and format check"
	@echo "  make clippy         Run clippy linter"
	@echo "  make fmt            Format code"
	@echo "  make fmt-check      Check formatting"
	@echo ""
	@echo "Security:"
	@echo "  make audit          Run cargo audit for vulnerabilities"
	@echo ""
	@echo "Other:"
	@echo "  make install        Install CLI to ~/.cargo/bin"
	@echo "  make clean          Clean build artifacts"
	@echo "  make doc            Generate and open documentation"
	@echo "  make ci             Simulate CI checks"
	@echo "  make help           Show this help"
