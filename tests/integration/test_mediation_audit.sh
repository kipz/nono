#!/bin/bash
# Mediation Audit Tests
# Verifies universal command audit logging via shim hooks.
# Commands listed in mediation.commands go through full request-response mediation.
# All other PATH commands get fire-and-forget audit logging + in-sandbox exec.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/test_helpers.sh"

echo ""
echo -e "${BLUE}=== Mediation Audit Tests ===${NC}"

verify_nono_binary

# Override sandbox probe to include --trust-override (trust key loading may block
# in non-interactive environments without it).
probe_mediation_sandbox() {
    local probe_dir
    probe_dir=$(mktemp -d)
    set +e
    local probe_output
    probe_output=$("$NONO_BIN" run --trust-override --allow "$probe_dir" -- true </dev/null 2>&1)
    local probe_exit=$?
    set -e
    rm -rf "$probe_dir"
    [[ "$probe_exit" -eq 0 ]]
}

if ! probe_mediation_sandbox; then
    skip_test "mediation audit suite" "sandbox unavailable in this environment"
    print_summary
    exit 0
fi

# Verify nono-shim binary exists next to nono
NONO_DIR=$(dirname "$NONO_BIN")
if [[ ! -x "$NONO_DIR/nono-shim" ]]; then
    skip_test "mediation audit suite" "nono-shim not found at $NONO_DIR/nono-shim"
    print_summary
    exit 0
fi

TMPDIR=$(setup_test_dir)
trap 'cleanup_test_dir "$TMPDIR"' EXIT

# Create test fixtures
echo "test content" > "$TMPDIR/file.txt"

# Create test profile with one mediated command and audit enabled
PROFILE_PATH="$TMPDIR/test-audit-profile.json"
cat > "$PROFILE_PATH" << 'EOF'
{
  "groups": ["system_read_common"],
  "mediation": {
    "commands": [
      {
        "name": "echo",
        "intercept": [
          {
            "args_prefix": ["SECRET"],
            "action": { "type": "respond", "stdout": "REDACTED\n", "exit_code": 0 }
          }
        ]
      }
    ]
  }
}
EOF

echo ""
echo "Test directory: $TMPDIR"
echo "Profile: $PROFILE_PATH"
echo ""

# Helper: run nono with our profile and capture output + exit code.
# The session dir is under /tmp (macOS: /private/tmp) named nono-session-{pid}.
# We capture nono's PID so we can find the session dir.
run_nono_mediated() {
    local stdout_file="$TMPDIR/last_stdout"
    local stderr_file="$TMPDIR/last_stderr"
    set +e
    "$NONO_BIN" run --silent --trust-override --profile "$PROFILE_PATH" --allow "$TMPDIR" --allow-cwd -- "$@" \
        >"$stdout_file" 2>"$stderr_file"
    LAST_EXIT=$?
    set -e
    LAST_STDOUT=$(cat "$stdout_file")
    LAST_STDERR=$(cat "$stderr_file")
}

# Helper: find the most recent audit.jsonl in /tmp/nono-session-* or /private/tmp/nono-session-*
find_audit_log() {
    local pattern
    if is_macos; then
        pattern="/private/tmp/nono-session-*/audit.jsonl"
    else
        pattern="/tmp/nono-session-*/audit.jsonl"
    fi
    # Return the most recently modified one
    # shellcheck disable=SC2086
    ls -t $pattern 2>/dev/null | head -1
}

# Helper: wait briefly for audit log to appear (async write)
wait_for_audit_log() {
    local max_wait=3
    local elapsed=0
    while [[ $elapsed -lt $max_wait ]]; do
        if [[ -n "$(find_audit_log)" ]]; then
            return 0
        fi
        sleep 0.5
        elapsed=$((elapsed + 1))
    done
    return 1
}

# =============================================================================
# Basic audit logging for non-mediated commands
# =============================================================================

echo "--- Basic Audit Logging ---"

# Test 1: Non-mediated command (ls) is audited
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated ls "$TMPDIR"
if [[ "$LAST_EXIT" -eq 0 ]] && echo "$LAST_STDOUT" | grep -q "file.txt"; then
    echo -e "  ${GREEN}PASS${NC}: ls runs successfully through audit shim"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: ls runs successfully through audit shim"
    echo "       Exit: $LAST_EXIT, stdout: ${LAST_STDOUT:0:200}"
    echo "       Stderr: ${LAST_STDERR:0:500}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 2: Audit log contains entry for ls
TESTS_RUN=$((TESTS_RUN + 1))
wait_for_audit_log
AUDIT_LOG=$(find_audit_log)
if [[ -n "$AUDIT_LOG" ]] && grep -q '"command":"ls"' "$AUDIT_LOG"; then
    echo -e "  ${GREEN}PASS${NC}: audit log contains ls entry"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: audit log contains ls entry"
    echo "       Audit log: ${AUDIT_LOG:-not found}"
    if [[ -n "$AUDIT_LOG" ]]; then
        echo "       Contents: $(cat "$AUDIT_LOG" 2>/dev/null | head -5)"
    fi
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 3: cat runs through audit shim
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated cat "$TMPDIR/file.txt"
if [[ "$LAST_EXIT" -eq 0 ]] && echo "$LAST_STDOUT" | grep -q "test content"; then
    echo -e "  ${GREEN}PASS${NC}: cat runs successfully through audit shim"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: cat runs successfully through audit shim"
    echo "       Exit: $LAST_EXIT, stdout: ${LAST_STDOUT:0:200}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Mediated vs Audit distinction
# =============================================================================

echo ""
echo "--- Mediated vs Audit Distinction ---"

# Test 4: echo SECRET is intercepted (returns REDACTED)
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated echo SECRET
if echo "$LAST_STDOUT" | grep -q "REDACTED"; then
    echo -e "  ${GREEN}PASS${NC}: echo SECRET is intercepted and returns REDACTED"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: echo SECRET is intercepted and returns REDACTED"
    echo "       stdout: ${LAST_STDOUT:0:200}"
    echo "       stderr: ${LAST_STDERR:0:200}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 5: echo normal runs via mediation passthrough (not intercepted)
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated echo normal
if echo "$LAST_STDOUT" | grep -q "normal"; then
    echo -e "  ${GREEN}PASS${NC}: echo normal passes through mediation"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: echo normal passes through mediation"
    echo "       stdout: ${LAST_STDOUT:0:200}"
    echo "       stderr: ${LAST_STDERR:0:200}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Exit code preservation
# =============================================================================

echo ""
echo "--- Exit Code Preservation ---"

# Test 6: false returns exit code 1 through audit shim
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated false
if [[ "$LAST_EXIT" -eq 1 ]]; then
    echo -e "  ${GREEN}PASS${NC}: false preserves exit code 1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: false preserves exit code 1"
    echo "       Expected exit 1, got: $LAST_EXIT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 7: sh -c 'exit 42' preserves exit code
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated sh -c "exit 42"
if [[ "$LAST_EXIT" -eq 42 ]]; then
    echo -e "  ${GREEN}PASS${NC}: sh -c 'exit 42' preserves exit code"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: sh -c 'exit 42' preserves exit code"
    echo "       Expected exit 42, got: $LAST_EXIT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Audit log format
# =============================================================================

echo ""
echo "--- Audit Log Format ---"

# Test 8: Each line of audit.jsonl is valid JSON with expected fields
TESTS_RUN=$((TESTS_RUN + 1))
AUDIT_LOG=$(find_audit_log)
if [[ -n "$AUDIT_LOG" ]]; then
    all_valid=true
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then continue; fi
        # Check it's valid JSON with required fields
        if ! echo "$line" | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'command' in d, 'missing command'
assert 'args' in d, 'missing args'
assert 'ts' in d, 'missing ts'
assert 'exit_code' in d, 'missing exit_code'
" 2>/dev/null; then
            all_valid=false
            break
        fi
    done < "$AUDIT_LOG"
    if $all_valid; then
        echo -e "  ${GREEN}PASS${NC}: audit.jsonl entries have valid format"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: audit.jsonl entries have valid format"
        echo "       Invalid line found in $AUDIT_LOG"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "  ${RED}FAIL${NC}: audit.jsonl entries have valid format"
    echo "       No audit log found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 9: Timestamps are monotonically non-decreasing
TESTS_RUN=$((TESTS_RUN + 1))
AUDIT_LOG=$(find_audit_log)
if [[ -n "$AUDIT_LOG" ]]; then
    monotonic=true
    last_ts=0
    while IFS= read -r line; do
        if [[ -z "$line" ]]; then continue; fi
        ts=$(echo "$line" | python3 -c "import sys, json; print(json.load(sys.stdin).get('ts', 0))" 2>/dev/null)
        if [[ -n "$ts" ]] && [[ "$ts" -lt "$last_ts" ]]; then
            monotonic=false
            break
        fi
        last_ts="${ts:-$last_ts}"
    done < "$AUDIT_LOG"
    if $monotonic; then
        echo -e "  ${GREEN}PASS${NC}: audit timestamps are monotonically non-decreasing"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo -e "  ${RED}FAIL${NC}: audit timestamps are monotonically non-decreasing"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "  ${RED}FAIL${NC}: audit timestamps are monotonically non-decreasing"
    echo "       No audit log found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Universal shim coverage
# =============================================================================

echo ""
echo "--- Universal Shim Coverage ---"

# Test 10: Shim dir is first in PATH inside sandbox (contains "shim" in name)
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated sh -c 'echo $PATH | cut -d: -f1'
first_path_entry="$LAST_STDOUT"
if echo "$first_path_entry" | grep -qi "shim"; then
    echo -e "  ${GREEN}PASS${NC}: shim dir is first in PATH inside sandbox"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: shim dir is first in PATH inside sandbox"
    echo "       First PATH entry: ${first_path_entry:0:200}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Pipe handling
# =============================================================================

echo ""
echo "--- Pipe and Stdin Handling ---"

# Test 11: Piped commands work through audit shims
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated sh -c "echo hello | cat"
if echo "$LAST_STDOUT" | grep -q "hello"; then
    echo -e "  ${GREEN}PASS${NC}: piped commands work through audit shims"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: piped commands work through audit shims"
    echo "       stdout: ${LAST_STDOUT:0:200}"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Response logging: exit_code and action_type in audit trail
# =============================================================================

echo ""
echo "--- Response Logging ---"

# Helper: find ALL audit.jsonl files across all nono sessions.
find_all_audit_logs() {
    local pattern
    if is_macos; then
        pattern="/private/tmp/nono-session-*/audit.jsonl"
    else
        pattern="/tmp/nono-session-*/audit.jsonl"
    fi
    # shellcheck disable=SC2086
    ls $pattern 2>/dev/null
}

# Test 12: echo SECRET (intercepted) has exit_code:0 and action_type:respond
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated echo SECRET
sleep 0.5
found_respond=false
for log in $(find_all_audit_logs); do
    if grep '"command":"echo"' "$log" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    if d['command'] == 'echo' and d.get('args', []) == ['SECRET']:
        assert d['exit_code'] == 0
        assert d.get('action_type') == 'respond'
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        found_respond=true
        break
    fi
done
if $found_respond; then
    echo -e "  ${GREEN}PASS${NC}: echo SECRET has exit_code:0 and action_type:respond"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: echo SECRET has exit_code:0 and action_type:respond"
    for log in $(find_all_audit_logs); do
        echo "       $log: $(grep '"command":"echo"' "$log" 2>/dev/null)"
    done
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 13: echo normal (passthrough) has exit_code:0 and action_type:passthrough
TESTS_RUN=$((TESTS_RUN + 1))
run_nono_mediated echo normal
sleep 0.5
found_passthrough=false
for log in $(find_all_audit_logs); do
    if grep '"command":"echo"' "$log" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    if d['command'] == 'echo' and d.get('args', []) == ['normal']:
        assert d['exit_code'] == 0
        assert d.get('action_type') == 'passthrough'
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        found_passthrough=true
        break
    fi
done
if $found_passthrough; then
    echo -e "  ${GREEN}PASS${NC}: echo normal has exit_code:0 and action_type:passthrough"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: echo normal has exit_code:0 and action_type:passthrough"
    for log in $(find_all_audit_logs); do
        echo "       $log: $(grep '"command":"echo"' "$log" 2>/dev/null)"
    done
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 14: mediated command with non-zero exit has exit_code in audit log.
# Use a profile where `false` is a mediated command (no intercepts → passthrough).
TESTS_RUN=$((TESTS_RUN + 1))
FALSE_PROFILE="$TMPDIR/false-profile.json"
cat > "$FALSE_PROFILE" << 'FALSEOF'
{
  "groups": ["system_read_common"],
  "mediation": {
    "commands": [
      { "name": "false", "intercept": [] }
    ]
  }
}
FALSEOF
set +e
"$NONO_BIN" run --silent --trust-override --profile "$FALSE_PROFILE" --allow "$TMPDIR" --allow-cwd -- false \
    >"$TMPDIR/false_stdout" 2>"$TMPDIR/false_stderr"
set -e
sleep 0.5
found_false=false
for log in $(find_all_audit_logs); do
    if grep '"command":"false"' "$log" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    if d['command'] == 'false' and d['exit_code'] == 1 and d.get('action_type') == 'passthrough':
        sys.exit(0)
sys.exit(1)
" 2>/dev/null; then
        found_false=true
        break
    fi
done
if $found_false; then
    echo -e "  ${GREEN}PASS${NC}: false has exit_code:1 and action_type:passthrough in audit log"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: false has exit_code:1 and action_type:passthrough in audit log"
    for log in $(find_all_audit_logs); do
        if grep -q '"command":"false"' "$log" 2>/dev/null; then
            echo "       $log: $(grep '"command":"false"' "$log")"
        fi
    done
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 15: No stdout or stderr keys in any audit log entry (secret safety)
TESTS_RUN=$((TESTS_RUN + 1))
leaked=false
for log in $(find_all_audit_logs); do
    if grep -q '"stdout"' "$log" || grep -q '"stderr"' "$log"; then
        leaked=true
        break
    fi
done
if ! $leaked; then
    echo -e "  ${GREEN}PASS${NC}: audit log contains no stdout or stderr keys"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: audit log must not contain stdout or stderr keys"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# Test 16: No nonce patterns in audit log (secret safety)
TESTS_RUN=$((TESTS_RUN + 1))
nonce_found=false
for log in $(find_all_audit_logs); do
    if grep -qE 'nono_[0-9a-f]' "$log"; then
        nonce_found=true
        break
    fi
done
if ! $nonce_found; then
    echo -e "  ${GREEN}PASS${NC}: audit log contains no nonce patterns"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo -e "  ${RED}FAIL${NC}: audit log must not contain nonce patterns"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# =============================================================================
# Summary
# =============================================================================

print_summary
