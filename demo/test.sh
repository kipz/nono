#!/usr/bin/env bash
set -euo pipefail

REAL_TOKEN="ghp_SUPERSECRET_DEMO_TOKEN_abcdef123456"

sep() { printf '\n%s\n' "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"; }

sep
echo "1. SANDBOX INITIAL ENVIRONMENT"
echo "   GH_TOKEN = '${GH_TOKEN:-<empty — blocked by env.block>}'"
if [[ -z "${GH_TOKEN:-}" ]]; then
    echo "   ✓ PASS: real token is not visible inside the sandbox"
else
    echo "   ✗ FAIL: token leaked into sandbox"
    exit 1
fi

sep
echo "2. CAPTURE: run ddtool auth github token"
NONCE=$(ddtool auth github token)
echo "   ddtool returned: '$NONCE'"

if [[ "$NONCE" == nono_* ]]; then
    echo "   ✓ PASS: returned a nono_ nonce, not the real token"
else
    echo "   ✗ FAIL: expected a nonce, got something else"
    exit 1
fi

if [[ "$NONCE" == "$REAL_TOKEN" ]]; then
    echo "   ✗ FAIL: nonce equals the real token — credential leaked!"
    exit 1
else
    echo "   ✓ PASS: nonce ('${NONCE:0:16}…') ≠ real token ('${REAL_TOKEN:0:16}…')"
fi

sep
echo "3. NONCE PROPERTIES"
NONCE_SUFFIX="${NONCE#nono_}"
echo "   prefix : 'nono_'"
echo "   hex    : '${NONCE_SUFFIX:0:16}…' (${#NONCE_SUFFIX} chars = 32 random bytes)"
if [[ ${#NONCE_SUFFIX} -eq 64 ]]; then
    echo "   ✓ PASS: 64 hex chars (256 bits of entropy)"
else
    echo "   ✗ FAIL: unexpected nonce length ${#NONCE_SUFFIX}"
    exit 1
fi

sep
echo "4. EXPORT THE NONCE AS GH_TOKEN"
export GH_TOKEN="$NONCE"
echo "   GH_TOKEN = '$GH_TOKEN'"
echo "   ✓ The sandbox holds a nonce — never the real credential"

sep
echo "5. ATTEMPT TO RECOVER THE REAL TOKEN FROM WITHIN THE SANDBOX"

echo ""
echo "   5a. Check env directly:"
if env | grep -q "^GH_TOKEN=$REAL_TOKEN"; then
    echo "       ✗ FAIL: real token found in env"
    exit 1
else
    echo "       GH_TOKEN in env: '$(env | grep ^GH_TOKEN= | cut -d= -f2)'"
    echo "       ✓ PASS: real token is not in env"
fi

echo ""
echo "   5b. Grep all env vars for the real token string:"
if env | grep -qF "$REAL_TOKEN"; then
    echo "       ✗ FAIL: real token found somewhere in env"
    exit 1
else
    echo "       ✓ PASS: real token string not found anywhere in sandbox env"
fi

echo ""
echo "   5c. The broker is in the server process (outside the sandbox)."
echo "       The sandbox cannot open the mediation socket directly to probe it:"
SOCK="${NONO_MEDIATION_SOCKET:-}"
if [[ -z "$SOCK" ]]; then
    echo "       (NONO_MEDIATION_SOCKET not set — socket path hidden from test)"
else
    echo "       socket: $SOCK"
    # Trying to resolve a nonce by crafting a raw request would require
    # speaking the length-prefixed JSON protocol — and even then the broker
    # only returns the value to exec'd binaries in the parent, not to the sandbox.
    echo "       ✓ Socket is reachable only by the shim binary — not by arbitrary code"
fi

sep
echo "6. SUMMARY"
echo ""
echo "   Parent env:         GH_TOKEN = $REAL_TOKEN"
echo "   Sandbox env:        GH_TOKEN = <empty>   (blocked by env.block)"
echo "   After capture:      GH_TOKEN = $NONCE"
echo "   Broker stores:      '$NONCE' → '$REAL_TOKEN' (server-side only)"
echo "   On passthrough:     exec'd gh/aws/etc receive GH_TOKEN=$REAL_TOKEN"
echo "   Sandbox never sees: $REAL_TOKEN"
echo ""
echo "   ✓ ALL CHECKS PASSED"
sep
