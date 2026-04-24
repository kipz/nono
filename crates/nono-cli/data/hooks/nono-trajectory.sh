#!/usr/bin/env bash
# nono-trajectory.sh - emit trajectory-spec JSONL from Claude Code hook events.
# Version: 0.0.1
#
# Installed to ~/.claude/hooks/ by the claude-code profile. Fires for
# SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, and SessionEnd.
# Exits silently when not running inside a nono sandbox or when required
# tooling is missing, so it is safe to leave registered outside nono.
#
# Output: one JSONL line per event appended to
#   $HOME/.nono/trajectory/session-<claude_session_id>.jsonl
#
# Spec: DataDog/trajectory-spec v0.1 (standard capture level).
# Deliberate non-conformance (see docs/2026-04-23-adopt-trajectory-spec.md §6):
# this first pass emits 5 of 8 event types; Stop/SubagentStop/PreCompact are
# follow-ups.

set -u

# Only run when nono is active. NONO_CAP_FILE is the established marker.
if [ -z "${NONO_CAP_FILE:-}" ]; then
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    exit 0
fi

payload=$(cat)
if [ -z "$payload" ]; then
    exit 0
fi

event_name=$(printf '%s' "$payload" | jq -r '.hook_event_name // empty' 2>/dev/null)
session_id=$(printf '%s' "$payload" | jq -r '.session_id // empty' 2>/dev/null)

if [ -z "$event_name" ] || [ -z "$session_id" ]; then
    exit 0
fi

# Validate session_id shape: hex / dash only, max 128 chars. Guards against
# path traversal via a malicious hook payload.
case "$session_id" in
    *[!a-zA-Z0-9_-]*) exit 0 ;;
esac
if [ "${#session_id}" -gt 128 ]; then
    exit 0
fi

traj_root="$HOME/.nono/trajectory"
out="$traj_root/session-$session_id.jsonl"
seq_file="$traj_root/.seq-$session_id"
turn_file="$traj_root/.turn-$session_id"
pending_tool_file="$traj_root/.pending-tool-$session_id"

mkdir -p "$traj_root" || exit 0
chmod 700 "$traj_root" 2>/dev/null || true

# Serialize reads and writes of the counters and output file under a single
# lock so sequence_number is strictly increasing across concurrent hook
# invocations (trajectory-spec I9).
lock="$traj_root/.lock-$session_id"
exec 9>"$lock" || exit 0
if command -v flock >/dev/null 2>&1; then
    flock 9
fi

seq=$(cat "$seq_file" 2>/dev/null || echo 0)
case "$seq" in ''|*[!0-9]*) seq=0 ;; esac
next_seq=$((seq + 1))
printf '%s' "$next_seq" > "$seq_file"

turn=$(cat "$turn_file" 2>/dev/null || echo 0)
case "$turn" in ''|*[!0-9]*) turn=0 ;; esac

# RFC 3339 UTC timestamp with millisecond precision. BSD `date` (macOS) does
# not support %3N / %N, so fall back to python when available.
if date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null | grep -qv 'N'; then
    ts=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ")
else
    ts=$(python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z")' 2>/dev/null)
    if [ -z "$ts" ]; then
        ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    fi
fi

# emit <event_type> <extra-json-object>
# Composes the base fields with an event-specific JSON fragment and appends
# one line to the output file.
emit() {
    local et="$1"
    local extra="$2"
    printf '%s' "$payload" | jq -c \
        --arg et "$et" \
        --arg ts "$ts" \
        --argjson sn "$seq" \
        --argjson extra "$extra" \
        '{event_type: $et, timestamp: $ts, sequence_number: $sn} + $extra' \
        >> "$out"
}

case "$event_name" in
    SessionStart)
        model=$(printf '%s' "$payload" | jq -r '.model // "unknown"')
        cwd=$(printf '%s' "$payload" | jq -r '.cwd // ""')
        source=$(printf '%s' "$payload" | jq -r '.source // ""')
        extra=$(jq -nc \
            --arg sid "$session_id" \
            --arg started "$ts" \
            --arg model "$model" \
            --arg cwd "$cwd" \
            --arg source "$source" \
            '{
                format_version: 1,
                session_id: $sid,
                started_at: $started,
                model: ("nono-sandbox/" + $model),
                capture_level: "standard",
                project_dir: $cwd,
                client_source: (if $source == "" then null else $source end)
            } | del(..|nulls)')
        emit session_start "$extra"
        # Fresh session: no turn has started yet.
        printf '0' > "$turn_file"
        ;;

    UserPromptSubmit)
        # Each new user prompt starts a new turn. Bump first so this prompt and
        # any tool_use events Claude emits while responding share the same turn_id.
        turn=$((turn + 1))
        printf '%s' "$turn" > "$turn_file"
        prompt=$(printf '%s' "$payload" | jq -r '.prompt // ""')
        extra=$(jq -nc \
            --argjson tid "$turn" \
            --arg content "$prompt" \
            '{turn_id: $tid, content: $content}')
        emit input_prompt "$extra"
        ;;

    PreToolUse)
        tool=$(printf '%s' "$payload" | jq -r '.tool_name // "unknown"')
        # tool_use_id: prefer Claude-provided id if present, else synthesize.
        tuid=$(printf '%s' "$payload" | jq -r '.tool_use_id // empty')
        if [ -z "$tuid" ]; then
            tuid="$session_id:$seq"
        fi
        input=$(printf '%s' "$payload" | jq -c '.tool_input // {}')
        extra=$(jq -nc \
            --argjson tid "$turn" \
            --arg tuid "$tuid" \
            --arg tn "$tool" \
            --argjson inp "$input" \
            '{turn_id: $tid, tool_use_id: $tuid, tool_name: $tn, phase: "pre", input: $inp}')
        emit tool_use "$extra"
        # Record the last tool_use_id so PostToolUse can pair even when Claude
        # does not echo it back on the post event.
        printf '%s\n%s' "$tuid" "$tool" > "$pending_tool_file"
        ;;

    PostToolUse)
        tool=$(printf '%s' "$payload" | jq -r '.tool_name // "unknown"')
        tuid=$(printf '%s' "$payload" | jq -r '.tool_use_id // empty')
        if [ -z "$tuid" ] && [ -f "$pending_tool_file" ]; then
            tuid=$(sed -n '1p' "$pending_tool_file")
        fi
        if [ -z "$tuid" ]; then
            tuid="$session_id:$seq"
        fi
        # Heuristic: treat absence of tool_response.error / presence of a result as success.
        success=$(printf '%s' "$payload" | jq -c '
            if (.tool_response // .tool_result // null) == null then true
            elif (.tool_response.error? // .tool_result.error? // null) != null then false
            elif (.tool_response.is_error? // false) == true then false
            else true end')
        # output_summary at standard capture: short structural summary only,
        # never raw output (spec I11 forbids `output` at standard level).
        exit_code=$(printf '%s' "$payload" | jq -c '.tool_response.exit_code? // .tool_result.exit_code? // null')
        summary_obj=$(jq -nc \
            --argjson ec "$exit_code" \
            --argjson succ "$success" \
            '{
                success: $succ,
                exit_code: (if $ec == null then null else $ec end)
            } | del(..|nulls)')
        extra=$(jq -nc \
            --argjson tid "$turn" \
            --arg tuid "$tuid" \
            --arg tn "$tool" \
            --argjson succ "$success" \
            --argjson summary "$summary_obj" \
            '{turn_id: $tid, tool_use_id: $tuid, tool_name: $tn, phase: "post", success: $succ, output_summary: ($summary | tojson)}')
        emit tool_use "$extra"
        rm -f "$pending_tool_file" 2>/dev/null || true
        ;;

    SessionEnd)
        reason=$(printf '%s' "$payload" | jq -r '.reason // "unknown"')
        exit_reason="task_complete"
        case "$reason" in
            clear|logout|user_exit) exit_reason="user_exit" ;;
            error|crash) exit_reason="error" ;;
            *) exit_reason="task_complete" ;;
        esac
        extra=$(jq -nc \
            --arg er "$exit_reason" \
            --argjson tt "$turn" \
            '{exit_reason: $er, total_turns: $tt}')
        emit session_end "$extra"
        # Clean up sidecars; leave the JSONL output in place.
        rm -f "$seq_file" "$turn_file" "$pending_tool_file" "$lock" 2>/dev/null || true
        ;;

    *)
        # Unknown event: drop silently. Spec compliance requires no action.
        exit 0
        ;;
esac
