//! Integration test for `data/hooks/nono-trajectory.sh`.
//!
//! Drives the dispatcher with a scripted sequence of Claude Code hook
//! payloads and asserts the emitted JSONL matches trajectory-spec v0.1
//! (standard capture level). Skipped when `jq` is not available — the
//! script gates on it and would simply exit 0.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("data/hooks/nono-trajectory.sh")
}

fn jq_available() -> bool {
    Command::new("jq")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pipe `payload_json` into the trajectory hook with `HOME` set to `home`
/// and `NONO_CAP_FILE` set (so the gate passes). Fails the test on non-zero exit.
fn feed(home: &PathBuf, payload_json: &str) {
    // Execute via the script's shebang rather than an explicit `bash` to
    // avoid picking up any shim binary a parent nono session may have on PATH.
    let mut child = Command::new(script_path())
        .env_clear()
        .env("HOME", home)
        .env("PATH", "/bin:/usr/bin")
        .env("NONO_CAP_FILE", "/tmp/fake-nono-cap")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trajectory hook");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(payload_json.as_bytes())
        .expect("write payload");
    let out = child.wait_with_output().expect("wait on hook");
    assert!(
        out.status.success(),
        "hook exited with status {:?}; stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
}

fn read_lines(path: &PathBuf) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).expect("read trajectory file");
    text.lines()
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("parse jsonl line"))
        .collect()
}

#[test]
fn trajectory_hook_emits_conformant_stream() {
    if !jq_available() {
        eprintln!("skipping: jq not available");
        return;
    }

    let tmp = tempfile::tempdir().expect("tmpdir");
    let home: PathBuf = tmp.path().to_path_buf();
    let session_id = "int-test-1";
    let out = home
        .join(".nono")
        .join("trajectory")
        .join(format!("session-{session_id}.jsonl"));

    let events = [
        r#"{"hook_event_name":"SessionStart","session_id":"int-test-1","model":"claude-sonnet-4-6","cwd":"/tmp","source":"startup"}"#,
        r#"{"hook_event_name":"UserPromptSubmit","session_id":"int-test-1","prompt":"list the repo"}"#,
        r#"{"hook_event_name":"PreToolUse","session_id":"int-test-1","tool_name":"Bash","tool_input":{"command":"ls"},"tool_use_id":"tu_1"}"#,
        r#"{"hook_event_name":"PostToolUse","session_id":"int-test-1","tool_name":"Bash","tool_use_id":"tu_1","tool_response":{"exit_code":0}}"#,
        r#"{"hook_event_name":"UserPromptSubmit","session_id":"int-test-1","prompt":"now rm it"}"#,
        r#"{"hook_event_name":"PreToolUse","session_id":"int-test-1","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"tool_use_id":"tu_2"}"#,
        r#"{"hook_event_name":"PostToolUse","session_id":"int-test-1","tool_name":"Bash","tool_use_id":"tu_2","tool_response":{"exit_code":1,"is_error":true}}"#,
        r#"{"hook_event_name":"SessionEnd","session_id":"int-test-1","reason":"user_exit"}"#,
    ];
    for ev in events {
        feed(&home, ev);
    }

    let lines = read_lines(&out);
    assert_eq!(lines.len(), 8, "expected 8 events, got {}", lines.len());

    // S1 / I1: first event is session_start, has required fields, starts at seq 0.
    let first = &lines[0];
    assert_eq!(first["event_type"], "session_start");
    assert_eq!(first["sequence_number"], 0);
    assert_eq!(first["format_version"], 1);
    assert_eq!(first["session_id"], session_id);
    assert_eq!(first["capture_level"], "standard");
    assert!(
        first["model"]
            .as_str()
            .unwrap_or("")
            .starts_with("nono-sandbox/"),
        "model should be namespaced under nono-sandbox/: {:?}",
        first["model"]
    );

    // I9: sequence_number strictly increasing with no gaps.
    for (i, line) in lines.iter().enumerate() {
        assert_eq!(
            line["sequence_number"].as_u64().expect("sequence_number"),
            i as u64,
            "sequence gap at index {}",
            i
        );
    }

    // I6: timestamps non-decreasing, RFC 3339 UTC with millisecond precision.
    let mut prev_ts = String::new();
    for line in &lines {
        let ts = line["timestamp"].as_str().expect("timestamp str");
        assert!(ts.ends_with('Z'), "timestamp must be UTC (end Z): {ts}");
        assert!(
            ts.contains('.') && ts.len() >= 23,
            "timestamp must carry ms precision: {ts}",
        );
        assert!(ts.as_bytes() >= prev_ts.as_bytes(), "timestamps regressed");
        prev_ts = ts.to_string();
    }

    // Turn pairing: input_prompt and the following tool_use pair share turn_id.
    let prompts: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|l| l["event_type"] == "input_prompt")
        .collect();
    assert_eq!(prompts.len(), 2, "expected 2 prompts");
    assert_eq!(prompts[0]["turn_id"], 1);
    assert_eq!(prompts[1]["turn_id"], 2);

    let tool_uses: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|l| l["event_type"] == "tool_use")
        .collect();
    assert_eq!(tool_uses.len(), 4, "expected 2 pre+post tool_use pairs");
    assert_eq!(tool_uses[0]["phase"], "pre");
    assert_eq!(tool_uses[1]["phase"], "post");
    assert_eq!(tool_uses[0]["turn_id"], 1);
    assert_eq!(tool_uses[1]["turn_id"], 1);
    assert_eq!(tool_uses[2]["turn_id"], 2);
    assert_eq!(tool_uses[3]["turn_id"], 2);
    // tool_use_id matches across pre/post of the same invocation.
    assert_eq!(tool_uses[0]["tool_use_id"], tool_uses[1]["tool_use_id"]);
    assert_eq!(tool_uses[2]["tool_use_id"], tool_uses[3]["tool_use_id"]);
    // success flag derived correctly.
    assert_eq!(tool_uses[1]["success"], true);
    assert_eq!(tool_uses[3]["success"], false);

    // I11: no `output` key on any tool_use at standard capture level.
    for tu in &tool_uses {
        assert!(
            tu.get("output").is_none(),
            "standard capture must not emit `output`: {tu}",
        );
    }

    // Last event is session_end and has exit_reason.
    let last = lines.last().expect("non-empty");
    assert_eq!(last["event_type"], "session_end");
    assert_eq!(last["exit_reason"], "user_exit");
}

#[test]
fn trajectory_hook_noop_without_nono_env() {
    if !jq_available() {
        eprintln!("skipping: jq not available");
        return;
    }
    let tmp = tempfile::tempdir().expect("tmpdir");
    let home: PathBuf = tmp.path().to_path_buf();

    // Intentionally do NOT set NONO_CAP_FILE. The hook must exit 0 and
    // write nothing, so it is safe to leave registered in Claude Code
    // when the agent is not running under nono.
    let mut child = Command::new(script_path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/bin:/usr/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            br#"{"hook_event_name":"SessionStart","session_id":"noenv","model":"x","cwd":"/"}"#,
        )
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "hook should exit 0 when nono inactive"
    );

    let traj_root = home.join(".nono").join("trajectory");
    assert!(
        !traj_root.exists(),
        "hook must not create files when nono inactive"
    );
}

#[test]
fn trajectory_hook_rejects_path_traversal_in_session_id() {
    if !jq_available() {
        eprintln!("skipping: jq not available");
        return;
    }
    let tmp = tempfile::tempdir().expect("tmpdir");
    let home: PathBuf = tmp.path().to_path_buf();

    let mut child = Command::new(script_path())
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/bin:/usr/bin")
        .env("NONO_CAP_FILE", "/tmp/fake")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(
            br#"{"hook_event_name":"SessionStart","session_id":"../../etc/passwd","model":"x","cwd":"/"}"#,
        )
        .expect("write");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success());

    // Nothing should have been written.
    let traj_root = home.join(".nono").join("trajectory");
    if traj_root.exists() {
        let entries: Vec<_> = std::fs::read_dir(&traj_root)
            .expect("read traj root")
            .collect();
        assert!(
            entries.is_empty(),
            "traversal payload must not produce any file: {:?}",
            entries,
        );
    }
}
