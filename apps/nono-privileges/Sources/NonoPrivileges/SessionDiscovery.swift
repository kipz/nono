import Foundation

/// Parsed content of a session.json file.
struct SessionInfo: Identifiable {
    let id: UInt32
    var pid: UInt32 { id }
    let controlSocket: String
    let controlToken: String
    let startedAt: String
    let sessionDir: String
}

/// Scans $TMPDIR/nono-admin-*/session.json and returns active sessions.
///
/// session.json is written to the admin dir (not the session dir) so that the
/// control_token is never accessible to the sandboxed child process.
func discoverSessions() -> [SessionInfo] {
    let tmpDir = FileManager.default.temporaryDirectory
    let fm = FileManager.default

    guard let entries = try? fm.contentsOfDirectory(
        at: tmpDir,
        includingPropertiesForKeys: nil
    ) else {
        return []
    }

    return entries.compactMap { entry -> SessionInfo? in
        guard entry.lastPathComponent.hasPrefix("nono-admin-") else { return nil }
        let jsonURL = entry.appendingPathComponent("session.json")
        guard let data = try? Data(contentsOf: jsonURL),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let pid = obj["pid"] as? Int,
              let controlSocket = obj["control_socket"] as? String,
              let controlToken = obj["control_token"] as? String
        else { return nil }

        // Skip sessions whose parent process is no longer alive
        guard kill(pid_t(pid), 0) == 0 else { return nil }

        let startedAt = obj["started_at"] as? String ?? ""
        return SessionInfo(
            id: UInt32(pid),
            controlSocket: controlSocket,
            controlToken: controlToken,
            startedAt: startedAt,
            sessionDir: entry.path
        )
    }.sorted { $0.pid < $1.pid }
}
