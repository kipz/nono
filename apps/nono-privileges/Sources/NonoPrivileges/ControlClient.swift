import Foundation

/// Admin mode status returned from the control socket.
struct AdminStatus {
    let isActive: Bool
    let expiresAtUnix: UInt64?
    let grantedBy: String?

    var secondsRemaining: Int? {
        guard let exp = expiresAtUnix else { return nil }
        let now = UInt64(Date().timeIntervalSince1970)
        if exp > now { return Int(exp - now) }
        return 0
    }
}

enum ControlError: Error {
    case connectionFailed(String)
    case writeFailed(String)
    case readFailed(String)
    case parseFailed(String)
    case serverError(String)
}

/// Synchronous AF_UNIX socket client using the same length-prefixed JSON protocol.
class ControlClient {
    let session: SessionInfo

    init(session: SessionInfo) {
        self.session = session
    }

    func status() throws -> AdminStatus {
        let resp = try sendRequest([
            "token": session.controlToken,
            "action": "status"
        ])
        return parseAdminStatus(from: resp)
    }

    func enable(durationSecs: UInt64 = 600, grantedBy: String) throws -> AdminStatus {
        let resp = try sendRequest([
            "token": session.controlToken,
            "action": "enable",
            "duration_secs": durationSecs,
            "granted_by": grantedBy
        ])
        return parseAdminStatus(from: resp)
    }

    func disable(grantedBy: String = "App") throws -> AdminStatus {
        let resp = try sendRequest([
            "token": session.controlToken,
            "action": "disable",
            "granted_by": grantedBy
        ])
        return parseAdminStatus(from: resp)
    }

    private func parseAdminStatus(from resp: [String: Any]) -> AdminStatus {
        let statusStr = resp["status"] as? String ?? "disabled"
        let isActive = statusStr == "active"
        let expiresAtUnix = resp["expires_at_unix"] as? UInt64
        let grantedBy = resp["granted_by"] as? String
        return AdminStatus(isActive: isActive, expiresAtUnix: expiresAtUnix, grantedBy: grantedBy)
    }

    private func sendRequest(_ request: [String: Any]) throws -> [String: Any] {
        guard let data = try? JSONSerialization.data(withJSONObject: request) else {
            throw ControlError.writeFailed("Failed to serialize request")
        }

        // Connect via AF_UNIX socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw ControlError.connectionFailed("socket() failed: \(errno)")
        }
        defer { close(fd) }

        // Set timeout
        var tv = timeval(tv_sec: 10, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        // Connect
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let socketPath = session.controlSocket
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            socketPath.withCString { cstr in
                ptr.withMemoryRebound(to: CChar.self, capacity: 108) { dest in
                    strncpy(dest, cstr, 107)
                }
            }
        }
        let connectResult = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { saddrPtr in
                connect(fd, saddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connectResult == 0 else {
            throw ControlError.connectionFailed("connect() failed: \(errno)")
        }

        // Write length-prefixed payload
        var len = UInt32(data.count).bigEndian
        let lenData = Data(bytes: &len, count: 4)
        try writeAll(fd: fd, data: lenData)
        try writeAll(fd: fd, data: data)

        // Read length-prefixed response
        var respLenBuf = [UInt8](repeating: 0, count: 4)
        try readAll(fd: fd, buffer: &respLenBuf)
        let respLen = Int(UInt32(bigEndian: respLenBuf.withUnsafeBytes { $0.load(as: UInt32.self) }))

        var respBuf = [UInt8](repeating: 0, count: respLen)
        try readAll(fd: fd, buffer: &respBuf)

        guard let obj = try? JSONSerialization.jsonObject(with: Data(respBuf)) as? [String: Any] else {
            throw ControlError.parseFailed("Failed to parse response")
        }

        if let ok = obj["ok"] as? Bool, !ok, let err = obj["error"] as? String {
            throw ControlError.serverError(err)
        }

        return obj
    }

    private func writeAll(fd: Int32, data: Data) throws {
        var remaining = data
        while !remaining.isEmpty {
            let written = remaining.withUnsafeBytes { ptr in
                send(fd, ptr.baseAddress, ptr.count, 0)
            }
            guard written > 0 else {
                throw ControlError.writeFailed("send() failed: \(errno)")
            }
            remaining = remaining.dropFirst(written)
        }
    }

    private func readAll(fd: Int32, buffer: inout [UInt8]) throws {
        var offset = 0
        while offset < buffer.count {
            let n = buffer.withUnsafeMutableBytes { ptr in
                recv(fd, ptr.baseAddress!.advanced(by: offset), ptr.count - offset, 0)
            }
            guard n > 0 else {
                throw ControlError.readFailed("recv() failed: \(errno)")
            }
            offset += n
        }
    }
}
