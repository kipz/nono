import SwiftUI
import LocalAuthentication

/// A button style that shows a rounded highlight on hover, working inside NSPopover.
struct MenuButtonStyle: ButtonStyle {
    var tint: Color = .primary
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(tint)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                RoundedRectangle(cornerRadius: 5)
                    .fill(hovering || configuration.isPressed
                          ? tint.opacity(0.15)
                          : Color.clear)
            )
            .onHover { hovering = $0 }
            .animation(.easeInOut(duration: 0.1), value: hovering)
    }
}

/// Minimal row-level hover highlight (for Quit and refresh).
struct RowButtonStyle: ButtonStyle {
    @State private var hovering = false

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundColor(hovering || configuration.isPressed ? .primary : .secondary)
            .onHover { hovering = $0 }
            .animation(.easeInOut(duration: 0.1), value: hovering)
    }
}

/// Observed store for session state, polled on a timer.
class SessionStore: ObservableObject {
    @Published var sessions: [SessionInfo] = []
    @Published var sessionStatuses: [UInt32: AdminStatus] = [:]

    func refresh() {
        DispatchQueue.global(qos: .utility).async {
            let discovered = discoverSessions()
            var statuses: [UInt32: AdminStatus] = [:]
            for session in discovered {
                let client = ControlClient(session: session)
                if let status = try? client.status() {
                    statuses[session.pid] = status
                }
            }
            DispatchQueue.main.async {
                self.sessions = discovered
                self.sessionStatuses = statuses
            }
        }
    }

    func hasAnyAdminActive() -> Bool {
        sessionStatuses.values.contains { $0.isActive }
    }
}

struct MenuBarView: View {
    @ObservedObject var store: SessionStore
    @State private var errorMessage: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Image(systemName: "key.horizontal.fill")
                    .foregroundColor(.primary)
                Text("nono-privileges")
                    .font(.headline)
                Spacer()
                Button(action: { store.refresh() }) {
                    Image(systemName: "arrow.clockwise")
                        .font(.caption)
                }
                .buttonStyle(RowButtonStyle())
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)

            Divider()

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 4)
                Divider()
            }

            if store.sessions.isEmpty {
                Text("No active sessions")
                    .foregroundColor(.secondary)
                    .font(.caption)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
            } else {
                ForEach(store.sessions) { session in
                    sessionRow(session)
                    Divider()
                }
            }

            Button("Quit") {
                NSApplication.shared.terminate(nil)
            }
            .buttonStyle(RowButtonStyle())
            .font(.caption)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .frame(width: 260)
    }

    @ViewBuilder
    private func sessionRow(_ session: SessionInfo) -> some View {
        let status = store.sessionStatuses[session.pid]
        let isActive = status?.isActive ?? false

        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Circle()
                    .fill(isActive ? Color.orange : Color.green)
                    .frame(width: 8, height: 8)
                Text("Session \(String(session.pid))")
                    .font(.subheadline)
                    .fontWeight(.medium)
                Spacer()
            }

            if isActive, let secs = status?.secondsRemaining {
                Text("Active: \(secs / 60)m \(secs % 60)s remaining")
                    .font(.caption)
                    .foregroundColor(.orange)
            } else {
                Text("Inactive")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            if isActive {
                Button("Disable YOLO Mode") {
                    errorMessage = nil
                    disableYoloMode(for: session)
                }
                .buttonStyle(MenuButtonStyle(tint: .red))
            } else {
                Button("Enable YOLO Mode") {
                    errorMessage = nil
                    authenticateAndEnable(for: session)
                }
                .buttonStyle(MenuButtonStyle(tint: .orange))
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }

    private func authenticateAndEnable(for session: SessionInfo) {
        let context = LAContext()
        var authError: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &authError) else {
            errorMessage = authError?.localizedDescription ?? "Authentication unavailable"
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Enable YOLO mode for session \(session.pid)"
        ) { success, err in
            if success {
                DispatchQueue.global(qos: .userInitiated).async {
                    let client = ControlClient(session: session)
                    do {
                        let status = try client.enable(durationSecs: 600, grantedBy: "TouchID")
                        DispatchQueue.main.async {
                            store.sessionStatuses[session.pid] = status
                        }
                    } catch {
                        DispatchQueue.main.async {
                            errorMessage = "Enable failed: \(error)"
                            store.refresh()
                        }
                    }
                }
            } else if let err {
                DispatchQueue.main.async {
                    // userCancel (-3) is silent; anything else show the message
                    let lac = err as? LAError
                    if lac?.code != .userCancel {
                        errorMessage = err.localizedDescription
                    }
                }
            }
        }
    }

    private func disableYoloMode(for session: SessionInfo) {
        DispatchQueue.global(qos: .userInitiated).async {
            let client = ControlClient(session: session)
            do {
                let status = try client.disable(grantedBy: "App")
                DispatchQueue.main.async {
                    store.sessionStatuses[session.pid] = status
                }
            } catch {
                DispatchQueue.main.async { store.refresh() }
            }
        }
    }
}
