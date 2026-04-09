import SwiftUI
import LocalAuthentication

/// Handles biometric/password authentication before enabling admin mode.
struct AdminAuthView: View {
    let session: SessionInfo
    let onComplete: (Bool) -> Void

    @State private var isAuthenticating = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "lock.open.fill")
                .font(.system(size: 32))
                .foregroundColor(.orange)

            Text("Enable Admin Mode")
                .font(.headline)

            Text("Session \(session.pid)")
                .font(.caption)
                .foregroundColor(.secondary)

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
                    .multilineTextAlignment(.center)
            }

            HStack {
                Button("Cancel") {
                    onComplete(false)
                }

                Button(action: authenticate) {
                    if isAuthenticating {
                        ProgressView()
                            .scaleEffect(0.8)
                    } else {
                        Label("Authenticate", systemImage: "touchid")
                    }
                }
                .buttonStyle(.borderedProminent)
                .disabled(isAuthenticating)
            }
        }
        .padding()
        .frame(width: 280)
    }

    private func authenticate() {
        isAuthenticating = true
        errorMessage = nil

        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            isAuthenticating = false
            errorMessage = error?.localizedDescription ?? "Authentication not available"
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthentication,
            localizedReason: "Enable nono admin mode for session \(session.pid)"
        ) { success, authError in
            DispatchQueue.main.async {
                isAuthenticating = false
                if success {
                    onComplete(true)
                } else {
                    errorMessage = authError?.localizedDescription ?? "Authentication failed"
                }
            }
        }
    }
}
