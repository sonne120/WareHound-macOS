import Foundation

enum AdminShell {
    enum Failure: LocalizedError {
        case cancelled
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: "Cancelled."
            case .failed(let message): message
            }
        }
    }

    // Runs via osascript so macOS shows its own admin-password dialog.
    static func run(_ script: String, prompt: String? = nil) async throws {
        let appleScript = "do shell script \(quoted(script))"
            + (prompt.map { " with prompt \(quoted($0))" } ?? "")
            + " with administrator privileges"

        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            process.arguments = ["-e", appleScript]
            let stderr = Pipe()
            process.standardError = stderr
            process.standardOutput = Pipe()
            process.terminationHandler = { proc in
                if proc.terminationStatus == 0 {
                    continuation.resume()
                    return
                }
                let message = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)?
                    .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
                // osascript reports error -128 when the user cancels the password dialog.
                continuation.resume(throwing: message.contains("-128") ? Failure.cancelled : Failure.failed(message))
            }
            do {
                try process.run()
            } catch {
                continuation.resume(throwing: Failure.failed(error.localizedDescription))
            }
        }
    }

    private static func quoted(_ text: String) -> String {
        "\"" + text.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
}
