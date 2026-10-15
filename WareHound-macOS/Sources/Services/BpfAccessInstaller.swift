import Foundation

enum BpfAccessInstaller {
    static let daemonLabel = "com.warehound.chmodbpf"
    static let daemonPath = "/Library/LaunchDaemons/\(daemonLabel).plist"

    enum Failure: LocalizedError {
        case cancelled
        case invalidUser
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: "Cancelled."
            case .invalidUser: "Unsupported user name."
            case .failed(let message): message
            }
        }
    }

    static func install() async throws {
        try await runAsAdmin(installScript(user: try currentUser()))
    }

    static func uninstall() async throws {
        try await runAsAdmin(uninstallScript(user: try currentUser()))
    }

    static var isDaemonInstalled: Bool {
        FileManager.default.fileExists(atPath: daemonPath)
    }

    // The name is interpolated into a root shell script, so allow only safe characters.
    private static func currentUser() throws -> String {
        let user = NSUserName()
        guard !user.isEmpty, user.allSatisfy({ $0.isLetter || $0.isNumber || "._-".contains($0) }) else {
            throw Failure.invalidUser
        }
        return user
    }

    private static func installScript(user: String) -> String {
        """
        set -e
        dseditgroup -o read access_bpf >/dev/null 2>&1 || dseditgroup -o create access_bpf
        dseditgroup -o edit -a '\(user)' -t user access_bpf
        chgrp access_bpf /dev/bpf*
        chmod g+rw /dev/bpf*
        cat > '\(daemonPath)' <<'PLIST'
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(daemonLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>/bin/sh</string>
                <string>-c</string>
                <string>/usr/bin/chgrp access_bpf /dev/bpf* &amp;&amp; /bin/chmod g+rw /dev/bpf*</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
        </dict>
        </plist>
        PLIST
        chown root:wheel '\(daemonPath)'
        chmod 644 '\(daemonPath)'
        launchctl bootout system '\(daemonPath)' >/dev/null 2>&1 || true
        launchctl bootstrap system '\(daemonPath)'
        """
    }

    private static func uninstallScript(user: String) -> String {
        """
        launchctl bootout system '\(daemonPath)' >/dev/null 2>&1 || true
        rm -f '\(daemonPath)'
        chmod g-rw /dev/bpf*
        chgrp wheel /dev/bpf*
        dseditgroup -o edit -d '\(user)' -t user access_bpf >/dev/null 2>&1 || true
        """
    }

    // Runs via osascript so macOS shows its own admin-password dialog.
    private static func runAsAdmin(_ script: String) async throws {
        let escaped = script
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let appleScript = "do shell script \"\(escaped)\" with administrator privileges"

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
}
