import Foundation

/// Points the HTTP and HTTPS system proxy of every enabled network service at the local proxy and
/// puts the previous settings back. The previous settings stay in UserDefaults until restored, so a
/// crash while routed is repaired on the next launch.
enum SystemProxy {
    struct Setting: Codable, Equatable, Sendable {
        var enabled: Bool
        var server: String
        var port: Int
    }

    struct ServiceState: Codable, Equatable, Sendable {
        var service: String
        var web: Setting
        var secureWeb: Setting
        var autoConfig: Bool
    }

    enum Failure: LocalizedError {
        case cancelled
        case conflict(String)
        case failed(String)

        var errorDescription: String? {
            switch self {
            case .cancelled: "Cancelled."
            case .conflict(let message), .failed(let message): message
            }
        }
    }

    private static let savedKey = "systemProxySavedSettings"
    private static let tool = "/usr/sbin/networksetup"

    static var hasSavedSettings: Bool { loadSaved() != nil }

    static func route(toPort port: Int) async throws {
        let current = try await Task.detached { try readAll() }.value
        // Saved settings left by a crash are the user's originals; the current ones may be ours.
        let savedNow = loadSaved() == nil
        if savedNow {
            for state in current { try checkCompatible(state, port: port) }
            save(current)
        }
        do {
            try await AdminShell.run(routeScript(services: current.map(\.service), port: port),
                                     prompt: "WareHound wants to route this Mac's web traffic through its local proxy.")
        } catch AdminShell.Failure.cancelled {
            if savedNow { clearSaved() }
            throw Failure.cancelled
        } catch AdminShell.Failure.failed(let message) {
            throw Failure.failed("Could not set the system proxy: \(message)")   // some services may have changed
        }
    }

    static func restore() async throws {
        guard let saved = loadSaved() else { return }
        do {
            try await AdminShell.run(restoreScript(saved),
                                     prompt: "WareHound wants to restore this Mac's proxy settings.")
        } catch AdminShell.Failure.cancelled {
            throw Failure.cancelled
        } catch AdminShell.Failure.failed(let message) {
            throw Failure.failed("Could not restore the system proxy: \(message)")
        }
        clearSaved()
    }

    // MARK: - Reading

    private static func readAll() throws -> [ServiceState] {
        try parseServices(run(["-listallnetworkservices"])).map { service in
            ServiceState(service: service,
                         web: parseSetting(try run(["-getwebproxy", service])),
                         secureWeb: parseSetting(try run(["-getsecurewebproxy", service])),
                         autoConfig: parseFields(try run(["-getautoproxyurl", service]))["Enabled"] == "Yes")
        }
    }

    static func parseServices(_ output: String) -> [String] {
        output.split(separator: "\n").map(String.init).filter {
            !$0.isEmpty && !$0.hasPrefix("*") && !$0.hasPrefix("An asterisk")
        }
    }

    static func parseSetting(_ output: String) -> Setting {
        let fields = parseFields(output)
        return Setting(enabled: fields["Enabled"] == "Yes",
                       server: fields["Server"] ?? "",
                       port: Int(fields["Port"] ?? "") ?? 0)
    }

    private static func parseFields(_ output: String) -> [String: String] {
        var fields: [String: String] = [:]
        for line in output.split(separator: "\n") {
            guard let colon = line.firstIndex(of: ":") else { continue }
            fields[String(line[..<colon])] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        return fields
    }

    // Routing through WareHound connects directly, so it would silently bypass an existing proxy.
    static func checkCompatible(_ state: ServiceState, port: Int) throws {
        if state.autoConfig {
            throw Failure.conflict("\(state.service) uses a proxy auto-configuration file; WareHound won't override it.")
        }
        for setting in [state.web, state.secureWeb] where setting.enabled {
            if setting.server == "127.0.0.1" && setting.port == port { continue }
            throw Failure.conflict("\(state.service) already uses the proxy \(setting.server):\(setting.port); routing through WareHound would bypass it.")
        }
    }

    private static func run(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = Pipe()
        try process.run()
        let data = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else {
            throw Failure.failed("networksetup \(arguments.joined(separator: " ")) failed")
        }
        return String(decoding: data, as: UTF8.self)
    }

    // MARK: - Scripts (run as root)

    static func routeScript(services: [String], port: Int) -> String {
        script(services.flatMap { service in
            ["\(tool) -setwebproxy \(shellQuoted(service)) 127.0.0.1 \(port) off",
             "\(tool) -setsecurewebproxy \(shellQuoted(service)) 127.0.0.1 \(port) off"]
        })
    }

    static func restoreScript(_ saved: [ServiceState]) -> String {
        script(saved.flatMap { state in
            restoreLines(state.service, state.web, set: "-setwebproxy", toggle: "-setwebproxystate")
                + restoreLines(state.service, state.secureWeb, set: "-setsecurewebproxy", toggle: "-setsecurewebproxystate")
        })
    }

    private static func restoreLines(_ service: String, _ setting: Setting, set: String, toggle: String) -> [String] {
        var lines: [String] = []
        if !setting.server.isEmpty && setting.port > 0 {
            lines.append("\(tool) \(set) \(shellQuoted(service)) \(shellQuoted(setting.server)) \(setting.port) off")
        }
        if !setting.enabled { lines.append("\(tool) \(toggle) \(shellQuoted(service)) off") }
        return lines
    }

    // Keeps going after a failed command (e.g. a service removed since) but reports the failure.
    private static func script(_ commands: [String]) -> String {
        (["rc=0"] + commands.map { "\($0) || rc=1" } + ["exit $rc"]).joined(separator: "\n")
    }

    private static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    // MARK: - Saved settings

    private static func loadSaved() -> [ServiceState]? {
        guard let data = UserDefaults.standard.data(forKey: savedKey) else { return nil }
        return try? JSONDecoder().decode([ServiceState].self, from: data)
    }

    private static func save(_ states: [ServiceState]) {
        UserDefaults.standard.set(try? JSONEncoder().encode(states), forKey: savedKey)
    }

    private static func clearSaved() {
        UserDefaults.standard.removeObject(forKey: savedKey)
    }
}
