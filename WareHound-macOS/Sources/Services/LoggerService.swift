import Foundation
import Observation
import AppKit


enum AppLogLevel: Int, CaseIterable, Sendable {
    case debug, info, warning, error

    var display: String {
        switch self {
        case .debug: "DEBUG"
        case .info: "INFO"
        case .warning: "WARN"
        case .error: "ERROR"
        }
    }
}

struct LogEntry: Identifiable, Sendable {
    let id = UUID()
    let timestamp: Date
    let level: AppLogLevel
    let message: String
    let exception: String?

    var timestampDisplay: String { Self.formatter.string(from: timestamp) }
    var levelDisplay: String { level.display }

    private static let formatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()
}


@MainActor
@Observable
final class LoggerService {
    static let shared = LoggerService()

    private(set) var entries: [LogEntry] = []
    private static let maxEntries = 5_000

    func log(_ message: String, level: AppLogLevel = .info, exception: String? = nil) {
        entries.append(LogEntry(timestamp: .now, level: level, message: message, exception: exception))
        if entries.count > Self.maxEntries {
            entries.removeFirst(entries.count - Self.maxEntries)
        }
    }

    func logDebug(_ m: String) { log(m, level: .debug) }
    func logWarning(_ m: String) { log(m, level: .warning) }
    func logError(_ m: String, exception: String? = nil) { log(m, level: .error, exception: exception) }
    func clear() { entries.removeAll() }
}


@MainActor
@Observable
final class LogViewModel {
    private let logger = LoggerService.shared

    var filterText = ""
    var selectedLevelIndex = 0
    var selectedEntry: LogEntry?

    let logLevels = ["All", "Debug", "Info", "Warning", "Error"]

    var entries: [LogEntry] {
        var result = logger.entries
        if selectedLevelIndex > 0, let level = AppLogLevel(rawValue: selectedLevelIndex - 1) {
            result = result.filter { $0.level == level }
        }
        if !filterText.isEmpty {
            let f = filterText.lowercased()
            result = result.filter { $0.message.lowercased().contains(f) }
        }
        return result
    }

    var logCount: Int { logger.entries.count }
    var errorCount: Int { logger.entries.count { $0.level == .error } }
    var warningCount: Int { logger.entries.count { $0.level == .warning } }

    init() { logger.log("Log viewer opened") }

    func clearLogs() { logger.clear() }

    func copySelected() {
        guard let e = selectedEntry else { return }
        var text = "[\(e.timestampDisplay)] [\(e.levelDisplay)] \(e.message)"
        if let ex = e.exception, !ex.isEmpty { text += "\n\(ex)" }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    func exportLogs() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.plainText]
        panel.nameFieldStringValue = "WareHound_Logs_\(Self.fileStamp.string(from: .now))"

        guard panel.runModal() == .OK, let url = panel.url else { return }

        let lines = logger.entries.map { e in
            "[\(e.timestampDisplay)] [\(e.levelDisplay)] \(e.message)"
            + (e.exception.map { "\n  \($0)" } ?? "")
        }
        try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        logger.log("Logs exported to \(url.path)")
    }

    private static let fileStamp: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd_HHmmss"
        return f
    }()
}
