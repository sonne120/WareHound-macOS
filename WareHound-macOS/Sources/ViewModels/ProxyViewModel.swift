import AppKit
import Foundation
import Observation

@MainActor
@Observable
final class ProxyViewModel {
    private(set) var transactions: [HttpTransaction] = []
    private(set) var isRunning = false
    private(set) var status = "Stopped"
    private(set) var clientApps: [String: AppIdentity] = [:]
    /// The system HTTP/HTTPS proxy points at this proxy (set during this session).
    private(set) var routesSystemProxy = false
    private(set) var isChangingSystemProxy = false
    /// Saved system proxy settings were not put back (a crash, or a cancelled password prompt).
    private(set) var systemProxyNeedsRestore = SystemProxy.hasSavedSettings
    var listenPort: Int {
        didSet { UserDefaults.standard.set(listenPort, forKey: "proxyListenPort") }
    }
    var filterText = ""

    private let service = LocalProxyService()
    private var transactionIndex: [UInt64: Int] = [:]
    private var httpVersion: UInt64 = 0
    private var pollTask: Task<Void, Never>?
    private static let transactionLimit = 5_000
    private static let pollInterval: Duration = .milliseconds(250)

    init() {
        let storedPort = UserDefaults.standard.integer(forKey: "proxyListenPort")
        listenPort = (1...65_535).contains(storedPort) ? storedPort : 9_090

        service.onStateChange = { [weak self] state in
            Task { @MainActor in self?.apply(state) }
        }
        service.onClientApp = { [weak self] client, app in
            Task { @MainActor in self?.clientApps[client] = app }
        }
    }

    var filteredTransactions: [HttpTransaction] {
        let needle = filterText.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return transactions }
        return transactions.filter {
            $0.host.lowercased().contains(needle)
                || $0.server.lowercased().contains(needle)
                || $0.method.lowercased().contains(needle)
                || $0.target.lowercased().contains(needle)
                || Self.statusText($0).lowercased().contains(needle)
                || (app(for: $0)?.name.lowercased().contains(needle) ?? false)
        }
    }

    var proxyURL: String { "http://127.0.0.1:\(listenPort)" }

    var shellConfiguration: String {
        """
        export HTTP_PROXY=\(proxyURL)
        export HTTPS_PROXY=\(proxyURL)
        export NO_PROXY=localhost,127.0.0.1,::1
        """
    }

    func app(for transaction: HttpTransaction) -> AppIdentity? {
        clientApps[transaction.client]
    }

    static func statusText(_ transaction: HttpTransaction) -> String {
        if transaction.status > 0 { return "\(transaction.status)" }
        return transaction.error.isEmpty ? "Active" : "Error"
    }

    func toggle() {
        isRunning ? stop() : start()
    }

    func start() {
        guard LicenseManager.shared.requireLicense() else { return }
        guard (1...65_535).contains(listenPort) else {
            status = "Choose a port between 1 and 65535."
            return
        }
        do {
            try service.start(port: UInt16(listenPort))
        } catch {
            isRunning = false
            status = "Proxy failed: \(error.localizedDescription)"
            LoggerService.shared.logError("Proxy start failed", exception: error.localizedDescription)
        }
    }

    func stop() {
        service.stop()
        restoreSystemProxy()
    }

    func setSystemRouting(_ enabled: Bool) {
        guard !isChangingSystemProxy else { return }
        guard enabled else {
            restoreSystemProxy()
            return
        }
        guard isRunning else { return }
        isChangingSystemProxy = true
        let port = listenPort
        Task {
            defer { isChangingSystemProxy = false }
            do {
                try await SystemProxy.route(toPort: port)
                routesSystemProxy = true
                systemProxyNeedsRestore = false
                status = "Routing this Mac's web traffic through 127.0.0.1:\(port)"
                LoggerService.shared.log("System HTTP/HTTPS proxy set to 127.0.0.1:\(port)")
            } catch SystemProxy.Failure.cancelled {
            } catch {
                status = error.localizedDescription
                systemProxyNeedsRestore = SystemProxy.hasSavedSettings
                LoggerService.shared.logError("System proxy routing failed", exception: error.localizedDescription)
            }
        }
    }

    /// Puts back the system proxy settings saved when routing started; no-op if none are saved.
    func restoreSystemProxy() {
        guard SystemProxy.hasSavedSettings else {
            routesSystemProxy = false
            systemProxyNeedsRestore = false
            return
        }
        guard !isChangingSystemProxy else { return }
        isChangingSystemProxy = true
        Task {
            defer { isChangingSystemProxy = false }
            do {
                try await SystemProxy.restore()
                routesSystemProxy = false
                systemProxyNeedsRestore = false
                LoggerService.shared.log("System proxy settings restored")
            } catch {
                routesSystemProxy = false
                systemProxyNeedsRestore = true
                if case SystemProxy.Failure.cancelled = error { return }
                status = error.localizedDescription
                LoggerService.shared.logError("System proxy restore failed", exception: error.localizedDescription)
            }
        }
    }

    func clear() {
        NativeHttp.clear(source: .proxy)
        transactions.removeAll(keepingCapacity: true)
        transactionIndex.removeAll(keepingCapacity: true)
        clientApps.removeAll()
    }

    func copyShellConfiguration() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(shellConfiguration, forType: .string)
        status = "Copied proxy environment variables"
    }

    private func apply(_ state: LocalProxyService.State) {
        switch state {
        case .stopped:
            isRunning = false
            status = "Stopped"
            stopPolling()
        case .starting(let port):
            isRunning = false
            status = "Starting on 127.0.0.1:\(port)…"
        case .running(let port):
            isRunning = true
            listenPort = Int(port)
            status = "Listening on 127.0.0.1:\(port)"
            startPolling()
            LoggerService.shared.log("Explicit proxy listening on 127.0.0.1:\(port)")
        case .failed(let message):
            isRunning = false
            status = message
            stopPolling()
            if routesSystemProxy { restoreSystemProxy() }
            LoggerService.shared.logError("Proxy failed", exception: message)
        }
    }

    private func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                self?.pullChanges()
                try? await Task.sleep(for: Self.pollInterval)
            }
        }
    }

    private func stopPolling() {
        pollTask?.cancel()
        pollTask = nil
        pullChanges()   // sessions are closed before .stopped is reported
    }

    private func pullChanges() {
        let changed = NativeHttp.changes(since: &httpVersion).filter { $0.source == .proxy }
        guard !changed.isEmpty else { return }
        for row in changed {
            if let index = transactionIndex[row.id] {
                transactions[index] = row
            } else {
                transactionIndex[row.id] = transactions.count
                transactions.append(row)
            }
        }

        if transactions.count > Self.transactionLimit {
            transactions.removeFirst(transactions.count - Self.transactionLimit)
            transactionIndex = Dictionary(uniqueKeysWithValues: transactions.enumerated().map { ($1.id, $0) })
        }
    }
}
