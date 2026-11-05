import Foundation
import Network

/// All mutable state is confined to `queue`.
final class LocalProxyService: @unchecked Sendable {
    enum State: Sendable {
        case stopped
        case starting(UInt16)
        case running(UInt16)
        case failed(String)
    }

    // Set both before calling start().
    var onStateChange: (@Sendable (State) -> Void)?
    /// The app behind a proxy client endpoint ("127.0.0.1:port"), once resolved.
    var onClientApp: (@Sendable (String, AppIdentity) -> Void)?

    private let queue = DispatchQueue(label: "com.sonne120.WareHound.local-proxy", qos: .userInitiated)
    private var listener: NWListener?
    private var retiringListener: NWListener?   // cancelled but still holding its port
    private var pendingPort: UInt16?
    private var sessions: [UUID: ProxySession] = [:]
    private var configuredPort: UInt16 = 0

    func start(port: UInt16) throws {
        guard port > 0 else { throw ProxyError.invalidPort }
        try queue.sync { try startOnQueue(port: port) }
    }

    func stop() {
        queue.async { [weak self] in self?.stopOnQueue() }
    }

    private func startOnQueue(port: UInt16) throws {
        stopOnQueue()
        onStateChange?(.starting(port))
        // A cancelled listener releases its port asynchronously; bind once it has.
        if retiringListener != nil {
            pendingPort = port
        } else {
            try bind(port: port)
        }
    }

    private func bind(port: UInt16) throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
        let listener = try NWListener(using: parameters)
        configuredPort = port
        self.listener = listener

        listener.stateUpdateHandler = { [weak self, weak listener] state in
            guard let self, let listener else { return }
            if case .cancelled = state, self.retiringListener === listener {
                self.retiringListener = nil
                self.bindPending()
                return
            }
            guard self.listener === listener else { return }
            switch state {
            case .ready:
                self.onStateChange?(.running(listener.port?.rawValue ?? port))
            case .failed(let error):
                self.retire(listener)
                self.onStateChange?(.failed("Could not listen on 127.0.0.1:\(port): \(error.localizedDescription)"))
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] connection in
            self?.accept(connection)
        }
        listener.start(queue: queue)
    }

    private func bindPending() {
        guard let port = pendingPort else { return }
        pendingPort = nil
        do {
            try bind(port: port)
        } catch {
            onStateChange?(.failed("Could not listen on 127.0.0.1:\(port): \(error.localizedDescription)"))
        }
    }

    private func retire(_ listener: NWListener) {
        if self.listener === listener { self.listener = nil }
        retiringListener = listener
        listener.cancel()
    }

    private func stopOnQueue() {
        pendingPort = nil
        if let listener { retire(listener) }

        let activeSessions = Array(sessions.values)
        sessions.removeAll(keepingCapacity: true)
        for session in activeSessions { session.stop() }
        onStateChange?(.stopped)
    }

    private func accept(_ connection: NWConnection) {
        let sessionID = UUID()
        let session = ProxySession(
            id: sessionID,
            proxyPort: configuredPort,
            client: connection,
            queue: queue,
            onClientApp: { [weak self] label, app in
                self?.onClientApp?(label, app)
            },
            onClose: { [weak self] id in
                self?.sessions[id] = nil
            }
        )
        sessions[sessionID] = session
        session.start()
    }

    private enum ProxyError: LocalizedError {
        case invalidPort

        var errorDescription: String? {
            switch self {
            case .invalidPort: "The proxy port must be between 1 and 65535."
            }
        }
    }
}

private final class ProxySession: @unchecked Sendable {
    private struct RequestRoute {
        let host: String
        let port: UInt16
        let isTunnel: Bool
        let forwardedHeader: Data   // HTTP: the head sent upstream; CONNECT: the head as recorded
        let initialBody: Data
    }

    private static let headerLimit = 64 * 1024
    private static let ioChunkSize = 64 * 1024
    private static let headerMarker = Data("\r\n\r\n".utf8)
    private static let connectTimeout = 15
    private static let appLookupAttempts = 6

    let id: UUID
    private let proxyPort: UInt16
    private let client: NWConnection
    private let queue: DispatchQueue
    private let onClientApp: @Sendable (String, AppIdentity) -> Void
    private let onClose: @Sendable (UUID) -> Void

    private var remote: NWConnection?
    private var initialBuffer = Data()
    private var stream: UInt64 = 0
    private var isClosed = false
    private var tunnelEstablished = false
    private var clientLabel = ""
    private var clientPort: Int32 = 0
    private var appResolved = false

    init(id: UUID,
         proxyPort: UInt16,
         client: NWConnection,
         queue: DispatchQueue,
         onClientApp: @escaping @Sendable (String, AppIdentity) -> Void,
         onClose: @escaping @Sendable (UUID) -> Void) {
        self.id = id
        self.proxyPort = proxyPort
        self.client = client
        self.queue = queue
        self.onClientApp = onClientApp
        self.onClose = onClose
    }

    func start() {
        if case .hostPort(let host, let port) = client.endpoint {
            clientLabel = Self.label(host: host, port: port.rawValue)
            clientPort = Int32(port.rawValue)
        }
        resolveClientApp(attempt: 0)
        client.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.readInitialRequest()
            case .failed(let error):
                self.finish(error: "Client connection failed: \(error.localizedDescription)")
            default:
                break
            }
        }
        client.start(queue: queue)
    }

    func stop() {
        finish(error: "Proxy stopped")
    }

    private func resolveClientApp(attempt: Int) {
        guard !appResolved, clientPort > 0 else { return }
        // Destination port 0 keeps the lookup on the client's port; the proxy's own socket shares the pair.
        if let app = NativeProcess.lookupTCP(sourceIp: "127.0.0.1", sourcePort: clientPort, destIp: "127.0.0.1", destPort: 0) {
            appResolved = true
            onClientApp(clientLabel, app)
            return
        }
        guard attempt + 1 < Self.appLookupAttempts else { return }
        queue.asyncAfter(deadline: .now() + .milliseconds(50 << attempt)) {
            self.resolveClientApp(attempt: attempt + 1)
        }
    }

    private func readInitialRequest() {
        guard !isClosed else { return }
        client.receive(minimumIncompleteLength: 1, maximumLength: Self.ioChunkSize) { [weak self] data, _, complete, error in
            guard let self, !self.isClosed else { return }
            if let data, !data.isEmpty {
                self.initialBuffer.append(data)
                if let headerRange = self.initialBuffer.range(of: Self.headerMarker) {
                    self.handleInitialRequest(headerEnd: headerRange.upperBound)
                    return
                }
                if self.initialBuffer.count > Self.headerLimit {
                    self.reject(status: 431, reason: "Request Header Fields Too Large")
                    return
                }
            }
            if let error {
                self.finish(error: "Could not read proxy request: \(error.localizedDescription)")
            } else if complete {
                self.finish(error: nil)
            } else {
                self.readInitialRequest()
            }
        }
    }

    private func handleInitialRequest(headerEnd: Data.Index) {
        let headerData = initialBuffer[..<headerEnd]
        let body = Data(initialBuffer[headerEnd...])
        guard let headerText = String(data: headerData, encoding: .isoLatin1),
              let route = Self.parseRequest(headerText, body: body) else {
            reject(status: 400, reason: "Bad Request")
            return
        }

        stream = NativeHttp.openStream(client: clientLabel,
                                       server: Self.label(host: route.host, port: route.port),
                                       source: .proxy)
        var recorded = route.forwardedHeader
        if !route.isTunnel { recorded.append(route.initialBody) }   // tunnel bytes count once established
        record(recorded, toServer: true)

        if Self.isProxyLoop(host: route.host, port: route.port, proxyPort: proxyPort) {
            reject(status: 508, reason: "Loop Detected")
            return
        }

        let tcp = NWProtocolTCP.Options()
        tcp.connectionTimeout = Self.connectTimeout
        let upstream = NWParameters(tls: nil, tcp: tcp)
        upstream.preferNoProxies = true   // the system proxy may point back at this proxy
        let remote = NWConnection(host: NWEndpoint.Host(route.host),
                                  port: NWEndpoint.Port(rawValue: route.port)!,
                                  using: upstream)
        self.remote = remote
        remote.stateUpdateHandler = { [weak self, weak remote] state in
            guard let self, let remote, self.remote === remote, !self.isClosed else { return }
            switch state {
            case .ready:
                self.beginForwarding(route: route, remote: remote)
            case .waiting(let error), .failed(let error):
                // Network.framework reports DNS failures and refused connections as .waiting and
                // would retry indefinitely; a proxy client wants an answer now.
                self.upstreamFailed(error.localizedDescription)
            default:
                break
            }
        }
        remote.start(queue: queue)
    }

    private func beginForwarding(route: RequestRoute, remote: NWConnection) {
        if route.isTunnel {
            let established = Data("HTTP/1.1 200 Connection Established\r\nProxy-Agent: WareHound\r\n\r\n".utf8)
            client.send(content: established, completion: .contentProcessed { [weak self, weak remote] error in
                guard let self, let remote, !self.isClosed else { return }
                if let error {
                    self.finish(error: "Could not establish client tunnel: \(error.localizedDescription)")
                    return
                }
                self.tunnelEstablished = true
                self.record(established, toServer: false)
                if !route.initialBody.isEmpty {
                    self.record(route.initialBody, toServer: true)
                    remote.send(content: route.initialBody, completion: .contentProcessed { [weak self] error in
                        if let error { self?.finish(error: "Tunnel write failed: \(error.localizedDescription)") }
                    })
                }
                self.relay(from: self.client, to: remote, clientToServer: true)
                self.relay(from: remote, to: self.client, clientToServer: false)
            })
        } else {
            var firstWrite = route.forwardedHeader
            firstWrite.append(route.initialBody)
            remote.send(content: firstWrite, completion: .contentProcessed { [weak self, weak remote] error in
                guard let self, let remote, !self.isClosed else { return }
                if let error {
                    self.upstreamFailed(error.localizedDescription)
                    return
                }
                self.relay(from: self.client, to: remote, clientToServer: true)
                self.relay(from: remote, to: self.client, clientToServer: false)
            })
        }
    }

    private func relay(from source: NWConnection, to destination: NWConnection, clientToServer: Bool) {
        guard !isClosed else { return }
        source.receive(minimumIncompleteLength: 1, maximumLength: Self.ioChunkSize) { [weak self, weak source, weak destination] data, _, complete, error in
            guard let self, let source, let destination, !self.isClosed else { return }

            if let error {
                self.finish(error: "Proxy relay failed: \(error.localizedDescription)")
                return
            }

            if let data, !data.isEmpty {
                self.record(data, toServer: clientToServer)
                destination.send(content: data, completion: .contentProcessed { [weak self, weak source, weak destination] sendError in
                    guard let self, let source, let destination, !self.isClosed else { return }
                    if let sendError {
                        self.finish(error: "Proxy relay write failed: \(sendError.localizedDescription)")
                    } else if complete {
                        self.directionCompleted(clientToServer: clientToServer, destination: destination)
                    } else {
                        self.relay(from: source, to: destination, clientToServer: clientToServer)
                    }
                })
            } else if complete {
                self.directionCompleted(clientToServer: clientToServer, destination: destination)
            } else {
                self.relay(from: source, to: destination, clientToServer: clientToServer)
            }
        }
    }

    private func record(_ data: Data, toServer: Bool) {
        NativeHttp.feedStream(stream, toServer: toServer, data: data)
    }

    private func directionCompleted(clientToServer: Bool, destination: NWConnection) {
        destination.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
        if !clientToServer {
            finish(error: nil)
        }
    }

    private func upstreamFailed(_ detail: String) {
        guard !tunnelEstablished else {
            finish(error: "Upstream connection failed: \(detail)")
            return
        }
        sendError(status: 502, reason: "Bad Gateway", detail: detail)
    }

    private func reject(status: Int, reason: String) {
        sendError(status: status, reason: reason, detail: reason)
    }

    private func sendError(status: Int, reason: String, detail: String) {
        let safeDetail = detail.replacingOccurrences(of: "\r", with: " ").replacingOccurrences(of: "\n", with: " ")
        let body = Data("WareHound proxy: \(safeDetail)\n".utf8)
        let header = "HTTP/1.1 \(status) \(reason)\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: \(body.count)\r\nConnection: close\r\n\r\n"
        var response = Data(header.utf8)
        response.append(body)
        record(response, toServer: false)
        // Ignore further state changes while the error is being written.
        remote?.stateUpdateHandler = nil
        client.send(content: response, completion: .contentProcessed { [weak self] _ in
            self?.finish(error: safeDetail)
        })
    }

    private func finish(error: String?) {
        guard !isClosed else { return }
        isClosed = true
        NativeHttp.closeStream(stream, error: error)
        stream = 0
        client.stateUpdateHandler = nil
        remote?.stateUpdateHandler = nil
        client.cancel()
        remote?.cancel()
        remote = nil
        onClose(id)
    }

    private static func parseRequest(_ text: String, body: Data) -> RequestRoute? {
        let lines = text.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }
        let parts = requestLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        guard parts.count == 3 else { return nil }
        let method = String(parts[0]).uppercased()
        let target = String(parts[1])
        let version = String(parts[2])

        var headers: [(name: String, value: String, original: String)] = []
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = String(line[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            headers.append((name, value, line))
        }
        let headerValue: (String) -> String? = { wanted in
            headers.first { $0.name.caseInsensitiveCompare(wanted) == .orderedSame }?.value
        }

        let isTunnel = method == "CONNECT"
        let authority: (host: String, port: UInt16)?
        let originTarget: String
        if isTunnel {
            authority = parseAuthority(target, defaultPort: 443)
            originTarget = target
        } else if let components = URLComponents(string: target),
                  let scheme = components.scheme?.lowercased(),
                  let host = components.host {
            let defaultPort: UInt16 = scheme == "https" ? 443 : 80
            let port = components.port.flatMap(UInt16.init(exactly:)) ?? defaultPort
            authority = (host, port)
            var path = components.percentEncodedPath
            if path.isEmpty { path = "/" }
            if let query = components.percentEncodedQuery { path += "?\(query)" }
            originTarget = path
        } else if let hostHeader = headerValue("Host") {
            authority = parseAuthority(hostHeader, defaultPort: 80)
            originTarget = target.isEmpty ? "/" : target
        } else {
            return nil
        }
        guard let authority, !authority.host.isEmpty else { return nil }

        // Hop-by-hop proxy headers never leave the proxy (or reach the recorded copy).
        var forwardedLines = ["\(method) \(originTarget) \(version)"]
        for header in headers {
            let lower = header.name.lowercased()
            if lower == "proxy-connection" || lower == "proxy-authorization" || lower == "connection" { continue }
            forwardedLines.append(header.original)
        }
        if !isTunnel { forwardedLines.append("Connection: close") }
        let forwardedHeader = Data((forwardedLines.joined(separator: "\r\n") + "\r\n\r\n").utf8)

        return RequestRoute(host: authority.host,
                            port: authority.port,
                            isTunnel: isTunnel,
                            forwardedHeader: forwardedHeader,
                            initialBody: body)
    }

    private static func parseAuthority(_ value: String, defaultPort: UInt16) -> (host: String, port: UInt16)? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") {
            let host = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            let suffix = trimmed[trimmed.index(after: close)...]
            if suffix.isEmpty { return (host, defaultPort) }
            guard suffix.first == ":", let port = UInt16(suffix.dropFirst()) else { return nil }
            return (host, port)
        }

        let colonCount = trimmed.reduce(into: 0) { if $1 == ":" { $0 += 1 } }
        if colonCount == 1, let colon = trimmed.lastIndex(of: ":") {
            let host = String(trimmed[..<colon])
            guard let port = UInt16(trimmed[trimmed.index(after: colon)...]) else { return nil }
            return (host, port)
        }
        return (trimmed, defaultPort)
    }

    // "ip:port" / "[v6]:port" / "name:port", matching how libsniffer labels endpoints.
    private static func label(host: NWEndpoint.Host, port: UInt16) -> String {
        switch host {
        case .ipv4(let address):
            return "\(address.rawValue.map(String.init).joined(separator: ".")):\(port)"
        case .ipv6(let address):
            return "[\(address)]:\(port)"
        case .name(let name, _):
            return label(host: name, port: port)
        @unknown default:
            return "\(host):\(port)"
        }
    }

    private static func label(host: String, port: UInt16) -> String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    private static func isProxyLoop(host: String, port: UInt16, proxyPort: UInt16) -> Bool {
        guard port == proxyPort else { return false }
        let normalized = host.lowercased()
        return normalized == "127.0.0.1" || normalized == "localhost" || normalized == "::1"
    }
}
