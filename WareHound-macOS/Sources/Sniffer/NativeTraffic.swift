import Foundation
import CSniffer

// Swift mirror of SnifferHttpTransaction; all parsing and pairing happens in libsniffer.
struct HttpTransaction: Identifiable, Hashable, Sendable {
    enum Kind: Sendable { case http, https, tls }
    enum Source: Sendable { case capture, proxy }

    let id: UInt64
    var version: UInt64
    var kind: Kind
    var requestFrame: Int
    var responseFrame: Int?
    var status: Int
    var isComplete: Bool
    var isTruncated: Bool
    var requestBytes: Int64
    var responseBytes: Int64
    var contentLength: Int64?
    var requestTime: Date
    var responseTime: Date?
    var method: String
    var host: String
    var target: String
    var reason: String
    var contentType: String
    var client: String
    var server: String
    var source: Source
    var error: String

    var isTunnel: Bool { method == "CONNECT" }
    var statusClass: Int { status / 100 }
    var isJSON: Bool { contentType.localizedCaseInsensitiveContains("json") }
    var isHTML: Bool { contentType.localizedCaseInsensitiveContains("html") }
    var url: String {
        switch kind {
        case .http: "http://\(host)\(target)"
        case .https: "https://\(host)\(target)"
        case .tls: "https://\(host)"
        }
    }
    var durationMs: Int? {
        responseTime.map { max(0, Int(($0.timeIntervalSince(requestTime) * 1000).rounded())) }
    }
}

struct HttpHeaderField: Identifiable, Hashable, Sendable {
    let id: Int
    let name: String
    let value: String
}

struct HttpHead: Sendable {
    var startLine: String
    var fields: [HttpHeaderField]
}

struct HttpSummary: Sendable {
    var total = 0, http = 0, tls = 0, json = 0, html = 0
    var status2xx = 0, status3xx = 0, status4xx = 0, status5xx = 0
}

struct AppStat: Identifiable, Sendable {
    var id: String { "\(app.name)|\(app.bundlePath ?? "")" }
    var app: AppIdentity
    var packets: Int
    var bytesSent: Int64
    var bytesReceived: Int64
    var connections: Int
    var hosts: Int
    var topHost: String
    var totalBytes: Int64 { bytesSent + bytesReceived }
    var isUnresolved: Bool { app.pid < 0 }
}

struct AppIdentity: Hashable, Sendable {
    var pid: Int32
    var name: String
    var bundlePath: String?
    var isContainer = false
}

enum NativeHttp {
    static func feed(_ packet: PacketModel) {
        let ts = UInt64(max(0, packet.captureTime.timeIntervalSince1970) * 1_000_000)
        packet.rawData.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress, raw.count > 0 else { return }
            SnifferHttp_Feed(base, Int32(raw.count), packet.linkTypeCode,
                             UInt32(truncatingIfNeeded: packet.number), ts)
        }
    }

    static func changes(since version: inout UInt64) -> [HttpTransaction] {
        var result: [HttpTransaction] = []
        var rows = [SnifferHttpTransaction](repeating: SnifferHttpTransaction(), count: 256)
        while true {
            var latest: UInt64 = 0
            let n = Int(SnifferHttp_GetChanged(version, &rows, Int32(rows.count), &latest))
            result.append(contentsOf: rows.prefix(n).map(Self.transaction))
            version = latest
            if n < rows.count { break }
        }
        return result
    }

    static func message(id: UInt64, response: Bool, decoded: Bool) -> Data? {
        let part: Int32 = response ? 1 : 0
        let size = Int(SnifferHttp_GetMessage(id, part, decoded ? 1 : 0, nil, 0))
        guard size >= 0 else { return nil }
        var data = Data(count: size)
        if size > 0 {
            data.withUnsafeMutableBytes { raw in
                _ = SnifferHttp_GetMessage(id, part, decoded ? 1 : 0,
                                           raw.bindMemory(to: UInt8.self).baseAddress, Int32(size))
            }
        }
        return data
    }

    static func head(id: UInt64, response: Bool) -> HttpHead? {
        var start = [CChar](repeating: 0, count: 2048)
        var rows = [SnifferHttpHeader](repeating: SnifferHttpHeader(), count: 128)
        let n = Int(SnifferHttp_GetHeaders(id, response ? 1 : 0, &start, Int32(start.count), &rows, Int32(rows.count)))
        guard n >= 0 else { return nil }
        let startLine = start.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
        let fields = rows.prefix(min(n, rows.count)).enumerated().map { i, r in
            HttpHeaderField(id: i, name: cstr(r.name), value: cstr(r.value))
        }
        return HttpHead(startLine: startLine, fields: fields)
    }

    static func body(id: UInt64, response: Bool, decoded: Bool) -> Data? {
        let part: Int32 = response ? 1 : 0
        let size = Int(SnifferHttp_GetBody(id, part, decoded ? 1 : 0, nil, 0))
        guard size >= 0 else { return nil }
        var data = Data(count: size)
        if size > 0 {
            data.withUnsafeMutableBytes { raw in
                _ = SnifferHttp_GetBody(id, part, decoded ? 1 : 0,
                                        raw.bindMemory(to: UInt8.self).baseAddress, Int32(size))
            }
        }
        return data
    }

    static func setKeylog(_ path: String) {
        SnifferHttp_SetKeylog(path)
    }

    // Decrypts in libsniffer without holding its lock; call off the main thread.
    static func decryptPending() -> Int {
        Int(SnifferHttp_DecryptPending())
    }

    static func summary() -> HttpSummary {
        var s = SnifferHttpSummary()
        SnifferHttp_GetSummary(&s)
        return HttpSummary(total: Int(s.total), http: Int(s.http), tls: Int(s.tls), json: Int(s.json),
                           html: Int(s.html), status2xx: Int(s.status2xx), status3xx: Int(s.status3xx),
                           status4xx: Int(s.status4xx), status5xx: Int(s.status5xx))
    }

    static func clear() {
        SnifferHttp_Clear()
    }

    static func clear(source: HttpTransaction.Source) {
        SnifferHttp_ClearSource(Int32(sourceCode(source)))
    }

    // Byte streams from the local proxy; parsed by the same tracker as captured traffic.
    static func openStream(client: String, server: String, source: HttpTransaction.Source) -> UInt64 {
        SnifferHttp_OpenStream(client, server, Int32(sourceCode(source)))
    }

    static func feedStream(_ stream: UInt64, toServer: Bool, data: Data) {
        guard stream != 0, !data.isEmpty else { return }
        let ts = UInt64(Date().timeIntervalSince1970 * 1_000_000)
        data.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            SnifferHttp_FeedStream(stream, toServer ? 0 : 1, base, Int32(raw.count), ts)
        }
    }

    static func closeStream(_ stream: UInt64, error: String?) {
        guard stream != 0 else { return }
        SnifferHttp_CloseStream(stream, error)
    }

    private static func sourceCode(_ source: HttpTransaction.Source) -> UInt32 {
        switch source {
        case .capture: SNIFFER_HTTP_SOURCE_CAPTURE.rawValue
        case .proxy: SNIFFER_HTTP_SOURCE_PROXY.rawValue
        }
    }

    private static func transaction(_ r: SnifferHttpTransaction) -> HttpTransaction {
        HttpTransaction(
            id: r.id,
            version: r.version,
            kind: r.kind == Int32(SNIFFER_HTTP_KIND_TLS.rawValue) ? .tls
                : (r.kind == Int32(SNIFFER_HTTP_KIND_HTTPS.rawValue) ? .https : .http),
            requestFrame: Int(r.requestFrame),
            responseFrame: r.responseFrame == 0 ? nil : Int(r.responseFrame),
            status: Int(r.status),
            isComplete: r.complete != 0,
            isTruncated: r.truncated != 0,
            requestBytes: r.requestBytes,
            responseBytes: r.responseBytes,
            contentLength: r.responseContentLength >= 0 ? r.responseContentLength : nil,
            requestTime: Date(timeIntervalSince1970: r.requestTime),
            responseTime: r.responseTime > 0 ? Date(timeIntervalSince1970: r.responseTime) : nil,
            method: cstr(r.method),
            host: cstr(r.host),
            target: cstr(r.target),
            reason: cstr(r.reason),
            contentType: cstr(r.contentType),
            client: cstr(r.client),
            server: cstr(r.server),
            source: r.source == Int32(SNIFFER_HTTP_SOURCE_PROXY.rawValue) ? .proxy : .capture,
            error: cstr(r.error))
    }
}

enum NativeProcess {
    static func lookup(_ packet: PacketModel) -> AppIdentity? {
        var info = SnifferProcessInfo()
        let found = SnifferProc_LookupFlow(Int32(packet.meta.ipProto), packet.sourceIp, packet.sourcePort,
                                           packet.destIp, packet.destPort, &info)
        guard found != 0 else { return nil }
        let bundle = cstr(info.bundlePath)
        return AppIdentity(pid: info.pid, name: cstr(info.name), bundlePath: bundle.isEmpty ? nil : bundle)
    }

    static func lookupTCP(sourceIp: String, sourcePort: Int32, destIp: String, destPort: Int32) -> AppIdentity? {
        var info = SnifferProcessInfo()
        guard SnifferProc_LookupFlow(6, sourceIp, sourcePort, destIp, destPort, &info) != 0 else { return nil }
        let bundle = cstr(info.bundlePath)
        return AppIdentity(pid: info.pid, name: cstr(info.name), bundlePath: bundle.isEmpty ? nil : bundle)
    }

    // Resolves like lookup and also counts the packet toward its app's totals.
    static func account(_ packet: PacketModel) -> AppIdentity? {
        var info = SnifferProcessInfo()
        let found = SnifferProc_AccountPacket(Int32(packet.meta.ipProto), packet.sourceIp, packet.sourcePort,
                                              packet.destIp, packet.destPort, packet.originalLen,
                                              packet.hostName, &info)
        guard found != 0 else { return nil }
        let bundle = cstr(info.bundlePath)
        return AppIdentity(pid: info.pid, name: cstr(info.name), bundlePath: bundle.isEmpty ? nil : bundle)
    }

    static func appStats(limit: Int = 64) -> [AppStat] {
        var rows = [SnifferAppStats](repeating: SnifferAppStats(), count: limit)
        let n = Int(SnifferApps_GetStats(&rows, Int32(limit)))
        return rows.prefix(n).map { r in
            let bundle = cstr(r.bundlePath)
            return AppStat(app: AppIdentity(pid: r.pid, name: cstr(r.name), bundlePath: bundle.isEmpty ? nil : bundle),
                           packets: Int(r.packets), bytesSent: Int64(r.bytesSent), bytesReceived: Int64(r.bytesReceived),
                           connections: Int(r.connections), hosts: Int(r.hosts), topHost: cstr(r.topHost))
        }
    }

    static func clear() {
        SnifferProc_Clear()
    }
}

private func cstr<T>(_ tuple: T) -> String {
    withUnsafeBytes(of: tuple) { raw in
        let bytes = raw.bindMemory(to: UInt8.self)
        let len = bytes.firstIndex(of: 0) ?? bytes.count
        return String(decoding: UnsafeBufferPointer(rebasing: bytes[..<len]), as: UTF8.self)
    }
}
