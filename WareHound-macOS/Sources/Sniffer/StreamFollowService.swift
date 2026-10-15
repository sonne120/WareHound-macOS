import Foundation
import CSniffer

struct FollowedStream: Sendable {
    enum Transport: Sendable { case tcp, udp, none }

    struct Chunk: Sendable, Identifiable {
        let id = UUID()
        let fromClient: Bool
        let offset: Int
        let length: Int
        let tsUsec: UInt64
    }

    var transport: Transport = .none
    var clientEndpoint = "—"
    var serverEndpoint = "—"
    var clientBytes = Data()
    var serverBytes = Data()
    var chunks: [Chunk] = []
    var segmentCount = 0
    var gapCount = 0

    var tlsAttempted = false
    var tlsStatus = ""
    var tlsRecordCount = 0
    var clientPlaintext = Data()
    var serverPlaintext = Data()
    var plaintextChunks: [Chunk] = []

    var isHttp2 = false
    var isGrpc = false
    var httpMethod = ""
    var grpcMethod = ""
    var httpStatus = ""
    var contentType = ""
    var authority = ""
    var grpcStatus = ""
    var grpcMessage = ""
    var h2Headers = ""
    var grpcMessages = 0
    var grpcBytes = 0
    var h2HeadersFrames = 0
    var h2DataFrames = 0

    var isEmpty: Bool { clientBytes.isEmpty && serverBytes.isEmpty }
    var hasDecryptedData: Bool { !clientPlaintext.isEmpty || !serverPlaintext.isEmpty }
}

enum StreamFollowService {

    // Native reassembler needs the real link type to strip the right header (lo0, SLL2).
    static func linkType(for packet: PacketModel) -> Int32 {
        packet.linkTypeCode
    }

    // Also decrypts TLS application data when `keylogPath` is set.
    static func build(from packets: [PacketModel], keylogPath: String? = nil) -> FollowedStream {
        guard let handle = fnStreamOpen() else { return FollowedStream() }
        defer { fnStreamClose(handle) }

        for packet in packets {
            let lt = linkType(for: packet)
            let ts = UInt64(max(0, packet.captureTime.timeIntervalSince1970) * 1_000_000)
            packet.rawData.withUnsafeBytes { raw in
                guard let base = raw.bindMemory(to: UInt8.self).baseAddress,
                      raw.count > 0 else { return }
                fnStreamFeed(handle, base, Int32(raw.count), lt, ts)
            }
        }

        var out = FollowedStream()
        switch fnStreamFinalize(handle) {
        case 6:  out.transport = .tcp
        case 17: out.transport = .udp
        default: out.transport = .none
        }

        out.clientBytes = directionBytes(handle, 0)
        out.serverBytes = directionBytes(handle, 1)
        out.chunks = chunkList(handle, decrypted: false)

        var c2s: UInt64 = 0, s2c: UInt64 = 0, segs: UInt32 = 0, gaps: UInt32 = 0
        fnStreamCounts(handle, &c2s, &s2c, &segs, &gaps)
        out.segmentCount = Int(segs)
        out.gapCount = Int(gaps)

        let (cip, cport) = endpoint(handle, isClient: true)
        let (sip, sport) = endpoint(handle, isClient: false)
        out.clientEndpoint = format(ip: cip, port: cport)
        out.serverEndpoint = format(ip: sip, port: sport)

        if let keylogPath, out.transport == .tcp {
            out.tlsAttempted = true
            keylogPath.withCString { fnStreamSetKeylog(handle, $0) }
            out.tlsRecordCount = Int(fnStreamDecryptTLS(handle))
            out.tlsStatus = String(cString: fnStreamTLSStatus(handle))
            out.clientPlaintext = plaintextBytes(handle, 0)
            out.serverPlaintext = plaintextBytes(handle, 1)
            out.plaintextChunks = chunkList(handle, decrypted: true)
        }

        if out.transport == .tcp {
            var h2 = SnifferH2Summary()
            if fnStreamHttp2(handle, &h2) != 0 {
                out.isHttp2        = true
                out.isGrpc         = h2.is_grpc != 0
                out.httpMethod     = cstr(h2.method)
                out.grpcMethod     = cstr(h2.path)
                out.httpStatus     = cstr(h2.status)
                out.contentType    = cstr(h2.content_type)
                out.authority      = cstr(h2.authority)
                out.grpcStatus     = cstr(h2.grpc_status)
                out.grpcMessage    = cstr(h2.grpc_message)
                out.h2Headers      = cstr(h2.transcript)
                out.grpcMessages   = Int(h2.grpc_messages)
                out.grpcBytes      = Int(h2.grpc_bytes)
                out.h2HeadersFrames = Int(h2.headers_frames)
                out.h2DataFrames   = Int(h2.data_frames)
            }
        }

        return out
    }

    private static func cstr<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            var len = 0
            while len < bytes.count && bytes[len] != 0 { len += 1 }
            return String(decoding: UnsafeBufferPointer(start: bytes.baseAddress, count: len), as: UTF8.self)
        }
    }

    // MARK: - C ABI readers

    private static func directionBytes(_ handle: OpaquePointer, _ dir: Int32) -> Data {
        var len: Int32 = 0
        guard let p = fnStreamBytes(handle, dir, &len), len > 0 else { return Data() }
        return Data(bytes: p, count: Int(len))
    }

    private static func plaintextBytes(_ handle: OpaquePointer, _ dir: Int32) -> Data {
        var len: Int32 = 0
        guard let p = fnStreamPlaintext(handle, dir, &len), len > 0 else { return Data() }
        return Data(bytes: p, count: Int(len))
    }

    private static func chunkList(_ handle: OpaquePointer, decrypted: Bool) -> [FollowedStream.Chunk] {
        let count = decrypted ? fnStreamPlaintextChunks(handle, nil, 0)
                              : fnStreamChunks(handle, nil, 0)
        guard count > 0 else { return [] }
        var raw = [SnifferStreamChunk](repeating: SnifferStreamChunk(), count: Int(count))
        _ = raw.withUnsafeMutableBufferPointer { buf in
            decrypted ? fnStreamPlaintextChunks(handle, buf.baseAddress, count)
                      : fnStreamChunks(handle, buf.baseAddress, count)
        }
        return raw.map {
            FollowedStream.Chunk(fromClient: $0.dir == 0,
                                 offset: Int($0.offset),
                                 length: Int($0.length),
                                 tsUsec: $0.ts_usec)
        }
    }

    private static func endpoint(_ handle: OpaquePointer, isClient: Bool) -> (String, Int32) {
        var ipBuf = [CChar](repeating: 0, count: 46)
        var port: Int32 = 0
        if isClient {
            fnStreamEndpoints(handle, &ipBuf, &port, nil, nil)
        } else {
            fnStreamEndpoints(handle, nil, nil, &ipBuf, &port)
        }
        return (String(cString: ipBuf), port)
    }

    private static func format(ip: String, port: Int32) -> String {
        let safeIp = ip.isEmpty ? "—" : ip
        return port > 0 ? "\(safeIp):\(port)" : safeIp
    }
}
