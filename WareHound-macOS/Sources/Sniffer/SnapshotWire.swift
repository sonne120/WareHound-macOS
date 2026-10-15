import Foundation

enum SnapshotWire {

    static let headerSize = 164

    private enum Offset {
        static let id            = 0
        static let sourcePort    = 4
        static let destPort      = 8
        static let proto         = 12
        static let sourceIp      = 34
        static let destIp        = 56
        static let sourceMac     = 78
        static let destMac       = 100
        static let hostName      = 122
        static let captureLen    = 144
        static let originalLen   = 148
        static let timestampSec  = 152
        static let timestampUsec = 160
    }

    private static let fixedStringLen = 22

    struct Snapshot {
        var id: Int32
        var sourcePort: Int32
        var destPort: Int32
        var proto: String
        var sourceIp: String
        var destIp: String
        var sourceMac: String
        var destMac: String
        var hostName: String
        var captureLen: UInt32
        var originalLen: UInt32
        var timestampSec: UInt64
        var timestampUsec: UInt32
        var rawData: Data
    }

    static func parse(_ bytes: UnsafeRawBufferPointer) -> Snapshot? {
        guard bytes.count >= headerSize, let base = bytes.baseAddress else { return nil }

        let captureLen = base.loadUnaligned(fromByteOffset: Offset.captureLen, as: UInt32.self)

        let available = bytes.count - headerSize
        let payloadLen = min(Int(captureLen), max(available, 0))

        var rawData = Data()
        if payloadLen > 0 {
            rawData = Data(bytes: base + headerSize, count: payloadLen)
        }

        return Snapshot(
            id:            base.loadUnaligned(fromByteOffset: Offset.id,            as: Int32.self),
            sourcePort:    base.loadUnaligned(fromByteOffset: Offset.sourcePort,    as: Int32.self),
            destPort:      base.loadUnaligned(fromByteOffset: Offset.destPort,      as: Int32.self),
            proto:         fixedCString(bytes, at: Offset.proto),
            sourceIp:      fixedCString(bytes, at: Offset.sourceIp),
            destIp:        fixedCString(bytes, at: Offset.destIp),
            sourceMac:     fixedCString(bytes, at: Offset.sourceMac),
            destMac:       fixedCString(bytes, at: Offset.destMac),
            hostName:      fixedCString(bytes, at: Offset.hostName),
            captureLen:    captureLen,
            originalLen:   base.loadUnaligned(fromByteOffset: Offset.originalLen,   as: UInt32.self),
            timestampSec:  base.loadUnaligned(fromByteOffset: Offset.timestampSec,  as: UInt64.self),
            timestampUsec: base.loadUnaligned(fromByteOffset: Offset.timestampUsec, as: UInt32.self),
            rawData:       rawData
        )
    }

    private static func fixedCString(_ bytes: UnsafeRawBufferPointer, at offset: Int) -> String {
        let start = bytes.baseAddress!.advanced(by: offset).assumingMemoryBound(to: UInt8.self)
        var len = 0
        while len < fixedStringLen && start[len] != 0 { len += 1 }
        return String(decoding: UnsafeBufferPointer(start: start, count: len), as: UTF8.self)
    }
}
