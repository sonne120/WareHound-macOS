import Foundation
import CPcap

final class PcapFileService: Sendable {

    enum PcapError: LocalizedError {
        case openFailed(String)
        case dumpFailed(String)
        case noPacketsWithRawData

        var errorDescription: String? {
            switch self {
            case .openFailed(let m):  return "Failed to open PCAP: \(m)"
            case .dumpFailed(let m):  return "Failed to write PCAP: \(m)"
            case .noPacketsWithRawData:
                return "No packets with raw data to save. Packets must have been captured (not just metadata)."
            }
        }
    }

    var backendName: String { "Native (libpcap)" }

    func canHandle(_ path: String) -> Bool {
        let ext = (path as NSString).pathExtension.lowercased()
        return ext == "pcap" || ext == "cap"
    }

    func save(_ packets: [PacketModel], to path: String,
              progress: (@Sendable (Int) -> Void)? = nil) async throws {
        let withData = packets.filter { !$0.rawData.isEmpty && $0.captureLen > 0 }
        guard !withData.isEmpty else { throw PcapError.noPacketsWithRawData }

        try await Task.detached(priority: .userInitiated) {
            guard let dead = pcap_open_dead(DLT_EN10MB, 65535) else {
                throw PcapError.openFailed("pcap_open_dead failed")
            }
            defer { pcap_close(dead) }

            guard let dumper = pcap_dump_open(dead, path) else {
                throw PcapError.dumpFailed(String(cString: pcap_geterr(dead)))
            }
            defer { pcap_dump_close(dumper) }

            for (i, packet) in withData.enumerated() {
                try Task.checkCancellation()

                var header = pcap_pkthdr()
                let t = packet.captureTime.timeIntervalSince1970
                header.ts.tv_sec = Int(t)
                header.ts.tv_usec = Int32((t - floor(t)) * 1_000_000)
                header.caplen = UInt32(packet.rawData.count)
                header.len = packet.originalLen > 0 ? packet.originalLen : header.caplen

                packet.rawData.withUnsafeBytes { raw in
                    pcap_dump(
                        UnsafeMutableRawPointer(dumper).assumingMemoryBound(to: UInt8.self),
                        &header,
                        raw.baseAddress!.assumingMemoryBound(to: UInt8.self))
                }

                progress?((i + 1) * 100 / withData.count)
            }
        }.value
    }

    func load(from path: String,
              progress: (@Sendable (Int) -> Void)? = nil) async throws -> [PacketModel] {
        try await Task.detached(priority: .userInitiated) {
            var errbuf = [CChar](repeating: 0, count: Int(PCAP_ERRBUF_SIZE))
            guard let handle = pcap_open_offline(path, &errbuf) else {
                throw PcapError.openFailed(String(cString: errbuf))
            }
            defer { pcap_close(handle) }

            let linkType: PacketParser.LinkType
            switch pcap_datalink(handle) {
            case 1:            linkType = .ethernet   // DLT_EN10MB
            case 0, 108:       linkType = .null       // DLT_NULL / DLT_LOOP
            case 12, 14, 101:  linkType = .raw        // DLT_RAW variants
            case 113:          linkType = .sll        // DLT_LINUX_SLL
            case 276:          linkType = .sll2       // DLT_LINUX_SLL2
            default:           linkType = .ethernet
            }

            var packets: [PacketModel] = []
            var headerPtr: UnsafeMutablePointer<pcap_pkthdr>?
            var dataPtr: UnsafePointer<UInt8>?
            var number = 0

            while true {
                try Task.checkCancellation()

                let rc = pcap_next_ex(handle, &headerPtr, &dataPtr)
                if rc == PCAP_ERROR_BREAK || rc == -2 { break }
                guard rc == 1, let h = headerPtr?.pointee, let d = dataPtr else {
                    if rc < 0 { throw PcapError.openFailed(String(cString: pcap_geterr(handle))) }
                    continue
                }

                number += 1
                let raw = Data(bytes: d, count: Int(h.caplen))
                packets.append(PacketModel.from(
                    rawFrame: raw,
                    number: number,
                    captureTime: Date(timeIntervalSince1970:
                        TimeInterval(h.ts.tv_sec) + TimeInterval(h.ts.tv_usec) / 1_000_000),
                    captureLen: h.caplen,
                    originalLen: h.len,
                    linkType: linkType
                ))

                if number % 500 == 0 { progress?(number) }
            }
            return packets
        }.value
    }
}
