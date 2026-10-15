import NetworkExtension
import Foundation
import CSniffer

final class PacketTunnelProvider: NEPacketTunnelProvider {
    private struct BridgedPacket: Codable {
        let sequence: UInt64
        let timestamp: TimeInterval
        let proto: String
        let sourceIp: String
        let destIp: String
        let sourcePort: Int32
        let destPort: Int32
        let captureLen: UInt32
        let originalLen: UInt32
    }

    private struct BridgedState: Codable {
        let isRunning: Bool
        let status: String
        let updatedAt: TimeInterval
    }

    private enum BridgeKeys {
        static let l7Stats = "l7stats"
        static let packets = "tunnelPackets"
        static let state = "tunnelState"
    }

    private struct RawPacketParser {
        struct Parsed {
            var proto = "Unknown"
            var sourceIp = ""
            var destIp = ""
            var sourcePort: Int32 = 0
            var destPort: Int32 = 0
        }

        static func parse(_ data: Data) -> Parsed {
            var parsed = Parsed()
            guard let first = data.first else { return parsed }
            switch first >> 4 {
            case 4: parseIPv4(data, 0, into: &parsed)
            case 6: parseIPv6(data, 0, into: &parsed)
            default: parsed.proto = "IP?"
            }
            return parsed
        }

        private static func parseIPv4(_ data: Data, _ off: Int, into parsed: inout Parsed) {
            guard data.count >= off + 20 else { parsed.proto = "IPv4"; return }
            let ihl = Int(data[data.startIndex + off] & 0x0F) * 4
            let proto = data[data.startIndex + off + 9]
            parsed.sourceIp = ipv4(data, off + 12)
            parsed.destIp = ipv4(data, off + 16)
            parseL4(data, off + ihl, proto, into: &parsed)
        }

        private static func parseIPv6(_ data: Data, _ off: Int, into parsed: inout Parsed) {
            guard data.count >= off + 40 else { parsed.proto = "IPv6"; return }
            let nextHeader = data[data.startIndex + off + 6]
            parsed.sourceIp = ipv6(data, off + 8)
            parsed.destIp = ipv6(data, off + 24)
            parseL4(data, off + 40, nextHeader, into: &parsed)
        }

        private static func parseL4(_ data: Data, _ off: Int, _ proto: UInt8, into parsed: inout Parsed) {
            switch proto {
            case 6:
                parsed.proto = "TCP"
                if data.count >= off + 4 {
                    parsed.sourcePort = Int32(be16(data, off))
                    parsed.destPort = Int32(be16(data, off + 2))
                }
            case 17:
                parsed.proto = "UDP"
                if data.count >= off + 4 {
                    parsed.sourcePort = Int32(be16(data, off))
                    parsed.destPort = Int32(be16(data, off + 2))
                }
            case 1:
                parsed.proto = "ICMP"
            case 58:
                parsed.proto = "ICMPv6"
            default:
                parsed.proto = "IP/\(proto)"
            }
        }

        private static func be16(_ data: Data, _ off: Int) -> UInt16 {
            let i = data.startIndex + off
            return UInt16(data[i]) << 8 | UInt16(data[i + 1])
        }

        private static func ipv4(_ data: Data, _ off: Int) -> String {
            let i = data.startIndex + off
            return "\(data[i]).\(data[i + 1]).\(data[i + 2]).\(data[i + 3])"
        }

        private static func ipv6(_ data: Data, _ off: Int) -> String {
            let i = data.startIndex + off
            var groups: [String] = []
            for g in 0..<8 {
                groups.append(String(format: "%x", UInt16(data[i + g * 2]) << 8 | UInt16(data[i + g * 2 + 1])))
            }
            return groups.joined(separator: ":")
        }
    }

    static let appGroup = "group.com.sonne120.WareHound"

    private var statsTimer: DispatchSourceTimer?
    private let bridgeLock = NSLock()
    private var pendingPackets: [BridgedPacket] = []
    private var nextSequence: UInt64 = 1

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: ["10.66.0.2"], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: ["fd66::2"], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        settings.mtu = 1500
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self, error == nil else { completionHandler(error); return }

            fnSetOutboundCallback({ _, pkt, len in
                guard let pkt, len > 0 else { return }
                let data = Data(bytes: pkt, count: Int(len))
                let family = (data.first.map { ($0 >> 4) == 6 } ?? false) ? AF_INET6 : AF_INET
                PacketTunnelProvider.shared?.packetFlow.writePackets([data], withProtocols: [NSNumber(value: family)])
            }, nil)

            fnSetCaptureSource(Int32(SNIFFER_SOURCE_TUNNEL.rawValue))
            fnSetIpcMode(Int32(SNIFFER_IPC_MODE_CALLBACK.rawValue))
            fnStartCapture()

            PacketTunnelProvider.shared = self
            self.publishState(isRunning: true, status: "Tunnel running (IP-only)")
            self.readLoop()
            self.startStatsPublishing()
            completionHandler(nil)
        }
    }

    private func readLoop() {
        packetFlow.readPackets { [weak self] packets, _ in
            for packet in packets {
                self?.queuePacket(packet)
                packet.withUnsafeBytes { raw in
                    guard let base = raw.bindMemory(to: UInt8.self).baseAddress, raw.count > 0 else { return }
                    fnSubmitPacket(base, Int32(raw.count))
                }
            }
            self?.readLoop()
        }
    }

    private func startStatsPublishing() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 0.3, repeating: 0.3)
        timer.setEventHandler { [weak self] in self?.publishBridgedData() }
        timer.resume()
        statsTimer = timer
    }

    private func publishBridgedData() {
        guard let defaults = UserDefaults(suiteName: Self.appGroup) else { return }

        var summary = NativeL7Summary()
        _ = SnifferL7_GetSummary(nil, &summary)

        var sniRows = [NativeTlsHostStats](repeating: .init(), count: 20)
        let sniN = Int(SnifferL7_GetTopSniHosts(nil, &sniRows, 20))
        var dnsRows = [NativeDnsStats](repeating: .init(), count: 20)
        let dnsN = Int(SnifferL7_GetTopDnsNames(nil, &dnsRows, 20))

        func cstr<T>(_ value: T) -> String {
            withUnsafeBytes(of: value) { raw in
                let bytes = raw.bindMemory(to: UInt8.self)
                var count = 0
                while count < bytes.count && bytes[count] != 0 { count += 1 }
                return String(decoding: bytes.prefix(count), as: UTF8.self)
            }
        }

        let payload: [String: Any] = [
            "tlsClientHellos": summary.tlsClientHellos,
            "dnsQueries": summary.dnsQueries,
            "sni": (0..<sniN).map { ["host": cstr(sniRows[$0].sni), "count": sniRows[$0].connectionCount] },
            "dns": (0..<dnsN).map { ["name": cstr(dnsRows[$0].qname), "count": dnsRows[$0].queryCount] },
        ]
        if let encodedStats = try? JSONSerialization.data(withJSONObject: payload) {
            defaults.set(encodedStats, forKey: BridgeKeys.l7Stats)
        }

        flushQueuedPackets(into: defaults)
        defaults.synchronize()
    }

    private func queuePacket(_ packet: Data) {
        let parsed = RawPacketParser.parse(packet)
        let bridged = BridgedPacket(
            sequence: nextSequence,
            timestamp: Date().timeIntervalSince1970,
            proto: parsed.proto,
            sourceIp: parsed.sourceIp,
            destIp: parsed.destIp,
            sourcePort: parsed.sourcePort,
            destPort: parsed.destPort,
            captureLen: UInt32(packet.count),
            originalLen: UInt32(packet.count)
        )

        bridgeLock.lock()
        nextSequence += 1
        pendingPackets.append(bridged)
        if pendingPackets.count > 256 {
            pendingPackets.removeFirst(pendingPackets.count - 256)
        }
        bridgeLock.unlock()
    }

    private func flushQueuedPackets(into defaults: UserDefaults) {
        bridgeLock.lock()
        let batch = pendingPackets
        pendingPackets.removeAll(keepingCapacity: true)
        bridgeLock.unlock()

        guard !batch.isEmpty, let encoded = try? JSONEncoder().encode(batch) else { return }
        defaults.set(encoded, forKey: BridgeKeys.packets)
    }

    private func publishState(isRunning: Bool, status: String) {
        guard let defaults = UserDefaults(suiteName: Self.appGroup) else { return }
        let state = BridgedState(isRunning: isRunning, status: status, updatedAt: Date().timeIntervalSince1970)
        guard let encoded = try? JSONEncoder().encode(state) else { return }
        defaults.set(encoded, forKey: BridgeKeys.state)
        defaults.synchronize()
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        statsTimer?.cancel()
        statsTimer = nil
        fnSetOutboundCallback(nil, nil)
        fnCloseApp()
        publishState(isRunning: false, status: "Stopped")
        PacketTunnelProvider.shared = nil
        completionHandler()
    }

    fileprivate static weak var shared: PacketTunnelProvider?
}
