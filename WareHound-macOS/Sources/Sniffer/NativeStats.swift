import Foundation
import CSniffer

enum NativeStats {

    private static let handle: UnsafeMutableRawPointer? = nil

    struct Overview {
        var totalPackets: UInt64
        var totalBytes: UInt64
        var packetsPerSecond: Double
        var captureDurationSeconds: Double
        var uniqueProtocols: Int32
        var uniqueSourceIPs: Int32
        var uniqueDestIPs: Int32
        var activeFlows: UInt64
    }

    struct Talker { var ip: String; var packetCount: UInt64 }
    struct Port { var port: UInt16; var serviceName: String; var packetCount: UInt64 }
    struct Protocol_ { var name: String; var packetCount: UInt64; var byteCount: UInt64; var percentage: Double }

    static func setEnabled(_ enabled: Bool) {
        Sniffer_EnableNativeStats(handle, enabled)
    }

    static func overview() -> Overview? {
        var s = NativeCaptureStatistics()
        guard Sniffer_GetCaptureStatistics(handle, &s) else { return nil }
        // Native counters lack wall-clock time; duration and pps are derived host-side.
        let (duration, pps) = tick(totalPackets: s.totalPackets)
        return Overview(
            totalPackets: s.totalPackets,
            totalBytes: s.totalBytes,
            packetsPerSecond: pps,
            captureDurationSeconds: duration,
            uniqueProtocols: Int32(clamping: s.uniqueProtocols),
            uniqueSourceIPs: Int32(clamping: s.uniqueSourceIPs),
            uniqueDestIPs: Int32(clamping: s.uniqueDestIPs),
            activeFlows: s.activeFlows
        )
    }

    static func protocolStats(limit: Int = 10) -> [Protocol_] {
        var buf = [NativeProtocolStats](repeating: NativeProtocolStats(), count: limit)
        let n = Int(Sniffer_GetProtocolStats(handle, &buf, Int32(limit)))
        let entries = buf.prefix(Swift.max(0, n))
        let total = entries.reduce(UInt64(0)) { $0 + $1.packetCount }
        return entries.map {
            let pct = total > 0 ? Double($0.packetCount) / Double(total) * 100 : 0
            return Protocol_(name: protoName($0.protocol),
                             packetCount: $0.packetCount,
                             byteCount: $0.byteCount,
                             percentage: pct)
        }
    }

    static func topSourceIPs(limit: Int = 5) -> [Talker] {
        var buf = [NativeTalkerStats](repeating: NativeTalkerStats(), count: limit)
        let n = Int(Sniffer_GetTopSourceIPs(handle, &buf, Int32(limit)))
        return buf.prefix(Swift.max(0, n)).map { Talker(ip: ipv4String($0.ipAddress), packetCount: $0.packetCount) }
    }

    static func topDestIPs(limit: Int = 5) -> [Talker] {
        var buf = [NativeTalkerStats](repeating: NativeTalkerStats(), count: limit)
        let n = Int(Sniffer_GetTopDestIPs(handle, &buf, Int32(limit)))
        return buf.prefix(Swift.max(0, n)).map { Talker(ip: ipv4String($0.ipAddress), packetCount: $0.packetCount) }
    }

    static func topPorts(limit: Int = 5) -> [Port] {
        var buf = [NativePortStats](repeating: NativePortStats(), count: limit)
        let n = Int(Sniffer_GetTopPorts(handle, &buf, Int32(limit)))
        return buf.prefix(Swift.max(0, n)).map {
            Port(port: $0.port, serviceName: serviceName($0.port), packetCount: $0.packetCount)
        }
    }

    static func clear() {
        Sniffer_ClearStatistics(handle)
        clock.lock()
        captureStart = nil
        lastSampleTime = nil
        lastPacketCount = 0
        clock.unlock()
    }

    static func flowCount() -> UInt64 {
        Sniffer_GetFlowCount(handle)
    }

    struct PcapDrops { var received: UInt64; var dropped: UInt64; var ifDropped: UInt64 }

    static func pcapStats() -> PcapDrops? {
        var r: UInt64 = 0, d: UInt64 = 0, i: UInt64 = 0
        guard fnGetPcapStats(&r, &d, &i) != 0 else { return nil }
        return PcapDrops(received: r, dropped: d, ifDropped: i)
    }

    struct L7Summary {
        var tlsClientHellos: UInt64
        var dnsQueries: UInt64
        var dnsAnswers: UInt64
        var distinctSniHosts: UInt64
        var distinctDnsNames: UInt64
    }
    struct SniHost { var sni: String; var connectionCount: UInt64; var lastTlsVersion: UInt16 }
    struct DnsName { var qname: String; var queryCount: UInt64; var avgResolveMs: UInt32; var lastQtype: UInt16 }
    struct ConnHealth { var dstIp: String; var dstPort: UInt16; var avgRttMs: UInt32; var retransmits: UInt32; var bytesSent: UInt64; var bytesRecv: UInt64 }

    static func l7Summary() -> L7Summary? {
        var s = NativeL7Summary()
        guard SnifferL7_GetSummary(handle, &s) else { return nil }
        return L7Summary(tlsClientHellos: s.tlsClientHellos,
                         dnsQueries: s.dnsQueries,
                         dnsAnswers: s.dnsAnswers,
                         distinctSniHosts: s.distinctSniHosts,
                         distinctDnsNames: s.distinctDnsNames)
    }

    static func topSniHosts(limit: Int = 10) -> [SniHost] {
        var buf = [NativeTlsHostStats](repeating: NativeTlsHostStats(), count: limit)
        let n = Int(SnifferL7_GetTopSniHosts(handle, &buf, Int32(limit)))
        return buf.prefix(Swift.max(0, n)).map {
            SniHost(sni: fixedString($0.sni), connectionCount: $0.connectionCount, lastTlsVersion: $0.lastTlsVersion)
        }
    }

    static func topDnsNames(limit: Int = 10) -> [DnsName] {
        var buf = [NativeDnsStats](repeating: NativeDnsStats(), count: limit)
        let n = Int(SnifferL7_GetTopDnsNames(handle, &buf, Int32(limit)))
        return buf.prefix(Swift.max(0, n)).map {
            DnsName(qname: fixedString($0.qname), queryCount: $0.queryCount, avgResolveMs: $0.avgResolveMs, lastQtype: $0.lastQtype)
        }
    }

    static func connHealth(limit: Int = 10) -> [ConnHealth] {
        var buf = [NativeConnHealthStats](repeating: NativeConnHealthStats(), count: limit)
        let n = Int(SnifferL7_GetConnHealth(handle, &buf, Int32(limit)))
        return buf.prefix(Swift.max(0, n)).map {
            ConnHealth(dstIp: fixedString($0.dstIp), dstPort: $0.dstPort, avgRttMs: $0.avgRttMs,
                       retransmits: $0.retransmits, bytesSent: $0.bytesSent, bytesRecv: $0.bytesRecv)
        }
    }

    static func l7Clear() {
        SnifferL7_Clear(handle)
    }

    // Prevents flow classifications from a previous capture leaking into a new one.
    static func resetFlows() {
        fnResetFlows()
    }

    private static let clock = NSLock()
    private static var captureStart: Date?
    private static var lastSampleTime: Date?
    private static var lastPacketCount: UInt64 = 0

    private static func tick(totalPackets: UInt64) -> (duration: Double, pps: Double) {
        clock.lock(); defer { clock.unlock() }
        let now = Date()
        if captureStart == nil && totalPackets > 0 {
            captureStart = now
            lastSampleTime = now
            lastPacketCount = totalPackets
        }
        let duration = captureStart.map { now.timeIntervalSince($0) } ?? 0
        var pps = 0.0
        if let last = lastSampleTime {
            let dt = now.timeIntervalSince(last)
            if dt > 0.001 {
                pps = Double(totalPackets &- lastPacketCount) / dt
                lastSampleTime = now
                lastPacketCount = totalPackets
            }
        }
        return (duration, Swift.max(0, pps))
    }

    private static func ipv4String(_ v: UInt32) -> String {
        // Native stores the address host-order with octet 0 in the high byte.
        "\((v >> 24) & 0xFF).\((v >> 16) & 0xFF).\((v >> 8) & 0xFF).\(v & 0xFF)"
    }

    private static func protoName(_ p: UInt8) -> String {
        switch p {
        case 0:   return "HOPOPT"
        case 1:   return "ICMP"
        case 2:   return "IGMP"
        case 6:   return "TCP"
        case 17:  return "UDP"
        case 41:  return "IPv6"
        case 47:  return "GRE"
        case 50:  return "ESP"
        case 51:  return "AH"
        case 58:  return "ICMPv6"
        case 89:  return "OSPF"
        case 132: return "SCTP"
        default:  return "IP proto \(p)"
        }
    }

    private static func serviceName(_ port: UInt16) -> String {
        PacketModel.serviceName(port: Int32(port)) ?? ""
    }

    private static func fixedString<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            var len = 0
            while len < bytes.count && bytes[len] != 0 { len += 1 }
            return String(decoding: bytes.prefix(len), as: UTF8.self)
        }
    }
}
