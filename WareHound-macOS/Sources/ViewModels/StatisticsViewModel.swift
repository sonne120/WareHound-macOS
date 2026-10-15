import Foundation
import Observation

struct TalkerInfo: Identifiable {
    var ip = ""
    var packetCount: Int64 = 0
    var id: String { ip }
}

struct PortInfo: Identifiable {
    var port: Int32 = 0
    var packetCount: Int64 = 0
    var serviceName = ""
    var id: Int32 { port }
    var display: String { serviceName.isEmpty ? "\(port)" : "\(port) (\(serviceName))" }
}

struct PpsSample: Identifiable {
    let id = UUID()
    let index: Int
    let pps: Double
}

@MainActor
@Observable
final class StatisticsViewModel {

    private static let refreshInterval: Duration = .milliseconds(1_000)

    private(set) var totalPackets: Int64 = 0
    private(set) var totalBytes: Int64 = 0
    private(set) var packetsPerSecond: Double = 0
    private(set) var captureTime = "00:00:00"
    private(set) var uniqueProtocols = 0
    private(set) var uniqueIPs = 0
    private(set) var isCapturing = false

    private(set) var protocolStats: [ProtocolStats] = []
    private(set) var topSourceIPs: [TalkerInfo] = []
    private(set) var topDestIPs: [TalkerInfo] = []
    private(set) var topPorts: [PortInfo] = []

    // Cumulative totals, so they never shrink on tab switches.
    var scanCount: Int { captureViewModel?.scanCount ?? 0 }
    var badChecksumCount: Int { captureViewModel?.badChecksumCount ?? 0 }

    // Sticky: only overwritten with fresh data, never blanked on tab switch.
    private(set) var droppedPackets = 0
    private(set) var receivedPackets = 0
    private(set) var packetLossPercent: Double = 0

    private(set) var ppsHistory: [PpsSample] = []
    private(set) var maxPps: Double = 0
    private var sampleIndex = 0

    private(set) var l7Summary: NativeStats.L7Summary?
    private(set) var topSniHosts: [NativeStats.SniHost] = []
    private(set) var topDnsNames: [NativeStats.DnsName] = []
    private(set) var connHealth: [NativeStats.ConnHealth] = []
    var hasL7Data: Bool { !topSniHosts.isEmpty || !topDnsNames.isEmpty || !connHealth.isEmpty }

    private(set) var arpOperations: [InspectionCounter] = []
    private(set) var arpSenders: [InspectionCounter] = []
    private(set) var dhcpMessages: [InspectionCounter] = []
    private(set) var httpHosts: [InspectionCounter] = []
    private(set) var httpMethods: [InspectionCounter] = []
    private(set) var mdnsNames: [InspectionCounter] = []
    private(set) var quicEndpoints: [InspectionCounter] = []
    var hasInspectionData: Bool {
        !arpOperations.isEmpty || !arpSenders.isEmpty || !dhcpMessages.isEmpty
            || !httpHosts.isEmpty || !httpMethods.isEmpty || !mdnsNames.isEmpty
            || !quicEndpoints.isEmpty
    }

    private(set) var isNativeStatsAvailable = true
    private weak var captureViewModel: CaptureViewModel?

    private var refreshTask: Task<Void, Never>?

    init(captureViewModel: CaptureViewModel? = nil) {
        self.captureViewModel = captureViewModel
    }

    func onCaptureStateChanged(isCapturing: Bool) {
        self.isCapturing = isCapturing
        if isCapturing {
            startTimer()
        } else {
            stopTimer()
            refresh()
        }
    }

    private func startTimer() {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            while !Task.isCancelled {
                self?.refresh()
                try? await Task.sleep(for: Self.refreshInterval)
            }
        }
    }

    private func stopTimer() {
        refreshTask?.cancel()
        refreshTask = nil
    }

    func refresh() {
        if captureViewModel != nil {
            isNativeStatsAvailable = false
            applyFallback()
        } else if let overview = NativeStats.overview() {
            applyNative(overview)
        } else {
            applyFallback()
        }
        applyL7()
        applyInspection()
        updatePacketLoss()
        recordPpsSample()
    }

    private func applyInspection() {
        guard let stats = captureViewModel?.statistics else {
            arpOperations = []
            arpSenders = []
            dhcpMessages = []
            httpHosts = []
            httpMethods = []
            mdnsNames = []
            quicEndpoints = []
            return
        }

        arpOperations = stats.topInspectionCounters(stats.arpOperations, limit: 6)
        arpSenders = stats.topInspectionCounters(stats.arpSenders, limit: 6)
        dhcpMessages = stats.topInspectionCounters(stats.dhcpMessages, limit: 8)
        httpHosts = stats.topInspectionCounters(stats.httpHosts, limit: 8)
        httpMethods = stats.topInspectionCounters(stats.httpMethods, limit: 8)
        mdnsNames = stats.topInspectionCounters(stats.mdnsNames, limit: 8)
        quicEndpoints = stats.topInspectionCounters(stats.quicEndpoints, limit: 8)
    }

    private func updatePacketLoss() {
        // Prefer kernel/NIC loss, else pipeline loss; keep previous value if neither is fresh.
        if let k = NativeStats.pcapStats(), k.received > 0 {
            let lost = k.dropped + k.ifDropped
            receivedPackets = Int(k.received)
            droppedPackets = Int(lost)
            packetLossPercent = Double(lost) / Double(k.received) * 100
            return
        }
        let c = SnifferBridge.shared.captureCounters()
        if c.received > 0 {
            receivedPackets = c.received
            droppedPackets = c.dropped
            packetLossPercent = Double(c.dropped) / Double(c.received) * 100
        }
    }

    private func applyL7() {
        let nativeSummary = NativeStats.l7Summary()
        let nativeSniHosts = NativeStats.topSniHosts(limit: 10)
        let nativeDnsNames = NativeStats.topDnsNames(limit: 10)
        let nativeConnHealth = NativeStats.connHealth(limit: 10)
        let nativeHasSummaryData = nativeSummary.map {
            $0.tlsClientHellos > 0
                || $0.dnsQueries > 0
                || $0.dnsAnswers > 0
                || $0.distinctSniHosts > 0
                || $0.distinctDnsNames > 0
        } ?? false

        if nativeHasSummaryData || !nativeSniHosts.isEmpty || !nativeDnsNames.isEmpty
            || !nativeConnHealth.isEmpty {
            l7Summary = nativeSummary
            topSniHosts = nativeSniHosts
            topDnsNames = nativeDnsNames
            connHealth = nativeConnHealth
            return
        }

        // pcap mode has no native L7: fall back to passive stats from captured packets.
        guard let stats = captureViewModel?.statistics else {
            l7Summary = nil
            topSniHosts = []
            topDnsNames = []
            connHealth = []
            return
        }

        connHealth = stats.topConnHealthList(limit: 10).map {
            NativeStats.ConnHealth(
                dstIp: $0.dstIp,
                dstPort: UInt16(truncatingIfNeeded: $0.dstPort),
                avgRttMs: $0.avgRttMs,
                retransmits: $0.retransmits,
                bytesSent: $0.bytesSent,
                bytesRecv: $0.bytesRecv
            )
        }

        let fallbackSummary = stats.l7Summary
        if fallbackSummary.tlsClientHellos == 0 && fallbackSummary.dnsQueries == 0
            && fallbackSummary.dnsAnswers == 0 {
            l7Summary = nil
            topSniHosts = []
            topDnsNames = []
            return
        }

        l7Summary = NativeStats.L7Summary(
            tlsClientHellos: fallbackSummary.tlsClientHellos,
            dnsQueries: fallbackSummary.dnsQueries,
            dnsAnswers: fallbackSummary.dnsAnswers,
            distinctSniHosts: fallbackSummary.distinctSniHosts,
            distinctDnsNames: fallbackSummary.distinctDnsNames
        )
        topSniHosts = stats.topSniHostsList(limit: 10).map {
            NativeStats.SniHost(sni: $0.host, connectionCount: $0.connectionCount, lastTlsVersion: $0.lastTlsVersion)
        }
        topDnsNames = stats.topDnsNamesList(limit: 10).map {
            NativeStats.DnsName(qname: $0.name, queryCount: $0.queryCount, avgResolveMs: $0.avgResolveMs, lastQtype: $0.lastQtype)
        }
    }

    private func applyNative(_ s: NativeStats.Overview) {
        totalPackets = Int64(s.totalPackets)
        totalBytes = Int64(s.totalBytes)
        packetsPerSecond = s.packetsPerSecond
        captureTime = Self.hms(s.captureDurationSeconds)
        uniqueProtocols = Int(s.uniqueProtocols)
        uniqueIPs = Int(s.uniqueSourceIPs + s.uniqueDestIPs)

        protocolStats = NativeStats.protocolStats(limit: 10).map {
            ProtocolStats(proto: $0.name, packetCount: Int64($0.packetCount),
                          byteCount: Int64($0.byteCount), percentage: $0.percentage)
        }
        topSourceIPs = NativeStats.topSourceIPs(limit: 5).map {
            TalkerInfo(ip: $0.ip, packetCount: Int64($0.packetCount))
        }
        topDestIPs = NativeStats.topDestIPs(limit: 5).map {
            TalkerInfo(ip: $0.ip, packetCount: Int64($0.packetCount))
        }
        topPorts = NativeStats.topPorts(limit: 5).map {
            PortInfo(port: Int32($0.port), packetCount: Int64($0.packetCount), serviceName: $0.serviceName)
        }
    }

    private func applyFallback() {
        guard let stats = captureViewModel?.statistics else { return }
        totalPackets = stats.totalPackets
        totalBytes = stats.totalBytes
        packetsPerSecond = stats.packetsPerSecond
        captureTime = Self.hms(stats.duration)
        uniqueProtocols = stats.protocolBreakdown.count
        uniqueIPs = stats.topSourceIPs.count + stats.topDestIPs.count

        let total = max(stats.totalPackets, 1)
        protocolStats = stats.protocolBreakdown.values
            .sorted { $0.packetCount > $1.packetCount }
            .prefix(10)
            .map { var p = $0; p.percentage = Double(p.packetCount) / Double(total) * 100; return p }

        topSourceIPs = stats.topSourceIPs.sorted { $0.value > $1.value }.prefix(5)
            .map { TalkerInfo(ip: $0.key, packetCount: $0.value) }
        topDestIPs = stats.topDestIPs.sorted { $0.value > $1.value }.prefix(5)
            .map { TalkerInfo(ip: $0.key, packetCount: $0.value) }
        topPorts = stats.topDestPorts.sorted { $0.value > $1.value }.prefix(5)
            .map { PortInfo(port: $0.key, packetCount: $0.value) }
    }

    private func recordPpsSample() {
        sampleIndex += 1
        ppsHistory.append(PpsSample(index: sampleIndex, pps: packetsPerSecond))
        if ppsHistory.count > 60 { ppsHistory.removeFirst(ppsHistory.count - 60) }
        if packetsPerSecond > maxPps { maxPps = packetsPerSecond }
    }

    var averagePps: Double {
        guard !ppsHistory.isEmpty else { return 0 }
        return ppsHistory.reduce(0) { $0 + $1.pps } / Double(ppsHistory.count)
    }

    func exportReportCSV(to url: URL) {
        var rows: [[String]] = []
        rows.append(["Section", "Name", "Value", "Extra"])
        rows.append(["Overview", "Packets", "\(totalPackets)", ""])
        rows.append(["Overview", "Bytes", "\(totalBytes)", ""])
        rows.append(["Overview", "Packets/s", String(format: "%.2f", packetsPerSecond), ""])
        rows.append(["Overview", "Duration", captureTime, ""])
        rows.append(["Overview", "Protocols", "\(uniqueProtocols)", ""])
        rows.append(["Overview", "Unique IPs", "\(uniqueIPs)", ""])
        rows.append(["Overview", "Scans", "\(scanCount)", ""])
        rows.append(["Overview", "Bad checksum", "\(badChecksumCount)", ""])
        rows.append(["Overview", "Packet loss", String(format: "%.2f%%", packetLossPercent), "\(droppedPackets) dropped"])

        for p in protocolStats {
            rows.append(["Protocol", p.proto, "\(p.packetCount)", String(format: "%.1f%%", p.percentage)])
        }
        for item in topSourceIPs {
            rows.append(["Top source IP", item.ip, "\(item.packetCount)", ""])
        }
        for item in topDestIPs {
            rows.append(["Top destination IP", item.ip, "\(item.packetCount)", ""])
        }
        for item in topPorts {
            rows.append(["Top port", item.display, "\(item.packetCount)", ""])
        }
        for item in topSniHosts {
            rows.append(["TLS SNI", item.sni, "\(item.connectionCount)", "TLS 0x\(String(item.lastTlsVersion, radix: 16))"])
        }
        for item in topDnsNames {
            rows.append(["DNS name", item.qname, "\(item.queryCount)", "\(item.avgResolveMs)ms avg"])
        }
        for item in connHealth {
            rows.append(["TCP health", "\(item.dstIp):\(item.dstPort)", "\(item.retransmits) retrans", "\(item.avgRttMs)ms RTT"])
        }
        appendInspectionRows(&rows, title: "ARP operation", arpOperations)
        appendInspectionRows(&rows, title: "ARP sender", arpSenders)
        appendInspectionRows(&rows, title: "DHCP message", dhcpMessages)
        appendInspectionRows(&rows, title: "HTTP method", httpMethods)
        appendInspectionRows(&rows, title: "HTTP host", httpHosts)
        appendInspectionRows(&rows, title: "mDNS name", mdnsNames)
        appendInspectionRows(&rows, title: "QUIC endpoint", quicEndpoints)

        let text = rows.map { $0.map(Self.csvEscape).joined(separator: ",") }.joined(separator: "\n") + "\n"
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            LoggerService.shared.log("Statistics CSV exported to \(url.path)")
        } catch {
            LoggerService.shared.logError("Statistics CSV export failed", exception: error.localizedDescription)
        }
    }

    func exportReportJSON(to url: URL) {
        let object: [String: Any] = [
            "overview": [
                "packets": totalPackets,
                "bytes": totalBytes,
                "packetsPerSecond": packetsPerSecond,
                "duration": captureTime,
                "uniqueProtocols": uniqueProtocols,
                "uniqueIPs": uniqueIPs,
                "scans": scanCount,
                "badChecksum": badChecksumCount,
                "packetLossPercent": packetLossPercent,
                "droppedPackets": droppedPackets,
            ],
            "protocols": protocolStats.map {
                ["protocol": $0.proto, "packets": $0.packetCount, "bytes": $0.byteCount, "percentage": $0.percentage]
            },
            "topSourceIPs": topSourceIPs.map { ["ip": $0.ip, "packets": $0.packetCount] },
            "topDestinationIPs": topDestIPs.map { ["ip": $0.ip, "packets": $0.packetCount] },
            "topPorts": topPorts.map { ["port": $0.port, "display": $0.display, "packets": $0.packetCount] },
            "l7": [
                "topSniHosts": topSniHosts.map {
                    ["sni": $0.sni, "connections": $0.connectionCount, "lastTlsVersion": $0.lastTlsVersion]
                },
                "topDnsNames": topDnsNames.map {
                    ["qname": $0.qname, "queries": $0.queryCount, "avgResolveMs": $0.avgResolveMs, "lastQtype": $0.lastQtype]
                },
                "tcpConnectionHealth": connHealth.map {
                    [
                        "destination": "\($0.dstIp):\($0.dstPort)",
                        "avgRttMs": $0.avgRttMs,
                        "retransmits": $0.retransmits,
                        "bytesSent": $0.bytesSent,
                        "bytesRecv": $0.bytesRecv,
                    ]
                },
            ],
            "inspection": [
                "arpOperations": counterObjects(arpOperations),
                "arpSenders": counterObjects(arpSenders),
                "dhcpMessages": counterObjects(dhcpMessages),
                "httpMethods": counterObjects(httpMethods),
                "httpHosts": counterObjects(httpHosts),
                "mdnsNames": counterObjects(mdnsNames),
                "quicEndpoints": counterObjects(quicEndpoints),
            ],
        ]

        do {
            let data = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: url)
            LoggerService.shared.log("Statistics JSON exported to \(url.path)")
        } catch {
            LoggerService.shared.logError("Statistics JSON export failed", exception: error.localizedDescription)
        }
    }

    private func appendInspectionRows(_ rows: inout [[String]], title: String, _ counters: [InspectionCounter]) {
        for item in counters {
            rows.append(["Inspection", title, item.name, "\(item.count)"])
        }
    }

    private func counterObjects(_ counters: [InspectionCounter]) -> [[String: Any]] {
        counters.map { ["name": $0.name, "count": $0.count] }
    }

    private static func csvEscape(_ value: String) -> String {
        guard value.contains(",") || value.contains("\"") || value.contains("\n") else { return value }
        return "\"" + value.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    func clear() {
        NativeStats.clear()
        NativeStats.l7Clear()
        l7Summary = nil
        topSniHosts = []
        topDnsNames = []
        connHealth = []
        arpOperations = []
        arpSenders = []
        dhcpMessages = []
        httpHosts = []
        httpMethods = []
        mdnsNames = []
        quicEndpoints = []
        ppsHistory.removeAll()
        maxPps = 0
        sampleIndex = 0
        droppedPackets = 0
        receivedPackets = 0
        packetLossPercent = 0
        totalPackets = 0
        totalBytes = 0
        packetsPerSecond = 0
        captureTime = "00:00:00"
        uniqueProtocols = 0
        uniqueIPs = 0
        protocolStats = []
        topSourceIPs = []
        topDestIPs = []
        topPorts = []
    }

    private static func hms(_ seconds: Double) -> String {
        let s = Int(seconds)
        return String(format: "%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
    }
}
