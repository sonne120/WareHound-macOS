import Foundation

struct ProtocolStats: Sendable {
    var proto: String = ""
    var packetCount: Int64 = 0
    var byteCount: Int64 = 0
    var percentage: Double = 0
}

struct TimelinePoint: Sendable {
    var time: Date
    var packetCount: Int64
    var byteCount: Int64
}

struct PassiveL7Summary: Sendable {
    var tlsClientHellos: UInt64 = 0
    var dnsQueries: UInt64 = 0
    var dnsAnswers: UInt64 = 0
    var distinctSniHosts: UInt64 = 0
    var distinctDnsNames: UInt64 = 0
}

struct PassiveSniHost: Sendable {
    var host: String
    var connectionCount: UInt64
    var lastTlsVersion: UInt16
}

struct PassiveDnsName: Sendable {
    var name: String
    var queryCount: UInt64
    var lastQtype: UInt16
    var answerCount: UInt64 = 0
    var resolvedAddresses: [String] = []
    var resolveSumMs: UInt64 = 0
    var resolveSamples: UInt64 = 0

    var avgResolveMs: UInt32 {
        resolveSamples > 0 ? UInt32(resolveSumMs / resolveSamples) : 0
    }

    var observations: UInt64 { queryCount + answerCount }
}

/// Passive per-connection TCP health; RTT = handshake time, retransmits ≈ seq regression.
struct PassiveConnHealth: Sendable {
    var dstIp: String
    var dstPort: Int32
    var avgRttMs: UInt32
    var retransmits: UInt32
    var bytesSent: UInt64 // client -> server
    var bytesRecv: UInt64 // server -> client

    var activity: UInt64 { bytesSent + bytesRecv }
}

struct InspectionCounter: Identifiable, Sendable {
    var name: String
    var count: Int64
    var id: String { name }
}

struct CaptureStatistics: Sendable {
    var totalPackets: Int64 = 0
    var totalBytes: Int64 = 0
    var captureStartTime: Date = .now
    var captureEndTime: Date = .now

    var protocolBreakdown: [String: ProtocolStats] = [:]
    var topSourceIPs: [String: Int64] = [:]
    var topDestIPs: [String: Int64] = [:]
    var topSourcePorts: [Int32: Int64] = [:]
    var topDestPorts: [Int32: Int64] = [:]
    var packetsTimeline: [TimelinePoint] = []
    var topSniHosts: [String: PassiveSniHost] = [:]
    var topDnsNames: [String: PassiveDnsName] = [:]
    var arpOperations: [String: Int64] = [:]
    var arpSenders: [String: Int64] = [:]
    var dhcpMessages: [String: Int64] = [:]
    var httpHosts: [String: Int64] = [:]
    var httpMethods: [String: Int64] = [:]
    var mdnsNames: [String: Int64] = [:]
    var quicEndpoints: [String: Int64] = [:]

    private var pendingDnsQueries: [UInt16: Date] = [:]
    private static let pendingDnsQueryLimit = 4096

    // Keyed by "serverIp:serverPort" (the SYN's destination).
    private struct ConnAgg: Sendable {
        var dstPort: Int32 = 0
        var rttSumMs: UInt64 = 0
        var rttSamples: UInt64 = 0
        var retransmits: UInt32 = 0
        var bytesSent: UInt64 = 0 // client -> server
        var bytesRecv: UInt64 = 0 // server -> client
        var maxSeqToServer: UInt32?
        var maxSeqToClient: UInt32?
    }
    private var conns: [String: ConnAgg] = [:]
    private var pendingSyns: [String: Date] = [:]
    private static let connLimit = 4096

    var duration: TimeInterval { captureEndTime.timeIntervalSince(captureStartTime) }
    var packetsPerSecond: Double { duration > 0 ? Double(totalPackets) / duration : 0 }
    var bytesPerSecond: Double { duration > 0 ? Double(totalBytes) / duration : 0 }

    var l7Summary: PassiveL7Summary {
        PassiveL7Summary(
            tlsClientHellos: UInt64(topSniHosts.values.reduce(0) { $0 + Int64($1.connectionCount) }),
            dnsQueries: UInt64(topDnsNames.values.reduce(0) { $0 + Int64($1.queryCount) }),
            dnsAnswers: UInt64(topDnsNames.values.reduce(0) { $0 + Int64($1.answerCount) }),
            distinctSniHosts: UInt64(topSniHosts.count),
            distinctDnsNames: UInt64(topDnsNames.count)
        )
    }

    func topSniHostsList(limit: Int = 10) -> [PassiveSniHost] {
        topSniHosts.values
            .sorted {
                if $0.connectionCount == $1.connectionCount {
                    return $0.host < $1.host
                }
                return $0.connectionCount > $1.connectionCount
            }
            .prefix(limit)
            .map { $0 }
    }

    func topDnsNamesList(limit: Int = 10) -> [PassiveDnsName] {
        topDnsNames.values
            .sorted {
                if $0.observations == $1.observations {
                    return $0.name < $1.name
                }
                return $0.observations > $1.observations
            }
            .prefix(limit)
            .map { $0 }
    }

    /// Worst connections first: retransmits, then total bytes.
    func topConnHealthList(limit: Int = 10) -> [PassiveConnHealth] {
        conns.map { key, agg -> PassiveConnHealth in
            let ip = key.lastIndex(of: ":").map { String(key[..<$0]) } ?? key
            return PassiveConnHealth(
                dstIp: ip,
                dstPort: agg.dstPort,
                avgRttMs: agg.rttSamples > 0 ? UInt32(agg.rttSumMs / agg.rttSamples) : 0,
                retransmits: agg.retransmits,
                bytesSent: agg.bytesSent,
                bytesRecv: agg.bytesRecv
            )
        }
        .sorted {
            if $0.retransmits != $1.retransmits { return $0.retransmits > $1.retransmits }
            return $0.activity > $1.activity
        }
        .prefix(limit)
        .map { $0 }
    }

    func topInspectionCounters(_ source: [String: Int64], limit: Int = 8) -> [InspectionCounter] {
        source
            .sorted {
                if $0.value == $1.value { return $0.key < $1.key }
                return $0.value > $1.value
            }
            .prefix(limit)
            .map { InspectionCounter(name: $0.key, count: $0.value) }
    }

    mutating func accumulate(_ packet: PacketModel) {
        totalPackets += 1
        totalBytes += Int64(packet.originalLen)
        captureEndTime = packet.captureTime

        var stats = protocolBreakdown[packet.proto] ?? ProtocolStats(proto: packet.proto)
        stats.packetCount += 1
        stats.byteCount += Int64(packet.originalLen)
        protocolBreakdown[packet.proto] = stats

        topSourceIPs[packet.sourceIp, default: 0] += 1
        topDestIPs[packet.destIp, default: 0] += 1
        topSourcePorts[packet.sourcePort, default: 0] += 1
        topDestPorts[packet.destPort, default: 0] += 1

        if let tls = packet.tlsClientHello, !tls.sni.isEmpty {
            var host = topSniHosts[tls.sni] ?? PassiveSniHost(host: tls.sni, connectionCount: 0, lastTlsVersion: tls.tlsVersion)
            host.connectionCount += 1
            host.lastTlsVersion = tls.tlsVersion
            topSniHosts[tls.sni] = host
        }
        if let dns = packet.dns, dns.kind == .query, !dns.name.isEmpty {
            var name = topDnsNames[dns.name] ?? PassiveDnsName(name: dns.name, queryCount: 0, lastQtype: dns.qtype)
            name.queryCount += 1
            name.lastQtype = dns.qtype
            topDnsNames[dns.name] = name
            if pendingDnsQueries.count < Self.pendingDnsQueryLimit {
                pendingDnsQueries[dns.txid] = packet.captureTime
            }
        }
        if let dns = packet.dns, dns.kind == .answer, !dns.name.isEmpty {
            var name = topDnsNames[dns.name] ?? PassiveDnsName(name: dns.name, queryCount: 0, lastQtype: dns.qtype)
            name.answerCount += 1
            name.lastQtype = dns.qtype
            if name.resolvedAddresses.isEmpty { name.resolvedAddresses = dns.addresses }
            if let asked = pendingDnsQueries.removeValue(forKey: dns.txid) {
                let ms = max(0, packet.captureTime.timeIntervalSince(asked) * 1000)
                name.resolveSumMs += UInt64(ms)
                name.resolveSamples += 1
            }
            topDnsNames[dns.name] = name
        }

        if let arp = packet.arp {
            arpOperations[arp.operationName, default: 0] += 1
            let sender = arp.senderIp.isEmpty ? arp.senderMac : "\(arp.senderIp) / \(arp.senderMac)"
            if !sender.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                arpSenders[sender, default: 0] += 1
            }
        }
        if let dhcp = packet.dhcp {
            dhcpMessages[dhcp.messageName, default: 0] += 1
        }
        if let http = packet.httpRequest {
            httpMethods[http.method, default: 0] += 1
            if !http.host.isEmpty {
                httpHosts[http.host, default: 0] += 1
            }
        }
        if packet.isMdns, let dns = packet.dns, !dns.name.isEmpty {
            mdnsNames[dns.name, default: 0] += 1
        }
        if packet.isQuic {
            let endpoint = packet.destinationEndpoint.isEmpty ? packet.sourceEndpoint : packet.destinationEndpoint
            quicEndpoints[endpoint, default: 0] += 1
        }

        accumulateConnHealth(packet)
    }

    private mutating func accumulateConnHealth(_ packet: PacketModel) {
        guard packet.meta.tcpParsed else { return }

        let synFlag: UInt8 = 0x02, ackFlag: UInt8 = 0x10
        let isSyn = packet.meta.tcpFlags & synFlag != 0
        let isAck = packet.meta.tcpFlags & ackFlag != 0
        let seq = packet.meta.tcpSeq

        // Bare SYN is client -> server; SYN-ACK is server -> client.
        if isSyn && !isAck {
            let key = "\(packet.destIp):\(packet.destPort)"
            if conns[key] == nil && conns.count < Self.connLimit {
                conns[key] = ConnAgg(dstPort: packet.destPort)
            }
            if pendingSyns.count < Self.connLimit { pendingSyns[key] = packet.captureTime }
        } else if isSyn && isAck {
            let key = "\(packet.sourceIp):\(packet.sourcePort)"
            if conns[key] == nil && conns.count < Self.connLimit {
                conns[key] = ConnAgg(dstPort: packet.sourcePort)
            }
            if let asked = pendingSyns.removeValue(forKey: key), var agg = conns[key] {
                let ms = max(0, packet.captureTime.timeIntervalSince(asked) * 1000)
                agg.rttSumMs += UInt64(ms)
                agg.rttSamples += 1
                conns[key] = agg
            }
        }

        // Seq regression within a direction ≈ retransmission.
        let toServerKey = "\(packet.destIp):\(packet.destPort)"
        let fromServerKey = "\(packet.sourceIp):\(packet.sourcePort)"
        if var agg = conns[toServerKey] {
            agg.bytesSent += UInt64(packet.originalLen)
            if let mx = agg.maxSeqToServer, seq < mx { agg.retransmits += 1 }
            agg.maxSeqToServer = max(agg.maxSeqToServer ?? 0, seq)
            conns[toServerKey] = agg
        } else if var agg = conns[fromServerKey] {
            agg.bytesRecv += UInt64(packet.originalLen)
            if let mx = agg.maxSeqToClient, seq < mx { agg.retransmits += 1 }
            agg.maxSeqToClient = max(agg.maxSeqToClient ?? 0, seq)
            conns[fromServerKey] = agg
        }
    }
}
