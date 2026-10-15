import Foundation

enum TimeFormatType {
    case relative, absolute, delta
}

struct PacketModel: Identifiable, Hashable, Sendable {
    struct TlsClientHello: Hashable, Sendable {
        let tlsVersion: UInt16
        let cipherSuites: [UInt16]
        let extensionCount: Int
        let sni: String
        let alpnProtocols: [String]

        var versionDisplay: String {
            switch tlsVersion {
            case 0x0301: return "TLS 1.0"
            case 0x0302: return "TLS 1.1"
            case 0x0303: return "TLS 1.2"
            case 0x0304: return "TLS 1.3"
            default: return String(format: "TLS 0x%04X", tlsVersion)
            }
        }

        var firstCipherDisplay: String {
            // Skip GREASE (RFC 8701) and SCSV markers; they aren't real ciphers.
            let real = cipherSuites.first { !Self.isPseudoCipher($0) }
            guard let first = real ?? cipherSuites.first else { return "-" }
            return Self.cipherName(for: first)
        }

        // 0x00FF, 0x5600 = SCSV; GREASE = 0x0A0A…0xFAFA (equal bytes, low nibble A).
        private static func isPseudoCipher(_ suite: UInt16) -> Bool {
            if suite == 0x00FF || suite == 0x5600 { return true }
            return (suite >> 8) == (suite & 0x00FF) && (suite & 0x000F) == 0x0A
        }

        var alpnDisplay: String {
            let joined = alpnProtocols.joined(separator: ", ")
            return joined.isEmpty ? "-" : joined
        }

        private static func cipherName(for suite: UInt16) -> String {
            switch suite {
            case 0x1301: return "TLS_AES_128_GCM_SHA256"
            case 0x1302: return "TLS_AES_256_GCM_SHA384"
            case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256"
            case 0x009C: return "TLS_RSA_WITH_AES_128_GCM_SHA256"
            case 0x009D: return "TLS_RSA_WITH_AES_256_GCM_SHA384"
            case 0xC02F: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            case 0xC030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
            case 0xCCA8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
            case 0xC02B: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
            case 0xC02C: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
            default: return String(format: "0x%04X", suite)
            }
        }
    }

    struct L3L4Meta: Hashable, Sendable {
        var isIP = false
        var isIPv6 = false
        var ttl: UInt8 = 0
        var ipProto: UInt8 = 0
        var checksumValidated = false
        var checksumOK = true
        var dontFragment = false
        var moreFragments = false
        var fragmentOffset: UInt16 = 0
        var tcpParsed = false
        var tcpFlags: UInt8 = 0
        var tcpWindow: UInt16 = 0
        var tcpSeq: UInt32 = 0
        var tcpAck: UInt32 = 0
        var dscp: UInt8 = 0
        var ecn: UInt8 = 0
        var vlanId: Int = -1
        var hasIcmp = false
        var icmpType: UInt8 = 0
        var icmpCode: UInt8 = 0
    }

    // Parsed once at creation so the passive L7 parser runs once per packet.
    struct DnsInfo: Hashable, Sendable {
        enum Kind: Hashable, Sendable { case query, answer }
        let kind: Kind
        let name: String
        let qtype: UInt16
        let txid: UInt16
        let addresses: [String]
        var records: [PassiveL7Parser.DnsResourceRecord] = []
    }

    @MainActor static var currentTimeFormat: TimeFormatType = .relative
    @MainActor static var captureStartTime: Date = .now

    // Read on background parse threads; writes are rare (settings edits).
    nonisolated(unsafe) static var portLabelOverrides: [Int32: String] = [:]

    static func applyPortLabelOverrides(_ raw: [String: String]) {
        var map: [Int32: String] = [:]
        for (key, value) in raw {
            let label = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if let port = Int32(key.trimmingCharacters(in: .whitespaces)), port > 0, !label.isEmpty {
                map[port] = label
            }
        }
        portLabelOverrides = map
    }

    let number: Int
    let packetId: Int32
    let sourcePort: Int32
    let destPort: Int32
    let proto: String
    let sourceIp: String
    let destIp: String
    let sourceMac: String
    let destMac: String
    let hostName: String
    let tlsClientHello: TlsClientHello?
    let captureTime: Date
    let rawData: Data
    let captureLen: UInt32
    let originalLen: UInt32
    var meta: L3L4Meta = L3L4Meta()
    var dns: DnsInfo? = nil
    var arp: PassiveL7Parser.ArpDetails? = nil
    var dhcp: PassiveL7Parser.DhcpDetails? = nil
    var httpRequest: PassiveL7Parser.HttpRequestDetails? = nil
    var isMdns = false
    var isQuic = false
    // Native L7 dissector summary; empty when no protocol was identified.
    var l7Info = ""
    // SnifferLinkType (0=Ethernet,1=raw,2=NULL/lo0,3=SLL,4=SLL2) for stream reassembly.
    var linkTypeCode: Int32 = 0

    var id: Int { number }

    var numberDisplay: String {
        "\(number)"
    }

    @MainActor
    var timeDisplay: String {
        switch Self.currentTimeFormat {
        case .absolute, .relative:
            return Self.absoluteFormatter.string(from: captureTime)
        case .delta:
            let dt = captureTime.timeIntervalSince(Self.captureStartTime)
            return String(format: "+%.3fs", dt)
        }
    }

    var captureTimestampDisplay: String {
        Self.absoluteFormatter.string(from: captureTime)
    }

    var info: String {
        let host = hostName.isEmpty ? "Unknown" : hostName
        let base = "Host: \(host) | \(sourcePort) → \(destPort) | ID: \(packetId)"
        return l7Info.isEmpty ? base : "\(l7Info) | \(base)"
    }

    var sourceEndpoint: String {
        endpoint(ip: sourceIp, port: sourcePort)
    }

    var destinationEndpoint: String {
        endpoint(ip: destIp, port: destPort)
    }

    var hostDisplay: String {
        hostName.isEmpty ? "-" : hostName
    }

    var sourceMacDisplay: String {
        sourceMac.isEmpty ? "-" : sourceMac
    }

    var destMacDisplay: String {
        destMac.isEmpty ? "-" : destMac
    }

    var ttlDisplay: String { meta.isIP ? "\(meta.ttl)" : "—" }

    var checksumDisplay: String {
        guard meta.checksumValidated else { return "—" }
        return meta.checksumOK ? "OK" : "bad"
    }

    var windowDisplay: String { meta.tcpParsed ? "\(meta.tcpWindow)" : "—" }

    var fragmentDisplay: String {
        guard meta.isIP, !meta.isIPv6 else { return "—" }
        if meta.dontFragment { return "DF" }
        if meta.moreFragments { return "MF@\(meta.fragmentOffset)" }
        if meta.fragmentOffset > 0 { return "off \(meta.fragmentOffset)" }
        return "none"
    }

    var tcpFlagsDisplay: String {
        guard meta.tcpParsed else { return "—" }
        let f = meta.tcpFlags
        var parts: [String] = []
        if f & 0x02 != 0 { parts.append("SYN") }
        if f & 0x10 != 0 { parts.append("ACK") }
        if f & 0x01 != 0 { parts.append("FIN") }
        if f & 0x04 != 0 { parts.append("RST") }
        if f & 0x08 != 0 { parts.append("PSH") }
        if f & 0x20 != 0 { parts.append("URG") }
        if f & 0x40 != 0 { parts.append("ECE") }
        if f & 0x80 != 0 { parts.append("CWR") }
        return parts.isEmpty ? "none" : parts.joined(separator: " ")
    }

    // Flag combos real stacks never send: NULL/Xmas/SYN+FIN scans or 4+ flags.
    var isScan: Bool {
        guard meta.tcpParsed else { return false }
        let f = meta.tcpFlags
        let fin: UInt8 = 0x01, syn: UInt8 = 0x02, psh: UInt8 = 0x08, urg: UInt8 = 0x20
        if f == 0 { return true }
        if (f & (fin | psh | urg)) == (fin | psh | urg) { return true }
        if (f & (syn | fin)) == (syn | fin) { return true }
        return f.nonzeroBitCount >= 4
    }

    var scanReason: String {
        guard meta.tcpParsed else { return "—" }
        let f = meta.tcpFlags
        let fin: UInt8 = 0x01, syn: UInt8 = 0x02, psh: UInt8 = 0x08, urg: UInt8 = 0x20
        if f == 0 { return "NULL scan" }
        if (f & (fin | psh | urg)) == (fin | psh | urg) { return "Xmas scan" }
        if (f & (syn | fin)) == (syn | fin) { return "SYN+FIN" }
        if f.nonzeroBitCount >= 4 { return "crafted (\(f.nonzeroBitCount) flags)" }
        return "—"
    }

    var vlanDisplay: String { meta.vlanId >= 0 ? "\(meta.vlanId)" : "—" }

    var tcpSeqDisplay: String { meta.tcpParsed ? "\(meta.tcpSeq)" : "—" }
    var tcpAckDisplay: String { meta.tcpParsed ? "\(meta.tcpAck)" : "—" }

    var dscpDisplay: String {
        guard meta.isIP else { return "—" }
        let name: String
        switch meta.dscp {
        case 0:  name = "CS0"
        case 8:  name = "CS1"
        case 10, 12, 14: name = "AF1"
        case 16: name = "CS2"
        case 18, 20, 22: name = "AF2"
        case 24: name = "CS3"
        case 26, 28, 30: name = "AF3"
        case 32: name = "CS4"
        case 34, 36, 38: name = "AF4"
        case 40: name = "CS5"
        case 46: name = "EF"
        case 48: name = "CS6"
        case 56: name = "CS7"
        default: name = "DSCP \(meta.dscp)"
        }
        return name
    }

    var ecnDisplay: String {
        guard meta.isIP else { return "—" }
        switch meta.ecn {
        case 0:  return "Not-ECT"
        case 1:  return "ECT(1)"
        case 2:  return "ECT(0)"
        default: return "CE"
        }
    }

    var qosDisplay: String {
        guard meta.isIP else { return "—" }
        return meta.ecn == 0 ? dscpDisplay : "\(dscpDisplay) · \(ecnDisplay)"
    }

    var icmpDisplay: String {
        guard meta.hasIcmp else { return "—" }
        return "\(meta.icmpType)/\(meta.icmpCode)"
    }

    var icmpDetail: String {
        guard meta.hasIcmp else { return "—" }
        return "\(icmpTypeName) (type \(meta.icmpType), code \(meta.icmpCode))"
    }

    var icmpTypeName: String {
        guard meta.hasIcmp else { return "—" }
        if meta.isIPv6 {
            switch meta.icmpType {
            case 1: return "Destination Unreachable"
            case 2: return "Packet Too Big"
            case 3: return "Time Exceeded"
            case 4: return "Parameter Problem"
            case 128: return "Echo Request"
            case 129: return "Echo Reply"
            case 133: return "Router Solicitation"
            case 134: return "Router Advertisement"
            case 135: return "Neighbor Solicitation"
            case 136: return "Neighbor Advertisement"
            default: return "ICMPv6 type \(meta.icmpType)"
            }
        }
        switch meta.icmpType {
        case 0: return "Echo Reply"
        case 3: return "Destination Unreachable"
        case 5: return "Redirect"
        case 8: return "Echo Request"
        case 11: return "Time Exceeded"
        case 12: return "Parameter Problem"
        case 13: return "Timestamp Request"
        case 14: return "Timestamp Reply"
        default: return "ICMP type \(meta.icmpType)"
        }
    }

    var tcpStreamKey: String {
        guard meta.tcpParsed else { return "—" }
        let lhs = sourceEndpoint
        let rhs = destinationEndpoint
        return lhs <= rhs ? "\(lhs) ↔ \(rhs)" : "\(rhs) ↔ \(lhs)"
    }

    var isTruncated: Bool { captureLen > 0 && UInt32(captureLen) < originalLen }

    var tlsVersionDisplay: String {
        tlsClientHello?.versionDisplay ?? "-"
    }

    var tlsCipherCountDisplay: String {
        guard let tlsClientHello else { return "-" }
        return "\(tlsClientHello.cipherSuites.count)"
    }

    var tlsFirstCipherDisplay: String {
        tlsClientHello?.firstCipherDisplay ?? "-"
    }

    var tlsExtensionCountDisplay: String {
        guard let tlsClientHello else { return "-" }
        return "\(tlsClientHello.extensionCount)"
    }

    var tlsSniDisplay: String {
        guard let tlsClientHello, !tlsClientHello.sni.isEmpty else { return "-" }
        return tlsClientHello.sni
    }

    var tlsAlpnDisplay: String {
        tlsClientHello?.alpnDisplay ?? "-"
    }

    var tlsFingerprintDisplay: String {
        guard let tls = tlsClientHello else { return "-" }
        let raw = "\(tls.tlsVersion)|"
            + tls.cipherSuites.map(String.init).joined(separator: ",")
            + "|\(tls.extensionCount)|"
            + tls.alpnProtocols.joined(separator: ",")
        return String(format: "%08x", Self.fnv1a(raw))
    }

    private static func fnv1a(_ s: String) -> UInt32 {
        var hash: UInt32 = 2166136261
        for byte in s.utf8 {
            hash ^= UInt32(byte)
            hash = hash &* 16777619
        }
        return hash
    }

    private static let absoluteFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    static func from(_ s: SnapshotWire.Snapshot, number: Int) -> PacketModel {
        let captureTime: Date
        if s.timestampSec > 0 {
            captureTime = Date(timeIntervalSince1970:
                TimeInterval(s.timestampSec) + TimeInterval(s.timestampUsec) / 1_000_000.0)
        } else {
            captureTime = .now
        }

        let parsed = PacketParser.parse(s.rawData)
        let observation = PassiveL7Parser.parse(s.rawData)
        return PacketModel(
            number: number,
            packetId: s.id,
            sourcePort: s.sourcePort,
            destPort: s.destPort,
            proto: protocolName(native: s.proto,
                                observation: observation,
                                sourcePort: s.sourcePort,
                                destPort: s.destPort),
            sourceIp: s.sourceIp,
            destIp: s.destIp,
            sourceMac: s.sourceMac,
            destMac: s.destMac,
            hostName: s.hostName,
            tlsClientHello: PacketModel.tlsClientHello(from: observation),
            captureTime: captureTime,
            rawData: s.rawData,
            captureLen: s.captureLen,
            originalLen: s.originalLen,
            meta: metadata(from: parsed),
            dns: dnsInfo(from: observation),
            arp: observation.arp,
            dhcp: observation.dhcp,
            httpRequest: observation.httpRequest,
            isMdns: observation.isMdns,
            isQuic: observation.isQuic
        )
    }

    static func from(rawFrame raw: Data, number: Int,
                     linkType: PacketParser.LinkType = .ethernet) -> PacketModel {
        let p = PacketParser.parse(raw, linkType: linkType)
        let l7 = PassiveL7Parser.parse(raw, linkType: linkType)
        let proto = protocolName(native: p.proto,
                                 observation: l7,
                                 sourcePort: p.sourcePort,
                                 destPort: p.destPort,
                                 l7Proto: p.l7Proto)
        return PacketModel(
            number: number,
            packetId: Int32(truncatingIfNeeded: number),
            sourcePort: p.sourcePort,
            destPort: p.destPort,
            proto: proto,
            sourceIp: p.sourceIp,
            destIp: p.destIp,
            sourceMac: p.sourceMac,
            destMac: p.destMac,
            // Native L7 host wins; PassiveL7Parser is only a fallback.
            hostName: p.host.isEmpty ? hostName(from: l7) : p.host,
            tlsClientHello: tlsClientHello(from: l7),
            captureTime: .now,
            rawData: raw,
            captureLen: UInt32(raw.count),
            originalLen: UInt32(raw.count),
            meta: metadata(from: p),
            dns: dnsInfo(from: l7),
            arp: l7.arp,
            dhcp: l7.dhcp,
            httpRequest: l7.httpRequest,
            isMdns: l7.isMdns,
            isQuic: l7.isQuic,
            l7Info: p.l7Info,
            linkTypeCode: Self.linkTypeCode(linkType)
        )
    }

    static func linkTypeCode(_ lt: PacketParser.LinkType) -> Int32 {
        switch lt {
        case .ethernet: 0
        case .raw:      1
        case .null:     2
        case .sll:      3
        case .sll2:     4
        }
    }

    static func from(rawFrame raw: Data, number: Int, captureTime: Date,
                     captureLen: UInt32, originalLen: UInt32,
                     linkType: PacketParser.LinkType = .ethernet) -> PacketModel {
        var packet = from(rawFrame: raw, number: number, linkType: linkType)
        packet = PacketModel(
            number: packet.number,
            packetId: packet.packetId,
            sourcePort: packet.sourcePort,
            destPort: packet.destPort,
            proto: packet.proto,
            sourceIp: packet.sourceIp,
            destIp: packet.destIp,
            sourceMac: packet.sourceMac,
            destMac: packet.destMac,
            hostName: packet.hostName,
            tlsClientHello: packet.tlsClientHello,
            captureTime: captureTime,
            rawData: packet.rawData,
            captureLen: captureLen,
            originalLen: originalLen,
            meta: packet.meta,
            dns: packet.dns,
            arp: packet.arp,
            dhcp: packet.dhcp,
            httpRequest: packet.httpRequest,
            isMdns: packet.isMdns,
            isQuic: packet.isQuic,
            l7Info: packet.l7Info,
            linkTypeCode: packet.linkTypeCode
        )
        return packet
    }

    static func metadata(from p: PacketParser.Parsed) -> L3L4Meta {
        L3L4Meta(
            isIP: p.isIP,
            isIPv6: p.isIPv6,
            ttl: p.ttl,
            ipProto: p.ipProto,
            checksumValidated: p.checksumValidated,
            checksumOK: p.checksumOK,
            dontFragment: p.dontFragment,
            moreFragments: p.moreFragments,
            fragmentOffset: p.fragmentOffset,
            tcpParsed: p.tcpParsed,
            tcpFlags: p.tcpFlags,
            tcpWindow: p.tcpWindow,
            tcpSeq: p.tcpSeq,
            tcpAck: p.tcpAck,
            dscp: p.dscp,
            ecn: p.ecn,
            vlanId: p.vlanId,
            hasIcmp: p.hasIcmp,
            icmpType: p.icmpType,
            icmpCode: p.icmpCode
        )
    }

    static func protocolName(native: String,
                             observation: PassiveL7Parser.Observation,
                             sourcePort: Int32,
                             destPort: Int32,
                             l7Proto: String = "") -> String {
        // Native dissector's protocol identification takes precedence.
        if !l7Proto.isEmpty { return l7Proto }
        if observation.arp != nil { return "ARP" }
        if observation.dhcp != nil { return "DHCP" }
        if observation.httpRequest != nil { return "HTTP" }
        if observation.isMdns { return "MDNS" }
        if observation.isQuic { return "QUIC" }
        if observation.dnsQuery != nil || observation.dnsAnswer != nil { return "DNS" }
        if observation.tlsClientHello != nil { return "TLS" }
        if let service = serviceName(sourcePort: sourcePort, destPort: destPort) { return service }
        return native
    }

    static func serviceName(sourcePort: Int32, destPort: Int32) -> String? {
        if let service = serviceName(port: destPort) { return service }
        return serviceName(port: sourcePort)
    }

    static func serviceName(port: Int32) -> String? {
        guard port > 0 else { return nil }
        if let custom = portLabelOverrides[port] { return custom }
        switch port {
        case 7: return "Echo"
        case 9: return "Discard"
        case 13: return "Daytime"
        case 17: return "QOTD"
        case 19: return "Chargen"
        case 20, 21: return "FTP"
        case 22: return "SSH"
        case 23: return "Telnet"
        case 25: return "SMTP"
        case 37: return "Time"
        case 43: return "WHOIS"
        case 49: return "TACACS"
        case 53: return "DNS"
        case 69: return "TFTP"
        case 67, 68: return "DHCP"
        case 88: return "Kerberos"
        case 80, 8080, 8000, 8888: return "HTTP"
        case 111: return "RPCBind"
        case 110: return "POP3"
        case 123: return "NTP"
        case 135: return "MSRPC"
        case 137, 138, 139: return "NetBIOS"
        case 143: return "IMAP"
        case 179: return "BGP"
        case 161: return "SNMP"
        case 389: return "LDAP"
        case 427: return "SLP"
        case 443, 5001, 8443: return "HTTPS"
        case 445: return "SMB"
        case 465, 587: return "SMTPS"
        case 464: return "Kerberos"
        case 500: return "IKE"
        case 512, 513, 514: return "RServices"
        case 515: return "LPD"
        case 520: return "RIP"
        case 546, 547: return "DHCPv6"
        case 554: return "RTSP"
        case 563: return "NNTPS"
        case 5683, 5684: return "CoAP"
        case 593: return "HTTP RPC"
        case 631: return "IPP"
        case 636: return "LDAPS"
        case 873: return "Rsync"
        case 993: return "IMAPS"
        case 995: return "POP3S"
        case 1080: return "SOCKS"
        case 1194: return "OpenVPN"
        case 1234: return "VLC"
        case 1433: return "SQL Server"
        case 1521: return "Oracle"
        case 1701: return "L2TP"
        case 1723: return "PPTP"
        case 1812, 1813: return "RADIUS"
        case 1883, 8883: return "MQTT"
        case 2049: return "NFS"
        case 2181: return "ZooKeeper"
        case 2222: return "SSH"
        case 2375, 2376: return "Docker"
        case 2380: return "etcd"
        case 2404: return "IEC 104"
        case 2483, 2484: return "Oracle"
        case 2525: return "SMTP"
        case 29418: return "Gerrit"
        case 3000: return "Grafana"
        case 3128: return "Squid"
        case 3306: return "MySQL"
        case 3389: return "RDP"
        case 3690: return "Subversion"
        case 4369: return "EPMD"
        case 4500: return "IPsec NAT-T"
        case 4789: return "VXLAN"
        case 5003: return "FileMaker"
        case 5000: return "HTTP"
        case 5060, 5061: return "SIP"
        case 5222, 5269: return "XMPP"
        case 5432: return "PostgreSQL"
        case 5353: return "MDNS"
        case 5355: return "LLMNR"
        case 5601: return "Kibana"
        case 5672, 15672: return "RabbitMQ"
        case 5900, 5901: return "VNC"
        case 5984: return "CouchDB"
        case 5985, 5986: return "WinRM"
        case 6000: return "X11"
        case 6443: return "Kubernetes"
        case 6379: return "Redis"
        case 7000, 7001, 7199, 9042, 9160: return "Cassandra"
        case 8008, 8081, 8088, 8090: return "HTTP"
        case 8086: return "InfluxDB"
        case 8123: return "ClickHouse"
        case 8200: return "Vault"
        case 8500, 8600: return "Consul"
        case 8761: return "Eureka"
        case 9090: return "Prometheus"
        case 9092, 9093, 29092: return "Kafka"
        case 9100: return "Node Exporter"
        case 9418: return "Git"
        case 9200, 9300: return "Elasticsearch"
        case 10250, 10255: return "Kubelet"
        case 11211: return "Memcached"
        case 11371: return "HKP"
        case 20000: return "Webmin"
        case 27017, 27018, 27019, 27020, 27021, 27022: return "MongoDB"
        case 50051: return "gRPC"
        default: return nil
        }
    }

    static func hostName(from l7: PassiveL7Parser.Observation) -> String {
        if let host = l7.tlsClientHello?.host, !host.isEmpty { return host }
        if let name = l7.dnsQuery?.name, !name.isEmpty { return name }
        if let name = l7.dnsAnswer?.name, !name.isEmpty { return name }
        return ""
    }

    static func tlsClientHello(from l7: PassiveL7Parser.Observation) -> TlsClientHello? {
        guard let tls = l7.tlsClientHello else { return nil }
        return TlsClientHello(
            tlsVersion: tls.tlsVersion,
            cipherSuites: tls.cipherSuites,
            extensionCount: tls.extensionCount,
            sni: tls.host,
            alpnProtocols: tls.alpnProtocols
        )
    }

    static func dnsInfo(from l7: PassiveL7Parser.Observation) -> DnsInfo? {
        if let q = l7.dnsQuery {
            return DnsInfo(kind: .query, name: q.name, qtype: q.qtype, txid: q.txid, addresses: [])
        }
        if let a = l7.dnsAnswer {
            return DnsInfo(kind: .answer, name: a.name, qtype: a.qtype, txid: a.txid,
                           addresses: a.addresses, records: a.records)
        }
        return nil
    }

    static func inferredHostName(from rawData: Data,
                                 linkType: PacketParser.LinkType = .ethernet) -> String {
        hostName(from: PassiveL7Parser.parse(rawData, linkType: linkType))
    }

    static func tlsClientHello(from rawData: Data,
                               linkType: PacketParser.LinkType = .ethernet) -> TlsClientHello? {
        tlsClientHello(from: PassiveL7Parser.parse(rawData, linkType: linkType))
    }

    func withProto(_ newProto: String) -> PacketModel {
        var p = self
        p = PacketModel(
            number: number, packetId: packetId, sourcePort: sourcePort, destPort: destPort,
            proto: newProto, sourceIp: sourceIp, destIp: destIp, sourceMac: sourceMac,
            destMac: destMac, hostName: hostName, tlsClientHello: tlsClientHello,
            captureTime: captureTime, rawData: rawData, captureLen: captureLen,
            originalLen: originalLen, meta: meta, dns: dns, arp: arp, dhcp: dhcp,
            httpRequest: httpRequest, isMdns: isMdns, isQuic: isQuic, l7Info: l7Info,
            linkTypeCode: linkTypeCode)
        return p
    }

    func withHostName(_ hostName: String) -> PacketModel {
        PacketModel(
            number: number,
            packetId: packetId,
            sourcePort: sourcePort,
            destPort: destPort,
            proto: proto,
            sourceIp: sourceIp,
            destIp: destIp,
            sourceMac: sourceMac,
            destMac: destMac,
            hostName: hostName,
            tlsClientHello: tlsClientHello,
            captureTime: captureTime,
            rawData: rawData,
            captureLen: captureLen,
            originalLen: originalLen,
            meta: meta,
            dns: dns,
            arp: arp,
            dhcp: dhcp,
            httpRequest: httpRequest,
            isMdns: isMdns,
            isQuic: isQuic,
            l7Info: l7Info,
            linkTypeCode: linkTypeCode
        )
    }

    private func endpoint(ip: String, port: Int32) -> String {
        let safeIp = ip.isEmpty ? "-" : ip
        return port > 0 ? "\(safeIp):\(port)" : safeIp
    }
}

struct NetworkDevice: Identifiable, Hashable, Sendable {
    let index: Int
    let name: String
    let description: String

    var id: Int { index }
    var displayName: String { description.isEmpty ? name : description }
}
