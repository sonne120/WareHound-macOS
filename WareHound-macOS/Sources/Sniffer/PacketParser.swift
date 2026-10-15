import Foundation
import CSniffer

enum PacketParser {

    enum LinkType { case ethernet, raw, null, sll, sll2 }

    struct Parsed {
        var proto: String = "Unknown"
        var sourceIp = ""
        var destIp = ""
        var sourceMac = ""
        var destMac = ""
        var sourcePort: Int32 = 0
        var destPort: Int32 = 0

        var isIP = false
        var isIPv6 = false
        var ttl: UInt8 = 0                 // IPv4 TTL / IPv6 hop limit
        var ipProto: UInt8 = 0
        var checksumValidated = false      // IPv4 only (IPv6 has no header checksum)
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
        var vlanId: Int = -1               // -1 if untagged
        var hasIcmp = false
        var icmpType: UInt8 = 0
        var icmpCode: UInt8 = 0

        var l7Proto = ""
        var l7Info = ""
        var host = ""
    }

    static func parse(_ data: Data, linkType: LinkType = .ethernet) -> Parsed {
        var out = SnifferParsedPacket()
        let lt: Int32
        switch linkType {
        case .raw:  lt = Int32(SNIFFER_LINK_RAW_IP.rawValue)
        case .null: lt = Int32(SNIFFER_LINK_NULL.rawValue)
        case .sll:  lt = Int32(SNIFFER_LINK_SLL.rawValue)
        case .sll2: lt = Int32(SNIFFER_LINK_SLL2.rawValue)
        case .ethernet: lt = Int32(SNIFFER_LINK_ETHERNET.rawValue)
        }
        data.withUnsafeBytes { raw in
            fnParsePacket(raw.bindMemory(to: UInt8.self).baseAddress,
                          Int32(raw.count), lt, &out)
        }

        var r = Parsed()
        r.proto             = cstr(out.proto)
        r.sourceIp          = cstr(out.src_ip)
        r.destIp            = cstr(out.dst_ip)
        r.sourceMac         = cstr(out.src_mac)
        r.destMac           = cstr(out.dst_mac)
        r.sourcePort        = out.src_port
        r.destPort          = out.dst_port
        r.isIP              = out.is_ip != 0
        r.isIPv6            = out.is_ipv6 != 0
        r.ttl               = out.ttl
        r.ipProto           = out.ip_proto
        r.checksumValidated = out.checksum_validated != 0
        r.checksumOK        = out.checksum_ok != 0
        r.dontFragment      = out.dont_fragment != 0
        r.moreFragments     = out.more_fragments != 0
        r.fragmentOffset    = out.frag_offset
        r.tcpParsed         = out.tcp_parsed != 0
        r.tcpFlags          = out.tcp_flags
        r.tcpWindow         = out.tcp_window
        r.tcpSeq            = out.tcp_seq
        r.tcpAck            = out.tcp_ack
        r.dscp              = out.dscp
        r.ecn               = out.ecn
        r.vlanId            = Int(out.vlan_id)
        r.hasIcmp           = out.has_icmp != 0
        r.icmpType          = out.icmp_type
        r.icmpCode          = out.icmp_code
        r.l7Proto           = cstr(out.l7_proto)
        r.l7Info            = cstr(out.l7_info)
        r.host              = cstr(out.host)
        return r
    }

    private static func cstr<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { raw in
            let bytes = raw.bindMemory(to: UInt8.self)
            var len = 0
            while len < bytes.count && bytes[len] != 0 { len += 1 }
            return String(decoding: UnsafeBufferPointer(start: bytes.baseAddress, count: len), as: UTF8.self)
        }
    }
}

enum PassiveL7Parser {
    struct ArpDetails: Sendable, Hashable {
        var operation: UInt16
        var senderMac: String
        var senderIp: String
        var targetMac: String
        var targetIp: String

        var operationName: String {
            switch operation {
            case 1: return "request"
            case 2: return "reply"
            default: return "op \(operation)"
            }
        }
    }

    struct DhcpDetails: Sendable, Hashable {
        var messageType: UInt8
        var transactionId: UInt32
        var clientMac: String
        var clientIp: String
        var yourIp: String
        var serverIp: String
        var hostName: String
        var requestedIp: String
        var serverIdentifier: String

        var messageName: String {
            switch messageType {
            case 1: return "Discover"
            case 2: return "Offer"
            case 3: return "Request"
            case 4: return "Decline"
            case 5: return "ACK"
            case 6: return "NAK"
            case 7: return "Release"
            case 8: return "Inform"
            default: return messageType == 0 ? "Unknown" : "Type \(messageType)"
            }
        }
    }

    struct HttpRequestDetails: Sendable, Hashable {
        var method: String
        var target: String
        var version: String
        var host: String
        var userAgent: String
    }

    struct DnsResourceRecord: Sendable, Hashable {
        var name: String
        var type: UInt16
        var ttl: UInt32
        var value: String
    }

    struct TlsClientHelloDetails: Sendable, Hashable {
        var host: String
        var tlsVersion: UInt16
        var cipherSuites: [UInt16]
        var extensionCount: Int
        var alpnProtocols: [String]
    }

    struct Observation {
        var arp: ArpDetails?
        var dhcp: DhcpDetails?
        var httpRequest: HttpRequestDetails?
        var tlsClientHello: TlsClientHelloDetails?
        var dnsQuery: (name: String, qtype: UInt16, txid: UInt16)?
        var dnsAnswer: (name: String, qtype: UInt16, txid: UInt16, addresses: [String], records: [DnsResourceRecord])?
        var isMdns = false
        var isQuic = false
    }

    static func parse(_ data: Data, linkType: PacketParser.LinkType = .ethernet) -> Observation {
        switch linkType {
        case .ethernet:
            return parseEthernet(data)
        case .raw:
            return parseIpPacket(data, offset: 0)
        case .null:
            // BSD loopback (lo0): 4-byte address-family header.
            return parseIpPacket(data, offset: 4)
        case .sll:
            // Linux cooked v1: 16-byte SLL header.
            return parseIpPacket(data, offset: 16)
        case .sll2:
            // Linux cooked v2: 20-byte SLL2 header.
            return parseIpPacket(data, offset: 20)
        }
    }

    private static func parseEthernet(_ data: Data) -> Observation {
        guard data.count >= 14 else { return Observation() }

        var etherType = be16(data, 12)
        var l3Offset = 14
        while etherType == 0x8100, data.count >= l3Offset + 4 {
            etherType = be16(data, l3Offset + 2)
            l3Offset += 4
        }

        switch etherType {
        case 0x0800, 0x86DD:
            return parseIpPacket(data, offset: l3Offset)
        case 0x0806:
            return parseArp(data, offset: l3Offset)
        default:
            return Observation()
        }
    }

    private static func parseIpPacket(_ data: Data, offset: Int) -> Observation {
        guard data.count > offset else { return Observation() }
        switch data[data.startIndex + offset] >> 4 {
        case 4:
            return parseIpv4(data, offset: offset)
        case 6:
            return parseIpv6(data, offset: offset)
        default:
            return Observation()
        }
    }

    private static func parseIpv4(_ data: Data, offset: Int) -> Observation {
        guard data.count >= offset + 20 else { return Observation() }
        let ihl = Int(data[data.startIndex + offset] & 0x0F) * 4
        guard ihl >= 20, data.count >= offset + ihl else { return Observation() }
        let proto = data[data.startIndex + offset + 9]
        return parseTransport(data, offset: offset + ihl, proto: proto)
    }

    private static func parseIpv6(_ data: Data, offset: Int) -> Observation {
        guard data.count >= offset + 40 else { return Observation() }
        let proto = data[data.startIndex + offset + 6]
        return parseTransport(data, offset: offset + 40, proto: proto)
    }

    private static func parseTransport(_ data: Data, offset: Int, proto: UInt8) -> Observation {
        switch proto {
        case 6:
            return parseTcp(data, offset: offset)
        case 17:
            return parseUdp(data, offset: offset)
        default:
            return Observation()
        }
    }

    private static func parseTcp(_ data: Data, offset: Int) -> Observation {
        guard data.count >= offset + 20 else { return Observation() }
        let sourcePort = be16(data, offset)
        let destPort = be16(data, offset + 2)
        let headerLength = Int((data[data.startIndex + offset + 12] >> 4) * 4)
        guard headerLength >= 20, data.count >= offset + headerLength else { return Observation() }
        let payloadOffset = offset + headerLength
        let payload = slice(data, from: payloadOffset)

        if sourcePort == 53 || destPort == 53 {
            return parseDnsPayload(payload, isTcp: true)
        }
        if let http = parseHttpRequest(payload) {
            return Observation(httpRequest: http)
        }
        let tls = parseTlsPayload(payload)
        if tls.tlsClientHello != nil {
            return tls
        }
        return Observation()
    }

    private static func parseUdp(_ data: Data, offset: Int) -> Observation {
        guard data.count >= offset + 8 else { return Observation() }
        let sourcePort = be16(data, offset)
        let destPort = be16(data, offset + 2)
        let payload = slice(data, from: offset + 8)
        if sourcePort == 67 || sourcePort == 68 || destPort == 67 || destPort == 68 {
            return Observation(dhcp: parseDhcpPayload(payload))
        }
        if sourcePort == 5353 || destPort == 5353 {
            var obs = parseDnsPayload(payload, isTcp: false)
            obs.isMdns = true
            return obs
        }
        if sourcePort == 53 || destPort == 53 {
            return parseDnsPayload(payload, isTcp: false)
        }
        if sourcePort == 443 || destPort == 443 || sourcePort == 4433 || destPort == 4433 || sourcePort == 8443 || destPort == 8443 {
            return Observation(isQuic: looksLikeQuic(payload))
        }
        return Observation()
    }

    private static func parseArp(_ data: Data, offset: Int) -> Observation {
        guard data.count >= offset + 28 else { return Observation() }
        let hardwareType = be16(data, offset)
        let protocolType = be16(data, offset + 2)
        let hardwareLength = data[data.startIndex + offset + 4]
        let protocolLength = data[data.startIndex + offset + 5]
        guard hardwareType == 1, protocolType == 0x0800,
              hardwareLength == 6, protocolLength == 4 else { return Observation() }

        return Observation(arp: ArpDetails(
            operation: be16(data, offset + 6),
            senderMac: macString(data, at: offset + 8),
            senderIp: ipv4String(data, at: offset + 14),
            targetMac: macString(data, at: offset + 18),
            targetIp: ipv4String(data, at: offset + 24)
        ))
    }

    private static func parseHttpRequest(_ payload: Data) -> HttpRequestDetails? {
        guard payload.count >= 16,
              let text = String(data: payload.prefix(min(payload.count, 4096)), encoding: .utf8),
              let firstLineEnd = text.range(of: "\r\n") ?? text.range(of: "\n") else { return nil }

        let requestLine = String(text[..<firstLineEnd.lowerBound])
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3,
              ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"].contains(parts[0]) else {
            return nil
        }

        var host = ""
        var userAgent = ""
        for line in text[firstLineEnd.upperBound...].split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty { break }
            if trimmed.lowercased().hasPrefix("host:") {
                host = String(trimmed.dropFirst(5)).trimmingCharacters(in: .whitespaces)
            } else if trimmed.lowercased().hasPrefix("user-agent:") {
                userAgent = String(trimmed.dropFirst(11)).trimmingCharacters(in: .whitespaces)
            }
        }

        return HttpRequestDetails(method: parts[0], target: parts[1], version: parts[2],
                                  host: host, userAgent: userAgent)
    }

    private static func parseDhcpPayload(_ payload: Data) -> DhcpDetails? {
        guard payload.count >= 240 else { return nil }
        guard payload[payload.startIndex] == 1 || payload[payload.startIndex] == 2 else { return nil }
        guard be32(payload, 236) == 0x63825363 else { return nil }

        var messageType: UInt8 = 0
        var hostName = ""
        var requestedIp = ""
        var serverIdentifier = ""
        var cursor = 240
        while cursor < payload.count {
            let option = payload[payload.startIndex + cursor]
            cursor += 1
            if option == 255 { break }
            if option == 0 { continue }
            guard cursor < payload.count else { break }
            let length = Int(payload[payload.startIndex + cursor])
            cursor += 1
            guard cursor + length <= payload.count else { break }
            switch option {
            case 53 where length >= 1:
                messageType = payload[payload.startIndex + cursor]
            case 12:
                hostName = String(decoding: payload.subdata(in: cursor..<(cursor + length)), as: UTF8.self)
            case 50 where length == 4:
                requestedIp = ipv4String(payload, at: cursor)
            case 54 where length == 4:
                serverIdentifier = ipv4String(payload, at: cursor)
            default:
                break
            }
            cursor += length
        }

        return DhcpDetails(
            messageType: messageType,
            transactionId: be32(payload, 4),
            clientMac: macString(payload, at: 28),
            clientIp: ipv4String(payload, at: 12),
            yourIp: ipv4String(payload, at: 16),
            serverIp: ipv4String(payload, at: 20),
            hostName: hostName,
            requestedIp: requestedIp,
            serverIdentifier: serverIdentifier
        )
    }

    private static func parseTlsPayload(_ payload: Data) -> Observation {
        guard payload.count >= 9 else { return Observation() }
        let contentType = payload[payload.startIndex]
        guard contentType == 22 else { return Observation() }

        let recordLength = Int(be16(payload, 3))
        guard payload.count >= 5 + recordLength else { return Observation() }
        let handshakeOffset = 5
        guard payload.count >= handshakeOffset + 4 else { return Observation() }
        guard payload[payload.startIndex + handshakeOffset] == 1 else { return Observation() }

        let bodyLength = Int(payload[payload.startIndex + handshakeOffset + 1]) << 16
            | Int(payload[payload.startIndex + handshakeOffset + 2]) << 8
            | Int(payload[payload.startIndex + handshakeOffset + 3])
        let bodyOffset = handshakeOffset + 4
        guard payload.count >= bodyOffset + bodyLength else { return Observation() }

        let version = be16(payload, bodyOffset)
        var cursor = bodyOffset + 2 + 32
        guard payload.count > cursor else { return Observation() }

        let sessionIdLength = Int(payload[payload.startIndex + cursor])
        cursor += 1 + sessionIdLength
        guard payload.count >= cursor + 2 else { return Observation() }

        let cipherSuitesLength = Int(be16(payload, cursor))
        guard cipherSuitesLength >= 2,
              cipherSuitesLength % 2 == 0,
              payload.count >= cursor + 2 + cipherSuitesLength else { return Observation() }
        let cipherSuitesStart = cursor + 2
        var cipherSuites: [UInt16] = []
        cipherSuites.reserveCapacity(cipherSuitesLength / 2)
        var cipherCursor = cipherSuitesStart
        while cipherCursor < cipherSuitesStart + cipherSuitesLength {
            cipherSuites.append(be16(payload, cipherCursor))
            cipherCursor += 2
        }
        cursor += 2 + cipherSuitesLength
        guard payload.count > cursor else { return Observation() }

        let compressionMethodsLength = Int(payload[payload.startIndex + cursor])
        cursor += 1 + compressionMethodsLength
        guard payload.count >= cursor + 2 else { return Observation() }

        let extensionsLength = Int(be16(payload, cursor))
        cursor += 2
        let extensionsEnd = cursor + extensionsLength
        guard payload.count >= extensionsEnd else { return Observation() }

        var host = ""
        var alpnProtocols: [String] = []
        var extensionCount = 0
        while cursor + 4 <= extensionsEnd {
            let extType = be16(payload, cursor)
            let extLength = Int(be16(payload, cursor + 2))
            cursor += 4
            guard cursor + extLength <= extensionsEnd else { return Observation() }
            extensionCount += 1
            if extType == 0,
               let parsedHost = parseServerNameExtension(payload, offset: cursor, length: extLength) {
                host = parsedHost
            } else if extType == 16 {
                alpnProtocols = parseAlpnExtension(payload, offset: cursor, length: extLength)
            }
            cursor += extLength
        }

        return Observation(tlsClientHello: TlsClientHelloDetails(
            host: host,
            tlsVersion: version,
            cipherSuites: cipherSuites,
            extensionCount: extensionCount,
            alpnProtocols: alpnProtocols
        ))
    }

    private static func parseServerNameExtension(_ payload: Data, offset: Int, length: Int) -> String? {
        guard length >= 2 else { return nil }
        let listLength = Int(be16(payload, offset))
        var cursor = offset + 2
        let end = min(offset + 2 + listLength, offset + length)

        while cursor + 3 <= end {
            let nameType = payload[payload.startIndex + cursor]
            let nameLength = Int(be16(payload, cursor + 1))
            cursor += 3
            guard cursor + nameLength <= end else { return nil }
            if nameType == 0 {
                let nameData = payload.subdata(in: cursor..<(cursor + nameLength))
                return String(data: nameData, encoding: .utf8)
            }
            cursor += nameLength
        }

        return nil
    }

    private static func parseAlpnExtension(_ payload: Data, offset: Int, length: Int) -> [String] {
        guard length >= 2 else { return [] }
        let listLength = Int(be16(payload, offset))
        var cursor = offset + 2
        let end = min(offset + 2 + listLength, offset + length)
        var protocols: [String] = []

        while cursor < end {
            let nameLength = Int(payload[payload.startIndex + cursor])
            cursor += 1
            guard nameLength > 0, cursor + nameLength <= end else { return [] }
            let nameData = payload.subdata(in: cursor..<(cursor + nameLength))
            protocols.append(String(decoding: nameData, as: UTF8.self))
            cursor += nameLength
        }

        return protocols
    }

    private static func parseDnsPayload(_ payload: Data, isTcp: Bool) -> Observation {
        let message: Data
        if isTcp {
            guard payload.count >= 2 else { return Observation() }
            let messageLength = Int(be16(payload, 0))
            guard payload.count >= 2 + messageLength else { return Observation() }
            message = payload.subdata(in: 2..<(2 + messageLength))
        } else {
            message = payload
        }

        guard message.count >= 12 else { return Observation() }
        let txid = be16(message, 0)
        let flags = be16(message, 2)
        let isResponse = (flags & 0x8000) != 0
        let questionCount = Int(be16(message, 4))
        let answerCount = Int(be16(message, 6))
        guard questionCount > 0 else { return Observation() }

        guard let question = readName(message, at: 12) else { return Observation() }
        var cursor = question.next
        guard cursor + 4 <= message.count, !question.name.isEmpty else { return Observation() }
        let qtype = be16(message, cursor)
        cursor += 4

        if !isResponse {
            return Observation(dnsQuery: (name: question.name, qtype: qtype, txid: txid))
        }

        var remainingQuestions = questionCount - 1
        while remainingQuestions > 0 {
            guard let q = readName(message, at: cursor), q.next + 4 <= message.count else {
                return Observation(dnsAnswer: (name: question.name, qtype: qtype, txid: txid, addresses: [], records: []))
            }
            cursor = q.next + 4
            remainingQuestions -= 1
        }

        var addresses: [String] = []
        var records: [DnsResourceRecord] = []
        var remainingAnswers = answerCount
        while remainingAnswers > 0 {
            guard let rr = readName(message, at: cursor) else { break }
            cursor = rr.next
            guard cursor + 10 <= message.count else { break }
            let type = be16(message, cursor)
            let ttl = be32(message, cursor + 4)
            let rdLength = Int(be16(message, cursor + 8))
            cursor += 10
            guard cursor + rdLength <= message.count else { break }
            if let value = dnsRecordValue(message, type: type, rdataOffset: cursor, rdLength: rdLength) {
                records.append(DnsResourceRecord(name: rr.name, type: type, ttl: ttl, value: value))
                if type == 1 || type == 28 { addresses.append(value) }
            }
            cursor += rdLength
            remainingAnswers -= 1
        }
        return Observation(dnsAnswer: (name: question.name, qtype: qtype, txid: txid, addresses: addresses, records: records))
    }

    private static func dnsRecordValue(_ message: Data, type: UInt16, rdataOffset: Int, rdLength: Int) -> String? {
        switch type {
        case 1 where rdLength == 4:
            return ipv4String(message, at: rdataOffset)
        case 28 where rdLength == 16:
            return ipv6String(message, at: rdataOffset)
        case 5, 12:
            return readName(message, at: rdataOffset)?.name
        case 15 where rdLength >= 3:
            let preference = be16(message, rdataOffset)
            let exchange = readName(message, at: rdataOffset + 2)?.name ?? ""
            return "\(preference) \(exchange)"
        case 16:
            var cursor = rdataOffset
            let end = rdataOffset + rdLength
            var strings: [String] = []
            while cursor < end {
                let length = Int(message[message.startIndex + cursor])
                cursor += 1
                guard cursor + length <= end else { break }
                strings.append(String(decoding: message.subdata(in: cursor..<(cursor + length)), as: UTF8.self))
                cursor += length
            }
            return strings.joined(separator: " ")
        case 33 where rdLength >= 7:
            let priority = be16(message, rdataOffset)
            let weight = be16(message, rdataOffset + 2)
            let port = be16(message, rdataOffset + 4)
            let target = readName(message, at: rdataOffset + 6)?.name ?? ""
            return "priority \(priority), weight \(weight), port \(port), target \(target)"
        case 6:
            return readName(message, at: rdataOffset)?.name
        case 64, 65:
            return "SVCB/HTTPS parameters (\(rdLength) bytes)"
        default:
            return nil
        }
    }

    private static func looksLikeQuic(_ payload: Data) -> Bool {
        guard let first = payload.first else { return false }
        return (first & 0x80) != 0 || (first & 0x40) != 0
    }

    private static func readName(_ message: Data, at offset: Int) -> (name: String, next: Int)? {
        var labels: [String] = []
        var cursor = offset
        var next: Int?
        var hops = 0
        while cursor < message.count {
            let length = Int(message[message.startIndex + cursor])
            if length == 0 {
                cursor += 1
                break
            }
            if (length & 0xC0) == 0xC0 {
                guard cursor + 1 < message.count else { return nil }
                let pointer = (length & 0x3F) << 8 | Int(message[message.startIndex + cursor + 1])
                if next == nil { next = cursor + 2 }
                hops += 1
                guard hops <= 16, pointer < message.count else { return nil }
                cursor = pointer
                continue
            }
            if (length & 0xC0) != 0 { return nil }
            let start = cursor + 1
            guard start + length <= message.count else { return nil }
            labels.append(String(decoding: message.subdata(in: start..<(start + length)), as: UTF8.self))
            cursor += 1 + length
        }
        return (labels.joined(separator: "."), next ?? cursor)
    }

    private static func ipv4String(_ data: Data, at offset: Int) -> String {
        guard offset >= 0, offset + 4 <= data.count else { return "" }
        let i = data.startIndex + offset
        return "\(data[i]).\(data[i + 1]).\(data[i + 2]).\(data[i + 3])"
    }

    private static func ipv6String(_ data: Data, at offset: Int) -> String {
        guard offset >= 0, offset + 16 <= data.count else { return "" }
        let i = data.startIndex + offset
        var groups: [String] = []
        for g in 0..<8 {
            groups.append(String(format: "%x", UInt16(data[i + g * 2]) << 8 | UInt16(data[i + g * 2 + 1])))
        }
        return groups.joined(separator: ":")
    }

    private static func macString(_ data: Data, at offset: Int) -> String {
        guard data.count >= offset + 6 else { return "" }
        let i = data.startIndex + offset
        return (0..<6)
            .map { String(format: "%02x", data[i + $0]) }
            .joined(separator: ":")
    }

    private static func be16(_ data: Data, _ offset: Int) -> UInt16 {
        guard offset >= 0, offset + 2 <= data.count else { return 0 }
        let i = data.startIndex + offset
        return UInt16(data[i]) << 8 | UInt16(data[i + 1])
    }

    private static func be32(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset >= 0, offset + 4 <= data.count else { return 0 }
        let i = data.startIndex + offset
        return UInt32(data[i]) << 24
            | UInt32(data[i + 1]) << 16
            | UInt32(data[i + 2]) << 8
            | UInt32(data[i + 3])
    }

    private static func slice(_ data: Data, from offset: Int) -> Data {
        guard data.count > offset else { return Data() }
        return data.subdata(in: offset..<data.count)
    }
}
