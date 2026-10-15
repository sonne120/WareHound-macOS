import SwiftUI

struct PacketDetailView: View {
    let packet: PacketModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()

            TabView {
                detailsTab
                    .tabItem { Label("Details", systemImage: "list.bullet.rectangle") }
                hexTab
                    .tabItem { Label("Hex Dump", systemImage: "number") }
            }
            .padding(16)

            Divider()
            HStack {
                Text("\(packet.originalLen) bytes captured")
                    .font(.caption)
                    .foregroundStyle(AppColors.textSecondary)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
            .padding(12)
        }
        .frame(width: 620, height: 560)
        .background(AppColors.primary)
    }

    private var header: some View {
        HStack(spacing: 14) {
            protocolBadge

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(packet.proto)
                        .font(.title2).bold()
                        .foregroundStyle(AppColors.textPrimary)
                    Text("#\(packet.number)")
                        .font(.caption).bold()
                        .padding(.horizontal, 8).padding(.vertical, 3)
                        .background(AppColors.accent.opacity(0.15), in: Capsule())
                        .foregroundStyle(AppColors.accent)
                }
                Label(Self.fullFormatter.string(from: packet.captureTime),
                      systemImage: "clock")
                    .font(.caption)
                    .foregroundStyle(AppColors.textSecondary)
            }

            Spacer()
        }
        .padding(16)
        .background(AppColors.secondary)
    }

    private var protocolBadge: some View {
        RoundedRectangle(cornerRadius: 12, style: .continuous)
            .fill(AppColors.rowColor(forProtocol: packet.proto) ?? AppColors.tertiary)
            .frame(width: 52, height: 52)
            .overlay(
                Image(systemName: protocolIcon)
                    .font(.title2)
                    .foregroundStyle(AppColors.textPrimary.opacity(0.75))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(AppColors.border.opacity(0.4), lineWidth: 1)
            )
    }

    private var protocolIcon: String {
        let p = packet.proto.uppercased()
        if p.hasPrefix("TLS") { return "lock.fill" }
        switch p {
        case "TCP":            return "arrow.left.arrow.right"
        case "UDP", "QUIC":    return "bolt.horizontal"
        case "HTTPS":          return "lock.fill"
        case "HTTP":           return "globe"
        case "DNS", "MDNS":    return "magnifyingglass"
        case "DHCP":           return "wifi"
        case "ICMP", "ICMPV6": return "waveform.path.ecg"
        case "ARP":            return "map"
        default:               return "shippingbox"
        }
    }

    private var detailsTab: some View {
        ScrollView {
            VStack(spacing: 16) {
                flowCard
                card("NETWORK", icon: "network") {
                    infoRow("Source IP", packet.sourceIp, mono: true)
                    infoRow("Destination IP", packet.destIp, mono: true)
                    infoRow("Source Port", "\(packet.sourcePort)", mono: true)
                    infoRow("Destination Port", "\(packet.destPort)", mono: true)
                }
                card("DATA LINK", icon: "cable.connector") {
                    infoRow("Source MAC", packet.sourceMac, mono: true)
                    infoRow("Destination MAC", packet.destMac, mono: true)
                }
                ipTransportCard
                card("INFO", icon: "info.circle") {
                    infoRow("Protocol", packet.proto)
                    infoRow("ID", "\(packet.packetId)", mono: true)
                    infoRow("Capture Time", Self.fullFormatter.string(from: packet.captureTime), mono: true)
                    infoRow("Length", lengthDescription)
                    infoRow("Host", packet.hostName.isEmpty ? "Unknown" : packet.hostName)
                }
                arpCard
                tlsCard
                dhcpCard
                httpCard
                dnsCard
            }
            .padding(2)
        }
    }

    private var lengthDescription: String {
        if packet.captureLen > 0, UInt32(packet.captureLen) < packet.originalLen {
            return "\(packet.originalLen) bytes (\(packet.captureLen) captured)"
        }
        return "\(packet.originalLen) bytes"
    }

    @ViewBuilder
    private var ipTransportCard: some View {
        if packet.meta.isIP {
            card("IP / TRANSPORT", icon: "shield.lefthalf.filled") {
                if packet.meta.vlanId >= 0 {
                    infoRow("VLAN ID", packet.vlanDisplay, mono: true)
                }
                infoRow(packet.meta.isIPv6 ? "Hop Limit" : "TTL", packet.ttlDisplay, mono: true)
                infoRow("DSCP", packet.dscpDisplay)
                infoRow("ECN", packet.ecnDisplay)
                if !packet.meta.isIPv6 {
                    infoRow("Header Checksum", packet.checksumDisplay)
                    infoRow("Fragmentation", packet.fragmentDisplay)
                }
                if packet.isTruncated {
                    infoRow("Capture", "truncated (\(packet.captureLen) of \(packet.originalLen) bytes)")
                }
                if packet.meta.hasIcmp {
                    infoRow("ICMP", packet.icmpDetail, mono: true)
                }
                if packet.meta.tcpParsed {
                    infoRow("TCP Stream", packet.tcpStreamKey, mono: true)
                    infoRow("TCP Flags", packet.tcpFlagsDisplay, mono: true)
                    infoRow("Sequence", packet.tcpSeqDisplay, mono: true)
                    infoRow("Acknowledgment", packet.tcpAckDisplay, mono: true)
                    infoRow("Window Size", packet.windowDisplay, mono: true)
                    if packet.isScan {
                        infoRow("Scan / Anomaly", packet.scanReason)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var arpCard: some View {
        if let arp = packet.arp {
            card("ARP", icon: "map") {
                infoRow("Operation", arp.operationName)
                infoRow("Sender MAC", arp.senderMac, mono: true)
                infoRow("Sender IP", arp.senderIp, mono: true)
                infoRow("Target MAC", arp.targetMac, mono: true)
                infoRow("Target IP", arp.targetIp, mono: true)
            }
        }
    }

    @ViewBuilder
    private var tlsCard: some View {
        if packet.tlsClientHello != nil {
            card("TLS CLIENT HELLO", icon: "lock.fill") {
                infoRow("Server Name (SNI)", packet.tlsSniDisplay)
                infoRow("Version", packet.tlsVersionDisplay)
                infoRow("ALPN", packet.tlsAlpnDisplay)
                infoRow("Offered Ciphers", packet.tlsCipherCountDisplay)
                infoRow("First Cipher", packet.tlsFirstCipherDisplay, mono: true)
                infoRow("Extensions", packet.tlsExtensionCountDisplay)
            }
        }
    }

    @ViewBuilder
    private var dhcpCard: some View {
        if let dhcp = packet.dhcp {
            card("DHCP", icon: "wifi") {
                infoRow("Message", dhcp.messageName)
                infoRow("Transaction ID", String(format: "0x%08X", dhcp.transactionId), mono: true)
                infoRow("Client MAC", dhcp.clientMac, mono: true)
                infoRow("Client IP", dhcp.clientIp, mono: true)
                infoRow("Your IP", dhcp.yourIp, mono: true)
                infoRow("Server IP", dhcp.serverIp, mono: true)
                if !dhcp.requestedIp.isEmpty && dhcp.requestedIp != "0.0.0.0" {
                    infoRow("Requested IP", dhcp.requestedIp, mono: true)
                }
                if !dhcp.serverIdentifier.isEmpty && dhcp.serverIdentifier != "0.0.0.0" {
                    infoRow("Server Identifier", dhcp.serverIdentifier, mono: true)
                }
                if !dhcp.hostName.isEmpty {
                    infoRow("Host Name", dhcp.hostName)
                }
            }
        }
    }

    @ViewBuilder
    private var httpCard: some View {
        if let http = packet.httpRequest {
            card("HTTP REQUEST", icon: "globe") {
                infoRow("Request", "\(http.method) \(http.target) \(http.version)", mono: true)
                infoRow("Host", http.host.isEmpty ? "—" : http.host, mono: true)
                if !http.userAgent.isEmpty {
                    infoRow("User-Agent", http.userAgent)
                }
            }
        }
    }

    @ViewBuilder
    private var dnsCard: some View {
        if let dns = packet.dns, dns.kind == .query {
            card("DNS QUERY", icon: "magnifyingglass") {
                infoRow("Name", dns.name, mono: true)
                infoRow("Type", Self.dnsTypeName(dns.qtype))
                infoRow("Transaction ID", String(format: "0x%04X", dns.txid), mono: true)
                if packet.isMdns {
                    infoRow("Transport", "mDNS multicast")
                }
            }
        } else if let dns = packet.dns, dns.kind == .answer {
            card("DNS RESPONSE", icon: "magnifyingglass") {
                infoRow("Name", dns.name, mono: true)
                infoRow("Type", Self.dnsTypeName(dns.qtype))
                infoRow("Transaction ID", String(format: "0x%04X", dns.txid), mono: true)
                if packet.isMdns {
                    infoRow("Transport", "mDNS multicast")
                }
                infoRow("Addresses",
                        dns.addresses.isEmpty ? "—" : dns.addresses.joined(separator: "\n"),
                        mono: true)
                if !dns.records.isEmpty {
                    infoRow("Records", dns.records.map(Self.dnsRecordLine).joined(separator: "\n"), mono: true)
                }
            }
        }
    }

    private static func dnsRecordLine(_ record: PassiveL7Parser.DnsResourceRecord) -> String {
        "\(record.name) \(dnsTypeName(record.type)) TTL=\(record.ttl) \(record.value)"
    }

    static func dnsTypeName(_ type: UInt16) -> String {
        switch type {
        case 1:   return "A"
        case 2:   return "NS"
        case 5:   return "CNAME"
        case 6:   return "SOA"
        case 12:  return "PTR"
        case 15:  return "MX"
        case 16:  return "TXT"
        case 28:  return "AAAA"
        case 33:  return "SRV"
        case 64:  return "SVCB"
        case 65:  return "HTTPS"
        default:  return "TYPE\(type)"
        }
    }

    private var flowCard: some View {
        HStack(spacing: 12) {
            endpoint(title: "SOURCE", ip: packet.sourceIp, port: packet.sourcePort,
                     icon: "arrow.up.right.circle.fill")

            VStack(spacing: 2) {
                Image(systemName: "arrow.right")
                    .font(.headline)
                    .foregroundStyle(AppColors.accent)
                Text(packet.proto)
                    .font(.caption2).bold()
                    .foregroundStyle(AppColors.textSecondary)
            }

            endpoint(title: "DESTINATION", ip: packet.destIp, port: packet.destPort,
                     icon: "arrow.down.left.circle.fill")
        }
        .padding(16)
        .frame(maxWidth: .infinity)
        .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(AppColors.borderLight, lineWidth: 1)
        )
    }

    private func endpoint(title: String, ip: String, port: Int32, icon: String) -> some View {
        VStack(spacing: 6) {
            Image(systemName: icon)
                .font(.title)
                .foregroundStyle(AppColors.accent)
            Text(title)
                .font(.caption2).bold()
                .foregroundStyle(AppColors.textSecondary)
            Text(ip.isEmpty ? "—" : ip)
                .font(.system(.callout, design: .monospaced))
                .foregroundStyle(AppColors.textPrimary)
                .lineLimit(1)
                .minimumScaleFactor(0.6)
            Text(port > 0 ? "port \(port)" : " ")
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
        }
        .frame(maxWidth: .infinity)
        .textSelection(.enabled)
    }

    @ViewBuilder
    private func card(_ title: String, icon: String,
                      @ViewBuilder _ content: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label(title, systemImage: icon)
                .font(.caption).bold()
                .foregroundStyle(AppColors.accent)
            VStack(spacing: 8) { content() }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(AppColors.borderLight, lineWidth: 1)
        )
    }

    private func infoRow(_ label: String, _ value: String, mono: Bool = false) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(label)
                .foregroundStyle(AppColors.textSecondary)
                .frame(width: 150, alignment: .leading)
            Text(value.isEmpty ? "—" : value)
                .font(mono ? .system(.callout, design: .monospaced) : .callout)
                .foregroundStyle(AppColors.textPrimary)
                .textSelection(.enabled)
            Spacer(minLength: 0)
        }
        .font(.callout)
    }

    private var hexTab: some View {
        ScrollView([.vertical, .horizontal]) {
            if Self.hexLines(packet.rawData).isEmpty {
                Text("(no data)")
                    .foregroundStyle(AppColors.textSecondary)
                    .padding()
            } else {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(Self.hexLines(packet.rawData), id: \.offset) { line in
                        HStack(spacing: 16) {
                            Text(line.offset)
                                .foregroundStyle(AppColors.accent)
                            Text(line.hex)
                                .foregroundStyle(AppColors.textPrimary)
                            Text(line.ascii)
                                .foregroundStyle(AppColors.textSecondary)
                        }
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                    }
                }
                .padding(14)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(AppColors.borderLight, lineWidth: 1)
        )
    }

    private struct HexLine { let offset: String; let hex: String; let ascii: String }

    private static func hexLines(_ data: Data) -> [HexLine] {
        guard !data.isEmpty else { return [] }
        let bytes = [UInt8](data)
        var lines: [HexLine] = []
        var offset = 0
        while offset < bytes.count {
            let end = min(offset + 16, bytes.count)
            let chunk = bytes[offset..<end]
            let hex = chunk
                .map { String(format: "%02X", $0) }
                .joined(separator: " ")
                .padding(toLength: 47, withPad: " ", startingAt: 0)
            let ascii = chunk
                .map { (0x20...0x7E).contains($0) ? String(UnicodeScalar($0)) : "." }
                .joined()
            lines.append(HexLine(offset: String(format: "%08X", UInt32(offset)),
                                 hex: hex, ascii: ascii))
            offset += 16
        }
        return lines
    }

    private static let fullFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return f
    }()
}
