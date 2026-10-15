import SwiftUI
import Charts
import AppKit
import UniformTypeIdentifiers

struct StatisticsView: View {
    @Bindable var viewModel: StatisticsViewModel
    @Bindable private var settings = SettingsViewModel.shared

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                overviewCards
                ppsChart
                HStack(alignment: .top, spacing: 16) {
                    protocolChart
                    talkersPanel
                }
                l7Panel
                inspectionPanel
            }
            .padding()
        }
        .toolbar {
            Button("Refresh") { viewModel.refresh() }
            Menu {
                Button("Export CSV…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.commaSeparatedText]
                    panel.nameFieldStringValue = "warehound-statistics.csv"
                    if panel.runModal() == .OK, let url = panel.url {
                        viewModel.exportReportCSV(to: url)
                    }
                }
                Button("Export JSON…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.json]
                    panel.nameFieldStringValue = "warehound-statistics.json"
                    if panel.runModal() == .OK, let url = panel.url {
                        viewModel.exportReportJSON(to: url)
                    }
                }
            } label: {
                Label("Export", systemImage: "square.and.arrow.down")
            }
            Button("Clear") { viewModel.clear() }
        }
        .onAppear { viewModel.refresh() }
    }

    private var overviewCards: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 158), spacing: 12)], spacing: 12) {
            metricCard("Packets", "\(viewModel.totalPackets)",
                       icon: "shippingbox.fill", tint: AppColors.accent)
            metricCard("Data", ByteCountFormatter.string(fromByteCount: viewModel.totalBytes, countStyle: .binary),
                       icon: "internaldrive.fill", tint: Color(hex: 0x5E5CE6))
            metricCard("Packets / sec", String(format: "%.0f", viewModel.packetsPerSecond),
                       icon: "speedometer", tint: Color(hex: 0x30B0C7))
            metricCard("Duration", viewModel.captureTime,
                       icon: "clock.fill", tint: AppColors.textSecondary)
            metricCard("Protocols", "\(viewModel.uniqueProtocols)",
                       icon: "square.stack.3d.up.fill", tint: Color(hex: 0xAF52DE))
            metricCard("Unique IPs", "\(viewModel.uniqueIPs)",
                       icon: "network", tint: AppColors.success)
            metricCard("Scans", "\(viewModel.scanCount)",
                       icon: "exclamationmark.shield.fill", tint: AppColors.error,
                       alert: viewModel.scanCount > 0)
            metricCard("Bad checksum", "\(viewModel.badChecksumCount)",
                       icon: "xmark.seal.fill", tint: AppColors.warning,
                       alert: viewModel.badChecksumCount > 0)
            metricCard("Packet loss", String(format: "%.2f%% (%d)", viewModel.packetLossPercent, viewModel.droppedPackets),
                       icon: "chart.line.downtrend.xyaxis", tint: AppColors.error,
                       alert: viewModel.packetLossPercent > 0)
        }
    }

    private func metricCard(_ title: String, _ value: String,
                            icon: String, tint: Color, alert: Bool = false) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(tint)
                .frame(width: 30, height: 30)
                .background(tint.opacity(0.15),
                            in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Text(value).font(.title3).monospacedDigit().bold()
                    .foregroundStyle(alert ? tint : AppColors.textPrimary)
                    .lineLimit(1).minimumScaleFactor(0.6)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppColors.secondary,
                    in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(alert ? tint.opacity(0.5) : AppColors.borderLight, lineWidth: 1)
        )
    }

    private var ppsChart: some View {
        GroupBox("Packets / second (last 60 samples) — avg \(String(format: "%.0f", viewModel.averagePps)), max \(String(format: "%.0f", viewModel.maxPps))") {
            Chart(viewModel.ppsHistory) { sample in
                LineMark(x: .value("Sample", sample.index),
                         y: .value("PPS", sample.pps))
                    .interpolationMethod(.monotone)
                AreaMark(x: .value("Sample", sample.index),
                         y: .value("PPS", sample.pps))
                    .opacity(0.15)
            }
            .chartXAxis(.hidden)
            .frame(height: 140)
        }
    }

    private var protocolChart: some View {
        GroupBox("Protocol breakdown") {
            if viewModel.protocolStats.isEmpty {
                Text("No data").foregroundStyle(.secondary).frame(maxWidth: .infinity, minHeight: 180)
            } else {
                Chart(viewModel.protocolStats, id: \.proto) { p in
                    BarMark(x: .value("Packets", p.packetCount),
                            y: .value("Protocol", p.proto))
                        .foregroundStyle(settings.color(forProtocol: p.proto))
                        .annotation(position: .trailing) {
                            Text(String(format: "%.1f%%", p.percentage))
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                }
                .chartLegend(.hidden)
                .frame(minHeight: 180)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var talkersPanel: some View {
        VStack(spacing: 12) {
            talkerList("Top source IPs", viewModel.topSourceIPs)
            talkerList("Top destination IPs", viewModel.topDestIPs)
            GroupBox("Top ports") {
                ForEach(viewModel.topPorts) { port in
                    HStack {
                        Text(port.display).monospaced()
                        Spacer()
                        Text("\(port.packetCount)").monospacedDigit().foregroundStyle(.secondary)
                    }
                    .font(.caption)
                }
                if viewModel.topPorts.isEmpty {
                    Text("No data").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        .frame(width: 260)
    }

    private var l7Panel: some View {
        GroupBox("L7 analytics (SNI / DNS / TCP)") {
            if viewModel.hasL7Data {
                VStack(alignment: .leading, spacing: 12) {
                    HStack(alignment: .top, spacing: 16) {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Top TLS SNI hosts").font(.caption).bold()
                            ForEach(viewModel.topSniHosts, id: \.sni) { h in
                                HStack {
                                    Text(h.sni.isEmpty ? "(no SNI)" : h.sni).monospaced().lineLimit(1)
                                    Spacer()
                                    Text("\(h.connectionCount)").monospacedDigit().foregroundStyle(.secondary)
                                }.font(.caption)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)

                        VStack(alignment: .leading, spacing: 4) {
                            Text("Top DNS names").font(.caption).bold()
                            ForEach(viewModel.topDnsNames, id: \.qname) { d in
                                HStack {
                                    Text(d.qname).monospaced().lineLimit(1)
                                    Spacer()
                                    Text("\(d.queryCount) • \(d.avgResolveMs)ms")
                                        .monospacedDigit().foregroundStyle(.secondary)
                                }.font(.caption)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    if !viewModel.connHealth.isEmpty {
                        connHealthSection
                    }
                }
                .padding(.vertical, 4)
            } else {
                Text("No L7 data — available in tunnel (smoltcp) mode.")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private var connHealthSection: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("TCP connection health").font(.caption).bold()
            HStack {
                Text("Destination").frame(maxWidth: .infinity, alignment: .leading)
                Text("RTT").frame(width: 70, alignment: .trailing)
                Text("Retrans").frame(width: 70, alignment: .trailing)
                Text("Sent").frame(width: 80, alignment: .trailing)
                Text("Recv").frame(width: 80, alignment: .trailing)
            }
            .font(.caption2).foregroundStyle(.secondary)

            ForEach(Array(viewModel.connHealth.enumerated()), id: \.offset) { _, c in
                HStack {
                    Text("\(c.dstIp):\(c.dstPort)").monospaced().lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Text("\(c.avgRttMs)ms").monospacedDigit()
                        .frame(width: 70, alignment: .trailing)
                    Text("\(c.retransmits)").monospacedDigit()
                        .frame(width: 70, alignment: .trailing)
                        .foregroundStyle(c.retransmits > 0 ? AppColors.warning : AppColors.textPrimary)
                    Text(Self.bytes(c.bytesSent)).monospacedDigit()
                        .frame(width: 80, alignment: .trailing).foregroundStyle(.secondary)
                    Text(Self.bytes(c.bytesRecv)).monospacedDigit()
                        .frame(width: 80, alignment: .trailing).foregroundStyle(.secondary)
                }
                .font(.caption)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var inspectionPanel: some View {
        GroupBox("Inspection summary (ARP / DHCP / HTTP / mDNS / QUIC)") {
            if viewModel.hasInspectionData {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 220), spacing: 16, alignment: .top)],
                    alignment: .leading,
                    spacing: 14
                ) {
                    inspectionList("ARP operations", viewModel.arpOperations)
                    inspectionList("Top ARP senders", viewModel.arpSenders)
                    inspectionList("DHCP messages", viewModel.dhcpMessages)
                    inspectionList("HTTP methods", viewModel.httpMethods)
                    inspectionList("Top HTTP hosts", viewModel.httpHosts)
                    inspectionList("mDNS names", viewModel.mdnsNames)
                    inspectionList("QUIC endpoints", viewModel.quicEndpoints)
                }
                .padding(.vertical, 4)
            } else {
                Text("No ARP, DHCP, HTTP, mDNS, or QUIC details captured yet.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 44, alignment: .leading)
            }
        }
        .frame(maxWidth: .infinity)
    }

    private func inspectionList(_ title: String, _ rows: [InspectionCounter]) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(title)
                .font(.caption)
                .bold()
            if rows.isEmpty {
                Text("No data")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                ForEach(rows) { row in
                    HStack(spacing: 8) {
                        Text(row.name.isEmpty ? "—" : row.name)
                            .font(.caption)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer(minLength: 8)
                        Text("\(row.count)")
                            .font(.caption)
                            .monospacedDigit()
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
        .background(AppColors.tertiary.opacity(0.28), in: RoundedRectangle(cornerRadius: 8))
    }

    private static func bytes(_ value: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(value), countStyle: .binary)
    }

    private func talkerList(_ title: String, _ talkers: [TalkerInfo]) -> some View {
        GroupBox(title) {
            ForEach(talkers) { t in
                HStack {
                    Text(t.ip).monospaced()
                    Spacer()
                    Text("\(t.packetCount)").monospacedDigit().foregroundStyle(.secondary)
                }
                .font(.caption)
            }
            if talkers.isEmpty {
                Text("No data").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
