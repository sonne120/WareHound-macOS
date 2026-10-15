import SwiftUI
import Charts
import AppKit
import UniformTypeIdentifiers
import SystemConfiguration

enum CaptureViewMode: Hashable { case table, cards, compact, timeline, heatmap }

enum SortColumn: Hashable { case number, time, source, destination, proto, length }

enum ColumnID: String, CaseIterable, Hashable {
    case time = "Time", source = "Source", srcMac = "Src MAC"
    case destination = "Destination", dstMac = "Dst MAC"
    case proto = "Protocol", length = "Length"
    case checksum = "Checksum", flags = "TCP Flags", ttl = "TTL", window = "Window"
    case vlan = "VLAN", qos = "QoS", icmp = "ICMP", seq = "Seq", ack = "Ack"
    case info = "Info"
}

private struct HeatCell: Identifiable {
    let fingerprint: String
    let bucket: String
    let count: Int
    var id: String { fingerprint + "|" + bucket }
}

private struct FollowStreamContext: Identifiable {
    let id = UUID()
    let title: String
    let packets: [PacketModel]
}

struct CaptureView: View {
    @Bindable var viewModel: CaptureViewModel
    @Bindable private var settings = SettingsViewModel.shared
    @State private var selection: PacketModel.ID?
    @State private var detailPacket: PacketModel?
    @State private var followContext: FollowStreamContext?
    @State private var viewMode: CaptureViewMode = .table
    @State private var hiddenColumns: Set<ColumnID> = [.srcMac, .dstMac]
    @State private var isFollowingLive = true
    @State private var isFilterHelpVisible = false
    @State private var isFilterHelpPinned = false
    @State private var gatewayFilterExpr: String?
    @State private var isRouterHelpVisible = false
    @State private var isRouterHelpPinned = false
    @State private var isPortLabelEditorPresented = false

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            Group {
                switch viewMode {
                case .table: packetTable
                case .cards: cardGrid
                case .compact: compactList
                case .timeline: timelineView
                case .heatmap: heatmapView
                }
            }
            statsPanel
            Divider()
            statusBar
        }
        .sheet(item: $detailPacket) { packet in
            PacketDetailView(packet: packet)
        }
        .sheet(item: $followContext) { ctx in
            FollowStreamView(title: ctx.title, packets: ctx.packets)
        }
        .sheet(isPresented: $isPortLabelEditorPresented) {
            PortLabelEditorView(settings: settings)
        }
        .onAppear {
            applyColumnSettings()
            if gatewayFilterExpr == nil { gatewayFilterExpr = Self.resolveGatewayFilter() }
        }
        .onChange(of: settings.showMacAddresses) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showChecksum) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showTcpFlags) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showTtl) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showTcpWindow) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showVlan) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showQos) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showIcmp) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showTcpSeq) { _, _ in applyColumnSettings() }
        .onChange(of: settings.showTcpAck) { _, _ in applyColumnSettings() }
        .onChange(of: viewModel.isCapturing) { _, isCapturing in
            if isCapturing && settings.autoScroll {
                isFollowingLive = true
            }
        }
    }

    // Owned by Settings so it survives tab switches, which rebuild this view's @State.
    private func applyColumnSettings() {
        setColumnVisible(.srcMac, settings.showMacAddresses)
        setColumnVisible(.dstMac, settings.showMacAddresses)
        setColumnVisible(.checksum, settings.showChecksum)
        setColumnVisible(.flags, settings.showTcpFlags)
        setColumnVisible(.ttl, settings.showTtl)
        setColumnVisible(.window, settings.showTcpWindow)
        setColumnVisible(.vlan, settings.showVlan)
        setColumnVisible(.qos, settings.showQos)
        setColumnVisible(.icmp, settings.showIcmp)
        setColumnVisible(.seq, settings.showTcpSeq)
        setColumnVisible(.ack, settings.showTcpAck)
    }

    private func setColumnVisible(_ col: ColumnID, _ visible: Bool) {
        if visible { hiddenColumns.remove(col) } else { hiddenColumns.insert(col) }
    }

    private var toolbar: some View {
        HStack {
            Picker("Interface", selection: $viewModel.selectedDevice) {
                ForEach(viewModel.availableDevices) { device in
                    Text(device.displayName).tag(Optional(device))
                }
            }
            .frame(maxWidth: 320)
            .disabled(viewModel.isCapturing)

            if viewModel.isCapturing {
                Button { viewModel.captureButtonPressed() } label: {
                    Label("Stop Capture", systemImage: "stop.fill")
                }
                .buttonStyle(.bordered)
                .tint(Color(hex: 0xB3261E))
                .keyboardShortcut("r", modifiers: [.command])
            } else {
                Button { viewModel.captureButtonPressed() } label: {
                    Label("Start Capture", systemImage: "play.fill")
                }
                .buttonStyle(.bordered)
                .tint(Color(hex: 0x1E7B34))
                .keyboardShortcut("r", modifiers: [.command])
            }

            Button("Clear") { viewModel.clear() }
                .buttonStyle(.bordered)
                .disabled(viewModel.isCapturing)

            HStack(spacing: 4) {
                Menu {
                    Button("Routed via gateway (MAC)") { applyGatewayFilter(byMAC: true) }
                    Button("Addressed to router (IP)") { applyGatewayFilter(byMAC: false) }
                    Divider()
                    Button("Show all traffic (clear filter)") { viewModel.filterText = "" }
                } label: {
                    Label("Router", systemImage: "wifi.router")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .tint(isGatewayFilterActive ? AppColors.accent : nil)
                .help("Filter router traffic, or show all captured traffic")

                Button {
                    isRouterHelpPinned.toggle()
                    isRouterHelpVisible = isRouterHelpPinned
                } label: {
                    Image(systemName: isRouterHelpPinned ? "questionmark.circle.fill" : "questionmark.circle")
                        .font(.system(size: 14, weight: .medium))
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppColors.accent)
                .help("What you can see to/from the router")
                .onHover { hovering in
                    if !isRouterHelpPinned { isRouterHelpVisible = hovering }
                }
                .popover(isPresented: routerHelpPresentation, arrowEdge: .bottom) {
                    routerHelpPopover
                }
            }

            Menu {
                Button {
                    viewModel.startDockerLiveCapture()
                } label: {
                    Label("Live capture — until Stop", systemImage: "dot.radiowaves.left.and.right")
                }
                Divider()
                Toggle(isOn: $settings.dockerCapturePortsOnly) {
                    Label("Ports only (quieter)", systemImage: "line.3.horizontal.decrease.circle")
                }
                .help("On: capture only containers' exposed/published ports. Off: capture ALL bridge-subnet traffic (noisier, includes health-checks & heartbeats).")
                Button {
                    isPortLabelEditorPresented = true
                } label: {
                    Label("Edit protocol labels…", systemImage: "tag")
                }
                .help("Override the protocol column for specific ports (e.g. 8000 → Kafka).")
                Divider()
                Section("Auto-detect · bounded window") {
                    Button("Capture 5 s")  { viewModel.captureDockerContainers(seconds: 5) }
                    Button("Capture 10 s") { viewModel.captureDockerContainers(seconds: 10) }
                    Button("Capture 30 s") { viewModel.captureDockerContainers(seconds: 30) }
                }
                Divider()
                Menu("Filter preset (10 s)") {
                    Button("Common services") {
                        viewModel.captureDockerContainers(filter: CaptureViewModel.defaultDockerFilter)
                    }
                    Button("Databases (SQL/Mongo)") {
                        viewModel.captureDockerContainers(
                            filter: "tcp port 5432 or tcp port 3306 or tcp port 27017 or tcp port 1433")
                    }
                    Button("Messaging (Kafka/Redis)") {
                        viewModel.captureDockerContainers(
                            filter: "tcp port 9092 or tcp port 29092 or tcp port 6379")
                    }
                    Button("HTTP") {
                        viewModel.captureDockerContainers(
                            filter: "tcp port 8080 or tcp port 8000 or tcp port 5001 or tcp port 8081")
                    }
                    Button("All TCP") { viewModel.captureDockerContainers(filter: "tcp") }
                }
            } label: {
                Label(dockerButtonTitle, systemImage: "shippingbox.fill")
            } primaryAction: {
                viewModel.startDockerLiveCapture()
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .tint(viewModel.isDockerLive || viewModel.isDockerCapturing ? AppColors.accent : nil)
            .disabled(viewModel.isCapturing || viewModel.isDockerCapturing)
            .help("Click: capture ALL container traffic LIVE (matches every Docker bridge subnet, so containers that expose no ports are included too) until you press Stop. Menu: bounded windows (5/10/30 s) & port-filter presets.")

            Spacer()

            HStack(spacing: 4) {
                TextField("Filter: proto == TCP, port == 443, dns contains google", text: $viewModel.filterText)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 260)
                    .help(filterTooltip)

                Button {
                    isFilterHelpPinned.toggle()
                    isFilterHelpVisible = isFilterHelpPinned
                } label: {
                    Image(systemName: isFilterHelpPinned ? "questionmark.circle.fill" : "questionmark.circle")
                        .font(.system(size: 14, weight: .medium))
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppColors.accent)
                .help("Show display filter examples")
            }
            .onHover { hovering in
                if !isFilterHelpPinned {
                    isFilterHelpVisible = hovering
                }
            }
            .popover(isPresented: filterHelpPresentation, arrowEdge: .bottom) {
                filterHelpPopover
            }

            Picker("View", selection: $viewMode) {
                Image(systemName: "list.bullet").tag(CaptureViewMode.table)
                Image(systemName: "square.grid.2x2").tag(CaptureViewMode.cards)
                Image(systemName: "chart.line.uptrend.xyaxis").tag(CaptureViewMode.compact)
                Image(systemName: "chart.dots.scatter").tag(CaptureViewMode.timeline)
                Image(systemName: "square.grid.3x3.fill").tag(CaptureViewMode.heatmap)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 208)
            .help("Table · cards · compact sparklines · timeline swimlanes · fingerprint heatmap")

            if viewMode == .table {
                Toggle(isOn: followLiveBinding) {
                    Label("Follow", systemImage: isFollowLiveActive ? "arrow.down.to.line.compact" : "pause")
                }
                .toggleStyle(.button)
                .disabled(!canFollowLive)
                .help(followLiveHelp)

                Menu {
                    ForEach(ColumnID.allCases, id: \.self) { col in
                        Toggle(col.rawValue, isOn: Binding(
                            get: { !hiddenColumns.contains(col) },
                            set: { on in
                                if on { hiddenColumns.remove(col) } else { hiddenColumns.insert(col) }
                            }
                        ))
                    }
                } label: {
                    Label("Columns", systemImage: "slider.horizontal.3")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Show or hide table columns")
            }

            Button {
                viewModel.toggleStatsPanel()
            } label: {
                Label("Stats", systemImage: viewModel.isStatsPanelVisible ? "chart.bar.fill" : "chart.bar")
            }
            .buttonStyle(.bordered)
            .tint(viewModel.isStatsPanelVisible ? AppColors.accent : nil)
        }
        .padding(8)
    }

    private var dockerButtonTitle: String {
        if viewModel.isDockerLive { return "Live…" }
        if viewModel.isDockerCapturing { return "Capturing…" }
        return "Containers"
    }

    private var filterTooltip: String {
        """
        Display filter examples:
        proto==TCP
        port=443
        proto == TCP and port == 443
        proto == TCP && checksum != bad
        http contains example.com
        method == GET
        dhcp == Discover
        arp contains 192.168.1.1
        quic == true
        mdns contains local

        Plain text search still works.
        """
    }

    private var filterHelpPresentation: Binding<Bool> {
        Binding(
            get: { isFilterHelpVisible || isFilterHelpPinned },
            set: { shown in
                isFilterHelpVisible = shown
                if !shown { isFilterHelpPinned = false }
            }
        )
    }

    private var filterHelpPopover: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Display filter examples", systemImage: "line.3.horizontal.decrease.circle")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(AppColors.accent)

            VStack(alignment: .leading, spacing: 4) {
                filterExample("proto==TCP")
                filterExample("port=443")
                filterExample("proto == TCP and port == 443")
                filterExample("proto == TCP && checksum != bad")
                filterExample("http contains example.com")
                filterExample("method == GET")
                filterExample("dhcp == Discover")
                filterExample("arp contains 192.168.1.1")
                filterExample("quic == true")
                filterExample("mdns contains local")
            }

            Text("Plain text search still works.")
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
        }
        .padding(12)
        .frame(width: 300, alignment: .leading)
    }

    private var routerHelpPresentation: Binding<Bool> {
        Binding(
            get: { isRouterHelpVisible || isRouterHelpPinned },
            set: { shown in
                isRouterHelpVisible = shown
                if !shown { isRouterHelpPinned = false }
            }
        )
    }

    private var routerHelpPopover: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("What you'll see to/from the router", systemImage: "wifi.router")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(AppColors.accent)

            VStack(alignment: .leading, spacing: 5) {
                routerHelpRow("ARP", "your Mac resolving the gateway (who-has)")
                routerHelpRow("DHCP", "Discover / Offer / Request / ACK")
                routerHelpRow("DNS", "your queries, if the router is your resolver")
                routerHelpRow("HTTP/TLS", "its web admin; MikroTik 8291 (Winbox), 8728/8729 (API)")
                routerHelpRow("Routed", "your traffic's next hop — router MAC is the L2 destination")
                routerHelpRow("Bcast/Mcast", "mDNS, SSDP, IGMP, LLMNR, and VRRP/HSRP if configured")
            }

            Divider()
            Text("Limitation").font(.caption).bold().foregroundStyle(AppColors.warning)
            Text("On a switched Wi-Fi/Ethernet network, capture sees your host's traffic plus broadcast/multicast — not other devices' unicast, nor router-to-internet control traffic (BGP/OSPF), unless you use a mirror/SPAN port. That's a physical-network limit, not a WareHound one.")
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()
            Text("Tip: “Show all traffic” in the Router menu clears the filter so every captured packet type is listed (promiscuous mode is always on).")
                .font(.caption2)
                .foregroundStyle(AppColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(width: 340, alignment: .leading)
    }

    private func routerHelpRow(_ tag: String, _ desc: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text(tag).font(.caption).bold()
                .foregroundStyle(AppColors.textPrimary)
                .frame(width: 82, alignment: .leading)
            Text(desc).font(.caption)
                .foregroundStyle(AppColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func filterExample(_ text: String) -> some View {
        Text(text)
            .font(.system(size: 12, design: .monospaced))
            .foregroundStyle(AppColors.textPrimary)
            .textSelection(.enabled)
    }

    private var followLiveBinding: Binding<Bool> {
        Binding(
            get: { isFollowLiveActive },
            set: { on in
                settings.autoScroll = on
                isFollowingLive = on
            }
        )
    }

    private var isFollowLiveActive: Bool {
        settings.autoScroll && isFollowingLive
    }

    private var canFollowLive: Bool {
        viewModel.sortColumn == .number && viewModel.sortAscending
    }

    private var followLiveHelp: String {
        if !canFollowLive { return "Follow is available when the packet table is sorted by number ascending" }
        if !settings.autoScroll { return "Turn on to follow live packets" }
        return isFollowingLive ? "Following newest packets" : "Follow paused after manual inspection"
    }

    @ViewBuilder
    private var statsPanel: some View {
        if viewModel.isStatsPanelVisible {
            Divider()
            HStack(alignment: .center, spacing: 12) {
                miniStat("Packets", "\(viewModel.statistics.totalPackets)", "shippingbox.fill")
                miniStat("Data", ByteCountFormatter.string(fromByteCount: viewModel.statistics.totalBytes, countStyle: .binary), "internaldrive.fill")
                miniStat("Rate", String(format: "%.0f/s", viewModel.statistics.packetsPerSecond), "speedometer")
                miniStat("Protocols", "\(viewModel.statistics.protocolBreakdown.count)", "square.stack.3d.up.fill")

                protocolDonut

                Spacer(minLength: 0)
            }
            .padding(.horizontal, 14)
            .padding(.top, 12)
            .padding(.bottom, 14)
            .background(AppColors.primary)
        }
    }

    private func miniStat(_ title: String, _ value: String, _ icon: String) -> some View {
        HStack(spacing: 9) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(AppColors.accent)
                .frame(width: 26, height: 26)
                .background(AppColors.accent.opacity(0.12), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundStyle(AppColors.textSecondary)
                Text(value)
                    .font(.system(size: 15, weight: .bold))
                    .monospacedDigit()
                    .foregroundStyle(AppColors.textPrimary)
            }
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 7)
        .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(AppColors.borderLight, lineWidth: 1)
        )
    }

    private var protocolDonut: some View {
        let items = topProtocols(limit: 5)
        return HStack(spacing: 12) {
            if items.isEmpty {
                Label("Waiting for packets…", systemImage: "chart.pie")
                    .font(.caption)
                    .foregroundStyle(AppColors.textSecondary)
                    .frame(height: 80, alignment: .center)
            } else {
                Chart(items, id: \.proto) { p in
                    SectorMark(
                        angle: .value("Packets", p.packetCount),
                        innerRadius: .ratio(0.62),
                        angularInset: 1.5
                    )
                    .cornerRadius(3)
                    .foregroundStyle(settings.color(forProtocol: p.proto))
                }
                .chartLegend(.hidden)
                .frame(width: 80, height: 80)

                VStack(alignment: .leading, spacing: 4) {
                    ForEach(items, id: \.proto) { p in
                        HStack(spacing: 7) {
                            Circle()
                                .fill(settings.color(forProtocol: p.proto))
                                .frame(width: 9, height: 9)
                            Text(p.proto)
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(AppColors.textPrimary)
                            Spacer(minLength: 12)
                            Text(String(format: "%.0f%%", p.percentage))
                                .font(.system(size: 11))
                                .monospacedDigit()
                                .foregroundStyle(AppColors.textSecondary)
                        }
                    }
                }
                .frame(width: 150)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(AppColors.borderLight, lineWidth: 1)
        )
    }

    private func topProtocols(limit: Int) -> [ProtocolStats] {
        let total = max(1, viewModel.statistics.totalPackets)
        return viewModel.statistics.protocolBreakdown.values
            .sorted { $0.packetCount > $1.packetCount }
            .prefix(limit)
            .map {
                var s = $0
                s.percentage = Double(s.packetCount) / Double(total) * 100
                return s
            }
    }

    private var packetTable: some View {
        ScrollViewReader { proxy in
            ScrollView([.horizontal, .vertical]) {
                LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                    Section {
                        if viewModel.filteredPackets.isEmpty {
                            emptyCaptureState
                        } else {
                            // Render only the tail: re-diffing the full buffer ~3×/s stalls the main thread.
                            ForEach(viewModel.sortedTablePackets.suffix(Self.maxLiveRows)) { packet in
                                packetRow(packet)
                            }
                            Color.clear.frame(height: 10).id(Self.bottomAnchorID)
                        }
                    } header: {
                        packetHeader
                    }
                }
            }
            .onChange(of: viewModel.filteredPackets.count) { _, _ in
                autoScrollToLatest(using: proxy)
            }
            .onChange(of: settings.autoScroll) { _, on in
                isFollowingLive = on
                if on { autoScrollToLatest(using: proxy) }
            }
            .onChange(of: viewModel.sortColumn) { _, _ in
                if !canFollowLive { isFollowingLive = false }
            }
            .onChange(of: viewModel.sortAscending) { _, _ in
                if !canFollowLive { isFollowingLive = false }
            }
            .simultaneousGesture(packetTableDragGesture)
        }
        .background(AppColors.primary)
        // No implicit animation: animated re-layout on each ~3×/s publish hangs the main thread.
        .transaction { $0.animation = nil }
    }

    private var cardGrid: some View {
        ScrollView {
            if viewModel.captureTablePackets.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    Text("No TLS ClientHellos yet")
                        .font(.headline)
                        .foregroundStyle(AppColors.textPrimary)
                    Text("Cards appear for each TLS ClientHello once capture sees HTTPS traffic.")
                        .font(.caption)
                        .foregroundStyle(AppColors.textSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
            } else {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 264, maximum: 360), spacing: 14)],
                    spacing: 14
                ) {
                    ForEach(viewModel.captureTablePackets) { packet in
                        clientHelloCard(packet)
                    }
                }
                .padding(14)
            }
        }
        .background(AppColors.primary)
    }

    @ViewBuilder
    private func clientHelloCard(_ packet: PacketModel) -> some View {
        if let tls = packet.tlsClientHello {
            let posture = securityPosture(for: tls)
            VStack(alignment: .leading, spacing: 0) {
                Rectangle().fill(posture.color).frame(height: 4)

                VStack(alignment: .leading, spacing: 9) {
                    HStack(spacing: 8) {
                        Text(packet.tlsSniDisplay)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(AppColors.textPrimary)
                            .lineLimit(1)
                        Spacer(minLength: 6)
                        Text(posture.label)
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(posture.color)
                            .padding(.horizontal, 7).padding(.vertical, 3)
                            .background(posture.color.opacity(0.14), in: Capsule())
                    }

                    Label(packet.sourceEndpoint, systemImage: "arrow.up.right.circle")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(AppColors.textSecondary)
                        .lineLimit(1)

                    HStack(spacing: 8) {
                        Text(packet.tlsVersionDisplay)
                            .font(.system(size: 10, weight: .bold))
                            .foregroundStyle(.white)
                            .padding(.horizontal, 7).padding(.vertical, 3)
                            .background(posture.color, in: Capsule())
                        Label(packet.tlsAlpnDisplay, systemImage: "bolt.horizontal")
                            .font(.system(size: 10))
                            .foregroundStyle(AppColors.textSecondary)
                            .lineLimit(1)
                        Spacer(minLength: 0)
                    }

                    Text(packet.tlsFirstCipherDisplay)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundStyle(AppColors.textPrimary)
                        .lineLimit(1)

                    Divider()

                    HStack {
                        Text(packet.captureTimestampDisplay)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(AppColors.textSecondary)
                        Spacer()
                        Text("\(tls.cipherSuites.count) ciphers · \(tls.extensionCount) ext")
                            .font(.system(size: 10))
                            .foregroundStyle(AppColors.textSecondary)
                        Text("FP \(packet.tlsFingerprintDisplay)")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(AppColors.accent)
                    }
                }
                .padding(12)
            }
            .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(AppColors.borderLight, lineWidth: 1)
            )
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .shadow(color: .black.opacity(0.06), radius: 4, y: 2)
            .contentShape(Rectangle())
            .onTapGesture { detailPacket = packet }
            .contextMenu {
                Button("Open Details") { detailPacket = packet }
                if viewModel.canFollowStream(packet) {
                    Button("Follow Stream") { followStream(packet) }
                }
                Divider()
                Button("Copy Row") { copyToPasteboard(CaptureViewModel.rowText(packet)) }
                if !tls.sni.isEmpty {
                    Button("Copy SNI") { copyToPasteboard(tls.sni) }
                    Button("Copy Fingerprint") { copyToPasteboard(packet.tlsFingerprintDisplay) }
                }
            }
        }
    }

    private func securityPosture(for tls: PacketModel.TlsClientHello) -> (label: String, color: Color) {
        if tls.cipherSuites.contains(where: { (0x1301...0x1303).contains($0) }) {
            return ("modern", AppColors.success)
        }
        let forwardSecret: Set<UInt16> = [0xC02F, 0xC030, 0xC02B, 0xC02C, 0xCCA8, 0xCCA9]
        if tls.cipherSuites.contains(where: { forwardSecret.contains($0) }) {
            return ("legacy", AppColors.warning)
        }
        return ("weak", AppColors.error)
    }

    private var compactList: some View {
        let rows = viewModel.captureTablePackets
        let trends = sourceTrends(rows)
        let maxCount = max(1, trends.values.flatMap { $0 }.max() ?? 1)
        return ScrollView {
            LazyVStack(spacing: 0, pinnedViews: [.sectionHeaders]) {
                Section {
                    if rows.isEmpty {
                        Text("No TLS ClientHellos yet — waiting for HTTPS traffic.")
                            .font(.caption)
                            .foregroundStyle(AppColors.textSecondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(12)
                    } else {
                        ForEach(rows) { packet in
                            compactRow(packet,
                                       trend: trends[packet.sourceIp] ?? [],
                                       maxCount: maxCount)
                        }
                    }
                } header: {
                    compactHeader
                }
            }
        }
        .background(AppColors.primary)
        .transaction { $0.animation = nil }
    }

    private var compactHeader: some View {
        HStack(spacing: 0) {
            headerCell("Time", width: 96)
            headerCell("Source", width: 150)
            headerCell("SNI", width: 240)
            headerCell("TLS", width: 60)
            headerCell("Top Cipher", width: 260)
            headerCell("Trend", width: 90)
        }
        .padding(.vertical, 4)
        .background(Color(nsColor: .controlBackgroundColor))
        .overlay(alignment: .bottom) { Rectangle().fill(AppColors.border).frame(height: 1) }
    }

    @ViewBuilder
    private func compactRow(_ packet: PacketModel, trend: [Int], maxCount: Int) -> some View {
        if let tls = packet.tlsClientHello {
            let posture = securityPosture(for: tls)
            HStack(spacing: 0) {
                compactCell(packet.captureTimestampDisplay, width: 96, mono: true)
                HStack(spacing: 5) {
                    Circle().fill(posture.color).frame(width: 6, height: 6)
                    Text(packet.sourceIp).font(.system(size: 10, design: .monospaced)).lineLimit(1)
                }
                .frame(width: 150, alignment: .leading).padding(.horizontal, 6)
                compactCell(packet.tlsSniDisplay, width: 240)
                compactCell(packet.tlsVersionDisplay, width: 60)
                compactCell(packet.tlsFirstCipherDisplay, width: 260, mono: true)
                sparkline(trend, color: posture.color, maxCount: maxCount)
                    .frame(width: 90, alignment: .leading).padding(.horizontal, 6)
            }
            .padding(.vertical, 1)
            .background(selection == packet.id ? AppColors.accent.opacity(0.18) : Color.clear)
            .contentShape(Rectangle())
            .onTapGesture { selectPacket(packet) }
            .simultaneousGesture(TapGesture(count: 2).onEnded { detailPacket = packet })
            .contextMenu {
                Button("Open Details") { detailPacket = packet }
                if viewModel.canFollowStream(packet) {
                    Button("Follow Stream") { followStream(packet) }
                }
                Divider()
                Button("Copy Row") { copyToPasteboard(CaptureViewModel.rowText(packet)) }
                if !tls.sni.isEmpty {
                    Button("Copy SNI") { copyToPasteboard(tls.sni) }
                    Button("Copy Fingerprint") { copyToPasteboard(packet.tlsFingerprintDisplay) }
                }
            }
        }
    }

    private func compactCell(_ text: String, width: CGFloat, mono: Bool = false) -> some View {
        Text(text.isEmpty ? "—" : text)
            .font(.system(size: 10, design: mono ? .monospaced : .default))
            .foregroundStyle(AppColors.textPrimary)
            .lineLimit(1)
            .truncationMode(.tail)
            .frame(width: width, alignment: .leading)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
    }

    private func sparkline(_ trend: [Int], color: Color, maxCount: Int) -> some View {
        Chart(Array(trend.enumerated()), id: \.offset) { index, value in
            BarMark(
                x: .value("Bucket", index),
                y: .value("Count", value),
                width: .fixed(3)
            )
            .foregroundStyle(color)
            .cornerRadius(1)
        }
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .chartYScale(domain: 0...Double(maxCount))
        .frame(height: 20)
    }

    private func sourceTrends(_ hellos: [PacketModel], buckets: Int = 12) -> [String: [Int]] {
        guard let first = hellos.first?.captureTime,
              let last = hellos.last?.captureTime else { return [:] }
        let span = last.timeIntervalSince(first)
        var trends: [String: [Int]] = [:]
        for p in hellos {
            let idx: Int
            if span <= 0 {
                idx = buckets - 1
            } else {
                let frac = p.captureTime.timeIntervalSince(first) / span
                idx = min(buckets - 1, max(0, Int(frac * Double(buckets - 1))))
            }
            var arr = trends[p.sourceIp] ?? Array(repeating: 0, count: buckets)
            arr[idx] += 1
            trends[p.sourceIp] = arr
        }
        return trends
    }

    private var timelineView: some View {
        let hellos = viewModel.captureTablePackets
        let counts = Dictionary(grouping: hellos, by: { $0.sourceIp }).mapValues { $0.count }
        let laneLimit = 14
        let topSources = counts.sorted { $0.value > $1.value }.prefix(laneLimit).map(\.key)
        let topSet = Set(topSources)
        let shown = hellos.filter { topSet.contains($0.sourceIp) }
        let laneHeight: CGFloat = 30

        return ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                if hellos.isEmpty {
                    Text("No TLS ClientHellos yet — waiting for HTTPS traffic.")
                        .font(.caption)
                        .foregroundStyle(AppColors.textSecondary)
                } else {
                    HStack(spacing: 12) {
                        Text("Swimlanes · ClientHello over time per source — dot size = #ciphers")
                            .font(.caption).foregroundStyle(AppColors.textSecondary)
                        Spacer()
                        postureLegend
                    }
                    if counts.count > laneLimit {
                        Text("Showing the \(laneLimit) busiest sources of \(counts.count).")
                            .font(.caption2).foregroundStyle(AppColors.textSecondary)
                    }

                    Chart(shown) { p in
                        PointMark(
                            x: .value("Time", p.captureTime),
                            y: .value("Source", p.sourceIp)
                        )
                        .symbolSize(CGFloat((p.tlsClientHello?.cipherSuites.count ?? 1)) * 9 + 24)
                        .foregroundStyle(postureColor(p).opacity(0.85))
                    }
                    .chartYAxis {
                        AxisMarks(preset: .aligned, position: .leading) { value in
                            AxisGridLine()
                            AxisValueLabel {
                                if let ip = value.as(String.self) {
                                    Text(ip).font(.system(size: 9, design: .monospaced))
                                }
                            }
                        }
                    }
                    .chartXAxis { AxisMarks() }
                    .chartLegend(.hidden)
                    .frame(height: max(180, CGFloat(topSources.count) * laneHeight))
                }
            }
            .padding(14)
        }
        .background(AppColors.primary)
    }

    private var postureLegend: some View {
        HStack(spacing: 12) {
            ForEach([("modern", AppColors.success), ("legacy", AppColors.warning), ("weak", AppColors.error)], id: \.0) { label, color in
                HStack(spacing: 5) {
                    Circle().fill(color).frame(width: 8, height: 8)
                    Text(label).font(.system(size: 10)).foregroundStyle(AppColors.textSecondary)
                }
            }
        }
    }

    private func postureColor(_ packet: PacketModel) -> Color {
        guard let tls = packet.tlsClientHello else { return AppColors.textSecondary }
        return securityPosture(for: tls).color
    }

    private var heatmapView: some View {
        let hellos = viewModel.captureTablePackets
        let buckets = 16
        let cells = heatCells(hellos, buckets: buckets)
        let fpCount = Set(cells.map(\.fingerprint)).count

        return ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                if cells.isEmpty {
                    Text("No TLS ClientHellos yet — waiting for HTTPS traffic.")
                        .font(.caption)
                        .foregroundStyle(AppColors.textSecondary)
                } else {
                    Text("Fingerprint × time — rows = JA3-style fingerprints, columns = \(buckets) time buckets (old → new), cell = occurrences")
                        .font(.caption).foregroundStyle(AppColors.textSecondary)

                    Chart(cells) { cell in
                        RectangleMark(
                            x: .value("Time", cell.bucket),
                            y: .value("Fingerprint", cell.fingerprint)
                        )
                        .foregroundStyle(by: .value("Count", Double(cell.count)))
                    }
                    .chartForegroundStyleScale(
                        range: Gradient(colors: [Color(hex: 0xE6F0FA), AppColors.accent, Color(hex: 0x0A2A5E)])
                    )
                    .chartXAxis(.hidden)
                    .chartYAxis {
                        AxisMarks(preset: .aligned, position: .leading) { value in
                            AxisValueLabel {
                                if let fp = value.as(String.self) {
                                    Text(fp).font(.system(size: 9, design: .monospaced))
                                }
                            }
                        }
                    }
                    .frame(height: max(160, CGFloat(fpCount) * 26))
                }
            }
            .padding(14)
        }
        .background(AppColors.primary)
    }

    private func heatCells(_ hellos: [PacketModel], buckets: Int) -> [HeatCell] {
        guard let first = hellos.first?.captureTime,
              let last = hellos.last?.captureTime else { return [] }
        let span = last.timeIntervalSince(first)

        var totals: [String: Int] = [:]
        var grid: [String: [Int]] = [:]
        for p in hellos {
            let fp = p.tlsFingerprintDisplay
            let idx: Int
            if span <= 0 {
                idx = buckets - 1
            } else {
                idx = min(buckets - 1, max(0, Int(p.captureTime.timeIntervalSince(first) / span * Double(buckets - 1))))
            }
            grid[fp, default: Array(repeating: 0, count: buckets)][idx] += 1
            totals[fp, default: 0] += 1
        }

        let topFingerprints = totals.sorted { $0.value > $1.value }.prefix(16).map(\.key)
        var cells: [HeatCell] = []
        for fp in topFingerprints {
            let series = grid[fp] ?? Array(repeating: 0, count: buckets)
            for (i, count) in series.enumerated() {
                cells.append(HeatCell(fingerprint: fp, bucket: String(format: "%02d", i), count: count))
            }
        }
        return cells
    }

    private var emptyCaptureState: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("No packets")
                .font(.headline)
                .foregroundStyle(AppColors.textPrimary)
            Text("Start a capture or load a pcap file to populate the main packet list.")
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
    }

    private func shows(_ col: ColumnID) -> Bool { !hiddenColumns.contains(col) }

    private static let maxLiveRows = 2_000
    private static let bottomAnchorID = "packet-list-bottom"

    // Follow live only in No.-ascending order; any other sort means the user is inspecting.
    private func autoScrollToLatest(using proxy: ScrollViewProxy) {
        guard settings.autoScroll,
              isFollowingLive,
              viewModel.sortColumn == .number, viewModel.sortAscending,
              !viewModel.filteredPackets.isEmpty else { return }
        // Non-animated: an animated scrollTo at ~3 Hz stalls the main thread under load.
        var tx = Transaction(); tx.disablesAnimations = true
        withTransaction(tx) { proxy.scrollTo(Self.bottomAnchorID, anchor: .bottomLeading) }
    }

    private var packetTableDragGesture: some Gesture {
        DragGesture(minimumDistance: 3)
            .onChanged { _ in
                if viewModel.isCapturing && settings.autoScroll {
                    isFollowingLive = false
                }
            }
    }

    private func selectPacket(_ packet: PacketModel) {
        selection = packet.id
        viewModel.selectedPacket = packet

        if viewModel.isCapturing,
           settings.autoScroll,
           packet.id != viewModel.sortedTablePackets.last?.id {
            isFollowingLive = false
        }
    }

    private var packetHeader: some View {
        HStack(spacing: 0) {
            sortableHeader("No.", .number, width: 72)
            if shows(.time) { sortableHeader("Time", .time, width: 118) }
            if shows(.source) { sortableHeader("Source", .source, width: 210) }
            if shows(.srcMac) { headerCell("Src MAC", width: 150) }
            if shows(.destination) { sortableHeader("Destination", .destination, width: 210) }
            if shows(.dstMac) { headerCell("Dst MAC", width: 150) }
            if shows(.proto) { sortableHeader("Protocol", .proto, width: 96) }
            if shows(.length) { sortableHeader("Length", .length, width: 78) }
            if shows(.checksum) { headerCell("Checksum", width: 90) }
            if shows(.flags) { headerCell("TCP Flags", width: 150) }
            if shows(.ttl) { headerCell("TTL", width: 56) }
            if shows(.window) { headerCell("Window", width: 90) }
            if shows(.vlan) { headerCell("VLAN", width: 60) }
            if shows(.qos) { headerCell("QoS", width: 110) }
            if shows(.icmp) { headerCell("ICMP", width: 72) }
            if shows(.seq) { headerCell("Seq", width: 112) }
            if shows(.ack) { headerCell("Ack", width: 112) }
            if shows(.info) { headerCell("Info", width: 680) }
        }
        .padding(.vertical, 5)
        .background(Color(nsColor: .controlBackgroundColor))
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(AppColors.border)
                .frame(height: 1)
        }
    }

    private func sortableHeader(_ title: String, _ column: SortColumn, width: CGFloat) -> some View {
        Button {
            viewModel.toggleSort(column)
        } label: {
            HStack(spacing: 3) {
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(viewModel.sortColumn == column ? AppColors.accent : AppColors.textPrimary)
                if viewModel.sortColumn == column {
                    Image(systemName: viewModel.sortAscending ? "chevron.up" : "chevron.down")
                        .font(.system(size: 8, weight: .bold))
                        .foregroundStyle(AppColors.accent)
                }
                Spacer(minLength: 0)
            }
            .frame(width: width, alignment: .leading)
            .padding(.horizontal, 6)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private func packetRow(_ packet: PacketModel) -> some View {
        HStack(spacing: 0) {
            numberCell(packet)
            if shows(.time) { rowCell(packet.captureTimestampDisplay, width: 118, mono: true) }
            if shows(.source) { rowCell(packet.sourceEndpoint, width: 210, mono: true) }
            if shows(.srcMac) { rowCell(packet.sourceMacDisplay, width: 150, mono: true) }
            if shows(.destination) { rowCell(packet.destinationEndpoint, width: 210, mono: true) }
            if shows(.dstMac) { rowCell(packet.destMacDisplay, width: 150, mono: true) }
            if shows(.proto) { rowCell(packet.proto, width: 96, mono: true) }
            if shows(.length) { rowCell("\(packet.originalLen)", width: 78, mono: true) }
            if shows(.checksum) { checksumCell(packet) }
            if shows(.flags) { flagsCell(packet) }
            if shows(.ttl) { rowCell(packet.ttlDisplay, width: 56, mono: true) }
            if shows(.window) { rowCell(packet.windowDisplay, width: 90, mono: true) }
            if shows(.vlan) { rowCell(packet.vlanDisplay, width: 60, mono: true) }
            if shows(.qos) { rowCell(packet.qosDisplay, width: 110, mono: true) }
            if shows(.icmp) { rowCell(packet.icmpDisplay, width: 72, mono: true) }
            if shows(.seq) { rowCell(packet.tcpSeqDisplay, width: 112, mono: true) }
            if shows(.ack) { rowCell(packet.tcpAckDisplay, width: 112, mono: true) }
            if shows(.info) { rowCell(wiresharkInfo(for: packet), width: 680) }
        }
        .padding(.vertical, 2)
        .background(rowBackground(for: packet))
        .contentShape(Rectangle())
        .onTapGesture {
            selectPacket(packet)
        }
        .simultaneousGesture(TapGesture(count: 2).onEnded {
            detailPacket = packet
        })
        .contextMenu {
            Button("Open Details") { detailPacket = packet }
            if viewModel.canFollowStream(packet) {
                Button("Follow Stream") { followStream(packet) }
            }
            Divider()
            Button("Copy Row") { copyToPasteboard(CaptureViewModel.rowText(packet)) }
            Button("Copy Info") { copyToPasteboard(wiresharkInfo(for: packet)) }
            if let tls = packet.tlsClientHello, !tls.sni.isEmpty {
                Button("Copy SNI") { copyToPasteboard(tls.sni) }
                Button("Copy Fingerprint") { copyToPasteboard(packet.tlsFingerprintDisplay) }
            }
        }
    }

    private func copyToPasteboard(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }

    private var isGatewayFilterActive: Bool {
        guard let expr = gatewayFilterExpr else { return false }
        return viewModel.filterText == expr
    }

    // byMAC shows all traffic routed via the gateway; otherwise only packets to the router's IP.
    private func applyGatewayFilter(byMAC: Bool = true) {
        let expr: String?
        if byMAC {
            expr = gatewayFilterExpr ?? Self.resolveGatewayFilter()
            if let expr { gatewayFilterExpr = expr }
        } else {
            expr = Self.defaultGateway().map { "ip == \($0)" }
        }
        guard let expr else { return }
        viewModel.filterText = (viewModel.filterText == expr) ? "" : expr
    }

    private static func resolveGatewayFilter() -> String? {
        if let mac = routerMAC() { return "mac == \(mac)" }
        if let ip = defaultGateway() { return "ip == \(ip)" }
        return nil
    }

    private static func defaultGateway() -> String? {
        guard let store = SCDynamicStoreCreate(nil, "WareHound" as CFString, nil, nil),
              let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any]
        else { return nil }
        return global["Router"] as? String
    }

    // Normalised to the parser's zero-padded lowercase form so the filter compares equal.
    private static func routerMAC() -> String? {
        guard let ip = defaultGateway() else { return nil }
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/usr/sbin/arp")
        proc.arguments = ["-n", ip]
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        do { try proc.run() } catch { return nil }
        proc.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        guard let out = String(data: data, encoding: .utf8),
              let atRange = out.range(of: " at ") else { return nil }
        let token = out[atRange.upperBound...].split(separator: " ").first.map(String.init) ?? ""
        return normalizeMAC(token)
    }

    private static func normalizeMAC(_ raw: String) -> String? {
        let parts = raw.split(separator: ":")
        guard parts.count == 6 else { return nil }
        var bytes: [String] = []
        for part in parts {
            guard let value = UInt8(part, radix: 16) else { return nil }
            bytes.append(String(format: "%02x", value))
        }
        return bytes.joined(separator: ":")
    }

    private func followStream(_ packet: PacketModel) {
        guard viewModel.canFollowStream(packet) else { return }
        followContext = FollowStreamContext(
            title: "\(packet.sourceEndpoint) ↔ \(packet.destinationEndpoint)",
            packets: viewModel.streamPackets(for: packet))
    }

    private func numberCell(_ packet: PacketModel) -> some View {
        HStack(spacing: 6) {
            Circle()
                .fill(settings.color(forProtocol: packet.proto))
                .frame(width: 7, height: 7)
            Text(packet.numberDisplay)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(AppColors.textPrimary)
                .lineLimit(1)
        }
        .frame(width: 72, alignment: .leading)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
    }

    private func headerCell(_ text: String, width: CGFloat) -> some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(AppColors.textPrimary)
            .frame(width: width, alignment: .leading)
            .padding(.horizontal, 6)
    }

    private func checksumCell(_ packet: PacketModel) -> some View {
        let color: Color = !packet.meta.checksumValidated ? AppColors.textSecondary
            : (packet.meta.checksumOK ? AppColors.textPrimary : AppColors.error)
        return Text(packet.checksumDisplay)
            .font(.system(size: 11, design: .monospaced))
            .foregroundStyle(color)
            .lineLimit(1)
            .frame(width: 90, alignment: .leading)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
    }

    private func flagsCell(_ packet: PacketModel) -> some View {
        HStack(spacing: 4) {
            if packet.isScan {
                Image(systemName: "flag.fill")
                    .font(.system(size: 8))
                    .foregroundStyle(AppColors.error)
            }
            Text(packet.tcpFlagsDisplay)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(packet.isScan ? AppColors.error : AppColors.textPrimary)
                .lineLimit(1)
        }
        .frame(width: 150, alignment: .leading)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
    }

    private func rowCell(_ text: String, width: CGFloat, mono: Bool = false) -> some View {
        Group {
            if mono {
                Text(text).font(.system(size: 11, design: .monospaced))
            } else {
                Text(text).font(.system(size: 11))
            }
        }
        .lineLimit(1)
        .truncationMode(.tail)
        .foregroundStyle(AppColors.textPrimary)
        .frame(width: width, alignment: .leading)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
    }

    private func rowBackground(for packet: PacketModel) -> Color {
        if selection == packet.id {
            return AppColors.accent.opacity(0.18)
        }
        if packet.isScan {
            return AppColors.error.opacity(0.14)
        }
        if packet.meta.checksumValidated && !packet.meta.checksumOK {
            return AppColors.warning.opacity(0.14)
        }
        return settings.color(forProtocol: packet.proto).opacity(0.16)
    }

    // Render-only: libsniffer owns protocol analysis; never re-parse protocols in Swift.
    private func wiresharkInfo(for packet: PacketModel) -> String {
        var pieces: [String] = []

        if !packet.l7Info.isEmpty {
            pieces.append(packet.l7Info)
        } else if packet.meta.tcpParsed {
            // Bare TCP: flags/window only when their own columns are hidden.
            var seg: [String] = []
            if !shows(.flags) {
                let flags = packet.tcpFlagsDisplay == "none"
                    ? "—"
                    : packet.tcpFlagsDisplay.replacingOccurrences(of: " ", with: ", ")
                seg.append("[\(flags)]")
            }
            if !shows(.window) { seg.append("Win=\(packet.meta.tcpWindow)") }
            if !seg.isEmpty { pieces.append(seg.joined(separator: " ")) }
        }

        if packet.isScan { pieces.append("⚠︎ \(packet.scanReason)") }

        if !shows(.source) && !shows(.destination) && (packet.sourcePort > 0 || packet.destPort > 0) {
            pieces.append("\(packet.sourcePort) → \(packet.destPort)")
        }
        if !packet.hostName.isEmpty && !(packet.l7Info.contains(packet.hostName)) {
            pieces.append("Host: \(packet.hostName)")
        }

        return pieces.isEmpty ? "—" : pieces.joined(separator: " · ")
    }

    private var statusBar: some View {
        HStack {
            Circle()
                .fill(viewModel.isCapturing ? .green : .secondary)
                .frame(width: 8, height: 8)
            Text(viewModel.statusMessage)
                .font(.caption)
            Spacer()
            if shouldShowTunnelState {
                Label(viewModel.tunnelRunState.title, systemImage: viewModel.tunnelRunState.icon)
                    .font(.caption)
                    .foregroundStyle(tunnelStateColor(viewModel.tunnelRunState))
                    .help(viewModel.tunnelStatusDetail)
            }
            Text("\(viewModel.statistics.totalPackets) pkts • \(String(format: "%.0f pkt/s", viewModel.statistics.packetsPerSecond))")
                .font(.caption)
                .monospacedDigit()
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
    }

    private var shouldShowTunnelState: Bool {
        settings.selectedCaptureBackend == .tunnel
            || viewModel.tunnelRunState == .failed
    }

    private func tunnelStateColor(_ state: CaptureViewModel.TunnelRunState) -> Color {
        switch state {
        case .unavailable, .failed:
            AppColors.warning
        case .available:
            AppColors.success
        case .starting:
            AppColors.accent
        case .running:
            AppColors.success
        case .stopped:
            AppColors.textSecondary
        }
    }
}

enum AppSection: String, CaseIterable, Identifiable {
    case capture = "Capture"
    case dashboard = "Dashboard"
    case statistics = "Statistics"
    case logs = "Logs"
    case settings = "Settings"

    var id: String { rawValue }
    var icon: String {
        switch self {
        case .capture: "dot.radiowaves.left.and.right"
        case .dashboard: "square.grid.2x2"
        case .statistics: "chart.bar.xaxis"
        case .logs: "text.alignleft"
        case .settings: "gearshape"
        }
    }
}

struct MainWindow: View {
    @State private var captureVM: CaptureViewModel
    @State private var dashboardVM = DashboardViewModel()
    @State private var statisticsVM: StatisticsViewModel
    @State private var logVM = LogViewModel()
    @State private var section: AppSection = .capture
    @Bindable private var settings = SettingsViewModel.shared

    init() {
        let capture = CaptureViewModel()
        let stats = StatisticsViewModel(captureViewModel: capture)
        capture.onCaptureStateChanged = { stats.onCaptureStateChanged(isCapturing: $0) }
        _captureVM = State(initialValue: capture)
        _statisticsVM = State(initialValue: stats)
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                HStack(spacing: 8) {
                    Image(systemName: "pawprint.fill")
                        .font(.title2)
                        .foregroundStyle(AppColors.accent)
                    Text("WareHound")
                        .font(.headline)
                        .foregroundStyle(AppColors.textPrimary)
                    Spacer()
                }
                .padding(.horizontal, 12)
                .padding(.top, 22)
                .padding(.bottom, 12)

                List(AppSection.allCases, selection: $section) { s in
                    Label(s.rawValue, systemImage: s.icon).tag(s)
                }
            }
            .navigationSplitViewColumnWidth(min: 160, ideal: 180)
        } detail: {
            switch section {
            case .capture:
                CaptureView(viewModel: captureVM)
                    .toolbar { capturePcapToolbar }
            case .dashboard: DashboardView(viewModel: dashboardVM)
            case .statistics: StatisticsView(viewModel: statisticsVM)
            case .logs: LogView(viewModel: logVM)
            case .settings: SettingsView()
            }
        }
        .tint(AppColors.accent)
        .preferredColorScheme(settings.darkModeEnabled ? .dark : .light)
        .navigationTitle("WareHound")
    }

    @ToolbarContentBuilder
    private var capturePcapToolbar: some ToolbarContent {
        ToolbarItemGroup {
            Button {
                captureVM.saveToDashboard()
            } label: { Label("Save to Dashboard", systemImage: "square.and.arrow.down.on.square") }
            .disabled(captureVM.packets.isEmpty)

            Button {
                let panel = NSOpenPanel()
                panel.allowedContentTypes = [.init(filenameExtension: "pcap")!, .init(filenameExtension: "cap")!]
                if panel.runModal() == .OK, let url = panel.url { captureVM.loadPcap(from: url) }
            } label: { Label("Open pcap", systemImage: "folder") }
            .disabled(captureVM.isCapturing)

            Button {
                let panel = NSSavePanel()
                panel.allowedContentTypes = [.init(filenameExtension: "pcap")!]
                panel.nameFieldStringValue = "capture.pcap"
                if panel.runModal() == .OK, let url = panel.url { captureVM.savePcap(to: url) }
            } label: { Label("Save pcap", systemImage: "square.and.arrow.down") }
            .disabled(captureVM.packets.isEmpty)

            Menu {
                Button("Selected Packet to PCAP…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.init(filenameExtension: "pcap")!]
                    panel.nameFieldStringValue = "selected-packet.pcap"
                    if panel.runModal() == .OK, let url = panel.url { captureVM.saveSelectedPcap(to: url) }
                }
                .disabled(captureVM.selectedPacket == nil)

                Button("Filtered Packets to PCAP…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.init(filenameExtension: "pcap")!]
                    panel.nameFieldStringValue = "filtered-capture.pcap"
                    if panel.runModal() == .OK, let url = panel.url { captureVM.saveFilteredPcap(to: url) }
                }
                .disabled(captureVM.filteredPackets.isEmpty)

                Button("Selected Packet Details…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.plainText]
                    panel.nameFieldStringValue = "packet-detail.txt"
                    if panel.runModal() == .OK, let url = panel.url { captureVM.exportSelectedPacketText(to: url) }
                }
                .disabled(captureVM.selectedPacket == nil)

                Divider()

                Button("Export CSV…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.commaSeparatedText]
                    panel.nameFieldStringValue = "warehound.csv"
                    if panel.runModal() == .OK, let url = panel.url { captureVM.exportCSV(to: url) }
                }
                Button("Export JSON…") {
                    let panel = NSSavePanel()
                    panel.allowedContentTypes = [.json]
                    panel.nameFieldStringValue = "warehound.json"
                    if panel.runModal() == .OK, let url = panel.url { captureVM.exportJSON(to: url) }
                }
            } label: {
                Label("Export", systemImage: "tablecells")
            }
            .disabled(captureVM.filteredPackets.isEmpty)
        }
    }
}

@main
struct WareHoundApp: App {
    var body: some Scene {
        WindowGroup {
            MainWindow()
                .frame(minWidth: 1000, minHeight: 620)
        }
    }
}
