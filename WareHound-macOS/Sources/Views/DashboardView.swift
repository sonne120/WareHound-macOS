import SwiftUI
import AppKit

struct DashboardView: View {
    @Bindable var viewModel: DashboardViewModel
    @Bindable private var settings = SettingsViewModel.shared
    @State private var selectedCollectionId: String?
    @State private var selectedPacketId: PacketModel.ID?

    var body: some View {
        HSplitView {
            collectionsList
                .frame(minWidth: 150, idealWidth: 170, maxWidth: 220)
            packetList
                .frame(minWidth: 340, maxWidth: .infinity)
            detailPane
                .frame(minWidth: 220, idealWidth: 240, maxWidth: 340)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .toolbar {
            Button("Export CSV") { viewModel.exportToCsv() }
                .disabled(viewModel.selectedCollection == nil)
            Button(role: .destructive) {
                viewModel.deleteCollection()
                selectedCollectionId = nil
            } label: { Label("Delete", systemImage: "trash") }
                .disabled(viewModel.selectedCollection == nil)
        }
    }

    private var collectionsList: some View {
        List(viewModel.collections, selection: $selectedCollectionId) { c in
            VStack(alignment: .leading) {
                Text(c.name).bold()
                Text("\(c.packetCount) packets • \(c.createdAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .tag(c.id)
        }
        .onChange(of: selectedCollectionId) { _, id in
            viewModel.selectedCollection = viewModel.collections.first { $0.id == id }
        }
        .overlay {
            if viewModel.collections.isEmpty {
                ContentUnavailableView("No saved captures",
                    systemImage: "tray",
                    description: Text("Use “Save to Dashboard” in the Capture tab"))
            }
        }
    }

    private var packetList: some View {
        Group {
            if settings.showMacAddresses {
                packetTableWithMac
            } else {
                packetTableNoMac
            }
        }
        .onChange(of: selectedPacketId) { _, id in
            viewModel.selectedPacket = viewModel.selectedCollection?.packets.first { $0.id == id }
        }
    }

    private var packetTableNoMac: some View {
        Table(viewModel.selectedCollection?.packets ?? [], selection: $selectedPacketId) {
            TableColumn("#") { Text("\($0.number)") }.width(50)
            TableColumn("Protocol", value: \.proto).width(70)
            TableColumn("Source", value: \.sourceIp)
            TableColumn("Destination", value: \.destIp)
            TableColumn("Info", value: \.info)
        }
    }

    private var packetTableWithMac: some View {
        Table(viewModel.selectedCollection?.packets ?? [], selection: $selectedPacketId) {
            TableColumn("#") { Text("\($0.number)") }.width(50)
            TableColumn("Protocol", value: \.proto).width(70)
            TableColumn("Source", value: \.sourceIp)
            TableColumn("Destination", value: \.destIp)
            TableColumn("Src MAC", value: \.sourceMacDisplay).width(140)
            TableColumn("Dst MAC", value: \.destMacDisplay).width(140)
            TableColumn("Info", value: \.info)
        }
    }

    private var detailPane: some View {
        VSplitView {
            List(viewModel.packetDetails, children: \.children) { node in
                Text(node.title)
                    .font(.system(.caption, design: .monospaced))
            }
            if let packet = viewModel.selectedPacket {
                HexDumpView(data: packet.rawData)
            } else {
                ContentUnavailableView("Select a packet", systemImage: "doc.text.magnifyingglass")
            }
        }
    }
}

struct HexDumpView: View {
    let data: Data
    private static let bytesPerRow = 16

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(rows, id: \.offset) { row in
                    Text(row.text)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
            .padding(8)
        }
    }

    private var rows: [(offset: Int, text: String)] {
        stride(from: 0, to: data.count, by: Self.bytesPerRow).map { offset in
            let end = min(offset + Self.bytesPerRow, data.count)
            let slice = data[data.startIndex + offset ..< data.startIndex + end]

            let hex = slice.map { String(format: "%02x", $0) }
                .joined(separator: " ")
                .padding(toLength: Self.bytesPerRow * 3 - 1, withPad: " ", startingAt: 0)

            let ascii = slice.map { b in (32...126).contains(b) ? String(UnicodeScalar(b)) : "." }
                .joined()

            return (offset, String(format: "%08x  %@  %@", offset, hex, ascii))
        }
    }
}

struct LogView: View {
    @Bindable var viewModel: LogViewModel
    @State private var selection: LogEntry.ID?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Picker("Level", selection: $viewModel.selectedLevelIndex) {
                    ForEach(Array(viewModel.logLevels.enumerated()), id: \.offset) { i, name in
                        Text(name).tag(i)
                    }
                }
                .frame(maxWidth: 180)
                TextField("Filter", text: $viewModel.filterText)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 240)
                Spacer()
                Text("\(viewModel.logCount) entries • \(viewModel.warningCount) warn • \(viewModel.errorCount) err")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(8)
            Divider()

            Table(viewModel.entries, selection: $selection) {
                TableColumn("Time") { Text($0.timestampDisplay).monospacedDigit() }.width(100)
                TableColumn("Level") { entry in
                    Text(entry.levelDisplay)
                        .foregroundStyle(color(for: entry.level))
                }.width(60)
                TableColumn("Message", value: \.message)
            }
            .onChange(of: selection) { _, id in
                viewModel.selectedEntry = viewModel.entries.first { $0.id == id }
            }
        }
        .toolbar {
            Button("Copy") { viewModel.copySelected() }
                .disabled(viewModel.selectedEntry == nil)
            Button("Export") { viewModel.exportLogs() }
            Button("Clear") { viewModel.clearLogs() }
        }
    }

    private func color(for level: AppLogLevel) -> Color {
        switch level {
        case .debug: .secondary
        case .info: .primary
        case .warning: .orange
        case .error: .red
        }
    }
}

struct SettingsView: View {
    @Bindable var settings = SettingsViewModel.shared
    @State private var newProtocolName = ""

    private static func columnCount(for width: CGFloat) -> Int {
        switch width {
        case ..<720: 1
        default: 2
        }
    }

    private static func contentWidth(for columns: Int) -> CGFloat {
        switch columns {
        case 1: 520
        default: 920
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            GeometryReader { proxy in
                let columns = Self.columnCount(for: proxy.size.width)
                ScrollView {
                    settingsLayout(columns: columns)
                    .padding(16)
                    .frame(maxWidth: Self.contentWidth(for: columns), alignment: .topLeading)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .animation(.easeInOut(duration: 0.22), value: columns)
                }
                .background(AppColors.primary)
            }
        }
    }

    @ViewBuilder
    private func settingsLayout(columns: Int) -> some View {
        switch columns {
        case 1:
            VStack(spacing: 16) {
                displayCard
                columnsCard
                protocolColorsCard
                bpfAccessCard
                captureCard
                backendCard
            }
        case 2:
            VStack(spacing: 16) {
                HStack(alignment: .top, spacing: 16) {
                    settingsColumn {
                        displayCard
                        bpfAccessCard
                    }
                    settingsColumn {
                        columnsCard
                        captureCard
                    }
                }
                protocolColorsCard
                backendCard
            }
        default:
            EmptyView()
        }
    }

    private func settingsColumn<Content: View>(@ViewBuilder content: () -> Content) -> some View {
        VStack(spacing: 16) {
            content()
        }
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    private var header: some View {
        HStack(spacing: 9) {
            iconChip("gearshape.fill")
            Text("Settings")
                .font(.system(size: 15, weight: .bold))
                .foregroundStyle(AppColors.textPrimary)
            Spacer()
        }
        .padding(8)
    }

    private func iconChip(_ systemImage: String) -> some View {
        Image(systemName: systemImage)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(AppColors.accent)
            .frame(width: 26, height: 26)
            .background(AppColors.accent.opacity(0.12),
                        in: RoundedRectangle(cornerRadius: 7, style: .continuous))
    }

    private func card<Content: View>(
        _ title: String,
        systemImage: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 9) {
                iconChip(systemImage)
                Text(title)
                    .font(.system(size: 15, weight: .bold))
                    .foregroundStyle(AppColors.textPrimary)
            }
            VStack(alignment: .leading, spacing: 10) { content() }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .topLeading)
        .background(AppColors.secondary,
                    in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(AppColors.borderLight, lineWidth: 1)
        )
    }

    private var displayCard: some View {
        card("Display", systemImage: "paintpalette") {
            settingPicker("Time format", selection: $settings.selectedTimeFormatIndex, values: settings.timeFormats)
            settingPicker("Theme", selection: $settings.selectedThemeIndex, values: settings.themes)
            Toggle(isOn: $settings.autoScroll) {
                Text("Auto-scroll packet list")
                    .font(.caption)
                    .foregroundStyle(AppColors.textPrimary)
                    .lineLimit(1)
            }
            .toggleStyle(.switch)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var columnsCard: some View {
        card("Packet columns", systemImage: "tablecells") {
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 10) {
                    settingToggle("MAC addresses", isOn: $settings.showMacAddresses)
                    settingToggle("Checksum", isOn: $settings.showChecksum)
                    settingToggle("TCP flags", isOn: $settings.showTcpFlags)
                    settingToggle("TTL", isOn: $settings.showTtl)
                    settingToggle("TCP window", isOn: $settings.showTcpWindow)
                }
                VStack(alignment: .leading, spacing: 10) {
                    settingToggle("VLAN", isOn: $settings.showVlan)
                    settingToggle("QoS", isOn: $settings.showQos)
                    settingToggle("ICMP", isOn: $settings.showIcmp)
                    settingToggle("TCP sequence", isOn: $settings.showTcpSeq)
                    settingToggle("TCP ack", isOn: $settings.showTcpAck)
                }
            }
        }
    }

    private var protocolColorsCard: some View {
        card("Protocol colors", systemImage: "paintpalette.fill") {
            let types = settings.allProtocolColorTypes
            let half = (types.count + 1) / 2
            HStack(alignment: .top, spacing: 24) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(Array(types.prefix(half)), id: \.self) { protocolColorRow($0) }
                }
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(Array(types.suffix(from: half)), id: \.self) { protocolColorRow($0) }
                }
            }

            Divider()

            HStack(spacing: 8) {
                TextField("New packet type (e.g. RTP)", text: $newProtocolName)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: 200)
                    .onSubmit { addNewProtocol() }
                Button("Add") { addNewProtocol() }
                    .buttonStyle(.bordered)
                    .disabled(newProtocolName.trimmingCharacters(in: .whitespaces).isEmpty)
                Spacer()
                Button {
                    settings.resetProtocolColors()
                } label: {
                    Label("Reset colors", systemImage: "arrow.counterclockwise")
                }
                .buttonStyle(.bordered)
                .controlSize(.small)
            }
        }
    }

    private func protocolColorRow(_ proto: String) -> some View {
        HStack(spacing: 10) {
            ColorPicker("", selection: protocolColorBinding(proto), supportsOpacity: false)
                .labelsHidden()
            Text(proto)
                .font(.caption)
                .foregroundStyle(AppColors.textPrimary)
            Spacer(minLength: 0)
            if settings.customProtocolTypes.contains(proto) {
                Button {
                    settings.removeCustomProtocol(proto)
                } label: {
                    Image(systemName: "minus.circle.fill")
                        .foregroundStyle(AppColors.textSecondary)
                }
                .buttonStyle(.plain)
                .help("Remove this custom packet type")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func addNewProtocol() {
        settings.addCustomProtocol(newProtocolName)
        newProtocolName = ""
    }

    private func protocolColorBinding(_ proto: String) -> Binding<Color> {
        Binding(
            get: { settings.color(forProtocol: proto) },
            set: { settings.setProtocolColor($0, forProtocol: proto) }
        )
    }

    private var bpfAccessCard: some View {
        card("BPF access", systemImage: "lock.shield") {
            Label {
                Text(settings.bpfAccessStatus.title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(AppColors.textPrimary)
            } icon: {
                Image(systemName: settings.bpfAccessStatus.isAvailable
                      ? "checkmark.circle.fill"
                      : "exclamationmark.triangle.fill")
                    .foregroundStyle(settings.bpfAccessStatus.isAvailable ? AppColors.success : AppColors.warning)
            }

            Text(settings.bpfAccessStatus.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 3) {
                Text("Device count: \(settings.bpfAccessStatus.deviceCount)")
                Text("Readable: \(settings.bpfAccessStatus.hasReadAccess ? "yes" : "no")")
                Text("Writable: \(settings.bpfAccessStatus.hasWriteAccess ? "yes" : "no")")
            }
            .font(.caption.monospaced())
            .foregroundStyle(AppColors.textSecondary)

            HStack {
                Button {
                    settings.refreshBpfAccessStatus()
                } label: {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }

                Button {
                    copyBpfSetupNote()
                } label: {
                    Label("Copy setup note", systemImage: "doc.on.doc")
                }
            }
            .buttonStyle(.bordered)
        }
    }

    private var captureCard: some View {
        card("Capture", systemImage: "dot.radiowaves.left.and.right") {
            VStack(alignment: .leading, spacing: 6) {
                Text("BPF capture filter").font(.caption).foregroundStyle(.secondary)
                TextField("e.g. tcp port 443", text: $settings.captureFilter)
                    .textFieldStyle(.roundedBorder)
                    .frame(maxWidth: .infinity)
            }
            Stepper("Max packet buffer: \(settings.maxPacketBuffer)",
                    value: $settings.maxPacketBuffer, in: 1_000...1_000_000, step: 1_000)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private var backendCard: some View {
        card("Capture backend", systemImage: "arrow.triangle.branch") {
            Picker("Source", selection: $settings.selectedCaptureBackend) {
                ForEach(CaptureBackend.availableBackends) { backend in
                    Text(backend.displayName).tag(backend)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: .infinity)

            Text(settings.selectedCaptureBackend.detail)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            tunnelBuildStatus

            if settings.selectedCaptureBackend == .tunnel {
                Label("SNI/DNS L7 analytics active (see Statistics). Full online tunnel forwarding needs the Network Extension.",
                      systemImage: "sparkle.magnifyingglass")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var tunnelBuildStatus: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label {
                Text(settings.tunnelBuildTitle)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(AppColors.textPrimary)
            } icon: {
                Image(systemName: settings.supportsTunnelCapture ? "checkmark.seal.fill" : "lock.slash")
                    .foregroundStyle(settings.supportsTunnelCapture ? AppColors.success : AppColors.warning)
            }

            Text(settings.tunnelBuildDetail)
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            Label("Tunnel mode is IP-only: Ethernet headers and ARP stay available only in libpcap / BPF mode.",
                  systemImage: "info.circle")
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppColors.tertiary.opacity(0.45),
                    in: RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .strokeBorder(AppColors.borderLight, lineWidth: 1)
        )
    }

    private func settingPicker(
        _ title: String,
        selection: Binding<Int>,
        values: [String]
    ) -> some View {
        LabeledContent {
            Picker(title, selection: selection) {
                ForEach(Array(values.enumerated()), id: \.offset) { index, value in
                    Text(value).tag(index)
                }
            }
            .labelsHidden()
            .frame(maxWidth: 170)
            // Pin light scheme so Picker text stays visible on the light card under forced .dark.
            .environment(\.colorScheme, .light)
        } label: {
            Text(title)
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
        }
    }

    private func settingToggle(_ title: String, isOn: Binding<Bool>) -> some View {
        HStack(spacing: 10) {
            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
            Text(title)
                .font(.caption)
                .foregroundStyle(AppColors.textPrimary)
                .lineLimit(1)
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func copyBpfSetupNote() {
        let note = """
        WareHound BPF capture setup

        Live libpcap capture on macOS needs read/write access to /dev/bpf*.

        Recommended:
        1. Install Wireshark's ChmodBPF helper.
        2. Add your macOS user to the access_bpf group.
        3. Log out and log back in.
        4. Reopen WareHound and press Settings > BPF access > Refresh.

        Development fallback:
        sudo ./WareHound.app/Contents/MacOS/WareHound

        Check current devices:
        ls -l /dev/bpf*
        """
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(note, forType: .string)
    }
}
