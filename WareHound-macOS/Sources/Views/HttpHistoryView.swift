import AppKit
import SwiftUI
import WebKit

extension PacketFlag {
    var color: Color {
        switch self {
        case .red: .red
        case .orange: .orange
        case .yellow: .yellow
        case .green: .green
        case .blue: .blue
        case .purple: .purple
        }
    }
}

struct FlagMenu: View {
    let current: PacketFlag?
    let set: (PacketFlag?) -> Void

    var body: some View {
        Menu("Flag") {
            ForEach(PacketFlag.allCases, id: \.self) { flag in
                Button {
                    set(flag)
                } label: {
                    Label(flag.rawValue, systemImage: current == flag ? "flag.fill" : "flag")
                }
            }
            if current != nil {
                Divider()
                Button("Remove Flag") { set(nil) }
            }
        }
    }
}

struct AppLabel: View {
    let app: AppIdentity?

    nonisolated(unsafe) private static var iconCache: [String: NSImage] = [:]

    var body: some View {
        HStack(spacing: 5) {
            icon.frame(width: 14, height: 14)
            Text(app?.name ?? "—")
                .font(.system(size: 11))
                .foregroundStyle(app == nil ? AppColors.textSecondary : AppColors.textPrimary)
                .lineLimit(1)
                .truncationMode(.tail)
        }
    }

    @ViewBuilder
    private var icon: some View {
        if let path = app?.bundlePath {
            Image(nsImage: Self.icon(for: path)).resizable().interpolation(.high)
        } else if app?.isContainer == true {
            Image(systemName: "shippingbox.fill").font(.system(size: 11)).foregroundStyle(AppColors.accent)
        } else if app != nil {
            Image(systemName: "terminal").font(.system(size: 11)).foregroundStyle(AppColors.textSecondary)
        } else {
            Color.clear
        }
    }

    static func icon(for path: String) -> NSImage {
        if let cached = iconCache[path] { return cached }
        let image = NSWorkspace.shared.icon(forFile: path)
        iconCache[path] = image
        return image
    }
}

struct QuickFilterBar: View {
    @Bindable var viewModel: CaptureViewModel

    var body: some View {
        HStack(spacing: 6) {
            ForEach(QuickFilter.allCases, id: \.self) { filter in
                chip(filter.rawValue, count: count(filter), selected: viewModel.quickFilter == filter,
                     color: chipColor(filter)) {
                    viewModel.quickFilter = filter
                }
            }

            Divider().frame(height: 16)

            Menu {
                Button("All Apps") { viewModel.appFilter = nil }
                Divider()
                ForEach(viewModel.appStats.filter { !$0.isUnresolved }) { stat in
                    Button {
                        viewModel.appFilter = stat.app.name
                    } label: {
                        if let path = stat.app.bundlePath {
                            Label { Text(appMenuTitle(stat)) } icon: { Image(nsImage: menuIcon(path)) }
                        } else {
                            Label(appMenuTitle(stat), systemImage: "terminal")
                        }
                    }
                }
                let counted = Set(viewModel.appStats.map(\.app.name))
                ForEach(viewModel.knownApps.subtracting(counted).sorted(), id: \.self) { name in
                    Button(name) { viewModel.appFilter = name }
                }
            } label: {
                Label(viewModel.appFilter ?? "Apps", systemImage: "app.badge")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .foregroundStyle(viewModel.appFilter == nil ? AppColors.textPrimary : AppColors.accent)

            Menu {
                Button("All Hosts") { viewModel.hostFilter = nil }
                Divider()
                ForEach(viewModel.knownHosts.sorted().prefix(300), id: \.self) { host in
                    Button(host) { viewModel.hostFilter = host }
                }
            } label: {
                Label(viewModel.hostFilter ?? "Hosts", systemImage: "globe")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .foregroundStyle(viewModel.hostFilter == nil ? AppColors.textPrimary : AppColors.accent)

            if viewModel.quickFilter != .all || viewModel.appFilter != nil || viewModel.hostFilter != nil {
                Button {
                    viewModel.quickFilter = .all
                    viewModel.appFilter = nil
                    viewModel.hostFilter = nil
                } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppColors.textSecondary)
                .help("Clear quick filters")
            }
            Spacer()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
    }

    private func chipColor(_ filter: QuickFilter) -> Color {
        switch filter {
        case .status2xx: AppColors.success
        case .status3xx: AppColors.accentLight
        case .status4xx: AppColors.warning
        case .status5xx: AppColors.error
        case .flagged: .orange
        default: AppColors.accent
        }
    }

    private func count(_ filter: QuickFilter) -> Int? {
        let s = viewModel.httpSummary
        switch filter {
        case .all: return nil
        case .http: return s.http
        case .json: return s.json
        case .html: return s.html
        case .status2xx: return s.status2xx
        case .status3xx: return s.status3xx
        case .status4xx: return s.status4xx
        case .status5xx: return s.status5xx
        case .flagged: return viewModel.flags.count
        }
    }

    private func appMenuTitle(_ stat: AppStat) -> String {
        "\(stat.app.name) · \(stat.packets.formatted()) pkts · "
            + ByteCountFormatter.string(fromByteCount: stat.totalBytes, countStyle: .file)
    }

    private func menuIcon(_ path: String) -> NSImage {
        let image = (AppLabel.icon(for: path).copy() as? NSImage) ?? NSImage()
        image.size = NSSize(width: 16, height: 16)
        return image
    }

    private func chip(_ title: String, count: Int?, selected: Bool, color: Color,
                      action: @escaping () -> Void) -> some View {
        let empty = count == 0 && !selected
        return Button(action: action) {
            HStack(spacing: 4) {
                Text(title)
                if let count {
                    Text(count.formatted())
                        .font(.system(size: 10, weight: .semibold, design: .rounded))
                        .foregroundStyle(selected ? .white.opacity(0.85) : AppColors.textSecondary)
                }
            }
            .font(.system(size: 11, weight: selected ? .semibold : .regular))
            .foregroundStyle(selected ? .white : AppColors.textPrimary)
            .padding(.horizontal, 9)
            .padding(.vertical, 3)
            .background(selected ? color : AppColors.tertiary, in: Capsule())
            .opacity(empty ? 0.45 : 1)
        }
        .buttonStyle(.plain)
    }
}

struct HttpHistoryView: View {
    @Bindable var viewModel: CaptureViewModel
    let onFollowStream: (HttpTransaction) -> Void
    @State private var selection: HttpTransaction.ID?

    private var selected: HttpTransaction? {
        guard let selection else { return nil }
        return viewModel.filteredTransactions.first { $0.id == selection }
    }

    var body: some View {
        VSplitView {
            table
                .frame(minHeight: 160)
            panes
                .frame(minHeight: 140)
        }
    }

    private var table: some View {
        Table(viewModel.filteredTransactions, selection: $selection) {
            TableColumn("#") { t in
                Text("\(t.id)").font(.system(size: 11, design: .monospaced))
            }
            .width(min: 36, ideal: 48, max: 70)
            TableColumn("Fl.") { t in
                let flag = viewModel.flags[t.requestFrame]
                Button {
                    viewModel.setFlag(flag == nil ? .red : nil, for: t.requestFrame)
                } label: {
                    Image(systemName: flag == nil ? "flag" : "flag.fill")
                        .font(.system(size: 9))
                        .foregroundStyle(flag?.color ?? AppColors.textDisabled.opacity(0.6))
                }
                .buttonStyle(.plain)
                .help(flag == nil ? "Flag (right-click for colours)" : "Remove flag")
            }
            .width(26)
            TableColumn("App") { t in
                AppLabel(app: viewModel.app(for: t))
            }
            .width(min: 80, ideal: 130)
            TableColumn("Host") { t in
                Text(t.host).font(.system(size: 11)).lineLimit(1)
            }
            .width(min: 90, ideal: 180)
            TableColumn("Method") { t in
                Text(t.method).font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(t.kind == .tls ? AppColors.textSecondary : AppColors.textPrimary)
            }
            .width(min: 44, ideal: 60, max: 90)
            TableColumn("URL") { t in
                HStack(spacing: 4) {
                    if t.kind == .https {
                        Image(systemName: "lock.open.fill").font(.system(size: 9)).foregroundStyle(AppColors.success)
                    }
                    Text(urlText(t))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(t.kind == .tls ? AppColors.textSecondary : AppColors.textPrimary)
                        .lineLimit(1)
                }
            }
            .width(min: 120, ideal: 280)
            TableColumn("Status") { t in
                Text(statusText(t))
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(statusColor(t))
            }
            .width(min: 44, ideal: 56, max: 80)
            TableColumn("Type") { t in
                Text(shortType(t.contentType)).font(.system(size: 11)).lineLimit(1)
                    .foregroundStyle(AppColors.textSecondary)
            }
            .width(min: 50, ideal: 90)
            TableColumn("Length") { t in
                Text(t.kind == .tls ? "—" : ByteCountFormatter.string(fromByteCount: t.responseBytes, countStyle: .file))
                    .font(.system(size: 11, design: .monospaced))
            }
            .width(min: 50, ideal: 70)
            TableColumn("Time") { t in
                Text(t.durationMs.map { "\($0) ms" } ?? "—").font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(AppColors.textSecondary)
            }
            .width(min: 50, ideal: 64)
        }
        .contextMenu(forSelectionType: HttpTransaction.ID.self) { ids in
            if let id = ids.first, let t = viewModel.filteredTransactions.first(where: { $0.id == id }) {
                FlagMenu(current: viewModel.flags[t.requestFrame]) { viewModel.setFlag($0, for: t.requestFrame) }
                if let app = viewModel.app(for: t) {
                    Button("Filter by App “\(app.name)”") { viewModel.appFilter = app.name }
                }
                Button("Filter by Host “\(t.host)”") { viewModel.hostFilter = t.host }
                Divider()
                Button("Follow Stream") { onFollowStream(t) }
                Divider()
                Button("Copy URL") { copy(t.url) }
                Button("Copy Host") { copy(t.host) }
            }
        }
        .overlay {
            if viewModel.filteredTransactions.isEmpty {
                VStack(spacing: 6) {
                    Image(systemName: "globe").font(.system(size: 28)).foregroundStyle(AppColors.textSecondary)
                    Text("No HTTP traffic yet").font(.headline).foregroundStyle(AppColors.textPrimary)
                    Text("Plain HTTP exchanges appear with request and response. HTTPS connections are listed by host; decrypt them via Follow Stream with an SSLKEYLOGFILE.")
                        .font(.caption)
                        .foregroundStyle(AppColors.textSecondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 420)
                }
            }
        }
    }

    @ViewBuilder
    private var panes: some View {
        if let t = selected {
            if t.kind == .tls {
                VStack(spacing: 8) {
                    Image(systemName: "lock.fill").font(.title2).foregroundStyle(AppColors.accent)
                    Text("Encrypted connection to \(t.host)").font(.headline)
                    Text("\(t.client) → \(t.server)").font(.caption.monospaced()).foregroundStyle(AppColors.textSecondary)
                    Text(tlsHint(t))
                        .font(.caption)
                        .foregroundStyle(AppColors.textSecondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 420)
                    Button("Follow Stream…") { onFollowStream(t) }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HSplitView {
                    MessagePane(title: "Request", viewModel: viewModel, transaction: t, response: false)
                    MessagePane(title: "Response", viewModel: viewModel, transaction: t, response: true)
                }
            }
        } else {
            Text("Select a request to see its details")
                .foregroundStyle(AppColors.textSecondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func urlText(_ t: HttpTransaction) -> String {
        guard t.kind == .tls else { return t.target }
        if t.reason.hasPrefix("decrypted") { return "TLS connection · \(t.reason)" }
        return "Encrypted (\(t.reason.isEmpty ? "TLS" : t.reason))"
    }

    private func tlsHint(_ t: HttpTransaction) -> String {
        if SettingsViewModel.shared.tlsKeylogPath.isEmpty {
            return "To see the requests inside, set a TLS key log in Settings → HTTPS decryption and start the app with SSLKEYLOGFILE."
        }
        if t.reason.hasPrefix("decrypted") {
            return "Decrypted — its requests are listed as separate rows with a green lock."
        }
        return "Not decrypted yet: \(t.reason). The app must write its keys to the key log file, and the connection must start after the key log was set."
    }

    private func statusText(_ t: HttpTransaction) -> String {
        if t.kind == .tls { return "—" }
        return t.status > 0 ? "\(t.status)" : "…"
    }

    private func statusColor(_ t: HttpTransaction) -> Color {
        switch t.statusClass {
        case 2: AppColors.success
        case 3: AppColors.accentLight
        case 4: AppColors.warning
        case 5: AppColors.error
        default: AppColors.textSecondary
        }
    }

    private func shortType(_ contentType: String) -> String {
        let base = contentType.split(separator: ";").first.map(String.init) ?? ""
        return base.split(separator: "/").last.map(String.init) ?? base
    }

    private func copy(_ string: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(string, forType: .string)
    }
}

private struct MessagePane: View {
    enum Mode: String, CaseIterable { case text = "Text", hex = "Hex", list = "List", html = "HTML" }

    let title: String
    let viewModel: CaptureViewModel
    let transaction: HttpTransaction
    let response: Bool
    @State private var mode: Mode = .text
    @State private var head: HttpHead?
    @State private var bodyData = Data()
    @State private var raw = Data()

    private static let maxBodyLines = 5_000
    private static let maxBodyBytes = 512 * 1024

    private var modes: [Mode] {
        response && transaction.isHTML ? Mode.allCases : [.text, .hex, .list]
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Picker("", selection: $mode) {
                    ForEach(modes, id: \.self) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                Spacer()
                Text(title).font(.system(size: 11, weight: .semibold)).foregroundStyle(AppColors.textSecondary)
                if transaction.isTruncated {
                    Label("Truncated", systemImage: "scissors").font(.caption).foregroundStyle(AppColors.warning)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            Divider()
            content
        }
        .frame(minWidth: 240, maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(nsColor: .textBackgroundColor))
        .task(id: "\(transaction.id)-\(transaction.version)-\(response)") {
            head = viewModel.httpHead(transaction, response: response)
            bodyData = viewModel.httpBody(transaction, response: response) ?? Data()
            raw = viewModel.httpMessage(transaction, response: response, decoded: false) ?? Data()
            if !modes.contains(mode) { mode = .text }
        }
    }

    @ViewBuilder
    private var content: some View {
        if head == nil {
            Text(response ? "No response captured yet." : "No request captured.")
                .foregroundStyle(AppColors.textSecondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            switch mode {
            case .text: numberedText
            case .hex: hexText
            case .list: headerList
            case .html: HTMLPreview(html: String(decoding: bodyData.prefix(Self.maxBodyBytes), as: UTF8.self))
            }
        }
    }

    // MARK: Text

    private struct Line: Identifiable {
        let id: Int
        let text: AttributedString
    }

    private var lines: [Line] {
        guard let head else { return [] }
        var out: [AttributedString] = [startLine(head.startLine)]
        for field in head.fields {
            var name = AttributedString(field.name)
            name.foregroundColor = AppColors.accent
            var colon = AttributedString(": ")
            colon.foregroundColor = AppColors.textPrimary
            var value = AttributedString(field.value)
            value.foregroundColor = Color.purple
            out.append(name + colon + value)
        }
        out.append(AttributedString(""))
        out.append(contentsOf: bodyLines())
        return out.enumerated().map { Line(id: $0.offset, text: $0.element) }
    }

    private func startLine(_ line: String) -> AttributedString {
        let parts = line.split(separator: " ", maxSplits: 2).map(String.init)
        var result = AttributedString()
        for (i, part) in parts.enumerated() {
            var token = AttributedString(part)
            if response {
                token.foregroundColor = i == 0 ? AppColors.accent : statusColor
            } else {
                token.foregroundColor = i == 0 ? AppColors.accent : (i == 2 ? AppColors.success : AppColors.textPrimary)
            }
            if i > 0 { result += AttributedString(" ") }
            result += token
        }
        return result
    }

    private var statusColor: Color {
        switch transaction.statusClass {
        case 2: AppColors.accent
        case 3: AppColors.accentLight
        case 4: AppColors.warning
        case 5: AppColors.error
        default: AppColors.textPrimary
        }
    }

    private func bodyLines() -> [AttributedString] {
        guard !bodyData.isEmpty else { return [] }
        let sample = bodyData.prefix(4096)
        let control = sample.filter { $0 < 0x09 || ($0 > 0x0D && $0 < 0x20) }.count
        if control > sample.count / 10 {
            var note = AttributedString("[binary body, \(bodyData.count) bytes — see Hex]")
            note.foregroundColor = AppColors.textSecondary
            return [note]
        }
        let text = String(decoding: bodyData.prefix(Self.maxBodyBytes), as: UTF8.self)
        var result = text.split(separator: "\n", omittingEmptySubsequences: false)
            .prefix(Self.maxBodyLines)
            .map { AttributedString($0.hasSuffix("\r") ? String($0.dropLast()) : String($0)) }
        if bodyData.count > Self.maxBodyBytes {
            var more = AttributedString("… \(bodyData.count - Self.maxBodyBytes) more bytes")
            more.foregroundColor = AppColors.textSecondary
            result.append(more)
        }
        return result
    }

    private var numberedText: some View {
        let all = lines
        let gutter = CGFloat(max(2, String(all.count).count)) * 8 + 6
        return ScrollView(.vertical) {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(all) { line in
                    HStack(alignment: .top, spacing: 10) {
                        Text("\(line.id + 1)")
                            .foregroundStyle(AppColors.textSecondary)
                            .frame(width: gutter, alignment: .trailing)
                        Text(line.text)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .font(.system(size: 12, design: .monospaced))
            .padding(8)
        }
    }

    // MARK: Hex

    private var hexText: some View {
        ScrollView([.vertical, .horizontal]) {
            Text(hexDump)
                .font(.system(size: 11, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .padding(8)
        }
    }

    private var hexDump: String {
        let data = raw.prefix(64 * 1024)
        var out: [String] = []
        var offset = 0
        while offset < data.count {
            let row = data[data.startIndex + offset ..< data.startIndex + min(offset + 16, data.count)]
            let hex = row.map { String(format: "%02x", $0) }.joined(separator: " ")
            let ascii = String(row.map { $0 >= 0x20 && $0 < 0x7F ? Character(UnicodeScalar($0)) : "." })
            out.append(String(format: "%08x  ", offset) + hex.padding(toLength: 48, withPad: " ", startingAt: 0) + "  " + ascii)
            offset += 16
        }
        if raw.count > data.count { out.append("… \(raw.count - data.count) more bytes") }
        return out.isEmpty ? "—" : out.joined(separator: "\n")
    }

    // MARK: List

    private var headerList: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(head.map { startLine($0.startLine) } ?? AttributedString())
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
                .padding(8)
            Table(head?.fields ?? []) {
                TableColumn("Key") { f in
                    Text(f.name).foregroundStyle(AppColors.accent).textSelection(.enabled)
                }
                .width(min: 80, ideal: 160, max: 260)
                TableColumn("Value") { f in
                    Text(f.value).foregroundStyle(Color.purple).textSelection(.enabled)
                }
            }
            .font(.system(size: 12, design: .monospaced))
        }
    }
}

// Renders captured HTML offline: JavaScript off and every network/file load blocked,
// so viewing a page never contacts its servers.
private struct HTMLPreview: NSViewRepresentable {
    let html: String

    private static let blockRules = """
    [{"trigger": {"url-filter": "^(https?|wss?|ftp|file):"}, "action": {"type": "block"}}]
    """

    func makeNSView(context: Context) -> WKWebView {
        let config = WKWebViewConfiguration()
        config.defaultWebpagePreferences.allowsContentJavaScript = false
        config.websiteDataStore = .nonPersistent()
        let view = WKWebView(frame: .zero, configuration: config)
        view.navigationDelegate = context.coordinator
        return view
    }

    func updateNSView(_ view: WKWebView, context: Context) {
        guard context.coordinator.loadedHTML != html else { return }
        context.coordinator.loadedHTML = html
        WKContentRuleListStore.default().compileContentRuleList(
            forIdentifier: "WareHoundOfflinePreview", encodedContentRuleList: Self.blockRules
        ) { list, _ in
            if let list { view.configuration.userContentController.add(list) }
            view.loadHTMLString(html, baseURL: nil)
        }
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator: NSObject, WKNavigationDelegate {
        var loadedHTML: String?

        // Clicking a link must not navigate to the live site.
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping @MainActor (WKNavigationActionPolicy) -> Void) {
            decisionHandler(action.navigationType == .other ? .allow : .cancel)
        }
    }
}
