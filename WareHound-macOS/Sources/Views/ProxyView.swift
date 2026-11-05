import SwiftUI

struct ProxyView: View {
    @Bindable var viewModel: ProxyViewModel
    @State private var selection: HttpTransaction.ID?
    @State private var detail: ProxyDetail?

    private var selected: HttpTransaction? {
        guard let selection else { return nil }
        return viewModel.transactions.first { $0.id == selection }
    }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            if viewModel.systemProxyNeedsRestore && !viewModel.routesSystemProxy {
                restoreBanner
                Divider()
            }
            safetyNotice
            Divider()
            VSplitView {
                transactionTable.frame(minHeight: 220)
                detailPane.frame(minHeight: 180)
            }
            Divider()
            statusBar
        }
        // Reload when the selected row changes or receives more bytes.
        .task(id: selected.map { DetailKey(id: $0.id, version: $0.version) }) {
            guard let transaction = selected else {
                detail = nil
                return
            }
            let loaded = await Task.detached(priority: .userInitiated) { ProxyDetail.load(transaction) }.value
            if !Task.isCancelled { detail = loaded }
        }
    }

    private var toolbar: some View {
        HStack(spacing: 10) {
            Text("127.0.0.1")
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(AppColors.textSecondary)
            TextField("Port", value: $viewModel.listenPort, format: .number.grouping(.never))
                .textFieldStyle(.roundedBorder)
                .frame(width: 86)
                .disabled(viewModel.isRunning)

            Button { viewModel.toggle() } label: {
                Label(viewModel.isRunning ? "Stop Proxy" : "Start Proxy",
                      systemImage: viewModel.isRunning ? "stop.fill" : "play.fill")
            }
            .buttonStyle(.borderedProminent)
            .tint(viewModel.isRunning ? AppColors.error : AppColors.success)

            Button("Clear") {
                viewModel.clear()
                selection = nil
            }
            .buttonStyle(.bordered)
            .disabled(viewModel.transactions.isEmpty)

            Button { viewModel.copyShellConfiguration() } label: {
                Label("Copy Setup", systemImage: "doc.on.doc")
            }
            .buttonStyle(.bordered)

            Toggle("Route this Mac", isOn: Binding(
                get: { viewModel.routesSystemProxy },
                set: { viewModel.setSystemRouting($0) }))
                .toggleStyle(.switch)
                .controlSize(.small)
                .disabled(!viewModel.isRunning || viewModel.isChangingSystemProxy)
                .help("Points the HTTP and HTTPS system proxy at WareHound so browsers and most apps use it. Your previous settings are restored when the proxy stops or WareHound quits.")

            if viewModel.isChangingSystemProxy {
                ProgressView().controlSize(.small)
            }

            Spacer()

            TextField("Filter app, host, method, URL, status", text: $viewModel.filterText)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 280)
        }
        .padding(8)
    }

    private var restoreBanner: some View {
        HStack(spacing: 8) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(AppColors.warning)
            Text("This Mac's proxy settings still point at WareHound from an earlier session. Web traffic fails while the proxy is stopped.")
                .font(.caption)
                .foregroundStyle(AppColors.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            Button("Restore Settings") { viewModel.restoreSystemProxy() }
                .controlSize(.small)
                .disabled(viewModel.isChangingSystemProxy)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(AppColors.warning.opacity(0.12))
    }

    private var safetyNotice: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "lock.shield")
                .foregroundStyle(AppColors.accent)
            Text("Explicit proxy, bound to this Mac only. HTTP exchanges are decoded in memory (up to 1 MB per message). HTTPS is forwarded as a CONNECT tunnel; WareHound shows its destination and byte counts without installing a CA or intercepting credentials. Use SSLKEYLOGFILE capture when HTTPS payload inspection is required.")
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(AppColors.tertiary.opacity(0.45))
    }

    private var transactionTable: some View {
        Table(viewModel.filteredTransactions, selection: $selection) {
            TableColumn("#") { transaction in
                Text("\(transaction.id)").font(.system(size: 11, design: .monospaced))
            }
            .width(min: 36, ideal: 46, max: 70)
            TableColumn("App") { transaction in
                AppLabel(app: viewModel.app(for: transaction))
            }
            .width(min: 80, ideal: 120)
            TableColumn("Kind") { transaction in
                Label(transaction.isTunnel ? "HTTPS tunnel" : "HTTP",
                      systemImage: transaction.isTunnel ? "lock.fill" : "doc.text.magnifyingglass")
                    .font(.system(size: 11))
                    .foregroundStyle(transaction.isTunnel ? AppColors.accent : AppColors.textPrimary)
            }
            .width(min: 90, ideal: 115)
            TableColumn("Method") { transaction in
                Text(transaction.method).font(.system(size: 11, weight: .semibold, design: .monospaced))
            }
            .width(min: 55, ideal: 70)
            TableColumn("Destination") { transaction in
                Text(transaction.server).font(.system(size: 11, design: .monospaced)).lineLimit(1)
            }
            .width(min: 120, ideal: 200)
            TableColumn("Target") { transaction in
                Text(transaction.target).font(.system(size: 11, design: .monospaced)).lineLimit(1)
            }
            .width(min: 140, ideal: 280)
            TableColumn("Status") { transaction in
                Text(ProxyViewModel.statusText(transaction))
                    .font(.system(size: 11, weight: .semibold, design: .monospaced))
                    .foregroundStyle(statusColor(transaction))
                    .help(transaction.error)
            }
            .width(min: 50, ideal: 65)
            TableColumn("Up") { transaction in
                Text(bytes(transaction.requestBytes)).font(.system(size: 11, design: .monospaced))
            }
            .width(min: 55, ideal: 70)
            TableColumn("Down") { transaction in
                Text(bytes(transaction.responseBytes)).font(.system(size: 11, design: .monospaced))
            }
            .width(min: 55, ideal: 70)
            TableColumn("Time") { transaction in
                Text(timeText(transaction))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(AppColors.textSecondary)
            }
            .width(min: 55, ideal: 70)
        }
        .overlay {
            if viewModel.filteredTransactions.isEmpty {
                ContentUnavailableView(
                    viewModel.isRunning ? "Waiting for proxied traffic" : "Proxy is stopped",
                    systemImage: "arrow.left.arrow.right",
                    description: Text("Start the proxy, then turn on Route this Mac for browsers and most apps, or point a terminal at \(viewModel.proxyURL) with Copy Setup.")
                )
            }
        }
    }

    @ViewBuilder
    private var detailPane: some View {
        if let transaction = selected {
            if transaction.isTunnel {
                VStack(spacing: 10) {
                    Image(systemName: "lock.fill").font(.title2).foregroundStyle(AppColors.accent)
                    Text("Encrypted tunnel to \(transaction.server)").font(.headline)
                    Text("\(bytes(transaction.requestBytes)) sent · \(bytes(transaction.responseBytes)) received")
                        .font(.caption.monospaced())
                        .foregroundStyle(AppColors.textSecondary)
                    Text("The proxy forwards TLS unchanged. Capture the relevant interface with an SSLKEYLOGFILE to inspect supported HTTPS sessions without trusting a WareHound root certificate.")
                        .font(.caption)
                        .foregroundStyle(AppColors.textSecondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 520)
                    if !transaction.error.isEmpty {
                        Text(transaction.error).font(.caption).foregroundStyle(AppColors.error).textSelection(.enabled)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                HSplitView {
                    messagePane(title: "Request", text: detail?.request, truncated: false, error: "")
                    messagePane(title: "Response", text: detail?.response,
                                truncated: transaction.isTruncated, error: transaction.error)
                }
            }
        } else {
            Text("Select a proxied request to inspect it")
                .foregroundStyle(AppColors.textSecondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    private func messagePane(title: String, text: String?, truncated: Bool, error: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(title).font(.system(size: 11, weight: .semibold))
                if !error.isEmpty {
                    Text(error)
                        .font(.caption)
                        .foregroundStyle(AppColors.error)
                        .lineLimit(1)
                        .help(error)
                }
                Spacer()
                if truncated {
                    Label("Stored bytes limited", systemImage: "scissors")
                        .font(.caption)
                        .foregroundStyle(AppColors.warning)
                }
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 6)
            Divider()
            ScrollView {
                Text(text ?? "Loading…")
                    .font(.system(size: 11, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
                    .padding(8)
            }
            .background(Color(nsColor: .textBackgroundColor))
        }
        .frame(minWidth: 260, maxWidth: .infinity, maxHeight: .infinity)
    }

    private func timeText(_ transaction: HttpTransaction) -> String {
        if transaction.isTunnel && !transaction.isComplete && transaction.error.isEmpty { return "open" }
        return transaction.durationMs.map { "\($0) ms" } ?? "…"
    }

    private func bytes(_ count: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: count, countStyle: .file)
    }

    private func statusColor(_ transaction: HttpTransaction) -> Color {
        if !transaction.error.isEmpty { return AppColors.error }
        switch transaction.statusClass {
        case 2: return AppColors.success
        case 3: return AppColors.accent
        case 4: return AppColors.warning
        case 5: return AppColors.error
        default: return AppColors.textSecondary
        }
    }

    private var statusBar: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(viewModel.isRunning ? AppColors.success : AppColors.textDisabled)
                .frame(width: 7, height: 7)
            Text(viewModel.status).font(.caption).foregroundStyle(AppColors.textSecondary)
            Spacer()
            Text("\(viewModel.transactions.count) exchanges")
                .font(.caption.monospacedDigit())
                .foregroundStyle(AppColors.textSecondary)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
    }
}

private struct DetailKey: Hashable {
    let id: UInt64
    let version: UInt64
}

/// Request/response text for the detail pane, read from libsniffer off the main thread.
private struct ProxyDetail: Sendable {
    var request: String
    var response: String

    private static let displayLimit = 256 * 1024
    private static let redactedHeaders: Set<String> = ["authorization", "proxy-authorization", "cookie", "set-cookie"]

    static func load(_ transaction: HttpTransaction) -> ProxyDetail {
        ProxyDetail(request: text(transaction, response: false), response: text(transaction, response: true))
    }

    private static func text(_ transaction: HttpTransaction, response: Bool) -> String {
        let head = NativeHttp.head(id: transaction.id, response: response)
        let body = NativeHttp.body(id: transaction.id, response: response, decoded: true) ?? Data()
        var lines: [String] = []
        if let head, !head.startLine.isEmpty {
            lines.append(head.startLine)
            lines += head.fields.map { field in
                redactedHeaders.contains(field.name.lowercased()) ? "\(field.name): <redacted>" : "\(field.name): \(field.value)"
            }
        }
        let headText = lines.joined(separator: "\n")
        let bodyText = render(body)
        if headText.isEmpty { return bodyText.isEmpty ? "Waiting for data…" : bodyText }
        return bodyText.isEmpty ? headText : headText + "\n\n" + bodyText
    }

    private static func render(_ data: Data) -> String {
        guard !data.isEmpty else { return "" }
        let shown = data.prefix(displayLimit)
        var text = isMostlyText(shown) ? String(decoding: shown, as: UTF8.self) : hexDump(shown)
        if data.count > shown.count {
            text += "\n\n… \(ByteCountFormatter.string(fromByteCount: Int64(data.count - shown.count), countStyle: .file)) more not shown"
        }
        return text
    }

    private static func isMostlyText(_ data: Data) -> Bool {
        let readable = data.reduce(into: 0) { count, byte in
            if byte == 9 || byte == 10 || byte == 13 || byte >= 32 { count += 1 }
        }
        return Double(readable) / Double(data.count) >= 0.85
    }

    private static func hexDump(_ data: Data) -> String {
        stride(from: 0, to: data.count, by: 16).map { offset in
            let end = min(offset + 16, data.count)
            let slice = data[data.startIndex + offset..<data.startIndex + end]
            let hex = slice.map { String(format: "%02x", $0) }.joined(separator: " ")
            return String(format: "%08x  %@", offset, hex)
        }.joined(separator: "\n")
    }
}
