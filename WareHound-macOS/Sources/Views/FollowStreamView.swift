import SwiftUI
import AppKit

struct FollowStreamView: View {
    let title: String
    let packets: [PacketModel]

    @Environment(\.dismiss) private var dismiss

    @State private var stream: FollowedStream?
    @State private var isLoading = true
    @State private var renderMode: RenderMode = .ascii
    @State private var directionFilter: DirectionFilter = .both
    @State private var keylogPath: String?
    @State private var showDecrypted = false

    private enum RenderMode: String, CaseIterable, Identifiable {
        case ascii = "ASCII", hex = "Hex"
        var id: String { rawValue }
    }
    private enum DirectionFilter: Hashable {
        case both, clientToServer, serverToClient
    }

    // Cap the rendered payload so a huge stream can't stall the UI.
    private static let renderByteCap = 256 * 1024

    private struct GrpcMessage {
        let length: Int
        let compressed: Bool
        let body: [UInt8]
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            controls
            Divider()
            content
            Divider()
            footer
        }
        .frame(width: 720, height: 620)
        .background(AppColors.primary)
        .task { await rebuild() }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            Image(systemName: "arrow.left.arrow.right.circle.fill")
                .font(.title2)
                .foregroundStyle(AppColors.accent)
            VStack(alignment: .leading, spacing: 2) {
                Text("Follow Stream").font(.headline)
                    .foregroundStyle(AppColors.textPrimary)
                Text(title).font(.caption).foregroundStyle(AppColors.textSecondary)
                    .lineLimit(1)
            }
            Spacer()
            if let stream {
                VStack(alignment: .trailing, spacing: 2) {
                    Text(transportLabel(stream.transport)).font(.caption).bold()
                        .foregroundStyle(AppColors.accent)
                    Text("\(stream.segmentCount) segments · \(stream.gapCount) gaps")
                        .font(.caption2).foregroundStyle(AppColors.textSecondary)
                }
            }
        }
        .padding(14)
        .background(AppColors.secondary)
    }

    // MARK: - Controls

    private var controls: some View {
        VStack(spacing: 8) {
            HStack(spacing: 10) {
                Picker("", selection: $renderMode) {
                    ForEach(RenderMode.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 140)

                Picker("", selection: $directionFilter) {
                    Text("Both").tag(DirectionFilter.both)
                    Text("\(endpointShort(isClient: true)) →").tag(DirectionFilter.clientToServer)
                    Text("← \(endpointShort(isClient: false))").tag(DirectionFilter.serverToClient)
                }
                .pickerStyle(.segmented).labelsHidden().frame(maxWidth: 320)

                Spacer()

                if let stream, stream.hasDecryptedData {
                    Toggle("Decrypted", isOn: $showDecrypted)
                        .toggleStyle(.button)
                        .tint(AppColors.success)
                }
            }

            if let stream, stream.transport == .tcp {
                tlsBar(stream)
            }
            if let stream, stream.isHttp2 {
                http2Bar(stream)
                if !stream.h2Headers.isEmpty { http2Headers(stream) }
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(AppColors.primary)
    }

    @ViewBuilder
    private func http2Bar(_ stream: FollowedStream) -> some View {
        HStack(spacing: 8) {
            Image(systemName: stream.isGrpc ? "shippingbox.circle.fill" : "bolt.horizontal.circle")
                .font(.caption).foregroundStyle(AppColors.accent)
            Text(stream.isGrpc ? "gRPC" : "HTTP/2").font(.caption).bold()
                .foregroundStyle(AppColors.textPrimary)
            if !stream.grpcMethod.isEmpty {
                Text(stream.grpcMethod).font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(AppColors.accent).lineLimit(1)
            } else if stream.h2HeadersFrames == 0 {
                // :method/:path come only in the initial HEADERS frame, missed by mid-connection captures.
                Text("method unknown — capture started mid-connection")
                    .font(.caption2).italic().foregroundStyle(AppColors.warning).lineLimit(1)
                    .help("Restart the client (or the capture) so the connection's opening HEADERS are captured, then Follow Stream again.")
            }
            if !stream.httpStatus.isEmpty {
                Text("· status \(stream.httpStatus)").font(.caption2).foregroundStyle(AppColors.textSecondary)
            }
            if !stream.grpcStatus.isEmpty {
                let ok = stream.grpcStatus == "0"
                Text("· grpc \(grpcStatusName(stream.grpcStatus))")
                    .font(.caption2).bold()
                    .foregroundStyle(ok ? AppColors.success : AppColors.warning)
                    .help(stream.grpcMessage.isEmpty ? "grpc-status: \(stream.grpcStatus)"
                                                     : "grpc-status: \(stream.grpcStatus) — \(stream.grpcMessage)")
            } else if stream.isGrpc {
                Text("· grpc status not captured")
                    .font(.caption2).bold()
                    .foregroundStyle(AppColors.warning)
                    .help("The stream has gRPC HEADERS/DATA, but no trailing HEADERS with grpc-status were captured.")
            }
            Spacer()
            Text("\(stream.h2HeadersFrames) hdrs · \(stream.h2DataFrames) data · \(stream.grpcMessages) msg · \(stream.grpcBytes)B")
                .font(.caption2).monospacedDigit().foregroundStyle(AppColors.textSecondary)
        }
        .padding(.horizontal, 10).padding(.vertical, 5)
        .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 7, style: .continuous))
        .help(stream.contentType.isEmpty ? "HTTP/2 stream" : "content-type: \(stream.contentType)")
    }

    @ViewBuilder
    private func http2Headers(_ stream: FollowedStream) -> some View {
        DisclosureGroup {
            Text(stream.h2Headers.trimmingCharacters(in: .whitespacesAndNewlines))
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(AppColors.textPrimary)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(8)
                .background(AppColors.secondary, in: RoundedRectangle(cornerRadius: 6))
        } label: {
            Text("HTTP/2 frames (HEADERS · DATA · trailers)").font(.caption).bold()
                .foregroundStyle(AppColors.textSecondary)
        }
    }

    private func grpcStatusName(_ code: String) -> String {
        let names = ["OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED",
                     "NOT_FOUND", "ALREADY_EXISTS", "PERMISSION_DENIED", "RESOURCE_EXHAUSTED",
                     "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED",
                     "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED"]
        if let n = Int(code), n >= 0, n < names.count { return "\(code) \(names[n])" }
        return code
    }

    @ViewBuilder
    private func tlsBar(_ stream: FollowedStream) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "lock.fill").font(.caption).foregroundStyle(AppColors.accent)
            Text("TLS").font(.caption).bold().foregroundStyle(AppColors.textSecondary)

            Button {
                pickKeylog()
            } label: {
                Label(keylogPath == nil ? "Choose SSLKEYLOGFILE…"
                                        : (keylogPath! as NSString).lastPathComponent,
                      systemImage: "key.fill")
                    .font(.caption)
            }
            .buttonStyle(.bordered)

            if keylogPath != nil {
                Button("Decrypt") { Task { await rebuild() } }
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }

            if stream.tlsAttempted {
                Text(stream.tlsStatus)
                    .font(.caption2)
                    .foregroundStyle(stream.hasDecryptedData ? AppColors.success : AppColors.textSecondary)
                    .lineLimit(1)
            }
            Spacer()
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if isLoading {
            VStack { ProgressView("Reassembling…") }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let stream, !stream.isEmpty {
            ScrollView([.vertical]) {
                Text(conversationText(stream))
                    .font(.system(.callout, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(12)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(AppColors.secondary)
        } else {
            VStack(spacing: 6) {
                Text("No stream payload").font(.headline)
                    .foregroundStyle(AppColors.textPrimary)
                Text("This conversation carried no reassembled application-layer bytes.")
                    .font(.caption).foregroundStyle(AppColors.textSecondary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack {
            if let stream {
                Circle().fill(AppColors.error).frame(width: 8, height: 8)
                Text("\(stream.clientEndpoint)  ·  \(byteLabel(clientLen(stream)))")
                    .font(.caption2).foregroundStyle(AppColors.textSecondary)
                Circle().fill(AppColors.accent).frame(width: 8, height: 8).padding(.leading, 6)
                Text("\(stream.serverEndpoint)  ·  \(byteLabel(serverLen(stream)))")
                    .font(.caption2).foregroundStyle(AppColors.textSecondary)
            }
            Spacer()
            Button("Export Protobuf…") { exportProtobufMessages() }
                .disabled(stream.map { grpcMessages($0).isEmpty } ?? true)
            Button("Save Payload…") { savePayload() }
                .disabled(stream?.isEmpty ?? true)
            Button("Close") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .padding(12)
    }

    // MARK: - Rendering

    private func conversationText(_ stream: FollowedStream) -> AttributedString {
        if renderMode == .ascii, let decoded = decodedHttp2Text(stream) {
            var result = AttributedString(decoded)
            result.foregroundColor = AppColors.textPrimary
            return result
        }

        let useDecrypted = showDecrypted && stream.hasDecryptedData
        let chunks = useDecrypted ? stream.plaintextChunks : stream.chunks
        let clientData = useDecrypted ? stream.clientPlaintext : stream.clientBytes
        let serverData = useDecrypted ? stream.serverPlaintext : stream.serverBytes

        var result = AttributedString()
        var rendered = 0

        for chunk in chunks {
            switch directionFilter {
            case .both: break
            case .clientToServer where !chunk.fromClient: continue
            case .serverToClient where chunk.fromClient: continue
            default: break
            }

            let source = chunk.fromClient ? clientData : serverData
            let start = chunk.offset
            let end = min(source.count, chunk.offset + chunk.length)
            guard start < end else { continue }
            let remaining = Self.renderByteCap - rendered
            if remaining <= 0 { break }
            let slice = source.subdata(in: start..<min(end, start + remaining))
            rendered += slice.count

            let text = renderMode == .ascii ? asciiString(slice) : hexBlock(slice)
            var run = AttributedString(text)
            run.foregroundColor = chunk.fromClient ? AppColors.error : AppColors.accent
            result.append(run)
        }

        if rendered >= Self.renderByteCap {
            var note = AttributedString("\n… output truncated at \(byteLabel(Self.renderByteCap)) …\n")
            note.foregroundColor = AppColors.textSecondary
            result.append(note)
        }
        if result.characters.isEmpty {
            var empty = AttributedString("(no bytes in this direction)")
            empty.foregroundColor = AppColors.textSecondary
            return empty
        }
        return result
    }

    private func decodedHttp2Text(_ stream: FollowedStream) -> String? {
        guard stream.isHttp2 else { return nil }

        let transcript = stream.h2Headers.trimmingCharacters(in: .whitespacesAndNewlines)
        if !transcript.isEmpty {
            let protobuf = protobufRawPreviewSection(stream)
            var decoded = sanitizedHttp2Transcript(
                transcript,
                hasProtobufPreview: !protobuf.isEmpty,
                isProbablyTruncated: stream.h2Headers.count >= 4095
            )
            if shouldShowMissingTrailersNote(stream, in: decoded) {
                decoded += "\n\nHEADERS (trailers)\n  grpc-status: not captured"
            }
            if !protobuf.isEmpty {
                decoded += "\n\n" + protobuf
            }
            return decoded + "\n"
        }

        let fallback = synthesizedHttp2Transcript(stream)
        return fallback.isEmpty ? nil : fallback
    }

    private func synthesizedHttp2Transcript(_ stream: FollowedStream) -> String {
        var sections: [String] = []

        var requestLines: [String] = []
        appendHeader(":method", stream.httpMethod, to: &requestLines)
        appendHeader(":scheme", inferredScheme(stream), to: &requestLines)
        appendHeader(":path", stream.grpcMethod, to: &requestLines)
        appendHeader(":authority", stream.authority, to: &requestLines)
        appendHeader("content-type", stream.contentType, to: &requestLines)
        if !requestLines.isEmpty {
            sections.append((["HEADERS"] + requestLines).joined(separator: "\n"))
        }

        if stream.h2DataFrames > 0 || stream.grpcMessages > 0 || stream.grpcBytes > 0 {
            var dataLines = ["DATA"]
            let payloadLabel = stream.grpcBytes > 0 ? "length=\(stream.grpcBytes)" : "length unknown"
            dataLines.append("  (binary payload: \(payloadLabel))")
            let protobuf = protobufRawPreviewSection(stream)
            if !protobuf.isEmpty {
                dataLines.append("")
                dataLines.append(protobuf)
            } else if stream.grpcMessages > 0 {
                let noun = stream.grpcMessages == 1 ? "message" : "messages"
                dataLines.append("  \(stream.grpcMessages) gRPC \(noun)")
            }
            sections.append(dataLines.joined(separator: "\n"))
        }

        var trailerLines: [String] = []
        appendHeader("grpc-status", stream.grpcStatus, to: &trailerLines)
        if !stream.grpcStatus.isEmpty {
            appendHeader("grpc-message", "\"\(stream.grpcMessage)\"", to: &trailerLines)
        }
        if !trailerLines.isEmpty {
            sections.append((["HEADERS (trailers)"] + trailerLines).joined(separator: "\n"))
        } else if stream.isGrpc {
            sections.append("HEADERS (trailers)\n  grpc-status: not captured")
        }

        return sections.isEmpty ? "" : sections.joined(separator: "\n\n") + "\n"
    }

    private func sanitizedHttp2Transcript(_ transcript: String,
                                          hasProtobufPreview: Bool,
                                          isProbablyTruncated: Bool) -> String {
        let lines = transcript.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        var output: [String] = []
        var collapsedDataFrames = 0
        var collapsedDataBytes = 0
        var sawTruncatedDataLine = false
        var index = 0

        while index < lines.count {
            let line = lines[index]
            if line.hasPrefix("DATA"), hasProtobufPreview {
                if index + 1 < lines.count,
                   let message = quotedGrpcMessage(in: lines[index + 1]),
                   isNoisyBinaryPreview(message) {
                    collapsedDataFrames += 1
                    collapsedDataBytes += dataLength(from: line) ?? 0
                    index += 2
                    continue
                }
                if isProbablyTruncated {
                    sawTruncatedDataLine = true
                    break
                }
            }
            if let message = quotedGrpcMessage(in: line), isNoisyBinaryPreview(message) {
                output.append("  protobuf: binary message (schema required to decode fields)")
            } else {
                output.append(line)
            }
            index += 1
        }

        if collapsedDataFrames > 0 {
            insertCollapsedDataSummary(
                frames: collapsedDataFrames,
                bytes: collapsedDataBytes,
                truncated: isProbablyTruncated || sawTruncatedDataLine,
                into: &output
            )
        }

        return compactBlankLines(output).joined(separator: "\n")
    }

    private func insertCollapsedDataSummary(frames: Int,
                                            bytes: Int,
                                            truncated: Bool,
                                            into lines: inout [String]) {
        var summary = [
            "DATA",
            "  \(frames) gRPC protobuf messages (\(bytes) bytes)",
            "  see PROTOBUF decode_raw preview below"
        ]
        if truncated {
            summary.append("  native HTTP/2 transcript truncated; preview is bounded")
        }

        let insertAt = lines.firstIndex { $0.hasPrefix("HEADERS (trailers)") } ?? lines.endIndex
        let needsLeadingBlank = insertAt > lines.startIndex && lines[insertAt - 1].isEmpty == false
        let needsTrailingBlank = insertAt < lines.endIndex && lines[insertAt].isEmpty == false
        var block = summary
        if needsLeadingBlank { block.insert("", at: 0) }
        if needsTrailingBlank { block.append("") }
        lines.insert(contentsOf: block, at: insertAt)
    }

    private func compactBlankLines(_ lines: [String]) -> [String] {
        var compacted: [String] = []
        var previousWasBlank = false

        for line in lines {
            let isBlank = line.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            if isBlank, previousWasBlank {
                continue
            }
            compacted.append(line)
            previousWasBlank = isBlank
        }

        while compacted.first?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true {
            compacted.removeFirst()
        }
        while compacted.last?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == true {
            compacted.removeLast()
        }

        return compacted
    }

    private func shouldShowMissingTrailersNote(_ stream: FollowedStream, in decoded: String) -> Bool {
        stream.isGrpc && stream.grpcStatus.isEmpty && !decoded.contains("HEADERS (trailers)")
    }

    private func quotedGrpcMessage(in line: String) -> String? {
        let prefix = "  message: \""
        guard line.hasPrefix(prefix), line.hasSuffix("\"") else { return nil }
        return String(line.dropFirst(prefix.count).dropLast())
    }

    private func isNoisyBinaryPreview(_ value: String) -> Bool {
        value.hasPrefix(".") || value.contains("..") || value.contains("\".")
    }

    private func dataLength(from line: String) -> Int? {
        guard let range = line.range(of: "length=") else { return nil }
        let suffix = line[range.upperBound...]
        let digits = suffix.prefix { $0.isNumber }
        return Int(digits)
    }

    private func appendHeader(_ name: String, _ value: String, to lines: inout [String]) {
        guard !value.isEmpty else { return }
        lines.append("  \(name): \(value)")
    }

    private func inferredScheme(_ stream: FollowedStream) -> String {
        if showDecrypted && stream.hasDecryptedData { return "https" }
        if stream.serverEndpoint.hasSuffix(":443") || stream.serverEndpoint.hasSuffix(":8443") { return "https" }
        return stream.isGrpc ? "http" : ""
    }

    private func protobufRawPreviewSection(_ stream: FollowedStream) -> String {
        let messages = grpcMessages(stream).prefix(8)
        guard !messages.isEmpty else { return "" }

        var lines = ["PROTOBUF decode_raw preview"]
        for (index, message) in messages.enumerated() {
            lines.append("message #\(index + 1) (length=\(message.length), compressed=\(message.compressed ? "yes" : "no"))")
            if message.compressed {
                lines.append("  compressed payload: set grpc-encoding/decompress before protobuf decode")
                continue
            }

            let decoded = decodeProtobufRaw(message.body, indent: "  ", depth: 0)
            if decoded.isEmpty {
                lines.append("  protobuf: binary message (schema required to decode fields)")
            } else {
                lines.append(contentsOf: decoded.prefix(16))
                if decoded.count > 16 {
                    lines.append("  ...")
                }
            }
        }

        return lines.joined(separator: "\n")
    }

    private func grpcMessages(_ stream: FollowedStream) -> [GrpcMessage] {
        let useDecrypted = showDecrypted && stream.hasDecryptedData
        let buffers = useDecrypted ? [stream.clientPlaintext, stream.serverPlaintext]
                                   : [stream.clientBytes, stream.serverBytes]
        return buffers.flatMap { grpcMessages(inHttp2Bytes: $0) }
    }

    private func grpcMessages(inHttp2Bytes data: Data) -> [GrpcMessage] {
        guard !data.isEmpty else { return [] }

        let bytes = [UInt8](data)
        let preface = Array("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".utf8)
        var offset = bytes.starts(with: preface) ? preface.count : 0
        var grpcPayload = [UInt8]()

        while offset + 9 <= bytes.count {
            let length = Int(bytes[offset]) << 16 | Int(bytes[offset + 1]) << 8 | Int(bytes[offset + 2])
            let type = bytes[offset + 3]
            let flags = bytes[offset + 4]
            let payloadStart = offset + 9
            let payloadEnd = payloadStart + length
            guard payloadEnd <= bytes.count else { break }

            if type == 0 {
                var dataStart = payloadStart
                var dataEnd = payloadEnd
                if flags & 0x08 != 0, dataStart < dataEnd {
                    let padding = Int(bytes[dataStart])
                    dataStart += 1
                    dataEnd = max(dataStart, dataEnd - padding)
                }
                if dataStart < dataEnd {
                    grpcPayload.append(contentsOf: bytes[dataStart..<dataEnd])
                }
            }

            offset = payloadEnd
        }

        return grpcMessages(inGrpcPayload: grpcPayload)
    }

    private func grpcMessages(inGrpcPayload bytes: [UInt8]) -> [GrpcMessage] {
        var messages: [GrpcMessage] = []
        var offset = 0

        while offset + 5 <= bytes.count {
            let compressed = bytes[offset] != 0
            let messageLength = Int(bytes[offset + 1]) << 24
                | Int(bytes[offset + 2]) << 16
                | Int(bytes[offset + 3]) << 8
                | Int(bytes[offset + 4])
            offset += 5

            guard messageLength >= 0, offset + messageLength <= bytes.count else { break }
            let message = Array(bytes[offset..<(offset + messageLength)])
            messages.append(GrpcMessage(length: messageLength, compressed: compressed, body: message))
            offset += messageLength
        }

        return messages
    }

    private func decodeProtobufRaw(_ bytes: [UInt8], indent: String, depth: Int) -> [String] {
        guard depth < 3 else { return [] }

        var lines: [String] = []
        var offset = 0
        while offset < bytes.count {
            guard let key = readVarint(bytes, offset: &offset) else { return [] }
            let fieldNumber = key >> 3
            let wireType = key & 0x7
            guard fieldNumber > 0 else { return [] }

            switch wireType {
            case 0:
                guard let value = readVarint(bytes, offset: &offset) else { return [] }
                lines.append("\(indent)\(fieldNumber): \(value)")
            case 1:
                guard offset + 8 <= bytes.count else { return [] }
                let value = bytes[offset..<(offset + 8)].map { String(format: "%02x", $0) }.joined()
                lines.append("\(indent)\(fieldNumber): 0x\(value)")
                offset += 8
            case 2:
                guard let length = readVarint(bytes, offset: &offset),
                      length <= UInt64(Int.max) else { return [] }
                let end = offset + Int(length)
                guard end <= bytes.count else { return [] }
                let field = Array(bytes[offset..<end])
                if let text = String(bytes: field, encoding: .utf8),
                   text.unicodeScalars.allSatisfy({ $0.value >= 32 || $0.value == 10 || $0.value == 9 }),
                   text.unicodeScalars.contains(where: { !$0.properties.isWhitespace }) {
                    lines.append("\(indent)\(fieldNumber): \"\(escapedProtobufString(text))\"")
                } else {
                    let nested = decodeProtobufRaw(field, indent: indent + "  ", depth: depth + 1)
                    if !nested.isEmpty {
                        lines.append("\(indent)\(fieldNumber) {")
                        lines.append(contentsOf: nested)
                        lines.append("\(indent)}")
                    } else {
                        lines.append("\(indent)\(fieldNumber): <\(field.count) bytes>")
                    }
                }
                offset = end
            case 5:
                guard offset + 4 <= bytes.count else { return [] }
                let value = bytes[offset..<(offset + 4)].map { String(format: "%02x", $0) }.joined()
                lines.append("\(indent)\(fieldNumber): 0x\(value)")
                offset += 4
            default:
                return []
            }

            guard offset <= bytes.count else { return [] }
        }

        return lines
    }

    private func escapedProtobufString(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\t", with: "\\t")
    }

    private func readVarint(_ bytes: [UInt8], offset: inout Int) -> UInt64? {
        var result: UInt64 = 0
        var shift: UInt64 = 0

        while offset < bytes.count, shift < 64 {
            let byte = bytes[offset]
            offset += 1
            result |= UInt64(byte & 0x7F) << shift
            if byte & 0x80 == 0 { return result }
            shift += 7
        }

        return nil
    }

    private func asciiString(_ data: Data) -> String {
        var s = String()
        s.reserveCapacity(data.count)
        for byte in data {
            if byte == 0x0A || byte == 0x09 || (0x20...0x7E).contains(byte) {
                s.unicodeScalars.append(UnicodeScalar(byte))
            } else if byte == 0x0D {
                continue                      // fold CR into the following LF
            } else {
                s.append(".")
            }
        }
        return s
    }

    private func hexBlock(_ data: Data) -> String {
        let bytes = [UInt8](data)
        var lines: [String] = []
        var i = 0
        while i < bytes.count {
            let end = min(i + 16, bytes.count)
            let chunk = bytes[i..<end]
            let hex = chunk.map { String(format: "%02X", $0) }
                .joined(separator: " ")
                .padding(toLength: 47, withPad: " ", startingAt: 0)
            let ascii = chunk.map { (0x20...0x7E).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
            lines.append("\(hex)  \(ascii)")
            i += 16
        }
        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: - Actions

    @MainActor
    private func rebuild() async {
        isLoading = true
        let pkts = packets
        let keylog = keylogPath
        let built = await Task.detached(priority: .userInitiated) {
            StreamFollowService.build(from: pkts, keylogPath: keylog)
        }.value
        stream = built
        if built.hasDecryptedData { showDecrypted = true }
        isLoading = false
    }

    private func pickKeylog() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.message = "Select an SSLKEYLOGFILE (NSS key-log format)"
        if panel.runModal() == .OK, let url = panel.url {
            keylogPath = url.path
        }
    }

    private func savePayload() {
        guard let stream else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "stream.txt"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let useDecrypted = showDecrypted && stream.hasDecryptedData
        var data = Data()
        data.append(useDecrypted ? stream.clientPlaintext : stream.clientBytes)
        data.append(useDecrypted ? stream.serverPlaintext : stream.serverBytes)
        try? data.write(to: url)
    }

    private func exportProtobufMessages() {
        guard let stream else { return }
        let messages = grpcMessages(stream)
        guard !messages.isEmpty else { return }

        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = "Export"
        panel.message = "Choose a folder for extracted gRPC protobuf message bodies"
        guard panel.runModal() == .OK, let folder = panel.url else { return }

        let formatter = NumberFormatter()
        formatter.minimumIntegerDigits = 3

        for (index, message) in messages.enumerated() {
            let number = formatter.string(from: NSNumber(value: index + 1)) ?? "\(index + 1)"
            let suffix = message.compressed ? "compressed.pb" : "pb"
            let url = folder.appendingPathComponent("grpc-message-\(number).\(suffix)")
            try? Data(message.body).write(to: url)
        }

        let readme = protobufExportReadme(messageCount: messages.count)
        try? readme.write(to: folder.appendingPathComponent("README.txt"), atomically: true, encoding: .utf8)
    }

    private func protobufExportReadme(messageCount: Int) -> String {
        """
        Exported \(messageCount) gRPC protobuf message bodies.

        Files ending in .pb are protobuf bodies with the 5-byte gRPC prefix already removed.
        Decode without a .proto:
          protoc --decode_raw < grpc-message-001.pb

        Decode with a .proto:
          protoc --proto_path=. --decode=package.MessageType service.proto < grpc-message-001.pb

        Files ending in .compressed.pb must be decompressed according to grpc-encoding before protobuf decoding.
        """
    }

    // MARK: - Helpers

    private func transportLabel(_ t: FollowedStream.Transport) -> String {
        switch t { case .tcp: "TCP"; case .udp: "UDP"; case .none: "—" }
    }

    private func clientLen(_ s: FollowedStream) -> Int {
        (showDecrypted && s.hasDecryptedData) ? s.clientPlaintext.count : s.clientBytes.count
    }
    private func serverLen(_ s: FollowedStream) -> Int {
        (showDecrypted && s.hasDecryptedData) ? s.serverPlaintext.count : s.serverBytes.count
    }

    private func endpointShort(isClient: Bool) -> String {
        guard let stream else { return isClient ? "client" : "server" }
        let ep = isClient ? stream.clientEndpoint : stream.serverEndpoint
        return ep.split(separator: ":").last.map(String.init) ?? ep
    }

    private func byteLabel(_ n: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary)
    }
}
