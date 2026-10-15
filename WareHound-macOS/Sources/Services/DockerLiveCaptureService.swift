import Foundation

// tcpdump -i any in a --net=host container sees every container bridge in the Docker VM.
final class DockerLiveCaptureService: @unchecked Sendable {

    // Called on the main queue.
    var onPackets: (@Sendable ([PacketModel]) -> Void)?
    // Called on the main queue.
    var onStopped: (@Sendable (String) -> Void)?

    private let queue = DispatchQueue(label: "com.warehound.docker-live")
    private var process: Process?
    private var readHandle: FileHandle?
    private var containerName = ""
    private var docker = ""
    private var stopping = false

    private var buf: [UInt8] = []
    private var haveHeader = false
    private var littleEndian = true
    private var nanoTimestamps = false
    private var linkType: PacketParser.LinkType = .ethernet
    private var number = 0

    var isRunning: Bool { process?.isRunning ?? false }

    func start(docker: String, filter: String, containerSuffix: String) {
        queue.async {
            self.docker = docker
            self.containerName = "warehound-live-\(containerSuffix)"
            self.resetParser()

            var tcpdump = ["tcpdump", "-i", "any", "-U", "-w", "-"]
            let trimmed = filter.trimmingCharacters(in: .whitespacesAndNewlines)
            if !trimmed.isEmpty { tcpdump.append(trimmed) }

            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: docker)
            proc.arguments = ["run", "--rm", "--name", self.containerName,
                              "--net=host", "--privileged", "nicolaka/netshoot"] + tcpdump

            let outPipe = Pipe()
            proc.standardOutput = outPipe
            proc.standardError = Pipe()
            let handle = outPipe.fileHandleForReading
            handle.readabilityHandler = { [weak self] h in
                let chunk = h.availableData
                guard let self else { return }
                if chunk.isEmpty {
                    h.readabilityHandler = nil
                    self.queue.async { self.finish(reason: "Docker live capture stopped.") }
                } else {
                    self.queue.async { self.consume(chunk) }
                }
            }

            proc.terminationHandler = { [weak self] _ in
                self?.queue.async { self?.finish(reason: "Docker live capture stopped.") }
            }

            do {
                try proc.run()
                self.process = proc
                self.readHandle = handle
            } catch {
                self.finish(reason: "Docker live capture failed: \(error.localizedDescription)")
            }
        }
    }

    func stop() {
        queue.async {
            guard !self.stopping else { return }
            self.stopping = true
            // Killing the local `docker run` client alone won't reliably stop tcpdump in the VM.
            if !self.containerName.isEmpty, !self.docker.isEmpty {
                let kill = Process()
                kill.executableURL = URL(fileURLWithPath: self.docker)
                kill.arguments = ["kill", self.containerName]
                kill.standardOutput = Pipe()
                kill.standardError = Pipe()
                try? kill.run()
                kill.waitUntilExit()
            }
            self.process?.terminate()
        }
    }

    // MARK: - Parsing

    private func resetParser() {
        buf.removeAll(keepingCapacity: true)
        haveHeader = false
        number = 0
        stopping = false
    }

    private func consume(_ chunk: Data) {
        buf.append(contentsOf: chunk)

        if !haveHeader {
            guard buf.count >= 24 else { return }
            guard parseGlobalHeader() else {
                finish(reason: "Docker live capture failed: unrecognized pcap stream.")
                return
            }
            buf.removeFirst(24)
            haveHeader = true
        }

        var batch: [PacketModel] = []
        while buf.count >= 16 {
            let inclLen = Int(u32(8))
            let origLen = Int(u32(12))
            // 16-byte record header + payload; wait for the whole record.
            guard inclLen >= 0, inclLen <= 262_144, buf.count >= 16 + inclLen else { break }

            let tsSec = TimeInterval(u32(0))
            let tsFrac = TimeInterval(u32(4))
            let seconds = tsSec + tsFrac / (nanoTimestamps ? 1_000_000_000 : 1_000_000)

            let raw = Data(buf[16 ..< 16 + inclLen])
            buf.removeFirst(16 + inclLen)

            number += 1
            batch.append(PacketModel.from(
                rawFrame: raw,
                number: number,
                captureTime: Date(timeIntervalSince1970: seconds),
                captureLen: UInt32(inclLen),
                originalLen: UInt32(origLen > 0 ? origLen : inclLen),
                linkType: linkType))
        }

        if !batch.isEmpty {
            let out = batch
            let cb = onPackets
            DispatchQueue.main.async { cb?(out) }
        }
    }

    private func parseGlobalHeader() -> Bool {
        let b = Array(buf[0..<4])
        switch (b[0], b[1], b[2], b[3]) {
        case (0xD4, 0xC3, 0xB2, 0xA1): littleEndian = true;  nanoTimestamps = false
        case (0xA1, 0xB2, 0xC3, 0xD4): littleEndian = false; nanoTimestamps = false
        case (0x4D, 0x3C, 0xB2, 0xA1): littleEndian = true;  nanoTimestamps = true
        case (0xA1, 0xB2, 0x3C, 0x4D): littleEndian = false; nanoTimestamps = true
        default: return false
        }
        // Link type is the last 4 bytes of the 24-byte global header.
        linkType = Self.mapLinkType(u32(20))
        return true
    }

    private static func mapLinkType(_ dlt: UInt32) -> PacketParser.LinkType {
        switch dlt {
        case 1:            return .ethernet   // DLT_EN10MB
        case 0, 108:       return .null       // DLT_NULL / DLT_LOOP
        case 12, 14, 101:  return .raw        // DLT_RAW variants
        case 113:          return .sll        // DLT_LINUX_SLL (tcpdump -i any)
        case 276:          return .sll2       // DLT_LINUX_SLL2
        default:           return .ethernet
        }
    }

    private func u32(_ offset: Int) -> UInt32 {
        let a = UInt32(buf[offset]), b = UInt32(buf[offset + 1])
        let c = UInt32(buf[offset + 2]), d = UInt32(buf[offset + 3])
        return littleEndian ? (a | b << 8 | c << 16 | d << 24)
                            : (a << 24 | b << 16 | c << 8 | d)
    }

    private func finish(reason: String) {
        guard process != nil || !stopping else { return }
        readHandle?.readabilityHandler = nil
        readHandle = nil
        process = nil
        let cb = onStopped
        onStopped = nil
        DispatchQueue.main.async { cb?(reason) }
    }
}
