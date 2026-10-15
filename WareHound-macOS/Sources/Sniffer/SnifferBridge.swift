import Foundation
import CSniffer

final class SnifferBridge: @unchecked Sendable {

    static let shared = SnifferBridge()

    enum State { case idle, capturing }

    private struct QueuedPacket: Sendable {
        let number: Int
        let raw: Data
    }

    private let lock = NSLock()
    private let queueCondition = NSCondition()
    private var state: State = .idle
    private var continuation: AsyncStream<PacketModel>.Continuation?
    private var packetNumber = 0
    private var droppedCount = 0
    private var rawQueue: [QueuedPacket] = []
    private var rawQueueHead = 0
    private var processingTask: Task<Void, Never>?
    private static let maxRawQueueDepth = 50_000
    private static let rawDrainBatchSize = 512

    // `dropped` counts packets the UI pipeline couldn't keep up with.
    func captureCounters() -> (received: Int, dropped: Int) {
        lock.lock(); defer { lock.unlock() }
        return (packetNumber, droppedCount)
    }

    private var flowHosts: [String: String] = [:]
    private static let flowHostLimit = 8192

    private var linkType: PacketParser.LinkType = .ethernet

    private(set) var lastStartError: String?

    private init() {}

    func listDevices() -> [NetworkDevice] {
        var count: Int32 = 0
        fnDevCPPDLL(nil, nil, &count)
        guard count > 0 else { return [] }

        let n = Int(count)
        var pointers = [UnsafeMutablePointer<CChar>?](repeating: nil, count: n)
        var sizes = [Int32](repeating: 0, count: n)

        pointers.withUnsafeMutableBufferPointer { ptrBuf in
            sizes.withUnsafeMutableBufferPointer { sizeBuf in
                fnDevCPPDLL(ptrBuf.baseAddress, sizeBuf.baseAddress, &count)
            }
        }

        var devices: [NetworkDevice] = []
        devices.reserveCapacity(n)
        for i in 0..<n {
            guard let p = pointers[i] else { continue }
            let name = String(cString: p)
            devices.append(NetworkDevice(index: i, name: name, description: ""))
        }

        // Native side allocated these with new[]; it must free them.
        pointers.withUnsafeMutableBufferPointer { ptrBuf in
            fnFreeDevList(ptrBuf.baseAddress, Int32(n))
        }
        return devices
    }

    func selectDevice(index: Int) {
        fnPutdevCPPDLL(Int32(index))
    }

    func startCapture(source: CaptureBackend = .pcap) -> AsyncStream<PacketModel> {
        // Tear down a stale capture first; stopCapture() takes the lock itself.
        lock.lock()
        let alreadyRunning = state == .capturing
        lock.unlock()
        if alreadyRunning {
            stopCapture()
        }

        // Tunnel delivers bare IP packets (no L2 header), so the link type must match.
        let nativeSource: SnifferCaptureSource
        let initialLinkType: PacketParser.LinkType
        switch source {
        case .pcap:
            nativeSource = SNIFFER_SOURCE_PCAP
            initialLinkType = .ethernet
        case .tunnel:
            nativeSource = SNIFFER_SOURCE_TUNNEL
            initialLinkType = .raw
        }

        lock.lock()
        guard state == .idle else {
            lastStartError = "Capture already running"
            lock.unlock()
            return AsyncStream { $0.finish() }
        }
        packetNumber = 0
        droppedCount = 0
        queueCondition.lock()
        rawQueue.removeAll(keepingCapacity: true)
        rawQueueHead = 0
        queueCondition.unlock()
        flowHosts.removeAll(keepingCapacity: true)
        linkType = initialLinkType
        lastStartError = nil
        state = .capturing
        lock.unlock()

        let stream = AsyncStream<PacketModel>(bufferingPolicy: .bufferingNewest(50_000)) { cont in
            self.lock.lock()
            self.continuation = cont
            self.lock.unlock()
            cont.onTermination = { _ in
                SnifferBridge.shared.stopNativeIfNeeded()
            }
        }

        fnSetCaptureSource(Int32(nativeSource.rawValue))
        fnSetL7Enabled(0)
        fnSetIpcMode(Int32(SNIFFER_IPC_MODE_CALLBACK.rawValue))
        fnSetPacketCallback(snifferPacketTrampoline)
        startProcessingTask()

        Task.detached(priority: .utility) { [weak self] in
            fnStartCapture()
            let err = String(cString: fnLastError())
            self?.handleNativeStartResult(source: source, error: err)
        }

        return stream
    }

    private func handleNativeStartResult(source: CaptureBackend, error err: String) {
        if err.isEmpty {
            // Not all pcap interfaces are Ethernet (lo0 is DLT_NULL); adopt the native link type.
            guard source == .pcap else { return }
            let activeLinkType: PacketParser.LinkType
            switch fnActiveLinkType() {
            case Int32(SNIFFER_LINK_RAW_IP.rawValue): activeLinkType = .raw
            case Int32(SNIFFER_LINK_NULL.rawValue):   activeLinkType = .null
            default:                                  activeLinkType = .ethernet
            }
            lock.lock()
            if state == .capturing {
                linkType = activeLinkType
            }
            lock.unlock()
        } else {
            lock.lock()
            lastStartError = err
            let cont = continuation
            continuation = nil
            state = .idle
            lock.unlock()
            fnSetPacketCallback(nil)
            stopProcessingTask()
            cont?.finish()
        }
    }

    private var outboundHandler: (@Sendable (Data) -> Void)?

    func setOutboundHandler(_ handler: (@Sendable (Data) -> Void)?) {
        lock.lock()
            outboundHandler = handler
        lock.unlock()
        fnSetOutboundCallback(handler == nil ? nil : snifferOutboundTrampoline, nil)
    }

    func submitTunnelPacket(_ data: Data) {
        data.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress, raw.count > 0 else { return }
            fnSubmitPacket(base, Int32(raw.count))
        }
    }

    fileprivate func handleOutboundPacket(_ data: UnsafePointer<UInt8>?, _ length: Int32) {
        guard let data, length > 0 else { return }
        let copy = Data(bytes: data, count: Int(length))
        lock.lock()
        let handler = outboundHandler
        lock.unlock()
        handler?(copy)
    }

    func stopCapture() {
        lock.lock()
        let cont = continuation
        let wasCapturing = state == .capturing
        continuation = nil
        state = .idle
        lock.unlock()

        if wasCapturing {
            fnCloseApp()
            fnSetPacketCallback(nil)
        }
        stopProcessingTask()
        cont?.finish()
    }

    func shutdown() {
        stopCapture()
    }

    private func stopNativeIfNeeded() {
        lock.lock()
        let wasCapturing = state == .capturing
        state = .idle
        continuation = nil
        lock.unlock()
        if wasCapturing {
            fnCloseApp()
            fnSetPacketCallback(nil)
        }
        stopProcessingTask()
    }

    fileprivate func handleRawPacket(_ data: UnsafePointer<UInt8>?, _ length: Int32) {
        guard let data, length > 0 else { return }

        let raw = Data(bytes: data, count: Int(length))

        lock.lock()
        guard state == .capturing else {
            lock.unlock()
            return
        }
        packetNumber += 1
        let packet = QueuedPacket(number: packetNumber, raw: raw)
        lock.unlock()

        var queueDropCount = 0
        queueCondition.lock()
        let pendingCount = rawQueue.count - rawQueueHead
        if pendingCount >= Self.maxRawQueueDepth {
            queueDropCount = pendingCount - Self.maxRawQueueDepth + 1
            rawQueueHead += queueDropCount
            compactRawQueueIfNeeded()
        }
        rawQueue.append(packet)
        queueCondition.signal()
        queueCondition.unlock()

        if queueDropCount > 0 {
            lock.lock()
            droppedCount += queueDropCount
            lock.unlock()
        }
    }

    private func startProcessingTask() {
        processingTask?.cancel()
        processingTask = Task.detached(priority: .utility) { [weak self] in
            self?.processRawPackets()
        }
    }

    private func stopProcessingTask() {
        processingTask?.cancel()
        processingTask = nil
        queueCondition.lock()
        queueCondition.signal()
        queueCondition.unlock()
    }

    private func processRawPackets() {
        while !Task.isCancelled {
            let batch = dequeueRawBatch()
            // Read link type at parse time: the DLT is only finalized just after fnStartCapture.
            lock.lock(); let lt = linkType; lock.unlock()
            for packet in batch where !Task.isCancelled {
                let model = PacketModel.from(rawFrame: packet.raw, number: packet.number, linkType: lt)
                yieldParsedPacket(resolveFlowHost(model))
            }
        }
    }

    private func dequeueRawBatch() -> [QueuedPacket] {
        queueCondition.lock()
        while rawQueueHead >= rawQueue.count && !Task.isCancelled {
            queueCondition.wait()
        }

        let pendingCount = rawQueue.count - rawQueueHead
        let batchCount = min(pendingCount, Self.rawDrainBatchSize)
        let endIndex = rawQueueHead + batchCount
        let batch = Array(rawQueue[rawQueueHead..<endIndex])
        rawQueueHead = endIndex
        compactRawQueueIfNeeded()
        queueCondition.unlock()
        return batch
    }

    private func compactRawQueueIfNeeded() {
        if rawQueueHead == rawQueue.count {
            rawQueue.removeAll(keepingCapacity: true)
            rawQueueHead = 0
        } else if rawQueueHead > 4_096 && rawQueueHead * 2 >= rawQueue.count {
            rawQueue.removeFirst(rawQueueHead)
            rawQueueHead = 0
        }
    }

    private func yieldParsedPacket(_ packet: PacketModel) {
        lock.lock()
        let cont = continuation
        lock.unlock()

        if let cont, case .dropped = cont.yield(packet) {
            lock.lock()
            droppedCount += 1
            lock.unlock()
        }
    }

    private func resolveFlowHost(_ model: PacketModel) -> PacketModel {
        guard model.proto.hasPrefix("TLS") else { return model }
        let key = Self.flowKey(model)

        lock.lock()
        defer { lock.unlock() }
        if !model.hostName.isEmpty {
            if flowHosts.count < Self.flowHostLimit { flowHosts[key] = model.hostName }
            return model
        }
        if let host = flowHosts[key] {
            return model.withHostName(host)
        }
        return model
    }

    private static func flowKey(_ p: PacketModel) -> String {
        let a = "\(p.sourceIp):\(p.sourcePort)"
        let b = "\(p.destIp):\(p.destPort)"
        return a <= b ? "\(a)|\(b)" : "\(b)|\(a)"
    }
}

private let snifferPacketTrampoline: PacketDataCallback = { data, length in
    SnifferBridge.shared.handleRawPacket(data, length)
}

private let snifferOutboundTrampoline: OutboundPacketCallback = { _, pkt, length in
    SnifferBridge.shared.handleOutboundPacket(pkt, length)
}
