import Foundation
import Observation

@MainActor
@Observable
final class CaptureViewModel {
    enum TunnelRunState: String, Sendable {
        case unavailable
        case available
        case starting
        case running
        case failed
        case stopped

        var title: String {
            switch self {
            case .unavailable: "Tunnel unavailable"
            case .available: "Tunnel available"
            case .starting: "Tunnel starting"
            case .running: "Tunnel running"
            case .failed: "Tunnel failed"
            case .stopped: "Tunnel stopped"
            }
        }

        var icon: String {
            switch self {
            case .unavailable: "lock.slash"
            case .available: "checkmark.seal"
            case .starting: "hourglass"
            case .running: "network"
            case .failed: "exclamationmark.triangle"
            case .stopped: "stop.circle"
            }
        }
    }

    private struct FlowKey: Hashable {
        let endpointA: String
        let endpointB: String

        init(packet: PacketModel) {
            let lhs = "\(packet.sourceIp):\(packet.sourcePort)"
            let rhs = "\(packet.destIp):\(packet.destPort)"
            if lhs <= rhs {
                endpointA = lhs
                endpointB = rhs
            } else {
                endpointA = rhs
                endpointB = lhs
            }
        }
    }

    private(set) var packets: [PacketModel] = []
    private(set) var isCapturing = false
    private(set) var statistics = CaptureStatistics()

    // Cumulative, independent of the rolling `packets` window, so stats survive the buffer cap.
    private(set) var scanCount = 0
    private(set) var badChecksumCount = 0
    var availableDevices: [NetworkDevice] = []
    var selectedDevice: NetworkDevice?
    var selectedPacket: PacketModel?
    var filterText: String = "" {
        didSet { rebuildDerivedPackets() }
    }
    var sortColumn: SortColumn = .number
    var sortAscending = true
    var isStatsPanelVisible = true
    private(set) var statusMessage = "Ready"
    private(set) var filteredPackets: [PacketModel] = []
    private(set) var sortedTablePackets: [PacketModel] = []
    private(set) var captureTablePackets: [PacketModel] = []
    private(set) var tunnelRunState: TunnelRunState = SettingsViewModel.shared.supportsTunnelCapture ? .available : .unavailable
    private(set) var tunnelStatusDetail = SettingsViewModel.shared.tunnelUnavailableReason
        ?? "Packet Tunnel is available. Capture is IP-only and depends on the signed Network Extension."

    private let sniffer = SnifferBridge.shared
    private let tunnelController = TunnelController()
    private let pcapService = PcapFileService()
    private let dockerLive = DockerLiveCaptureService()
    private var captureTask: Task<Void, Never>?
    private var activeBackend: CaptureBackend?
    private var flowHosts: [FlowKey: String] = [:]

    private var ipHosts: [String: String] = [:]

    // Docker IP → container name; distinguishes services that port alone can't.
    private var containerNames: [String: String] = [:]

    // Aggregation updates every flush; SwiftUI-observed state republishes at a capped rate.
    private var liveStats = CaptureStatistics()
    private var liveScanCount = 0
    private var liveBadChecksumCount = 0
    private var uiPublishScheduled = false
    private var lastUiPublish = ContinuousClock.now
    private static let uiPublishInterval: Duration = .milliseconds(350)
    private static let liveDisplayRowLimit = 2_000

    var onCaptureStateChanged: ((Bool) -> Void)?

    nonisolated private static let flushInterval: Duration = .milliseconds(250)
    nonisolated private static let flushPacketBatchSize = 512

    init() {
        refreshDevices()
    }

    func refreshDevices() {
        availableDevices = sniffer.listDevices()
        if selectedDevice == nil { selectedDevice = availableDevices.first }
    }

    func toggleCapture() {
        isCapturing ? stopCapture() : startCapture()
    }

    func captureButtonPressed() {
        statusMessage = isCapturing ? "Stop button pressed" : "Start button pressed"
        LoggerService.shared.log(statusMessage)
        toggleCapture()
    }

    func startCapture() {
        guard LicenseManager.shared.requireLicense() else { return }
        guard !isCapturing else { return }

        let backend = SettingsViewModel.shared.selectedCaptureBackend
        if backend == .tunnel, !SettingsViewModel.shared.supportsTunnelCapture {
            let reason = SettingsViewModel.shared.tunnelUnavailableReason
                ?? "Packet Tunnel is unavailable in this build."
            setTunnelRunState(.unavailable, detail: reason)
            statusMessage = reason
            LoggerService.shared.logError("Tunnel unavailable", exception: reason)
            return
        }
        switch backend {
        case .pcap:
            SettingsViewModel.shared.refreshBpfAccessStatus()
            guard SettingsViewModel.shared.bpfAccessStatus.isAvailable else {
                statusMessage = "BPF unavailable: \(SettingsViewModel.shared.bpfAccessStatus.detail)"
                LoggerService.shared.logError("Capture start failed", exception: statusMessage)
                return
            }
            guard let device = selectedDevice else {
                refreshDevices()
                guard let refreshedDevice = selectedDevice else {
                    statusMessage = "No capture device selected. Check BPF permissions or refresh interfaces."
                    LoggerService.shared.logError("Capture start failed", exception: "No capture device selected")
                    return
                }
                startPcapCapture(on: refreshedDevice)
                return
            }
            startPcapCapture(on: device)
        case .tunnel:
            startTunnelCapture()
        }
    }

    private func startPcapCapture(on device: NetworkDevice) {
        let backend = SettingsViewModel.shared.selectedCaptureBackend
        activeBackend = backend
        isCapturing = true
        statusMessage = "Starting capture on \(device.displayName)…"
        onCaptureStateChanged?(true)
        LoggerService.shared.log("Capture start requested on \(device.displayName) [\(backend.displayName)]")

        Task { [weak self] in
            await Task.yield()
            self?.finishStartingPcapCapture(on: device, backend: backend)
        }
    }

    private func finishStartingPcapCapture(on device: NetworkDevice, backend: CaptureBackend) {
        guard isCapturing, activeBackend == backend else { return }

        packets.removeAll(keepingCapacity: true)
        rebuildDerivedPackets()
        statistics = CaptureStatistics()
        scanCount = 0
        badChecksumCount = 0
        flowHosts.removeAll(keepingCapacity: true)
        ipHosts.removeAll(keepingCapacity: true)
        NativeStats.l7Clear()
        NativeStats.resetFlows()
        statistics.captureStartTime = .now
        PacketModel.captureStartTime = .now
        liveStats = statistics
        liveScanCount = 0
        liveBadChecksumCount = 0
        lastUiPublish = ContinuousClock.now
        statusMessage = "Capturing on \(device.displayName) via \(backend.displayName)…"
        NativeStats.setEnabled(true)
        LoggerService.shared.log("Capture started on \(device.displayName) [\(backend.displayName)]")
        schedulePcapStartWatchdog(deviceName: device.displayName)

        captureTask = Task.detached(priority: .utility) { [weak self, sniffer] in
            sniffer.selectDevice(index: device.index)
            let stream = sniffer.startCapture(source: backend)

            if let err = sniffer.lastStartError {
                await self?.handlePcapStartFailure(err)
                return
            }

            var batch: [PacketModel] = []
            batch.reserveCapacity(Self.flushPacketBatchSize)
            var lastFlush = ContinuousClock.now
            var didFlushFirstPacket = false

            for await packet in stream {
                batch.append(packet)

                let now = ContinuousClock.now
                if !didFlushFirstPacket || batch.count >= Self.flushPacketBatchSize || now - lastFlush >= Self.flushInterval {
                    let toFlush = batch
                    batch.removeAll(keepingCapacity: true)
                    lastFlush = now
                    didFlushFirstPacket = true
                    await self?.flushFromCaptureTask(toFlush)
                }
            }
            if !batch.isEmpty {
                await self?.flushFromCaptureTask(batch)
            }
            if let err = sniffer.lastStartError {
                await self?.handlePcapStartFailure(err)
            }
        }
    }

    private func schedulePcapStartWatchdog(deviceName: String) {
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(2))
            guard let self, self.isCapturing, self.activeBackend == .pcap, self.statistics.totalPackets == 0 else { return }
            let counters = SnifferBridge.shared.captureCounters()
            if counters.received > 0 {
                self.statusMessage = "Native capture received \(counters.received) packets, but none reached the table (dropped: \(counters.dropped))."
            } else {
                self.statusMessage = "Capturing on \(deviceName), waiting for packets. Try generating traffic or selecting another interface."
            }
            LoggerService.shared.log(self.statusMessage)
        }
    }

    private func handlePcapStartFailure(_ err: String) {
        guard isCapturing, activeBackend == .pcap else { return }
        isCapturing = false
        activeBackend = nil
        captureTask = nil
        NativeStats.setEnabled(false)
        onCaptureStateChanged?(false)
        statusMessage = err.contains("Permission")
            ? "Capture failed — no packet-capture permission. Grant BPF access or switch to Packet Tunnel (IP-only). [\(err)]"
            : "Capture failed: \(err)"
        LoggerService.shared.logError("Capture start failed", exception: err)
    }

    private func flushFromCaptureTask(_ batch: [PacketModel]) {
        guard isCapturing, activeBackend == .pcap else { return }
        flush(batch)
    }

    private func startTunnelCapture() {
        let backend = SettingsViewModel.shared.selectedCaptureBackend
        activeBackend = backend
        setTunnelRunState(.starting, detail: "Starting Packet Tunnel. This mode captures IP packets only; Ethernet and ARP are not available.")

        tunnelController.onPacketBatch = { [weak self] packets in
            self?.flush(packets)
        }
        tunnelController.onStateChanged = { [weak self] isRunning, status in
            guard let self else { return }
            self.statusMessage = status
            if isRunning {
                self.setTunnelRunState(.running, detail: status)
            } else if status.localizedCaseInsensitiveContains("failed") {
                self.setTunnelRunState(.failed, detail: status)
            } else if status.localizedCaseInsensitiveContains("starting")
                        || status.localizedCaseInsensitiveContains("preparing")
                        || status.localizedCaseInsensitiveContains("saving") {
                self.setTunnelRunState(.starting, detail: status)
            } else {
                self.setTunnelRunState(.stopped, detail: status)
            }
            let shouldEndTunnelCapture = !isRunning
                && self.activeBackend == .tunnel
                && (status.localizedCaseInsensitiveContains("failed")
                    || status.localizedCaseInsensitiveContains("stopped"))
            if shouldEndTunnelCapture {
                self.isCapturing = false
                self.captureTask?.cancel()
                self.captureTask = nil
                self.activeBackend = nil
                self.onCaptureStateChanged?(false)
            }
        }

        packets.removeAll(keepingCapacity: true)
        rebuildDerivedPackets()
        statistics = CaptureStatistics()
        scanCount = 0
        badChecksumCount = 0
        flowHosts.removeAll(keepingCapacity: true)
        ipHosts.removeAll(keepingCapacity: true)
        statistics.captureStartTime = .now
        PacketModel.captureStartTime = .now
        liveStats = statistics
        liveScanCount = 0
        liveBadChecksumCount = 0
        lastUiPublish = ContinuousClock.now
        isCapturing = true
        statusMessage = "Starting \(backend.displayName)…"
        NativeStats.setEnabled(false)
        onCaptureStateChanged?(true)
        LoggerService.shared.log("Tunnel start requested [\(backend.displayName)]")

        captureTask = Task { [weak self] in
            guard let self else { return }
            await self.tunnelController.start()
            await MainActor.run {
                if self.tunnelController.isRunning {
                    self.statusMessage = self.tunnelController.status
                    self.setTunnelRunState(.running, detail: self.tunnelController.status)
                } else {
                    self.isCapturing = false
                    self.activeBackend = nil
                    self.onCaptureStateChanged?(false)
                    self.statusMessage = self.tunnelController.status
                    self.setTunnelRunState(.failed, detail: self.tunnelController.status)
                }
            }
        }
    }

    func stopCapture() {
        guard isCapturing else { return }

        if isDockerLive {
            statusMessage = "Stopping Docker live capture…"
            dockerLive.stop()   // finishDockerLive() finalizes on container exit
            return
        }

        if activeBackend == .tunnel {
            tunnelController.onPacketBatch = nil
            tunnelController.onStateChanged = nil
            tunnelController.stop()
            setTunnelRunState(.stopped, detail: "Packet Tunnel stopped.")
        } else {
            sniffer.stopCapture()
        }

        captureTask?.cancel()
        captureTask = nil
        activeBackend = nil
        isCapturing = false
        publishUI() // flush buffered burst so final counts are exact
        statusMessage = "Stopped — \(statistics.totalPackets) packets, \(statistics.totalBytes) bytes"
        onCaptureStateChanged?(false)
        LoggerService.shared.log(statusMessage)
    }

    private func setTunnelRunState(_ state: TunnelRunState, detail: String) {
        tunnelRunState = state
        tunnelStatusDetail = detail
    }

    func saveToDashboard(name: String? = nil) {
        guard !packets.isEmpty else { return }
        let title = name ?? "Capture \(Date.now.formatted(date: .abbreviated, time: .shortened))"
        PacketCollectionService.shared.createCollection(name: title, packets: packets)
        statusMessage = "Saved \(packets.count) packets to Dashboard"
        LoggerService.shared.log(statusMessage)
    }

    static let exportColumns = [
        "No", "Time", "Source", "Destination", "Protocol", "Length",
        "TLSVersion", "Ciphers", "TopCipher", "Extensions", "SNI", "ALPN", "Fingerprint", "Host",
    ]

    static let exportTimeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return f
    }()

    static func exportFields(_ p: PacketModel) -> [String] {
        [
            "\(p.number)",
            exportTimeFormatter.string(from: p.captureTime),
            p.sourceEndpoint,
            p.destinationEndpoint,
            p.proto,
            "\(p.originalLen)",
            p.tlsClientHello != nil ? p.tlsVersionDisplay : "",
            p.tlsClientHello.map { "\($0.cipherSuites.count)" } ?? "",
            p.tlsClientHello != nil ? p.tlsFirstCipherDisplay : "",
            p.tlsClientHello.map { "\($0.extensionCount)" } ?? "",
            p.tlsClientHello?.sni ?? "",
            p.tlsClientHello != nil ? p.tlsAlpnDisplay : "",
            p.tlsClientHello != nil ? p.tlsFingerprintDisplay : "",
            p.hostName,
        ]
    }

    static func rowText(_ p: PacketModel) -> String {
        exportFields(p).joined(separator: "\t")
    }

    static func packetDetailText(_ p: PacketModel) -> String {
        var lines: [String] = [
            "Packet #\(p.number): \(p.proto)",
            "Capture Time: \(exportTimeFormatter.string(from: p.captureTime))",
            "Packet ID: \(p.packetId)",
            "Length: \(p.originalLen) bytes" + (p.isTruncated ? " (\(p.captureLen) captured)" : ""),
            "",
            "Flow",
            "  Source: \(p.sourceEndpoint)",
            "  Destination: \(p.destinationEndpoint)",
            "  Source MAC: \(p.sourceMacDisplay)",
            "  Destination MAC: \(p.destMacDisplay)",
            "  Host: \(p.hostName.isEmpty ? "Unknown" : p.hostName)",
        ]

        if p.meta.isIP {
            lines += [
                "",
                "IP / Transport",
                "  \(p.meta.isIPv6 ? "Hop Limit" : "TTL"): \(p.ttlDisplay)",
                "  DSCP: \(p.dscpDisplay)",
                "  ECN: \(p.ecnDisplay)",
                "  Checksum: \(p.checksumDisplay)",
                "  Fragmentation: \(p.fragmentDisplay)",
            ]
        }
        if p.meta.tcpParsed {
            lines += [
                "  TCP Stream: \(p.tcpStreamKey)",
                "  TCP Flags: \(p.tcpFlagsDisplay)",
                "  Sequence: \(p.tcpSeqDisplay)",
                "  Acknowledgment: \(p.tcpAckDisplay)",
                "  Window: \(p.windowDisplay)",
            ]
        }
        if p.meta.hasIcmp {
            lines.append("  ICMP: \(p.icmpDetail)")
        }
        if let arp = p.arp {
            lines += [
                "",
                "ARP",
                "  Operation: \(arp.operationName)",
                "  Sender: \(arp.senderIp) / \(arp.senderMac)",
                "  Target: \(arp.targetIp) / \(arp.targetMac)",
            ]
        }
        if let dhcp = p.dhcp {
            lines += [
                "",
                "DHCP",
                "  Message: \(dhcp.messageName)",
                String(format: "  Transaction ID: 0x%08X", dhcp.transactionId),
                "  Client MAC: \(dhcp.clientMac)",
                "  Requested IP: \(dhcp.requestedIp.isEmpty ? "—" : dhcp.requestedIp)",
                "  Server Identifier: \(dhcp.serverIdentifier.isEmpty ? "—" : dhcp.serverIdentifier)",
            ]
        }
        if let http = p.httpRequest {
            lines += [
                "",
                "HTTP Request",
                "  Request: \(http.method) \(http.target) \(http.version)",
                "  Host: \(http.host.isEmpty ? "—" : http.host)",
                "  User-Agent: \(http.userAgent.isEmpty ? "—" : http.userAgent)",
            ]
        }
        if let dns = p.dns {
            lines += [
                "",
                p.isMdns ? "mDNS" : "DNS",
                "  Name: \(dns.name)",
                "  Type: \(PacketDetailView.dnsTypeName(dns.qtype))",
                String(format: "  Transaction ID: 0x%04X", dns.txid),
                "  Addresses: \(dns.addresses.isEmpty ? "—" : dns.addresses.joined(separator: ", "))",
            ]
            if !dns.records.isEmpty {
                lines.append("  Records:")
                lines += dns.records.map { "    \($0.name) \(PacketDetailView.dnsTypeName($0.type)) TTL=\($0.ttl) \($0.value)" }
            }
        }
        if let tls = p.tlsClientHello {
            lines += [
                "",
                "TLS ClientHello",
                "  SNI: \(tls.sni.isEmpty ? "—" : tls.sni)",
                "  Version: \(p.tlsVersionDisplay)",
                "  ALPN: \(p.tlsAlpnDisplay)",
                "  Ciphers: \(tls.cipherSuites.count)",
                "  First Cipher: \(p.tlsFirstCipherDisplay)",
                "  Extensions: \(tls.extensionCount)",
                "  Fingerprint: \(p.tlsFingerprintDisplay)",
            ]
        }

        return lines.joined(separator: "\n") + "\n"
    }

    func exportCSV(to url: URL) {
        guard LicenseManager.shared.requireLicense() else { return }
        let rows = filteredPackets
        var lines = [Self.exportColumns.joined(separator: ",")]
        for p in rows {
            lines.append(Self.exportFields(p).map(Self.csvEscape).joined(separator: ","))
        }
        let text = lines.joined(separator: "\n") + "\n"
        do {
            try text.write(to: url, atomically: true, encoding: .utf8)
            statusMessage = "Exported \(rows.count) rows to \(url.lastPathComponent)"
            LoggerService.shared.log(statusMessage)
        } catch {
            statusMessage = "CSV export failed: \(error.localizedDescription)"
            LoggerService.shared.logError("CSV export failed", exception: error.localizedDescription)
        }
    }

    func exportJSON(to url: URL) {
        guard LicenseManager.shared.requireLicense() else { return }
        let rows = filteredPackets
        let objects: [[String: Any]] = rows.map { p in
            var d: [String: Any] = [
                "no": p.number,
                "time": Self.exportTimeFormatter.string(from: p.captureTime),
                "source": p.sourceEndpoint,
                "destination": p.destinationEndpoint,
                "protocol": p.proto,
                "length": Int(p.originalLen),
                "host": p.hostName,
            ]
            if let tls = p.tlsClientHello {
                d["tls"] = [
                    "version": p.tlsVersionDisplay,
                    "cipherCount": tls.cipherSuites.count,
                    "topCipher": p.tlsFirstCipherDisplay,
                    "extensionCount": tls.extensionCount,
                    "sni": tls.sni,
                    "alpn": tls.alpnProtocols,
                    "fingerprint": p.tlsFingerprintDisplay,
                ]
            }
            return d
        }
        do {
            let data = try JSONSerialization.data(withJSONObject: objects, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: url)
            statusMessage = "Exported \(rows.count) rows to \(url.lastPathComponent)"
            LoggerService.shared.log(statusMessage)
        } catch {
            statusMessage = "JSON export failed: \(error.localizedDescription)"
            LoggerService.shared.logError("JSON export failed", exception: error.localizedDescription)
        }
    }

    func exportSelectedPacketText(to url: URL) {
        guard LicenseManager.shared.requireLicense() else { return }
        guard let selectedPacket else { return }
        do {
            try Self.packetDetailText(selectedPacket).write(to: url, atomically: true, encoding: .utf8)
            statusMessage = "Exported packet #\(selectedPacket.number) details to \(url.lastPathComponent)"
            LoggerService.shared.log(statusMessage)
        } catch {
            statusMessage = "Packet detail export failed: \(error.localizedDescription)"
            LoggerService.shared.logError("Packet detail export failed", exception: error.localizedDescription)
        }
    }

    private static func csvEscape(_ s: String) -> String {
        guard s.contains(",") || s.contains("\"") || s.contains("\n") else { return s }
        return "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    func savePcap(to url: URL) {
        let toSave = packets
        savePcapPackets(toSave, to: url, label: "capture")
    }

    func saveFilteredPcap(to url: URL) {
        savePcapPackets(filteredPackets, to: url, label: "filtered capture")
    }

    func saveSelectedPcap(to url: URL) {
        guard let selectedPacket else { return }
        savePcapPackets([selectedPacket], to: url, label: "selected packet")
    }

    private func savePcapPackets(_ packets: [PacketModel], to url: URL, label: String) {
        guard LicenseManager.shared.requireLicense() else { return }
        let toSave = packets
        Task {
            do {
                try await pcapService.save(toSave, to: url.path)
                statusMessage = "Saved \(toSave.count) \(label) packet(s) to \(url.lastPathComponent)"
                LoggerService.shared.log(statusMessage)
            } catch {
                statusMessage = error.localizedDescription
                LoggerService.shared.logError("PCAP save failed", exception: error.localizedDescription)
            }
        }
    }

    func loadPcap(from url: URL, keepContainerNames: Bool = false) {
        guard !isCapturing else { return }
        Task {
            do {
                NativeStats.l7Clear()
                NativeStats.resetFlows()
                let loaded = try await pcapService.load(from: url.path)
                flowHosts.removeAll(keepingCapacity: true)
        ipHosts.removeAll(keepingCapacity: true)
                if !keepContainerNames { containerNames.removeAll(keepingCapacity: true) }
                packets = loaded.map { self.enrichHostName(for: $0) }
                rebuildDerivedPackets()
                statistics = CaptureStatistics()
                statistics.captureStartTime = packets.first?.captureTime ?? .now
                for p in packets { statistics.accumulate(p) }
                liveStats = statistics
                statusMessage = "Loaded \(loaded.count) packets from \(url.lastPathComponent)"
                LoggerService.shared.log(statusMessage)
            } catch {
                statusMessage = error.localizedDescription
                LoggerService.shared.logError("PCAP load failed", exception: error.localizedDescription)
            }
        }
    }

    // MARK: - Docker (VM) capture

    private(set) var isDockerCapturing = false
    private(set) var isDockerLive = false

    // Fallback when no containers can be inspected; common ports keep the pcap small.
    nonisolated static let defaultDockerFilter =
        "tcp port 6379 or tcp port 9092 or tcp port 29092 or tcp port 8080 "
      + "or tcp port 8000 or tcp port 5432 or tcp port 3306 or tcp port 27017 or tcp port 5001"

    // Bounded tcpdump in the Docker VM host netns, then loads the pcap; nil filter = auto-detect.
    func captureDockerContainers(seconds: Int = 10, maxPackets: Int = 8000,
                                 filter: String? = nil) {
        guard LicenseManager.shared.requireLicense() else { return }
        guard !isDockerCapturing else { return }
        if isCapturing { stopCapture() }   // free the pipeline so the pcap can load
        isDockerCapturing = true
        statusMessage = filter == nil
            ? "Detecting running containers…"
            : "Capturing Docker containers for \(seconds)s — generate traffic now…"
        Task { [weak self] in
            do {
                let effectiveFilter: String
                if let filter {
                    effectiveFilter = filter
                } else {
                    effectiveFilter = await Self.autoDetectedDockerFilter(
                        portsOnly: SettingsViewModel.shared.dockerCapturePortsOnly)
                    self?.statusMessage = "Capturing Docker containers for \(seconds)s — generate traffic now…"
                }
                if let docker = Self.dockerPath() {
                    self?.containerNames = await Self.discoverContainerNames(docker: docker)
                }
                let url = try await Self.runDockerCapture(seconds: seconds, maxPackets: maxPackets, filter: effectiveFilter)
                self?.loadPcap(from: url, keepContainerNames: true)
            } catch {
                self?.statusMessage = "Docker capture failed: \(error.localizedDescription)"
                LoggerService.shared.logError("Docker capture failed", exception: error.localizedDescription)
            }
            self?.isDockerCapturing = false
        }
    }

    // Streams tcpdump from the Docker VM into the table until Stop; nil filter = auto-detect.
    func startDockerLiveCapture(filter: String? = nil) {
        guard LicenseManager.shared.requireLicense() else { return }
        guard !isCapturing, !isDockerCapturing, !isDockerLive else { return }
        guard let docker = Self.dockerPath() else {
            statusMessage = "Docker CLI not found"
            LoggerService.shared.logError("Docker live capture failed", exception: "Docker CLI not found")
            return
        }

        packets.removeAll(keepingCapacity: true)
        rebuildDerivedPackets()
        statistics = CaptureStatistics()
        scanCount = 0
        badChecksumCount = 0
        flowHosts.removeAll(keepingCapacity: true)
        ipHosts.removeAll(keepingCapacity: true)
        NativeStats.l7Clear()
        NativeStats.resetFlows()
        statistics.captureStartTime = .now
        PacketModel.captureStartTime = .now
        liveStats = statistics
        liveScanCount = 0
        liveBadChecksumCount = 0
        lastUiPublish = ContinuousClock.now
        isCapturing = true
        isDockerLive = true
        NativeStats.setEnabled(false)
        statusMessage = "Detecting running containers…"
        onCaptureStateChanged?(true)
        LoggerService.shared.log("Docker live capture started")

        dockerLive.onPackets = { [weak self] pkts in
            Task { @MainActor in self?.flush(pkts) }
        }
        dockerLive.onStopped = { [weak self] reason in
            Task { @MainActor in self?.finishDockerLive(reason) }
        }

        Task { [weak self] in
            guard let self else { return }
            let effective: String
            if let filter {
                effective = filter
            } else {
                effective = await Self.autoDetectedDockerFilter(
                    portsOnly: SettingsViewModel.shared.dockerCapturePortsOnly)
            }
            guard self.isDockerLive else { return }   // user pressed Stop during detection
            self.containerNames = await Self.discoverContainerNames(docker: docker)
            self.statusMessage = "Live capturing Docker containers — generate traffic now…"
            self.dockerLive.start(docker: docker,
                                  filter: effective,
                                  containerSuffix: String(UUID().uuidString.prefix(8)).lowercased())
        }
    }

    private func finishDockerLive(_ reason: String) {
        guard isDockerLive else { return }
        isDockerLive = false
        isCapturing = false
        dockerLive.onPackets = nil
        dockerLive.onStopped = nil
        publishUI()   // flush the final burst so counts are exact
        statusMessage = reason.localizedCaseInsensitiveContains("failed")
            ? reason
            : "Stopped — \(statistics.totalPackets) packets, \(statistics.totalBytes) bytes"
        onCaptureStateChanged?(false)
        LoggerService.shared.log(statusMessage)
    }

    static func dockerPath() -> String? {
        let candidates = ["/usr/local/bin/docker", "/opt/homebrew/bin/docker",
                          "/Applications/Docker.app/Contents/Resources/bin/docker"]
        return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
    }

    // Prefer bridge subnets so containers without exposed ports aren't dropped; else ports, else default.
    private static func autoDetectedDockerFilter(portsOnly: Bool) async -> String {
        guard let docker = dockerPath() else { return defaultDockerFilter }

        if !portsOnly {
            let subnets = await discoverNetworkSubnets(docker: docker)
            if !subnets.isEmpty {
                return subnets.map { "net \($0)" }.joined(separator: " or ")
            }
        }

        let ports = await discoverContainerPorts(docker: docker)
        guard !ports.isEmpty else { return defaultDockerFilter }
        return ports.sorted().prefix(128).map { "port \($0)" }.joined(separator: " or ")
    }

    private static func discoverNetworkSubnets(docker: String) async -> [String] {
        guard let idsOut = try? await runDockerText(docker: docker, args: ["network", "ls", "-q"]) else { return [] }
        let ids = idsOut.split(whereSeparator: \.isNewline).map(String.init)
        guard !ids.isEmpty else { return [] }

        guard let out = try? await runDockerText(
            docker: docker,
            args: ["network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"] + ids
        ) else { return [] }

        var seen: Set<String> = []
        var subnets: [String] = []
        let regex = try? NSRegularExpression(pattern: #"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b"#)
        let range = NSRange(out.startIndex..., in: out)
        regex?.enumerateMatches(in: out, range: range) { match, _, _ in
            guard let match, let r = Range(match.range(at: 1), in: out) else { return }
            let cidr = String(out[r])
            if seen.insert(cidr).inserted { subnets.append(cidr) }
        }
        return Array(subnets.prefix(32))
    }

    private static func discoverContainerNames(docker: String) async -> [String: String] {
        guard let idsOut = try? await runDockerText(docker: docker, args: ["ps", "-q"]) else { return [:] }
        let ids = idsOut.split(whereSeparator: \.isNewline).map(String.init)
        guard !ids.isEmpty else { return [:] }

        // Format: "/name|ip1 ip2 …" (name has a leading slash).
        guard let out = try? await runDockerText(
            docker: docker,
            args: ["inspect", "--format",
                   "{{.Name}}|{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"] + ids
        ) else { return [:] }

        var map: [String: String] = [:]
        for line in out.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: "|", maxSplits: 1)
            guard parts.count == 2 else { continue }
            let name = String(parts[0].drop(while: { $0 == "/" }))
            guard !name.isEmpty else { continue }
            for ip in parts[1].split(separator: " ") where !ip.isEmpty {
                map[String(ip)] = name
            }
        }
        return map
    }

    // Internal exposed ports (inter-container traffic) plus published host ports.
    private static func discoverContainerPorts(docker: String) async -> Set<Int> {
        guard let idsOut = try? await runDockerText(docker: docker, args: ["ps", "-q"]) else { return [] }
        let ids = idsOut.split(whereSeparator: \.isNewline).map(String.init)
        guard !ids.isEmpty else { return [] }

        // Keys are "port/proto", e.g. "5432/tcp".
        let format = "{{range $p, $_ := .Config.ExposedPorts}}{{$p}} {{end}}"
                   + "{{range $p, $c := .NetworkSettings.Ports}}{{$p}} {{end}}"
        guard let out = try? await runDockerText(docker: docker,
                                                 args: ["inspect", "--format", format] + ids) else { return [] }

        var ports: Set<Int> = []
        let regex = try? NSRegularExpression(pattern: #"(\d{1,5})/(?:tcp|udp)"#)
        let range = NSRange(out.startIndex..., in: out)
        regex?.enumerateMatches(in: out, range: range) { match, _, _ in
            guard let match, let r = Range(match.range(at: 1), in: out),
                  let port = Int(out[r]), (1...65535).contains(port) else { return }
            ports.insert(port)
        }
        return ports
    }

    private static func runDockerText(docker: String, args: [String]) async throws -> String {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: docker)
        proc.arguments = args
        let outPipe = Pipe()
        proc.standardOutput = outPipe
        proc.standardError = Pipe()
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<String, Error>) in
            proc.terminationHandler = { _ in
                let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                cont.resume(returning: String(decoding: data, as: UTF8.self))
            }
            do { try proc.run() }
            catch { cont.resume(throwing: error) }
        }
    }

    private static func runDockerCapture(seconds: Int, maxPackets: Int, filter: String) async throws -> URL {
        guard let docker = dockerPath() else {
            throw NSError(domain: "WareHound", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "Docker CLI not found"])
        }

        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("warehound-docker-\(UUID().uuidString).pcap")
        FileManager.default.createFile(atPath: url.path, contents: nil)
        let outHandle = try FileHandle(forWritingTo: url)

        let inner = "timeout \(seconds) tcpdump -i any -U -c \(maxPackets) -w - '\(filter)'"

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: docker)
        proc.arguments = ["run", "--rm", "--net=host", "--privileged",
                          "nicolaka/netshoot", "sh", "-c", inner]
        proc.standardOutput = outHandle
        proc.standardError = Pipe()

        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            proc.terminationHandler = { _ in try? outHandle.close(); cont.resume() }
            do { try proc.run() }
            catch { try? outHandle.close(); cont.resume(throwing: error) }
        }

        let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
        guard size > 24 else {   // 24 = empty pcap (global header only)
            throw NSError(domain: "WareHound", code: 2, userInfo: [NSLocalizedDescriptionKey:
                "no container traffic captured — make sure Docker is running and services are active"])
        }
        return url
    }

    func clear() {
        packets.removeAll()
        rebuildDerivedPackets()
        statistics = CaptureStatistics()
        scanCount = 0
        badChecksumCount = 0
        flowHosts.removeAll(keepingCapacity: true)
        ipHosts.removeAll(keepingCapacity: true)
        NativeStats.l7Clear()
        NativeStats.resetFlows()
        containerNames.removeAll(keepingCapacity: true)
        liveStats = CaptureStatistics()
        liveScanCount = 0
        liveBadChecksumCount = 0
        selectedPacket = nil
        statusMessage = "Cleared"
    }

    func toggleStatsPanel() {
        isStatsPanelVisible.toggle()
    }

    // MARK: - Follow Stream

    func streamPackets(for packet: PacketModel) -> [PacketModel] {
        let key = Self.endpointPairKey(packet)
        return packets.filter { Self.endpointPairKey($0) == key }
    }

    func canFollowStream(_ packet: PacketModel) -> Bool {
        packet.meta.isIP
            && (packet.meta.ipProto == 6 || packet.meta.ipProto == 17)
            && (packet.sourcePort > 0 || packet.destPort > 0)
    }

    static func endpointPairKey(_ p: PacketModel) -> String {
        let a = "\(p.sourceIp):\(p.sourcePort)"
        let b = "\(p.destIp):\(p.destPort)"
        return a <= b ? "\(a)|\(b)" : "\(b)|\(a)"
    }

    func toggleSort(_ column: SortColumn) {
        if sortColumn == column {
            sortAscending.toggle()
        } else {
            sortColumn = column
            sortAscending = true
        }
        rebuildSortedPackets()
    }

    private func rebuildDerivedPackets() {
        let source = isCapturing
            ? Array(packets.suffix(Self.liveDisplayRowLimit))
            : packets
        let filtered = filterPackets(source)
        filteredPackets = filtered
        captureTablePackets = filterPackets(source.lazy.filter { $0.tlsClientHello != nil })
        sortedTablePackets = sortPackets(filtered)
    }

    private func rebuildSortedPackets() {
        let source = isCapturing
            ? filterPackets(packets.suffix(Self.liveDisplayRowLimit))
            : filteredPackets
        filteredPackets = source
        sortedTablePackets = sortPackets(source)
    }

    private enum FilterOperator {
        case equals
        case notEquals
        case contains
    }

    private struct FilterClause {
        let field: String
        let op: FilterOperator
        let value: String
    }

    private func filterPackets<S: Sequence>(_ source: S) -> [PacketModel] where S.Element == PacketModel {
        let text = filterText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return Array(source) }

        if let clauses = parseFilterExpression(text) {
            return source.filter { packet in
                clauses.allSatisfy { matches(packet, clause: $0) }
            }
        }

        let f = text.lowercased()
        return source.filter {
            searchableText(for: $0).contains(f)
        }
    }

    private func parseFilterExpression(_ text: String) -> [FilterClause]? {
        let normalized = text.replacingOccurrences(
            of: #"(?i)\s+and\s+|\s*&&\s*"#,
            with: " && ",
            options: .regularExpression
        )
        let parts = normalized
            .components(separatedBy: " && ")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }

        var clauses: [FilterClause] = []
        for part in parts {
            if let clause = parseFilterClause(part) {
                clauses.append(clause)
            } else {
                return nil
            }
        }
        return clauses.isEmpty ? nil : clauses
    }

    private func parseFilterClause(_ text: String) -> FilterClause? {
        let operators: [(String, FilterOperator)] = [
            ("contains", .contains),
            ("==", .equals),
            ("!=", .notEquals),
            ("=", .equals),
        ]

        for (token, op) in operators {
            guard let range = text.range(of: token, options: [.caseInsensitive]) else { continue }
            let field = text[..<range.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let value = text[range.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            guard !field.isEmpty, !value.isEmpty else { return nil }
            return FilterClause(field: field, op: op, value: value.lowercased())
        }

        return nil
    }

    private func matches(_ packet: PacketModel, clause: FilterClause) -> Bool {
        let candidates = filterValues(for: clause.field, packet: packet)
        guard !candidates.isEmpty else { return false }

        switch clause.op {
        case .equals:
            return candidates.contains { $0 == clause.value }
        case .notEquals:
            return !candidates.contains { $0 == clause.value }
        case .contains:
            return candidates.contains { $0.contains(clause.value) }
        }
    }

    private func filterValues(for field: String, packet: PacketModel) -> [String] {
        let values: [String] = switch field {
        case "proto", "protocol":
            [packet.proto]
        case "ip", "addr", "address":
            [packet.sourceIp, packet.destIp, packet.sourceEndpoint, packet.destinationEndpoint]
        case "src", "source", "srcip", "sourceip":
            [packet.sourceIp, packet.sourceEndpoint]
        case "dst", "dest", "destination", "dstip", "destip":
            [packet.destIp, packet.destinationEndpoint]
        case "mac", "ethaddr", "hwaddr":
            [packet.sourceMac, packet.destMac]
        case "srcmac", "sourcemac":
            [packet.sourceMac]
        case "dstmac", "destmac":
            [packet.destMac]
        case "port":
            ["\(packet.sourcePort)", "\(packet.destPort)"]
        case "srcport", "sourceport":
            ["\(packet.sourcePort)"]
        case "dstport", "destport", "destinationport":
            ["\(packet.destPort)"]
        case "host", "hostname", "sni":
            [packet.hostName, packet.tlsSniDisplay, packet.httpRequest?.host ?? ""]
        case "dns", "qname":
            [packet.dns?.name ?? ""] + (packet.dns?.addresses ?? []) + (packet.dns?.records.map(\.value) ?? [])
        case "checksum":
            [packet.checksumDisplay]
        case "flags", "tcpflags":
            [packet.tcpFlagsDisplay]
        case "icmp":
            [packet.icmpTypeName, packet.icmpDetail]
        case "http":
            if let http = packet.httpRequest {
                [http.method, http.target, http.version, http.host, http.userAgent]
            } else {
                []
            }
        case "method", "httpmethod":
            [packet.httpRequest?.method ?? ""]
        case "dhcp":
            [packet.dhcp?.messageName ?? ""]
        case "arp":
            if let arp = packet.arp {
                [arp.operationName, arp.senderIp, arp.senderMac, arp.targetIp, arp.targetMac]
            } else {
                []
            }
        case "quic":
            [packet.isQuic ? "true" : "false", packet.proto]
        case "mdns":
            [packet.isMdns ? "true" : "false", packet.proto, packet.dns?.name ?? ""]
        case "length", "len":
            ["\(packet.originalLen)", "\(packet.captureLen)"]
        default:
            []
        }
        return values
            .map { $0.lowercased() }
            .filter { !$0.isEmpty && $0 != "-" && $0 != "—" }
    }

    private func searchableText(for packet: PacketModel) -> String {
        let values: [String] = [
            packet.proto,
            packet.sourceIp,
            packet.destIp,
            packet.hostName,
            packet.sourceEndpoint,
            packet.destinationEndpoint,
            packet.tlsVersionDisplay,
            packet.tlsFirstCipherDisplay,
            packet.tlsSniDisplay,
            packet.tlsAlpnDisplay,
            packet.dns?.name ?? "",
            packet.httpRequest?.host ?? "",
            packet.httpRequest?.target ?? "",
            packet.dhcp?.messageName ?? "",
            packet.arp?.senderIp ?? "",
            packet.arp?.targetIp ?? "",
            packet.icmpTypeName,
        ]
        return values.joined(separator: " ").lowercased()
    }

    private func sortPackets(_ rows: [PacketModel]) -> [PacketModel] {
        // Packets are already in number order; skip the O(n log n) sort on every flush.
        if sortColumn == .number {
            return sortAscending ? rows : Array(rows.reversed())
        }
        let ordered = rows.sorted { a, b in
            switch sortColumn {
            case .number:      return a.number < b.number
            case .time:        return a.captureTime < b.captureTime
            case .source:      return a.sourceEndpoint.localizedStandardCompare(b.sourceEndpoint) == .orderedAscending
            case .destination: return a.destinationEndpoint.localizedStandardCompare(b.destinationEndpoint) == .orderedAscending
            case .proto:       return a.proto < b.proto
            case .length:      return a.originalLen < b.originalLen
            }
        }
        return sortAscending ? ordered : Array(ordered.reversed())
    }

    private func flush(_ batch: [PacketModel]) {
        let enrichedBatch = batch.map { enrichHostName(for: $0) }
        for packet in enrichedBatch {
            liveStats.accumulate(packet)
            if packet.isScan { liveScanCount += 1 }
            if packet.meta.checksumValidated && !packet.meta.checksumOK { liveBadChecksumCount += 1 }
        }
        packets.append(contentsOf: enrichedBatch)

        let cap = max(SettingsViewModel.shared.maxPacketBuffer, 1_000)
        if packets.count > cap {
            packets.removeFirst(packets.count - cap)
        }
        scheduleUIPublish()
    }

    // Throttle: leading-edge publish when idle, trailing-edge for the final burst (~3 Hz).
    private func scheduleUIPublish() {
        let now = ContinuousClock.now
        if now - lastUiPublish >= Self.uiPublishInterval {
            publishUI()
        } else if !uiPublishScheduled {
            uiPublishScheduled = true
            let delay = Self.uiPublishInterval - (now - lastUiPublish)
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: delay)
                guard let self else { return }
                self.uiPublishScheduled = false
                self.publishUI()
            }
        }
    }

    private func publishUI() {
        lastUiPublish = ContinuousClock.now
        statistics = liveStats
        scanCount = liveScanCount
        badChecksumCount = liveBadChecksumCount
        rebuildDerivedPackets()
        if isCapturing {
            statusMessage = "Capturing — \(statistics.totalPackets) packets, \(statistics.totalBytes) bytes"
        }
    }

    private func enrichHostName(for packet: PacketModel) -> PacketModel {
        let flowKey = FlowKey(packet: packet)

        if let tls = packet.tlsClientHello, !tls.sni.isEmpty {
            ipHosts[packet.destIp] = tls.sni
        }
        if let dns = packet.dns, dns.kind == .answer, !dns.name.isEmpty {
            for ip in dns.addresses { ipHosts[ip] = dns.name }
        }

        if !packet.hostName.isEmpty {
            flowHosts[flowKey] = packet.hostName
            return packet
        }

        if let hostName = flowHosts[flowKey], !hostName.isEmpty {
            return packet.withHostName(hostName)
        }
        if let hostName = ipHosts[packet.destIp] ?? ipHosts[packet.sourceIp] {
            return packet.withHostName(hostName)
        }
        let srcName = containerNames[packet.sourceIp]
        let dstName = containerNames[packet.destIp]
        if let srcName, let dstName {
            return packet.withHostName("\(srcName) → \(dstName)")
        }
        if let name = dstName ?? srcName {
            return packet.withHostName(name)
        }
        return packet
    }
}
