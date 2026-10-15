import Foundation
import Observation
import SwiftUI

struct BpfAccessStatus {
    var deviceCount = 0
    var hasReadAccess = false
    var hasWriteAccess = false
    var detail = "Not checked"

    var isAvailable: Bool {
        deviceCount > 0 && hasReadAccess && hasWriteAccess
    }

    var title: String {
        if isAvailable { return "BPF access available" }
        if deviceCount == 0 { return "No BPF devices found" }
        return "BPF permission required"
    }
}

private enum BuildCapabilities {
    #if WAREHOUND_TUNNEL_BUILD
    static let supportsTunnelCapture = true
    static let tunnelUnavailableReason: String? = nil
    #else
    static let supportsTunnelCapture = false
    static let tunnelUnavailableReason = "Packet Tunnel is unavailable in unsigned local builds. Rebuild with ./build_app.sh tunnel-signed and valid Apple signing to enable it."
    #endif
}

enum CaptureBackend: Int, Identifiable, Sendable {
    case pcap   = 0
    case tunnel = 1

    static var availableBackends: [CaptureBackend] {
        BuildCapabilities.supportsTunnelCapture ? [.pcap, .tunnel] : [.pcap]
    }

    var id: Int { rawValue }

    var displayName: String {
        switch self {
        case .pcap:   "libpcap / BPF"
        case .tunnel: "Packet Tunnel (IP-only)"
        }
    }

    var detail: String {
        switch self {
        case .pcap:   "Live L2 capture via libpcap (includes ARP). Requires BPF access."
        case .tunnel: "Intercept traffic through NEPacketTunnelProvider as bare IP packets. No ARP, no Ethernet headers, no fake L2 assumptions."
        }
    }
}

@MainActor
@Observable
final class SettingsViewModel {
    static let shared = SettingsViewModel()

    let timeFormats = ["Relative", "Absolute", "Delta"]
    let themes = ["Light", "Dark"]
    let pcapBackends = ["Native (libpcap)"]

    var selectedCaptureBackend: CaptureBackend = .pcap {
        didSet {
            if selectedCaptureBackend == .tunnel && !BuildCapabilities.supportsTunnelCapture {
                selectedCaptureBackend = .pcap
                return
            }
            UserDefaults.standard.set(selectedCaptureBackend.rawValue, forKey: "captureBackend")
        }
    }

    var supportsTunnelCapture: Bool { BuildCapabilities.supportsTunnelCapture }
    var tunnelUnavailableReason: String? { BuildCapabilities.tunnelUnavailableReason }
    var tunnelBuildTitle: String {
        supportsTunnelCapture ? "Packet Tunnel available" : "Packet Tunnel unavailable"
    }
    var tunnelBuildDetail: String {
        if let tunnelUnavailableReason {
            return tunnelUnavailableReason
        }
        return "Signed Network Extension build detected. Tunnel mode captures IP packets only and does not include Ethernet headers or ARP."
    }

    var darkModeEnabled = false {
        didSet { UserDefaults.standard.set(darkModeEnabled, forKey: "darkMode") }
    }

    var maxPacketBuffer = 10_000 {
        didSet { UserDefaults.standard.set(maxPacketBuffer, forKey: "maxPacketBuffer") }
    }

    var autoScroll = true {
        didSet { UserDefaults.standard.set(autoScroll, forKey: "autoScroll") }
    }

    // Ports-only Docker auto-detect (quieter) instead of whole bridge subnets.
    var dockerCapturePortsOnly = false {
        didSet { UserDefaults.standard.set(dockerCapturePortsOnly, forKey: "dockerCapturePortsOnly") }
    }

    // Port-string → label overrides; take precedence over the built-in table.
    var customPortLabels: [String: String] = [:] {
        didSet {
            UserDefaults.standard.set(customPortLabels, forKey: "customPortLabels")
            PacketModel.applyPortLabelOverrides(customPortLabels)
        }
    }
    var showMacAddresses = false {
        didSet { UserDefaults.standard.set(showMacAddresses, forKey: "showMacAddresses") }
    }
    var showChecksum = true {
        didSet { UserDefaults.standard.set(showChecksum, forKey: "showChecksum") }
    }
    var showTcpFlags = true {
        didSet { UserDefaults.standard.set(showTcpFlags, forKey: "showTcpFlags") }
    }
    var showTtl = true {
        didSet { UserDefaults.standard.set(showTtl, forKey: "showTtl") }
    }
    var showTcpWindow = true {
        didSet { UserDefaults.standard.set(showTcpWindow, forKey: "showTcpWindow") }
    }
    var showVlan = false {
        didSet { UserDefaults.standard.set(showVlan, forKey: "showVlan") }
    }
    var showQos = false {
        didSet { UserDefaults.standard.set(showQos, forKey: "showQos") }
    }
    var showIcmp = false {
        didSet { UserDefaults.standard.set(showIcmp, forKey: "showIcmp") }
    }
    var showTcpSeq = false {
        didSet { UserDefaults.standard.set(showTcpSeq, forKey: "showTcpSeq") }
    }
    var showTcpAck = false {
        didSet { UserDefaults.standard.set(showTcpAck, forKey: "showTcpAck") }
    }
    var captureFilter = "" {
        didSet { UserDefaults.standard.set(captureFilter, forKey: "captureFilter") }
    }
    private(set) var bpfAccessStatus = BpfAccessStatus()
    private(set) var isBpfDaemonInstalled = false
    private(set) var isBpfInstallerRunning = false
    private(set) var bpfInstallerMessage: String?

    static let protocolColorTypes = ["TCP", "UDP", "TLS", "HTTPS", "QUIC", "HTTP",
                                     "DNS", "MDNS", "DHCP", "ICMP", "ARP"]

    // 0xRRGGBB overrides; missing entries fall back to AppColors.chartColor.
    var protocolColorOverrides: [String: Int] = [:] {
        didSet { UserDefaults.standard.set(protocolColorOverrides, forKey: "protocolColors") }
    }

    var customProtocolTypes: [String] = [] {
        didSet { UserDefaults.standard.set(customProtocolTypes, forKey: "customProtocolTypes") }
    }

    var allProtocolColorTypes: [String] { Self.protocolColorTypes + customProtocolTypes }

    func addCustomProtocol(_ name: String) {
        let key = name.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        guard !key.isEmpty,
              !Self.protocolColorTypes.contains(key),
              !customProtocolTypes.contains(key) else { return }
        customProtocolTypes.append(key)
    }

    func removeCustomProtocol(_ name: String) {
        let key = name.uppercased()
        customProtocolTypes.removeAll { $0 == key }
        protocolColorOverrides[key] = nil
    }

    // ICMPv6 shares the ICMP colour.
    func color(forProtocol proto: String) -> Color {
        let key = normalizedProtocolKey(proto)
        if let hex = protocolColorOverrides[key] {
            return Color(hex: UInt32(truncatingIfNeeded: hex))
        }
        return AppColors.chartColor(forProtocol: key)
    }

    func setProtocolColor(_ color: Color, forProtocol proto: String) {
        protocolColorOverrides[normalizedProtocolKey(proto)] = Int(color.rgbHex)
    }

    func resetProtocolColors() {
        protocolColorOverrides = [:]
    }

    private func normalizedProtocolKey(_ proto: String) -> String {
        let upper = proto.uppercased()
        if upper.hasPrefix("TLS") { return "TLS" }
        return upper == "ICMPV6" ? "ICMP" : upper
    }

    var selectedTimeFormatIndex = 0 {
        didSet {
            let format: TimeFormatType = switch selectedTimeFormatIndex {
            case 1: .absolute
            case 2: .delta
            default: .relative
            }
            PacketModel.currentTimeFormat = format
        }
    }

    var selectedThemeIndex = 0 {
        didSet { darkModeEnabled = selectedThemeIndex == 1 }
    }

    private init() {
        darkModeEnabled = UserDefaults.standard.bool(forKey: "darkMode")
        showMacAddresses = UserDefaults.standard.bool(forKey: "showMacAddresses")
        let d = UserDefaults.standard
        if d.object(forKey: "autoScroll") != nil { autoScroll = d.bool(forKey: "autoScroll") }
        if d.object(forKey: "dockerCapturePortsOnly") != nil { dockerCapturePortsOnly = d.bool(forKey: "dockerCapturePortsOnly") }
        if let savedPortLabels = d.dictionary(forKey: "customPortLabels") as? [String: String] {
            customPortLabels = savedPortLabels
        }
        PacketModel.applyPortLabelOverrides(customPortLabels)
        if d.object(forKey: "showChecksum") != nil { showChecksum = d.bool(forKey: "showChecksum") }
        if d.object(forKey: "showTcpFlags") != nil { showTcpFlags = d.bool(forKey: "showTcpFlags") }
        if d.object(forKey: "showTtl") != nil { showTtl = d.bool(forKey: "showTtl") }
        if d.object(forKey: "showTcpWindow") != nil { showTcpWindow = d.bool(forKey: "showTcpWindow") }
        if d.object(forKey: "showVlan") != nil { showVlan = d.bool(forKey: "showVlan") }
        if d.object(forKey: "showQos") != nil { showQos = d.bool(forKey: "showQos") }
        if d.object(forKey: "showIcmp") != nil { showIcmp = d.bool(forKey: "showIcmp") }
        if d.object(forKey: "showTcpSeq") != nil { showTcpSeq = d.bool(forKey: "showTcpSeq") }
        if d.object(forKey: "showTcpAck") != nil { showTcpAck = d.bool(forKey: "showTcpAck") }
        let buf = UserDefaults.standard.integer(forKey: "maxPacketBuffer")
        if buf > 0 { maxPacketBuffer = buf }
        selectedThemeIndex = darkModeEnabled ? 1 : 0
        if let backend = CaptureBackend(rawValue: UserDefaults.standard.integer(forKey: "captureBackend")) {
            selectedCaptureBackend = backend
        }
        if selectedCaptureBackend == .tunnel && !BuildCapabilities.supportsTunnelCapture {
            selectedCaptureBackend = .pcap
        }
        captureFilter = UserDefaults.standard.string(forKey: "captureFilter") ?? ""
        // Read per element (values are NSNumber); a whole-dictionary cast can drop them.
        if let saved = UserDefaults.standard.dictionary(forKey: "protocolColors") {
            var restored: [String: Int] = [:]
            for (key, value) in saved {
                if let number = value as? NSNumber { restored[key] = number.intValue }
            }
            protocolColorOverrides = restored
        }
        if let savedCustom = UserDefaults.standard.array(forKey: "customProtocolTypes") as? [String] {
            customProtocolTypes = savedCustom
        }
        refreshBpfAccessStatus()
    }

    func installBpfAccess() async {
        await runBpfInstaller(BpfAccessInstaller.install) { status in
            status.isAvailable
                ? "BPF access installed. Live capture is ready."
                : "Installed. Log out and back in so macOS applies the new access_bpf group membership."
        }
    }

    func removeBpfAccess() async {
        await runBpfInstaller(BpfAccessInstaller.uninstall) { _ in
            "BPF access removed. Log out and back in to drop the access_bpf group membership."
        }
    }

    private func runBpfInstaller(_ action: () async throws -> Void,
                                 message: (BpfAccessStatus) -> String) async {
        isBpfInstallerRunning = true
        bpfInstallerMessage = nil
        defer { isBpfInstallerRunning = false }
        do {
            try await action()
            refreshBpfAccessStatus()
            bpfInstallerMessage = message(bpfAccessStatus)
        } catch BpfAccessInstaller.Failure.cancelled {
            bpfInstallerMessage = nil
        } catch {
            bpfInstallerMessage = "Failed: \(error.localizedDescription)"
        }
    }

    func refreshBpfAccessStatus() {
        isBpfDaemonInstalled = BpfAccessInstaller.isDaemonInstalled
        let deviceNames = (try? FileManager.default.contentsOfDirectory(atPath: "/dev")) ?? []
        let bpfPaths = deviceNames
            .filter { $0.hasPrefix("bpf") }
            .map { "/dev/\($0)" }
            .sorted()

        guard !bpfPaths.isEmpty else {
            bpfAccessStatus = BpfAccessStatus(
                deviceCount: 0,
                hasReadAccess: false,
                hasWriteAccess: false,
                detail: "libpcap needs /dev/bpf* devices for live capture. macOS normally creates them when packet capture is available."
            )
            return
        }

        let readable = bpfPaths.contains { FileManager.default.isReadableFile(atPath: $0) }
        let writable = bpfPaths.contains { FileManager.default.isWritableFile(atPath: $0) }
        let accessDetail = readable && writable
            ? "Found \(bpfPaths.count) BPF device(s). Live libpcap capture should be able to open a BPF device."
            : "Found \(bpfPaths.count) BPF device(s), but this app cannot read/write them. Press Install BPF access… to grant it."

        bpfAccessStatus = BpfAccessStatus(
            deviceCount: bpfPaths.count,
            hasReadAccess: readable,
            hasWriteAccess: writable,
            detail: accessDetail
        )
    }
}
