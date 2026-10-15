import Foundation
import NetworkExtension
import Observation

@MainActor
@Observable
final class TunnelController {
    struct BridgedPacket: Codable {
        let sequence: UInt64
        let timestamp: TimeInterval
        let proto: String
        let sourceIp: String
        let destIp: String
        let sourcePort: Int32
        let destPort: Int32
        let captureLen: UInt32
        let originalLen: UInt32
    }

    struct BridgedState: Codable {
        let isRunning: Bool
        let status: String
        let updatedAt: TimeInterval
    }

    private enum BridgeKeys {
        static let l7Stats = "l7stats"
        static let packets = "tunnelPackets"
        static let state = "tunnelState"
    }

    static let appGroup = "group.com.sonne120.WareHound"
    static let providerBundleId = "com.sonne120.WareHound.Tunnel"

    private(set) var isRunning = false
    private(set) var status = "Idle"
    private(set) var topSni: [(host: String, count: UInt64)] = []
    private(set) var topDns: [(name: String, count: UInt64)] = []

    var onPacketBatch: (([PacketModel]) -> Void)?
    var onStateChanged: ((Bool, String) -> Void)?

    private var manager: NETunnelProviderManager?
    private var pollTask: Task<Void, Never>?
    private var lastSequence: UInt64 = 0

    func start() async {
        do {
            updateState(isRunning: false, status: "Preparing Packet Tunnel configuration...")
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            let manager = managers.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = Self.providerBundleId
            proto.serverAddress = "WareHound IP tunnel"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "WareHound IP tunnel"
            manager.isEnabled = true

            updateState(isRunning: false, status: "Saving Packet Tunnel preferences...")
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()

            updateState(isRunning: false, status: "Starting Packet Tunnel (IP-only)...")
            try (manager.connection as? NETunnelProviderSession)?.startTunnel(options: nil)

            self.manager = manager
            updateState(isRunning: true, status: "Tunnel running (IP-only)")
            startPolling()
        } catch {
            updateState(isRunning: false, status: friendlyTunnelError(error))
        }
    }

    func stop() {
        (manager?.connection as? NETunnelProviderSession)?.stopTunnel()
        pollTask?.cancel()
        pollTask = nil
        updateState(isRunning: false, status: "Tunnel stopped")
    }

    private func updateState(isRunning: Bool, status: String) {
        self.isRunning = isRunning
        self.status = status
        onStateChanged?(isRunning, status)
    }

    private func friendlyTunnelError(_ error: Error) -> String {
        let message = error.localizedDescription
        let lowercased = message.lowercased()

        if lowercased.contains("permission")
            || lowercased.contains("denied")
            || lowercased.contains("entitlement")
            || lowercased.contains("profile")
            || lowercased.contains("sign")
            || lowercased.contains("configuration") {
            return "Tunnel failed: permission/signing issue. Check Network Extension entitlement and provisioning profile. [\(message)]"
        }

        return "Tunnel failed: \(message)"
    }

    private func startPolling() {
        pollTask?.cancel()
        pollTask = Task { [weak self] in
            guard let defaults = UserDefaults(suiteName: Self.appGroup) else { return }
            while !Task.isCancelled {
                self?.applyState(from: defaults)
                self?.applyPackets(from: defaults)
                self?.applyL7Stats(from: defaults)
                try? await Task.sleep(for: .milliseconds(1_000))
            }
        }
    }

    private func applyState(from defaults: UserDefaults) {
        guard let data = defaults.data(forKey: BridgeKeys.state),
              let bridgedState = try? JSONDecoder().decode(BridgedState.self, from: data) else { return }

        if bridgedState.isRunning != isRunning || bridgedState.status != status {
            isRunning = bridgedState.isRunning
            status = bridgedState.status
            onStateChanged?(isRunning, status)
        }
    }

    private func applyPackets(from defaults: UserDefaults) {
        guard let data = defaults.data(forKey: BridgeKeys.packets),
              let bridgedPackets = try? JSONDecoder().decode([BridgedPacket].self, from: data) else { return }

        let freshPackets = bridgedPackets
            .filter { $0.sequence > lastSequence }
            .sorted { $0.sequence < $1.sequence }

        guard !freshPackets.isEmpty else { return }
        lastSequence = freshPackets.last?.sequence ?? lastSequence

        let models = freshPackets.map { packet in
            PacketModel(
                number: Int(packet.sequence),
                packetId: Int32(truncatingIfNeeded: packet.sequence),
                sourcePort: packet.sourcePort,
                destPort: packet.destPort,
                proto: packet.proto,
                sourceIp: packet.sourceIp,
                destIp: packet.destIp,
                sourceMac: "",
                destMac: "",
                hostName: "",
                tlsClientHello: nil,
                captureTime: Date(timeIntervalSince1970: packet.timestamp),
                rawData: Data(),
                captureLen: packet.captureLen,
                originalLen: packet.originalLen
            )
        }
        onPacketBatch?(models)
    }

    private func applyL7Stats(from defaults: UserDefaults) {
        guard let data = defaults.data(forKey: BridgeKeys.l7Stats),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }

        let sni = (object["sni"] as? [[String: Any]]) ?? []
        let dns = (object["dns"] as? [[String: Any]]) ?? []
        topSni = sni.map { ($0["host"] as? String ?? "", ($0["count"] as? UInt64) ?? 0) }
        topDns = dns.map { ($0["name"] as? String ?? "", ($0["count"] as? UInt64) ?? 0) }
    }
}
