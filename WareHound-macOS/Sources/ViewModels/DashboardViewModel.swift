import Foundation
import Observation
import AppKit


struct SavedCollection: Identifiable {
    let id: String
    var name: String
    let createdAt: Date
    var modifiedAt: Date
    var packets: [PacketModel]

    var packetCount: Int { packets.count }
    var displayInfo: String { "\(name) (\(packetCount) packets)" }
}

@MainActor
@Observable
final class PacketCollectionService {
    static let shared = PacketCollectionService()

    private struct CollectionRecord: Codable {
        let id: String
        var name: String
        let createdAt: Date
        var modifiedAt: Date
        var pcapFileName: String
        var packetCount: Int
    }

    private(set) var collections: [SavedCollection] = []
    private let pcapService = PcapFileService()
    private let fileManager = FileManager.default
    private let indexFileName = "collections.json"

    private var storageDirectory: URL {
        let base = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? fileManager.temporaryDirectory
        return base.appendingPathComponent("WareHound/Collections", isDirectory: true)
    }

    private var indexURL: URL {
        storageDirectory.appendingPathComponent(indexFileName)
    }

    private init() {
        Task { await loadFromDisk() }
    }

    @discardableResult
    func createCollection(name: String, packets: [PacketModel]) -> SavedCollection {
        let c = SavedCollection(id: UUID().uuidString, name: name,
                                createdAt: .now, modifiedAt: .now, packets: packets)
        collections.append(c)
        Task { await persistCollection(c) }
        return c
    }

    func removeCollection(id: String) {
        let removed = collections.first { $0.id == id }
        collections.removeAll { $0.id == id }
        Task { await removePersistedCollection(id: id, fallback: removed) }
    }

    func exportToCsv(collectionId: String, to url: URL) {
        guard LicenseManager.shared.requireLicense() else { return }
        guard let c = collections.first(where: { $0.id == collectionId }) else { return }

        var lines = ["Number,Time,Protocol,SourceIP,DestIP,SourcePort,DestPort,SourceMAC,DestMAC,HostName"]
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"

        for p in c.packets {
            lines.append([
                "\(p.number)", df.string(from: p.captureTime), p.proto,
                p.sourceIp, p.destIp, "\(p.sourcePort)", "\(p.destPort)",
                p.sourceMac, p.destMac, p.hostName
            ].joined(separator: ","))
        }
        try? lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    private func loadFromDisk() async {
        let records: [CollectionRecord]
        do {
            guard fileManager.fileExists(atPath: indexURL.path) else { return }
            let data = try Data(contentsOf: indexURL)
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            records = try decoder.decode([CollectionRecord].self, from: data)
        } catch {
            LoggerService.shared.logError("Failed to load saved collections", exception: error.localizedDescription)
            return
        }

        var loaded: [SavedCollection] = []
        for record in records {
            let pcapURL = storageDirectory.appendingPathComponent(record.pcapFileName)
            do {
                let packets = try await pcapService.load(from: pcapURL.path)
                loaded.append(SavedCollection(
                    id: record.id,
                    name: record.name,
                    createdAt: record.createdAt,
                    modifiedAt: record.modifiedAt,
                    packets: packets
                ))
            } catch {
                LoggerService.shared.logError(
                    "Failed to load saved collection \(record.name)",
                    exception: error.localizedDescription
                )
            }
        }

        var merged = Dictionary(uniqueKeysWithValues: loaded.map { ($0.id, $0) })
        for collection in collections {
            merged[collection.id] = collection
        }
        collections = Array(merged.values).sorted { $0.modifiedAt > $1.modifiedAt }
        if !loaded.isEmpty {
            LoggerService.shared.log("Loaded \(loaded.count) saved packet collection(s)")
        }
    }

    private func persistCollection(_ collection: SavedCollection) async {
        do {
            try ensureStorageDirectory()
            let pcapURL = storageDirectory.appendingPathComponent(pcapFileName(for: collection.id))
            try await pcapService.save(collection.packets, to: pcapURL.path)
            try saveIndex()
            LoggerService.shared.log("Saved packet collection \(collection.name)")
        } catch {
            LoggerService.shared.logError(
                "Failed to persist packet collection \(collection.name)",
                exception: error.localizedDescription
            )
        }
    }

    private func removePersistedCollection(id: String, fallback: SavedCollection?) async {
        let pcapURL = storageDirectory.appendingPathComponent(pcapFileName(for: id))
        do {
            if fileManager.fileExists(atPath: pcapURL.path) {
                try fileManager.removeItem(at: pcapURL)
            }
            try saveIndex()
            if let fallback {
                LoggerService.shared.log("Removed saved packet collection \(fallback.name)")
            }
        } catch {
            LoggerService.shared.logError("Failed to remove saved collection", exception: error.localizedDescription)
        }
    }

    private func saveIndex() throws {
        try ensureStorageDirectory()
        let records = collections.map {
            CollectionRecord(
                id: $0.id,
                name: $0.name,
                createdAt: $0.createdAt,
                modifiedAt: $0.modifiedAt,
                pcapFileName: pcapFileName(for: $0.id),
                packetCount: $0.packetCount
            )
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(records)
        try data.write(to: indexURL, options: [.atomic])
    }

    private func ensureStorageDirectory() throws {
        try fileManager.createDirectory(at: storageDirectory, withIntermediateDirectories: true)
    }

    private func pcapFileName(for id: String) -> String {
        "\(id).pcap"
    }
}


struct PacketTreeNode: Identifiable {
    let id = UUID()
    let title: String
    var children: [PacketTreeNode]?

    init(_ title: String, children: [PacketTreeNode]? = nil) {
        self.title = title
        self.children = children
    }
}


@MainActor
@Observable
final class DashboardViewModel {
    private let collectionService = PacketCollectionService.shared

    var selectedCollection: SavedCollection? {
        didSet { selectedPacket = nil }
    }
    var selectedPacket: PacketModel? {
        didSet { updatePacketDetails() }
    }
    private(set) var packetDetails: [PacketTreeNode] = []

    var collections: [SavedCollection] { collectionService.collections }

    func deleteCollection() {
        guard let c = selectedCollection else { return }
        collectionService.removeCollection(id: c.id)
        selectedCollection = nil
    }

    func exportToCsv() {
        guard LicenseManager.shared.requireLicense() else { return }
        guard let c = selectedCollection else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.commaSeparatedText]
        panel.nameFieldStringValue = "\(c.name).csv"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        collectionService.exportToCsv(collectionId: c.id, to: url)
    }

    private func updatePacketDetails() {
        guard let p = selectedPacket else { packetDetails = []; return }

        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"

        var details = [
            PacketTreeNode("Packet #\(p.number): \(p.proto)", children: [
                PacketTreeNode("Capture Time: \(df.string(from: p.captureTime))"),
                PacketTreeNode("Packet ID: \(p.packetId)"),
            ]),
            PacketTreeNode("Ethernet II, Src: \(p.sourceMac), Dst: \(p.destMac)", children: [
                PacketTreeNode("Source MAC: \(p.sourceMac)"),
                PacketTreeNode("Destination MAC: \(p.destMac)"),
            ]),
            PacketTreeNode("Internet Protocol, Src: \(p.sourceIp), Dst: \(p.destIp)", children: [
                PacketTreeNode("Source IP: \(p.sourceIp)"),
                PacketTreeNode("Destination IP: \(p.destIp)"),
            ]),
            PacketTreeNode("\(p.proto), Src Port: \(p.sourcePort), Dst Port: \(p.destPort)", children: [
                PacketTreeNode("Source Port: \(p.sourcePort)"),
                PacketTreeNode("Destination Port: \(p.destPort)"),
            ]),
        ]

        if let arp = p.arp {
            details.append(PacketTreeNode("ARP \(arp.operationName)", children: [
                PacketTreeNode("Sender: \(arp.senderIp) / \(arp.senderMac)"),
                PacketTreeNode("Target: \(arp.targetIp) / \(arp.targetMac)"),
            ]))
        }
        if let dhcp = p.dhcp {
            details.append(PacketTreeNode("DHCP \(dhcp.messageName)", children: [
                PacketTreeNode(String(format: "Transaction ID: 0x%08X", dhcp.transactionId)),
                PacketTreeNode("Client MAC: \(dhcp.clientMac)"),
                PacketTreeNode("Requested IP: \(dhcp.requestedIp.isEmpty ? "—" : dhcp.requestedIp)"),
                PacketTreeNode("Server Identifier: \(dhcp.serverIdentifier.isEmpty ? "—" : dhcp.serverIdentifier)"),
            ]))
        }
        if let http = p.httpRequest {
            details.append(PacketTreeNode("HTTP \(http.method) \(http.target)", children: [
                PacketTreeNode("Version: \(http.version)"),
                PacketTreeNode("Host: \(http.host.isEmpty ? "—" : http.host)"),
                PacketTreeNode("User-Agent: \(http.userAgent.isEmpty ? "—" : http.userAgent)"),
            ]))
        }
        if let dns = p.dns {
            let kind = p.isMdns ? "mDNS" : "DNS"
            details.append(PacketTreeNode("\(kind) \(dns.kind == .query ? "Query" : "Response"): \(dns.name)", children: [
                PacketTreeNode("Type: \(PacketDetailView.dnsTypeName(dns.qtype))"),
                PacketTreeNode(String(format: "Transaction ID: 0x%04X", dns.txid)),
                PacketTreeNode("Addresses: \(dns.addresses.isEmpty ? "—" : dns.addresses.joined(separator: ", "))"),
                PacketTreeNode("Records: \(dns.records.isEmpty ? "—" : dns.records.map { "\($0.name) \(PacketDetailView.dnsTypeName($0.type)) \($0.value)" }.joined(separator: "; "))"),
            ]))
        }
        if p.meta.hasIcmp {
            details.append(PacketTreeNode("ICMP: \(p.icmpTypeName)", children: [
                PacketTreeNode(p.icmpDetail),
            ]))
        }
        if p.meta.tcpParsed {
            details.append(PacketTreeNode("TCP Stream", children: [
                PacketTreeNode(p.tcpStreamKey),
            ]))
        }

        packetDetails = details
    }
}
