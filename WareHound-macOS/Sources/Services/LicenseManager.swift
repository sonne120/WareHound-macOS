import CryptoKit
import Foundation
import IOKit
import Observation

struct LicenseInfo: Codable, Equatable {
    var v: Int
    var product: String
    var email: String
    var issued: Int
    var expires: Int?
}

// Key format: WH1.<base64url JSON payload>.<base64url Ed25519 signature of the payload bytes>
enum LicenseKey {
    static let publicKeyBase64 = "P/sCwvrAPH7qwIyA84LfqVy1dU38DaSbnpqprMNVMjc="

    enum Failure: LocalizedError, Equatable {
        case malformed, badSignature, wrongProduct, expired

        var errorDescription: String? {
            switch self {
            case .malformed: "This is not a valid WareHound license key."
            case .badSignature: "The license key signature is invalid."
            case .wrongProduct: "This license key is for a different product."
            case .expired: "This license key has expired."
            }
        }
    }

    static func normalize(_ key: String) -> String {
        key.filter { !$0.isWhitespace }
    }

    static func verify(_ key: String, now: Date = .now) throws -> LicenseInfo {
        let parts = normalize(key).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3, parts[0] == "WH1",
              let payload = Data(base64URL: String(parts[1])),
              let signature = Data(base64URL: String(parts[2]))
        else { throw Failure.malformed }

        let publicKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: Data(base64Encoded: publicKeyBase64)!)
        guard publicKey.isValidSignature(signature, for: payload) else { throw Failure.badSignature }
        guard let info = try? JSONDecoder().decode(LicenseInfo.self, from: payload) else { throw Failure.malformed }
        guard info.product == "WareHound" else { throw Failure.wrongProduct }
        if let expires = info.expires, Double(expires) < now.timeIntervalSince1970 { throw Failure.expired }
        return info
    }
}

struct TrialRecord: Codable, Equatable {
    var first: Double
    var last: Double
}

enum TrialStore {
    enum LoadResult: Equatable {
        case missing
        case valid(TrialRecord)
        case tampered
    }

    private static let library = FileManager.default.urls(for: .libraryDirectory, in: .userDomainMask)[0]
    static var trialURLs = [
        library.appendingPathComponent("Application Support/WareHound/.state"),
        library.appendingPathComponent("Preferences/com.sonne120.WareHound.state"),
    ]
    static var licenseURL = library.appendingPathComponent("Application Support/WareHound/license.key")

    static func load() -> LoadResult {
        let blobs = trialURLs.compactMap { try? Data(contentsOf: $0) }
        guard !blobs.isEmpty else { return .missing }
        let records = blobs.compactMap(open)
        guard !records.isEmpty else { return .tampered }
        // Earliest start and latest sighting across copies, so restoring an old copy gains nothing.
        return .valid(TrialRecord(first: records.map(\.first).min()!, last: records.map(\.last).max()!))
    }

    static func save(_ record: TrialRecord) {
        guard let blob = seal(record) else { return }
        for url in trialURLs { write(blob, to: url) }
    }

    static func readLicense() -> String? {
        (try? String(contentsOf: licenseURL, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func writeLicense(_ key: String) {
        write(Data(key.utf8), to: licenseURL)
    }

    static func deleteLicense() {
        try? FileManager.default.removeItem(at: licenseURL)
    }

    // Test hook: wipes every copy of the trial record and the license.
    static func resetAll() {
        for url in trialURLs { try? FileManager.default.removeItem(at: url) }
        deleteLicense()
    }

    private static func write(_ data: Data, to url: URL) {
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: url, options: .atomic)
    }

    // MARK: - HMAC

    private static var hmacKey: SymmetricKey {
        let seed = Data("WareHound.trial.v1|\(deviceID)".utf8)
        return SymmetricKey(data: SHA256.hash(data: seed))
    }

    private static func seal(_ record: TrialRecord) -> Data? {
        guard let body = try? JSONEncoder().encode(record) else { return nil }
        return body + Data(HMAC<SHA256>.authenticationCode(for: body, using: hmacKey))
    }

    private static func open(_ blob: Data) -> TrialRecord? {
        guard blob.count > 32 else { return nil }
        let body = blob.prefix(blob.count - 32)
        let tag = blob.suffix(32)
        guard HMAC<SHA256>.isValidAuthenticationCode(tag, authenticating: body, using: hmacKey) else { return nil }
        return try? JSONDecoder().decode(TrialRecord.self, from: body)
    }

    static var deviceID: String {
        let entry = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        defer { IOObjectRelease(entry) }
        return IORegistryEntryCreateCFProperty(entry, "IOPlatformUUID" as CFString, kCFAllocatorDefault, 0)?
            .takeRetainedValue() as? String ?? "unknown-device"
    }
}

@MainActor
@Observable
final class LicenseManager {
    static let shared = LicenseManager()
    nonisolated static let trialDays = 10
    // Allowed backwards clock drift (NTP corrections, travel) before it counts as rollback.
    nonisolated static let clockTolerance: TimeInterval = 6 * 3600

    enum Status: Equatable {
        case trial(daysLeft: Int)
        case trialExpired
        case clockRolledBack
        case tampered
        case licensed(LicenseInfo)
    }

    private(set) var status: Status = .trialExpired
    private(set) var activationError: String?
    var isLicenseSheetPresented = false

    var isUsable: Bool {
        switch status {
        case .trial, .licensed: true
        case .trialExpired, .clockRolledBack, .tampered: false
        }
    }

    var statusText: String {
        switch status {
        case .trial(let days): "Trial · \(days) day\(days == 1 ? "" : "s") left"
        case .trialExpired: "Trial ended"
        case .clockRolledBack: "System clock was set back"
        case .tampered: "Trial data was modified"
        case .licensed(let info): "Licensed to \(info.email)"
        }
    }

    private init() {
        refresh()
    }

    func refresh(now: Date = .now) {
        status = Self.evaluate(now: now)
    }

    nonisolated static func evaluate(now: Date) -> Status {
        if let key = TrialStore.readLicense(), let info = try? LicenseKey.verify(key, now: now) {
            return .licensed(info)
        }
        let t = now.timeIntervalSince1970
        switch TrialStore.load() {
        case .missing:
            TrialStore.save(TrialRecord(first: t, last: t))
            return .trial(daysLeft: trialDays)
        case .tampered:
            return .tampered
        case .valid(var record):
            if t < record.last - clockTolerance { return .clockRolledBack }
            if t > record.last {
                record.last = t
                TrialStore.save(record)
            }
            let remaining = record.first + Double(trialDays) * 86_400 - t
            return remaining > 0 ? .trial(daysLeft: Int((remaining / 86_400).rounded(.up))) : .trialExpired
        }
    }

    @discardableResult
    func activate(_ key: String) -> Bool {
        do {
            _ = try LicenseKey.verify(key)
            TrialStore.writeLicense(LicenseKey.normalize(key))
            activationError = nil
            refresh()
            return true
        } catch {
            activationError = error.localizedDescription
            return false
        }
    }

    func removeLicense() {
        TrialStore.deleteLicense()
        refresh()
    }

    // Gate for paid features: shows the license sheet instead of running the action.
    func requireLicense() -> Bool {
        refresh()
        if isUsable { return true }
        isLicenseSheetPresented = true
        return false
    }
}

extension Data {
    init?(base64URL string: String) {
        var base64 = string.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        self.init(base64Encoded: base64)
    }
}
