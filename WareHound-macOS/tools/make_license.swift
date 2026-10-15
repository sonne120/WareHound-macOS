
// Private key location: ~/.warehound/license_signing_key (override with WAREHOUND_SIGNING_KEY).
import CryptoKit
import Foundation

let keyPath = ProcessInfo.processInfo.environment["WAREHOUND_SIGNING_KEY"]
    ?? (NSHomeDirectory() as NSString).appendingPathComponent(".warehound/license_signing_key")

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func loadKey() -> Curve25519.Signing.PrivateKey {
    guard let text = try? String(contentsOfFile: keyPath, encoding: .utf8),
          let raw = Data(base64Encoded: text.trimmingCharacters(in: .whitespacesAndNewlines)),
          let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    else { fail("No signing key at \(keyPath). Run: swift tools/make_license.swift init") }
    return key
}

func base64URL(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "init":
    guard !FileManager.default.fileExists(atPath: keyPath) else {
        fail("Refusing to overwrite existing key at \(keyPath): every issued license depends on it.")
    }
    let key = Curve25519.Signing.PrivateKey()
    let dir = (keyPath as NSString).deletingLastPathComponent
    try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    FileManager.default.createFile(atPath: keyPath,
                                   contents: Data(key.rawRepresentation.base64EncodedString().utf8),
                                   attributes: [.posixPermissions: 0o600])
    print("Private key saved to \(keyPath) — back it up somewhere safe.")
    print("Public key (paste into LicenseKey.publicKeyBase64):")
    print(key.publicKey.rawRepresentation.base64EncodedString())

case "pubkey":
    print(loadKey().publicKey.rawRepresentation.base64EncodedString())

case "issue":
    guard args.count >= 2, args[1].contains("@") else { fail("Usage: issue <email> [days]") }
    let now = Int(Date().timeIntervalSince1970)
    var payload: [String: Any] = ["v": 1, "product": "WareHound", "email": args[1], "issued": now]
    if args.count >= 3 {
        guard let days = Int(args[2]), days > 0 else { fail("days must be a positive number") }
        payload["expires"] = now + days * 86_400
    }
    let body = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
    let signature = try loadKey().signature(for: body)
    print("WH1.\(base64URL(body)).\(base64URL(signature))")

default:
    fail("Usage: swift tools/make_license.swift init | pubkey | issue <email> [days]")
}
