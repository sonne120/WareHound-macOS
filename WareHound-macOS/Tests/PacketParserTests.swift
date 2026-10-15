import Foundation
import XCTest

final class PacketParserTests: XCTestCase {
    func testParsesIPv4TcpAndChecksum() {
        let tcp = PacketFixtures.tcp(sourcePort: 12_345, destPort: 443, flags: 0x02)
        let ip = PacketFixtures.ipv4(proto: 6, source: [192, 168, 1, 10], destination: [93, 184, 216, 34], payload: tcp)
        let frame = PacketFixtures.ethernet(etherType: 0x0800, payload: ip)

        let packet = PacketModel.from(rawFrame: frame, number: 1)

        XCTAssertEqual(packet.proto, "TCP")
        XCTAssertEqual(packet.sourceIp, "192.168.1.10")
        XCTAssertEqual(packet.destIp, "93.184.216.34")
        XCTAssertEqual(packet.sourcePort, 12_345)
        XCTAssertEqual(packet.destPort, 443)
        XCTAssertTrue(packet.meta.isIP)
        XCTAssertFalse(packet.meta.isIPv6)
        XCTAssertTrue(packet.meta.tcpParsed)
        XCTAssertEqual(packet.tcpFlagsDisplay, "SYN")
        XCTAssertTrue(packet.meta.checksumValidated)
        XCTAssertTrue(packet.meta.checksumOK)
    }

    func testParsesIPv6Udp() {
        let udp = PacketFixtures.udp(sourcePort: 53_000, destPort: 123, payload: Data([1, 2, 3, 4]))
        let ip = PacketFixtures.ipv6(
            nextHeader: 17,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            payload: udp
        )
        let frame = PacketFixtures.ethernet(etherType: 0x86DD, payload: ip)

        let packet = PacketModel.from(rawFrame: frame, number: 2)

        XCTAssertEqual(packet.proto, "UDP")
        XCTAssertTrue(packet.meta.isIP)
        XCTAssertTrue(packet.meta.isIPv6)
        XCTAssertEqual(packet.sourcePort, 53_000)
        XCTAssertEqual(packet.destPort, 123)
        XCTAssertFalse(packet.meta.checksumValidated)
    }

    func testParsesIcmpTypeAndCode() {
        let ip = PacketFixtures.ipv4(
            proto: 1,
            source: [10, 0, 0, 1],
            destination: [10, 0, 0, 2],
            payload: PacketFixtures.icmpEchoRequest()
        )
        let frame = PacketFixtures.ethernet(etherType: 0x0800, payload: ip)

        let packet = PacketModel.from(rawFrame: frame, number: 3)

        XCTAssertEqual(packet.proto, "ICMP")
        XCTAssertTrue(packet.meta.hasIcmp)
        XCTAssertEqual(packet.meta.icmpType, 8)
        XCTAssertEqual(packet.meta.icmpCode, 0)
        XCTAssertEqual(packet.icmpDisplay, "Echo request")
    }

    func testParsesVlanTag() {
        let udp = PacketFixtures.udp(sourcePort: 5353, destPort: 5353, payload: PacketFixtures.dnsQuery("printer.local"))
        let ip = PacketFixtures.ipv4(proto: 17, source: [192, 168, 1, 20], destination: [224, 0, 0, 251], payload: udp)
        let frame = PacketFixtures.vlanEthernet(vlanId: 42, innerEtherType: 0x0800, payload: ip)

        let packet = PacketModel.from(rawFrame: frame, number: 4)

        XCTAssertEqual(packet.meta.vlanId, 42)
        XCTAssertEqual(packet.vlanDisplay, "42")
        XCTAssertEqual(packet.proto, "MDNS")
        XCTAssertTrue(packet.isMdns)
    }

    func testParsesDnsQuery() throws {
        let udp = PacketFixtures.udp(sourcePort: 55_000, destPort: 53, payload: PacketFixtures.dnsQuery("example.com"))
        let ip = PacketFixtures.ipv4(proto: 17, source: [192, 168, 1, 10], destination: [1, 1, 1, 1], payload: udp)
        let frame = PacketFixtures.ethernet(etherType: 0x0800, payload: ip)

        let packet = PacketModel.from(rawFrame: frame, number: 5)
        let dns = try XCTUnwrap(packet.dns)

        XCTAssertEqual(packet.proto, "DNS")
        XCTAssertEqual(dns.kind, .query)
        XCTAssertEqual(dns.name, "example.com")
        XCTAssertEqual(dns.qtype, 1)
        XCTAssertTrue(dns.addresses.isEmpty)
    }

    func testParsesDnsResponseRecords() throws {
        let udp = PacketFixtures.udp(sourcePort: 53, destPort: 55_000, payload: PacketFixtures.dnsResponseA("example.com", address: [93, 184, 216, 34]))
        let ip = PacketFixtures.ipv4(proto: 17, source: [1, 1, 1, 1], destination: [192, 168, 1, 10], payload: udp)
        let frame = PacketFixtures.ethernet(etherType: 0x0800, payload: ip)

        let packet = PacketModel.from(rawFrame: frame, number: 6)
        let dns = try XCTUnwrap(packet.dns)

        XCTAssertEqual(packet.proto, "DNS")
        XCTAssertEqual(dns.kind, .answer)
        XCTAssertEqual(dns.name, "example.com")
        XCTAssertEqual(dns.addresses, ["93.184.216.34"])
        XCTAssertEqual(dns.records.count, 1)
        XCTAssertEqual(dns.records.first?.value, "93.184.216.34")
    }

    func testParsesTlsClientHelloSni() throws {
        let tls = PacketFixtures.tlsClientHello(host: "www.example.com")
        let tcp = PacketFixtures.tcp(sourcePort: 52_000, destPort: 443, flags: 0x18, payload: tls)
        let ip = PacketFixtures.ipv4(proto: 6, source: [192, 168, 1, 10], destination: [93, 184, 216, 34], payload: tcp)
        let frame = PacketFixtures.ethernet(etherType: 0x0800, payload: ip)

        let packet = PacketModel.from(rawFrame: frame, number: 7)
        let clientHello = try XCTUnwrap(packet.tlsClientHello)

        XCTAssertEqual(packet.proto, "TLS")
        XCTAssertEqual(clientHello.sni, "www.example.com")
        XCTAssertEqual(clientHello.cipherSuites, [UInt16(0x1301)])
        XCTAssertEqual(clientHello.extensionCount, 1)
    }

    func testHandlesTruncatedPackets() {
        let tcp = PacketFixtures.tcp(sourcePort: 12_345, destPort: 80, flags: 0x10)
        let ip = PacketFixtures.ipv4(proto: 6, source: [10, 1, 1, 1], destination: [10, 1, 1, 2], payload: tcp)
        let frame = PacketFixtures.ethernet(etherType: 0x0800, payload: ip)
        let packet = PacketModel.from(
            rawFrame: frame,
            number: 8,
            captureTime: Date(timeIntervalSince1970: 0),
            captureLen: UInt32(frame.count - 8),
            originalLen: UInt32(frame.count)
        )
        let tooShort = PacketModel.from(rawFrame: Data([0x00, 0x01, 0x02]), number: 9)

        XCTAssertTrue(packet.isTruncated)
        XCTAssertEqual(tooShort.proto, "Unknown")
        XCTAssertFalse(tooShort.meta.isIP)
    }

    func testDetectsBadIpv4Checksum() {
        let udp = PacketFixtures.udp(sourcePort: 1234, destPort: 5678, payload: Data([0xaa]))
        let goodIp = PacketFixtures.ipv4(proto: 17, source: [172, 16, 0, 1], destination: [172, 16, 0, 2], payload: udp)
        let badIp = PacketFixtures.ipv4(proto: 17, source: [172, 16, 0, 1], destination: [172, 16, 0, 2], payload: udp, corruptChecksum: true)

        let good = PacketModel.from(rawFrame: PacketFixtures.ethernet(etherType: 0x0800, payload: goodIp), number: 10)
        let bad = PacketModel.from(rawFrame: PacketFixtures.ethernet(etherType: 0x0800, payload: badIp), number: 11)

        XCTAssertTrue(good.meta.checksumValidated)
        XCTAssertTrue(good.meta.checksumOK)
        XCTAssertEqual(good.checksumDisplay, "OK")
        XCTAssertTrue(bad.meta.checksumValidated)
        XCTAssertFalse(bad.meta.checksumOK)
        XCTAssertEqual(bad.checksumDisplay, "bad")
    }
}

private enum PacketFixtures {
    static func ethernet(etherType: UInt16, payload: Data) -> Data {
        var bytes: [UInt8] = [
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ]
        appendBE16(etherType, to: &bytes)
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    static func vlanEthernet(vlanId: UInt16, innerEtherType: UInt16, payload: Data) -> Data {
        var bytes: [UInt8] = [
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55
        ]
        appendBE16(0x8100, to: &bytes)
        appendBE16(vlanId & 0x0fff, to: &bytes)
        appendBE16(innerEtherType, to: &bytes)
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    static func ipv4(proto: UInt8, source: [UInt8], destination: [UInt8], payload: Data, corruptChecksum: Bool = false) -> Data {
        var bytes: [UInt8] = [
            0x45, 0x00,
            0x00, 0x00,
            0x12, 0x34,
            0x40, 0x00,
            64, proto,
            0x00, 0x00
        ]
        bytes.append(contentsOf: source)
        bytes.append(contentsOf: destination)
        let totalLength = UInt16(bytes.count + payload.count)
        writeBE16(totalLength, to: &bytes, at: 2)
        let checksum = ipv4HeaderChecksum(bytes)
        writeBE16(checksum, to: &bytes, at: 10)
        if corruptChecksum {
            bytes[8] = 63
        }
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    static func ipv6(nextHeader: UInt8, source: [UInt8], destination: [UInt8], payload: Data) -> Data {
        var bytes: [UInt8] = [0x60, 0x00, 0x00, 0x00]
        appendBE16(UInt16(payload.count), to: &bytes)
        bytes.append(nextHeader)
        bytes.append(64)
        bytes.append(contentsOf: source)
        bytes.append(contentsOf: destination)
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    static func tcp(sourcePort: UInt16, destPort: UInt16, flags: UInt8, payload: Data = Data()) -> Data {
        var bytes: [UInt8] = []
        appendBE16(sourcePort, to: &bytes)
        appendBE16(destPort, to: &bytes)
        appendBE32(0x01020304, to: &bytes)
        appendBE32(0x05060708, to: &bytes)
        bytes.append(0x50)
        bytes.append(flags)
        appendBE16(2048, to: &bytes)
        appendBE16(0, to: &bytes)
        appendBE16(0, to: &bytes)
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    static func udp(sourcePort: UInt16, destPort: UInt16, payload: Data) -> Data {
        var bytes: [UInt8] = []
        appendBE16(sourcePort, to: &bytes)
        appendBE16(destPort, to: &bytes)
        appendBE16(UInt16(8 + payload.count), to: &bytes)
        appendBE16(0, to: &bytes)
        bytes.append(contentsOf: payload)
        return Data(bytes)
    }

    static func icmpEchoRequest() -> Data {
        Data([8, 0, 0, 0, 0x12, 0x34, 0, 1])
    }

    static func dnsQuery(_ name: String) -> Data {
        var bytes: [UInt8] = []
        appendBE16(0x1234, to: &bytes)
        appendBE16(0x0100, to: &bytes)
        appendBE16(1, to: &bytes)
        appendBE16(0, to: &bytes)
        appendBE16(0, to: &bytes)
        appendBE16(0, to: &bytes)
        bytes.append(contentsOf: dnsName(name))
        appendBE16(1, to: &bytes)
        appendBE16(1, to: &bytes)
        return Data(bytes)
    }

    static func dnsResponseA(_ name: String, address: [UInt8]) -> Data {
        var bytes: [UInt8] = []
        appendBE16(0x1234, to: &bytes)
        appendBE16(0x8180, to: &bytes)
        appendBE16(1, to: &bytes)
        appendBE16(1, to: &bytes)
        appendBE16(0, to: &bytes)
        appendBE16(0, to: &bytes)
        bytes.append(contentsOf: dnsName(name))
        appendBE16(1, to: &bytes)
        appendBE16(1, to: &bytes)
        appendBE16(0xc00c, to: &bytes)
        appendBE16(1, to: &bytes)
        appendBE16(1, to: &bytes)
        appendBE32(60, to: &bytes)
        appendBE16(4, to: &bytes)
        bytes.append(contentsOf: address)
        return Data(bytes)
    }

    static func tlsClientHello(host: String) -> Data {
        let hostBytes = Array(host.utf8)
        var serverName: [UInt8] = []
        appendBE16(UInt16(3 + hostBytes.count), to: &serverName)
        serverName.append(0)
        appendBE16(UInt16(hostBytes.count), to: &serverName)
        serverName.append(contentsOf: hostBytes)

        var extensions: [UInt8] = []
        appendBE16(0, to: &extensions)
        appendBE16(UInt16(serverName.count), to: &extensions)
        extensions.append(contentsOf: serverName)

        var body: [UInt8] = []
        appendBE16(0x0303, to: &body)
        body.append(contentsOf: Array(repeating: 0x11, count: 32))
        body.append(0)
        appendBE16(2, to: &body)
        appendBE16(0x1301, to: &body)
        body.append(1)
        body.append(0)
        appendBE16(UInt16(extensions.count), to: &body)
        body.append(contentsOf: extensions)

        var handshake: [UInt8] = [1]
        appendBE24(body.count, to: &handshake)
        handshake.append(contentsOf: body)

        var record: [UInt8] = [22, 0x03, 0x03]
        appendBE16(UInt16(handshake.count), to: &record)
        record.append(contentsOf: handshake)
        return Data(record)
    }

    private static func dnsName(_ name: String) -> [UInt8] {
        var bytes: [UInt8] = []
        for label in name.split(separator: ".") {
            let labelBytes = Array(label.utf8)
            bytes.append(UInt8(labelBytes.count))
            bytes.append(contentsOf: labelBytes)
        }
        bytes.append(0)
        return bytes
    }

    private static func ipv4HeaderChecksum(_ bytes: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0
        var cursor = 0
        while cursor < 20 {
            sum += UInt32(bytes[cursor]) << 8 | UInt32(bytes[cursor + 1])
            cursor += 2
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16)
        }
        return UInt16(~sum & 0xffff)
    }

    private static func appendBE16(_ value: UInt16, to bytes: inout [UInt8]) {
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    private static func appendBE24(_ value: Int, to bytes: inout [UInt8]) {
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    private static func appendBE32(_ value: UInt32, to bytes: inout [UInt8]) {
        bytes.append(UInt8((value >> 24) & 0xff))
        bytes.append(UInt8((value >> 16) & 0xff))
        bytes.append(UInt8((value >> 8) & 0xff))
        bytes.append(UInt8(value & 0xff))
    }

    private static func writeBE16(_ value: UInt16, to bytes: inout [UInt8], at offset: Int) {
        bytes[offset] = UInt8((value >> 8) & 0xff)
        bytes[offset + 1] = UInt8(value & 0xff)
    }
}
