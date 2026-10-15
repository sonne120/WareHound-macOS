import SwiftUI
import AppKit

enum AppColors {

    static let primary       = Color(hex: 0xF5F5F7)
    static let secondary     = Color(hex: 0xFFFFFF)
    static let tertiary      = Color(hex: 0xE8E8ED)
    static let sidebar       = Color(hex: 0xF0F0F5)
    static let accent        = Color(hex: 0x007AFF)
    static let accentLight   = Color(hex: 0x5AC8FA)

    static let textPrimary   = Color(hex: 0x3D3D44)
    static let textSecondary = Color(hex: 0x8E8E93)
    static let textDisabled  = Color(hex: 0xC7C7CC)

    static let border        = Color(hex: 0xD2D2D7)
    static let borderLight   = Color(hex: 0xE5E5EA)

    static let success       = Color(hex: 0x34C759)
    static let warning       = Color(hex: 0xFF9500)
    static let error         = Color(hex: 0xFF3B30)

    static func rowColor(forProtocol proto: String) -> Color? {
        let p = proto.uppercased()
        if p.hasPrefix("TLS") { return Color(rgb: 212, 237, 218) }
        switch p {
        case "TCP":            return Color(rgb: 230, 230, 250)
        case "HTTPS":          return Color(rgb: 212, 237, 218)
        case "HTTP":           return Color(rgb: 225, 245, 254)
        case "UDP":            return Color(rgb: 218, 232, 252)
        case "QUIC":           return Color(rgb: 224, 235, 255)
        case "DNS":            return Color(rgb: 232, 245, 233)
        case "MDNS":           return Color(rgb: 220, 247, 240)
        case "DHCP":           return Color(rgb: 255, 253, 231)
        case "ICMP", "ICMPV6": return Color(rgb: 252, 228, 236)
        case "ARP":            return Color(rgb: 255, 243, 224)
        default:               return nil
        }
    }

    static func chartColor(forProtocol proto: String) -> Color {
        let p = proto.uppercased()
        if p.hasPrefix("TLS") { return Color(hex: 0x34C759) }
        switch p {
        case "TCP":            return Color(hex: 0x5E5CE6)
        case "HTTPS":          return Color(hex: 0x34C759)
        case "HTTP":           return Color(hex: 0x0A84FF)
        case "UDP":            return Color(hex: 0xFF9500)
        case "QUIC":           return Color(hex: 0x3D5AFE)
        case "DNS":            return Color(hex: 0x30B0C7)
        case "MDNS":           return Color(hex: 0x00BFA5)
        case "DHCP":           return Color(hex: 0xFFCC00)
        case "ICMP", "ICMPV6": return Color(hex: 0xFF2D55)
        case "ARP":            return Color(hex: 0xAF52DE)
        default:               return Color(hex: 0x8E8E93)
        }
    }
}

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red:   Double((hex >> 16) & 0xFF) / 255.0,
            green: Double((hex >> 8)  & 0xFF) / 255.0,
            blue:  Double( hex        & 0xFF) / 255.0,
            opacity: 1.0
        )
    }

    init(rgb r: Int, _ g: Int, _ b: Int) {
        self.init(
            .sRGB,
            red:   Double(r) / 255.0,
            green: Double(g) / 255.0,
            blue:  Double(b) / 255.0,
            opacity: 1.0
        )
    }

    var rgbHex: UInt32 {
        let ns = NSColor(self).usingColorSpace(.sRGB) ?? .black
        let r = UInt32((min(max(ns.redComponent,   0), 1) * 255).rounded())
        let g = UInt32((min(max(ns.greenComponent, 0), 1) * 255).rounded())
        let b = UInt32((min(max(ns.blueComponent,  0), 1) * 255).rounded())
        return (r << 16) | (g << 8) | b
    }
}
