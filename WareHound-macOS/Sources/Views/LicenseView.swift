import SwiftUI

struct LicenseView: View {
    @Environment(\.dismiss) private var dismiss
    private let license = LicenseManager.shared
    @State private var key = ""

    private var isLicensed: Bool {
        if case .licensed = license.status { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                Image(systemName: "pawprint.fill")
                    .font(.system(size: 30))
                    .foregroundStyle(AppColors.accent)
                VStack(alignment: .leading, spacing: 2) {
                    Text("WareHound License")
                        .font(.title2.bold())
                        .foregroundStyle(AppColors.textPrimary)
                    Text(license.statusText)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(statusColor)
                }
            }

            Text(explanation)
                .font(.callout)
                .foregroundStyle(AppColors.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            if case .licensed(let info) = license.status {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Email: \(info.email)")
                    Text("Valid: \(validity(info))")
                }
                .font(.callout.monospaced())
                .foregroundStyle(AppColors.textPrimary)
            } else {
                VStack(alignment: .leading, spacing: 6) {
                    Text("License key").font(.caption).foregroundStyle(.secondary)
                    TextField("WH1.…", text: $key, axis: .vertical)
                        .lineLimit(3...5)
                        .font(.system(.caption, design: .monospaced))
                        .textFieldStyle(.roundedBorder)
                    if let error = license.activationError {
                        Text(error)
                            .font(.caption)
                            .foregroundStyle(AppColors.error)
                    }
                }
            }

            HStack {
                if isLicensed {
                    Button("Remove License", role: .destructive) { license.removeLicense() }
                }
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                if !isLicensed {
                    Button("Activate") {
                        if license.activate(key) { key = "" }
                    }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(key.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
            }
        }
        .padding(24)
        .frame(width: 480)
        .onAppear { license.refresh() }
    }

    private var statusColor: Color {
        switch license.status {
        case .licensed: AppColors.success
        case .trial: AppColors.accent
        case .trialExpired, .clockRolledBack, .tampered: AppColors.error
        }
    }

    private var explanation: String {
        switch license.status {
        case .trial:
            "You're using the \(LicenseManager.trialDays)-day free trial. When it ends, live capture, container capture and export are locked. Opening and viewing pcap files stays free."
        case .trialExpired:
            "Your \(LicenseManager.trialDays)-day trial has ended. Enter a license key to keep using live capture, container capture and export."
        case .clockRolledBack:
            "Your Mac's date is earlier than when WareHound last ran. Set the correct date and time, or enter a license key."
        case .tampered:
            "WareHound's trial data was modified. Enter a license key to continue."
        case .licensed:
            "Thank you for supporting WareHound."
        }
    }

    private func validity(_ info: LicenseInfo) -> String {
        guard let expires = info.expires else { return "lifetime" }
        return "until " + Date(timeIntervalSince1970: TimeInterval(expires)).formatted(date: .abbreviated, time: .omitted)
    }
}
