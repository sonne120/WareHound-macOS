import SwiftUI

struct PortLabelEditorView: View {
    @Bindable var settings: SettingsViewModel
    @Environment(\.dismiss) private var dismiss

    private struct Row: Identifiable {
        let id = UUID()
        var port: String
        var label: String
    }

    @State private var rows: [Row] = []

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Custom protocol labels")
                .font(.system(size: 15, weight: .semibold))
            Text("Map a port to a protocol name. Overrides the built-in table (e.g. 8000 → Kafka). Applies to new captures.")
                .font(.caption)
                .foregroundStyle(AppColors.textSecondary)

            ScrollView {
                VStack(spacing: 6) {
                    ForEach($rows) { $row in
                        HStack(spacing: 8) {
                            TextField("Port", text: $row.port)
                                .frame(width: 80)
                                .textFieldStyle(.roundedBorder)
                            Image(systemName: "arrow.right")
                                .foregroundStyle(AppColors.textSecondary)
                            TextField("Label (e.g. Kafka)", text: $row.label)
                                .textFieldStyle(.roundedBorder)
                            Button(role: .destructive) {
                                rows.removeAll { $0.id == row.id }
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.borderless)
                        }
                    }
                }
                .padding(.vertical, 2)
            }
            .frame(minHeight: 120, maxHeight: 260)

            HStack {
                Button {
                    rows.append(Row(port: "", label: ""))
                } label: {
                    Label("Add", systemImage: "plus")
                }
                Spacer()
                Button("Cancel") { dismiss() }
                Button("Save") { save(); dismiss() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 440)
        .onAppear {
            rows = settings.customPortLabels
                .sorted { (Int($0.key) ?? 0) < (Int($1.key) ?? 0) }
                .map { Row(port: $0.key, label: $0.value) }
            if rows.isEmpty { rows = [Row(port: "", label: "")] }
        }
    }

    private func save() {
        var map: [String: String] = [:]
        for row in rows {
            let port = row.port.trimmingCharacters(in: .whitespaces)
            let label = row.label.trimmingCharacters(in: .whitespaces)
            if !port.isEmpty, !label.isEmpty, Int(port) != nil {
                map[port] = label
            }
        }
        settings.customPortLabels = map
    }
}
