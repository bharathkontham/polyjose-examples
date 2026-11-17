// The Log tab: every step of every tap, newest first, grouped by tap. Copy all and Share give the
// whole log, oldest first; it holds no secrets (PLAYGROUND.md, "Secrets").
import SwiftUI
import UIKit

struct LogView: View {
    @ObservedObject var log: PlaygroundLog
    @State private var info: InfoItem?

    var body: some View {
        NavigationStack {
            List {
                if log.entries.isEmpty { Text("No taps yet").foregroundStyle(.secondary) }
                ForEach(log.entries) { entry in
                    Section(entry.title) {
                        ForEach(Array(entry.lines.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.caption2.monospaced()).textSelection(.enabled)
                        }
                    }
                }
            }
            .navigationTitle("Log")
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    InfoButton(id: "tab.log", info: $info)
                    Button("Copy all") { UIPasteboard.general.string = log.exportText }
                    ShareLink(item: log.exportText, subject: Text("polyjose playground log"))
                }
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Clear", role: .destructive) { log.clear() }
                }
            }
            .sheet(item: $info) { InfoSheet(item: $0) }
        }
    }
}
