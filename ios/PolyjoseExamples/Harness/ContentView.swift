// The one screen: the lines of the last run, the same ones the app prints to stdout, and a button
// to run the checks again.
import SwiftUI

struct ContentView: View {
    @ObservedObject var runner: Runner

    var body: some View {
        NavigationStack {
            List {
                if let result = runner.result {
                    Section {
                        Text("\(result.passed)/\(result.ran) checks passed")
                            .font(.headline)
                            .foregroundStyle(result.passed == result.ran && result.ran > 0 ? .green : .red)
                    }
                }
                Section {
                    ForEach(runner.lines) { line in
                        LineRow(text: line.text)
                    }
                }
            }
            .navigationTitle("polyjose examples")
            .toolbar {
                if runner.isRunning {
                    ProgressView()
                } else {
                    Button("Run again") { Task { await runner.runAll() } }
                }
            }
        }
    }
}

private struct LineRow: View {
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            symbol
            Text(text).font(.footnote.monospaced())
        }
    }

    @ViewBuilder private var symbol: some View {
        if text.hasPrefix("PASS ") {
            Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        } else if text.hasPrefix("FAIL ") {
            Image(systemName: "xmark.octagon.fill").foregroundStyle(.red)
        } else if text.hasPrefix("SKIP ") {
            Image(systemName: "minus.circle").foregroundStyle(.orange)
        } else {
            Image(systemName: "info.circle").foregroundStyle(.secondary)
        }
    }
}
