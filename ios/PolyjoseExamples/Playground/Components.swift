// The pieces the playground tabs share: a choice row that shows why it is disabled, the info sheet
// (with Run anyway for a disabled combination) and the result card.
import SwiftUI
import UIKit

/// What an info sheet shows: an explanation, and for a disabled combination its reason, its code
/// and Run anyway.
struct InfoItem: Identifiable {
    let id: String
    var support: Support?
    var runAnyway: (() -> Void)?
}

struct InfoButton: View {
    let id: String
    @Binding var info: InfoItem?

    var body: some View {
        Button { info = InfoItem(id: id) } label: { Image(systemName: "info.circle") }
            .buttonStyle(.borderless)
            .accessibilityLabel("About \(Explanations.title(id))")
    }
}

/// One option: a checkmark when chosen; disabled options are greyed and show their reason, and a
/// tap on them opens the info sheet with Run anyway.
struct ChoiceRow: View {
    let title: String
    let selected: Bool
    var support: Support = .enabled(note: nil)
    let infoId: String?
    @Binding var info: InfoItem?
    let select: () -> Void
    var runAnyway: (() -> Void)?

    var body: some View {
        HStack {
            Button {
                if support.isEnabled {
                    select()
                } else {
                    info = InfoItem(id: infoId ?? reasonId, support: support, runAnyway: runAnyway)
                }
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title).foregroundStyle(support.isEnabled ? .primary : .secondary)
                        if case .disabled(let reason, _) = support {
                            Text(Explanations.text(reason)).font(.caption).foregroundStyle(.secondary)
                        } else if case .enabled(let note?) = support {
                            Text(Explanations.text(note)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Spacer()
                    if selected && support.isEnabled { Image(systemName: "checkmark").foregroundStyle(.tint) }
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            if let infoId {
                Button { info = InfoItem(id: infoId, support: support, runAnyway: runAnyway) } label: {
                    Image(systemName: "info.circle")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("About \(title)")
            }
        }
    }

    private var reasonId: String {
        if case .disabled(let reason, _) = support { return reason }
        return "tab.sign"
    }
}

struct InfoSheet: View {
    let item: InfoItem
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section { Text(Explanations.text(item.id)) }
                if case .disabled(let reason, let code)? = item.support {
                    Section("Disabled here") {
                        Text(Explanations.text(reason))
                        if !code.isEmpty {
                            LabeledContent("Run anyway gives", value: code)
                            Text(Explanations.text("error.\(code)")).font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                    if let runAnyway = item.runAnyway, !code.isEmpty {
                        Section {
                            Button("Run anyway") {
                                dismiss()
                                runAnyway()
                            }
                        } footer: {
                            Text("Makes the call the library would refuse, and shows its code.")
                        }
                    }
                }
            }
            .navigationTitle(Explanations.title(item.id))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { Button("Done") { dismiss() } }
        }
        .presentationDetents([.medium, .large])
    }
}

/// The result card: the token and protected header, the outcome or the error code with its
/// explanation, where the key lives, and the time of each step.
struct ResultCardView: View {
    let card: Card

    var body: some View {
        Group {
            Text(card.title).font(.headline)
            if let code = card.errorCode {
                VStack(alignment: .leading, spacing: 4) {
                    Label(code, systemImage: "xmark.octagon.fill").foregroundStyle(.red).font(.body.monospaced())
                    Text(Explanations.text("error.\(code)")).font(.footnote)
                }
            }
            ForEach(card.outcome, id: \.self) { line in
                Label(line, systemImage: card.plaintextDiffers ? "xmark.octagon.fill" : "checkmark.seal.fill")
                    .foregroundStyle(card.plaintextDiffers ? .red : .green)
            }
            if let claims = card.claims { Monospaced(title: "Claims", text: claims) }
            if let header = card.header { Monospaced(title: "Protected header", text: header) }
            if let token = card.token { Monospaced(title: "Token", text: token, copy: true) }
            if let jwk = card.publicJwk { Monospaced(title: "Public JWK", text: jwk, copy: true) }
            if let store = card.livesIn {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Key lives in: \(store.title)").font(.subheadline.bold())
                    Text(Explanations.text(store.explanationId)).font(.caption).foregroundStyle(.secondary)
                }
            }
            ForEach(card.notes, id: \.self) { note in
                Text(Explanations.text(note)).font(.caption).foregroundStyle(.secondary)
            }
            if !card.timings.isEmpty {
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(card.timings) { timing in
                        LabeledContent(timing.step, value: "\(timing.ms) ms").font(.caption.monospaced())
                    }
                }
            }
        }
    }
}

struct Monospaced: View {
    let title: String
    let text: String
    var copy = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(title).font(.caption).foregroundStyle(.secondary)
                Spacer()
                if copy {
                    Button { UIPasteboard.general.string = text } label: { Image(systemName: "doc.on.doc") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("Copy \(title)")
                }
            }
            Text(text).font(.caption.monospaced()).textSelection(.enabled)
        }
    }
}

/// The key options of a platform key: the RSA size, the access flag and the shared context.
struct KeyOptionsSection: View {
    @Binding var spec: KeySpec
    let device: DeviceCapabilities
    @Binding var info: InfoItem?
    var runAnyway: ((AccessOption) -> Void)?

    var body: some View {
        if spec.store.isPlatform {
            if Matrix.isRsa(spec.alg) {
                Section {
                    ForEach(Matrix.rsaSizes, id: \.self) { size in
                        ChoiceRow(title: "\(size) bits", selected: spec.size == size, infoId: nil, info: $info) { spec.size = size }
                    }
                } header: {
                    HStack { Text("RSA size"); Spacer(); InfoButton(id: "option.rsa-size", info: $info) }
                }
            }
            Section("User authentication") {
                ForEach(AccessOption.allCases) { option in
                    ChoiceRow(
                        title: option.title, selected: spec.access == option, support: Matrix.access(option, store: spec.store, device: device),
                        infoId: option.explanationId, info: $info, select: { spec.access = option },
                        runAnyway: runAnyway.map { run in { run(option) } })
                }
                if spec.access != .none {
                    HStack {
                        Toggle("One shared LAContext", isOn: $spec.sharedContext)
                        InfoButton(id: "option.access.shared-context", info: $info)
                    }
                }
            }
        }
    }
}

/// The first rule that refuses a combination: the algorithm table (with the device), then the
/// access option.
func combined(_ cell: Support, access: Support) -> Support {
    cell.isEnabled ? access.isEnabled ? cell : access : cell
}
