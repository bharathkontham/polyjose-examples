// The Keys tab: this device's capabilities, the playground's keys in each store (listed by their
// tag prefix, attributes only, so listing never asks the user to authenticate), a key's public
// JWK, RFC 7638 thumbprint, Open again and Delete, Create key and Delete all playground keys.
// Software keys are held in this app's memory only.
import SwiftUI
import UIKit

struct KeysView: View {
    @ObservedObject var playground: Playground
    @State private var info: InfoItem?
    @State private var confirmDeleteAll = false
    @State private var card: Card?

    var body: some View {
        NavigationStack {
            List {
                if let device = playground.device {
                    Section("This device") {
                        LabeledContent("Model", value: device.model)
                        LabeledContent("iOS", value: device.os.replacingOccurrences(of: "iOS-", with: ""))
                        LabeledContent("Simulator", value: device.simulator ? "yes" : "no")
                        LabeledContent("Secure Enclave", value: device.secureEnclave ? "available" : "not available")
                        LabeledContent("Passcode set", value: device.passcodeSet ? "yes" : "no")
                        LabeledContent("polyjose", value: device.polyjose)
                    }
                }
                ForEach([Store.keychain, .secureEnclave]) { store in
                    Section {
                        let keys = playground.platformKeys.filter { $0.store == store }
                        if keys.isEmpty { Text("No playground keys").foregroundStyle(.secondary) }
                        ForEach(keys) { key in
                            NavigationLink {
                                PlatformKeyDetail(playground: playground, key: key)
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(key.tag.replacingOccurrences(of: KeyListing.prefix, with: "…")).font(.footnote.monospaced())
                                    Text("\(key.algorithm), \(key.sizeLabel), lives in: \(key.store.title), authentication: \(authentication(key))")
                                        .font(.caption).foregroundStyle(.secondary)
                                }
                            }
                        }
                    } header: {
                        HStack { Text(store.title); Spacer(); InfoButton(id: store.explanationId, info: $info) }
                    }
                }
                Section {
                    if playground.softwareKeys.isEmpty { Text("No software keys").foregroundStyle(.secondary) }
                    ForEach(playground.softwareKeys) { key in
                        NavigationLink {
                            SoftwareKeyDetail(playground: playground, key: key)
                        } label: {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(key.id).font(.footnote.monospaced())
                                Text(softwareLine(key)).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                } header: {
                    HStack { Text("Software (in memory)"); Spacer(); InfoButton(id: "store.software", info: $info) }
                }
                Section {
                    NavigationLink("Create key") { CreateKeyView(playground: playground) }
                    Button("Delete all playground keys", role: .destructive) { confirmDeleteAll = true }
                        .disabled(playground.busy)
                }
                if let card { Section("Result") { ResultCardView(card: card) } }
            }
            .navigationTitle("Keys")
            .toolbar {
                if playground.busy { ProgressView() }
                InfoButton(id: "tab.keys", info: $info)
            }
            .refreshable { await playground.refreshKeys() }
            .task { await playground.refreshKeys() }
            .sheet(item: $info) { InfoSheet(item: $0) }
            .confirmationDialog("Delete every playground key?", isPresented: $confirmDeleteAll, titleVisibility: .visible) {
                Button("Delete all", role: .destructive) { Task { card = await playground.deleteAll() } }
            }
        }
    }

    private func authentication(_ key: ListedKey) -> String {
        playground.knownAccess[key.tag].map { $0 == .none ? "none" : $0.rawValue } ?? "not reported by iOS"
    }

    private func softwareLine(_ key: SoftwareKey) -> String {
        let summary = key.summary
        var line = "\(summary.kty), \(summary.alg), kid \(summary.kid)"
        if let bits = summary.bits { line += ", \(bits) bits" }
        if summary.testKey { line += ", RFC 7515 A.2 test key" }
        return line
    }
}

private struct PlatformKeyDetail: View {
    @ObservedObject var playground: Playground
    let key: ListedKey
    @State private var card: Card?
    @State private var thumbprint: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            Section {
                LabeledContent("Tag") { Text(key.tag).font(.caption.monospaced()).textSelection(.enabled) }
                LabeledContent("Algorithm", value: key.algorithm)
                LabeledContent("Key", value: key.sizeLabel)
                LabeledContent("Lives in", value: key.store.title)
            } footer: {
                Text(Explanations.text(key.store.explanationId))
            }
            Section {
                Button("Open again") { Task { (card, thumbprint) = await playground.openAgain(key) } }
                if let jwk = card?.publicJwk {
                    Button("Copy public JWK") {
                        UIPasteboard.general.string = jwk
                        playground.copied(jwk, title: key.store.title)
                    }
                }
                Button("Delete", role: .destructive) {
                    Task {
                        card = await playground.deleteKey(key)
                        if card?.succeeded == true { dismiss() }
                    }
                }
            }
            .disabled(playground.busy)
            if let thumbprint {
                Section("RFC 7638 thumbprint (SHA-256)") { Monospaced(title: "Thumbprint", text: thumbprint, copy: true) }
            }
            if let card { Section("Result") { ResultCardView(card: card) } }
        }
        .navigationTitle(key.algorithm)
    }
}

private struct SoftwareKeyDetail: View {
    @ObservedObject var playground: Playground
    let key: SoftwareKey
    @State private var card: Card?
    @State private var thumbprint: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            Section {
                LabeledContent("kty", value: key.summary.kty)
                LabeledContent("alg", value: key.summary.alg)
                LabeledContent("kid", value: key.summary.kid)
                if let bits = key.summary.bits { LabeledContent("Length", value: "\(bits) bits") }
            } footer: {
                Text(Explanations.text(key.summary.testKey ? "key.test-rsa" : "store.software"))
            }
            if let jwk = key.publicJwk {
                Section("Public JWK") {
                    Monospaced(title: "Public JWK", text: publicOnly(jwk).text)
                    Button("Copy public JWK") {
                        UIPasteboard.general.string = publicOnly(jwk).text
                        playground.copied(jwk, title: "Software")
                    }
                    Button("Thumbprint") { Task { (card, thumbprint) = await playground.thumbprint(of: key) } }
                }
            } else {
                Section { Text("A symmetric key has no public half: it is shown by kty, alg, kid and length only.") }
            }
            if let thumbprint {
                Section("RFC 7638 thumbprint (SHA-256)") { Monospaced(title: "Thumbprint", text: thumbprint, copy: true) }
            }
            Section {
                Button("Delete", role: .destructive) {
                    playground.deleteSoftware(key)
                    dismiss()
                }
            } footer: {
                Text(Explanations.text("reason.software-not-stored"))
            }
        }
        .navigationTitle(key.alg)
    }
}

private struct CreateKeyView: View {
    @ObservedObject var playground: Playground
    @State private var spec = KeySpec()
    @State private var card: Card?
    @State private var info: InfoItem?

    private static let algorithms = Matrix.signingAlgs + ["ECDH-ES", "RSA-OAEP-256"]
    private var device: DeviceCapabilities { playground.capabilities }

    private func cell(_ alg: String, crv: String) -> Support {
        Matrix.signingAlgs.contains(alg)
            ? Matrix.signing(alg: alg, store: spec.store, device: device)
            : Matrix.decryption(alg: alg, crv: crv, store: spec.store, device: device)
    }

    private var support: Support {
        combined(cell(spec.alg, crv: spec.crv),
                 access: Matrix.access(spec.access, store: spec.store, device: device))
    }

    var body: some View {
        Form {
            Section("Key store") {
                ForEach(Store.allCases) { store in
                    ChoiceRow(title: store.title, selected: spec.store == store, infoId: store.explanationId, info: $info) { spec.store = store }
                }
            }
            Section("Algorithm") {
                ForEach(Self.algorithms, id: \.self) { alg in
                    ChoiceRow(
                        title: alg, selected: spec.alg == alg, support: cell(alg, crv: spec.crv), infoId: "alg.\(alg)", info: $info,
                        select: { spec.alg = alg },
                        runAnyway: { var anyway = spec; anyway.alg = alg; create(anyway, anyway: true) })
                }
            }
            if Matrix.isEcdh(spec.alg) {
                Section("Curve") {
                    ForEach(Matrix.curves, id: \.self) { crv in
                        ChoiceRow(
                            title: crv, selected: spec.crv == crv, support: cell(spec.alg, crv: crv), infoId: "crv.\(crv)", info: $info,
                            select: { spec.crv = crv },
                            runAnyway: { var anyway = spec; anyway.crv = crv; create(anyway, anyway: true) })
                    }
                }
            }
            KeyOptionsSection(spec: $spec, device: device, info: $info) { option in
                var anyway = spec
                anyway.access = option
                create(anyway, anyway: true)
            }
            Section {
                Button("Create key") { create(spec) }.disabled(!support.isEnabled || playground.busy)
            }
            if let card { Section("Result") { ResultCardView(card: card) } }
        }
        .navigationTitle("Create key")
        .sheet(item: $info) { InfoSheet(item: $0) }
    }

    private func create(_ spec: KeySpec, anyway: Bool = false) {
        Task { card = await playground.createKey(spec, anyway: anyway) }
    }
}
