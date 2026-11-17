// The Sign tab: a JWS or JWT, a key store, an algorithm, the key options and the key; Sign, Verify,
// Sign and verify, and Try a failure. Verification is always in software, with the key's public JWK
// and an allow-list of the chosen algorithm.
import SwiftUI

struct SignView: View {
    @ObservedObject var playground: Playground
    @State private var jwt = false
    @State private var spec = KeySpec()
    @State private var card: Card?
    @State private var info: InfoItem?

    private var device: DeviceCapabilities { playground.capabilities }
    private var support: Support {
        combined(Matrix.signing(alg: spec.alg, store: spec.store, device: device),
                 access: Matrix.access(spec.access, store: spec.store, device: device))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker("Operation", selection: $jwt) {
                        Text("JWS compact").tag(false)
                        Text("JWT").tag(true)
                    }
                    .pickerStyle(.segmented)
                }
                Section("Key store") {
                    ForEach(Store.allCases) { store in
                        ChoiceRow(title: store.title, selected: spec.store == store, infoId: store.explanationId, info: $info) {
                            spec.store = store
                        }
                    }
                }
                Section("Algorithm") {
                    ForEach(Matrix.signingAlgs, id: \.self) { alg in
                        ChoiceRow(
                            title: alg, selected: spec.alg == alg,
                            support: Matrix.signing(alg: alg, store: spec.store, device: device),
                            infoId: "alg.\(alg)", info: $info, select: { spec.alg = alg },
                            runAnyway: { var anyway = spec; anyway.alg = alg; run(.signAndVerify, anyway, anyway: true) })
                    }
                }
                KeyOptionsSection(spec: $spec, device: device, info: $info) { option in
                    var anyway = spec
                    anyway.access = option
                    run(.signAndVerify, anyway, anyway: true)
                }
                Section("Key") {
                    KeyPicker(playground: playground, spec: $spec, matches: { key in key.algorithm == spec.alg && (!key.rsa || key.bits == spec.size) },
                              softwareMatches: { $0.alg == spec.alg })
                }
                Section {
                    HStack {
                        Text(jwt ? "JWT: iss, aud, sub, exp now + 5 min" : demoPayload).font(.footnote.monospaced())
                        Spacer()
                        InfoButton(id: "option.payload", info: $info)
                    }
                } header: { Text("Payload") }
                Section {
                    if case .disabled(let reason, _) = support {
                        Button { info = InfoItem(id: reason, support: support) { run(.signAndVerify, spec, anyway: true) } } label: {
                            Label("Disabled: \(Explanations.text(reason))", systemImage: "nosign").font(.footnote)
                        }
                    }
                    Button("Sign") { run(.sign, spec) }.disabled(!support.isEnabled || playground.busy)
                    Button("Verify") { run(.verify, spec) }.disabled(playground.lastSigned == nil || playground.busy)
                    Button("Sign and verify") { run(.signAndVerify, spec) }.disabled(!support.isEnabled || playground.busy)
                    Menu("Try a failure") {
                        ForEach(Failure.sign) { failure in
                            let allowed = Matrix.failure(failure, store: spec.store, alg: spec.alg)
                            if case .disabled(let reason, _) = allowed {
                                Button("\(failure.title): \(Explanations.text(reason))") {}.disabled(true)
                            } else {
                                Button(failure.title) { run(.failure(failure), spec) }
                            }
                        }
                    }
                    .disabled(!support.isEnabled || playground.busy)
                }
                if let card {
                    Section("Result") { ResultCardView(card: card) }
                }
            }
            .navigationTitle("Sign")
            .toolbar {
                if playground.busy { ProgressView() }
                InfoButton(id: "tab.sign", info: $info)
            }
            .sheet(item: $info) { InfoSheet(item: $0) }
        }
    }

    private func run(_ action: SignAction, _ spec: KeySpec, anyway: Bool = false) {
        let jwt = jwt
        Task { card = await playground.sign(spec, jwt: jwt, action, anyway: anyway) }
    }
}

/// "New key", or one of the playground's keys that fits the chosen store and algorithm.
struct KeyPicker: View {
    @ObservedObject var playground: Playground
    @Binding var spec: KeySpec
    let matches: (ListedKey) -> Bool
    let softwareMatches: (SoftwareKey) -> Bool

    var body: some View {
        Picker("Key", selection: $spec.choice) {
            Text("New key").tag(KeyChoice.new)
            if spec.store == .software {
                ForEach(playground.softwareKeys.filter(softwareMatches)) { key in
                    Text(key.id).tag(KeyChoice.software(id: key.id))
                }
            } else {
                ForEach(playground.platformKeys.filter { $0.store == spec.store && matches($0) }) { key in
                    Text(key.tag.replacingOccurrences(of: KeyListing.prefix, with: "…")).tag(KeyChoice.platform(tag: key.tag))
                }
            }
        }
        // A chosen key fits only the store, algorithm, size and curve it was chosen for.
        .onChange(of: spec.store) { _ in spec.choice = .new }
        .onChange(of: spec.alg) { _ in spec.choice = .new }
        .onChange(of: spec.size) { _ in spec.choice = .new }
        .onChange(of: spec.crv) { _ in spec.choice = .new }
    }
}
