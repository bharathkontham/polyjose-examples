// The Encrypt tab: a key-management `alg`, its curve or RSA size, an `enc` and the key store that
// decrypts. Encryption is always polyjose's, in software, to the key's public JWK; decryption uses
// the key in its store, with an allow-list of the chosen `alg` and `enc`.
import SwiftUI

struct EncryptView: View {
    @ObservedObject var playground: Playground
    @State private var spec = KeySpec(alg: "ECDH-ES+A256KW")
    @State private var enc = Matrix.defaultEnc
    @State private var card: Card?
    @State private var info: InfoItem?

    private var device: DeviceCapabilities { playground.capabilities }
    private var support: Support {
        combined(Matrix.decryption(alg: spec.alg, crv: spec.crv, store: spec.store, device: device),
                 access: Matrix.access(spec.access, store: spec.store, device: device))
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Key store that decrypts") {
                    ForEach(Store.allCases) { store in
                        ChoiceRow(title: store.title, selected: spec.store == store, infoId: store.explanationId, info: $info) {
                            spec.store = store
                        }
                    }
                }
                Section("Key management (alg)") {
                    ForEach(Matrix.keyManagementAlgs, id: \.self) { alg in
                        ChoiceRow(
                            title: alg, selected: spec.alg == alg,
                            support: Matrix.decryption(alg: alg, crv: Matrix.isEcdh(alg) ? spec.crv : "P-256", store: spec.store, device: device),
                            infoId: "alg.\(alg)", info: $info, select: { spec.alg = alg },
                            runAnyway: { var anyway = spec; anyway.alg = alg; run(.roundTrip, anyway, anyway: true) })
                    }
                }
                if Matrix.isEcdh(spec.alg) {
                    Section {
                        ForEach(Matrix.curves, id: \.self) { crv in
                            ChoiceRow(
                                title: crv, selected: spec.crv == crv,
                                support: Matrix.decryption(alg: spec.alg, crv: crv, store: spec.store, device: device),
                                infoId: "crv.\(crv)", info: $info, select: { spec.crv = crv },
                                runAnyway: { var anyway = spec; anyway.crv = crv; run(.roundTrip, anyway, anyway: true) })
                        }
                    } header: {
                        HStack { Text("Curve"); Spacer(); InfoButton(id: "option.curve", info: $info) }
                    }
                }
                Section("Content encryption (enc)") {
                    ForEach(Matrix.encs, id: \.self) { value in
                        ChoiceRow(title: value, selected: enc == value, infoId: "enc.\(value)", info: $info) { enc = value }
                    }
                }
                KeyOptionsSection(spec: $spec, device: device, info: $info) { option in
                    var anyway = spec
                    anyway.access = option
                    run(.roundTrip, anyway, anyway: true)
                }
                Section("Key") {
                    KeyPicker(
                        playground: playground, spec: $spec,
                        matches: { key in
                            key.algorithm == spec.keyAlgorithm && key.bits == (Matrix.isEcdh(spec.alg) ? Matrix.curveBits(spec.crv) : spec.size)
                        },
                        softwareMatches: { key in
                            key.alg == spec.alg && (!Matrix.isEcdh(spec.alg) || key.crv == spec.crv)
                                && (spec.alg != "dir" || key.summary.bits == Matrix.octBytes(alg: "dir", enc: enc) * 8)
                        })
                }
                Section {
                    if case .disabled(let reason, _) = support {
                        Button { info = InfoItem(id: reason, support: support) { run(.roundTrip, spec, anyway: true) } } label: {
                            Label("Disabled: \(Explanations.text(reason))", systemImage: "nosign").font(.footnote)
                        }
                    }
                    Button("Encrypt") { run(.encrypt, spec) }.disabled(!support.isEnabled || playground.busy)
                    Button("Decrypt") { run(.decrypt, spec) }.disabled(playground.lastEncrypted == nil || playground.busy)
                    Button("Round trip") { run(.roundTrip, spec) }.disabled(!support.isEnabled || playground.busy)
                    Menu("Try a failure") {
                        ForEach(Failure.encrypt) { failure in
                            let allowed = Matrix.failure(failure, store: spec.store, alg: spec.alg)
                            if case .disabled(let reason, _) = allowed {
                                Button("\(failure.title): \(Explanations.text(reason))") {}.disabled(true)
                            } else {
                                Button(failure.title) { run(.failure(failure), spec) }
                            }
                        }
                    }
                    .disabled(!support.isEnabled || playground.busy)
                } footer: {
                    Text("Payload: \(demoPayload)")
                }
                if let card {
                    Section("Result") { ResultCardView(card: card) }
                }
            }
            .navigationTitle("Encrypt")
            .toolbar {
                if playground.busy { ProgressView() }
                InfoButton(id: "tab.encrypt", info: $info)
            }
            .sheet(item: $info) { InfoSheet(item: $0) }
        }
    }

    private func run(_ action: EncryptAction, _ spec: KeySpec, anyway: Bool = false) {
        let enc = enc
        Task { if let made = await playground.encrypt(spec, enc: enc, action, anyway: anyway) { card = made } }
    }
}
