// The demo walk (PLAYGROUND.md at the root of this repository, "Demo walk"): launched with the
// argument `-playground-demo` (`run.sh --playground` does this), the app runs every cell of the
// support matrix on this device through the same `Playground` functions the buttons call, then
// every failure action, then the key actions, and deletes the keys it made. Its last step is the
// secrets check (PLAYGROUND.md, "Secrets"): no secret member value of a software key it made is
// anywhere in its log.
//
//   WALK OK sign/jws/secure-enclave/ES384 expected=UnsupportedAlgorithm got=UnsupportedAlgorithm
//   POLYJOSE-PLAYGROUND: 181/181 OK
//
// A ✓ cell must succeed and a ✗ cell runs "Run anyway" and must give the code of its row. Options
// that need user authentication are not used, because no one is there to authenticate; creating
// and listing such a key is, with each of the four flags, because neither prompts.
import Foundation

@MainActor
enum DemoWalk {
    private struct Step {
        let id: String
        /// `ok`, or the error code the step must end with.
        let expected: String
        let run: @MainActor () async -> String
    }

    /// Runs the walk and prints one `WALK` line per step and the final line. `true` when every step
    /// gave its expected outcome.
    static func run(_ playground: Playground) async -> Bool {
        await playground.start()
        let device = playground.capabilities
        if let info = playground.device {
            emit("# playground demo walk: polyjose \(info.polyjose), \(info.os) (\(info.simulator ? "Simulator" : "device")), Secure Enclave \(info.secureEnclave), passcode \(info.passcodeSet)")
        }
        let firstTag = playground.createdTagCount
        let secrets = SecretValues()
        playground.softwareKeyMade = { secrets.add($0) }
        defer { playground.softwareKeyMade = nil }
        var steps: [Step] = []

        // Signing: every algorithm on every store, as a JWS; RSA sizes; a JWT per store.
        for store in Store.allCases {
            for alg in Matrix.signingAlgs {
                steps.append(signCell("sign/jws/\(store.rawValue)/\(alg)", KeySpec(store: store, alg: alg), playground, device))
            }
        }
        for size in [3072, 4096] {
            steps.append(signCell("sign/jws/keychain/RS256-\(size)", KeySpec(store: .keychain, alg: "RS256", size: size), playground, device))
        }
        for store in Store.allCases {
            steps.append(signCell("sign/jwt/\(store.rawValue)/ES256", KeySpec(store: store, alg: "ES256"), playground, device, jwt: true))
        }

        // Decryption: every `alg` (and curve) on every store with the default `enc`, then every
        // other `enc` with ECDH-ES+A256KW on P-256, and the RSA sizes.
        for store in Store.allCases {
            for alg in Matrix.keyManagementAlgs {
                for crv in Matrix.isEcdh(alg) ? Matrix.curves : ["P-256"] {
                    let name = Matrix.isEcdh(alg) ? "\(alg)/\(crv)" : alg
                    steps.append(encryptCell("encrypt/\(store.rawValue)/\(name)/\(Matrix.defaultEnc)",
                                             KeySpec(store: store, alg: alg, crv: crv), enc: Matrix.defaultEnc, playground, device))
                }
            }
            for enc in Matrix.encs where enc != Matrix.defaultEnc {
                steps.append(encryptCell("encrypt/\(store.rawValue)/ECDH-ES+A256KW/P-256/\(enc)",
                                         KeySpec(store: store, alg: "ECDH-ES+A256KW"), enc: enc, playground, device))
            }
        }
        for size in [3072, 4096] {
            steps.append(encryptCell("encrypt/keychain/RSA-OAEP-256-\(size)/\(Matrix.defaultEnc)",
                                     KeySpec(store: .keychain, alg: "RSA-OAEP-256", size: size), enc: Matrix.defaultEnc, playground, device))
        }

        // Failure actions.
        var signFailures: [(Store, String, Failure)] = []
        for store in Store.allCases {
            for failure in Failure.sign { signFailures.append((store, "ES256", failure)) }
        }
        signFailures += [
            (.software, "HS256", .signTamper), (.software, "HS256", .signOtherAlg), (.software, "HS256", .signWrongKey),
            (.software, "EdDSA", .signOtherAlg), (.software, "PS256", .signOtherAlg), (.keychain, "RS256", .signWrongKey),
        ]
        for (store, alg, failure) in signFailures where Matrix.failure(failure, store: store, alg: alg).isEnabled {
            let spec = KeySpec(store: store, alg: alg)
            steps.append(Step(id: "failure/\(failure.rawValue)/\(store.rawValue)/\(alg)", expected: failure.code) {
                outcome(await playground.sign(spec, jwt: false, .failure(failure)), livesIn: spec.store)
            })
        }
        var encryptFailures: [(Store, String, Failure)] = []
        for store in Store.allCases {
            for failure in Failure.encrypt { encryptFailures.append((store, "ECDH-ES+A256KW", failure)) }
        }
        encryptFailures += [
            (.software, "A256KW", .encryptTamper), (.software, "A256KW", .encryptOtherAlg), (.software, "A256KW", .encryptWrongKey),
            (.software, "RSA-OAEP-256", .encryptTamper), (.keychain, "RSA-OAEP-256", .encryptWrongKey),
        ]
        for (store, alg, failure) in encryptFailures where Matrix.failure(failure, store: store, alg: alg).isEnabled {
            let spec = KeySpec(store: store, alg: alg)
            steps.append(Step(id: "failure/\(failure.rawValue)/\(store.rawValue)/\(alg)", expected: failure.code) {
                outcome(await playground.encrypt(spec, enc: Matrix.defaultEnc, .failure(failure)), livesIn: spec.store)
            })
        }

        // Keys: a key with user authentication is created and listed without a prompt (attributes
        // only); a key is opened again and its thumbprint shown; the secrets gate withholds private
        // and symmetric JWKs.
        for store in [Store.keychain, .secureEnclave] {
            for option in AccessOption.allCases where option != .none {
                let spec = KeySpec(store: store, alg: "ES256", access: option)
                let support = Matrix.access(option, store: store, device: device)
                let id = "keys/list-without-prompt/\(store.rawValue)/\(option.rawValue)"
                steps.append(Step(id: id, expected: support.isEnabled ? "listed" : expected(support)) {
                    let card = await playground.createKey(spec, anyway: !support.isEnabled)
                    guard let card, card.succeeded else { return outcome(card) }
                    let tag = playground.lastCreatedTag
                    await playground.refreshKeys()
                    return playground.platformKeys.contains { $0.tag == tag && $0.store == store } ? "listed" : "not-listed"
                })
            }
        }
        steps.append(Step(id: "keys/open-again/keychain/ES256", expected: "ok") {
            let card = await playground.createKey(KeySpec(store: .keychain, alg: "ES256"))
            guard let card, card.succeeded, let listed = playground.platformKeys.first(where: { $0.tag == playground.lastCreatedTag }) else {
                return outcome(card)
            }
            guard let opened = await playground.openAgain(listed) else { return "busy" }
            return opened.card.succeeded && opened.thumbprint != nil ? "ok" : outcome(opened.card)
        })
        steps.append(Step(id: "secrets/public-only-gate", expected: "withheld") {
            await playground.secretsGateWithholds() ? "withheld" : "shown"
        })

        var ok = 0
        for step in steps {
            let got = await step.run()
            if got == step.expected { ok += 1 }
            emit("WALK \(got == step.expected ? "OK" : "FAIL") \(step.id) expected=\(step.expected) got=\(got)")
        }

        // Clean-up: every key the walk made, then a listing that must hold none of them.
        let tags = playground.createdTags(since: firstTag)
        for tag in Set(tags) { _ = await playground.deleteTag(tag) }
        await playground.refreshKeys()
        let left = playground.platformKeys.filter { tags.contains($0.tag) }.count
        if left == 0 { ok += 1 }
        emit("WALK \(left == 0 ? "OK" : "FAIL") keys/walk-keys-deleted expected=0 got=\(left)")

        // The secrets check, after the clean-up so it covers every tap: how many secret member
        // values of the software keys the walk made appear in its log. Only counts are printed.
        let found = await secrets.found(in: playground.log.joinedText)
        emit("# secrets check: \(found.matches) of \(found.values) secret values of \(secrets.keys) software keys found in \(found.lines) log lines")
        let secretsOutcome = secrets.values.isEmpty || secrets.unreadable > 0 ? "no-values" : "\(found.matches)"
        if secretsOutcome == "0" { ok += 1 }
        emit("WALK \(secretsOutcome == "0" ? "OK" : "FAIL") secrets/no-secret-value-in-log expected=0 got=\(secretsOutcome)")
        let total = steps.count + 2
        emit("POLYJOSE-PLAYGROUND: \(ok)/\(total) OK")
        return ok == total
    }

    private static func signCell(_ id: String, _ spec: KeySpec, _ playground: Playground, _ device: DeviceCapabilities, jwt: Bool = false) -> Step {
        let support = Matrix.signing(alg: spec.alg, store: spec.store, device: device)
        return Step(id: id, expected: expected(support)) {
            outcome(await playground.sign(spec, jwt: jwt, .signAndVerify, anyway: !support.isEnabled))
        }
    }

    private static func encryptCell(_ id: String, _ spec: KeySpec, enc: String, _ playground: Playground, _ device: DeviceCapabilities) -> Step {
        let support = Matrix.decryption(alg: spec.alg, crv: spec.crv, store: spec.store, device: device)
        return Step(id: id, expected: expected(support)) {
            outcome(await playground.encrypt(spec, enc: enc, .roundTrip, anyway: !support.isEnabled))
        }
    }

    private static func expected(_ support: Support) -> String {
        if case .disabled(_, let code) = support { return code }
        return "ok"
    }

    /// `ok` for a tap that ended without an error, else its code; `busy` when the tap didn't start.
    private static func outcome(_ card: Card?) -> String {
        guard let card else { return "busy" }
        if card.plaintextDiffers { return "plaintext-differs" }
        return card.errorCode ?? "ok"
    }

    /// As `outcome`, and the card's "Key lives in" must be the store of the tap's key, also when
    /// a failure action made a software key as its "other" key.
    private static func outcome(_ card: Card?, livesIn store: Store) -> String {
        if let card, card.livesIn != store { return "lives-in-\(card.livesIn?.rawValue ?? "none")" }
        return outcome(card)
    }

    private static func emit(_ line: String) {
        print(line)
        fflush(stdout)
    }
}

/// The secret member values (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) of every software key
/// the walk makes, for its secrets check. They are only compared with the log text: never logged,
/// printed or shown. The walk reports counts only.
@MainActor
private final class SecretValues {
    private(set) var keys = 0
    private(set) var unreadable = 0
    private(set) var values: Set<String> = []

    func add(_ secretJwk: String) {
        keys += 1
        guard let object = try? playgroundObject(secretJwk) else { unreadable += 1; return }
        for (member, value) in object where secretMembers.contains(member) { collect(value) }
    }

    /// A string value, or every string inside an `oth` array (RFC 7518 §6.3.2.7).
    private func collect(_ value: Any) {
        if let text = value as? String {
            if !text.isEmpty { values.insert(text) }
        } else if let array = value as? [Any] {
            array.forEach(collect)
        } else if let object = value as? [String: Any] {
            object.values.forEach(collect)
        }
    }

    /// How many of the values appear in `text`, searched off the main thread.
    func found(in log: (text: String, lines: Int)) async -> (matches: Int, values: Int, lines: Int) {
        let values = values, text = log.text
        let matches = await Task.detached(priority: .userInitiated) {
            values.filter { text.range(of: $0, options: .literal) != nil }.count
        }.value
        return (matches, values.count, log.lines)
    }
}
