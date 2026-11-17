// The demo walk (PLAYGROUND.md at the root of this repository, "Demo walk"): launched with the
// argument `-playground-demo` (`run.sh --playground` does this), the app runs every cell of the
// support matrix on this device through the same `Playground` functions the buttons call, then
// every failure action, then the key actions, and deletes the keys it made.
//
//   WALK OK sign/jws/secure-enclave/ES384 expected=UnsupportedAlgorithm got=UnsupportedAlgorithm
//   POLYJOSE-PLAYGROUND: 180/180 OK
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
                outcome(await playground.sign(spec, jwt: false, .failure(failure)))
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
                outcome(await playground.encrypt(spec, enc: Matrix.defaultEnc, .failure(failure)))
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
                    guard card.succeeded else { return outcome(card) }
                    let tag = playground.lastCreatedTag
                    await playground.refreshKeys()
                    return playground.platformKeys.contains { $0.tag == tag && $0.store == store } ? "listed" : "not-listed"
                })
            }
        }
        steps.append(Step(id: "keys/open-again/keychain/ES256", expected: "ok") {
            let card = await playground.createKey(KeySpec(store: .keychain, alg: "ES256"))
            guard card.succeeded, let listed = playground.platformKeys.first(where: { $0.tag == playground.lastCreatedTag }) else {
                return outcome(card)
            }
            let opened = await playground.openAgain(listed)
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
        let total = steps.count + 1
        emit("WALK \(left == 0 ? "OK" : "FAIL") keys/walk-keys-deleted expected=0 got=\(left)")
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

    /// `ok` for a tap that ended without an error, else its code.
    private static func outcome(_ card: Card) -> String {
        if card.plaintextDiffers { return "plaintext-differs" }
        return card.errorCode ?? "ok"
    }

    private static func emit(_ line: String) {
        print(line)
        fflush(stdout)
    }
}
