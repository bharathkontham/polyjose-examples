// The playground's support matrix for polyjose 0.4.0 on iOS: which store, algorithm and option
// combinations are enabled, and for each disabled one its reason and the code "Run anyway" gives
// (PLAYGROUND.md at the root of this repository, "Support matrix" and "Apple notes").
//
// polyjose has no "is this supported here" query, so the app holds the table itself. The demo walk
// (DemoWalk.swift) runs every cell, so a cell where this table and the library disagree fails it.
//
// Precedence: the algorithm table, then the key options, then the device (a Secure Enclave, a
// passcode). A cell's reason and code are those of the first rule that refuses it.
import Foundation

/// Where a playground key lives. The raw value is the `store` log field.
enum Store: String, CaseIterable, Identifiable, Sendable {
    case software
    case keychain
    case secureEnclave = "secure-enclave"

    var id: String { rawValue }
    var title: String {
        switch self {
        case .software: return "Software"
        case .keychain: return "Keychain"
        case .secureEnclave: return "Secure Enclave"
        }
    }
    var explanationId: String { "store.\(rawValue)" }
    var isPlatform: Bool { self != .software }
}

/// The user authentication a platform key asks for on each use (`AppleKey.Access.Flags`).
enum AccessOption: String, CaseIterable, Identifiable, Sendable {
    case none
    case userPresence
    case biometryAny
    case biometryCurrentSet
    case devicePasscode

    var id: String { rawValue }
    var title: String {
        switch self {
        case .none: return "None (no prompt)"
        case .userPresence: return ".userPresence"
        case .biometryAny: return ".biometryAny"
        case .biometryCurrentSet: return ".biometryCurrentSet"
        case .devicePasscode: return ".devicePasscode"
        }
    }
    /// The explanation id; `nil` for no authentication.
    var explanationId: String? { self == .none ? nil : "option.access.\(rawValue)" }
}

/// What the device offers, read once at start (KeysView's "This device" card).
struct DeviceCapabilities: Sendable {
    let secureEnclave: Bool
    let passcodeSet: Bool
    let simulator: Bool
}

/// Whether a combination is enabled.
enum Support: Equatable, Sendable {
    /// Enabled; `note` is an explanation id shown with the result (the RSA test key).
    case enabled(note: String?)
    /// Disabled: `reason` is an explanation id, `code` the error code "Run anyway" gives.
    case disabled(reason: String, code: String)

    var isEnabled: Bool { if case .enabled = self { return true } else { return false } }
}

enum Matrix {
    static let signingAlgs = [
        "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
    ]
    static let keyManagementAlgs = [
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "dir",
    ]
    static let encs = ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]
    static let defaultEnc = "A256GCM"
    static let curves = ["P-256", "P-384", "P-521", "X25519"]
    static let rsaSizes = [2048, 3072, 4096]

    static func isRsa(_ alg: String) -> Bool { alg.hasPrefix("RS") || alg.hasPrefix("PS") || alg == "RSA-OAEP-256" }
    static func isEcdh(_ alg: String) -> Bool { alg.hasPrefix("ECDH-ES") }
    static func isSymmetric(_ alg: String) -> Bool { alg.hasPrefix("HS") || (alg.hasSuffix("KW") && !isEcdh(alg)) || alg == "dir" }

    private static let unsupported = "UnsupportedAlgorithm"

    /// One cell of a table row: enabled, enabled with the RSA test key, or refused for a reason.
    private enum Cell {
        case yes
        case testKey
        case no(String)
    }

    private struct Row {
        let software: Cell
        let keychain: Cell
        let secureEnclave: Cell

        func cell(_ store: Store) -> Cell {
            switch store {
            case .software: return software
            case .keychain: return keychain
            case .secureEnclave: return secureEnclave
            }
        }
    }

    private static let p256Only = "reason.secure-enclave-p256"
    private static let symmetric = "reason.symmetric"
    private static let curve25519 = "reason.no-curve25519"

    /// PLAYGROUND.md, "Signing (JWS compact and JWT)".
    private static func signingRow(_ alg: String) -> Row {
        switch alg {
        case "HS256", "HS384", "HS512": return Row(software: .yes, keychain: .no(symmetric), secureEnclave: .no(symmetric))
        case "ES256": return Row(software: .yes, keychain: .yes, secureEnclave: .yes)
        case "ES384", "ES512": return Row(software: .yes, keychain: .yes, secureEnclave: .no(p256Only))
        case "EdDSA": return Row(software: .yes, keychain: .no(curve25519), secureEnclave: .no(curve25519))
        default: return Row(software: .testKey, keychain: .yes, secureEnclave: .no(p256Only))  // RS*, PS*
        }
    }

    /// PLAYGROUND.md, "Decryption (JWE compact)". `crv` matters for the ECDH-ES family only.
    private static func decryptionRow(_ alg: String, crv: String) -> Row {
        if isEcdh(alg) {
            switch crv {
            case "P-256": return Row(software: .yes, keychain: .yes, secureEnclave: .yes)
            case "X25519": return Row(software: .yes, keychain: .no(curve25519), secureEnclave: .no(curve25519))
            default: return Row(software: .yes, keychain: .yes, secureEnclave: .no(p256Only))  // P-384, P-521
            }
        }
        if alg == "RSA-OAEP-256" { return Row(software: .testKey, keychain: .yes, secureEnclave: .no(p256Only)) }
        return Row(software: .yes, keychain: .no(symmetric), secureEnclave: .no(symmetric))  // A*KW, A*GCMKW, dir
    }

    /// The table cell first, then the device.
    private static func support(_ cell: Cell, store: Store, device: DeviceCapabilities) -> Support {
        switch cell {
        case .no(let reason): return .disabled(reason: reason, code: unsupported)
        case .yes, .testKey:
            if store == .secureEnclave && !device.secureEnclave {
                return .disabled(reason: "reason.no-secure-enclave", code: unsupported)
            }
            if case .testKey = cell { return .enabled(note: "key.test-rsa") }
            return .enabled(note: nil)
        }
    }

    static func signing(alg: String, store: Store, device: DeviceCapabilities) -> Support {
        support(signingRow(alg).cell(store), store: store, device: device)
    }

    static func decryption(alg: String, crv: String, store: Store, device: DeviceCapabilities) -> Support {
        support(decryptionRow(alg, crv: crv).cell(store), store: store, device: device)
    }

    /// An access flag needs a passcode (PLAYGROUND.md, "Apple notes": an impossible authentication
    /// is `UserAuthenticationRequired`). The Simulator's Secure Enclave can't create a key with
    /// an access flag at all: `generate` gives `UserAuthenticationRequired` (measured on the iOS
    /// 27.2 Simulator, for each of the four flags; Keychain keys with them are created).
    static func access(_ option: AccessOption, store: Store, device: DeviceCapabilities) -> Support {
        guard option != .none, store.isPlatform else { return .enabled(note: nil) }
        if !device.passcodeSet { return .disabled(reason: "reason.no-lock-screen", code: "UserAuthenticationRequired") }
        if store == .secureEnclave && device.simulator {
            return .disabled(reason: "reason.simulator-secure-enclave-auth", code: "UserAuthenticationRequired")
        }
        return .enabled(note: nil)
    }

    /// A failure action on this store and algorithm (PLAYGROUND.md, "Failure actions").
    static func failure(_ failure: Failure, store: Store, alg: String) -> Support {
        switch failure {
        case .signDeletedKey, .encryptDeletedKey:
            if store == .software { return .disabled(reason: "reason.software-not-stored", code: "") }
        case .signWrongKey, .encryptWrongKey:
            // The one software RSA private key is the RFC 7515 A.2 test key: there is no second.
            if store == .software && Matrix.isRsa(alg) { return .disabled(reason: "key.test-rsa", code: "") }
        default:
            break
        }
        return .enabled(note: nil)
    }

    /// The other algorithm that `failure.*.other-alg` allows instead: one of the same key type, or
    /// for EdDSA, which no other signing algorithm shares a key with, ES256 (the allow-list is
    /// checked before the key, RFC 8725 §3.1).
    static func otherAlg(_ alg: String) -> String {
        switch alg {
        case "ES256": return "ES384"
        case "ES384", "ES512": return "ES256"
        case "HS256": return "HS384"
        case "HS384", "HS512": return "HS256"
        case "RS256": return "RS384"
        case "PS256": return "PS384"
        case "ECDH-ES": return "ECDH-ES+A256KW"
        case "ECDH-ES+A256KW": return "ECDH-ES+A128KW"
        case "ECDH-ES+A128KW", "ECDH-ES+A192KW": return "ECDH-ES+A256KW"
        case "A256KW": return "A128KW"
        case "A128KW", "A192KW": return "A256KW"
        case "A256GCMKW": return "A128GCMKW"
        case "A128GCMKW", "A192GCMKW": return "A256GCMKW"
        case "dir": return "A256KW"
        case "RSA-OAEP-256": return "ECDH-ES"
        default: return alg.hasPrefix("RS") ? "RS256" : alg.hasPrefix("PS") ? "PS256" : "ES256"
        }
    }

    /// The bits of a curve, as `AppleKey.generate` takes it for `ECDH-ES`. X25519 has no Apple key
    /// type: it is asked for as 255 bits (RFC 7748 §4.1), which no Apple key has.
    static func curveBits(_ crv: String) -> Int {
        switch crv {
        case "P-384": return 384
        case "P-521": return 521
        case "X25519": return 255
        default: return 256
        }
    }

    /// The bytes of a software `oct` key for a JWE `alg` (RFC 7518 §4.4, §4.7) or, for `dir`, the
    /// content key of `enc` (RFC 7518 §4.5, §5.2.3–§5.2.5, §5.3).
    static func octBytes(alg: String, enc: String) -> Int {
        if alg == "dir" {
            switch enc {
            case "A128GCM": return 16
            case "A192GCM": return 24
            case "A192CBC-HS384": return 48
            case "A256CBC-HS512": return 64
            default: return 32  // A256GCM, A128CBC-HS256
            }
        }
        if alg.hasPrefix("A128") { return 16 }
        if alg.hasPrefix("A192") { return 24 }
        return 32
    }
}

/// A "Try a failure" action (PLAYGROUND.md, "Failure actions"). The raw value is the `failure` log
/// field; `"failure." + rawValue` is its explanation id.
enum Failure: String, CaseIterable, Identifiable, Sendable {
    case signTamper = "sign.tamper"
    case signOtherAlg = "sign.other-alg"
    case signWrongKey = "sign.wrong-key"
    case signExpired = "sign.expired"
    case signDeletedKey = "sign.deleted-key"
    case encryptTamper = "encrypt.tamper"
    case encryptOtherAlg = "encrypt.other-alg"
    case encryptWrongKey = "encrypt.wrong-key"
    case encryptDeletedKey = "encrypt.deleted-key"

    var id: String { rawValue }
    var explanationId: String { "failure.\(rawValue)" }
    static let sign: [Failure] = [.signTamper, .signOtherAlg, .signWrongKey, .signExpired, .signDeletedKey]
    static let encrypt: [Failure] = [.encryptTamper, .encryptOtherAlg, .encryptWrongKey, .encryptDeletedKey]

    var title: String {
        switch self {
        case .signTamper, .encryptTamper: return "Tamper"
        case .signOtherAlg, .encryptOtherAlg: return "Other algorithm allowed"
        case .signWrongKey, .encryptWrongKey: return "Wrong key"
        case .signExpired: return "Expired (JWT)"
        case .signDeletedKey, .encryptDeletedKey: return "Deleted key"
        }
    }

    /// The code the action ends with.
    var code: String {
        switch self {
        case .signTamper, .signWrongKey: return "InvalidSignature"
        case .signOtherAlg, .encryptOtherAlg: return "AlgorithmNotAllowed"
        case .signExpired: return "TokenExpired"
        case .signDeletedKey, .encryptDeletedKey: return "KeyNotFound"
        case .encryptTamper, .encryptWrongKey: return "DecryptionFailed"
        }
    }
}
