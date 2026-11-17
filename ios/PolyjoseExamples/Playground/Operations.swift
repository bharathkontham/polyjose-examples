// The one place the playground reaches a key store or makes a software key.
//
// - Keychain and Secure Enclave keys go through the example files PlatformKeysKeychain.swift and
//   PlatformKeysSecureEnclave.swift, the same functions the checks use.
// - Software keys come from SignVerifyJws.swift, EncryptDecrypt.swift and TestKeys.swift, or from
//   polyjose directly where no example covers the key (an `oct` key for a JWE `alg`).
// - Every call runs off the main thread (`offMain`, a `Task.detached`): a key with user
//   authentication shows a system prompt during the call and blocks its thread until it closes.
// - Durations come from `ContinuousClock`, a monotonic clock; they are shown, never checked.
import Foundation
import LocalAuthentication
import Polyjose
import Security

// MARK: - Off the main thread, timed

struct Timed<T: Sendable>: Sendable {
    let result: Result<T, any Error>
    let ms: Int
}

/// Runs `body` in a detached task and measures it with the monotonic clock.
func offMain<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async -> Timed<T> {
    await Task.detached(priority: .userInitiated) {
        let clock = ContinuousClock()
        let start = clock.now
        let result = Result { try body() }
        let elapsed = (clock.now - start).components
        return Timed(result: result, ms: Int(elapsed.seconds) * 1000 + Int(elapsed.attoseconds / 1_000_000_000_000_000))
    }.value
}

// MARK: - Platform keys, through the example files

/// One `LAContext` the user chose to share between a key's calls (`AppleKey.Access.context`,
/// `kSecUseAuthenticationContext`), so one authentication serves several of them.
final class SharedContext: @unchecked Sendable {
    let context = LAContext()
}

/// The `access` of a new platform key.
struct AccessChoice: Sendable {
    var option: AccessOption = .none
    var shared: SharedContext?

    var access: AppleKey.Access {
        var flags: AppleKey.Access.Flags = []
        switch option {
        case .none: break
        case .userPresence: flags = .userPresence
        case .biometryAny: flags = .biometryAny
        case .biometryCurrentSet: flags = .biometryCurrentSet
        case .devicePasscode: flags = .devicePasscode
        }
        return AppleKey.Access(flags: flags, context: shared?.context)
    }
}

/// Keychain and Secure Enclave keys: each function calls the store's example file.
enum PlatformStore {
    static func create(_ store: Store, tag: String, algorithm: String, keySizeInBits: Int?, access: AccessChoice) throws -> AppleKey {
        switch store {
        case .secureEnclave:
            return try PlatformKeysSecureEnclave.create(tag: tag, algorithm: algorithm, keySizeInBits: keySizeInBits, access: access.access)
        default:
            return try PlatformKeysKeychain.create(tag: tag, algorithm: algorithm, keySizeInBits: keySizeInBits, access: access.access)
        }
    }

    /// Opens the key under `tag`. With a shared context, the key's calls use it, so the example
    /// files' `open` (which takes none) is replaced by `AppleKey.open(tag:algorithm:context:)`.
    static func open(_ store: Store, tag: String, algorithm: String, shared: SharedContext?) throws -> AppleKey {
        if let shared { return try AppleKey.open(tag: tag, algorithm: algorithm, context: shared.context) }
        switch store {
        case .secureEnclave: return try PlatformKeysSecureEnclave.open(tag: tag, algorithm: algorithm)
        default: return try PlatformKeysKeychain.open(tag: tag, algorithm: algorithm)
        }
    }

    static func signJws(_ store: Store, _ payload: Data, key: AppleKey, alg: String) throws -> String {
        switch store {
        case .secureEnclave: return try PlatformKeysSecureEnclave.signJws(payload, key: key, alg: alg)
        default: return try PlatformKeysKeychain.signJws(payload, key: key, alg: alg)
        }
    }

    static func signJwt(_ store: Store, _ claims: [String: Any], key: AppleKey, alg: String) throws -> String {
        switch store {
        case .secureEnclave: return try PlatformKeysSecureEnclave.signJwt(claims, key: key, alg: alg)
        default: return try PlatformKeysKeychain.signJwt(claims, key: key, alg: alg)
        }
    }

    static func decrypt(_ store: Store, _ token: String, key: AppleKey, allowedAlgs: [String], allowedEnc: [String]) throws -> JweDecrypted {
        switch store {
        case .secureEnclave: return try PlatformKeysSecureEnclave.decrypt(token, key: key, allowedAlgs: allowedAlgs, allowedEnc: allowedEnc)
        default: return try PlatformKeysKeychain.decrypt(token, key: key, allowedAlgs: allowedAlgs, allowedEnc: allowedEnc)
        }
    }

    static func delete(_ store: Store, tag: String) throws {
        switch store {
        case .secureEnclave: try PlatformKeysSecureEnclave.delete(tag: tag)
        default: try PlatformKeysKeychain.delete(tag: tag)
        }
    }

    static func whereItLives(_ store: Store, _ key: AppleKey) -> AppleKey.Protection {
        store == .secureEnclave ? PlatformKeysSecureEnclave.whereItLives(key) : PlatformKeysKeychain.whereItLives(key)
    }
}

// MARK: - Software keys, in memory only

/// A software key: a polyjose JWK held in this app's memory and nowhere else. Its secret JWK is
/// never shown or logged; printing it shows its id only.
struct SoftwareKey: Sendable, Identifiable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    let id: String
    /// The JWS `alg`, or the JWE `alg` it was made for.
    let alg: String
    let crv: String?
    /// The private or symmetric JWK. Secret: pass it to polyjose only.
    let secretJwk: String
    /// The public JWK; `nil` for an `oct` key, which has no public half.
    let publicJwk: String?
    let summary: SoftwareKeySummary

    /// The key a verifier or an encrypter uses: the public JWK, or the shared secret of an `oct` key.
    var verifyOrEncryptKey: String { publicJwk ?? secretJwk }

    var description: String { "SoftwareKey(\(id))" }
    var debugDescription: String { description }
    var customMirror: Mirror { Mirror(self, children: ["id": id], displayStyle: .struct) }
}

enum SoftwareKeys {
    /// A signing key for `alg` (RFC 7518 §3; RFC 8037 §3.1), through SignVerifyJws.signingKeyPair:
    /// HS* a random secret, ES* and EdDSA a random key pair, RS* and PS* the RFC 7515 A.2 test key.
    static func signing(alg: String, kid: String) throws -> SoftwareKey {
        let pair = try SignVerifyJws.signingKeyPair(alg: alg)
        return try make(kid: kid, alg: alg, crv: nil, secret: pair.signKey, symmetric: alg.hasPrefix("HS"))
    }

    /// A decryption key for the JWE `alg` (RFC 7518 §4): an EC or X25519 key pair through
    /// EncryptDecrypt.recipientKeyPair, the RFC 7515 A.2 test key for RSA-OAEP-256, or a random
    /// `oct` key of the size `alg` (or, for `dir`, `enc`) needs (RFC 7518 §6.4).
    static func decryption(alg: String, crv: String, enc: String, kid: String) throws -> SoftwareKey {
        if Matrix.isEcdh(alg) {
            return try make(kid: kid, alg: alg, crv: crv, secret: EncryptDecrypt.recipientKeyPair(crv: crv).privateKey, symmetric: false)
        }
        if alg == "RSA-OAEP-256" {
            return try make(kid: kid, alg: alg, crv: nil, secret: TestKeys.rfc7515A2RsaPrivateJwk, symmetric: false)
        }
        let secret = try jwkGenerateOct(lenBytes: UInt32(Matrix.octBytes(alg: alg, enc: enc)))
        return try make(kid: kid, alg: alg, crv: nil, secret: secret, symmetric: true)
    }

    private static func make(kid: String, alg: String, crv: String?, secret: String, symmetric: Bool) throws -> SoftwareKey {
        var object = try playgroundObject(secret)
        object["kid"] = kid
        let secretJwk = try playgroundText(object)
        let kty = object["kty"] as? String ?? "?"
        var bits: Int?
        if symmetric, let k = object["k"] as? String { bits = try base64urlDecode(text: k).count * 8 }
        let summary = SoftwareKeySummary(kty: kty, alg: alg, kid: kid, bits: bits, testKey: kty == "RSA")
        return SoftwareKey(
            id: kid, alg: alg, crv: crv, secretJwk: secretJwk,
            publicJwk: symmetric ? nil : try jwkToPublic(jwk: secretJwk), summary: summary)
    }

}

// MARK: - Listing the playground's keys

/// A platform key found by listing: attributes only.
struct ListedKey: Sendable, Identifiable, Hashable {
    let tag: String
    /// Where the platform reports it lives (`kSecAttrTokenID`).
    let store: Store
    /// The algorithm in its tag, `dev.polyjose.examples.playground.<alg>.<n>`.
    let algorithm: String
    let rsa: Bool
    let bits: Int
    var id: String { tag }

    var sizeLabel: String {
        if rsa { return "RSA \(bits)" }
        return bits == 521 ? "P-521" : "P-\(bits)"
    }
}

struct KeyListingFailed: Error {}

enum KeyListing {
    static let prefix = "dev.polyjose.examples.playground."

    /// The private keys whose tag has the playground prefix. The query asks for attributes only
    /// (`kSecReturnAttributes`, never data or a reference), with an `LAContext` whose
    /// `interactionNotAllowed` is set, so listing never asks the user to authenticate.
    static func list() throws -> [ListedKey] {
        let context = LAContext()
        context.interactionNotAllowed = true
        let query: [CFString: Any] = [
            kSecClass: kSecClassKey,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecMatchLimit: kSecMatchLimitAll,
            kSecReturnAttributes: true,
            kSecUseDataProtectionKeychain: true,
            kSecUseAuthenticationContext: context,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let items = result as? [[CFString: Any]] else { throw KeyListingFailed() }
        return items.compactMap { item -> ListedKey? in
            guard let data = item[kSecAttrApplicationTag] as? Data else { return nil }
            let tag = String(decoding: data, as: UTF8.self)
            guard tag.hasPrefix(prefix) else { return nil }
            let parts = tag.dropFirst(prefix.count).split(separator: ".")
            let token = item[kSecAttrTokenID] as? String
            let type = item[kSecAttrKeyType].map { "\($0)" } ?? ""
            let bits = (item[kSecAttrKeySizeInBits] as? NSNumber)?.intValue ?? 0
            return ListedKey(
                tag: tag,
                store: token == kSecAttrTokenIDSecureEnclave as String ? .secureEnclave : .keychain,
                algorithm: parts.dropLast().joined(separator: "."),
                rsa: type == kSecAttrKeyTypeRSA as String,
                bits: bits)
        }
        .sorted { $0.tag < $1.tag }
    }

    /// `dev.polyjose.examples.playground.<algorithm>.<n>`, `<n>` the lowest number not in use.
    static func nextTag(_ algorithm: String, existing: [ListedKey]) -> String {
        let used = Set(existing.map(\.tag))
        var n = 1
        while used.contains("\(prefix)\(algorithm).\(n)") { n += 1 }
        return "\(prefix)\(algorithm).\(n)"
    }
}

// MARK: - This device

struct DeviceInfo: Sendable {
    let polyjose: String
    let os: String
    let model: String
    let simulator: Bool
    let secureEnclave: Bool
    /// A passcode is set: `LAContext.canEvaluatePolicy(.deviceOwnerAuthentication)`.
    let passcodeSet: Bool

    var capabilities: DeviceCapabilities { DeviceCapabilities(secureEnclave: secureEnclave, passcodeSet: passcodeSet, simulator: simulator) }

    static func read() -> DeviceInfo {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        var os = "\(version.majorVersion).\(version.minorVersion)"
        if version.patchVersion > 0 { os += ".\(version.patchVersion)" }
        #if targetEnvironment(simulator)
        let simulator = true
        let model = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] ?? "Simulator"
        #else
        let simulator = false
        var name = utsname()
        uname(&name)
        let model = withUnsafeBytes(of: &name.machine) { String(decoding: $0.prefix { $0 != 0 }, as: UTF8.self) }
        #endif
        return DeviceInfo(
            polyjose: Polyjose.version(), os: "iOS-\(os)", model: model, simulator: simulator,
            secureEnclave: PlatformKeysSecureEnclave.isAvailable,
            passcodeSet: LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil))
    }
}

// MARK: - Small helpers

let demoPayload = "polyjose example payload"
let demoIssuer = "https://issuer.example"
let demoAudience = "polyjose-playground"
let demoSubject = "demo-user"

/// The fixed JWT claims (PLAYGROUND.md, `option.payload`): `exp` five minutes from now, or an hour
/// ago for `failure.sign.expired` (RFC 7519 §4.1.4).
func demoClaims(expired: Bool) -> [String: Any] {
    let now = Int64(Date().timeIntervalSince1970)
    return ["iss": demoIssuer, "aud": demoAudience, "sub": demoSubject, "exp": expired ? now - 3600 : now + 300]
}

/// The protected header of a compact JWS or JWE: its first part, base64url-decoded (RFC 7515 §7.1,
/// RFC 7516 §7.1).
func protectedHeader(of token: String) throws -> String {
    let first = token.split(separator: ".", omittingEmptySubsequences: false).first.map(String.init) ?? ""
    return String(decoding: try base64urlDecode(text: first), as: UTF8.self)
}

/// Changes one character in the middle of part `part` of a compact token (`A` and `B` swap, any
/// other character becomes `A`). Returns the token and the index of the character in the token.
func tampered(_ token: String, part: Int) -> (token: String, index: Int) {
    var parts = token.split(separator: ".", omittingEmptySubsequences: false).map { Array($0) }
    let middle = parts[part].count / 2
    parts[part][middle] = parts[part][middle] == "A" ? "B" : "A"
    let index = parts[..<part].reduce(0) { $0 + $1.count + 1 } + middle
    return (parts.map { String($0) }.joined(separator: "."), index)
}

struct NotAJsonObject: Error {}

func playgroundObject(_ text: String) throws -> [String: Any] {
    guard let object = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else { throw NotAJsonObject() }
    return object
}

func playgroundText(_ object: [String: Any]) throws -> String {
    String(decoding: try JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]), as: UTF8.self)
}
