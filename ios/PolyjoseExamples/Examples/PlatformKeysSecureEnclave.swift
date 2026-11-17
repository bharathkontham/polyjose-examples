// How do I keep a signing or decryption key in the Secure Enclave?
//
// `AppleKey` with `protection: .secureEnclave` is a hardware-bound P-256 key: it is created in
// the Secure Enclave and its private key never leaves it, not even to your app (Apple:
// "Protecting keys with the Secure Enclave"). polyjose asks the key for one signature or ECDH
// shared secret at a time, and checks every signature against the public key before it returns
// the token.
//
// The Secure Enclave serves P-256 only, so a key is bound to one of two algorithms
// (RFC 8725 §3.1):
//   ES256     ECDSA on P-256 with SHA-256 (RFC 7518 §3.4)
//   ECDH-ES   ECDH-ES and ECDH-ES+A128KW/A192KW/A256KW on P-256 (RFC 7518 §4.6)
// Anything else (ES384, RSA, a 384-bit ECDH-ES key) is `UnsupportedAlgorithm`, and no key is
// created. On a device without a Secure Enclave (`isAvailable` is false), `create` is
// `UnsupportedAlgorithm` too: there is no fallback to a Keychain key. An app that wants one
// checks `isAvailable` and calls PlatformKeysKeychain.swift itself.
//
// On the iOS Simulator, `isAvailable` is true and the keys work, but the Simulator's Secure
// Enclave is a host pass-through, not a hardware guarantee; only a run on an iPhone shows the
// hardware.
//
// A key is created once under a tag (`kSecAttrApplicationTag`) and found again by that tag on
// later launches. It is `ThisDeviceOnly` and never synchronized.
//
// Threading: every call is synchronous. A key created with `access` flags (`.userPresence`,
// `.biometryAny`, `.biometryCurrentSet`, `.devicePasscode`) shows a system prompt during each
// sign or decrypt call and blocks the calling thread until the prompt closes, so call these
// functions off the main thread, for example in a `Task.detached`. A cancelled or failed
// authentication is `UserAuthenticationRequired`.
//
// Errors are `PolyjoseError`s with a stable `code()`: `KeyNotFound`, `UnsupportedAlgorithm`,
// `KeyAlgorithmMismatch`, `UserAuthenticationRequired`, `PlatformKeyFailed` (and the usual JOSE
// codes). None holds key material, a tag or platform error text.
import CryptoKit  // `SecureEnclave.isAvailable` only
import Foundation
import Polyjose

enum PlatformKeysSecureEnclave {
    /// Whether this device has a Secure Enclave (CryptoKit `SecureEnclave.isAvailable`).
    static var isAvailable: Bool { SecureEnclave.isAvailable }

    /// Creates a permanent Secure Enclave key under `tag`, bound to `algorithm`, `ES256` or
    /// `ECDH-ES` (RFC 8725 §3.1). `keySizeInBits` is implied (256); any other value is
    /// `UnsupportedAlgorithm`. `access` sets when the key can be used and whether each use
    /// prompts (the default: when unlocked, no prompt). `PlatformKeyFailed` when a key already
    /// exists under `tag`.
    static func create(
        tag: String, algorithm: String, keySizeInBits: Int? = nil, access: AppleKey.Access = AppleKey.Access()
    ) throws -> AppleKey {
        try AppleKey.generate(tag: tag, algorithm: algorithm, protection: .secureEnclave, access: access, keySizeInBits: keySizeInBits)
    }

    /// Finds the key stored under `tag` and binds it to `algorithm`. `KeyNotFound` when there is
    /// none; `KeyAlgorithmMismatch` when the key can't serve `algorithm` (RFC 8725 §3.1).
    static func open(tag: String, algorithm: String) throws -> AppleKey {
        try AppleKey.open(tag: tag, algorithm: algorithm)
    }

    /// Signs `payload` in the JWS Compact Serialization (RFC 7515 §5.1, §7.1) with the Secure
    /// Enclave key. The protected header is `{"alg": "ES256"}` (RFC 7515 §4.1.1; RFC 7518 §3.4).
    /// Anyone verifies it with `key.publicJwk()` and the ordinary `jwsVerifyCompact`.
    static func signJws(_ payload: Data, key: AppleKey, alg: String = "ES256") throws -> String {
        let header = String(decoding: try JSONSerialization.data(withJSONObject: ["alg": alg]), as: UTF8.self)
        return try jwsSignCompactWithPlatformKey(payload: payload, key: key, options: JwsSignOptions(protectedHeader: header))
    }

    /// Issues a JWT (RFC 7519 §7.1) over `claims`, a JSON object, signed with the Secure Enclave
    /// key. The header gets `typ: "JWT"` (RFC 7519 §5.1). Anyone validates it with
    /// `key.publicJwk()` and the ordinary `jwtVerify` (RFC 7519 §7.2).
    static func signJwt(_ claims: [String: Any], key: AppleKey, alg: String = "ES256") throws -> String {
        let claimsJson = String(decoding: try JSONSerialization.data(withJSONObject: claims), as: UTF8.self)
        return try jwtSignWithPlatformKey(claims: claimsJson, key: key, options: JwtSignOptions(alg: alg))
    }

    /// Decrypts a compact JWE (RFC 7516 §5.2) that was encrypted to `key.publicJwk()`, accepting
    /// only `allowedAlgs` and `allowedEnc`: your own fixed lists, never values read from the
    /// token's header (RFC 8725 §3.1). The Secure Enclave computes the ECDH shared secret
    /// (RFC 7518 §4.6); the key derivation, key unwrap and content decryption are polyjose's. An
    /// `alg` or `enc` outside the lists is `AlgorithmNotAllowed`, before the key is used; a wrong
    /// key or a changed token is the one `DecryptionFailed`, whatever the cause (RFC 7516 §11.5).
    static func decrypt(_ token: String, key: AppleKey, allowedAlgs: [String], allowedEnc: [String]) throws -> JweDecrypted {
        try jweDecryptCompactWithPlatformKey(
            token: token, key: key, options: JweDecryptOptions(allowedAlgs: allowedAlgs, allowedEnc: allowedEnc))
    }

    /// Deletes every key stored under `tag`. No key under `tag` is not an error. (A key-store
    /// operation: no RFC defines it.)
    static func delete(tag: String) throws {
        try AppleKey.delete(tag: tag)
    }

    /// Where the key lives, as the platform reports it (`kSecAttrTokenID`), not as requested:
    /// `.secureEnclave` for a key from `create`. (A key-store property: no RFC defines it.)
    static func whereItLives(_ key: AppleKey) -> AppleKey.Protection {
        key.protection
    }
}
