// How do I keep a signing or decryption key in the iOS Keychain?
//
// `AppleKey` with `protection: .keychain` is a Keychain key: stored and protected by the OS, not
// hardware-bound; on iOS, code that holds the key reference can export the private key. Your
// code never handles the private key as JWK text: polyjose asks the key for one signature, ECDH
// shared secret or RSA-OAEP-256 decryption at a time, and checks every signature against the
// public key before it returns the token. For a key that can't be exported at all, see
// PlatformKeysSecureEnclave.swift.
//
// One algorithm per key (RFC 8725 §3.1), chosen when the key is created:
//   ES256, ES384, ES512        an EC key on P-256, P-384 or P-521 (RFC 7518 §3.4)
//   RS256…RS512, PS256…PS512   an RSA key of 2048 (default), 3072 or 4096 bits (RFC 7518 §3.3, §3.5)
//   ECDH-ES                    an EC key on P-256 (default), P-384 or P-521, for ECDH-ES and
//                              ECDH-ES+A128KW/A192KW/A256KW (RFC 7518 §4.6)
//   RSA-OAEP-256               an RSA key of 2048, 3072 or 4096 bits (RFC 7518 §4.3)
// Anything else (HS256, EdDSA, X25519) is `UnsupportedAlgorithm`.
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
import Foundation
import Polyjose

enum PlatformKeysKeychain {
    /// Creates a permanent Keychain key under `tag`, bound to one `algorithm` (RFC 8725 §3.1; the
    /// list above).
    /// `keySizeInBits`: the RSA size (2048, 3072, 4096) or, for `ECDH-ES`, the curve (256, 384,
    /// 521); `nil` takes the default, and ES256/384/512 imply it. `access` sets when the key can
    /// be used and whether each use prompts (the default: when unlocked, no prompt).
    /// `PlatformKeyFailed` when a key already exists under `tag`.
    static func create(
        tag: String, algorithm: String, keySizeInBits: Int? = nil, access: AppleKey.Access = AppleKey.Access()
    ) throws -> AppleKey {
        try AppleKey.generate(tag: tag, algorithm: algorithm, protection: .keychain, access: access, keySizeInBits: keySizeInBits)
    }

    /// Finds the key stored under `tag` and binds it to `algorithm`. `KeyNotFound` when there is
    /// none; `KeyAlgorithmMismatch` when the key can't serve `algorithm` (RFC 8725 §3.1).
    static func open(tag: String, algorithm: String) throws -> AppleKey {
        try AppleKey.open(tag: tag, algorithm: algorithm)
    }

    /// Signs `payload` in the JWS Compact Serialization (RFC 7515 §5.1, §7.1) with the Keychain
    /// key. The protected header is `{"alg": alg}` (RFC 7515 §4.1.1); `alg` must be the key's
    /// algorithm. Anyone verifies it with `key.publicJwk()` and the ordinary `jwsVerifyCompact`.
    static func signJws(_ payload: Data, key: AppleKey, alg: String) throws -> String {
        let header = String(decoding: try JSONSerialization.data(withJSONObject: ["alg": alg]), as: UTF8.self)
        return try jwsSignCompactWithPlatformKey(payload: payload, key: key, options: JwsSignOptions(protectedHeader: header))
    }

    /// Issues a JWT (RFC 7519 §7.1) over `claims`, a JSON object, signed with the Keychain key.
    /// The header gets `typ: "JWT"` (RFC 7519 §5.1). Anyone validates it with `key.publicJwk()`
    /// and the ordinary `jwtVerify` (RFC 7519 §7.2).
    static func signJwt(_ claims: [String: Any], key: AppleKey, alg: String) throws -> String {
        let claimsJson = String(decoding: try JSONSerialization.data(withJSONObject: claims), as: UTF8.self)
        return try jwtSignWithPlatformKey(claims: claimsJson, key: key, options: JwtSignOptions(alg: alg))
    }

    /// Decrypts a compact JWE (RFC 7516 §5.2) that was encrypted to `key.publicJwk()`, accepting
    /// only `allowedAlgs` and `allowedEnc`: your own fixed lists, never values read from the
    /// token's header (RFC 8725 §3.1). The key does the ECDH or RSA-OAEP-256 step
    /// (RFC 7518 §4.6, §4.3); content decryption is polyjose's. An `alg` or `enc` outside the
    /// lists is `AlgorithmNotAllowed`, before the key is used; a wrong key or a changed token is
    /// the one `DecryptionFailed`, whatever the cause (RFC 7516 §11.5).
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
    /// `.keychain` for a key from `create`. (A key-store property: no RFC defines it.)
    static func whereItLives(_ key: AppleKey) -> AppleKey.Protection {
        key.protection
    }
}
