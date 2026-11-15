// How do I encrypt data for someone, and decrypt what was encrypted for me (JWE)?
//
// A JWE (RFC 7516) names two algorithms:
//   alg  how the content key reaches the recipient. Here ECDH-ES+A256KW: an ephemeral key
//        agreement with the recipient's public key, then AES Key Wrap (RFC 7518 §4.6)
//   enc  how the content is encrypted with that key. Here A256GCM (RFC 7518 §5.3)
// The sender needs only the recipient's public key. The recipient's curve can be P-256,
// P-384, P-521 (`kty: EC`, RFC 7518 §6.2) or X25519 (`kty: OKP`, RFC 8037 §3.2).
//
// Decryption takes an allow-list for each, `allowedAlgs` and `allowedEnc` (RFC 8725 §3.1).
// A wrong key, a changed token and a bad tag all fail with one code, `DecryptionFailed`, so
// the error tells an attacker nothing about the cause (RFC 7516 §11.5).
import Foundation
import Polyjose

enum EncryptDecrypt {
    static let alg = "ECDH-ES+A256KW"
    static let enc = "A256GCM"

    /// The recipient's key pair, as JWK JSON text. Keep `privateKey` (it is secret); give
    /// `publicKey` to whoever encrypts to you.
    struct RecipientKeyPair: Sendable {
        let privateKey: String
        let publicKey: String
    }

    /// An EC key on P-256, P-384 or P-521, or an X25519 OKP key, from the OS CSPRNG.
    static func recipientKeyPair(crv: String) throws -> RecipientKeyPair {
        let privateKey = try crv == "X25519" ? jwkGenerateOkp(crv: crv) : jwkGenerateEc(crv: crv)
        return RecipientKeyPair(privateKey: privateKey, publicKey: try jwkToPublic(jwk: privateKey))
    }

    /// Encrypts `plaintext` to `recipientPublicKey` in the JWE Compact Serialization
    /// (RFC 7516 §3.1, §7.1): `header.encryptedKey.iv.ciphertext.tag`.
    static func encryptTo(_ plaintext: Data, recipientPublicKey: String) throws -> String {
        try jweEncryptCompact(
            plaintext: plaintext,
            options: JweEncryptOptions(enc: enc, recipients: [JweRecipient(alg: alg, key: recipientPublicKey)])
        )
    }

    /// Decrypts a compact JWE (RFC 7516 §5.2), accepting only `allowedAlgs` and `allowedEnc`
    /// (default: the two this file encrypts with). The result has `plaintext` and `header`, the
    /// JSON text that says which `alg` and `enc` were used.
    static func decrypt(
        _ token: String,
        privateKey: String,
        allowedAlgs: [String] = [alg],
        allowedEnc: [String] = [enc]
    ) throws -> JweDecrypted {
        try jweDecryptCompact(
            token: token,
            key: privateKey,
            options: JweDecryptOptions(allowedAlgs: allowedAlgs, allowedEnc: allowedEnc)
        )
    }
}
