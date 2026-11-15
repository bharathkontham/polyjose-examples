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
package dev.polyjose.examples

import dev.polyjose.JweDecryptOptions
import dev.polyjose.JweDecrypted
import dev.polyjose.JweEncryptOptions
import dev.polyjose.JweRecipient
import dev.polyjose.jweDecryptCompact
import dev.polyjose.jweEncryptCompact
import dev.polyjose.jwkGenerateEc
import dev.polyjose.jwkGenerateOkp
import dev.polyjose.jwkToPublic

const val JWE_ALG = "ECDH-ES+A256KW"
const val JWE_ENC = "A256GCM"

/**
 * A recipient's key pair, JWK JSON text. Keep [privateKey] (it is secret: never log it); give
 * [publicKey] to whoever encrypts to you.
 */
class RecipientKeyPair(val privateKey: String, val publicKey: String)

/** A recipient key pair: an EC key on `P-256`, `P-384` or `P-521`, or an `X25519` OKP key. */
fun recipientKeyPair(crv: String): RecipientKeyPair {
    val privateKey = if (crv == "X25519") jwkGenerateOkp(crv) else jwkGenerateEc(crv)
    return RecipientKeyPair(privateKey = privateKey, publicKey = jwkToPublic(privateKey))
}

/**
 * Encrypts [plaintext] to [recipientPublicKey] in the JWE Compact Serialization
 * (RFC 7516 §3.1, §7.1): `header.encryptedKey.iv.ciphertext.tag`.
 */
fun encryptTo(plaintext: ByteArray, recipientPublicKey: String): String =
    jweEncryptCompact(
        plaintext,
        JweEncryptOptions(enc = JWE_ENC, recipients = listOf(JweRecipient(alg = JWE_ALG, key = recipientPublicKey))),
    )

/**
 * Decrypts a compact JWE (RFC 7516 §5.2), accepting only [allowedAlgs] and [allowedEnc]
 * (default: the two this file encrypts with). The result holds `plaintext` and `header` (JSON
 * text), which says which `alg` and `enc` were used. Wipe the plaintext when you are done. The
 * allow-lists are always your own fixed lists, never values read from the token's header
 * (RFC 8725 §3.1).
 */
fun decrypt(
    token: String,
    privateKey: String,
    allowedAlgs: List<String> = listOf(JWE_ALG),
    allowedEnc: List<String> = listOf(JWE_ENC),
): JweDecrypted =
    jweDecryptCompact(token, privateKey, JweDecryptOptions(allowedAlgs = allowedAlgs, allowedEnc = allowedEnc))
