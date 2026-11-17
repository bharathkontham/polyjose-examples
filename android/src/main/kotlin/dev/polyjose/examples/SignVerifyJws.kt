// How do I sign bytes and verify the signature (JWS)?
//
// A JWS (RFC 7515) signs any bytes. For claims about a user or a client, with an expiry, an
// issuer and an audience, use a JWT instead (SignVerifyJwt.kt).
//
// Verification always takes an explicit allow-list, `allowedAlgs`. Never build it from the
// token: whoever made the token chose its header (RFC 8725 §3.1). `alg: none` is never
// accepted, whatever the list says (RFC 8725 §3.2). See VerifyAllowList.kt for the rejections.
//
// Algorithms (RFC 7518 §3, RFC 8037 §3.1) and the keys they take:
//   HS256            a shared secret, `kty: oct`; the same key signs and verifies
//   RS256, PS256     an RSA key pair, 2048 bits or more
//   ES256/384/512    an EC key pair on P-256, P-384 or P-521
//   EdDSA            an Ed25519 key pair (`kty: OKP`)
//
// Keys are JWK JSON text (RFC 7517). Every polyjose call is synchronous and does real
// cryptography: on Android, call it off the main thread.
package dev.polyjose.examples

import dev.polyjose.JwsSignOptions
import dev.polyjose.JwsSigner
import dev.polyjose.JwsVerified
import dev.polyjose.JwsVerifyOptions
import dev.polyjose.jwkGenerateForAlg
import dev.polyjose.jwkToPublic
import dev.polyjose.jwsSignCompact
import dev.polyjose.jwsSignGeneral
import dev.polyjose.jwsVerifyCompact
import dev.polyjose.jwsVerifyJson
import org.json.JSONObject

/**
 * A key pair for a JWS algorithm: [signKey] signs, [verifyKey] verifies (RFC 7518 §3). Both are
 * JWK JSON text. [signKey] is secret: never log it (this class has no `toString` that shows it).
 */
class SigningKeyPair(val signKey: String, val verifyKey: String)

/**
 * A key pair for [alg]:
 * - HS256: one random secret for both (RFC 7518 §3.2: at least as long as the hash).
 * - RS256, PS256: polyjose 0.4.0 does not generate RSA keys, so this uses the RFC 7515 A.2
 *   test key. In your app, load your own key, for example with `jwkFromPem`.
 * - ES256/384/512, EdDSA: `jwkGenerateForAlg` makes a key on the right curve, with `alg` set.
 */
fun signingKeyPair(alg: String): SigningKeyPair {
    if (alg.startsWith("HS")) {
        val secret = jwkGenerateForAlg(alg)
        return SigningKeyPair(signKey = secret, verifyKey = secret)
    }
    val signKey = if (alg.startsWith("RS") || alg.startsWith("PS")) RFC7515_A2_RSA_PRIVATE_JWK else jwkGenerateForAlg(alg)
    return SigningKeyPair(signKey = signKey, verifyKey = jwkToPublic(signKey))
}

/**
 * Signs [payload] in the JWS Compact Serialization, `header.payload.signature`
 * (RFC 7515 §3.1, §7.1). The protected header carries `alg` (RFC 7515 §4.1.1).
 */
fun signCompact(payload: ByteArray, signKey: String, alg: String): String =
    jwsSignCompact(payload, signKey, JwsSignOptions(protectedHeader = JSONObject().put("alg", alg).toString()))

/**
 * Verifies a compact JWS (RFC 7515 §5.2), accepting only [alg]. Returns the verified `alg`,
 * `payload` and `protectedHeader`. Throws a `PolyjoseException`: `AlgorithmNotAllowed`,
 * `KeyAlgorithmMismatch`, `InvalidSignature`, ...
 */
fun verifyCompact(token: String, verifyKey: String, alg: String): JwsVerified =
    jwsVerifyCompact(token, verifyKey, JwsVerifyOptions(allowedAlgs = listOf(alg)))

/** One signer of a general JSON JWS: its private key and its algorithm. */
class Signer(val signKey: String, val alg: String)

/**
 * The general JWS JSON Serialization (RFC 7515 §7.2.1): several signatures over one payload,
 * for example an old and a new key during a key rollover. Returns the JSON text.
 */
fun signGeneral(payload: ByteArray, signers: List<Signer>): String =
    jwsSignGeneral(
        payload,
        signers.map { JwsSigner(key = it.signKey, protectedHeader = JSONObject().put("alg", it.alg).toString()) },
        false, // detached: the payload stays in the JWS
    )

/**
 * Verifies a JWS JSON Serialization (RFC 7515 §7.2, §5.2) with one key, accepting only [alg].
 * `signatureIndex` in the result says which signature verified.
 */
fun verifyJson(jws: String, verifyKey: String, alg: String): JwsVerified =
    jwsVerifyJson(jws, verifyKey, JwsVerifyOptions(allowedAlgs = listOf(alg)))
