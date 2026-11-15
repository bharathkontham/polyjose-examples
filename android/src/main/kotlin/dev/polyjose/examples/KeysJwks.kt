// How do I create keys, export them, and pick one from a JWK Set?
//
// Keys are JWKs (RFC 7517), passed and returned as JSON text. A private JWK holds secret members
// (`d` for EC, OKP and RSA, `k` for oct): never log it, and call `jwkToPublic` before you publish
// or send one. This file reads and edits JWK JSON with Android's built-in `org.json`.
package dev.polyjose.examples

import dev.polyjose.JwkSelector
import dev.polyjose.jwkFromPem
import dev.polyjose.jwkGenerateEc
import dev.polyjose.jwkThumbprint
import dev.polyjose.jwkToPem
import dev.polyjose.jwkToPublic
import dev.polyjose.jwksSelect
import org.json.JSONArray
import org.json.JSONObject

/** A random EC private key (RFC 7518 §6.2) on `P-256`, `P-384` or `P-521`, from the OS CSPRNG. */
fun generateEcKey(crv: String = "P-256"): String = jwkGenerateEc(crv)

/** The public half of a key (RFC 7517 §4, RFC 7518 §6.2.1): the private members are removed. */
fun publicKeyOf(privateJwk: String): String = jwkToPublic(privateJwk)

/**
 * The JWK Thumbprint (RFC 7638 §3), SHA-256, base64url: a stable identifier of a key's public
 * members, and a good `kid`. Do not publish the thumbprint of a secret `oct` key: it is an
 * unsalted hash of the secret (RFC 7638 §7).
 */
fun thumbprint(jwk: String): String = jwkThumbprint(jwk)

/** A key exported as PEM and imported back. [jwk] is a private key: never log it. */
class PemRoundTrip(val pem: String, val jwk: String)

/**
 * Exports a private key as PKCS#8 PEM (RFC 5958, RFC 7468 §10, "PRIVATE KEY") and imports it
 * back as a JWK. `jwkToPem` also takes `"spki"` for a public key (RFC 7468 §13).
 */
fun pemRoundTrip(privateJwk: String): PemRoundTrip {
    val pem = jwkToPem(privateJwk, "pkcs8")
    return PemRoundTrip(pem = pem, jwk = jwkFromPem(pem))
}

/** A copy of [jwk] with its `kid` member (RFC 7517 §4.5) set to [kid]. */
fun withKid(jwk: String, kid: String): String = JSONObject(jwk).put("kid", kid).toString()

/**
 * A public JWK Set (RFC 7517 §5), as a `jwks_uri` endpoint serves it: each key's public half,
 * with its `kid` (RFC 7517 §4.5). [entries] maps each `kid` to its key, in order.
 */
fun publicJwks(entries: List<Pair<String, String>>): String {
    val keys = JSONArray()
    for ((kid, key) in entries) keys.put(JSONObject(withKid(jwkToPublic(key), kid)))
    return JSONObject().put("keys", keys).toString()
}

/**
 * The one key of a JWK Set that [selector] picks, by `kid`, `alg` and `keyUse` (each optional;
 * RFC 7517 §4.2, §4.4, §4.5). No match throws `NoMatchingKey`, more than one
 * `MultipleMatchingKeys` (a set's order has no meaning, RFC 7517 §5).
 */
fun selectKey(jwks: String, selector: JwkSelector): String = jwksSelect(jwks, selector)
