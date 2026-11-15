// Every check of ../CATALOG.md, in its order, run through the example files in
// dev.polyjose.examples. Each check produces one line:
//
//   PASS jws/sign-verify/es256
//   FAIL jwt/verify/rejects-expired: expected TokenExpired, got InvalidClaim
//
// and the run ends with `POLYJOSE-VERIFY: P/R PASS`. A FAIL line never shows key material,
// plaintext or token contents.
package dev.polyjose.examples.app

import dev.polyjose.JwkSelector
import dev.polyjose.JwtVerifyOptions
import dev.polyjose.PolyjoseException
import dev.polyjose.base64urlEncode
import dev.polyjose.examples.JWE_ALG
import dev.polyjose.examples.JWE_ENC
import dev.polyjose.examples.RFC7638_3_1_JWK
import dev.polyjose.examples.RFC7638_3_1_THUMBPRINT
import dev.polyjose.examples.Signer
import dev.polyjose.examples.decrypt
import dev.polyjose.examples.encryptTo
import dev.polyjose.examples.generateEcKey
import dev.polyjose.examples.issueToken
import dev.polyjose.examples.jwsRejection
import dev.polyjose.examples.jwtRejection
import dev.polyjose.examples.pemRoundTrip
import dev.polyjose.examples.publicJwks
import dev.polyjose.examples.publicKeyOf
import dev.polyjose.examples.recipientKeyPair
import dev.polyjose.examples.rejectionCode
import dev.polyjose.examples.selectKey
import dev.polyjose.examples.signCompact
import dev.polyjose.examples.signGeneral
import dev.polyjose.examples.signingKeyPair
import dev.polyjose.examples.thumbprint
import dev.polyjose.examples.validateToken
import dev.polyjose.examples.validateWithJwks
import dev.polyjose.examples.verifyCompact
import dev.polyjose.examples.verifyJson
import dev.polyjose.examples.withKid
import dev.polyjose.jwkGenerateEc
import dev.polyjose.jwkGenerateForAlg
import dev.polyjose.jwkToPublic
import org.json.JSONObject
import java.util.Locale

// --- helpers ----------------------------------------------------------------------------------

/** A check that did not hold. Its message is the FAIL reason. */
class CheckFailure(message: String) : Exception(message)

fun expect(cond: Boolean, what: String) {
    if (!cond) throw CheckFailure(what)
}

/** For public, non-secret values only (algorithm names, kids, indexes): shows both. */
fun expectEq(actual: Any?, expected: Any?, what: String) {
    if (actual != expected) throw CheckFailure("$what: expected $expected, got $actual")
}

/** For anything that may be secret or token content: says only that it differs. */
fun expectSame(actual: Any?, expected: Any?, what: String) = expect(actual == expected, "$what differs")

fun expectBytes(actual: ByteArray, expected: ByteArray, what: String) = expect(actual.contentEquals(expected), "$what differs")

/** The check fails unless [code] is what [rejection] (an error code, or null for success) says. */
fun expectCode(rejection: String?, code: String) {
    if (rejection != code) throw CheckFailure("expected $code, got ${rejection ?: "success"}")
}

fun nowSec(): Long = System.currentTimeMillis() / 1000

/** A member of a JSON object (JSON text), or null when it is absent. */
fun member(json: String, name: String): Any? = JSONObject(json).opt(name)

/** Changes one character in the middle of part [index] of a compact token. */
fun tamper(token: String, index: Int): String {
    val parts = token.split(".").toMutableList()
    val p = parts[index]
    val i = p.length / 2
    parts[index] = p.substring(0, i) + (if (p[i] == 'A') 'B' else 'A') + p.substring(i + 1)
    return parts.joinToString(".")
}

// --- the catalog, in CATALOG.md order ---------------------------------------------------------

val JWS_ALGS = listOf("HS256", "RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA")
val PAYLOAD = "polyjose example payload".toByteArray(Charsets.UTF_8)
const val ISSUER = "https://issuer.example"
const val AUDIENCE = "https://api.example"

/** Claims with `iss`, `aud`, `sub` and an `exp` five minutes from now, as JSON text. */
fun claims(exp: Long = nowSec() + 300): String =
    JSONObject().put("iss", ISSUER).put("aud", AUDIENCE).put("sub", "user-123").put("exp", exp).toString()

class Check(val id: String, val run: () -> Unit)

val CHECKS: List<Check> = buildList {
    fun check(id: String, run: () -> Unit) = add(Check(id, run))

    // JWS: sign and verify (SignVerifyJws.kt)
    for (alg in JWS_ALGS) {
        check("jws/sign-verify/${alg.lowercase(Locale.ROOT)}") {
            val keys = signingKeyPair(alg)
            val token = signCompact(PAYLOAD, keys.signKey, alg)
            val verified = verifyCompact(token, keys.verifyKey, alg)
            expectEq(verified.alg, alg, "verified alg")
            expectBytes(verified.payload, PAYLOAD, "payload")
        }
    }

    check("jws/json/general-two-signers") {
        val es = signingKeyPair("ES256")
        val ed = signingKeyPair("EdDSA")
        val jws = signGeneral(PAYLOAD, listOf(Signer(es.signKey, "ES256"), Signer(ed.signKey, "EdDSA")))
        val byEs = verifyJson(jws, es.verifyKey, "ES256")
        val byEd = verifyJson(jws, ed.verifyKey, "EdDSA")
        expectEq(byEs.signatureIndex.toInt(), 0, "ES256 signatureIndex")
        expectEq(byEd.signatureIndex.toInt(), 1, "EdDSA signatureIndex")
        expectBytes(byEs.payload, PAYLOAD, "payload (ES256)")
        expectBytes(byEd.payload, PAYLOAD, "payload (EdDSA)")
    }

    // JWS: rejections (VerifyAllowList.kt)
    check("jws/verify/rejects-alg-not-allowed") {
        val keys = signingKeyPair("ES256")
        val token = signCompact(PAYLOAD, keys.signKey, "ES256")
        expectCode(jwsRejection(token, keys.verifyKey, listOf("ES384")), "AlgorithmNotAllowed")
    }

    check("jws/verify/rejects-none") {
        // An Unsecured JWS (RFC 7515 Appendix A.5): header {"alg":"none"}, empty signature.
        val header = base64urlEncode("""{"alg":"none"}""".toByteArray(Charsets.UTF_8))
        val token = "$header.${base64urlEncode(PAYLOAD)}."
        val verifyKey = signingKeyPair("ES256").verifyKey
        expectCode(jwsRejection(token, verifyKey, listOf("ES256")), "AlgorithmNotAllowed")
        expectCode(jwsRejection(token, verifyKey, listOf("none")), "AlgorithmNotAllowed")
        expectCode(jwsRejection(token, verifyKey, listOf("ES256", "none")), "AlgorithmNotAllowed")
    }

    check("jws/verify/rejects-tampered-payload") {
        val keys = signingKeyPair("ES256")
        val token = signCompact(PAYLOAD, keys.signKey, "ES256")
        expectCode(jwsRejection(tamper(token, 1), keys.verifyKey, listOf("ES256")), "InvalidSignature")
    }

    check("jws/verify/rejects-wrong-key") {
        val keys = signingKeyPair("ES256")
        val token = signCompact(PAYLOAD, keys.signKey, "ES256")
        val other = signingKeyPair("ES256")
        expectCode(jwsRejection(token, other.verifyKey, listOf("ES256")), "InvalidSignature")
    }

    check("jws/verify/rejects-key-family-mismatch") {
        val hs = signingKeyPair("HS256")
        val token = signCompact(PAYLOAD, hs.signKey, "HS256")
        val ecPublic = jwkToPublic(jwkGenerateEc("P-256"))
        expectCode(jwsRejection(token, ecPublic, listOf("HS256")), "KeyAlgorithmMismatch")
    }

    // JWT: issue and validate (SignVerifyJwt.kt)
    for (alg in JWS_ALGS) {
        check("jwt/sign-verify/${alg.lowercase(Locale.ROOT)}") {
            val keys = signingKeyPair(alg)
            val sent = claims()
            val token = issueToken(sent, keys.signKey, alg)
            val verified = validateToken(token, keys.verifyKey, alg, ISSUER, AUDIENCE)
            expectEq(verified.alg, alg, "verified alg")
            for (name in listOf("iss", "aud", "sub", "exp")) {
                expectSame(member(verified.claims, name), member(sent, name), "claim $name")
            }
        }
    }

    // JWT: rejections (VerifyAllowList.kt)
    check("jwt/verify/rejects-expired") {
        val keys = signingKeyPair("ES256")
        val exp = nowSec() - 3600
        val token = issueToken(claims(exp), keys.signKey, "ES256")
        val options = JwtVerifyOptions(
            allowedAlgs = listOf("ES256"),
            issuers = listOf(ISSUER),
            audiences = listOf(AUDIENCE),
            now = exp + 1,
            leeway = 0u,
        )
        expectCode(jwtRejection(token, keys.verifyKey, options), "TokenExpired")
    }

    check("jwt/verify/rejects-wrong-audience") {
        val keys = signingKeyPair("ES256")
        val token = issueToken(claims(), keys.signKey, "ES256")
        val options = JwtVerifyOptions(
            allowedAlgs = listOf("ES256"),
            issuers = listOf(ISSUER),
            audiences = listOf("https://other-api.example"),
        )
        expectCode(jwtRejection(token, keys.verifyKey, options), "InvalidClaim")
    }

    check("jwt/verify/rejects-alg-not-allowed") {
        val keys = signingKeyPair("ES256")
        val token = issueToken(claims(), keys.signKey, "ES256")
        val options = JwtVerifyOptions(allowedAlgs = listOf("ES384"), issuers = listOf(ISSUER), audiences = listOf(AUDIENCE))
        expectCode(jwtRejection(token, keys.verifyKey, options), "AlgorithmNotAllowed")
    }

    check("jwt/verify-with-jwks/selects-by-kid") {
        val first = jwkGenerateForAlg("ES256")
        val second = jwkGenerateForAlg("ES256")
        val jwks = publicJwks(listOf("key-1" to first, "key-2" to second))
        val token = issueToken(claims(), withKid(second, "key-2"), "ES256")
        val verified = validateWithJwks(token, jwks, listOf("ES256"), ISSUER, AUDIENCE)
        expectEq(verified.kid, "key-2", "kid")
        expectEq(verified.keyIndex?.toInt(), 1, "keyIndex")
    }

    // JWE: encrypt and decrypt (EncryptDecrypt.kt)
    for (crv in listOf("P-256", "P-384", "P-521", "X25519")) {
        check("jwe/ecdh-es-a256kw/${crv.lowercase(Locale.ROOT)}") {
            val keys = recipientKeyPair(crv)
            val token = encryptTo(PAYLOAD, keys.publicKey)
            val decrypted = decrypt(token, keys.privateKey)
            expectBytes(decrypted.plaintext, PAYLOAD, "plaintext")
            expectEq(member(decrypted.header, "alg"), JWE_ALG, "header alg")
            expectEq(member(decrypted.header, "enc"), JWE_ENC, "header enc")
        }
    }

    check("jwe/decrypt/rejects-alg-not-allowed") {
        val keys = recipientKeyPair("P-256")
        val token = encryptTo(PAYLOAD, keys.publicKey)
        expectCode(rejectionCode { decrypt(token, keys.privateKey, listOf("ECDH-ES+A128KW"), listOf(JWE_ENC)) }, "AlgorithmNotAllowed")
    }

    check("jwe/decrypt/rejects-wrong-key") {
        val keys = recipientKeyPair("P-256")
        val other = recipientKeyPair("P-256")
        val token = encryptTo(PAYLOAD, keys.publicKey)
        expectCode(rejectionCode { decrypt(token, other.privateKey) }, "DecryptionFailed")
    }

    // Keys and JWK Sets (KeysJwks.kt)
    check("jwk/generate/ec-p-256") {
        val key = generateEcKey("P-256")
        expectEq(member(key, "kty"), "EC", "kty")
        expectEq(member(key, "crv"), "P-256", "crv")
        expect(member(key, "d") is String, "the private key has no d")
        val pub = publicKeyOf(key)
        expect(!JSONObject(pub).has("d"), "the public key still has d")
        expectSame(member(pub, "x"), member(key, "x"), "x")
        expectSame(member(pub, "y"), member(key, "y"), "y")
    }

    check("jwk/thumbprint/rfc7638") {
        expectEq(thumbprint(RFC7638_3_1_JWK), RFC7638_3_1_THUMBPRINT, "thumbprint")
    }

    check("jwk/pem/round-trip") {
        val key = generateEcKey("P-256")
        val result = pemRoundTrip(key)
        expect(result.pem.startsWith("-----BEGIN PRIVATE KEY-----\n"), "not a PKCS#8 PEM")
        expectSame(member(result.jwk, "d"), member(key, "d"), "d")
        expectSame(thumbprint(result.jwk), thumbprint(key), "thumbprint")
    }

    check("jwks/select/by-kid") {
        val jwks = publicJwks(listOf("key-1" to generateEcKey("P-256"), "key-2" to generateEcKey("P-256")))
        val selected = selectKey(jwks, JwkSelector(kid = "key-2"))
        expectEq(member(selected, "kid"), "key-2", "kid")
        val second = JSONObject(jwks).getJSONArray("keys").getJSONObject(1)
        expectSame(member(selected, "x"), second.opt("x"), "x")
        expectCode(rejectionCode { selectKey(jwks, JwkSelector(kid = "key-3")) }, "NoMatchingKey")
    }
}

// --- run --------------------------------------------------------------------------------------

/**
 * Why a check failed. A polyjose error is shown by its stable code only, and any other
 * exception by its class name only: their messages might quote a key or a token.
 */
fun describe(e: Throwable): String = when (e) {
    is CheckFailure -> e.message ?: "failed"
    is PolyjoseException -> "unexpected ${e.code()}"
    else -> "unexpected ${e.javaClass.simpleName}"
}

/**
 * Runs every check, passing each line to [emit]: the [info] lines first (each starting with
 * `# `), then one line per check, then the result line. Returns true when every check passed.
 */
fun runCatalog(info: List<String>, emit: (String) -> Unit): Boolean {
    info.forEach { emit("# $it") }
    var passed = 0
    for (c in CHECKS) {
        try {
            c.run()
            passed += 1
            emit("PASS ${c.id}")
        } catch (e: Throwable) {
            emit("FAIL ${c.id}: ${describe(e)}")
        }
    }
    val ran = CHECKS.size
    emit("POLYJOSE-VERIFY: $passed/$ran PASS")
    return passed == ran && ran > 0
}
