// How do I issue a JWT and validate one?
//
// A JWT (RFC 7519) is a signed set of claims. Validation (RFC 7519 §7.2) checks the signature
// against an explicit allow-list of algorithms (RFC 8725 §3.1), then the claims:
//   exp  required by default; the token is refused once it has passed (RFC 7519 §4.1.4)
//   iss  must be one of `issuers`, when you give them (RFC 7519 §4.1.1, RFC 8725 §3.8)
//   aud  must contain one of `audiences` (RFC 7519 §4.1.3, RFC 8725 §3.9)
// The default clock skew is 60 seconds (`leeway`). `now` defaults to the system clock.
//
// Claims and keys are JSON text. The signing algorithms and keys are the JWS ones
// (SignVerifyJws.kt).
package dev.polyjose.examples

import dev.polyjose.JwtSignOptions
import dev.polyjose.JwtVerified
import dev.polyjose.JwtVerifyOptions
import dev.polyjose.jwtSign
import dev.polyjose.jwtVerify
import dev.polyjose.jwtVerifyWithJwks

/**
 * Issues a signed JWT (RFC 7519 §7.1) over [claimsJson], a JSON object. The header gets
 * `typ: "JWT"` (RFC 7519 §5.1), and the key's `kid` member when it has one (RFC 7515 §4.1.4):
 * that `kid` tells the verifier which key of its JWK Set to use.
 */
fun issueToken(claimsJson: String, signKey: String, alg: String): String =
    jwtSign(claimsJson, signKey, JwtSignOptions(alg = alg))

/**
 * Validates a JWT with one key (RFC 7519 §7.2). Accepts only [alg], only the issuer [issuer]
 * and only tokens meant for [audience]. Returns `claims` and `header` (JSON text) and `alg`.
 */
fun validateToken(token: String, verifyKey: String, alg: String, issuer: String, audience: String): JwtVerified =
    jwtVerify(
        token,
        verifyKey,
        JwtVerifyOptions(allowedAlgs = listOf(alg), issuers = listOf(issuer), audiences = listOf(audience)),
    )

/**
 * Validates a JWT against a JWK Set (RFC 7517 §5), as a resource server does with its
 * identity provider's `jwks_uri`. The token's `kid` header (RFC 7515 §4.1.4) picks the key;
 * the result reports that `kid` and the key's position in the set (`keyIndex`).
 *
 * Choosing a key never authorizes an algorithm: [allowedAlgs] still decides (RFC 8725 §3.1).
 */
fun validateWithJwks(token: String, jwks: String, allowedAlgs: List<String>, issuer: String, audience: String): JwtVerified =
    jwtVerifyWithJwks(
        token,
        jwks,
        JwtVerifyOptions(allowedAlgs = allowedAlgs, issuers = listOf(issuer), audiences = listOf(audience)),
    )
