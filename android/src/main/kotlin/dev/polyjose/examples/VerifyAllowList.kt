// How do I make sure I reject the tokens I must not accept?
//
// Every verify and decrypt call in polyjose takes an explicit allow-list (`allowedAlgs`, and
// `allowedEnc` for JWE). Write it down in your code: never build it from the token's header,
// which whoever made the token controls (RFC 8725 §3.1).
//
// A refused token throws a `PolyjoseException`. Match on `code()`, which is stable, never on the
// message, which may be reworded. Neither ever holds key material or token contents, so both
// are safe to log. The codes these examples show:
//
//   AlgorithmNotAllowed   the header's `alg` is not in your list, or is `none`
//                         (RFC 8725 §3.1, §3.2; RFC 7515 §5.2)
//   InvalidSignature      the signature does not match: changed content or another key
//                         (RFC 7515 §5.2 step 8)
//   KeyAlgorithmMismatch  the key is of the wrong family for `alg`, for example an EC key for
//                         HS256 (RFC 8725 §3.1)
//   TokenExpired          the JWT's `exp` has passed (RFC 7519 §4.1.4)
//   InvalidClaim          a claim is wrong or missing, for example `aud` (RFC 7519 §4.1.3)
//   DecryptionFailed      a JWE does not decrypt with this key, whatever the cause
//                         (RFC 7516 §11.5; see EncryptDecrypt.kt)
//
// A typical caller maps a few codes to its own outcomes:
//
//   when (rejectionCode { validateToken(token, key, "ES256", issuer, audience) }) {
//       null -> accept()
//       "TokenExpired" -> askToSignInAgain()
//       else -> reject()
//   }
package dev.polyjose.examples

import dev.polyjose.JwsVerifyOptions
import dev.polyjose.JwtVerifyOptions
import dev.polyjose.PolyjoseException
import dev.polyjose.jwsVerifyCompact
import dev.polyjose.jwtVerify

/**
 * Runs [operation] and returns the code polyjose refused it with, or `null` when it succeeded.
 * A `PolyjoseException` is an answer ("this token is expired"); anything else is a bug, so it
 * propagates.
 */
inline fun rejectionCode(operation: () -> Unit): String? =
    try {
        operation()
        null
    } catch (e: PolyjoseException) {
        e.code()
    }

/** Verifies a compact JWS with the caller's list; `null` when it verified, else the code. */
fun jwsRejection(token: String, verifyKey: String, allowedAlgs: List<String>): String? =
    rejectionCode { jwsVerifyCompact(token, verifyKey, JwsVerifyOptions(allowedAlgs = allowedAlgs)) }

/** Validates a JWT with the caller's [options]; `null` when valid, else the code. */
fun jwtRejection(token: String, verifyKey: String, options: JwtVerifyOptions): String? =
    rejectionCode { jwtVerify(token, verifyKey, options) }
