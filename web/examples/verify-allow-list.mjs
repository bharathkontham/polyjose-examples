// How do I make sure I reject the tokens I must not accept?
//
// Every verify and decrypt call in polyjose takes an explicit allow-list (`allowedAlgs`, and
// `allowedEnc` for JWE). Write it down in your code: never build it from the token's header,
// which whoever made the token controls (RFC 8725 §3.1).
//
// A refused token rejects the Promise with a `PolyjoseError`. Match on `err.code`, which is
// stable, never on `err.message`, which may be reworded. Neither ever holds key material or
// token contents, so both are safe to log. The codes these examples show:
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
//                         (RFC 7516 §11.5; see encrypt-decrypt.mjs)
//
// A bad argument (a number where a string belongs) is a plain `TypeError` instead: a bug in
// the caller, not a refused token.
import { PolyjoseError, jwsVerifyCompact, jwtVerify } from "@polyjose/wasm";

/**
 * Runs `operation` and returns the code polyjose refused it with, or `null` when it
 * succeeded. A `PolyjoseError` is an answer ("this token is expired"); anything else is a bug,
 * so it is thrown again.
 */
export async function rejectionCode(operation) {
  try {
    await operation();
    return null;
  } catch (err) {
    if (err instanceof PolyjoseError) return err.code;
    throw err;
  }
}

/** Verifies a compact JWS with the caller's list; `null` when it verified, else the code. */
export async function jwsRejection(token, verifyKey, allowedAlgs) {
  return rejectionCode(() => jwsVerifyCompact(token, verifyKey, { allowedAlgs }));
}

/** Validates a JWT with the caller's `JwtVerifyOptions`; `null` when valid, else the code. */
export async function jwtRejection(token, verifyKey, options) {
  return rejectionCode(() => jwtVerify(token, verifyKey, options));
}

