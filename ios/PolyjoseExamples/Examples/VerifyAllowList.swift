// How do I make sure I reject the tokens I must not accept?
//
// Every verify and decrypt call in polyjose takes an explicit allow-list (`allowedAlgs`, and
// `allowedEnc` for JWE). Write it down in your code: never build it from the token's header,
// which whoever made the token controls (RFC 8725 §3.1).
//
// A refused token throws a `PolyjoseError`. Match on `error.code()`, which is stable, never on
// its description, which may be reworded. Neither ever holds key material or token contents, so
// both are safe to log. The codes these examples show:
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
//                         (RFC 7516 §11.5; see EncryptDecrypt.swift)
//
// `errorCodes()` lists every code.
import Foundation
import Polyjose

enum VerifyAllowList {
    /// Runs `operation` and returns the code polyjose refused it with, or `nil` when it
    /// succeeded. A `PolyjoseError` is an answer ("this token is expired"); anything else is a
    /// bug, so it is thrown again.
    static func rejectionCode(_ operation: () throws -> Void) throws -> String? {
        do {
            try operation()
            return nil
        } catch let error as PolyjoseError {
            return error.code()
        }
    }

    /// Verifies a compact JWS with the caller's list; `nil` when it verified, else the code.
    static func jwsRejection(_ token: String, verifyKey: String, allowedAlgs: [String]) throws -> String? {
        try rejectionCode {
            _ = try jwsVerifyCompact(token: token, key: verifyKey, options: JwsVerifyOptions(allowedAlgs: allowedAlgs))
        }
    }

    /// Validates a JWT with the caller's `JwtVerifyOptions`; `nil` when valid, else the code.
    static func jwtRejection(_ token: String, verifyKey: String, options: JwtVerifyOptions) throws -> String? {
        try rejectionCode {
            _ = try jwtVerify(token: token, key: verifyKey, options: options)
        }
    }
}
