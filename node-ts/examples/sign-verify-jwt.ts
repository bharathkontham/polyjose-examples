// How do I issue a JWT and validate one?
//
// A JWT (RFC 7519) is a signed set of claims. Validation (RFC 7519 §7.2) checks the signature
// against an explicit allow-list of algorithms (RFC 8725 §3.1), then the claims:
//   exp  required by default; the token is refused once it has passed (RFC 7519 §4.1.4)
//   iss  must be one of `issuers`, when you give them (RFC 7519 §4.1.1, RFC 8725 §3.8)
//   aud  must contain one of `audiences` (RFC 7519 §4.1.3, RFC 8725 §3.9)
// The default clock skew is 60 seconds (`leeway`). `now` defaults to the system clock.
//
// The signing algorithms and keys are the JWS ones (sign-verify-jws.ts).
import { jwtSign, jwtVerify, jwtVerifyWithJwks } from "@polyjose/node";
import type { JsonObject, Jwk, JwkSet, JwtVerified, JwtVerifyOptions } from "@polyjose/node";

/**
 * What `validateToken` checks: one algorithm, one issuer and one audience, plus any further
 * `JwtVerifyOptions` (such as `now` and `leeway`, in seconds) except the three lists it sets.
 */
export interface ValidateOptions extends Omit<JwtVerifyOptions, "allowedAlgs" | "issuers" | "audiences"> {
  alg: string;
  issuer: string;
  audience: string;
}

/** What `validateWithJwks` checks: the accepted algorithms, one issuer and one audience. */
export interface JwksValidateOptions {
  allowedAlgs: readonly string[];
  issuer: string;
  audience: string;
}

/**
 * Issues a signed JWT (RFC 7519 §7.1) over `claims`, a plain object. The header gets
 * `typ: "JWT"` (RFC 7519 §5.1), and the key's `kid` member when it has one (RFC 7515 §4.1.4):
 * that `kid` tells the verifier which key of its JWK Set to use.
 */
export async function issueToken(claims: JsonObject, signKey: Jwk, alg: string): Promise<string> {
  return jwtSign(claims, signKey, { alg });
}

/**
 * Validates a JWT with one key (RFC 7519 §7.2). Accepts only `alg`, only the issuer `issuer`
 * and only tokens meant for `audience`. Resolves with `{ claims, header, alg }`.
 */
export async function validateToken(
  token: string,
  verifyKey: Jwk,
  { alg, issuer, audience, ...extra }: ValidateOptions,
): Promise<JwtVerified> {
  return jwtVerify(token, verifyKey, {
    ...extra, // first, so that it can never replace the three lists below
    allowedAlgs: [alg],
    issuers: [issuer],
    audiences: [audience],
  });
}

/**
 * Validates a JWT against a JWK Set (RFC 7517 §5), as a resource server does with its
 * identity provider's `jwks_uri`. The token's `kid` header (RFC 7515 §4.1.4) picks the key;
 * the result reports that `kid` and the key's position in the set (`keyIndex`).
 *
 * Choosing a key never authorizes an algorithm: `allowedAlgs` still decides (RFC 8725 §3.1).
 */
export async function validateWithJwks(
  token: string,
  jwks: JwkSet,
  { allowedAlgs, issuer, audience }: JwksValidateOptions,
): Promise<JwtVerified> {
  return jwtVerifyWithJwks(token, jwks, {
    allowedAlgs,
    issuers: [issuer],
    audiences: [audience],
  });
}
