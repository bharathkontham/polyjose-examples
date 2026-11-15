// How do I sign bytes and verify the signature (JWS)?
//
// A JWS (RFC 7515) signs any bytes. For claims about a user or a client, with an expiry, an
// issuer and an audience, use a JWT instead (sign-verify-jwt.mjs).
//
// Verification always takes an explicit allow-list, `allowedAlgs`. Never build it from the
// token: whoever made the token chose its header (RFC 8725 §3.1). `alg: none` is never
// accepted, whatever the list says (RFC 8725 §3.2). See verify-allow-list.mjs for the rejections.
//
// Algorithms (RFC 7518 §3, RFC 8037 §3.1) and the keys they take:
//   HS256            a shared secret, `kty: oct`; the same key signs and verifies
//   RS256, PS256     an RSA key pair, 2048 bits or more
//   ES256/384/512    an EC key pair on P-256, P-384 or P-521
//   EdDSA            an Ed25519 key pair (`kty: OKP`)
import {
  jwkGenerateForAlg,
  jwkToPublic,
  jwsSignCompact,
  jwsSignGeneral,
  jwsVerifyCompact,
  jwsVerifyJson,
} from "@polyjose/wasm";
import { RFC7515_A2_RSA_PRIVATE_JWK } from "./test-keys.mjs";

/**
 * A key pair for a JWS algorithm: `signKey` signs, `verifyKey` verifies (RFC 7518 §3).
 * - HS256: one random secret for both (RFC 7518 §3.2: at least as long as the hash).
 * - RS256, PS256: polyjose 0.2.0 does not generate RSA keys, so this uses the RFC 7515 A.2
 *   test key. In your app, load your own key, for example with `jwkFromPem`.
 * - ES256/384/512, EdDSA: `jwkGenerateForAlg` makes a key on the right curve, with `alg` set.
 */
export async function signingKeyPair(alg) {
  if (alg.startsWith("HS")) {
    const secret = await jwkGenerateForAlg(alg);
    return { signKey: secret, verifyKey: secret };
  }
  const signKey = /^(RS|PS)/.test(alg) ? RFC7515_A2_RSA_PRIVATE_JWK : await jwkGenerateForAlg(alg);
  return { signKey, verifyKey: await jwkToPublic(signKey) };
}

/**
 * Signs `payload` (bytes) in the JWS Compact Serialization, `header.payload.signature`
 * (RFC 7515 §3.1, §7.1). The protected header carries `alg` (RFC 7515 §4.1.1).
 */
export async function signCompact(payload, signKey, alg) {
  return jwsSignCompact(payload, signKey, { protectedHeader: { alg } });
}

/**
 * Verifies a compact JWS (RFC 7515 §5.2), accepting only `alg`. Resolves with
 * `{ alg, payload, protectedHeader }`. Rejects with a `PolyjoseError`: `AlgorithmNotAllowed`,
 * `KeyAlgorithmMismatch`, `InvalidSignature`, ...
 */
export async function verifyCompact(token, verifyKey, alg) {
  return jwsVerifyCompact(token, verifyKey, { allowedAlgs: [alg] });
}

/**
 * The general JWS JSON Serialization (RFC 7515 §7.2.1): several signatures over one payload,
 * for example an old and a new key during a key rollover. Returns the JSON text.
 *
 * `signers` is `[{ signKey, alg }, ...]`.
 */
export async function signGeneral(payload, signers) {
  return jwsSignGeneral(
    payload,
    signers.map(({ signKey, alg }) => ({ key: signKey, protectedHeader: { alg } })),
  );
}

/**
 * Verifies a JWS JSON Serialization (RFC 7515 §7.2, §5.2) with one key, accepting only `alg`.
 * `signatureIndex` in the result says which signature verified.
 */
export async function verifyJson(jws, verifyKey, alg) {
  return jwsVerifyJson(jws, verifyKey, { allowedAlgs: [alg] });
}
