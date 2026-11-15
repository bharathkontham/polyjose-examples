// How do I create keys, export them, and pick one from a JWK Set?
//
// Keys are JWKs (RFC 7517): pass one as a plain object or as its JSON text; results come back
// as objects. A private JWK holds secret members (`d` for EC, OKP and RSA, `k` for oct):
// never log it, and call `jwkToPublic` before you publish or send one.
import { jwkFromPem, jwkGenerateEc, jwkThumbprint, jwkToPem, jwkToPublic, jwksSelect } from "@polyjose/wasm";

/** A random EC private key (RFC 7518 §6.2) on P-256, P-384 or P-521, from the OS CSPRNG. */
export async function generateEcKey(crv = "P-256") {
  return jwkGenerateEc(crv);
}

/** The public half of a key (RFC 7517 §4, RFC 7518 §6.2.1): the private members are removed. */
export async function publicKeyOf(privateJwk) {
  return jwkToPublic(privateJwk);
}

/**
 * The JWK Thumbprint (RFC 7638 §3), SHA-256, base64url: a stable identifier of a key's public
 * members, and a good `kid`. Do not publish the thumbprint of a secret `oct` key: it is an
 * unsalted hash of the secret (RFC 7638 §7).
 */
export async function thumbprint(jwk) {
  return jwkThumbprint(jwk);
}

/**
 * Exports a private key as PKCS#8 PEM (RFC 5958, RFC 7468 §10, "PRIVATE KEY") and imports it
 * back as a JWK. `jwkToPem` also takes "spki" for a public key (RFC 7468 §13).
 */
export async function pemRoundTrip(privateJwk) {
  const pem = await jwkToPem(privateJwk, "pkcs8");
  return { pem, jwk: await jwkFromPem(pem) };
}

/**
 * A public JWK Set (RFC 7517 §5), as a `jwks_uri` endpoint serves it: each key's public half,
 * with its `kid` (RFC 7517 §4.5). `entries` is `[{ kid, key }, ...]`.
 */
export async function publicJwks(entries) {
  const keys = [];
  for (const { kid, key } of entries) keys.push({ ...(await jwkToPublic(key)), kid });
  return { keys };
}

/**
 * The one key of a JWK Set that `selector` picks, by `kid`, `alg` and `keyUse` (each
 * optional; RFC 7517 §4.2, §4.4, §4.5). No match rejects with `NoMatchingKey`, more than one
 * with `MultipleMatchingKeys` (a set's order has no meaning, RFC 7517 §5).
 */
export async function selectKey(jwks, selector) {
  return jwksSelect(jwks, selector);
}
