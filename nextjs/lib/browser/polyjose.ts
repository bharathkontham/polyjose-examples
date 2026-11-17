"use client";

// Every polyjose operation the browser side of this app runs, on @polyjose/wasm. The checks,
// the crossing buttons and the playground all call these functions and nothing else.
//
// - @polyjose/wasm fetches its WebAssembly module on the first call, checked with Subresource
//   Integrity, so nothing runs when this module is imported. It is only called from client
//   components, in effects and event handlers, never while the server renders the page.
// - Private keys are plain JWK objects in page memory (polyjose 0.4.0 has no browser key store
//   and no non-extractable WebCrypto keys). They are never sent, shown or logged; only their
//   public halves leave this module's callers.
// - Verify and decrypt take explicit allow-lists, never values read from the token
//   (RFC 8725 §3.1). `none` is never accepted (RFC 8725 §3.2).
import {
  PolyjoseError,
  base64urlEncode,
  jweDecryptCompact,
  jweEncryptCompact,
  jwkGenerateEc,
  jwkThumbprint,
  jwkToPublic,
  jwksSelect,
  jwsSignCompact,
  jwsVerifyCompact,
  jwtVerifyWithJwks,
  version,
  type EcCurve,
  type JsonObject,
  type JwkObject,
  type JwkSetObject,
} from "@polyjose/wasm";

import { CONTENT_ENC, KEY_MANAGEMENT_ALG } from "../shared";

export type { JsonObject, JwkObject, JwkSetObject };

/** The kinds of key this app makes: two signing algorithms and one key agreement. */
export type KeyAlg = "ES256" | "ES384" | typeof KEY_MANAGEMENT_ALG;

const CURVE: Record<KeyAlg, EcCurve> = { ES256: "P-256", ES384: "P-384", [KEY_MANAGEMENT_ALG]: "P-256" };

/** A key pair in page memory. `privateKey` stays in the page; `publicKey` may be sent. */
export interface KeyPair {
  readonly alg: KeyAlg;
  readonly kid: string;
  readonly privateKey: JwkObject;
  readonly publicKey: JwkObject;
}

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

/** The polyjose version the WebAssembly module reports. */
export function polyjoseVersion(): Promise<string> {
  return version();
}

/** The RFC 7638 JWK Thumbprint (SHA-256) of a key's public members. */
export function thumbprint(jwk: JwkObject): Promise<string> {
  return jwkThumbprint(jwk, "sha-256");
}

/** The public half of a private JWK (RFC 7517 §4, RFC 7518 §6.2.1): `d` is dropped. */
export function publicJwk(jwk: JwkObject): Promise<JwkObject> {
  return jwkToPublic(jwk);
}

/**
 * A new EC key for `alg` from the browser's CSPRNG (`crypto.getRandomValues`), labelled with
 * `alg`, `use` (RFC 7517 §4.4, §4.2) and its thumbprint as `kid` (RFC 7517 §4.5, RFC 7638).
 */
export async function generateKey(alg: KeyAlg): Promise<KeyPair> {
  const generated = await jwkGenerateEc(CURVE[alg]);
  const kid = await thumbprint(generated);
  const privateKey: JwkObject = { ...generated, alg, use: alg === KEY_MANAGEMENT_ALG ? "enc" : "sig", kid };
  return { alg, kid, privateKey, publicKey: await publicJwk(privateKey) };
}

/** Signs `payload` (text) as a compact JWS (RFC 7515 §7.1) with the key's `alg` and `kid`. */
export function sign(payload: string, key: KeyPair): Promise<string> {
  return jwsSignCompact(utf8.encode(payload), key.privateKey, { protectedHeader: { alg: key.alg, kid: key.kid } });
}

/** A verified JWS: the algorithm that verified and the payload as text. */
export interface Verified {
  readonly alg: string;
  readonly payload: string;
}

/** Verifies a compact JWS (RFC 7515 §5.2) with `publicKey`, accepting only `allowedAlgs`. */
export async function verify(token: string, publicKey: JwkObject, allowedAlgs: readonly string[]): Promise<Verified> {
  const verified = await jwsVerifyCompact(token, publicKey, { allowedAlgs });
  return { alg: verified.alg, payload: fromUtf8.decode(verified.payload) };
}

/** Who the JWT must come from and be meant for. */
export interface JwtPolicy {
  readonly allowedAlgs: readonly string[];
  readonly issuer: string;
  readonly audience: string;
}

/** A validated JWT: its claims, its algorithm and the `kid` of the key that verified it. */
export interface JwtValidated {
  readonly claims: JsonObject;
  readonly alg: string;
  readonly kid: string | undefined;
}

/**
 * Validates a JWT against a JWK Set (RFC 7519 §7.2, RFC 7517 §5): the token's `kid` picks the
 * key, `allowedAlgs` decides the algorithm, and `iss`, `aud` and `exp` must hold
 * (RFC 7519 §4.1.1, §4.1.3, §4.1.4; RFC 8725 §3.8, §3.9).
 */
export async function verifyJwtWithJwks(token: string, jwks: JwkSetObject, policy: JwtPolicy): Promise<JwtValidated> {
  const validated = await jwtVerifyWithJwks(token, jwks, {
    allowedAlgs: policy.allowedAlgs,
    issuers: [policy.issuer],
    audiences: [policy.audience],
  });
  return { claims: validated.claims, alg: validated.alg, kid: validated.kid };
}

/** The key of a JWK Set whose `alg` is `alg` (RFC 7517 §4.4); NoMatchingKey when none is. */
export function selectKey(jwks: JwkSetObject, alg: string): Promise<JwkObject> {
  return jwksSelect(jwks, { alg });
}

/**
 * Encrypts `plaintext` (text) to `recipientPublicKey` as a compact JWE (RFC 7516 §7.1) with
 * ECDH-ES+A256KW (RFC 7518 §4.6) and A256GCM (RFC 7518 §5.3). The recipient's `kid` goes into
 * the protected header (RFC 7516 §4.1.6).
 */
export function encrypt(plaintext: string, recipientPublicKey: JwkObject): Promise<string> {
  const kid = recipientPublicKey.kid;
  return jweEncryptCompact(utf8.encode(plaintext), {
    enc: CONTENT_ENC,
    protectedHeader: typeof kid === "string" ? { kid } : undefined,
    recipients: [{ alg: KEY_MANAGEMENT_ALG, key: recipientPublicKey }],
  });
}

/**
 * Decrypts a compact JWE (RFC 7516 §5.2) with the page's private key, accepting only
 * ECDH-ES+A256KW and A256GCM. Any failure is DecryptionFailed (RFC 7516 §11.5).
 */
export async function decrypt(token: string, key: KeyPair): Promise<string> {
  const decrypted = await jweDecryptCompact(token, key.privateKey, {
    allowedAlgs: [KEY_MANAGEMENT_ALG],
    allowedEnc: [CONTENT_ENC],
  });
  return fromUtf8.decode(decrypted.plaintext);
}

/** A failure action: changes one character in the middle of part `index` of a compact token. */
export function tamper(token: string, index = 1): string {
  const parts = token.split(".");
  const part = parts[index] ?? "";
  const i = Math.floor(part.length / 2);
  parts[index] = part.slice(0, i) + (part[i] === "A" ? "B" : "A") + part.slice(i + 1);
  return parts.join(".");
}

/**
 * A failure action: an Unsecured JWS (RFC 7515 Appendix A.5), header `{"alg":"none"}` and an
 * empty signature. Every verifier in this app must refuse it (RFC 8725 §3.2).
 */
export async function unsecuredJws(payload: string): Promise<string> {
  const header = await base64urlEncode(utf8.encode(JSON.stringify({ alg: "none" })));
  return `${header}.${await base64urlEncode(utf8.encode(payload))}.`;
}

/**
 * What a failure is safe to show: the polyjose code (`PolyjoseError.code`, stable), else the
 * error's type name. Never the message.
 */
export function errorCode(err: unknown): string {
  if (err instanceof PolyjoseError) return err.code;
  return err instanceof Error ? err.name : typeof err;
}
