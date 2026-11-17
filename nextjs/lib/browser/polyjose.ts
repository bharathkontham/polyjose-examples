"use client";

// Every polyjose operation the browser side of this app runs, on @polyjose/wasm. The checks,
// the crossings, the playground's tabs and the demo walk all call these functions and nothing
// else.
//
// - @polyjose/wasm fetches its WebAssembly module on the first call, checked with Subresource
//   Integrity, so nothing runs when this module is imported. It is only called from client
//   components, in effects and event handlers, never while the server renders the page.
// - Private keys are plain JWK objects in page memory (polyjose 0.4.0 has no browser key store
//   and no non-extractable WebCrypto keys), so any script on the page can read them. They are
//   never sent, shown or logged; only their public halves leave this module's callers.
// - Verify and decrypt take explicit allow-lists, never values read from the token
//   (RFC 8725 §3.1). `none` is never accepted (RFC 8725 §3.2).
import {
  PolyjoseError,
  base64urlEncode,
  decodeProtectedHeaderUnverified,
  jweDecryptCompact,
  jweEncryptCompact,
  jwkGenerateEc,
  jwkGenerateForAlg,
  jwkGenerateOct,
  jwkGenerateOkp,
  jwkThumbprint,
  jwkToPublic,
  jwksSelect,
  jwsSignCompact,
  jwsVerifyCompact,
  jwtSign,
  jwtVerify,
  jwtVerifyWithJwks,
  version,
  type EcCurve,
  type JsonObject,
  type JwkObject,
  type JwkSetObject,
} from "@polyjose/wasm";

import type { EcdhCurve, EncryptKind, KeyKind } from "../matrix";
import { CONTENT_ENC, KEY_MANAGEMENT_ALG } from "../shared";
import { RFC7515_A2_RSA_PRIVATE_JWK } from "./test-keys";

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
  return encryptJwe(plaintext, recipientPublicKey, KEY_MANAGEMENT_ALG, CONTENT_ENC);
}

/**
 * Decrypts a compact JWE (RFC 7516 §5.2) with the page's private key, accepting only
 * ECDH-ES+A256KW and A256GCM. Any failure is DecryptionFailed (RFC 7516 §11.5).
 */
export async function decrypt(token: string, key: KeyPair): Promise<string> {
  return (await decryptJwe(token, key.privateKey, [KEY_MANAGEMENT_ALG], [CONTENT_ENC])).plaintext;
}

/**
 * A failure action: changes one character in the middle of part `part` of a compact token
 * (`A`, or `B` when it is `A`; PLAYGROUND.md, "Failure actions"). Returns the token and the
 * index of the changed character in that part.
 */
export function tamper(token: string, part = 1): { token: string; index: number } {
  const parts = token.split(".");
  const text = parts[part] ?? "";
  const index = Math.floor(text.length / 2);
  parts[part] = text.slice(0, index) + (text[index] === "A" ? "B" : "A") + text.slice(index + 1);
  return { token: parts.join("."), index };
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

// ---------------------------------------------------------------------------------------------
// The playground: any row of the support matrix (lib/matrix.ts).

/**
 * A software key of the playground, in page memory. `privateKey` is never shown, sent or
 * logged. `publicKey` is null for a shared (oct) key, which is shown as `kty`, `alg`, `kid` and
 * its length only (PLAYGROUND.md, "Secrets").
 */
export interface SoftwareKey {
  /** The JWS `alg` or JWE key-management `alg` the key was made for. */
  readonly alg: string;
  readonly kty: string;
  readonly crv?: string;
  /** A `dir` key: the `enc` whose key size it has (RFC 7518 §4.5). */
  readonly enc?: string;
  /** A shared key: its length in bits. */
  readonly bits?: number;
  readonly kid: string;
  /** The RFC 7515 Appendix A.2 test key (PLAYGROUND.md `key.test-rsa`). */
  readonly testKey: boolean;
  readonly privateKey: JwkObject;
  readonly publicKey: JwkObject | null;
}

/** What key to make: the matrix row's kind and `alg`, and the curve or `enc` where it needs one. */
export interface KeyRequest {
  readonly kind: KeyKind | EncryptKind;
  readonly alg: string;
  readonly crv?: EcdhCurve | undefined;
  readonly enc?: string | undefined;
}

/** The PBES2 password's length in bytes: random bytes, not something a person typed. */
const PASSWORD_BYTES = 16;

let sharedKeys = 0;

/** An asymmetric key with `alg`, `use` and its RFC 7638 thumbprint as `kid` (RFC 7517 §4.2, §4.4, §4.5). */
async function asymmetric(jwk: Readonly<JwkObject>, alg: string | undefined, use: "sig" | "enc", testKey: boolean): Promise<SoftwareKey> {
  const labelled: JwkObject = alg === undefined ? { ...jwk } : { ...jwk, alg, use };
  const publicKey = await jwkToPublic(labelled);
  const kid = await thumbprint(publicKey);
  const privateKey: JwkObject = { ...labelled, kid };
  return {
    alg: alg ?? jwk.kty,
    kty: jwk.kty,
    ...(typeof jwk.crv === "string" ? { crv: jwk.crv } : {}),
    kid,
    testKey,
    privateKey,
    publicKey: { ...publicKey, kid },
  };
}

/**
 * A shared key, labelled with a page-local `kid`. Its thumbprint isn't used as the `kid`: that
 * would publish a hash of the secret.
 */
function shared(jwk: JwkObject, alg: string, enc?: string): SoftwareKey {
  sharedKeys += 1;
  const kid = `secret-${sharedKeys}`;
  const k = typeof jwk.k === "string" ? jwk.k : "";
  return {
    alg,
    kty: jwk.kty,
    ...(enc === undefined ? {} : { enc }),
    bits: Math.floor((k.length * 3) / 4) * 8, // base64url without padding (RFC 7515 §2)
    kid,
    testKey: false,
    privateKey: { ...jwk, alg: enc ?? alg, kid },
    publicKey: null,
  };
}

/**
 * A key for one matrix row, from the browser's CSPRNG (`crypto.getRandomValues`):
 * - a JWS key: `jwkGenerateForAlg` (RFC 7518 §6, RFC 8037 §2, RFC 8812 §3.1);
 * - an ECDH-ES key on a curve (RFC 7518 §4.6, §6.2; RFC 8037 §3.2);
 * - an AES key-wrap or AES-GCM key-wrap key for its `alg` (RFC 7518 §4.4, §4.7), a `dir` key of
 *   the `enc`'s size (RFC 7518 §4.5), or a PBES2 password of random bytes (RFC 7518 §4.8);
 * - RSA: the RFC 7515 A.2 test key, because polyjose 0.4.0 can't generate RSA keys.
 */
export async function newSoftwareKey(request: KeyRequest): Promise<SoftwareKey> {
  switch (request.kind) {
    case "RSA":
    case "rsa":
      // The one RSA key serves every RSA row, so its JWK isn't bound to one `alg`.
      return { ...(await asymmetric(RFC7515_A2_RSA_PRIVATE_JWK, undefined, "sig", true)), alg: request.alg };
    case "EC":
    case "OKP":
      return asymmetric(await jwkGenerateForAlg(request.alg), request.alg, "sig", false);
    case "ecdh": {
      const crv = request.crv ?? "P-256";
      const jwk = crv === "X25519" ? await jwkGenerateOkp("X25519") : await jwkGenerateEc(crv);
      return asymmetric(jwk, request.alg, "enc", false);
    }
    case "oct":
      return shared(await jwkGenerateForAlg(request.alg), request.alg);
    case "dir": {
      const enc = request.enc ?? CONTENT_ENC;
      return shared(await jwkGenerateForAlg(enc), request.alg, enc);
    }
    case "pbes2":
      return shared(await jwkGenerateOct(PASSWORD_BYTES), request.alg);
  }
}

/** The key that verifies or encrypts to `key`: its public JWK, or the shared secret itself. */
export function counterpart(key: SoftwareKey): JwkObject {
  return key.publicKey ?? key.privateKey;
}

/** Signs `payload` (text) as a compact JWS (RFC 7515 §7.1) with `alg` and the key's `kid` (RFC 7515 §4.1.4). */
export function signJws(payload: string, key: SoftwareKey, alg: string): Promise<string> {
  return jwsSignCompact(utf8.encode(payload), key.privateKey, { protectedHeader: { alg, kid: key.kid } });
}

/** Signs a JWT (RFC 7519 §7.1). polyjose puts the key's `kid` in the header. */
export function signJwt(claims: JsonObject, key: SoftwareKey, alg: string): Promise<string> {
  return jwtSign(claims, key.privateKey, { alg });
}

/** A JWT's validation rules. `leeway` absent is polyjose's default (60 s). */
export interface JwtKeyPolicy extends JwtPolicy {
  readonly leeway?: number | undefined;
}

/**
 * Validates a JWT with one key (RFC 7519 §7.2): `allowedAlgs` decides the algorithm, and `iss`,
 * `aud` and `exp` must hold (RFC 7519 §4.1.1, §4.1.3, §4.1.4; RFC 8725 §3.1, §3.8, §3.9).
 */
export async function verifyJwt(token: string, key: JwkObject, policy: JwtKeyPolicy): Promise<JwtValidated> {
  const validated = await jwtVerify(token, key, {
    allowedAlgs: policy.allowedAlgs,
    issuers: [policy.issuer],
    audiences: [policy.audience],
    leeway: policy.leeway,
  });
  return { claims: validated.claims, alg: validated.alg, kid: validated.kid ?? (typeof validated.header.kid === "string" ? validated.header.kid : undefined) };
}

/**
 * Encrypts `plaintext` (text) to `recipient` as a compact JWE (RFC 7516 §5.1, §7.1). With
 * `withKid` (the default), the recipient's `kid` goes into the protected header, so a recipient
 * with several keys can pick one (RFC 7516 §4.1.6).
 *
 * polyjose 0.4.0 refuses a decryption key whose `kid` differs from the header's with
 * KeyAlgorithmMismatch, before it decrypts. The playground's tabs encrypt to one known key and
 * leave `kid` out, so a wrong key fails in decryption itself, with DecryptionFailed.
 */
export function encryptJwe(plaintext: string, recipient: JwkObject, alg: string, enc: string, withKid = true): Promise<string> {
  const kid = recipient.kid;
  return jweEncryptCompact(utf8.encode(plaintext), {
    enc,
    protectedHeader: withKid && typeof kid === "string" ? { kid } : undefined,
    recipients: [{ alg, key: recipient }],
  });
}

/** A decrypted JWE: the plaintext as text and its protected header. */
export interface Decrypted {
  readonly plaintext: string;
  readonly header: JsonObject;
}

/**
 * Decrypts a compact JWE (RFC 7516 §5.2) accepting only `allowedAlgs` and `allowedEnc`
 * (RFC 8725 §3.1). Every decryption failure is DecryptionFailed (RFC 7516 §11.5).
 */
export async function decryptJwe(token: string, key: JwkObject, allowedAlgs: readonly string[], allowedEnc: readonly string[]): Promise<Decrypted> {
  const decrypted = await jweDecryptCompact(token, key, { allowedAlgs, allowedEnc });
  return { plaintext: fromUtf8.decode(decrypted.plaintext), header: decrypted.protectedHeader ?? decrypted.header };
}

/**
 * A token's protected header, read without verifying anything (RFC 7515 §7.1, RFC 7516 §7.1),
 * for the result card only. Nothing here decides anything with it.
 */
export function readProtectedHeader(token: string): Promise<JsonObject> {
  return decodeProtectedHeaderUnverified(token);
}
