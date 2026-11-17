// How do I encrypt data for someone, and decrypt what was encrypted for me (JWE)?
//
// A JWE (RFC 7516) names two algorithms:
//   alg  how the content key reaches the recipient. Here ECDH-ES+A256KW: an ephemeral key
//        agreement with the recipient's public key, then AES Key Wrap (RFC 7518 §4.6)
//   enc  how the content is encrypted with that key. Here A256GCM (RFC 7518 §5.3)
// The sender needs only the recipient's public key. The recipient's curve can be P-256,
// P-384, P-521 (`kty: EC`, RFC 7518 §6.2) or X25519 (`kty: OKP`, RFC 8037 §3.2).
//
// Decryption takes an allow-list for each, `allowedAlgs` and `allowedEnc` (RFC 8725 §3.1).
// A wrong key, a changed token and a bad tag all fail with one code, `DecryptionFailed`, so
// the error tells an attacker nothing about the cause (RFC 7516 §11.5).
import { jweDecryptCompact, jweEncryptCompact, jwkGenerateEc, jwkGenerateOkp, jwkToPublic } from "@polyjose/node";
import type { JweDecrypted, Jwk, JwkObject } from "@polyjose/node";

export const ALG = "ECDH-ES+A256KW";
export const ENC = "A256GCM";

/** The recipient curves of this example (RFC 7518 §6.2.1.1, RFC 8037 §2). */
export type RecipientCurve = "P-256" | "P-384" | "P-521" | "X25519";

/** Keep `privateKey` (never log it); give `publicKey` to whoever encrypts to you. */
export interface RecipientKeyPair {
  privateKey: JwkObject;
  publicKey: JwkObject;
}

/** The recipient's key pair: an EC key on P-256, P-384 or P-521, or an X25519 OKP key. */
export async function recipientKeyPair(crv: RecipientCurve): Promise<RecipientKeyPair> {
  const privateKey = crv === "X25519" ? await jwkGenerateOkp(crv) : await jwkGenerateEc(crv);
  return { privateKey, publicKey: await jwkToPublic(privateKey) };
}

/**
 * Encrypts `plaintext` (bytes) to `recipientPublicKey` in the JWE Compact Serialization
 * (RFC 7516 §3.1, §7.1): `header.encryptedKey.iv.ciphertext.tag`.
 */
export async function encryptTo(plaintext: Uint8Array, recipientPublicKey: Jwk): Promise<string> {
  return jweEncryptCompact(plaintext, { enc: ENC, recipients: [{ alg: ALG, key: recipientPublicKey }] });
}

/**
 * Decrypts a compact JWE (RFC 7516 §5.2), accepting only `allowedAlgs` and `allowedEnc`
 * (default: the two this file encrypts with). Resolves with `{ plaintext, header, ... }`; the
 * header says which `alg` and `enc` were used. The allow-lists are always your own fixed lists,
 * never values read from the token's header (RFC 8725 §3.1).
 */
export async function decrypt(
  token: string,
  privateKey: Jwk,
  allowedAlgs: readonly string[] = [ALG],
  allowedEnc: readonly string[] = [ENC],
): Promise<JweDecrypted> {
  return jweDecryptCompact(token, privateKey, { allowedAlgs, allowedEnc });
}
