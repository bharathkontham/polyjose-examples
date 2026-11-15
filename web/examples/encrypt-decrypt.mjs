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
import { jweDecryptCompact, jweEncryptCompact, jwkGenerateEc, jwkGenerateOkp, jwkToPublic } from "@polyjose/wasm";

export const ALG = "ECDH-ES+A256KW";
export const ENC = "A256GCM";

/**
 * The recipient's key pair: an EC key on P-256, P-384 or P-521, or an X25519 OKP key. Keep
 * `privateKey`; give `publicKey` to whoever encrypts to you.
 */
export async function recipientKeyPair(crv) {
  const privateKey = crv === "X25519" ? await jwkGenerateOkp(crv) : await jwkGenerateEc(crv);
  return { privateKey, publicKey: await jwkToPublic(privateKey) };
}

/**
 * Encrypts `plaintext` (bytes) to `recipientPublicKey` in the JWE Compact Serialization
 * (RFC 7516 §3.1, §7.1): `header.encryptedKey.iv.ciphertext.tag`.
 */
export async function encryptTo(plaintext, recipientPublicKey) {
  return jweEncryptCompact(plaintext, { enc: ENC, recipients: [{ alg: ALG, key: recipientPublicKey }] });
}

/**
 * Decrypts a compact JWE (RFC 7516 §5.2), accepting only `allowedAlgs` and `allowedEnc`
 * (default: the two this file encrypts with). Resolves with `{ plaintext, header, ... }`; the
 * header says which `alg` and `enc` were used.
 */
export async function decrypt(token, privateKey, allowedAlgs = [ALG], allowedEnc = [ENC]) {
  return jweDecryptCompact(token, privateKey, { allowedAlgs, allowedEnc });
}
