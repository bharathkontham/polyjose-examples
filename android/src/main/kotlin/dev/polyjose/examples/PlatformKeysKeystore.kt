// How do I keep a private key in the Android Keystore (the TEE) and sign or decrypt with it?
//
// `AndroidKeystoreKey` creates the key inside the Android Keystore. The private key never leaves
// it: polyjose asks the Keystore for one signature, one ECDH shared secret or one RSA-OAEP-256
// decryption at a time, and does every JOSE step itself (headers, allow-lists, the key
// derivation, the content encryption). This file uses `StrongBox.Off`: the key lives in the
// device's trusted execution environment (TEE), isolated from Android. On an emulator the keys
// are software, whatever it reports. For StrongBox, see PlatformKeysStrongBox.kt.
//
// What the Keystore serves, and from which Android API level (the app's minSdk is 23):
//   ES256, ES384, ES512                        23
//   RS256 … RS512, PS256 … PS512               23, 2048, 3072 or 4096 bits
//   ECDH-ES (+A128KW, +A192KW, +A256KW)        31, on P-256, P-384 or P-521
//   RSA-OAEP-256                               34, for keys created on 34 or later
// Anything else, or a lower API level, is `UnsupportedAlgorithm` from `generate` or `open`, never
// at first use.
//
// One key serves one algorithm (an ECDH-ES key serves the whole ECDH-ES family). Verification and
// encryption need only the public key, so they run in software anywhere: `key.publicJwk()` is an
// ordinary public JWK for `jwsVerifyCompact`, `jwtVerify` or `jweEncryptCompact`.
//
// Every call is synchronous and talks to the Keystore: call it off the main thread. A key with
// user authentication may also wait for the user while a prompt is up.
//
// Errors are `PolyjoseException`s with a stable `code()`: `KeyNotFound` (no key under the alias,
// or the platform invalidated it), `UserAuthenticationRequired`, `PlatformKeyFailed` (anything
// else, for example an alias that already holds a key), `UnsupportedAlgorithm`.
package dev.polyjose.examples

import dev.polyjose.AndroidKeystoreKey
import dev.polyjose.JweDecryptOptions
import dev.polyjose.JweDecrypted
import dev.polyjose.JwsSignOptions
import dev.polyjose.JwtSignOptions
import dev.polyjose.PlatformKeyAuthorizer
import dev.polyjose.jweDecryptCompactWithPlatformKey
import dev.polyjose.jwsSignCompactWithPlatformKey
import dev.polyjose.jwtSignWithPlatformKey
import org.json.JSONObject

/**
 * Creates a key for [algorithm] under [alias] in the Android Keystore (TEE), `StrongBox.Off`.
 *
 * - [algorithm]: ES256, ES384, ES512, RS256 … PS512, `ECDH-ES` (for the ECDH-ES family,
 *   RFC 7518 §4.6) or RSA-OAEP-256 (RFC 7518 §4.3).
 * - [keySize]: RSA bits (2048 by default, 3072, 4096), or the ECDH-ES curve (256 by default for
 *   P-256, 384, 521). ES256/384/512 imply their curve (RFC 7518 §3.4).
 * - [userAuthentication]: null for none. Otherwise time-bound (`validitySeconds` > 0: show your
 *   own `BiometricPrompt` first) or per use (0: each operation goes through [authorizer]). The
 *   device needs a secure lock screen.
 *
 * Fails with `PlatformKeyFailed` when [alias] already holds a key: delete it first. A failed
 * create leaves no key under [alias].
 */
fun createKeystoreKey(
    alias: String,
    algorithm: String,
    keySize: Int? = null,
    userAuthentication: AndroidKeystoreKey.UserAuthentication? = null,
    authorizer: PlatformKeyAuthorizer? = null,
): AndroidKeystoreKey =
    AndroidKeystoreKey.generate(alias, algorithm, AndroidKeystoreKey.StrongBox.Off, userAuthentication, keySize, authorizer)

/**
 * Finds the key under [alias] again, for [algorithm]: after a restart, or in another part of the
 * app. `KeyNotFound` when there is none; `KeyAlgorithmMismatch` when the key was made for another
 * algorithm. Its `publicJwk()` (RFC 7517 §4) is the same as when it was created.
 */
fun openKeystoreKey(alias: String, algorithm: String, authorizer: PlatformKeyAuthorizer? = null): AndroidKeystoreKey =
    AndroidKeystoreKey.open(alias, algorithm, authorizer)

/**
 * Signs [payload] as a compact JWS (RFC 7515 §5.1, §7.1) with the Keystore key; the protected
 * header carries `alg` (RFC 7515 §4.1.1). [alg] must be the key's algorithm. polyjose checks the
 * signature against the public key before it returns the token.
 */
fun keystoreSignCompact(payload: ByteArray, key: AndroidKeystoreKey, alg: String): String =
    jwsSignCompactWithPlatformKey(payload, key, JwsSignOptions(protectedHeader = JSONObject().put("alg", alg).toString()))

/**
 * Issues a signed JWT (RFC 7519 §7.1) over [claimsJson], a JSON object, with the Keystore key.
 * The header gets `typ: "JWT"` (RFC 7519 §5.1).
 */
fun keystoreSignJwt(claimsJson: String, key: AndroidKeystoreKey, alg: String): String =
    jwtSignWithPlatformKey(claimsJson, key, JwtSignOptions(alg = alg))

/**
 * Decrypts a compact JWE (RFC 7516 §5.2) whose content key reached this key by ECDH-ES
 * (RFC 7518 §4.6) or RSA-OAEP-256 (RFC 7518 §4.3). The Keystore computes only the shared secret,
 * or unwraps only the content key; polyjose does the rest. [allowedAlgs] and [allowedEnc] are
 * your own fixed lists, never values read from the token (RFC 8725 §3.1). Any failure of the
 * ciphertext or the key is `DecryptionFailed` (RFC 7516 §11.5). Wipe the plaintext when done.
 */
fun keystoreDecrypt(token: String, key: AndroidKeystoreKey, allowedAlgs: List<String>, allowedEnc: List<String>): JweDecrypted =
    jweDecryptCompactWithPlatformKey(token, key, JweDecryptOptions(allowedAlgs = allowedAlgs, allowedEnc = allowedEnc))

/** Deletes the key under [alias]; nothing happens when there is none. A key store operation, no RFC. */
fun deleteKeystoreKey(alias: String) = AndroidKeystoreKey.delete(alias)

/**
 * Where the platform says the key lives (`KeyInfo`): `TrustedEnvironment` on a device from
 * API 31. Below API 31 the platform does not name the place. On an emulator the key is software,
 * whatever this says.
 */
fun keystoreKeyLevel(key: AndroidKeystoreKey): AndroidKeystoreKey.SecurityLevel = key.securityLevel
