// How do I keep a private key in StrongBox and sign or decrypt with it?
//
// StrongBox is a separate hardware secure element, on some devices from Android API 28. It is
// slower than the TEE and serves fewer algorithms. `AndroidKeystoreKey` asks for it with
// `strongBox`:
//   StrongBox.Required   StrongBox or nothing. Without StrongBox, creating the key fails with
//                        `PlatformKeyFailed` and leaves no key behind: there is never a silent
//                        move to the TEE.
//   StrongBox.Preferred  StrongBox when the device has it and it can serve the algorithm, else
//                        the TEE. The key's `securityLevel` says where it went.
// The private key never leaves the key store: polyjose asks it for one signature, one ECDH shared
// secret or one RSA-OAEP-256 decryption at a time. The keys of PlatformKeysKeystore.kt
// (`StrongBox.Off`) live in the TEE.
//
// What StrongBox serves, and from which Android API level (the app's minSdk is 23):
//   ES256                         28
//   RS256, PS256                  28, 2048 bits only
//   ECDH-ES family, P-256         31
//   RSA-OAEP-256                  34, 2048 bits only; not verified on a StrongBox device
// Under `Required` anything else (ES384, RSA 3072, P-384, …) is `UnsupportedAlgorithm`, with or
// without StrongBox. Under `Preferred` it goes to the TEE, whose levels are in
// PlatformKeysKeystore.kt.
//
// Whether the device has StrongBox: `PackageManager.FEATURE_STRONGBOX_KEYSTORE` (hasStrongBox
// below). An emulator has none. Only a run on a device shows the hardware.
//
// Every call is synchronous and talks to the key store: call it off the main thread.
package dev.polyjose.examples

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import dev.polyjose.AndroidKeystoreKey
import dev.polyjose.JweDecryptOptions
import dev.polyjose.JweDecrypted
import dev.polyjose.JwsSignOptions
import dev.polyjose.JwtSignOptions
import dev.polyjose.PlatformKeyAuthorizer
import dev.polyjose.PolyjoseException
import dev.polyjose.jweDecryptCompactWithPlatformKey
import dev.polyjose.jwsSignCompactWithPlatformKey
import dev.polyjose.jwtSignWithPlatformKey
import org.json.JSONObject

/** Whether this device has a StrongBox Keymaster or KeyMint (API 28 or later). */
fun hasStrongBox(context: Context): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
        context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

/**
 * Creates a key for [algorithm] under [alias], in StrongBox ([mode] `Required`, the default) or
 * in StrongBox when possible ([mode] `Preferred`). `StrongBox.Off` is not taken here: that is
 * [createKeystoreKey].
 *
 * - [algorithm]: ES256 (RFC 7518 §3.4), RS256 or PS256 (RFC 7518 §3.3, §3.5), `ECDH-ES`
 *   (RFC 7518 §4.6, P-256) or RSA-OAEP-256 (RFC 7518 §4.3).
 * - [keySize]: 2048 for RSA (the default), 256 for ECDH-ES (the default).
 * - [userAuthentication], [authorizer]: as for [createKeystoreKey].
 *
 * Under `Required` on a device without StrongBox this fails with `PlatformKeyFailed` and leaves
 * no key under [alias]; see [createInStrongBoxOrNull]. An [alias] that already holds a key is
 * `PlatformKeyFailed` too.
 */
fun createStrongBoxKey(
    alias: String,
    algorithm: String,
    mode: AndroidKeystoreKey.StrongBox = AndroidKeystoreKey.StrongBox.Required,
    keySize: Int? = null,
    userAuthentication: AndroidKeystoreKey.UserAuthentication? = null,
    authorizer: PlatformKeyAuthorizer? = null,
): AndroidKeystoreKey {
    require(mode != AndroidKeystoreKey.StrongBox.Off) { "StrongBox.Off is createKeystoreKey" }
    return AndroidKeystoreKey.generate(alias, algorithm, mode, userAuthentication, keySize, authorizer)
}

/**
 * A key in StrongBox, or null when this device can't make one: no StrongBox, or StrongBox
 * failed (`PlatformKeyFailed` under `Required`). Nothing is left under [alias] then, and the app
 * decides what to do: tell the user, or create the key with [createKeystoreKey] on purpose.
 * `UnsupportedAlgorithm` (an algorithm StrongBox can't serve) is still thrown: that is a
 * programming error, not a property of the device.
 */
fun createInStrongBoxOrNull(context: Context, alias: String, algorithm: String): AndroidKeystoreKey? {
    if (!hasStrongBox(context)) return null
    return try {
        createStrongBoxKey(alias, algorithm, AndroidKeystoreKey.StrongBox.Required)
    } catch (e: PolyjoseException.PlatformKeyFailed) {
        null
    }
}

/** Finds the key under [alias] again, for [algorithm]. `KeyNotFound` when there is none (RFC 7517 §4 for its `publicJwk()`). */
fun openStrongBoxKey(alias: String, algorithm: String, authorizer: PlatformKeyAuthorizer? = null): AndroidKeystoreKey =
    AndroidKeystoreKey.open(alias, algorithm, authorizer)

/** Signs [payload] as a compact JWS (RFC 7515 §5.1, §7.1) with the key; the header carries `alg` (RFC 7515 §4.1.1). */
fun strongBoxSignCompact(payload: ByteArray, key: AndroidKeystoreKey, alg: String): String =
    jwsSignCompactWithPlatformKey(payload, key, JwsSignOptions(protectedHeader = JSONObject().put("alg", alg).toString()))

/** Issues a signed JWT (RFC 7519 §7.1) over [claimsJson], a JSON object, with the key. */
fun strongBoxSignJwt(claimsJson: String, key: AndroidKeystoreKey, alg: String): String =
    jwtSignWithPlatformKey(claimsJson, key, JwtSignOptions(alg = alg))

/**
 * Decrypts a compact JWE (RFC 7516 §5.2) with the key: ECDH-ES (RFC 7518 §4.6) or RSA-OAEP-256
 * (RFC 7518 §4.3). [allowedAlgs] and [allowedEnc] are your own fixed lists (RFC 8725 §3.1). Any
 * failure is `DecryptionFailed` (RFC 7516 §11.5).
 */
fun strongBoxDecrypt(token: String, key: AndroidKeystoreKey, allowedAlgs: List<String>, allowedEnc: List<String>): JweDecrypted =
    jweDecryptCompactWithPlatformKey(token, key, JweDecryptOptions(allowedAlgs = allowedAlgs, allowedEnc = allowedEnc))

/** Deletes the key under [alias]; nothing happens when there is none. A key store operation, no RFC. */
fun deleteStrongBoxKey(alias: String) = AndroidKeystoreKey.delete(alias)

/**
 * Where the platform says the key lives (`KeyInfo`, API 31 or later): `StrongBox`, or
 * `TrustedEnvironment` when a `Preferred` key went to the TEE (an emulator reports `Software`:
 * its keys are software). Below API 31 the platform reports `SecureHardware` and can't say which
 * of the two.
 */
fun strongBoxKeyLevel(key: AndroidKeystoreKey): AndroidKeystoreKey.SecurityLevel = key.securityLevel
