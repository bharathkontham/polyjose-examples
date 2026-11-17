// The support matrix of PLAYGROUND.md at the repository root ("Support matrix", "Android notes"),
// held by the app because polyjose 0.4.0 has no "is this supported here" query. Every picker row
// of the Sign and Encrypt tabs is a cell computed here: enabled, or disabled with its reason and
// the code "Run anyway" gives. The demo walk runs every cell, so a cell where this table and the
// library disagree fails the walk.
//
// The order of the checks follows the library: the algorithm table, then the API level and the
// key options (user authentication), then the device (StrongBox present, secure lock screen).
package dev.polyjose.examples.playground

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import dev.polyjose.examples.hasStrongBox

/** A key store column of the matrix. [id] is the `store` value of the log. */
enum class Store(val id: String, val label: String, val explanation: String) {
    Software("software", "Software", "store.software"),
    Keystore("keystore", "Android Keystore (TEE)", "store.keystore"),
    StrongBox("strongbox", "StrongBox", "store.strongbox"),
}

/** `AndroidKeystoreKey.StrongBox` for the StrongBox store (the Keystore store is `Off`). */
enum class StrongBoxMode(val id: String, val label: String, val explanation: String) {
    Preferred("preferred", "Preferred: falls back to the TEE; the key reports where it went", "option.strongbox.preferred"),
    Required("required", "Required: StrongBox or nothing", "option.strongbox.required"),
}

/** User authentication of a new platform key (`AndroidKeystoreKey.UserAuthentication`). */
sealed class Auth(val id: String) {
    object None : Auth("none")

    /** `validitySeconds` > 0: the app's own prompt, then a window of [seconds]. */
    data class TimeBound(val seconds: Int, val deviceCredential: Boolean) : Auth("time-bound")

    /** `validitySeconds` = 0: `BiometricPromptAuthorizer` for each operation. */
    data class PerUse(val deviceCredential: Boolean) : Auth("per-use")

    val prompted: Boolean get() = this !is None
}

/** What the matrix needs to know about this device. Read again on every screen change. */
data class DeviceInfo(
    val api: Int,
    val release: String,
    val model: String,
    val emulator: Boolean,
    val hasStrongBox: Boolean,
    val lockScreen: Boolean,
) {
    companion object {
        fun read(context: Context): DeviceInfo = DeviceInfo(
            api = Build.VERSION.SDK_INT,
            release = Build.VERSION.RELEASE,
            model = Build.MODEL,
            emulator = isEmulator(),
            hasStrongBox = hasStrongBox(context),
            lockScreen = context.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true,
        )

        /** The Android emulator's builds: a heuristic, shown on the "This device" card only. */
        private fun isEmulator(): Boolean =
            Build.FINGERPRINT.startsWith("generic") || Build.FINGERPRINT.contains("emulator") ||
                Build.PRODUCT.contains("sdk") || Build.MODEL.contains("Emulator") || Build.MODEL.startsWith("sdk_")
    }
}

/** Why a cell is disabled: the explanation id, the short line under the row, and the API level it needs. */
class Reason(val id: String, val line: String, val level: Int? = null)

/**
 * One cell: [enabled], or disabled with [reason]. [expected] is the error code the call gives
 * (with Run anyway when disabled), or null when it succeeds. [prompted] marks a cell whose key
 * needs user authentication: the demo walk never runs an enabled prompted cell.
 */
class Cell(val enabled: Boolean, val reason: Reason?, val expected: String?, val prompted: Boolean) {
    companion object {
        fun ok(prompted: Boolean) = Cell(true, null, null, prompted)
        fun no(reason: Reason, expected: String?, prompted: Boolean) = Cell(false, reason, expected, prompted)
    }
}

/** A platform key's parameters: the `AndroidKeystoreKey.generate` algorithm and key size. */
class KeySpec(val algorithm: String, val keySize: Int?) {
    val isEcdh: Boolean get() = algorithm == "ECDH-ES"
    val isRsa: Boolean get() = algorithm.startsWith("RS") || algorithm.startsWith("PS") || algorithm == "RSA-OAEP-256"
}

object Matrix {
    const val UNSUPPORTED = "UnsupportedAlgorithm"
    const val PLATFORM_KEY_FAILED = "PlatformKeyFailed"

    /** The signing algorithms, one row each (RFC 7518 §3.1, RFC 8037 §3.1). */
    val SIGN_ALGS = listOf("HS256", "HS384", "HS512", "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA")

    /** The key-management algorithms of a JWE, one row each (RFC 7518 §4.1). */
    val JWE_ALGS = listOf(
        "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", "RSA-OAEP-256",
        "A128KW", "A192KW", "A256KW", "A128GCMKW", "A192GCMKW", "A256GCMKW", "dir",
    )

    /** Content encryption (RFC 7518 §5.1): every store, always polyjose's. */
    val ENCS = listOf("A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512")

    val CURVES = listOf("P-256", "P-384", "P-521", "X25519")
    val RSA_SIZES = listOf(2048, 3072, 4096)
    val AUTH_SECONDS = listOf(10, 30, 60)

    // API levels of the Keystore (AndroidKeystoreKey's table).
    const val STRONGBOX_API = 28
    const val PROMPT_API = 28 // the framework BiometricPrompt, and per-use authentication
    const val DEVICE_CREDENTIAL_API = 30
    const val ECDH_API = 31
    const val RSA_OAEP_256_API = 34
    const val NAMED_LEVEL_API = 31 // KeyInfo.getSecurityLevel: below it the platform doesn't name the TEE or StrongBox

    fun isRsaSign(alg: String) = alg.startsWith("RS") || alg.startsWith("PS")
    fun isEcdh(alg: String) = alg.startsWith("ECDH-ES")
    fun isOct(alg: String) = alg.startsWith("HS") || alg.startsWith("A1") || alg.startsWith("A2") || alg == "dir"

    /** The Android version of an API level, for the reason line. */
    fun androidVersion(api: Int): String = when (api) {
        23 -> "6.0"
        28 -> "9"
        30 -> "11"
        31 -> "12"
        34 -> "14"
        else -> "API $api"
    }

    fun apiReason(api: Int) = Reason("reason.api-level", "needs Android ${androidVersion(api)} (API $api)", api)

    val NO_STRONGBOX = Reason("reason.no-strongbox", "no StrongBox on this device")
    val NO_LOCK_SCREEN = Reason("reason.no-lock-screen", "set a screen lock")
    val PER_USE_ECDH = Reason("reason.per-use-ecdh", "per-use isn't possible for ECDH keys")
    val SYMMETRIC = Reason("reason.symmetric", "HMAC and AES keys stay in software")
    val NO_CURVE25519 = Reason("reason.no-curve25519", "no key store here offers Ed25519 or X25519")
    val SOFTWARE_NOT_STORED = Reason("reason.software-not-stored", "a software key isn't stored")
    /** Software RSA has one private key, the RFC 7515 A.2 test key, so there is no other key. */
    val ONE_SOFTWARE_RSA_KEY = Reason("key.test-rsa", "software RSA has one key, a test key")

    /**
     * The platform key of a row: null when the Keystore can't hold it at all (HMAC, AES and `dir`
     * keys; Ed25519 and X25519). [alg] is a signing or key-management algorithm.
     */
    fun keySpec(alg: String, crv: String?, rsaSize: Int): KeySpec? = when {
        alg.startsWith("ES") -> KeySpec(alg, null)
        isRsaSign(alg) -> KeySpec(alg, rsaSize)
        alg == "RSA-OAEP-256" -> KeySpec(alg, rsaSize)
        isEcdh(alg) -> when (crv) {
            "P-256" -> KeySpec("ECDH-ES", 256)
            "P-384" -> KeySpec("ECDH-ES", 384)
            "P-521" -> KeySpec("ECDH-ES", 521)
            else -> null
        }
        else -> null
    }

    /** The lowest API level of [k] in the TEE, or null when the Keystore can't serve it. */
    fun teeApi(k: KeySpec): Int? = when {
        k.algorithm.startsWith("ES") -> 23
        isRsaSign(k.algorithm) -> if (k.keySize in RSA_SIZES) 23 else null
        k.isEcdh -> ECDH_API
        k.algorithm == "RSA-OAEP-256" -> if (k.keySize in RSA_SIZES) RSA_OAEP_256_API else null
        else -> null
    }

    /** The lowest API level of [k] in StrongBox, or null when StrongBox can't serve it. */
    fun strongBoxApi(k: KeySpec): Int? = when {
        k.algorithm == "ES256" -> STRONGBOX_API
        (k.algorithm == "RS256" || k.algorithm == "PS256") && k.keySize == 2048 -> STRONGBOX_API
        k.isEcdh && k.keySize == 256 -> ECDH_API
        k.algorithm == "RSA-OAEP-256" && k.keySize == 2048 -> RSA_OAEP_256_API
        else -> null
    }

    /** "StrongBox can't do …", naming the algorithm and, where it matters, the size or curve. */
    private fun strongBoxReason(alg: String, k: KeySpec): Reason {
        val what = when {
            k.isEcdh -> "ECDH-ES on P-${k.keySize}"
            k.isRsa && (alg == "RS256" || alg == "PS256" || alg == "RSA-OAEP-256") -> "$alg at ${k.keySize} bits"
            else -> alg
        }
        return Reason("reason.strongbox-algorithms", "StrongBox can't do $what")
    }

    /**
     * The cell of ([store], [mode], [alg] with [crv] or [rsaSize], [auth]) on [device]. The
     * software store takes every algorithm and no authentication.
     */
    fun cell(store: Store, mode: StrongBoxMode, alg: String, crv: String?, rsaSize: Int, auth: Auth, device: DeviceInfo): Cell {
        if (store == Store.Software) return Cell.ok(prompted = false)
        val prompted = auth.prompted
        val k = keySpec(alg, crv, rsaSize)
            ?: return Cell.no(if (alg == "EdDSA" || crv == "X25519") NO_CURVE25519 else SYMMETRIC, UNSUPPORTED, prompted)
        val required = store == Store.StrongBox && mode == StrongBoxMode.Required
        // 1. The algorithm table and the API level (StrongBox Required: the StrongBox table).
        val minApi = (if (required) strongBoxApi(k) else teeApi(k))
            ?: return Cell.no(if (required) strongBoxReason(alg, k) else SYMMETRIC, UNSUPPORTED, prompted)
        if (device.api < minApi) return Cell.no(apiReason(minApi), UNSUPPORTED, prompted)
        // 2. User authentication: per use is for signing and RSA-OAEP-256 keys, API 28 or later.
        if (auth is Auth.PerUse && k.isEcdh) return Cell.no(PER_USE_ECDH, UNSUPPORTED, prompted)
        if (auth is Auth.PerUse && device.api < PROMPT_API) return Cell.no(apiReason(PROMPT_API), UNSUPPORTED, prompted)
        if (auth is Auth.TimeBound && device.api < PROMPT_API) {
            // The library takes time-bound keys from API 23; the playground needs BiometricPrompt.
            return Cell.no(apiReason(PROMPT_API), if (device.lockScreen) null else PLATFORM_KEY_FAILED, prompted)
        }
        // 3. The device.
        if (required && !device.hasStrongBox) return Cell.no(NO_STRONGBOX, PLATFORM_KEY_FAILED, prompted)
        if (prompted && !device.lockScreen) return Cell.no(NO_LOCK_SCREEN, PLATFORM_KEY_FAILED, prompted)
        return Cell.ok(prompted)
    }

    /**
     * Whether an authentication option row is disabled by itself (not by the algorithm): its
     * reason, or null. These rows are the ones the task lists: API 28, no lock screen, per-use ECDH.
     */
    fun authReason(store: Store, alg: String, auth: Auth, device: DeviceInfo): Reason? {
        if (store == Store.Software || !auth.prompted) return null
        if (device.api < PROMPT_API) return apiReason(PROMPT_API)
        if (auth is Auth.PerUse && isEcdh(alg)) return PER_USE_ECDH
        if (!device.lockScreen) return NO_LOCK_SCREEN
        return null
    }

    /** Below API 30 the platform decides the device credential: time-bound admits it, per use doesn't. */
    fun deviceCredential(auth: Auth, device: DeviceInfo): Boolean = when (auth) {
        is Auth.None -> false
        is Auth.TimeBound -> if (device.api < DEVICE_CREDENTIAL_API) true else auth.deviceCredential
        is Auth.PerUse -> if (device.api < DEVICE_CREDENTIAL_API) false else auth.deviceCredential
    }

    /**
     * The other algorithm of the same key type, for `failure.sign.other-alg`. An Ed25519 key has
     * no other one, so EdDSA allows ES256.
     */
    fun otherSignAlg(alg: String): String = when (alg) {
        "HS256" -> "HS384"
        "HS384", "HS512" -> "HS256"
        "ES256" -> "ES384"
        "ES384", "ES512" -> "ES256"
        "RS256" -> "RS384"
        "RS384", "RS512" -> "RS256"
        "PS256" -> "PS384"
        "PS384", "PS512" -> "PS256"
        else -> "ES256" // EdDSA
    }

    /** Another key-management algorithm, for `failure.encrypt.other-alg`. */
    fun otherJweAlg(alg: String): String = when (alg) {
        "ECDH-ES" -> "ECDH-ES+A256KW"
        "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW" -> "ECDH-ES"
        "RSA-OAEP-256" -> "RSA-OAEP"
        "A128KW" -> "A256KW"
        "A192KW", "A256KW" -> "A128KW"
        "A128GCMKW" -> "A128KW"
        "A192GCMKW" -> "A192KW"
        "A256GCMKW" -> "A256KW"
        else -> "A256KW" // dir
    }

    /** The length in bytes of a shared key for [alg] (RFC 7518 §4.4, §4.5, §4.7), `dir` sized by [enc] (§5). */
    fun octBytes(alg: String, enc: String): Int = when (alg) {
        "A128KW", "A128GCMKW" -> 16
        "A192KW", "A192GCMKW" -> 24
        "A256KW", "A256GCMKW" -> 32
        else -> when (enc) { // dir: the content key itself
            "A128GCM" -> 16
            "A192GCM" -> 24
            "A256GCM", "A128CBC-HS256" -> 32
            "A192CBC-HS384" -> 48
            else -> 64
        }
    }
}
