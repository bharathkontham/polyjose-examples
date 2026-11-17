// The playground's keys in the Android Keystore: every alias with the prefix
// `dev.polyjose.examples.playground.`, named `<prefix><algorithm>.<n>` with `<n>` the lowest number
// not in use (PLAYGROUND.md "Key names"). The checks' keys (`dev.polyjose.examples.check.`) are
// never listed or deleted here. Listing reads aliases and `KeyInfo` only, which never asks the
// user to authenticate. polyjose 0.4.0 has no "list keys by prefix" call, so the app reads the
// platform's `KeyStore` itself.
package dev.polyjose.examples.playground

import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyStore
import java.security.PrivateKey

object PlaygroundKeys {
    const val PREFIX = "dev.polyjose.examples.playground."

    private fun store(): KeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    /** Every playground alias, sorted. */
    fun aliases(): List<String> = store().aliases().toList().filter { it.startsWith(PREFIX) }.sorted()

    fun exists(alias: String): Boolean = store().containsAlias(alias)

    /** The algorithm part of an alias: `ES256`, `ECDH-ES`, `RSA-OAEP-256`, … */
    fun algorithmOf(alias: String): String = alias.removePrefix(PREFIX).substringBeforeLast('.')

    /** `<prefix><algorithm>.<n>`, `<n>` the lowest number not in use. */
    fun nextAlias(algorithm: String): String {
        val taken = aliases().toSet()
        var n = 1
        while ("$PREFIX$algorithm.$n" in taken) n++
        return "$PREFIX$algorithm.$n"
    }

    /** What `KeyInfo` says about a key's size and its user authentication. */
    class Info(val keySize: Int, val authRequired: Boolean, val validitySeconds: Int, val deviceCredential: Boolean) {
        val perUse: Boolean get() = authRequired && validitySeconds <= 0
        val auth: String get() = when {
            !authRequired -> "none"
            perUse -> "per use"
            else -> "time-bound ${validitySeconds}s"
        } + if (authRequired && deviceCredential) ", device credential" else ""
    }

    /** The key's `KeyInfo`, or null when there is no key under [alias]. */
    fun info(alias: String): Info? {
        val key = store().getKey(alias, null) as? PrivateKey ?: return null
        val info = KeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java)
        val credential = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            info.userAuthenticationType and KeyProperties.AUTH_DEVICE_CREDENTIAL != 0
        } else {
            info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds > 0
        }
        @Suppress("DEPRECATION")
        return Info(info.keySize, info.isUserAuthenticationRequired, info.userAuthenticationValidityDurationSeconds, credential)
    }
}
