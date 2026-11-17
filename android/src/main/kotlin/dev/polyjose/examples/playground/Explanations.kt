// The explanation texts of PLAYGROUND.md ("Explanations"), keyed by id: every tab, algorithm,
// `enc`, curve, store, option, refusal reason, failure action and error code. The info buttons,
// the disabled rows and the result card show them. The iOS-only ids (Keychain, Secure Enclave,
// access flags) are not here. A text never holds key material, a token's secret parts or a
// library error message.
package dev.polyjose.examples.playground

object Explanations {
    private val TEXTS: Map<String, String> = mapOf(
        // Tabs
        "tab.checks" to "Every check of the catalog, run against the polyjose release this app pins.",
        "tab.sign" to "Sign a JWS or JWT with a key from any store, verify it in software, and try how misuse is refused.",
        "tab.encrypt" to "Encrypt to a key's public JWK in software, decrypt with the key in its store, and try how misuse is refused.",
        "tab.keys" to "The playground's keys in each store, where the platform says each one lives, and this device's capabilities.",
        "tab.log" to "Every step of every tap, newest first. It holds no secrets, so it can be copied and shared.",

        // Signing algorithms
        "alg.HS256" to "HMAC with SHA-256 (RFC 7518 §3.2). One shared secret, at least 32 bytes, both signs and verifies, so whoever can verify can also sign.",
        "alg.HS384" to "HMAC with SHA-384 (RFC 7518 §3.2). One shared secret, at least 48 bytes, both signs and verifies.",
        "alg.HS512" to "HMAC with SHA-512 (RFC 7518 §3.2). One shared secret, at least 64 bytes, both signs and verifies.",
        "alg.RS256" to "RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies.",
        "alg.RS384" to "RSASSA-PKCS1-v1_5 with SHA-384 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies.",
        "alg.RS512" to "RSASSA-PKCS1-v1_5 with SHA-512 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies.",
        "alg.PS256" to "RSASSA-PSS with SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5): RSA with randomized padding, so signing the same input twice gives two signatures.",
        "alg.PS384" to "RSASSA-PSS with SHA-384 and MGF1 with SHA-384 (RFC 7518 §3.5): RSA with randomized padding.",
        "alg.PS512" to "RSASSA-PSS with SHA-512 and MGF1 with SHA-512 (RFC 7518 §3.5): RSA with randomized padding.",
        "alg.ES256" to "ECDSA on P-256 with SHA-256 (RFC 7518 §3.4). Small keys and signatures; the one signing algorithm the Secure Enclave serves.",
        "alg.ES384" to "ECDSA on P-384 with SHA-384 (RFC 7518 §3.4).",
        "alg.ES512" to "ECDSA on P-521 with SHA-512 (RFC 7518 §3.4).",
        "alg.EdDSA" to "Ed25519 signatures (RFC 8037 §3.1): deterministic, with small keys. polyjose signs in software; neither key store here offers Ed25519.",

        // Key management
        "alg.ECDH-ES" to "Ephemeral-static ECDH (RFC 7518 §4.6): the sender makes a one-time key pair, agrees a secret with the recipient's public key, and derives the content key from it with the Concat KDF. No encrypted key is sent.",
        "alg.ECDH-ES+A128KW" to "ECDH-ES (RFC 7518 §4.6), whose derived 128-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4).",
        "alg.ECDH-ES+A192KW" to "ECDH-ES (RFC 7518 §4.6), whose derived 192-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4).",
        "alg.ECDH-ES+A256KW" to "ECDH-ES (RFC 7518 §4.6), whose derived 256-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4).",
        "alg.RSA-OAEP-256" to "RSAES-OAEP with SHA-256 and MGF1 with SHA-256 (RFC 7518 §4.3): the content key is encrypted to the recipient's RSA public key.",
        "alg.A128KW" to "AES Key Wrap with a 128-bit shared key (RFC 7518 §4.4): sender and recipient hold the same secret key.",
        "alg.A192KW" to "AES Key Wrap with a 192-bit shared key (RFC 7518 §4.4).",
        "alg.A256KW" to "AES Key Wrap with a 256-bit shared key (RFC 7518 §4.4).",
        "alg.A128GCMKW" to "AES-GCM key encryption with a 128-bit shared key (RFC 7518 §4.7); the `iv` and `tag` header parameters carry its nonce and tag.",
        "alg.A192GCMKW" to "AES-GCM key encryption with a 192-bit shared key (RFC 7518 §4.7).",
        "alg.A256GCMKW" to "AES-GCM key encryption with a 256-bit shared key (RFC 7518 §4.7).",
        "alg.dir" to "Direct encryption with a shared key (RFC 7518 §4.5): the shared key is the content key, so no key is sent, and its size must fit `enc`.",

        // Content encryption
        "enc.A128GCM" to "AES-GCM with a 128-bit content key (RFC 7518 §5.3): authenticated encryption, so any change to the ciphertext, IV, tag or protected header makes decryption fail.",
        "enc.A192GCM" to "AES-GCM with a 192-bit content key (RFC 7518 §5.3).",
        "enc.A256GCM" to "AES-GCM with a 256-bit content key (RFC 7518 §5.3).",
        "enc.A128CBC-HS256" to "AES-128-CBC, then HMAC SHA-256 truncated to 128 bits (RFC 7518 §5.2.3): encrypt-then-MAC with a 256-bit content key.",
        "enc.A192CBC-HS384" to "AES-192-CBC, then HMAC SHA-384 truncated to 192 bits (RFC 7518 §5.2.4), with a 384-bit content key.",
        "enc.A256CBC-HS512" to "AES-256-CBC, then HMAC SHA-512 truncated to 256 bits (RFC 7518 §5.2.5), with a 512-bit content key.",

        // Curves
        "crv.P-256" to "The NIST P-256 curve (RFC 7518 §6.2.1.1). The only curve the Secure Enclave and StrongBox serve.",
        "crv.P-384" to "The NIST P-384 curve (RFC 7518 §6.2.1.1).",
        "crv.P-521" to "The NIST P-521 curve (RFC 7518 §6.2.1.1).",
        "crv.X25519" to "Curve25519 key agreement (RFC 8037 §3.2). In software only.",

        // Stores
        "store.software" to "A polyjose JWK in this app's memory (RFC 7517 §4). Every algorithm works; the private key is ordinary app data, gone when the app quits.",
        "store.keystore" to "Android Keystore (TEE): isolated from Android in the device's trusted execution environment; on an emulator the keys are software, whatever it reports. The private key can't be exported.",
        "store.strongbox" to "StrongBox: a separate hardware secure element (API 28 or later). It is slower and serves fewer algorithms: ES256, RS256 and PS256 at 2048 bits, ECDH-ES on P-256, RSA-OAEP-256 at 2048 bits.",
        "key.test-rsa" to "The RFC 7515 Appendix A.2 RSA key: a published test key, never use it in production. polyjose 0.4.0 can't generate RSA keys, so software RSA uses it.",

        // Options
        "option.payload" to "A fixed demo payload, never free text, so every token here is a demo token. JWS: `polyjose example payload`. JWT: `iss`, `aud`, `sub`, and `exp` five minutes from now.",
        "option.rsa-size" to "The RSA modulus: 2048, 3072 or 4096 bits (at least 2048, RFC 7518 §3.3). StrongBox: 2048 only. Bigger keys are slower to create and use.",
        "option.curve" to "The curve of an ECDH-ES key: P-256, P-384, P-521 or X25519.",
        "option.strongbox.off" to "The TEE. StrongBox is never asked for.",
        "option.strongbox.preferred" to "StrongBox when the device has it and it can serve the algorithm, else the TEE: falls back to the TEE; the key reports where it went.",
        "option.strongbox.required" to "StrongBox or nothing. Without StrongBox, creating the key fails with `PlatformKeyFailed` (API 28 or later; below 28, StrongBox is refused with `UnsupportedAlgorithm`) and no key is left behind; there is never a silent move to the TEE.",
        "option.auth.none" to "No user authentication: the key works whenever the app calls it.",
        "option.auth.time-bound" to "After the user authenticates in the app's prompt, the key works for the chosen number of seconds; outside that window a call fails with `UserAuthenticationRequired`. Every key kind.",
        "option.auth.per-use" to "Each signature or decryption shows a prompt bound to that one operation. Signing and RSA-OAEP-256 keys, API 28 or later.",
        "option.auth.device-credential" to "The PIN, pattern or password may stand in for a strong biometric. A free choice from API 30; below that the platform decides.",

        // Refusal reasons
        "reason.symmetric" to "Platform keys here are private keys for signatures, ECDH and RSA-OAEP-256. HMAC and AES keys stay in software.",
        "reason.no-curve25519" to "Neither key store here offers Ed25519 or X25519; they run in software.",
        "reason.strongbox-algorithms" to "StrongBox serves ES256, RS256 and PS256 at 2048 bits, ECDH-ES on P-256, and RSA-OAEP-256 at 2048 bits.",
        "reason.api-level" to "Needs Android API <level>; this device runs API <current>.",
        "reason.no-strongbox" to "This device has no StrongBox. `Preferred` falls back to the TEE; `Required` fails.",
        "reason.per-use-ecdh" to "An ECDH key can be time-bound only, not per use.",
        "reason.no-lock-screen" to "Set a screen lock first: a key that needs user authentication needs a secure lock screen.",
        "reason.software-not-stored" to "A software key isn't stored anywhere, so there is nothing to delete.",

        // Failure actions
        "failure.sign.tamper" to "One character of the payload changed, so the signature no longer matches (RFC 7515 §5.2 step 8).",
        "failure.sign.other-alg" to "The verifier allows only another algorithm. polyjose never trusts the token's `alg` alone (RFC 8725 §3.1).",
        "failure.sign.wrong-key" to "Another key of the same algorithm verifies, and its signature check fails (RFC 7515 §5.2 step 8).",
        "failure.sign.expired" to "The JWT's `exp` is an hour ago and the leeway is 0 (RFC 7519 §4.1.4).",
        "failure.sign.deleted-key" to "The key was deleted, so opening it again by its name finds nothing.",
        "failure.encrypt.tamper" to "One character of the ciphertext changed. Every decryption failure gives the same code, so it reveals nothing (RFC 7516 §11.5).",
        "failure.encrypt.other-alg" to "The recipient allows only another `alg` (RFC 8725 §3.1).",
        "failure.encrypt.wrong-key" to "The token is decrypted with a key other than the one it was encrypted to, of the same kind, and decryption fails (RFC 7516 §11.5).",
        "failure.encrypt.deleted-key" to "The key was deleted, so opening it again by its name finds nothing.",

        // Error codes
        "error.InvalidBase64" to "A token part or key member isn't valid base64url (RFC 7515 §2). Reject the input.",
        "error.InvalidJson" to "A header, claims set or JWK isn't a valid JSON object, or names a member twice (RFC 7515 §5.2). Reject the input.",
        "error.InvalidHeader" to "The JOSE header is malformed, for example `alg` is missing (RFC 7515 §4.1). Reject the token.",
        "error.UnsupportedAlgorithm" to "The algorithm isn't available, or not with this key store, device or option. Pick another algorithm or store; retrying won't help.",
        "error.AlgorithmNotAllowed" to "The token's algorithm isn't in the allow-list the app passed (RFC 8725 §3.1); `none` is never allowed. Reject the token.",
        "error.InvalidKey" to "The key is malformed or too weak, for example RSA under 2048 bits (RFC 7518 §6). Use a valid key.",
        "error.KeyAlgorithmMismatch" to "The key is valid but bound to another algorithm or use (RFC 8725 §3.1). Use the key made for this algorithm.",
        "error.InvalidSignature" to "The signature doesn't verify (RFC 7515 §5.2 step 8): the token was changed, or another key signed it. Reject the token.",
        "error.DecryptionFailed" to "Decryption failed. The cause is never told apart (RFC 7516 §11.5). Reject the token.",
        "error.UnknownCritical" to "The `crit` header names an extension polyjose doesn't understand (RFC 7515 §4.1.11). Reject the token.",
        "error.TokenExpired" to "The JWT's `exp` has passed, allowing for the leeway (RFC 7519 §4.1.4). Get a fresh token.",
        "error.TokenNotYetValid" to "The JWT's `nbf` hasn't been reached yet (RFC 7519 §4.1.5). Reject it, or check the clocks.",
        "error.InvalidClaim" to "A JWT claim is missing or wrong, for example `iss` or `aud` (RFC 7519 §4.1; RFC 8725 §3.8, §3.9). Reject the token.",
        "error.RandomnessUnavailable" to "The OS random number generator failed; polyjose never falls back to a weaker one (RFC 8725 §3.5). Report it.",
        "error.InvalidFormat" to "The input doesn't have the shape its RFC requires, for example a compact JWS without three parts (RFC 7515 §7.1), or it is over a size limit. Reject the input.",
        "error.NoMatchingKey" to "No key in the JWK Set matches the token's `kid` and `alg` (RFC 7517 §5). Refresh the key set once, then reject.",
        "error.MultipleMatchingKeys" to "More than one key in the JWK Set matches (RFC 7517 §5). Give the keys distinct `kid`s.",
        "error.KeyNotFound" to "No usable key under that name: none was created, it was deleted, or the platform invalidated it. Create a new key.",
        "error.UserAuthenticationRequired" to "The key needs the user to authenticate, and they haven't, cancelled, or can't (lockout, no biometrics). Prompt, then retry.",
        "error.PlatformKeyFailed" to "Any other key store failure, for example a name that already holds a key, or StrongBox required and absent. Report it; retrying may not help. When decrypting, such a failure gives `DecryptionFailed` instead, so every decryption failure looks the same (RFC 7516 §11.5).",
    )

    /** The text of [id]; an id with no text (a non-polyjose error type) says so. */
    fun text(id: String, device: DeviceInfo? = null): String {
        val t = TEXTS[id] ?: return if (id.startsWith("error.")) "Not a polyjose error code: an unexpected failure of the app or the platform." else id
        return if (device != null) t.replace("<current>", device.api.toString()) else t
    }

    /** The explanation of an API-level reason, with the level filled in. */
    fun apiLevel(level: Int, device: DeviceInfo): String = text("reason.api-level", device).replace("<level>", level.toString())
}
