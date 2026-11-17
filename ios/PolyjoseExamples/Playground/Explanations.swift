// Every explanation the playground shows, keyed by id: the info buttons, the disabled rows and the
// result card. The texts are the canonical ones of PLAYGROUND.md, "Explanations" (at the root of
// this repository), for the ids that apply on iOS. No text holds key material, a token's secret
// parts or a library error message.
enum Explanations {
    /// The text of `id`, or the id itself when there is none.
    static func text(_ id: String) -> String { texts[id] ?? id }

    /// The title an info sheet shows for `id`: the part after the first dot.
    static func title(_ id: String) -> String {
        guard let dot = id.firstIndex(of: ".") else { return id }
        return String(id[id.index(after: dot)...])
    }

    static let texts: [String: String] = [
        // Tabs
        "tab.checks": "Every check of the catalog, run against the polyjose release this app pins.",
        "tab.sign": "Sign a JWS or JWT with a key from any store, verify it in software, and try how misuse is refused.",
        "tab.encrypt": "Encrypt to a key's public JWK in software, decrypt with the key in its store, and try how misuse is refused.",
        "tab.keys": "The playground's keys in each store, where the platform says each one lives, and this device's capabilities.",
        "tab.log": "Every step of every tap, newest first. It holds no secrets, so it can be copied and shared.",

        // Signing algorithms
        "alg.HS256": "HMAC with SHA-256 (RFC 7518 §3.2). One shared secret, at least 32 bytes, both signs and verifies, so whoever can verify can also sign.",
        "alg.HS384": "HMAC with SHA-384 (RFC 7518 §3.2). One shared secret, at least 48 bytes, both signs and verifies.",
        "alg.HS512": "HMAC with SHA-512 (RFC 7518 §3.2). One shared secret, at least 64 bytes, both signs and verifies.",
        "alg.RS256": "RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies.",
        "alg.RS384": "RSASSA-PKCS1-v1_5 with SHA-384 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies.",
        "alg.RS512": "RSASSA-PKCS1-v1_5 with SHA-512 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies.",
        "alg.PS256": "RSASSA-PSS with SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5): RSA with randomized padding, so signing the same input twice gives two signatures.",
        "alg.PS384": "RSASSA-PSS with SHA-384 and MGF1 with SHA-384 (RFC 7518 §3.5): RSA with randomized padding.",
        "alg.PS512": "RSASSA-PSS with SHA-512 and MGF1 with SHA-512 (RFC 7518 §3.5): RSA with randomized padding.",
        "alg.ES256": "ECDSA on P-256 with SHA-256 (RFC 7518 §3.4). Small keys and signatures; the one signing algorithm the Secure Enclave serves.",
        "alg.ES384": "ECDSA on P-384 with SHA-384 (RFC 7518 §3.4).",
        "alg.ES512": "ECDSA on P-521 with SHA-512 (RFC 7518 §3.4).",
        "alg.EdDSA": "Ed25519 signatures (RFC 8037 §3.1): deterministic, with small keys. polyjose signs in software; neither key store here offers Ed25519.",

        // Key management (`alg` of a JWE)
        "alg.ECDH-ES": "Ephemeral-static ECDH (RFC 7518 §4.6): the sender makes a one-time key pair, agrees a secret with the recipient's public key, and derives the content key from it with the Concat KDF. No encrypted key is sent.",
        "alg.ECDH-ES+A128KW": "ECDH-ES (RFC 7518 §4.6), whose derived 128-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4).",
        "alg.ECDH-ES+A192KW": "ECDH-ES (RFC 7518 §4.6), whose derived 192-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4).",
        "alg.ECDH-ES+A256KW": "ECDH-ES (RFC 7518 §4.6), whose derived 256-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4).",
        "alg.RSA-OAEP-256": "RSAES-OAEP with SHA-256 and MGF1 with SHA-256 (RFC 7518 §4.3): the content key is encrypted to the recipient's RSA public key.",
        "alg.A128KW": "AES Key Wrap with a 128-bit shared key (RFC 7518 §4.4): sender and recipient hold the same secret key.",
        "alg.A192KW": "AES Key Wrap with a 192-bit shared key (RFC 7518 §4.4).",
        "alg.A256KW": "AES Key Wrap with a 256-bit shared key (RFC 7518 §4.4).",
        "alg.A128GCMKW": "AES-GCM key encryption with a 128-bit shared key (RFC 7518 §4.7); the `iv` and `tag` header parameters carry its nonce and tag.",
        "alg.A192GCMKW": "AES-GCM key encryption with a 192-bit shared key (RFC 7518 §4.7).",
        "alg.A256GCMKW": "AES-GCM key encryption with a 256-bit shared key (RFC 7518 §4.7).",
        "alg.dir": "Direct encryption with a shared key (RFC 7518 §4.5): the shared key is the content key, so no key is sent, and its size must fit `enc`.",

        // Content encryption (`enc`)
        "enc.A128GCM": "AES-GCM with a 128-bit content key (RFC 7518 §5.3): authenticated encryption, so any change to the ciphertext, IV, tag or protected header makes decryption fail.",
        "enc.A192GCM": "AES-GCM with a 192-bit content key (RFC 7518 §5.3).",
        "enc.A256GCM": "AES-GCM with a 256-bit content key (RFC 7518 §5.3).",
        "enc.A128CBC-HS256": "AES-128-CBC, then HMAC SHA-256 truncated to 128 bits (RFC 7518 §5.2.3): encrypt-then-MAC with a 256-bit content key.",
        "enc.A192CBC-HS384": "AES-192-CBC, then HMAC SHA-384 truncated to 192 bits (RFC 7518 §5.2.4), with a 384-bit content key.",
        "enc.A256CBC-HS512": "AES-256-CBC, then HMAC SHA-512 truncated to 256 bits (RFC 7518 §5.2.5), with a 512-bit content key.",

        // Curves
        "crv.P-256": "The NIST P-256 curve (RFC 7518 §6.2.1.1). The only curve the Secure Enclave and StrongBox serve.",
        "crv.P-384": "The NIST P-384 curve (RFC 7518 §6.2.1.1).",
        "crv.P-521": "The NIST P-521 curve (RFC 7518 §6.2.1.1).",
        "crv.X25519": "Curve25519 key agreement (RFC 8037 §3.2). In software only.",

        // Stores
        "store.software": "A polyjose JWK in this app's memory (RFC 7517 §4). Every algorithm works; the private key is ordinary app data, gone when the app quits.",
        "store.keychain": "iOS Keychain: stored and protected by the OS, not hardware-bound; on iOS, code that holds the key reference can export the private key. The key stays on this device and is never synchronized.",
        "store.secure-enclave": "Secure Enclave: a hardware-bound P-256 key, created inside the Secure Enclave and never exported from it; it serves ES256 and ECDH-ES. In the Simulator it is a host pass-through, not a hardware guarantee.",
        "key.test-rsa": "The RFC 7515 Appendix A.2 RSA key: a published test key, never use it in production. polyjose 0.4.0 can't generate RSA keys, so software RSA uses it.",

        // Options
        "option.payload": "A fixed demo payload, never free text, so every token here is a demo token. JWS: `polyjose example payload`. JWT: `iss`, `aud`, `sub`, and `exp` five minutes from now.",
        "option.rsa-size": "The RSA modulus: 2048, 3072 or 4096 bits (at least 2048, RFC 7518 §3.3). StrongBox: 2048 only. Bigger keys are slower to create and use.",
        "option.curve": "The curve of an ECDH-ES key: P-256, P-384, P-521 or X25519.",
        "option.access.userPresence": "The user confirms each use with Face ID, Touch ID or the device passcode.",
        "option.access.biometryAny": "The user confirms each use with Face ID or Touch ID, with any enrolled face or finger, including ones enrolled later.",
        "option.access.biometryCurrentSet": "The user confirms each use with Face ID or Touch ID, with the faces or fingers enrolled now; a change to them makes the key unusable.",
        "option.access.devicePasscode": "The user confirms each use with the device passcode.",
        "option.access.shared-context": "One LAContext for the key's calls (kSecUseAuthenticationContext): after the user authenticates once, later calls with the same context don't ask again.",

        // Refusal reasons
        "reason.symmetric": "Platform keys here are private keys for signatures, ECDH and RSA-OAEP-256. HMAC and AES keys stay in software.",
        "reason.no-curve25519": "Neither key store here offers Ed25519 or X25519; they run in software.",
        "reason.secure-enclave-p256": "The Secure Enclave holds P-256 keys only: ES256 and ECDH-ES on P-256.",
        "reason.no-secure-enclave": "This device has no Secure Enclave.",
        "reason.no-lock-screen": "Set a screen lock first: a key that needs user authentication needs a secure lock screen.",
        "reason.simulator-secure-enclave-auth": "The Simulator's Secure Enclave can't create a key that needs user authentication. Try it on an iPhone, or with a Keychain key here.",
        "reason.software-not-stored": "A software key isn't stored anywhere, so there is nothing to delete.",

        // Failure actions
        "failure.sign.tamper": "One character of the payload changed, so the signature no longer matches (RFC 7515 §5.2 step 8).",
        "failure.sign.other-alg": "The verifier allows only another algorithm. polyjose never trusts the token's `alg` alone (RFC 8725 §3.1).",
        "failure.sign.wrong-key": "Another key of the same algorithm verifies, and its signature check fails (RFC 7515 §5.2 step 8).",
        "failure.sign.expired": "The JWT's `exp` is an hour ago and the leeway is 0 (RFC 7519 §4.1.4).",
        "failure.sign.deleted-key": "The key was deleted, so opening it again by its name finds nothing.",
        "failure.encrypt.tamper": "One character of the ciphertext changed. Every decryption failure gives the same code, so it reveals nothing (RFC 7516 §11.5).",
        "failure.encrypt.other-alg": "The recipient allows only another `alg` (RFC 8725 §3.1).",
        "failure.encrypt.wrong-key": "Another key of the same kind decrypts, and decryption fails (RFC 7516 §11.5).",
        "failure.encrypt.deleted-key": "The key was deleted, so opening it again by its name finds nothing.",

        // Error codes: the meaning, then what an app does about it
        "error.InvalidBase64": "A token part or key member isn't valid base64url (RFC 7515 §2). Reject the input.",
        "error.InvalidJson": "A header, claims set or JWK isn't a valid JSON object, or names a member twice (RFC 7515 §5.2). Reject the input.",
        "error.InvalidHeader": "The JOSE header is malformed, for example `alg` is missing (RFC 7515 §4.1). Reject the token.",
        "error.UnsupportedAlgorithm": "The algorithm isn't available, or not with this key store, device or option. Pick another algorithm or store; retrying won't help.",
        "error.AlgorithmNotAllowed": "The token's algorithm isn't in the allow-list the app passed (RFC 8725 §3.1); `none` is never allowed. Reject the token.",
        "error.InvalidKey": "The key is malformed or too weak, for example RSA under 2048 bits (RFC 7518 §6). Use a valid key.",
        "error.KeyAlgorithmMismatch": "The key is valid but bound to another algorithm or use (RFC 8725 §3.1). Use the key made for this algorithm.",
        "error.InvalidSignature": "The signature doesn't verify (RFC 7515 §5.2 step 8): the token was changed, or another key signed it. Reject the token.",
        "error.DecryptionFailed": "Decryption failed. The cause is never told apart (RFC 7516 §11.5). Reject the token.",
        "error.UnknownCritical": "The `crit` header names an extension polyjose doesn't understand (RFC 7515 §4.1.11). Reject the token.",
        "error.TokenExpired": "The JWT's `exp` has passed, allowing for the leeway (RFC 7519 §4.1.4). Get a fresh token.",
        "error.TokenNotYetValid": "The JWT's `nbf` hasn't been reached yet (RFC 7519 §4.1.5). Reject it, or check the clocks.",
        "error.InvalidClaim": "A JWT claim is missing or wrong, for example `iss` or `aud` (RFC 7519 §4.1; RFC 8725 §3.8, §3.9). Reject the token.",
        "error.RandomnessUnavailable": "The OS random number generator failed; polyjose never falls back to a weaker one (RFC 8725 §3.5). Report it.",
        "error.InvalidFormat": "The input doesn't have the shape its RFC requires, for example a compact JWS without three parts (RFC 7515 §7.1), or it is over a size limit. Reject the input.",
        "error.NoMatchingKey": "No key in the JWK Set matches the token's `kid` and `alg` (RFC 7517 §5). Refresh the key set once, then reject.",
        "error.MultipleMatchingKeys": "More than one key in the JWK Set matches (RFC 7517 §5). Give the keys distinct `kid`s.",
        "error.KeyNotFound": "No usable key under that name: none was created, it was deleted, or the platform invalidated it. Create a new key.",
        "error.UserAuthenticationRequired": "The key needs the user to authenticate, and they haven't, cancelled, or can't (lockout, no biometrics). Prompt, then retry.",
        "error.PlatformKeyFailed": "Any other key store failure, for example a name that already holds a key, or StrongBox required and absent. Report it; retrying may not help.",
    ]
}
