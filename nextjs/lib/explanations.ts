// The playground's explanation texts, keyed by id: the info buttons, the disabled rows and the
// result card show them. Nothing here calls polyjose or holds a secret, so both the page and
// the server may import it.
//
// The first part is the canonical text of PLAYGROUND.md ("Explanations") for every id that
// applies in a browser, copied as it is there. The second part adds the ids this web
// playground needs and the mobile ones don't: the Server tab, the algorithms @polyjose/wasm
// offers beyond that table, the disabled key-store rows and the browser note.
// A text never contains key material, a token's secret parts or a library error message.

/** The texts of PLAYGROUND.md, unchanged. */
const CONTRACT = {
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

  // Key management (alg of a JWE)
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

  // Content encryption (enc)
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
  "key.test-rsa": "The RFC 7515 Appendix A.2 RSA key: a published test key, never use it in production. polyjose 0.4.0 can't generate RSA keys, so software RSA uses it.",

  // Options
  "option.payload": "A fixed demo payload, never free text, so every token here is a demo token. JWS: `polyjose example payload`. JWT: `iss`, `aud`, `sub`, and `exp` five minutes from now.",
  "option.curve": "The curve of an ECDH-ES key: P-256, P-384, P-521 or X25519.",

  // Refusal reasons
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

  // Error codes
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
} as const;

/** The texts this web playground adds. */
const BROWSER = {
  // Tabs
  "tab.server":
    "Tokens crossing between this page (`@polyjose/wasm`) and the app's route handlers (`@polyjose/node`). Each button is one round trip, and the log shows both sides' steps.",

  // Algorithms @polyjose/wasm 0.4.0 offers beyond the shared table
  "alg.ES256K": "ECDSA on secp256k1 with SHA-256 (RFC 8812 §3.2). In software only.",
  "alg.Ed25519":
    "Ed25519 signatures under the fully specified name `Ed25519` (RFC 9864 §2.2): the same signatures as `EdDSA` with an Ed25519 key, without a second algorithm name to check.",
  "alg.PBES2-HS256+A128KW":
    "Password-based key wrap (RFC 7518 §4.8): PBKDF2 with HMAC SHA-256 turns the password, a random salt (`p2s`) and an iteration count (`p2c`) into a 128-bit key that wraps the content key with AES Key Wrap.",
  "alg.PBES2-HS384+A192KW": "Password-based key wrap (RFC 7518 §4.8): PBKDF2 with HMAC SHA-384, and a 192-bit AES Key Wrap key.",
  "alg.PBES2-HS512+A256KW": "Password-based key wrap (RFC 7518 §4.8): PBKDF2 with HMAC SHA-512, and a 256-bit AES Key Wrap key.",
  "crv.secp256k1": "The secp256k1 curve (RFC 8812 §3.1), for ES256K signatures. polyjose doesn't use it for ECDH-ES.",
  "key.password":
    "The PBES2 password here is 16 random bytes made in this page, shown like a shared key: its length only, never its value.",

  // Stores and the browser
  "store.platform":
    "Platform key store: not in polyjose 0.4.0. polyjose has no browser key store, so a browser key can't be kept by the operating system or the browser for this page.",
  "store.webcrypto":
    "WebCrypto non-extractable key: not in polyjose 0.4.0. Every polyjose key is a JWK, so polyjose can't use a `CryptoKey` that keeps its private part out of JavaScript.",
  "reason.not-in-polyjose": "not in polyjose 0.4.0",
  "note.browser":
    "In a browser, the software keys live in page memory, and any script on the page can read them: another script, an extension or an injected script can copy a private key. Keep the page's scripts to your own, and use a server key or a platform key store for keys that matter.",
  "reason.rsa-wrong-key":
    "Not offered for RSA: the only software RSA private key is the RFC 7515 Appendix A.2 test key, and polyjose 0.4.0 can't generate another.",
  "reason.rsa-other-alg":
    "Not offered for RSA: the only software RSA private key is the RFC 7515 Appendix A.2 test key, and polyjose 0.4.0 can't generate another.",
  "reason.eddsa-other-alg": "Not offered for EdDSA: an Ed25519 key has no other signing algorithm to allow.",
  "note.decrypt-failures":
    "On the decrypt side, a wrong key and a changed token both give `DecryptionFailed`, never a key or key-store code: the recipient can't tell the causes apart, and neither can an attacker (RFC 7516 §11.5).",
  "reason.expired-is-jwt": "Expiry (`exp`) is a JWT claim, so this action signs a JWT whatever the operation above.",

  // The server tab's failure actions
  "failure.server.alg-not-allowed":
    "The browser signs with ES384 and the server allows only ES256. The server's allow-list decides, never the token's `alg` (RFC 8725 §3.1).",
  "failure.server.tampered":
    "The browser changes one character of the payload after signing, so the server's signature check fails (RFC 7515 §5.2 step 8).",
  "failure.server.jwe-tampered":
    "The browser changes one character of the ciphertext after encrypting to the server's key. The server's decryption fails with `DecryptionFailed`, the one code for every decryption failure (RFC 7516 §11.5).",
  "failure.server.none":
    "The browser sends an Unsecured JWS (`alg: none`, RFC 7515 Appendix A.5). No allow-list holds `none` (RFC 8725 §3.2).",

  // The app's own codes, which aren't polyjose codes
  "error.BadRequest": "The route handler couldn't use the request: a missing field, or a body that isn't a JSON object. Fix the request.",
  "error.BodyTooLarge": "The request body is over the route's size limit. Reject the input.",
  "error.PrivateKeySent":
    "The request held a JWK with a private or symmetric member. A client sends public keys only; the server refuses and never logs it.",
  "error.NothingToVerify": "Sign first: there is no token to verify yet.",
  "error.NothingToDecrypt": "Encrypt first: there is no token to decrypt yet.",
  "error.BadResponse": "The server's answer didn't arrive or wasn't the expected JSON. Check that the server is running.",
} as const;

export const EXPLANATIONS: Readonly<Record<string, string>> = { ...CONTRACT, ...BROWSER };

/** The text of `id`, or a fallback that names the id (an id without a text is a bug to fix). */
export function explain(id: string): string {
  return EXPLANATIONS[id] ?? `(no text for ${id})`;
}

/** The explanation of an error code: `error.<Code>`. */
export function explainCode(code: string): string {
  return explain(`error.${code}`);
}
