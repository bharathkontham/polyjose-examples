# Playground

The playground is the interactive part of the example apps. You pick an operation, a key store, an algorithm and its options, run it, and see every step: the key, where the platform says it lives, the call, the header and token, the result, and the timings. A **Try a failure** menu shows how each misuse is refused, and with which error code.

This file is the contract every playground follows, for polyjose **0.4.0**: the tabs, what is enabled where (and the code a refused combination gives), the explanation texts, the log format, the secrets rule and the key names. The iOS and Android apps implement it. Most of it applies to any app: the explanation ids, the log format, the secrets rule and the **Software** column. Each platform key store is its own column, with its own notes, so a playground on another platform adds its column and notes and leaves the others as they are.

The playground calls the same example files as the [checks](CATALOG.md): there is one implementation of each key store.

## Tabs

| Tab | Content |
|---|---|
| **Checks** | The catalog run and **Run again**, as without the playground. The app opens on this tab. |
| **Sign** | Operation: JWS compact or JWT. Key store. Algorithm: one row per algorithm; a disabled row shows its reason; each row has an info button. Key options: RSA size, StrongBox mode, user authentication. Key: a new key, or one from the Keys tab. Payload: a fixed preset. Buttons: **Sign**, **Verify**, **Sign and verify**. **Try a failure**: tamper, other algorithm allowed, wrong key, expired, deleted key. The result card below. |
| **Encrypt** | Key-management `alg`, `enc`, curve or RSA size, and the key store that decrypts. **Encrypt** (always in software, to the key's public JWK), **Decrypt**, **Round trip**. **Try a failure**: tamper ciphertext, other `alg` allowed, wrong key, deleted key. The result card below. |
| **Keys** | A "This device" card (OS, model, emulator or Simulator, Secure Enclave, StrongBox, API level, screen lock). The playground's keys grouped by store: tag or alias, algorithm, where the platform reports the key lives, authentication. A key's detail shows its public JWK (copy), its RFC 7638 thumbprint, **Open again** and **Delete**. **Create key**, **Delete all playground keys**. |
| **Log** | Entries newest first, grouped by tap (`#12 Sign JWS ES256 · Secure Enclave`), one line per step. **Copy all**, **Share**, **Clear**. |

**The result card** shows the token (monospaced, with a copy button) and its protected header, then the outcome: the verified `alg` and `kid` and the claims, or that the decrypted plaintext equals the input. On a failure it shows the error code and its explanation. It ends with "Key lives in: <reported value>" and the time of each step.

Every polyjose call runs off the main thread: a key with user authentication shows a system prompt during the call and blocks its thread until the prompt closes.

## Support matrix

`✓` = enabled. A number = the lowest Android API level. `✗` = disabled: the playground shows the reason, and **Run anyway** makes the call and shows the code in the last column. The app holds this table itself, because polyjose has no "is this supported here" query; the [demo walk](#demo-walk) runs every cell, so a cell where the app and the library disagree fails the walk.

- **Software** is a polyjose JWK in app memory, on any platform. polyjose 0.4.0 can't generate RSA keys, so software RS\*, PS\* and RSA-OAEP-256 use the RFC 7515 Appendix A.2 test key, labelled as one (`key.test-rsa`).
- **iOS Keychain** and **Secure Enclave** are `AppleKey` protections (`.keychain`, `.secureEnclave`). **Android Keystore (TEE)** and **StrongBox** are `AndroidKeystoreKey` with `StrongBox.Off` and `StrongBox.Required`.

### Signing (JWS compact and JWT)

| Algorithm | Software | [Browser](#web-notes) | iOS Keychain | Secure Enclave | Android Keystore (TEE) | StrongBox | Refusal when ✗ |
|---|---|---|---|---|---|---|---|
| HS256, HS384, HS512 | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | `UnsupportedAlgorithm` |
| ES256 | ✓ | ✓ | ✓ | ✓ | 23 | 28 | — |
| ES384, ES512 | ✓ | ✓ | ✓ | ✗ | 23 | ✗ | `UnsupportedAlgorithm` |
| RS256, PS256 | ✓ (A.2 key) | ✓ (A.2 key) | ✓ 2048/3072/4096 | ✗ | 23, 2048/3072/4096 | 28, 2048 only | `UnsupportedAlgorithm` |
| RS384, RS512, PS384, PS512 | ✓ (A.2 key) | ✓ (A.2 key) | ✓ 2048/3072/4096 | ✗ | 23, 2048/3072/4096 | ✗ | `UnsupportedAlgorithm` |
| EdDSA (Ed25519) | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | `UnsupportedAlgorithm` |

### Decryption (JWE compact)

Encryption is always done in software, to the key's public JWK. The store column is the key that decrypts.

| `alg` | Software | [Browser](#web-notes) | iOS Keychain | Secure Enclave | Android Keystore (TEE) | StrongBox | Refusal when ✗ |
|---|---|---|---|---|---|---|---|
| ECDH-ES, ECDH-ES+A128KW, +A192KW, +A256KW on P-256 | ✓ | ✓ | ✓ | ✓ | 31 | 31 | `UnsupportedAlgorithm` (below 31 too) |
| the same on P-384 and P-521 | ✓ | ✓ | ✓ | ✗ | 31 | ✗ | `UnsupportedAlgorithm` |
| the same on X25519 | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | `UnsupportedAlgorithm` |
| RSA-OAEP-256 | ✓ (A.2 key) | ✓ (A.2 key) | ✓ 2048/3072/4096 | ✗ | 34 (keys created on 34 or later) | 34, 2048 only, *not verified on a StrongBox device* | `UnsupportedAlgorithm` |
| A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW, `dir` | ✓ (oct key) | ✓ (oct key) | ✗ | ✗ | ✗ | ✗ | `UnsupportedAlgorithm` |

- **`enc`:** A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384 and A256CBC-HS512, with every store. Content encryption is always polyjose's, in software.
- **Below an API level** the cell is ✗ with `reason.api-level`, and Run anyway gives `UnsupportedAlgorithm`.
- **Precedence.** The library checks in this order: the algorithm table, then the API level and the key options, then the device (a Secure Enclave or StrongBox present, a secure lock screen). When a cell breaks several rules, its refusal code is that of the first rule that fails in this order, and the playground shows that rule's reason.

### Apple notes

- **No Secure Enclave** ([`SecureEnclave.isAvailable`](https://developer.apple.com/documentation/cryptokit/secureenclave/isavailable) false): the Secure Enclave column is ✗ with `reason.no-secure-enclave`; Run anyway gives `UnsupportedAlgorithm` from `AppleKey.generate`. There is no fallback to the Keychain.
- **User authentication:** the four access flags (`option.access.*`, [`SecAccessControlCreateFlags`](https://developer.apple.com/documentation/security/secaccesscontrolcreateflags)), on Keychain and Secure Enclave keys. A cancelled, failed or impossible authentication gives `UserAuthenticationRequired`.
  - **With no passcode set** ([`canEvaluatePolicy(.deviceOwnerAuthentication)`](https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)) false): the playground disables every access flag, on Keychain and Secure Enclave keys, with `reason.no-lock-screen`. Run anyway is expected to give `UserAuthenticationRequired`; this is not yet confirmed on a device without a passcode.
  - **On the iOS Simulator** a Secure Enclave key with any of the four flags can't be created: `AppleKey.generate` gives `UserAuthenticationRequired` at once, with no prompt. Keychain keys with the same flags are created. So on the Simulator only, the playground disables the four flags for the Secure Enclave with `reason.simulator-secure-enclave-auth`, and Run anyway gives `UserAuthenticationRequired`.
  - **One shared `LAContext`** (`option.access.shared-context`): with a flag chosen, a toggle passes the playground's one [`LAContext`](https://developer.apple.com/documentation/localauthentication/lacontext), made on first use, to the key's calls (`AppleKey.Access.context`, [`kSecUseAuthenticationContext`](https://developer.apple.com/documentation/security/ksecuseauthenticationcontext)), so after one authentication the later calls with it don't ask again.
  - **The Keys tab** shows a key's access flag only for keys made since the app started. For any other key it shows "not reported by iOS": the attributes that listing reads don't say which flag a key has.
- **X25519** has no Apple key type. With the Keychain or the Secure Enclave, Run anyway asks `AppleKey.generate` for an `ECDH-ES` key of 255 bits (RFC 7748 §4.1) and gets `UnsupportedAlgorithm`.
- **[Wrong-key decryption](#wrong-key-decryption)** encrypts to the chosen key and decrypts with a new key of the same kind in the same store, which it deletes afterwards.
- **Where a key lives** is `AppleKey.protection`, which the platform reports for the key ([`kSecAttrTokenID`](https://developer.apple.com/documentation/security/ksecattrtokenid)), not the protection asked for.

### Android notes

- **No StrongBox** ([`PackageManager.FEATURE_STRONGBOX_KEYSTORE`](https://developer.android.com/reference/android/content/pm/PackageManager)):
  - `StrongBox.Required` is ✗ with `reason.no-strongbox`; from API 28, Run anyway gives `PlatformKeyFailed`, and no key is left behind. Below API 28 the StrongBox cells are ✗ with `reason.api-level` (StrongBox needs API 28), and the library gives `UnsupportedAlgorithm` before it asks the Keystore.
  - `StrongBox.Preferred` is enabled and labelled "falls back to the TEE; the key reports where it went": it succeeds, and `securityLevel` is not `StrongBox`: `TrustedEnvironment` on a device, `Software` on the `polyjose-api34` emulator.
  - A StrongBox cell that is ✗ in the tables gives `UnsupportedAlgorithm` under `Required`, with or without StrongBox.
- **User authentication** ([`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)):
  - None (`option.auth.none`): the key works whenever the app calls it.
  - Time-bound (`option.auth.time-bound`): every key kind, with a window of 10, 30 or 60 seconds. **Authenticate now** shows the framework `BiometricPrompt`, with no crypto object, and opens the window; it is a tap of its own (`op=authenticate`, see [Log](#log)).
  - Per use (`option.auth.per-use`): signing and RSA-OAEP-256 keys. An ECDH key is ✗ with `reason.per-use-ecdh`; Run anyway gives `UnsupportedAlgorithm`.
  - `option.auth.device-credential` is a free choice from API 30; below 30 the platform decides it.
  - The playground offers keys with user authentication from API 28, because it shows the framework [`BiometricPrompt`](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt). Below 28 they are ✗ with `reason.api-level`.
  - A device with no secure lock screen: every user-authentication option is ✗ with `reason.no-lock-screen`, and Run anyway gives `PlatformKeyFailed` (time-bound and per use, signing and RSA-OAEP-256 keys, every store). Per use on an ECDH key gives `UnsupportedAlgorithm` with `reason.per-use-ecdh` first, because the table is checked before the device.
- **[Wrong-key decryption](#wrong-key-decryption)** encrypts to another software key of the same kind and decrypts with the chosen key. For a platform RSA-OAEP-256 key, the other key is the RFC 7515 Appendix A.2 public key.
- **Where a key lives** is `AndroidKeystoreKey.securityLevel`, read from [`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo): `StrongBox`, `TrustedEnvironment`, `Software` or `Unknown` from API 31. Below 31, or when the platform reports an unnamed secure level, it is `SecureHardware`: the platform doesn't say whether the key is in the TEE or StrongBox.

### Web notes

The **Browser** column is the Next.js app's playground (`nextjs/`): `@polyjose/wasm` 0.4.0 in the page, with software keys only, and `@polyjose/node` 0.4.0 in the route handlers for the Server tab. Its matrix is `nextjs/lib/matrix.ts`, and its explanation texts are `nextjs/lib/explanations.ts`.

- **Software keys live in page memory, and any script on the page can read them** (`note.browser`, shown at the top of the page and on the Keys tab). The result card says "Key lives in: page memory (software, readable by any script on this page)". **Delete** drops the page's reference to a key; JavaScript can't wipe the memory, and closing the tab ends it.
- **Key stores.** The Sign, Encrypt and Keys tabs show two more store rows, **Platform key store** (`store.platform`) and **WebCrypto non-extractable key** (`store.webcrypto`), both disabled with `reason.not-in-polyjose`, "not in polyjose 0.4.0". They have no call to make, so there is no **Run anyway**, and the demo walk doesn't count them.
- **RSA** is the RFC 7515 Appendix A.2 test key (`key.test-rsa`) at 2048 bits; there is no RSA size option. There are no StrongBox or user-authentication options.
- **Algorithms beyond the tables**, all in software, which `@polyjose/wasm` 0.4.0 offers:
  - signing: ES256K (`alg.ES256K`, `crv.secp256k1`; RFC 8812 §3.2), and `Ed25519`, the fully specified name of EdDSA with an Ed25519 key (`alg.Ed25519`; RFC 9864 §2.2);
  - key management: PBES2-HS256+A128KW, PBES2-HS384+A192KW and PBES2-HS512+A256KW (`alg.PBES2-*`; RFC 7518 §4.8). The password is 16 random bytes made in the page, shown like a shared key, by its length only (`key.password`).
  - polyjose 0.4.0 refuses RSA-OAEP and RSA1_5 with `UnsupportedAlgorithm`, so they aren't rows.
- **Failure actions.**
  - Deleted key: disabled with `reason.software-not-stored`, as for every software key.
  - Wrong key and other algorithm allowed: disabled for RS\*, PS\* and RSA-OAEP-256 (`reason.rsa-wrong-key`, `reason.rsa-other-alg`), because the only software RSA private key is the A.2 test key and polyjose 0.4.0 can't generate another.
  - Other algorithm allowed: disabled for EdDSA and `Ed25519` (`reason.eddsa-other-alg`), because an Ed25519 key has no other signing algorithm.
  - Expired always signs a JWT, whatever the operation (`reason.expired-is-jwt`).
  - A disabled action isn't a demo walk step.
- **Decrypt-side key failures are `DecryptionFailed`.** A wrong key and a changed JWE both give `DecryptionFailed`, never a key or key-store code (`note.decrypt-failures`, on the Encrypt and Server tabs; RFC 7516 §11.5). polyjose 0.4.0 refuses a decryption key whose `kid` differs from the header's `kid` with `KeyAlgorithmMismatch` before it decrypts, so the Encrypt tab's JWEs carry no `kid`: each goes to one known key. The Server tab's JWEs keep the recipient's `kid`.
- **Tabs.**
  - **Checks** runs the eight [Next.js checks](CATALOG.md#nextjs-checks), not 1–34, and has a **Run the demo walk** button.
  - **Server** (`tab.server`), between Encrypt and Keys: the four crossings (`browser-signs`, `server-issues`, `browser-encrypts`, `server-encrypts`) and the server's four refusals, one button each. The refusals are `failure.server.alg-not-allowed` (`AlgorithmNotAllowed`), `failure.server.tampered` (`InvalidSignature`), `failure.server.none` (`AlgorithmNotAllowed`) and `failure.server.jwe-tampered` (`DecryptionFailed`).
  - **Keys** has a "This browser" card instead of "This device": the polyjose version, the browser, whether the page is a secure context, and whether WebCrypto is present (polyjose 0.4.0 doesn't use `CryptoKey` objects). Keys are named by `kid`, not by tag or alias: an asymmetric key's RFC 7638 thumbprint, or `secret-<n>` for a shared key. The [key names](#key-names) don't apply, and there is no **Open again**, because nothing is stored.
- **Calls run on the page's thread.** No call shows a prompt, so none blocks waiting for one.
- **Explanation ids the web adds**, besides the ids above: `error.BadRequest`, `error.BodyTooLarge`, `error.PrivateKeySent`, `error.NothingToVerify`, `error.NothingToDecrypt` and `error.BadResponse`. These are the app's own codes, not polyjose codes. The web keeps only the shared ids that apply in a browser, so it has no ids for the platform stores, their options or their refusal reasons.
- **Log.** The format and the secrets rule are as above.
  - Every line also goes to `console.log` in the page. The route handlers write their lines to the server's stdout and return them in the answer (`steps`), and the Log tab shows them under the tap: `LOG <tap>.s<n> …`. The server logs `LOG 0.1 server-keys source=… signing=<kid> decryption=<kid>` once, when it makes or reads its keys.
  - `device` has `polyjose`, `browser`, `secure-context`, `webcrypto`, `platform-key-store=false` and `non-extractable-keys=false`.
  - `input` may also carry `crossing`, `kid` and `count`; on the server it may carry `allowedAlgs` and `allowedEnc`, comma-separated. `op` adds `crossing` and `key-show`, and `failure` adds `server.alg-not-allowed`, `server.tampered`, `server.none` and `server.jwe-tampered`.
  - `key-software` may also carry `crv` and `enc`. `key-delete` is a software key the page dropped: `kid`, `alg`. `note` has `shared=true` when a shared key is shown, because a shared key has no public JWK. `error` also carries `call` (the step that failed) in the page, and `route` on the server. The server's `verify` and `decrypt` lines carry no `ms`, because its `call` lines carry the times, and its `verify` line carries `bytes` (the payload length) in place of `kid`.
  - New events: `request` (`method` and `route` in the page, `route` on the server), `response` (`status`, `ok`, `ms`), `jwks` (`keys`, the number of keys, then the JWK Set through the public-only gate), and `secrets` (`lines`, `matches`), the demo walk's last step.
- **Demo walk.** `npm run verify` opens `/?verify=1&demo=1` in headless Chrome and prints `POLYJOSE-VERIFY: 8/8 PASS`, then `POLYJOSE-PLAYGROUND: 330/330 OK` ([CATALOG.md](CATALOG.md#nextjs-checks)). The walk covers every enabled cell and every enabled failure action of the Browser column and the rows above, then Verify and Decrypt as second taps, the Keys tab, the Server tab's eight buttons and the secrets check over its own log. A disabled cell has no call, so it isn't a step. The secrets grep also fails the run on an unhandled `PolyjoseError` in the browser console or the server output.

## Failure actions

Each action is one tap. It logs every step and ends with the code below.

| Id | Tab | What it does | Code |
|---|---|---|---|
| `failure.sign.tamper` | Sign | Signs, changes one character in the middle of the payload part (`A`↔`B`), and verifies | `InvalidSignature` |
| `failure.sign.other-alg` | Sign | Signs, then verifies with an allow-list that names only another algorithm of the same key type (ES256 → `["ES384"]`) | `AlgorithmNotAllowed` |
| `failure.sign.wrong-key` | Sign | Signs, then verifies with the public key (for HS\*, the secret) of another key of the same algorithm | `InvalidSignature` |
| `failure.sign.expired` | Sign (JWT) | Signs a JWT whose `exp` is an hour ago, then verifies with leeway 0 | `TokenExpired` |
| `failure.sign.deleted-key` | Sign (platform keys) | Creates a key, deletes it, then opens it again by its tag or alias | `KeyNotFound` |
| `failure.encrypt.tamper` | Encrypt | Encrypts, changes one character in the middle of the ciphertext part, and decrypts | `DecryptionFailed` |
| `failure.encrypt.other-alg` | Encrypt | Encrypts, then decrypts with an `alg` allow-list that names only another `alg` | `AlgorithmNotAllowed` |
| `failure.encrypt.wrong-key` | Encrypt | Encrypts to one key and decrypts with another key of the same `alg` and curve or size ([below](#wrong-key-decryption)) | `DecryptionFailed` |
| `failure.encrypt.deleted-key` | Encrypt (platform keys) | Creates a key, deletes it, then opens it again by its tag or alias | `KeyNotFound` |

With a software key, the two deleted-key actions are disabled with `reason.software-not-stored`. In the iOS and Android playgrounds, two more cases have no second key to use (the Browser column's rules for them are in [Web notes](#web-notes)):

- **Software RS\*, PS\* and RSA-OAEP-256:** `failure.sign.wrong-key` and `failure.encrypt.wrong-key` are disabled with `key.test-rsa`, because the RFC 7515 Appendix A.2 test key is the only software RSA private key.
- **EdDSA:** no other signing algorithm uses an Ed25519 key, so `failure.sign.other-alg` verifies with `["ES256"]`. The code is the same, `AlgorithmNotAllowed`, because the allow-list is checked before the key (RFC 8725 §3.1).

### Wrong-key decryption

`failure.encrypt.wrong-key` ends with `DecryptionFailed` (RFC 7516 §11.5). The playground's JWEs carry no `kid`, so polyjose doesn't refuse the key on a `kid` mismatch first: when the JWE and the key both carry a `kid` and they differ, polyjose 0.4.0 gives `KeyAlgorithmMismatch` before it decrypts (RFC 7516 §4.1.6). Which key encrypts and which decrypts is in each platform's notes ([Apple](#apple-notes), [Android](#android-notes)).

## Explanations

Every tab, algorithm, `enc`, curve, store, option, refusal reason, failure action and error code has an id and one canonical text. Each app keeps them in one explanations file, keyed by id, with this text. The info buttons, the disabled rows and the result card show them.

**Wording.** "Hardware" is used for the Secure Enclave and StrongBox only. The Keychain is "stored and protected by the OS, not hardware-bound; on iOS, code that holds the key reference can export the private key". The TEE is "isolated from Android in the device's trusted execution environment; on an emulator the keys are software, whatever it reports". The Simulator's Secure Enclave is "a host pass-through, not a hardware guarantee". A text never contains key material, a token's secret parts or a library error message.

### Tabs

| Id | Text |
|---|---|
| `tab.checks` | Every check of the catalog, run against the polyjose release this app pins. |
| `tab.sign` | Sign a JWS or JWT with a key from any store, verify it in software, and try how misuse is refused. |
| `tab.encrypt` | Encrypt to a key's public JWK in software, decrypt with the key in its store, and try how misuse is refused. |
| `tab.keys` | The playground's keys in each store, where the platform says each one lives, and this device's capabilities. |
| `tab.log` | Every step of every tap, newest first. It holds no secrets, so it can be copied and shared. |

### Signing algorithms

| Id | Text |
|---|---|
| `alg.HS256` | HMAC with SHA-256 (RFC 7518 §3.2). One shared secret, at least 32 bytes, both signs and verifies, so whoever can verify can also sign. |
| `alg.HS384` | HMAC with SHA-384 (RFC 7518 §3.2). One shared secret, at least 48 bytes, both signs and verifies. |
| `alg.HS512` | HMAC with SHA-512 (RFC 7518 §3.2). One shared secret, at least 64 bytes, both signs and verifies. |
| `alg.RS256` | RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies. |
| `alg.RS384` | RSASSA-PKCS1-v1_5 with SHA-384 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies. |
| `alg.RS512` | RSASSA-PKCS1-v1_5 with SHA-512 (RFC 7518 §3.3). An RSA private key of 2048 bits or more signs; its public key verifies. |
| `alg.PS256` | RSASSA-PSS with SHA-256 and MGF1 with SHA-256 (RFC 7518 §3.5): RSA with randomized padding, so signing the same input twice gives two signatures. |
| `alg.PS384` | RSASSA-PSS with SHA-384 and MGF1 with SHA-384 (RFC 7518 §3.5): RSA with randomized padding. |
| `alg.PS512` | RSASSA-PSS with SHA-512 and MGF1 with SHA-512 (RFC 7518 §3.5): RSA with randomized padding. |
| `alg.ES256` | ECDSA on P-256 with SHA-256 (RFC 7518 §3.4). Small keys and signatures; the one signing algorithm the Secure Enclave serves. |
| `alg.ES384` | ECDSA on P-384 with SHA-384 (RFC 7518 §3.4). |
| `alg.ES512` | ECDSA on P-521 with SHA-512 (RFC 7518 §3.4). |
| `alg.EdDSA` | Ed25519 signatures (RFC 8037 §3.1): deterministic, with small keys. polyjose signs in software; neither key store here offers Ed25519. |

### Key management (`alg` of a JWE)

| Id | Text |
|---|---|
| `alg.ECDH-ES` | Ephemeral-static ECDH (RFC 7518 §4.6): the sender makes a one-time key pair, agrees a secret with the recipient's public key, and derives the content key from it with the Concat KDF. No encrypted key is sent. |
| `alg.ECDH-ES+A128KW` | ECDH-ES (RFC 7518 §4.6), whose derived 128-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4). |
| `alg.ECDH-ES+A192KW` | ECDH-ES (RFC 7518 §4.6), whose derived 192-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4). |
| `alg.ECDH-ES+A256KW` | ECDH-ES (RFC 7518 §4.6), whose derived 256-bit key wraps a random content key with AES Key Wrap (RFC 7518 §4.4). |
| `alg.RSA-OAEP-256` | RSAES-OAEP with SHA-256 and MGF1 with SHA-256 (RFC 7518 §4.3): the content key is encrypted to the recipient's RSA public key. |
| `alg.A128KW` | AES Key Wrap with a 128-bit shared key (RFC 7518 §4.4): sender and recipient hold the same secret key. |
| `alg.A192KW` | AES Key Wrap with a 192-bit shared key (RFC 7518 §4.4). |
| `alg.A256KW` | AES Key Wrap with a 256-bit shared key (RFC 7518 §4.4). |
| `alg.A128GCMKW` | AES-GCM key encryption with a 128-bit shared key (RFC 7518 §4.7); the `iv` and `tag` header parameters carry its nonce and tag. |
| `alg.A192GCMKW` | AES-GCM key encryption with a 192-bit shared key (RFC 7518 §4.7). |
| `alg.A256GCMKW` | AES-GCM key encryption with a 256-bit shared key (RFC 7518 §4.7). |
| `alg.dir` | Direct encryption with a shared key (RFC 7518 §4.5): the shared key is the content key, so no key is sent, and its size must fit `enc`. |

### Content encryption (`enc`)

| Id | Text |
|---|---|
| `enc.A128GCM` | AES-GCM with a 128-bit content key (RFC 7518 §5.3): authenticated encryption, so any change to the ciphertext, IV, tag or protected header makes decryption fail. |
| `enc.A192GCM` | AES-GCM with a 192-bit content key (RFC 7518 §5.3). |
| `enc.A256GCM` | AES-GCM with a 256-bit content key (RFC 7518 §5.3). |
| `enc.A128CBC-HS256` | AES-128-CBC, then HMAC SHA-256 truncated to 128 bits (RFC 7518 §5.2.3): encrypt-then-MAC with a 256-bit content key. |
| `enc.A192CBC-HS384` | AES-192-CBC, then HMAC SHA-384 truncated to 192 bits (RFC 7518 §5.2.4), with a 384-bit content key. |
| `enc.A256CBC-HS512` | AES-256-CBC, then HMAC SHA-512 truncated to 256 bits (RFC 7518 §5.2.5), with a 512-bit content key. |

### Curves

| Id | Text |
|---|---|
| `crv.P-256` | The NIST P-256 curve (RFC 7518 §6.2.1.1). The only curve the Secure Enclave and StrongBox serve. |
| `crv.P-384` | The NIST P-384 curve (RFC 7518 §6.2.1.1). |
| `crv.P-521` | The NIST P-521 curve (RFC 7518 §6.2.1.1). |
| `crv.X25519` | Curve25519 key agreement (RFC 8037 §3.2). In software only. |

### Stores

| Id | Text |
|---|---|
| `store.software` | A polyjose JWK in this app's memory (RFC 7517 §4). Every algorithm works; the private key is ordinary app data, gone when the app quits. |
| `store.keychain` | iOS Keychain: stored and protected by the OS, not hardware-bound; on iOS, code that holds the key reference can export the private key. The key stays on this device and is never synchronized. |
| `store.secure-enclave` | Secure Enclave: a hardware-bound P-256 key, created inside the Secure Enclave and never exported from it; it serves ES256 and ECDH-ES. In the Simulator it is a host pass-through, not a hardware guarantee. |
| `store.keystore` | Android Keystore (TEE): isolated from Android in the device's trusted execution environment; on an emulator the keys are software, whatever it reports. The private key can't be exported. |
| `store.strongbox` | StrongBox: a separate hardware secure element (API 28 or later). It is slower and serves fewer algorithms: ES256, RS256 and PS256 at 2048 bits, ECDH-ES on P-256, RSA-OAEP-256 at 2048 bits. |
| `key.test-rsa` | The RFC 7515 Appendix A.2 RSA key: a published test key, never use it in production. polyjose 0.4.0 can't generate RSA keys, so software RSA uses it. |

### Options

| Id | Text |
|---|---|
| `option.payload` | A fixed demo payload, never free text, so every token here is a demo token. JWS: `polyjose example payload`. JWT: `iss`, `aud`, `sub`, and `exp` five minutes from now. |
| `option.rsa-size` | The RSA modulus: 2048, 3072 or 4096 bits (at least 2048, RFC 7518 §3.3). StrongBox: 2048 only. Bigger keys are slower to create and use. |
| `option.curve` | The curve of an ECDH-ES key: P-256, P-384, P-521 or X25519. |
| `option.strongbox.off` | The TEE. StrongBox is never asked for. |
| `option.strongbox.preferred` | StrongBox when the device has it and it can serve the algorithm, else the TEE: falls back to the TEE; the key reports where it went. |
| `option.strongbox.required` | StrongBox or nothing. Without StrongBox, creating the key fails with `PlatformKeyFailed` (API 28 or later; below 28, StrongBox is refused with `UnsupportedAlgorithm`) and no key is left behind; there is never a silent move to the TEE. |
| `option.access.userPresence` | The user confirms each use with Face ID, Touch ID or the device passcode. |
| `option.access.biometryAny` | The user confirms each use with Face ID or Touch ID, with any enrolled face or finger, including ones enrolled later. |
| `option.access.biometryCurrentSet` | The user confirms each use with Face ID or Touch ID, with the faces or fingers enrolled now; a change to them makes the key unusable. |
| `option.access.devicePasscode` | The user confirms each use with the device passcode. |
| `option.access.shared-context` | One LAContext for the key's calls (kSecUseAuthenticationContext): after the user authenticates once, later calls with the same context don't ask again. |
| `option.auth.none` | No user authentication: the key works whenever the app calls it. |
| `option.auth.time-bound` | After the user authenticates in the app's prompt, the key works for the chosen number of seconds; outside that window a call fails with `UserAuthenticationRequired`. Every key kind. |
| `option.auth.per-use` | Each signature or decryption shows a prompt bound to that one operation. Signing and RSA-OAEP-256 keys, API 28 or later. |
| `option.auth.device-credential` | The PIN, pattern or password may stand in for a strong biometric. A free choice from API 30; below that the platform decides. |

### Refusal reasons

| Id | Text |
|---|---|
| `reason.symmetric` | Platform keys here are private keys for signatures, ECDH and RSA-OAEP-256. HMAC and AES keys stay in software. |
| `reason.no-curve25519` | Neither key store here offers Ed25519 or X25519; they run in software. |
| `reason.secure-enclave-p256` | The Secure Enclave holds P-256 keys only: ES256 and ECDH-ES on P-256. |
| `reason.strongbox-algorithms` | StrongBox serves ES256, RS256 and PS256 at 2048 bits, ECDH-ES on P-256, and RSA-OAEP-256 at 2048 bits. |
| `reason.api-level` | Needs Android API <level>; this device runs API <current>. |
| `reason.no-secure-enclave` | This device has no Secure Enclave. |
| `reason.simulator-secure-enclave-auth` | The Simulator's Secure Enclave can't create a key that needs user authentication. Try it on an iPhone, or with a Keychain key here. |
| `reason.no-strongbox` | This device has no StrongBox. `Preferred` falls back to the TEE; `Required` fails. |
| `reason.per-use-ecdh` | An ECDH key can be time-bound only, not per use. |
| `reason.no-lock-screen` | Set a screen lock first: a key that needs user authentication needs a secure lock screen. |
| `reason.software-not-stored` | A software key isn't stored anywhere, so there is nothing to delete. |

### Failure actions

| Id | Text |
|---|---|
| `failure.sign.tamper` | One character of the payload changed, so the signature no longer matches (RFC 7515 §5.2 step 8). |
| `failure.sign.other-alg` | The verifier allows only another algorithm. polyjose never trusts the token's `alg` alone (RFC 8725 §3.1). |
| `failure.sign.wrong-key` | Another key of the same algorithm verifies, and its signature check fails (RFC 7515 §5.2 step 8). |
| `failure.sign.expired` | The JWT's `exp` is an hour ago and the leeway is 0 (RFC 7519 §4.1.4). |
| `failure.sign.deleted-key` | The key was deleted, so opening it again by its name finds nothing. |
| `failure.encrypt.tamper` | One character of the ciphertext changed. Every decryption failure gives the same code, so it reveals nothing (RFC 7516 §11.5). |
| `failure.encrypt.other-alg` | The recipient allows only another `alg` (RFC 8725 §3.1). |
| `failure.encrypt.wrong-key` | The token is decrypted with a key other than the one it was encrypted to, of the same kind, and decryption fails (RFC 7516 §11.5). |
| `failure.encrypt.deleted-key` | The key was deleted, so opening it again by its name finds nothing. |

### Error codes

The text gives the meaning, then what an app does about it.

| Id | Text |
|---|---|
| `error.InvalidBase64` | A token part or key member isn't valid base64url (RFC 7515 §2). Reject the input. |
| `error.InvalidJson` | A header, claims set or JWK isn't a valid JSON object, or names a member twice (RFC 7515 §5.2). Reject the input. |
| `error.InvalidHeader` | The JOSE header is malformed, for example `alg` is missing (RFC 7515 §4.1). Reject the token. |
| `error.UnsupportedAlgorithm` | The algorithm isn't available, or not with this key store, device or option. Pick another algorithm or store; retrying won't help. |
| `error.AlgorithmNotAllowed` | The token's algorithm isn't in the allow-list the app passed (RFC 8725 §3.1); `none` is never allowed. Reject the token. |
| `error.InvalidKey` | The key is malformed or too weak, for example RSA under 2048 bits (RFC 7518 §6). Use a valid key. |
| `error.KeyAlgorithmMismatch` | The key is valid but bound to another algorithm or use (RFC 8725 §3.1). Use the key made for this algorithm. |
| `error.InvalidSignature` | The signature doesn't verify (RFC 7515 §5.2 step 8): the token was changed, or another key signed it. Reject the token. |
| `error.DecryptionFailed` | Decryption failed. The cause is never told apart (RFC 7516 §11.5). Reject the token. |
| `error.UnknownCritical` | The `crit` header names an extension polyjose doesn't understand (RFC 7515 §4.1.11). Reject the token. |
| `error.TokenExpired` | The JWT's `exp` has passed, allowing for the leeway (RFC 7519 §4.1.4). Get a fresh token. |
| `error.TokenNotYetValid` | The JWT's `nbf` hasn't been reached yet (RFC 7519 §4.1.5). Reject it, or check the clocks. |
| `error.InvalidClaim` | A JWT claim is missing or wrong, for example `iss` or `aud` (RFC 7519 §4.1; RFC 8725 §3.8, §3.9). Reject the token. |
| `error.RandomnessUnavailable` | The OS random number generator failed; polyjose never falls back to a weaker one (RFC 8725 §3.5). Report it. |
| `error.InvalidFormat` | The input doesn't have the shape its RFC requires, for example a compact JWS without three parts (RFC 7515 §7.1), or it is over a size limit. Reject the input. |
| `error.NoMatchingKey` | No key in the JWK Set matches the token's `kid` and `alg` (RFC 7517 §5). Refresh the key set once, then reject. |
| `error.MultipleMatchingKeys` | More than one key in the JWK Set matches (RFC 7517 §5). Give the keys distinct `kid`s. |
| `error.KeyNotFound` | No usable key under that name: none was created, it was deleted, or the platform invalidated it. Create a new key. |
| `error.UserAuthenticationRequired` | The key needs the user to authenticate, and they haven't, cancelled, or can't (lockout, no biometrics). Prompt, then retry. |
| `error.PlatformKeyFailed` | Any other key store failure, for example a name that already holds a key, or StrongBox required and absent. Report it; retrying may not help. When decrypting, such a failure gives `DecryptionFailed` instead, so every decryption failure looks the same (RFC 7516 §11.5). |

## Log

Every step of every tap is one line, on the Log tab and on the system log:

```
LOG <tap>.<step> <event> key=value …
LOG 12.1 input op=jws-sign store=secure-enclave alg=ES256 auth=userPresence
LOG 12.2 key-create tag=dev.polyjose.examples.playground.ES256.3 reported=secureEnclave ms=41
LOG 12.3 call jwsSignCompactWithPlatformKey ms=380
LOG 12.4 header {"alg":"ES256","kid":"…"}
LOG 12.5 token eyJ…
LOG 12.6 verify ok alg=ES256 ms=2
LOG 13.3 error code=UserAuthenticationRequired ms=2110
```

- **Numbering.** `<tap>` counts taps from 1 since the app started; `<step>` counts the tap's lines from 1. Tap 0 is the `device` line, logged once at start.
- **Values.** `key=value` pairs, with no spaces in a value. Booleans are `true` and `false`. `ms` is a whole number of milliseconds from a monotonic clock; timings are shown, never checked. The `header`, `jwk`, `claims` and `token` events carry their JSON or token as the rest of the line.
- **Long lines** are split every 800 characters. Each continuation line repeats `LOG <tap>.<step>` and has `+` in place of the event: `LOG 12.5 + <next 800 characters>`. Joining the parts without separators gives the line back.
- **Mirroring.** Every mirrored line starts with `LOG `, so a check run ignores it.
  - iOS: `print`, for the Simulator and Xcode's console, and `os.Logger(subsystem: "dev.polyjose.examples", category: "playground")` with `privacy: .public`, because `print` doesn't reach Console.app from a device that isn't attached to Xcode.
  - Android: `Log.i("POLYJOSE", …)`, so `adb logcat -s POLYJOSE` shows the playground and the checks together.

| Event | Fields | When |
|---|---|---|
| `device` | `polyjose`, `os`, `model`, `simulator` or `emulator`, `secure-enclave` (iOS), `api` and `strongbox` (Android), `lock-screen` | once, at start (tap 0) |
| `input` | `op`, `store`, `alg`, and as they apply `enc`, `crv`, `size`, `strongbox`, `auth`, `seconds` (Android: the time-bound window), `device-credential` (Android, time-bound or per use: whether the PIN, pattern or password may stand in), `payload`, `key` (Android: the alias of the chosen platform key, or the number of the chosen software key), `failure`, `anyway=true` | first line of every tap |
| `key-create` | `tag` (iOS) or `alias` (Android), `reported`, `ms` | a platform key was created |
| `key-open` | `tag` or `alias`, `reported`, `ms` | a platform key was opened again |
| `key-delete` | `tag` or `alias`, `ms` | a platform key was deleted |
| `key-software` | `kty`, `alg`, `kid`, and `bits` for an oct key; `test-key=true` for the RFC 7515 A.2 key | a software key was made or chosen |
| `jwk` | the public JWK, through the public-only gate | a key's public JWK was shown or copied |
| `thumbprint` | `value`, the RFC 7638 SHA-256 thumbprint | a thumbprint was shown |
| `call` | the polyjose function name, `ms` | each polyjose call, also `jwkThumbprint` for a thumbprint and, on Android, `decodeProtectedHeaderUnverified` for the `header` line of a token it made |
| `authenticate` | `ok` or `failed`, then `result` (the framework's error number, when it gives one; never its text) and `ms`: `authenticate ok ms=…`, `authenticate failed result=<n> ms=…` | Android: the **Authenticate now** prompt closed |
| `tamper` | `part` (`payload` or `ciphertext`), `index` | a failure action changed a token |
| `header` | the protected header JSON | a token was made or read |
| `token` | the compact token | a token was made or changed |
| `verify` | `ok`, `alg`, `kid`, `ms` | a signature verified |
| `claims` | the verified claims JSON | a JWT verified |
| `decrypt` | `ok`, `alg`, `enc`, `plaintext=equal` or `plaintext=differs`, `ms` | a JWE decrypted |
| `error` | `code`, `ms` | a step failed |
| `note` | `id`, an explanation id | the app showed an explanation with the result, for example `key.test-rsa` |

`op` is one of `jws-sign`, `jws-verify`, `jws-sign-verify`, `jwt-sign`, `jwt-verify`, `jwt-sign-verify`, `jwe-encrypt`, `jwe-decrypt`, `jwe-round-trip`, `key-create`, `key-open`, `key-delete`, `key-delete-all`, and on Android `authenticate` (**Authenticate now**). `store` is the store id without `store.` (`software`, `keychain`, `secure-enclave`, `keystore`, `strongbox`). `failure` is the failure action id without `failure.`.

## Secrets

Nothing the user can see or copy holds a secret: the screen, the Log tab, the mirrored system log and the explanations.

- **Never shown:** private or symmetric key members (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`), content encryption keys, ECDH shared secrets, passwords, and raw library or platform error messages.
- **Allowed:** public JWKs, thumbprints, tags and aliases, protected headers, tokens made from the demo payloads, decrypted demo payloads, error codes and timings.
- **By construction:**
  - One logger takes typed fields only.
  - Every JWK passes one public-only gate, which replaces any object with a private or symmetric member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) by `[withheld]`.
  - A software oct key is shown as `kty`, `alg`, `kid` and its length only. A private EC, OKP or RSA JWK is shown only as its public JWK.
  - An error is shown and logged as its code only: the `PolyjoseError` case name in Swift, the `PolyjoseException` subclass's simple name in Kotlin, and the type name of any other error. Never its message, `detail`, `localizedDescription` or platform error text.
- **Checked:** the demo walk's captured log has no line that matches `"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:` (as `grep -E`), and the walk includes HS256 and A256KW oct keys and the software EC and RSA keys. This grep is the checkable minimum, not the whole rule: the rule above holds for every screen and log line, also those the walk doesn't reach.

## Key names

| Prefix | Used by | Lifetime |
|---|---|---|
| `dev.polyjose.examples.playground.` | the playground's keys: `dev.polyjose.examples.playground.<alg>.<n>`, `<n>` the lowest number not in use | until the user deletes them. The Keys tab lists only this prefix, and **Delete all playground keys** deletes only it. |
| `dev.polyjose.examples.check.<run>.` | the [platform-key checks](CATALOG.md#platform-key-checks), one `<run>` per run | deleted at the end of each check |

The name is the iOS tag (`kSecAttrApplicationTag`) or the Android Keystore alias. Listing keys reads attributes only and never asks the user to authenticate.

## Demo walk

`run.sh --playground` is the playground's automated run on the iOS Simulator and the Android emulator. It launches the app with `-playground-demo` (iOS) or `--ez playgroundDemo true` (Android), without a tap.

- The walk runs every cell of the support matrix on that device: a ✓ cell must succeed, and a ✗ cell runs **Run anyway** and must give the code in its row. Then every failure action, which must give its code. It deletes its keys at the end. Options that need user authentication are skipped by the walk, because no one is there to authenticate; they are tried on a device by hand.
- Its last line is `POLYJOSE-PLAYGROUND: N/M OK`, where M is the number of steps walked and N the number whose outcome was the expected one.
- `run.sh --playground` exits 0 only when N = M and the [secrets check](#secrets) finds nothing. Without `--playground`, `run.sh` runs the checks as before.
