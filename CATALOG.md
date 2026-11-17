# Check catalog

Every app in this repository runs the same checks, in the same order, and prints the same lines; the NestJS service runs its own [service checks](#nestjs-service-checks). This file is the single list. An app is correct when its run ends in `POLYJOSE-VERIFY: R/R PASS`, where R is the number of checks below that ran on it, and every other check of its platform printed a `SKIP` line.

polyjose **0.4.0**. The count N per platform:

| Platform | N | Checks |
|---|---|---|
| Node.js | 34 | 1–34 |
| Node.js, TypeScript (`node-ts/`) | 34 | 1–34, the same ids in the same order as Node.js |
| NestJS (`nestjs/`) | 10 | the ten [NestJS service checks](#nestjs-service-checks), not 1–34 |
| Web | 34 | 1–34 |
| iOS | 44 | 1–34, then the ten [iOS platform-key checks](#ios-applekey) as 35–44 |
| Android | 44 | 1–34, then the ten [Android platform-key checks](#android-androidkeystorekey) as 35–44 |

Checks 1–34 run on every platform except NestJS. Node.js, Node.js TypeScript and web run checks 1–34, so N = 34. iOS and Android run checks 1–44, the [platform-key checks](#platform-key-checks) of their per-store examples included, so N = 44.

## Output and pass rule

```
# polyjose 0.4.0 through dev.polyjose:polyjose, Android 14 (API 34)
PASS jws/sign-verify/hs256
…
FAIL jwt/verify/rejects-expired: expected TokenExpired, got InvalidClaim
…
SKIP platform-key/strongbox/es256-sign: no StrongBox on this device
…
POLYJOSE-VERIFY: 41/42 PASS (2 skipped)
```

(`…` stands for the lines left out here. This run exits 1: R + S = 44 = N, but P ≠ R.)

- **Information lines** start with `# ` and come before the first check. The first one names the polyjose version (`version()`), the package and the runtime. Readers of the output ignore them.
- **One line per check**, in catalog order: `PASS <id>`, `FAIL <id>: <reason>` or `SKIP <id>: <reason>`.
- **A FAIL reason never shows key material, plaintext or token contents.** It is one of:
  - `expected <Code>, got <Code>` or `expected <Code>, got success`, for a check that expects an error code;
  - `unexpected <Code>`, when a call that should succeed fails with a polyjose error;
  - `<what>: expected <a>, got <b>`, only for public values (algorithm names, `kid`, indexes, the RFC 7638 thumbprint, HTTP status codes and headers);
  - `<what> differs`, for anything else (payloads, claims, key members).
- **The final line** is `POLYJOSE-VERIFY: P/R PASS`. P is the number of PASS lines and R the number of checks that ran (PASS plus FAIL; skips excluded). ` (S skipped)` is appended only when S > 0.
- **A run exits 0 only when P = R and R + S = N**, where P and R are read from the final line, S is the number of `SKIP` lines, and N is the platform's count in the table above. So every check that ran passed, and every check of the platform either ran or was skipped: a skip can't hide a missing check, and a run that prints fewer than N check lines fails. Node.js, Node.js TypeScript, NestJS and web have no skips, so their runs require P = R = N. The iOS and Android `run.sh` also require:
  - the final line agrees with the lines above it (P `PASS` lines, R − P `FAIL` lines, S `SKIP` lines);
  - no check id appears twice;
  - at least the 34 checks that never skip ran (R ≥ 34), so a `0/0 PASS (N skipped)` run never exits 0.

  Anything else, including a timeout, exits non-zero. On a timeout it prints `POLYJOSE-VERIFY: 0/<N> PASS (timeout)`. The run is `npm run verify` for Node.js, Node.js TypeScript and NestJS, and `run.sh` for the other apps; each holds N once (`EXPECTED_CHECKS` in `node/run.mjs`, `node-ts/run.ts` and `nestjs/src/verify.ts`, `expected_checks` in each `run.sh`), and a change that adds checks raises it.
- **A skip is allowed only** when the device lacks the hardware a check needs (Secure Enclave, StrongBox) or the OS level its platform key store needs. A skip never counts as a pass. Checks 1–34 and the NestJS service checks never skip; each platform-key check below states its one skip condition.
- **Where the lines go.** Node.js, Node.js TypeScript and NestJS: stdout. Web: the page (`<pre id="result">`) and the browser console. iOS: stdout (`print`). Android: logcat, tag `POLYJOSE`. Each app with a screen also shows them there.

## Developer tasks

Each app has one example file per developer task, which you can read and copy on its own. The checks call those files. Each platform README has a "How do I…?" section with one heading per task, spelled exactly as below, so the links from the root README land on it.

| Task | File stem (Node.js, web) | Swift, Kotlin file | README heading |
|---|---|---|---|
| Sign and verify a JWS | `sign-verify-jws` | `SignVerifyJws` | Sign and verify a JWS |
| Issue and validate a JWT | `sign-verify-jwt` | `SignVerifyJwt` | Issue and validate a JWT |
| Reject tokens with an allow-list | `verify-allow-list` | `VerifyAllowList` | Reject tokens with an allow-list |
| Encrypt and decrypt | `encrypt-decrypt` | `EncryptDecrypt` | Encrypt and decrypt (JWE) |
| Create keys and use a JWK Set | `keys-jwks` | `KeysJwks` | Create keys and use a JWK Set |
| Decode a token before verifying it | `decode-unverified` | `DecodeUnverified` | Decode a token before verifying it |
| Use a platform key store | — | one file per store: `PlatformKeysKeychain`, `PlatformKeysSecureEnclave` (Swift); `PlatformKeysKeystore`, `PlatformKeysStrongBox` (Kotlin) | Use a platform key store |

- The fixed keys live in `test-keys` (`TestKeys`).
- The decode task is not in the apps yet; its headings exist already, and say so.
- The platform key store examples are `PlatformKeysKeychain.swift` and `PlatformKeysSecureEnclave.swift` in the iOS app, and `PlatformKeysKeystore.kt` and `PlatformKeysStrongBox.kt` in the Android app. The [platform-key checks](#platform-key-checks) call them.
- `node-ts/` has the same files as `node/`, in TypeScript (`.ts`). The NestJS service is organised by NestJS module instead; its README says what is where.
- [PLAYGROUND.md](PLAYGROUND.md) describes the interactive playground of the iOS and Android apps, which calls the same example files.

## Fixed keys

All other keys are generated at run time from the OS random number generator. These two are fixed, and every app labels them **"test key, never use in production"** and cites the source:

| Name | Key | Source | Why it is fixed |
|---|---|---|---|
| `RFC7515_A2_RSA_PRIVATE_JWK` | 2048-bit RSA private key (`kty`, `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`) | RFC 7515 Appendix A.2.1 | polyjose 0.4.0 cannot generate RSA keys. Used by every software RS256 and PS256 check. |
| `RFC7638_3_1` | RSA public key with `alg: RS256` and `kid: 2011-04-29`, and its thumbprint `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs` | RFC 7638 §3.1 | The thumbprint check needs the RFC's published answer. |

## Shared inputs

| Input | Value |
|---|---|
| Payload and plaintext | the UTF-8 bytes of `polyjose example payload` |
| JWT claims | `iss: "https://issuer.example"`, `aud: "https://api.example"`, `sub: "user-123"`, `exp`: now + 300 s |
| Verify options for JWTs | `allowedAlgs: [<alg>]`, `issuers: ["https://issuer.example"]`, `audiences: ["https://api.example"]` |
| JWK Set `kid`s | `key-1`, `key-2` (an unknown one: `key-3`) |
| Key for each JWS `alg` | HS256: `jwkGenerateForAlg("HS256")`, one key for both sides. RS256, PS256: `RFC7515_A2_RSA_PRIVATE_JWK` and its `jwkToPublic`. ES256, ES384, ES512, EdDSA: `jwkGenerateForAlg(alg)` and its `jwkToPublic`. |

## The checks

Ids are `area/op/case`, lowercase. The expected error codes are the core's stable codes (`errorCodes()`); each was confirmed against the polyjose core's documented error order and its tests.

### Sign and verify a JWS (`sign-verify-jws`)

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 1–7 | `jws/sign-verify/hs256`, `/rs256`, `/ps256`, `/es256`, `/es384`, `/es512`, `/eddsa` | `jwsSignCompact` with `protectedHeader: {alg}`, then `jwsVerifyCompact` with the verify key and `allowedAlgs: [alg]` | the verified `alg` is `alg`; the payload equals the input | RFC 7515 §5.1, §5.2, §7.1; RFC 7518 §3.2–§3.5; RFC 8037 §3.1 |
| 8 | `jws/json/general-two-signers` | `jwsSignGeneral` with an ES256 and an EdDSA signer; `jwsVerifyJson` with each public key and its own `alg` as the only allowed one | `signatureIndex` is 0 for ES256 and 1 for EdDSA; both payloads equal the input | RFC 7515 §7.2.1 |

### Reject tokens with an allow-list (`verify-allow-list`)

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 9 | `jws/verify/rejects-alg-not-allowed` | An ES256 compact JWS verified with `allowedAlgs: ["ES384"]` | `AlgorithmNotAllowed` | RFC 8725 §3.1; RFC 7515 §5.2 |
| 10 | `jws/verify/rejects-none` | A hand-built Unsecured JWS, `base64url({"alg":"none"}) . base64url(payload) .` (empty signature), verified with an ES256 public key and each of `["ES256"]`, `["none"]`, `["ES256", "none"]` | `AlgorithmNotAllowed` all three times | RFC 8725 §3.2; RFC 7518 §3.6; RFC 7515 Appendix A.5 |
| 11 | `jws/verify/rejects-tampered-payload` | An ES256 compact JWS with one character in the middle of its payload part changed (`A`↔`B`), verified with `allowedAlgs: ["ES256"]` | `InvalidSignature` | RFC 7515 §5.2 step 8 |
| 12 | `jws/verify/rejects-wrong-key` | An ES256 compact JWS verified with the public key of another generated ES256 key | `InvalidSignature` | RFC 7515 §5.2 step 8 |
| 13 | `jws/verify/rejects-key-family-mismatch` | An HS256 compact JWS verified with a P-256 public key and `allowedAlgs: ["HS256"]` | `KeyAlgorithmMismatch` | RFC 8725 §3.1 |

### Issue and validate a JWT (`sign-verify-jwt`)

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 14–20 | `jwt/sign-verify/hs256`, `/rs256`, `/ps256`, `/es256`, `/es384`, `/es512`, `/eddsa` | `jwtSign` of the shared claims with `{alg}`, then `jwtVerify` with the verify key and the shared JWT verify options | the verified `alg` is `alg`; `iss`, `aud`, `sub` and `exp` equal the claims sent | RFC 7519 §7.1, §7.2, §4.1.1, §4.1.3, §4.1.4; RFC 8725 §3.1, §3.8, §3.9 |

### Reject tokens with an allow-list, JWT (`verify-allow-list`)

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 21 | `jwt/verify/rejects-expired` | An ES256 JWT with `exp` an hour ago, verified with `now: exp + 1` and `leeway: 0` | `TokenExpired` | RFC 7519 §4.1.4 |
| 22 | `jwt/verify/rejects-wrong-audience` | An ES256 JWT verified with `audiences: ["https://other-api.example"]` | `InvalidClaim` | RFC 7519 §4.1.3; RFC 8725 §3.9 |
| 23 | `jwt/verify/rejects-alg-not-allowed` | An ES256 JWT verified with `allowedAlgs: ["ES384"]` | `AlgorithmNotAllowed` | RFC 8725 §3.1 |

### Issue and validate a JWT, with a JWK Set (`sign-verify-jwt`)

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 24 | `jwt/verify-with-jwks/selects-by-kid` | Two ES256 keys; a public JWK Set `{keys: [key-1, key-2]}`. The JWT is signed with the second private key carrying `kid: "key-2"` (`jwtSign` puts the key's `kid` in the header; a `kid` in the `header` option is refused with `InvalidHeader`). `jwtVerifyWithJwks` with the shared JWT verify options and `allowedAlgs: ["ES256"]` | `kid` is `key-2`; `keyIndex` is 1 | RFC 7517 §5; RFC 7515 §4.1.4 |

### Encrypt and decrypt (`encrypt-decrypt`)

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 25–28 | `jwe/ecdh-es-a256kw/p-256`, `/p-384`, `/p-521`, `/x25519` | A recipient key from `jwkGenerateEc(crv)` (`jwkGenerateOkp("X25519")` for X25519). `jweEncryptCompact` to its public key with `alg: ECDH-ES+A256KW`, `enc: A256GCM`; `jweDecryptCompact` with the private key, `allowedAlgs: ["ECDH-ES+A256KW"]`, `allowedEnc: ["A256GCM"]` | the plaintext equals the input; the decrypted `header` has `alg: ECDH-ES+A256KW` and `enc: A256GCM` | RFC 7516 §5.1, §5.2, §7.1; RFC 7518 §4.6, §5.3; RFC 8037 §3.2 |
| 29 | `jwe/decrypt/rejects-alg-not-allowed` | A P-256 token as above, decrypted with `allowedAlgs: ["ECDH-ES+A128KW"]`, `allowedEnc: ["A256GCM"]` | `AlgorithmNotAllowed` | RFC 8725 §3.1; RFC 7516 §5.2 |
| 30 | `jwe/decrypt/rejects-wrong-key` | A P-256 token as above, decrypted with another generated P-256 private key and the right allow-lists | `DecryptionFailed` | RFC 7516 §11.5 |

### Create keys and use a JWK Set (`keys-jwks`)

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 31 | `jwk/generate/ec-p-256` | `jwkGenerateEc("P-256")`, then `jwkToPublic` | the private key has `kty: EC`, `crv: P-256` and a `d`; the public key has no `d`, and the same `x` and `y` | RFC 7517 §4; RFC 7518 §6.2 |
| 32 | `jwk/thumbprint/rfc7638` | `jwkThumbprint` of the RFC 7638 §3.1 key (default hash, SHA-256) | `NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs` | RFC 7638 §3.1 |
| 33 | `jwk/pem/round-trip` | A generated P-256 private key → `jwkToPem(key, "pkcs8")` → `jwkFromPem` | the PEM starts with `-----BEGIN PRIVATE KEY-----`; the imported key has the same `d` and the same thumbprint | RFC 5958; RFC 7468 §10; RFC 7638 §3 |
| 34 | `jwks/select/by-kid` | A public JWK Set of two generated P-256 keys, `key-1` and `key-2`; `jwksSelect` with `{kid: "key-2"}`, then with `{kid: "key-3"}` | the first returns the `key-2` member (same `kid` and `x`); the second fails with `NoMatchingKey` | RFC 7517 §5, §4.5 |

## Platform-key checks

Checks 35–44 of the iOS and Android apps use keys held by the platform: the private key stays in the key store, and polyjose asks it for one signature, ECDH shared secret or RSA-OAEP-256 decryption at a time. They need no user authentication and show no prompt.

- **Keys.** Each check creates its key under a per-run tag (iOS) or alias (Android) that starts with `dev.polyjose.examples.check.<run>.`, and deletes it at the end, also when the check fails, so a re-run starts clean.
- **Cross-checks.** Every signature is also verified with the pure-software `jwsVerifyCompact` or `jwtVerify`, using the key's `publicJwk()` and `allowedAlgs: [<alg>]`. Every JWE is encrypted to `publicJwk()` with the ordinary `jweEncryptCompact`, `enc: A256GCM`, and decrypted with `jweDecryptCompactWithPlatformKey`, `allowedAlgs: ["ECDH-ES+A256KW"]`, `allowedEnc: ["A256GCM"]`. Payload, plaintext and claims are the [shared inputs](#shared-inputs).
- **Operations.** `jwsSignCompactWithPlatformKey` with `protectedHeader: {alg}`, `jwtSignWithPlatformKey` with the shared claims, `jweDecryptCompactWithPlatformKey`.
- **Skips.** A check skips only for the reason in its row, and prints it as the `SKIP` reason.

### iOS (`AppleKey`)

`AppleKey.generate(tag:algorithm:protection:)`, `AppleKey.open(tag:algorithm:)`, `AppleKey.delete(tag:)`; `protection` is what the platform reports for the key. A `.keychain` key is stored and protected by the OS, not hardware-bound; on iOS, code that holds the key reference can export the private key. A `.secureEnclave` key is a hardware-bound P-256 key ([Protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave)).

| # | Id | What the check does | Expect | Skips when | RFC |
|---|---|---|---|---|---|
| 35 | `platform-key/keychain/es256-sign` | `generate` ES256, `.keychain`; sign a compact JWS; verify in software | `protection` is `.keychain`; the verified `alg` is ES256; the payload equals the input | never | RFC 7515 §5.1, §5.2; RFC 7518 §3.4 |
| 36 | `platform-key/keychain/es384-jwt` | `generate` ES384, `.keychain`; sign a JWT; verify in software with the shared JWT verify options | the verified `alg` is ES384; `iss`, `aud`, `sub`, `exp` equal the claims sent | never | RFC 7519 §7.1, §7.2; RFC 7518 §3.4 |
| 37 | `platform-key/keychain/ps256-sign` | `generate` PS256, `.keychain`, `keySizeInBits: 2048`; sign a compact JWS; verify in software | the verified `alg` is PS256; the payload equals the input | never | RFC 7515 §5.1, §5.2; RFC 7518 §3.5 |
| 38 | `platform-key/keychain/ecdh-es-a256kw-p-384` | `generate` ECDH-ES, `.keychain`, `keySizeInBits: 384`; encrypt to its public JWK with `ECDH-ES+A256KW`; decrypt with the key | the public JWK has `crv: P-384`; the plaintext equals the input | never | RFC 7516 §5.1, §5.2; RFC 7518 §4.6 |
| 39 | `platform-key/keychain/open-again` | `generate` ES256, `.keychain`; `open` the same tag; sign with the opened key; verify with the first key's public JWK | both public JWKs have the same RFC 7638 thumbprint; the signature verifies | never | RFC 7638 §3; RFC 7515 §5.2 |
| 40 | `platform-key/keychain/delete-then-open` | `generate` ES256, `.keychain`; `delete` the tag; `open` it | `KeyNotFound` | never | — (key store) |
| 41 | `platform-key/secure-enclave/es256-sign` | `generate` ES256, `.secureEnclave`; sign a compact JWS; verify in software | `protection` is `.secureEnclave`; the verified `alg` is ES256; the payload equals the input | `SecureEnclave.isAvailable` is false: `no Secure Enclave on this device` | RFC 7515 §5.1, §5.2; RFC 7518 §3.4 |
| 42 | `platform-key/secure-enclave/es256-jwt` | `generate` ES256, `.secureEnclave`; sign a JWT; verify in software | the verified `alg` is ES256; the claims equal the claims sent | as 41 | RFC 7519 §7.1, §7.2 |
| 43 | `platform-key/secure-enclave/ecdh-es-a256kw-p-256` | `generate` ECDH-ES, `.secureEnclave`; encrypt to its public JWK with `ECDH-ES+A256KW`; decrypt with the key | the public JWK has `crv: P-256`; the plaintext equals the input | as 41 | RFC 7516 §5.2; RFC 7518 §4.6 |
| 44 | `platform-key/secure-enclave/rejects-es384` | `generate` ES384, `.secureEnclave` | `UnsupportedAlgorithm`, and no key under the tag afterwards (`open` gives `KeyNotFound`) | never: `generate` refuses ES384 for the Secure Enclave before it checks that one is available | RFC 7518 §3.4 |

- The Simulator reports a Secure Enclave ([`SecureEnclave.isAvailable`](https://developer.apple.com/documentation/cryptokit/secureenclave/isavailable)), so checks 41–44 run there: **`POLYJOSE-VERIFY: 44/44 PASS`**. The Simulator's Secure Enclave is a host pass-through, not a hardware guarantee; only a run on an iPhone shows the hardware.

### Android (`AndroidKeystoreKey`)

`AndroidKeystoreKey.generate(alias, algorithm, strongBox)`, `AndroidKeystoreKey.open(alias, algorithm)`, `AndroidKeystoreKey.delete(alias)`; `strongBox` is `StrongBox.Off`, `StrongBox.Preferred` or `StrongBox.Required`, and `securityLevel` is where the platform reports the key lives ([`KeyInfo`](https://developer.android.com/reference/android/security/keystore/KeyInfo)). "Has StrongBox" means [`PackageManager.FEATURE_STRONGBOX_KEYSTORE`](https://developer.android.com/reference/android/content/pm/PackageManager) ([Android Keystore system](https://developer.android.com/privacy-and-security/keystore)).

| # | Id | What the check does | Expect | Skips when | RFC |
|---|---|---|---|---|---|
| 35 | `platform-key/keystore/es256-sign` | `generate` ES256, `StrongBox.Off`; sign a compact JWS; verify in software | the verified `alg` is ES256; the payload equals the input | never | RFC 7515 §5.1, §5.2; RFC 7518 §3.4 |
| 36 | `platform-key/keystore/es256-jwt` | `generate` ES256, `StrongBox.Off`; sign a JWT; verify in software with the shared JWT verify options | the verified `alg` is ES256; the claims equal the claims sent | never | RFC 7519 §7.1, §7.2 |
| 37 | `platform-key/keystore/ps256-sign` | `generate` PS256, `StrongBox.Off`, 2048 bits; sign a compact JWS; verify in software | the verified `alg` is PS256; the payload equals the input | never | RFC 7515 §5.1, §5.2; RFC 7518 §3.5 |
| 38 | `platform-key/keystore/ecdh-es-a256kw-p-256` | `generate` ECDH-ES, `StrongBox.Off`; encrypt to its public JWK with `ECDH-ES+A256KW`; decrypt with the key | the plaintext equals the input | API level below 31: `needs API 31` | RFC 7516 §5.2; RFC 7518 §4.6 |
| 39 | `platform-key/keystore/open-again` | `generate` ES256, `StrongBox.Off`; `open` the same alias; sign with the opened key; verify with the first key's public JWK | both public JWKs have the same RFC 7638 thumbprint; the signature verifies | never | RFC 7638 §3; RFC 7515 §5.2 |
| 40 | `platform-key/keystore/delete-then-open` | `generate` ES256; `delete` the alias; `open` it | `KeyNotFound` | never | — (key store) |
| 41 | `platform-key/strongbox/es256-sign` | `generate` ES256, `StrongBox.Required`; sign a compact JWS; verify in software | `securityLevel` is `StrongBox`; the signature verifies | no StrongBox: `no StrongBox on this device` | RFC 7515 §5.2; RFC 7518 §3.4 |
| 42 | `platform-key/strongbox/ecdh-es-a256kw-p-256` | `generate` ECDH-ES, `StrongBox.Required`; encrypt and decrypt as 38 | `securityLevel` is `StrongBox`; the plaintext equals the input | no StrongBox: `no StrongBox on this device`; else API level below 31: `needs API 31` | RFC 7516 §5.2; RFC 7518 §4.6 |
| 43 | `platform-key/strongbox/required-when-absent` | On a device without StrongBox: `generate` ES256, `StrongBox.Required`; then `open` the alias | `PlatformKeyFailed`, then `KeyNotFound`: no key is left behind, and there is no silent move to the TEE | the device has StrongBox: `StrongBox present`; else API level below 28: `needs API 28` (below 28 the library refuses StrongBox with `UnsupportedAlgorithm` before it asks the Keystore) | — (key store) |
| 44 | `platform-key/strongbox/preferred-reports-level` | `generate` ES256, `StrongBox.Preferred`; sign a compact JWS; verify in software | succeeds. With StrongBox: `securityLevel` is `StrongBox` (below API 31, where the platform can't say which, `SecureHardware`). Without StrongBox: `securityLevel` is not `StrongBox` (it is where the platform puts the fallback: `TrustedEnvironment` on a device, `Software` on the `polyjose-api34` emulator), and `open` finds the key (same RFC 7638 thumbprint) | never | RFC 7515 §5.2; RFC 7638 §3 |

- On the `polyjose-api34` emulator (no StrongBox, API 34), checks 41 and 42 skip: **`POLYJOSE-VERIFY: 42/42 PASS (2 skipped)`**. On a device with StrongBox and API 31 or later, check 43 skips: `43/43 PASS (1 skipped)`. An emulator's keys are software, whatever it reports; only a run on a device shows the TEE or StrongBox.

## NestJS service checks

The NestJS app (`nestjs/`) is a service, not a set of task files, so it runs its own ten checks instead of 1–34. `npm run verify` boots the service in the same process on a free port and calls it over HTTP with `fetch`. Its configuration is two ES256 keys generated at run time (the current key, private and signing, first; the previous key, public only, after it), the [shared](#shared-inputs) issuer `https://issuer.example` and audience `https://api.example`, the client `demo-client` and a fixed test client secret. Its tokens last 300 s, with 30 s leeway.

| # | Id | What the check does | Expect | RFC |
|---|---|---|---|---|
| 1 | `nestjs/jwks/public-only` | `GET /.well-known/jwks.json`; then `KeyService` printed with `JSON.stringify` and `util.inspect` | 200 with a `Cache-Control` `max-age`; the current key's `kid`, then the previous key's; no key has `d`, `p`, `q`, `dp`, `dq`, `qi`, `oth` or `k`; neither printed form shows a private member | RFC 7517 §5; RFC 7518 §6.2.2, §6.3.2, §6.4.1 |
| 2 | `nestjs/token/issues-es256-jwt` | `POST /token`, form-encoded, `grant_type=client_credentials` with the client id and secret; the token verified with the published JWK Set only, `allowedAlgs: ["ES256"]` and the shared issuer and audience | 200, `Cache-Control: no-store`, `token_type: Bearer`, `expires_in: 300`; the verified `alg` is ES256, the `kid` the current key's, `sub` the client id, `exp` − `iat` = 300 | RFC 6749 §4.4.2, §4.4.3, §5.1; RFC 7519 §7.2; RFC 7517 §5 |
| 3 | `nestjs/token/rejects-bad-client-secret` | `POST /token` with a wrong client secret | 401 and the body `{"error":"invalid_client"}`; no token | RFC 6749 §5.2 |
| 4 | `nestjs/guard/accepts-valid` | `GET /me` with a token from `POST /token` | 200; the body's `sub`, `iss` and `aud` are the client id and the shared issuer and audience | RFC 6750 §2.1; RFC 7519 §7.2 |
| 5 | `nestjs/guard/rejects-missing` | `GET /me` with no `Authorization` header | 401 with a bare `WWW-Authenticate: Bearer`, no error code | RFC 6750 §3.1 |
| 6 | `nestjs/guard/rejects-expired` | `GET /me` with a token signed by the current key, `exp` 120 s ago (outside the leeway) | `TokenExpired` | RFC 7519 §4.1.4 |
| 7 | `nestjs/guard/rejects-wrong-audience` | as 6, valid, with `aud: "https://other-api.example"` | `InvalidClaim` | RFC 7519 §4.1.3; RFC 8725 §3.9 |
| 8 | `nestjs/guard/rejects-alg-not-allowed` | as 6, valid, signed ES384 by a P-384 key under the current key's `kid` | `AlgorithmNotAllowed` | RFC 8725 §3.1 |
| 9 | `nestjs/guard/rejects-tampered` | a token from `POST /token` with one character in the middle of its payload part changed (`A`↔`B`) | `InvalidSignature` | RFC 7515 §5.2 step 8 |
| 10 | `nestjs/guard/rejects-unknown-kid` | as 6, valid, signed by a generated key whose `kid` is not published | `NoMatchingKey` | RFC 7517 §5; RFC 7515 §4.1.4 |

- **Rejected tokens (6–10).** Each answer is 401 with `WWW-Authenticate: Bearer error="invalid_token"` and the body `{"error":"invalid_token"}` (RFC 6750 §3.1). The expected code is read from the one `token rejected code=<Code>` line the service logged during the request; the client never sees it (RFC 8725 §3.1).
- **Secrets scan.** After the checks, `npm run verify` sends one request that is not a check, `GET /token?grant_type=client_credentials&client_id=demo-client&client_secret=<the test secret>` (a route that doesn't exist). It then scans the whole server log, every response body and both printed forms of `KeyService` for a private JWK member (`"d":`, `"k":` and the RSA ones), for the signing key's `d` value and for the client secret, and the log for every issued access token. It prints only counts, in one `# secrets scan: ...` line between the last check line and the final line, which readers ignore like an information line. On top of the pass rule above, the run exits 0 only when the scan is clean.

## Adding checks

New checks are appended after check 34, one area at a time, in the order this file lists them. An existing id never changes its meaning: a changed expectation gets a new id. Checks for an API that is not in a published release yet only run when the app is built against a polyjose checkout (`POLYJOSE_SRC`) with that API's switch on; the default run against the published release stays at the count above.
