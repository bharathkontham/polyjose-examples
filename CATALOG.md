# Check catalog

Every app in this repository runs the same checks, in the same order, and prints the same lines. This file is the single list. An app is correct when its run ends in `POLYJOSE-VERIFY: R/R PASS`, where R is the number of checks below that ran on it.

polyjose **0.2.0**: **34 checks on every platform** (Node.js, web, iOS, Android).

## Output and pass rule

```
# polyjose 0.2.0 through @polyjose/node, Node.js 24.21.0
PASS jws/sign-verify/hs256
FAIL jwt/verify/rejects-expired: expected TokenExpired, got InvalidClaim
SKIP platform-key/strongbox/es256-sign: no StrongBox on this device
POLYJOSE-VERIFY: 33/34 PASS (1 skipped)
```

- **Information lines** start with `# ` and come before the first check. The first one names the polyjose version (`version()`), the package and the runtime. Readers of the output ignore them.
- **One line per check**, in catalog order: `PASS <id>`, `FAIL <id>: <reason>` or `SKIP <id>: <reason>`.
- **A FAIL reason never shows key material, plaintext or token contents.** It is one of:
  - `expected <Code>, got <Code>` or `expected <Code>, got success`, for a check that expects an error code;
  - `unexpected <Code>`, when a call that should succeed fails with a polyjose error;
  - `<what>: expected <a>, got <b>`, only for public values (algorithm names, `kid`, indexes, the RFC 7638 thumbprint);
  - `<what> differs`, for anything else (payloads, claims, key members).
- **The final line** is `POLYJOSE-VERIFY: P/R PASS`. P is the number of PASS lines and R the number of checks that ran (PASS plus FAIL; skips excluded). ` (S skipped)` is appended only when S > 0.
- **`run.sh` exits 0 only when P = R and R > 0.** Anything else, including a timeout, exits non-zero. On a timeout `run.sh` prints `POLYJOSE-VERIFY: 0/<R> PASS (timeout)`.
- **A skip is allowed only** when the device lacks the hardware a check needs (Secure Enclave, StrongBox) or the OS level its platform key store needs. A skip never counts as a pass. None of the 0.2.0 checks can skip.
- **Where the lines go.** Node.js: stdout. Web: the page (`<pre id="result">`) and the browser console. iOS: stdout (`print`). Android: logcat, tag `POLYJOSE`. Each app with a screen also shows them there.

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
| Use a platform key store | — | `PlatformKeys` | Use a platform key store |

- The fixed keys live in `test-keys` (`TestKeys`).
- The last two tasks need a polyjose release after 0.2.0. Their headings exist already, and say so.

## Fixed keys

All other keys are generated at run time from the OS random number generator. These two are fixed, and every app labels them **"test key, never use in production"** and cites the source:

| Name | Key | Source | Why it is fixed |
|---|---|---|---|
| `RFC7515_A2_RSA_PRIVATE_JWK` | 2048-bit RSA private key (`kty`, `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi`) | RFC 7515 Appendix A.2.1 | polyjose 0.2.0 cannot generate RSA keys. Used by every RS256 and PS256 check. |
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

## Adding checks

New checks are appended after check 34, one area at a time, in the order this file lists them. An existing id never changes its meaning: a changed expectation gets a new id. Checks for an API that is not in a published release yet only run when the app is built against a polyjose checkout (`POLYJOSE_SRC`) with that API's switch on; the default run against the published release stays at the count above.
