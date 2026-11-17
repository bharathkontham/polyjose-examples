# polyjose example app for iOS

`polyjose-examples-ios` is a SwiftUI app (iOS 16 or later) that uses the [`polyjose`](https://github.com/bharathkontham/polyjose) Swift package, version 0.4.0, product `Polyjose`, its only dependency. Each file in [`PolyjoseExamples/Examples/`](PolyjoseExamples/Examples/) answers one "How do I…?" question, imports `Polyjose` directly, and can be copied into your app on its own. [`PolyjoseExamples/Harness/`](PolyjoseExamples/Harness/) runs every check of the [catalog](../CATALOG.md) through those files when the app starts, prints the lines to stdout and shows them on screen.

Needs macOS with Xcode and an iOS Simulator runtime. `DEVELOPER_DIR` selects the Xcode, as for any Xcode command-line tool.

## Run it

```sh
./run.sh
```

`run.sh` builds the app with `xcodebuild` for an iOS Simulator, boots the Simulator, installs the app and launches it with `simctl launch --console-pty` and the argument `-autorun`. It prints one line per check and ends with:

```
POLYJOSE-VERIFY: 44/44 PASS
```

It exits 0 only when every check that ran passed and every check of the catalog either ran or was skipped. The output format and the pass rule are in [CATALOG.md](../CATALOG.md#output-and-pass-rule). The app exits by itself after the run when it was launched with `-autorun`.

- **The Simulator.** `run.sh` uses a device named `polyjose-examples` on the newest installed iOS runtime, and creates it the first time. When the device is not running, `run.sh` boots it and shuts it down at the end; a device that was already running stays running. `POLYJOSE_SIMULATOR=<name or UDID>` picks another device, and `POLYJOSE_SIM_RUNTIME=<runtime identifier>` the runtime of a new one (`xcrun simctl list runtimes` lists them). To remove the device: `xcrun simctl delete polyjose-examples`.
- **The timeout.** From the boot to the final line, `run.sh` waits at most `POLYJOSE_TIMEOUT` seconds (default 300). Then it prints `POLYJOSE-VERIFY: 0/44 PASS (timeout)`, stops the app and exits 1.
- **Its files.** The Swift package checkout, DerivedData and the logs (`build.log`, `app.log`) go to `.build/` next to `run.sh`, which git ignores.

### In Xcode, on the Simulator

Open `PolyjoseExamples.xcodeproj`, pick an iPhone Simulator and run (⌘R). The app runs the checks at launch and lists the lines; **Run again** repeats them. The scheme's `-autorun` argument is off, so the app stays open.

### On an iPhone

1. Create `Config/Local.xcconfig` (git ignores it) with your Apple development team, which you find in Xcode under Settings > Accounts, or in the Apple Developer account's Membership details:

   ```
   DEVELOPMENT_TEAM = ABCDE12345
   ```

   If Xcode says the bundle id `dev.polyjose.examples` is not available to your team, add your own: `PRODUCT_BUNDLE_IDENTIFIER = com.example.polyjose-examples`.
2. Open `PolyjoseExamples.xcodeproj`, connect the iPhone (with Developer Mode on: Settings > Privacy & Security), pick it as the run destination and run (⌘R).
3. The app runs every check at launch. Read the result on screen: the first line names the polyjose version and the iOS version, and the list ends with `POLYJOSE-VERIFY: 44/44 PASS`. In Xcode's console the same lines appear.

Checks 1–34 use only polyjose's own pure-Rust cryptography, so they behave the same on an iPhone and on the Simulator. Checks 35–44 use keys held by iOS: on an iPhone, the four Secure Enclave checks run in the device's Secure Enclave hardware; on the Simulator they also run, but the Simulator's Secure Enclave is a host pass-through, not a hardware guarantee. On a device without a Secure Enclave those four print `SKIP` with `no Secure Enclave on this device`, and the run ends `40/40 PASS (4 skipped)`.

### Against a local polyjose checkout

```sh
(cd ../../polyjose && platforms/swift/scripts/build-xcframework.sh)   # once, and after each Rust change
POLYJOSE_SRC=../../polyjose ./run.sh
```

The checkout's Swift package needs its locally built XCFramework, `platforms/swift/build/PolyjoseFFI.xcframework`, which polyjose's `platforms/swift/scripts/build-xcframework.sh` builds (it needs the Rust toolchains in polyjose's `CONTRIBUTING.md`). `run.sh` warns when that XCFramework is older than the checkout's Rust code.

`run.sh` then copies the checkout (tracked files, plus untracked files that git does not ignore) and its XCFramework to `.build/polyjose`, and builds `.build/PolyjoseLink.xcworkspace`: a workspace with the app project and that copy as a local package. A local package with the same name as a remote one replaces it, so the app builds against the checkout without any change to the project, and `POLYJOSE_LOCAL_XCFRAMEWORK=1` makes polyjose's `Package.swift` use the local XCFramework. The checkout itself is never written to. Run `./run.sh` without `POLYJOSE_SRC` to go back to the published package: it builds the project itself, which still names the published package.

## How do I…?

Every verify and decrypt call passes an explicit `allowedAlgs` (and `allowedEnc` for JWE), never one taken from the token (RFC 8725 §3.1). Every function cites the RFC section it implements. Keys, headers and claims are JSON text. polyjose calls are synchronous; the app runs them off the main thread.

### Sign and verify a JWS

[`Examples/SignVerifyJws.swift`](PolyjoseExamples/Examples/SignVerifyJws.swift): a key pair for each algorithm (HS256, RS256, PS256, ES256, ES384, ES512, EdDSA), compact signing and verification, and a general JSON JWS with two signers (RFC 7515).
Checks: `jws/sign-verify/*`, `jws/json/general-two-signers`.

### Issue and validate a JWT

[`Examples/SignVerifyJwt.swift`](PolyjoseExamples/Examples/SignVerifyJwt.swift): issue a JWT with `iss`, `aud` and `exp`, validate it with one key, or with a JWK Set where the token's `kid` picks the key (RFC 7519, RFC 7517 §5).
Checks: `jwt/sign-verify/*`, `jwt/verify-with-jwks/selects-by-kid`.

### Reject tokens with an allow-list

[`Examples/VerifyAllowList.swift`](PolyjoseExamples/Examples/VerifyAllowList.swift): handle a refused token by the stable code of its `PolyjoseError` (`code()`): an algorithm outside the list, `alg: none`, a changed payload, the wrong key, a key of the wrong family, an expired JWT, the wrong audience (RFC 8725).
Checks: `jws/verify/rejects-*`, `jwt/verify/rejects-*`.

### Encrypt and decrypt (JWE)

[`Examples/EncryptDecrypt.swift`](PolyjoseExamples/Examples/EncryptDecrypt.swift): encrypt to a recipient's public key with `ECDH-ES+A256KW` and `A256GCM` on P-256, P-384, P-521 or X25519, and decrypt with allow-lists (RFC 7516, RFC 7518 §4.6).
Checks: `jwe/ecdh-es-a256kw/*`, `jwe/decrypt/rejects-*`.

### Create keys and use a JWK Set

[`Examples/KeysJwks.swift`](PolyjoseExamples/Examples/KeysJwks.swift): generate an EC key, take its public half, compute its RFC 7638 thumbprint, export and import PKCS#8 PEM, build a public JWK Set and select a key from it by `kid` (RFC 7517).
Checks: `jwk/generate/ec-p-256`, `jwk/thumbprint/rfc7638`, `jwk/pem/round-trip`, `jwks/select/by-kid`.

### Decode a token before verifying it

Not in this app yet. polyjose 0.4.0 has the unverified decode functions; this example arrives in a later update of this repository.

### Use a platform key store

polyjose's `AppleKey` keeps the private key in an iOS key store: polyjose asks it for one signature, ECDH shared secret or RSA-OAEP-256 decryption at a time and checks every signature against the public key. One file per store, each with the same functions: create (`AppleKey.generate`, with `access` and `keySizeInBits`), open, sign a JWS, sign a JWT, decrypt a compact JWE, delete, and where the key lives (`protection`, as iOS reports it).

- [`Examples/PlatformKeysKeychain.swift`](PolyjoseExamples/Examples/PlatformKeysKeychain.swift): a Keychain key (`.keychain`), stored and protected by the OS, not hardware-bound; on iOS, code that holds the key reference can export the private key. ES256, ES384, ES512, RS\*, PS\*, ECDH-ES on P-256, P-384 or P-521, and RSA-OAEP-256.
- [`Examples/PlatformKeysSecureEnclave.swift`](PolyjoseExamples/Examples/PlatformKeysSecureEnclave.swift): a Secure Enclave key (`.secureEnclave`), a hardware-bound P-256 key that can't be exported. ES256 and ECDH-ES on P-256 only; anything else, or a device without a Secure Enclave, is `UnsupportedAlgorithm`, with no fallback to the Keychain.

A key with `access` flags (Face ID, Touch ID or the passcode) shows a system prompt during each sign or decrypt call and blocks the calling thread, so call these functions off the main thread. The checks use no `access` flags, so nothing prompts. Each check's key has a tag `dev.polyjose.examples.check.<run>.<name>` and is deleted at the end of the check, also when it fails. Every signature is verified again in software with `jwsVerifyCompact` or `jwtVerify` and the key's `publicJwk()`, and every JWE is encrypted in software with `jweEncryptCompact` to it.
Checks: `platform-key/keychain/*`, `platform-key/secure-enclave/*` ([CATALOG.md](../CATALOG.md#ios-applekey)).

Ran on: the iOS 27.2 Simulator, `POLYJOSE-VERIFY: 44/44 PASS`, the Secure Enclave checks included. [PLAYGROUND.md](../PLAYGROUND.md) describes the playground that will try each key store by hand.

## Test keys

[`Examples/TestKeys.swift`](PolyjoseExamples/Examples/TestKeys.swift) holds two keys copied from the RFCs: the RFC 7515 Appendix A.2 RSA key (polyjose 0.4.0 cannot generate RSA keys) and the RFC 7638 §3.1 key. They are published: **test keys, never use them in production.** Every other key is generated at run time.

## Files

| Path | What it is |
|---|---|
| `PolyjoseExamples.xcodeproj` | The Xcode project: one app target, `PolyjoseExamples`, and the Swift package requirement (`https://github.com/bharathkontham/polyjose`, exactly 0.4.0) |
| `Config/App.xcconfig` | The target's build settings: bundle id `dev.polyjose.examples`, iOS 16, Swift 6; includes `Config/Local.xcconfig` when it exists |
| `PolyjoseExamples/Examples/` | One file per developer task (two for platform keys, one per key store), and the test keys |
| `PolyjoseExamples/Harness/` | The checks in catalog order (`Catalog.swift`), their expectations (`Check.swift`), the runner (`Runner.swift`) and the screen (`ContentView.swift`) |
| `run.sh` | Builds, runs on a Simulator and checks the result |
