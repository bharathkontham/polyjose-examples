# polyjose example app for Android (Kotlin)

`polyjose-examples-android` uses [`dev.polyjose:polyjose`](https://central.sonatype.com/artifact/dev.polyjose/polyjose) 0.4.0 from Maven Central, its only library dependency. Each file in [`src/main/kotlin/dev/polyjose/examples/`](src/main/kotlin/dev/polyjose/examples/) answers one "How do I…?" question, imports `dev.polyjose` directly, and can be copied into your project on its own. The app in [`app/`](src/main/kotlin/dev/polyjose/examples/app/) runs every check of the [catalog](../CATALOG.md) through those files ([`Catalog.kt`](src/main/kotlin/dev/polyjose/examples/app/Catalog.kt)) and shows the result lines on screen and in logcat.

minSdk 23 (the AAR's), compileSdk and targetSdk 36. Keys, claims and headers are JSON text, as the polyjose Kotlin API takes them; the examples read and edit that JSON with Android's built-in `org.json`. Every polyjose call is synchronous and does real cryptography, so call it off the main thread, as the app does.

## Run it

Needs a JDK, 17 or later (`JAVA_HOME`), and the Android SDK with platform-tools and the emulator (`ANDROID_HOME`).

```sh
./run.sh
```

[`run.sh`](run.sh) builds the debug APK with the Gradle wrapper, installs it, starts the activity with the `autorun` extra, and reads the app's lines from `adb logcat -s POLYJOSE` until the result line:

```
POLYJOSE-VERIFY: 42/42 PASS (2 skipped)
```

That is the result on the `polyjose-api34` emulator (Android 14, API 34, no StrongBox): the two StrongBox checks that need StrongBox skip. On a device with StrongBox and API 31 or later it is `43/43 PASS (1 skipped)`. It exits 0 only when every check that ran passed and every check of the catalog either ran or was skipped. After `POLYJOSE_TIMEOUT` seconds (default 300) without a result line it prints `POLYJOSE-VERIFY: 0/44 PASS (timeout)` and exits 1. The output format and the pass rule are in [CATALOG.md](../CATALOG.md#output-and-pass-rule).

Which device `run.sh` uses:

- **`ANDROID_SERIAL` set:** that device, as `adb devices` lists it.
- **Otherwise:** the emulator running the AVD named by `POLYJOSE_AVD` (default `polyjose-api34`). If that AVD is not running, `run.sh` starts it without a window on console port `POLYJOSE_EMULATOR_PORT` (default 5580), and stops that emulator again when it ends. It never stops an emulator or device it did not start.

Create the AVD once, with any system image of API 23 or later, for example:

```sh
sdkmanager "system-images;android-34;google_apis;arm64-v8a"
avdmanager create avd -n polyjose-api34 -k "system-images;android-34;google_apis;arm64-v8a"
```

(use `x86_64` in place of `arm64-v8a` on an Intel machine).

### On a phone

1. Turn on USB debugging (Settings → About phone → tap Build number seven times, then Settings → Developer options → USB debugging) and connect the phone.
2. Find its serial with `adb devices`, then run `ANDROID_SERIAL=<serial> ./run.sh`.

Or open this folder in Android Studio, run the app on the phone, and tap **Run the checks**: the lines appear on screen, and in Logcat under the tag `POLYJOSE`. The first `# ` line names the polyjose version, the Android version and the device model, so a result always says which device produced it.

### Against a local polyjose checkout

```sh
POLYJOSE_SRC=../../polyjose ./run.sh
```

[`build.sh`](build.sh) copies the checkout to `.build/src`, builds and publishes the AAR there with polyjose's own Gradle build (`publishAllPublicationsToBuildLocalRepository`, cargo output in `.build/target`), and builds the app with `-PpolyjoseSrc=.build/src`. With `polyjoseSrc` set (or `POLYJOSE_SRC`, when you run `./gradlew` yourself), [`settings.gradle.kts`](settings.gradle.kts) takes `dev.polyjose` only from that checkout's `platforms/android/build/repo`, never from Maven Central, and the version from its `Cargo.toml`. The checkout itself is never written to. It needs what polyjose's `CONTRIBUTING.md` lists for the Android binding (Rust, the Android NDK, cargo-ndk); the first build takes several minutes. Run `./run.sh` without `POLYJOSE_SRC` to go back to the published release.

The version pin is `polyjoseVersion` in [`build.gradle.kts`](build.gradle.kts). That file also pins the Kotlin Gradle plugin to 2.4.21, the Kotlin that the 0.4.0 AAR is built with (its POM requires `kotlin-stdlib` 2.4.21): the Kotlin built into AGP 9.5 is older and cannot read the `kotlin-stdlib` the AAR brings.

## How do I…?

Every verify and decrypt call passes an explicit `allowedAlgs` (and `allowedEnc` for JWE), never one taken from the token (RFC 8725 §3.1). Every function cites the RFC section it implements. A refused token throws `PolyjoseException`; match on its stable `code()`.

### Sign and verify a JWS

[`SignVerifyJws.kt`](src/main/kotlin/dev/polyjose/examples/SignVerifyJws.kt): a key pair for each algorithm (HS256, RS256, PS256, ES256, ES384, ES512, EdDSA), compact signing and verification, and a general JSON JWS with two signers (RFC 7515).
Checks: `jws/sign-verify/*`, `jws/json/general-two-signers`.

### Issue and validate a JWT

[`SignVerifyJwt.kt`](src/main/kotlin/dev/polyjose/examples/SignVerifyJwt.kt): issue a JWT with `iss`, `aud` and `exp`, validate it with one key, or with a JWK Set where the token's `kid` picks the key (RFC 7519, RFC 7517 §5).
Checks: `jwt/sign-verify/*`, `jwt/verify-with-jwks/selects-by-kid`.

### Reject tokens with an allow-list

[`VerifyAllowList.kt`](src/main/kotlin/dev/polyjose/examples/VerifyAllowList.kt): handle a refused token by its stable `PolyjoseException` code: an algorithm outside the list, `alg: none`, a changed payload, the wrong key, a key of the wrong family, an expired JWT, the wrong audience (RFC 8725).
Checks: `jws/verify/rejects-*`, `jwt/verify/rejects-*`.

### Encrypt and decrypt (JWE)

[`EncryptDecrypt.kt`](src/main/kotlin/dev/polyjose/examples/EncryptDecrypt.kt): encrypt to a recipient's public key with `ECDH-ES+A256KW` and `A256GCM` on P-256, P-384, P-521 or X25519, and decrypt with allow-lists (RFC 7516, RFC 7518 §4.6).
Checks: `jwe/ecdh-es-a256kw/*`, `jwe/decrypt/rejects-*`.

### Create keys and use a JWK Set

[`KeysJwks.kt`](src/main/kotlin/dev/polyjose/examples/KeysJwks.kt): generate an EC key, take its public half, compute its RFC 7638 thumbprint, export and import PKCS#8 PEM, build a public JWK Set and select a key from it by `kid` (RFC 7517).
Checks: `jwk/generate/ec-p-256`, `jwk/thumbprint/rfc7638`, `jwk/pem/round-trip`, `jwks/select/by-kid`.

### Decode a token before verifying it

Not in this app yet. polyjose 0.4.0 has the unverified decode functions; this example arrives in a later update of this repository.

### Use a platform key store (platform keys)

`AndroidKeystoreKey` keeps the private key in the Android Keystore: polyjose asks it for one signature, ECDH shared secret or RSA-OAEP-256 decryption at a time, and does every JOSE step itself. Verifying and encrypting need only the key's `publicJwk()`, so they run in software. Each file below has the same small functions: create, open, sign a JWS, sign a JWT, decrypt a compact JWE, delete, and where the key lives (`securityLevel`, as the platform reports it). Call them off the main thread.

- [`PlatformKeysKeystore.kt`](src/main/kotlin/dev/polyjose/examples/PlatformKeysKeystore.kt): the Android Keystore's trusted execution environment (TEE), `StrongBox.Off`. ES256, ES384, ES512, RS256 to PS512 from API 23; ECDH-ES from API 31; RSA-OAEP-256 from API 34. On an emulator the keys are software, whatever it reports.
- [`PlatformKeysStrongBox.kt`](src/main/kotlin/dev/polyjose/examples/PlatformKeysStrongBox.kt): StrongBox, a separate hardware secure element, with `StrongBox.Required` (StrongBox or nothing: `PlatformKeyFailed` without it, and no key is left behind) or `StrongBox.Preferred` (else the TEE, and `securityLevel` says which). It shows the `PackageManager.FEATURE_STRONGBOX_KEYSTORE` check. ES256, RS256 and PS256 at 2048 bits from API 28; ECDH-ES on P-256 from API 31; RSA-OAEP-256 at 2048 bits from API 34, not verified on a StrongBox device.

Checks: `platform-key/keystore/*`, `platform-key/strongbox/*` ([CATALOG.md](../CATALOG.md#android-androidkeystorekey)). They need no user authentication, use the aliases `dev.polyjose.examples.check.<run>.…`, and delete their keys by the end of the run, also when a check fails.

Ran on: the `polyjose-api34` emulator (Android 14, API 34, no StrongBox), `42/42 PASS (2 skipped)`: `platform-key/strongbox/es256-sign` and `platform-key/strongbox/ecdh-es-a256kw-p-256` skip with `no StrongBox on this device`. There, a `StrongBox.Preferred` key reports `Software`. That proves the code paths, not the hardware: only a run on a device shows the TEE or StrongBox. [PLAYGROUND.md](../PLAYGROUND.md) describes the playground that will try each key store by hand.

## Test keys

[`TestKeys.kt`](src/main/kotlin/dev/polyjose/examples/TestKeys.kt) holds two keys copied from the RFCs: the RFC 7515 Appendix A.2 RSA key (polyjose 0.4.0 cannot generate RSA keys) and the RFC 7638 §3.1 key. They are published: **test keys, never use them in production.** Every other key is generated at run time.
