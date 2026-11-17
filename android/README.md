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

That is the result on the `polyjose-api34` emulator (Android 14, API 34, no StrongBox): the two StrongBox checks that need StrongBox skip. On a device with StrongBox and API 31 or later it is `43/43 PASS (1 skipped)`. It exits 0 only when every check that ran passed, every check of the catalog either ran or was skipped, checks 1–34 (which never skip) all ran, and no check id appears twice. After `POLYJOSE_TIMEOUT` seconds (default 300) without a result line it prints `POLYJOSE-VERIFY: 0/44 PASS (timeout)` and exits 1. The output format and the pass rule are in [CATALOG.md](../CATALOG.md#output-and-pass-rule).

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

Ran on: the `polyjose-api34` emulator (Android 14, API 34, no StrongBox), `42/42 PASS (2 skipped)`: `platform-key/strongbox/es256-sign` and `platform-key/strongbox/ecdh-es-a256kw-p-256` skip with `no StrongBox on this device`. There, a `StrongBox.Preferred` key reports `Software`. Below API 31 the ECDH-ES checks skip with `needs API 31`, and below API 28 `platform-key/strongbox/required-when-absent` skips with `needs API 28`. That proves the code paths, not the hardware: only a run on a device shows the TEE or StrongBox. The [playground](#playground) tries each key store by hand.

## Playground

The app opens on **Checks**. Four more tabs in the bottom row make it a playground ([PLAYGROUND.md](../PLAYGROUND.md) is the contract):

- **Sign**: a JWS or a JWT with a key from any store (Software, Android Keystore (TEE), StrongBox `Preferred` or `Required`), verified in software with an explicit allow-list.
- **Encrypt**: a JWE encrypted in software to the key's public JWK and decrypted with the key in its store.
- **Keys**: the "This device" card and the playground's keys (aliases `dev.polyjose.examples.playground.<alg>.<n>`), each with **Open again** (public JWK and RFC 7638 thumbprint) and **Delete**, plus **Create key** and **Delete all playground keys** (also this session's software keys). Software keys live in app memory for the session only.
- **Log**: every step of every tap, with **Copy all**, **Share** and **Clear**.

Each picker row comes from the support matrix in [`playground/Matrix.kt`](src/main/kotlin/dev/polyjose/examples/playground/Matrix.kt). A row the device can't do is disabled and says why ("needs Android 12 (API 31)", "no StrongBox on this device", "StrongBox can't do ES384", "per-use isn't possible for ECDH keys", "set a screen lock"). Its **Run anyway** makes the call and shows the code the library returns. Every row has an info button with its explanation ([`playground/Explanations.kt`](src/main/kotlin/dev/polyjose/examples/playground/Explanations.kt)). **Try a failure** runs one misuse (a tampered token, another algorithm allowed, the wrong key, an expired JWT, a deleted key) and shows its code. The result card shows the token, the protected header, the outcome or the error code with its meaning, "Key lives in" as the platform reports it, and the time of each step.

Platform keys go through [`PlatformKeysKeystore.kt`](src/main/kotlin/dev/polyjose/examples/PlatformKeysKeystore.kt) and [`PlatformKeysStrongBox.kt`](src/main/kotlin/dev/polyjose/examples/PlatformKeysStrongBox.kt), the files the checks use. Every polyjose call runs on one background thread, never the main thread: a key with user authentication blocks its thread while the prompt is up. For a **time-bound** key, **Authenticate now** shows the framework `BiometricPrompt`, and the key then works for its window. For a **per-use** key, polyjose's `BiometricPromptAuthorizer` shows the prompt during each signature or decryption. Prompted keys need API 28 and a secure lock screen; the app declares `android.permission.USE_BIOMETRIC`.

The log holds no secrets: no private or symmetric key member, content key, shared secret or error message, only public JWKs, thumbprints, aliases, headers, demo tokens, error codes and timings. Each line also goes to logcat as `LOG <tap>.<step> <event> …` under the tag `POLYJOSE` (`adb logcat -s POLYJOSE`).

### The demo walk

```sh
./run.sh --playground
```

It starts the app with `--ez playgroundDemo true`. The walk then runs every enabled cell of the matrix that needs no prompt, **Run anyway** on every disabled cell, every failure action and the Keys tab's actions, through the code the buttons call. It deletes the Keystore keys it made at the end, and only those: keys you made by hand stay. It prints one `PLAYGROUND OK <step>` line per step and ends with:

```
POLYJOSE-PLAYGROUND: 326/326 OK
```

That is the result on the `polyjose-api34` emulator (API 34, no StrongBox, no screen lock). There, every option with user authentication is disabled ("set a screen lock"), and its Run anyway gives `PlatformKeyFailed`, except per-use on an ECDH key, which gives `UnsupportedAlgorithm`. StrongBox `Required` gives `PlatformKeyFailed` and leaves no key, and `Preferred` reports `Software`, because the emulator's keys are software. `run.sh --playground` exits 0 only when every step gave its expected outcome and the secrets checks find nothing. The walk's last step, `secrets/no-secret-value-in-log`, looks for the values of the private and symmetric members of every software key the walk made (also the other key of each wrong-key action) in the whole log, long lines joined, and reports only how many it checked. `run.sh` then looks for the `d` value of the RFC 7515 A.2 test key (the walk's software RSA key) in the capture, and for any line with a private or symmetric JWK member (`"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`, `"oth"`, `"k"`). The whole capture is in `build/playground-logcat.txt`.

### On your device

The emulator proves the code paths, not where keys live. These steps are the device run, by hand:

1. Build and install the debug app: `./gradlew installDebug` with the phone connected, or `./gradlew assembleDebug` and `adb install -r build/outputs/apk/debug/polyjose-examples-android-debug.apk`. Use a device with Android 12 (API 31) or later (Android 14, API 34, for RSA-OAEP-256), a screen lock (PIN, pattern or password) and an enrolled strong biometric (fingerprint or face). Record the model and the Android version.
2. **Checks:** tap **Run the checks**. Expected: `43/43 PASS (1 skipped)` with StrongBox, `42/42 PASS (2 skipped)` without. Record the line.
3. **Keys:** read the "This device" card: model, Android and API level, emulator (no), StrongBox, secure lock screen (yes).
4. **Sign**, Android Keystore (TEE), ES256, **Sign and verify**. Expected: verified, "Key lives in: TrustedEnvironment".
5. **Sign**, StrongBox, `Required`, ES256. With StrongBox: "Key lives in: StrongBox". Without: the row is disabled ("no StrongBox on this device"), and Run anyway gives `PlatformKeyFailed` with no key left. Then `Preferred`: record the reported level (`StrongBox`, or `TrustedEnvironment` without StrongBox).
6. **Sign**, StrongBox, `Required`, ES384: disabled ("StrongBox can't do ES384"); Run anyway gives `UnsupportedAlgorithm`.
7. **Encrypt**, RSA-OAEP-256, Android Keystore (TEE), **Round trip**. Expected: the plaintext is the demo payload. Then the same with StrongBox `Required`: record what it gives, success or the code (RSA-OAEP-256 in StrongBox isn't verified on a device yet).
8. **Time-bound**: Sign, Android Keystore (TEE), ES256, User authentication "Time-bound", 30 seconds. Tap **Sign and verify** before any prompt. Expected: `UserAuthenticationRequired`, and the new key is chosen under Key. Android counts unlocking the phone as an authentication: if it was unlocked within the last 30 seconds, the key may sign without a prompt, so wait 30 seconds and tap again. Tap **Authenticate now**, authenticate, then **Sign and verify** within 30 seconds. Expected: verified. Wait past the window and sign again. Expected: `UserAuthenticationRequired`.
9. **Per use**: Sign, Android Keystore (TEE), ES256, User authentication "Per use", **Sign and verify**. A prompt appears during the signature: authenticate. Expected: verified. Again, and press **Cancel**. Expected: `UserAuthenticationRequired`. Record what each prompt showed.
10. **PS256**: Sign, Android Keystore (TEE), PS256, **Sign and verify**. Expected: verified in software (polyjose checks the Keystore's PSS signature).
11. **Keys:** with the time-bound and per-use keys of steps 8 and 9 still there, open the Keys tab and tap **Refresh**. Expected: both are listed with their authentication, and no prompt appears.
12. **Log:** tap **Share** (or **Copy all**) and save the text. Check it has no private member: `grep -E '"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:' log.txt` finds nothing (the demo walk also checks the secret values themselves). Then **Keys** → **Delete all playground keys**, which also drops this session's software keys.

Record one row per device: the model, Android and API level, the app's commit, the Checks line, the default key level (step 4), the TEE results for sign, ECDH and RSA-OAEP-256, the StrongBox results for ES256, RS256, ECDH P-256 and RSA-OAEP-256 (or "no StrongBox"), step 8, step 9 (approve, cancel), step 10 and step 11. Write PASS, FAIL with the code, or SKIPPED with the reason in each cell.

## Test keys

[`TestKeys.kt`](src/main/kotlin/dev/polyjose/examples/TestKeys.kt) holds two keys copied from the RFCs: the RFC 7515 Appendix A.2 RSA key (polyjose 0.4.0 cannot generate RSA keys) and the RFC 7638 §3.1 key. They are published: **test keys, never use them in production.** Every other key is generated at run time.
