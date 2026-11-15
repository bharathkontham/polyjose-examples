# polyjose examples

Complete example apps for [polyjose](https://github.com/bharathkontham/polyjose), the pure-Rust JOSE library (JWS, JWE, JWK, JWT), on every platform it ships for:

| Folder | App | Package |
|---|---|---|
| [`node/`](node/README.md) | `polyjose-examples-node`, a Node.js script | [`@polyjose/node`](https://www.npmjs.com/package/@polyjose/node) |
| [`web/`](web/README.md) | `polyjose-examples-web`, a web page (WebAssembly) | [`@polyjose/wasm`](https://www.npmjs.com/package/@polyjose/wasm) |
| [`ios/`](ios/README.md) | `polyjose-examples-ios`, a SwiftUI app | the `polyjose` Swift package |
| [`android/`](android/README.md) | `polyjose-examples-android`, a Kotlin app | [`dev.polyjose:polyjose`](https://central.sonatype.com/artifact/dev.polyjose/polyjose) |

Each app is organised by developer task: one example file per task, which you can read and copy on its own. Each app also runs every example as a check and reports the result, so the examples are known to work with the release they pin (polyjose **0.2.0**). The checks are the same on every platform; [CATALOG.md](CATALOG.md) lists them.

## How do I…?

| Task | Node.js | Web | iOS | Android |
|---|---|---|---|---|
| Sign and verify a JWS | [node](node/README.md#sign-and-verify-a-jws) | [web](web/README.md#sign-and-verify-a-jws) | [ios](ios/README.md#sign-and-verify-a-jws) | [android](android/README.md#sign-and-verify-a-jws) |
| Issue and validate a JWT | [node](node/README.md#issue-and-validate-a-jwt) | [web](web/README.md#issue-and-validate-a-jwt) | [ios](ios/README.md#issue-and-validate-a-jwt) | [android](android/README.md#issue-and-validate-a-jwt) |
| Reject tokens with an allow-list | [node](node/README.md#reject-tokens-with-an-allow-list) | [web](web/README.md#reject-tokens-with-an-allow-list) | [ios](ios/README.md#reject-tokens-with-an-allow-list) | [android](android/README.md#reject-tokens-with-an-allow-list) |
| Encrypt and decrypt (JWE) | [node](node/README.md#encrypt-and-decrypt-jwe) | [web](web/README.md#encrypt-and-decrypt-jwe) | [ios](ios/README.md#encrypt-and-decrypt-jwe) | [android](android/README.md#encrypt-and-decrypt-jwe) |
| Create keys and use a JWK Set | [node](node/README.md#create-keys-and-use-a-jwk-set) | [web](web/README.md#create-keys-and-use-a-jwk-set) | [ios](ios/README.md#create-keys-and-use-a-jwk-set) | [android](android/README.md#create-keys-and-use-a-jwk-set) |
| Decode a token before verifying it | [node](node/README.md#decode-a-token-before-verifying-it) | [web](web/README.md#decode-a-token-before-verifying-it) | [ios](ios/README.md#decode-a-token-before-verifying-it) | [android](android/README.md#decode-a-token-before-verifying-it) |
| Use a platform key store | — | — | [ios](ios/README.md#use-a-platform-key-store) | [android](android/README.md#use-a-platform-key-store) |

The last two tasks need a polyjose release after 0.2.0; their sections say when they arrive.

Every example passes an explicit algorithm allow-list to verify and decrypt (RFC 8725 §3.1), never accepts `alg: none`, and never logs key material. Keys are generated at run time, except two RSA keys copied from the RFCs, which are labelled **test keys, never use in production**.

## Run an app

Each app has a `run.sh` that builds it, runs every check without a user interface, and prints one line per check, then a final line:

```
POLYJOSE-VERIFY: 34/34 PASS
```

`run.sh` exits 0 only when every check passed. The format and the rules are in [CATALOG.md](CATALOG.md#output-and-pass-rule).

| App | Needs | Run |
|---|---|---|
| Node.js | Node.js 22.12 or later | `node/run.sh` |
| Web | Node.js 22.12 or later, and Google Chrome (`CHROME` names its binary) | `web/run.sh` |
| iOS | macOS with Xcode and an iOS Simulator (`DEVELOPER_DIR` selects the Xcode) | `ios/run.sh` |
| Android | A JDK (`JAVA_HOME`) and the Android SDK with an emulator (`ANDROID_HOME`) | `android/run.sh` |

Each app's README says how to run it by hand as well (in a browser, from Xcode on an iPhone, from Android Studio), and what each run shows.

## Build against a polyjose checkout

By default each app uses the published polyjose release, pinned in one place per platform (`node/package.json`, `web/package.json`, the iOS project's Swift package requirement, `android/build.gradle.kts`). To try the apps against unreleased polyjose code instead, point `POLYJOSE_SRC` at a polyjose checkout:

```sh
POLYJOSE_SRC=../../polyjose node/run.sh
```

The app then builds polyjose from that checkout with polyjose's own build scripts, which need the toolchains in polyjose's `CONTRIBUTING.md`. The checkout is never written to. A relative `POLYJOSE_SRC` is resolved from the app's folder.

## License

[MIT](LICENSE).
