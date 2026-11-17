# polyjose example app for the web

`polyjose-examples-web` uses [`@polyjose/wasm`](https://www.npmjs.com/package/@polyjose/wasm) 0.4.0, the only dependency, in the browser, with no bundler. Each file in [`examples/`](examples/) answers one "How do I…?" question, imports `@polyjose/wasm` directly, and can be copied into your project on its own. [`index.html`](index.html) runs every check of the [catalog](../CATALOG.md) through those files, with [`verify.mjs`](verify.mjs).

Needs Node.js 22.12 or later (for `npm` and the local server) and a current browser. `run.sh` needs Google Chrome or Chromium.

## How it loads

- An [import map](https://html.spec.whatwg.org/multipage/webappapis.html#import-maps) in `index.html` maps the name `@polyjose/wasm` to `node_modules/@polyjose/wasm/browser.mjs`, the package's `browser` entry. The examples keep the plain `import … from "@polyjose/wasm"`, so they also work unchanged with a bundler (webpack 5, Vite, esbuild), which picks the same entry from the package's `exports`.
- Nothing is loaded at import time. The first polyjose call fetches `polyjose_wasm_bg.wasm` from next to `browser.mjs`, checks it against the SHA-384 the package was built with (Subresource Integrity), and compiles it. Every function returns a Promise.
- The page must come from a web server: browsers do not fetch WebAssembly from `file://`, and the server must send `.wasm` as `application/wasm`. [`serve.mjs`](serve.mjs) is such a server, with no dependencies, on `127.0.0.1` only.

## Run it

```sh
./run.sh
```

`run.sh` runs `npm ci`, starts `serve.mjs` on a free port, loads the page in headless Chrome and prints the page's lines, which end with:

```
POLYJOSE-VERIFY: 34/34 PASS
```

It exits 0 only when every check passed, and stops the server and Chrome before it exits. Chrome is `CHROME` when set, else the macOS Google Chrome app, else `google-chrome` or `chromium` on `PATH`; it runs with a fresh temporary profile. When the result line does not arrive within `RUN_TIMEOUT` seconds (default 120), `run.sh` prints `POLYJOSE-VERIFY: 0/34 PASS (timeout)` and exits 1. The output format is described in [CATALOG.md](../CATALOG.md#output-and-pass-rule).

### In a browser

```sh
npm ci
node serve.mjs
```

Open the printed URL (`http://127.0.0.1:8000/`; `--port` picks another port). The page lists one line per check in `<pre id="result">`, and logs the same lines to the browser console.

### Against a local polyjose checkout

```sh
POLYJOSE_SRC=../../polyjose ./run.sh
```

[`build.sh`](build.sh) copies the checkout to `.build/src`, builds `@polyjose/wasm` there with polyjose's own `bindings/wasm/scripts/build-package.sh --no-pack`, runs `npm ci` and points `node_modules/@polyjose/wasm` at the local build. The checkout itself is never written to. It needs Rust (cargo) with the `wasm32-unknown-unknown` target and wasm-pack as well; the first build takes a few minutes. `POLYJOSE_SRC=../../polyjose ./build.sh` followed by `node serve.mjs` shows the result in your own browser. Run `./run.sh` without `POLYJOSE_SRC` (or `npm ci`) to go back to the published package.

## How do I…?

Every verify and decrypt call passes an explicit `allowedAlgs` (and `allowedEnc` for JWE), never one taken from the token (RFC 8725 §3.1). Every function cites the RFC section it implements.

### Sign and verify a JWS

[`examples/sign-verify-jws.mjs`](examples/sign-verify-jws.mjs): a key pair for each algorithm (HS256, RS256, PS256, ES256, ES384, ES512, EdDSA), compact signing and verification, and a general JSON JWS with two signers (RFC 7515).
Checks: `jws/sign-verify/*`, `jws/json/general-two-signers`.

### Issue and validate a JWT

[`examples/sign-verify-jwt.mjs`](examples/sign-verify-jwt.mjs): issue a JWT with `iss`, `aud` and `exp`, validate it with one key, or with a JWK Set where the token's `kid` picks the key (RFC 7519, RFC 7517 §5).
Checks: `jwt/sign-verify/*`, `jwt/verify-with-jwks/selects-by-kid`.

### Reject tokens with an allow-list

[`examples/verify-allow-list.mjs`](examples/verify-allow-list.mjs): handle a refused token by its stable `PolyjoseError` code: an algorithm outside the list, `alg: none`, a changed payload, the wrong key, a key of the wrong family, an expired JWT, the wrong audience (RFC 8725).
Checks: `jws/verify/rejects-*`, `jwt/verify/rejects-*`.

### Encrypt and decrypt (JWE)

[`examples/encrypt-decrypt.mjs`](examples/encrypt-decrypt.mjs): encrypt to a recipient's public key with `ECDH-ES+A256KW` and `A256GCM` on P-256, P-384, P-521 or X25519, and decrypt with allow-lists (RFC 7516, RFC 7518 §4.6).
Checks: `jwe/ecdh-es-a256kw/*`, `jwe/decrypt/rejects-*`.

### Create keys and use a JWK Set

[`examples/keys-jwks.mjs`](examples/keys-jwks.mjs): generate an EC key, take its public half, compute its RFC 7638 thumbprint, export and import PKCS#8 PEM, build a public JWK Set and select a key from it by `kid` (RFC 7517).
Checks: `jwk/generate/ec-p-256`, `jwk/thumbprint/rfc7638`, `jwk/pem/round-trip`, `jwks/select/by-kid`.

### Decode a token before verifying it

Not in this app yet. polyjose 0.4.0 has the unverified decode functions; this example arrives in a later update of this repository.

### Use a platform key store

Not on the web: platform key stores are an iOS and Android feature (see [ios](../ios/README.md) and [android](../android/README.md)).

## Test keys

[`examples/test-keys.mjs`](examples/test-keys.mjs) holds two keys copied from the RFCs: the RFC 7515 Appendix A.2 RSA key (polyjose 0.4.0 cannot generate RSA keys) and the RFC 7638 §3.1 key. They are published: **test keys, never use them in production.** Every other key is generated at run time, from the browser's random number generator (`crypto.getRandomValues`).
