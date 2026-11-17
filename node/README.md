# polyjose example app for Node.js

`polyjose-examples-node` uses [`@polyjose/node`](https://www.npmjs.com/package/@polyjose/node) 0.4.0, the only dependency. Each file in [`examples/`](examples/) answers one "How do I…?" question, imports `@polyjose/node` directly, and can be copied into your project on its own. [`verify.mjs`](verify.mjs) runs every check of the [catalog](../CATALOG.md) through those files.

Needs Node.js 22.12 or later.

## Run it

```sh
npm ci --ignore-scripts
npm run verify
```

`npm ci --ignore-scripts` installs `@polyjose/node` 0.4.0 from `package-lock.json`, running no install script. `npm run verify` ([`run.mjs`](run.mjs)) runs [`verify.mjs`](verify.mjs), which prints one line per check and ends with:

```
POLYJOSE-VERIFY: 34/34 PASS
```

It exits 0 only when all 34 checks of the catalog ran and passed. When they take longer than `RUN_TIMEOUT` seconds (default 120), it stops them, prints `POLYJOSE-VERIFY: 0/34 PASS (timeout)` and exits 1. The output format is described in [CATALOG.md](../CATALOG.md#output-and-pass-rule).

### Against a local polyjose checkout

```sh
npm ci --ignore-scripts
POLYJOSE_SRC=../../polyjose npm run verify
```

With `POLYJOSE_SRC` set, `npm run verify` first runs `npm run build:local` ([`build.mjs`](build.mjs)), which you can also run on its own. It copies the checkout to `.build/src` (`POLYJOSE_BUILD_DIR` picks another folder outside the checkout), builds `@polyjose/node` there with polyjose's own `bindings/node/scripts/build.sh`, and points `node_modules/@polyjose/node` at the local build. The checkout itself is never written to. It needs Rust (cargo) as well; the first build takes a few minutes. Run `npm ci --ignore-scripts` again to go back to the published package.

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

Not on Node.js: platform key stores are an iOS and Android feature (see [ios](../ios/README.md) and [android](../android/README.md)).

## Test keys

[`examples/test-keys.mjs`](examples/test-keys.mjs) holds two keys copied from the RFCs: the RFC 7515 Appendix A.2 RSA key (polyjose 0.4.0 cannot generate RSA keys) and the RFC 7638 §3.1 key. They are published: **test keys, never use them in production.** Every other key is generated at run time.
