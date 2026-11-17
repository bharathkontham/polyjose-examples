# polyjose example app for Node.js, in TypeScript

`polyjose-examples-node-ts` uses [`@polyjose/node`](https://www.npmjs.com/package/@polyjose/node) 0.4.0, its only dependency, and the types it ships (`JwkObject`, `JwsVerified`, `JwtVerified`, `JweDecrypted`, `PolyjoseError`, `ErrorCode`, ...). Each file in [`examples/`](examples/) answers one "How do I…?" question, imports `@polyjose/node` directly, and can be copied into your project. [`verify.ts`](verify.ts) runs every check of the [catalog](../CATALOG.md) through those files.

The code is strict TypeScript (`strict`, `noUncheckedIndexedAccess`; see [`tsconfig.json`](tsconfig.json)) with no `any`. There is no build step: Node.js runs the `.ts` files directly, by type stripping, and `tsc --noEmit` only checks the types. So the files use only erasable syntax (`erasableSyntaxOnly`), import types with `import type` (`verbatimModuleSyntax`), and import each other with the `.ts` extension (`allowImportingTsExtensions`). The dev dependencies are `typescript` and `@types/node`, nothing else.

For the same examples in plain JavaScript, with no build step and no types, see [`node/`](../node/README.md).

Needs Node.js 22.18 or later, where type stripping is on by default. On Node.js 22.12 to 22.17 it is behind the `--experimental-strip-types` flag:

```sh
npx tsc --noEmit && node --experimental-strip-types run.ts
```

## Run it

```sh
npm ci --ignore-scripts
npm run verify
```

`npm ci --ignore-scripts` installs the pinned versions from `package-lock.json`, running no install script. `npm run verify` type-checks everything with `tsc --noEmit`, then runs [`run.ts`](run.ts), which runs [`verify.ts`](verify.ts). That prints one line per check and ends with:

```
POLYJOSE-VERIFY: 34/34 PASS
```

The check ids and their order are the same as in `node/`. It exits 0 only when all 34 checks of the catalog ran and passed. When they take longer than `RUN_TIMEOUT` seconds (default 120), it stops them, prints `POLYJOSE-VERIFY: 0/34 PASS (timeout)` and exits 1. The output format is described in [CATALOG.md](../CATALOG.md#output-and-pass-rule).

This app runs against the published package only. To try a local polyjose build, use `node/` (`POLYJOSE_SRC`, see its README).

## How do I…?

Every verify and decrypt call passes an explicit `allowedAlgs` (and `allowedEnc` for JWE), never one taken from the token (RFC 8725 §3.1). `@polyjose/node`'s types make both lists required, so leaving one out does not compile. Every function cites the RFC section it implements.

### Sign and verify a JWS

[`examples/sign-verify-jws.ts`](examples/sign-verify-jws.ts): a key pair for each algorithm (HS256, RS256, PS256, ES256, ES384, ES512, EdDSA; the `JwsAlg` type), compact signing and verification, and a general JSON JWS with two signers (RFC 7515).
Checks: `jws/sign-verify/*`, `jws/json/general-two-signers`.

### Issue and validate a JWT

[`examples/sign-verify-jwt.ts`](examples/sign-verify-jwt.ts): issue a JWT with `iss`, `aud` and `exp`, validate it with one key, or with a JWK Set where the token's `kid` picks the key (RFC 7519, RFC 7517 §5).
Checks: `jwt/sign-verify/*`, `jwt/verify-with-jwks/selects-by-kid`.

### Reject tokens with an allow-list

[`examples/verify-allow-list.ts`](examples/verify-allow-list.ts): handle a refused token by its stable `PolyjoseError` code, typed as `ErrorCode`: an algorithm outside the list, `alg: none`, a changed payload, the wrong key, a key of the wrong family, an expired JWT, the wrong audience (RFC 8725).
Checks: `jws/verify/rejects-*`, `jwt/verify/rejects-*`.

### Encrypt and decrypt (JWE)

[`examples/encrypt-decrypt.ts`](examples/encrypt-decrypt.ts): encrypt to a recipient's public key with `ECDH-ES+A256KW` and `A256GCM` on P-256, P-384, P-521 or X25519, and decrypt with allow-lists (RFC 7516, RFC 7518 §4.6).
Checks: `jwe/ecdh-es-a256kw/*`, `jwe/decrypt/rejects-*`.

### Create keys and use a JWK Set

[`examples/keys-jwks.ts`](examples/keys-jwks.ts): generate an EC key, take its public half, compute its RFC 7638 thumbprint, export and import PKCS#8 PEM, build a public JWK Set and select a key from it by `kid` (RFC 7517).
Checks: `jwk/generate/ec-p-256`, `jwk/thumbprint/rfc7638`, `jwk/pem/round-trip`, `jwks/select/by-kid`.

### Use a platform key store

Not on Node.js: platform key stores are an iOS and Android feature (see [ios](../ios/README.md) and [android](../android/README.md)).

## Copying a file into your project

Each example imports only `@polyjose/node`, except that `sign-verify-jws.ts` takes its RSA test key from `test-keys.ts`; replace that with your own key. To run `.ts` files the same way, use the compiler options of [`tsconfig.json`](tsconfig.json). If you compile to JavaScript instead, drop `noEmit` and `allowImportingTsExtensions` and set `rewriteRelativeImportExtensions`, so that the `.ts` imports become `.js`.

## Test keys

[`examples/test-keys.ts`](examples/test-keys.ts) holds two keys copied from the RFCs: the RFC 7515 Appendix A.2 RSA key (polyjose 0.4.0 cannot generate RSA keys) and the RFC 7638 §3.1 key. They are published: **test keys, never use them in production.** Every other key is generated at run time.
