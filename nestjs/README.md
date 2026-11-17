# polyjose example app for NestJS

`polyjose-examples-nestjs` is a small NestJS service that issues and validates JWTs with [`@polyjose/node`](https://www.npmjs.com/package/@polyjose/node) 0.4.0. It shows the patterns a backend copies:

- signing keys loaded from configuration, with rotation;
- a public JWK Set at `/.well-known/jwks.json`;
- a token endpoint shaped like the OAuth 2.0 client credentials grant (RFC 6749 §4.4);
- a guard that validates Bearer tokens with an explicit algorithm allow-list, issuer, audience and clock leeway (RFC 8725 §3.1, §3.8, §3.9);
- errors that leak nothing: a rejected token gets one opaque `invalid_token` (RFC 6750 §3.1), and the polyjose error code goes to the server log only.

It is an example, not an authorization server: one configured client, no user store, no refresh tokens. Needs Node.js 22.12 or later.

## What is where

| File | What it shows |
|---|---|
| [`src/config.ts`](src/config.ts) | Every environment variable, read once at boot. |
| [`src/polyjose/key.service.ts`](src/polyjose/key.service.ts) | `KeyService`: loads the private JWK Set, signs with the first key, publishes every key's public half (`jwkToPublic`), and derives the verify allow-list from the keys' `alg`. The private key never leaves the service; printing the service (`JSON.stringify`, `util.inspect`) shows only the `kid`. |
| [`src/polyjose/token.service.ts`](src/polyjose/token.service.ts) | `TokenService`: issues tokens with `iss`, `sub`, `aud`, `iat` and `exp` = 5 minutes (RFC 7519 §4.1), and validates them with `jwtVerifyWithJwks`, 30 s leeway. |
| [`src/polyjose/polyjose.module.ts`](src/polyjose/polyjose.module.ts) | The global `PolyjoseModule` that provides both services. |
| [`src/auth/jwt-auth.guard.ts`](src/auth/jwt-auth.guard.ts) | `JwtAuthGuard`: `Authorization: Bearer` (RFC 6750 §2.1), 401 with `WWW-Authenticate: Bearer error="invalid_token"` and the fixed body `{"error":"invalid_token"}` on any failure. |
| [`src/auth/claims.decorator.ts`](src/auth/claims.decorator.ts) | `@Claims()`: the validated claims in a handler. |
| [`src/routes/`](src/routes/) | `GET /.well-known/jwks.json`, `POST /token`, `GET /me`. |
| [`src/safe-exception.filter.ts`](src/safe-exception.filter.ts) | Any other error becomes a plain 500; only its name or polyjose code is logged, never its message. |
| [`src/verify.ts`](src/verify.ts) | The checks (below). |

Every verify call passes an explicit `allowedAlgs` built from the service's own keys, never from the token; `none` is never accepted.

## Configuration

| Variable | Meaning |
|---|---|
| `POLYJOSE_SIGNING_JWKS` | A private JWK Set (RFC 7517 §5) as JSON text. Each key needs a unique `kid` and an `alg`; symmetric (`oct`) keys are refused, because every key is published. |
| `POLYJOSE_SIGNING_JWKS_FILE` | A path to a file holding that JWK Set, used when `POLYJOSE_SIGNING_JWKS` is unset. |
| `POLYJOSE_ISSUER` | The `iss` of issued tokens, required on validation. Default `http://localhost:3000`. |
| `POLYJOSE_AUDIENCE` | The `aud` of issued tokens, required on validation. Default `polyjose-examples-nestjs`. |
| `POLYJOSE_DEMO_CLIENT_ID` | The one client `POST /token` serves. Default `demo-client`. |
| `POLYJOSE_DEMO_CLIENT_SECRET` | Its secret, compared in constant time (`crypto.timingSafeEqual` over SHA-256 digests). When unset, `POST /token` refuses every request. |
| `PORT` | The HTTP port. Default `3000`. |

With neither signing variable set, the service generates an ephemeral ES256 key at boot and logs `ephemeral signing key kid=<kid>` (the kid is the key's RFC 7638 thumbprint). Tokens it signed stop verifying when the process restarts.

**Rotation.** Put the new private key first and keep the old key after it; the old key's public half is enough. New tokens are signed by the new key, and tokens signed by the old one keep verifying until they expire, because the JWK Set still publishes it and the token's `kid` picks it. Remove the old key once its last token has expired (5 minutes plus the 30 s leeway).

Keep private keys out of source control and out of logs; load them from your secret store into one of the two variables.

## Run the checks

```sh
npm ci --ignore-scripts
npm run verify
```

`npm run verify` compiles the service with `tsc` and runs [`src/verify.ts`](src/verify.ts). It boots the service in the same process on a free port, with two keys generated at run time (the current one signs; the previous one is published as a public key only) and a fixed test client secret, then calls the endpoints with `fetch`. It prints one line per check and ends with:

```
POLYJOSE-VERIFY: 10/10 PASS
```

The checks: `nestjs/jwks/public-only`, `nestjs/token/issues-es256-jwt`, `nestjs/token/rejects-bad-client-secret`, `nestjs/guard/accepts-valid`, `nestjs/guard/rejects-missing`, and `nestjs/guard/rejects-expired`, `-wrong-audience`, `-alg-not-allowed`, `-tampered` and `-unknown-kid`, each of which asserts the 401 challenge and the polyjose code (`TokenExpired`, `InvalidClaim`, `AlgorithmNotAllowed`, `InvalidSignature`, `NoMatchingKey`) in the server log.

It also scans the whole server log and every response body for private JWK members (`"d":`, `"k":` and the RSA ones) and for the client secret. It exits 0 only when all 10 checks ran and passed and the scan found nothing. `RUN_TIMEOUT` (seconds, default 120) bounds the run; when it runs out, it prints `POLYJOSE-VERIFY: 0/10 PASS (timeout)` and exits 1. `VERIFY_LOG=1` prints the captured server log to stderr.

There is no test framework: the app is the test.

## Run the service

```sh
npm ci --ignore-scripts
POLYJOSE_DEMO_CLIENT_SECRET=change-me npm start
```

Then, in another shell:

```sh
# The public JWK Set
curl -s http://localhost:3000/.well-known/jwks.json

# A token for the demo client (RFC 6749 §4.4.2, form-encoded)
TOKEN=$(curl -s -X POST http://localhost:3000/token \
  -d grant_type=client_credentials -d client_id=demo-client -d client_secret=change-me \
  | node -e 'process.stdin.on("data", (d) => console.log(JSON.parse(d).access_token))')

# The protected route: 200 with the claims
curl -s http://localhost:3000/me -H "Authorization: Bearer $TOKEN"

# Without a token, or with a bad one: 401 and the WWW-Authenticate challenge
curl -si http://localhost:3000/me
curl -si http://localhost:3000/me -H "Authorization: Bearer not.a.token"
```

The server log shows why a token was refused (`token rejected code=InvalidBase64`, for the last line); the client only ever sees `invalid_token`.

## Notes

- NestJS 12 is ESM; the build is plain `tsc` with `experimentalDecorators` and `emitDecoratorMetadata` (Nest's own ESM starter settings, plus `strict`). There is no `@nestjs/cli`.
- Only the form body parser is enabled, the one `POST /token` needs.
- `@polyjose/node` is a native addon, so the service runs on Node.js, not on an edge runtime.
