# polyjose in Next.js: the browser and the server

A Next.js (App Router) app in which the same tokens cross between the browser and the server:

- the browser signs a JWS and the server verifies it;
- the server issues a JWT and the browser validates it against the server's JWK Set;
- the browser encrypts a JWE to the server, and the server encrypts one to the browser.

The browser side uses [`@polyjose/wasm`](https://www.npmjs.com/package/@polyjose/wasm) (WebAssembly). The server side uses [`@polyjose/node`](https://www.npmjs.com/package/@polyjose/node) (a native Node.js addon) in route handlers. Both are polyjose 0.4.0.

## Run it

Needs Node.js 22.12 or later. `npm run verify` also needs Google Chrome or Chromium.

```sh
npm ci --ignore-scripts
npm run verify             # build, start, run the 8 checks in headless Chrome
```

`npm run verify` builds the app (`next build`), starts it on a free port of 127.0.0.1 (`next start`), opens `/?verify=1` in headless Chrome and prints the page's lines:

```
# polyjose 0.4.0 through @polyjose/wasm in HeadlessChrome …, and @polyjose/node in the route handlers
PASS nextjs/browser-signs/server-verifies-es256
…
POLYJOSE-VERIFY: 8/8 PASS
```

It exits 0 only when all 8 checks pass and the secrets grep is empty: no private or symmetric JWK member (`"d":`, `"k":`, …) and no unhandled polyjose error in the browser console or the server output. It also checks that the `.wasm` file Next.js emitted is the package's file, byte for byte. `CHROME` names the Chrome binary. `RUN_TIMEOUT` (seconds, default 120) bounds the run; when it runs out the last line is `POLYJOSE-VERIFY: 0/8 PASS (timeout)` and the exit is 1.

To use the app yourself:

```sh
npm run build && npm start # then open http://localhost:3000
```

Each button runs one crossing and writes both sides' steps to the log on the page, the browser console and the server's stdout. **Run the checks** runs the same checks as `npm run verify`.

## What runs where

| Where | Files | Uses |
|---|---|---|
| Browser | `lib/browser/polyjose.ts`: every polyjose operation of the page (generate a key, public JWK, thumbprint, sign, verify, validate a JWT with a JWK Set, encrypt, decrypt) | `@polyjose/wasm` |
| Browser | `lib/browser/crossings.ts`: the four crossings; `lib/browser/checks.ts`: the checks; `components/Playground.tsx`: the buttons and the log | the module above, and `fetch` to `/api` |
| Server | `app/api/*/route.ts`: the route handlers; `app/api/_server/keys.ts`: the server's private keys | `@polyjose/node` |
| Both | `lib/shared.ts`: algorithms, demo claims, the fixed demo messages, the log line format | nothing |

The route handlers:

| Route | Does |
|---|---|
| `GET /api/jwks` | the server's public keys as a JWK Set: one ES256 signing key, one ECDH-ES+A256KW key |
| `POST /api/verify` `{ token, jwk }` | verifies the browser's compact JWS with the browser's public JWK, ES256 only |
| `POST /api/issue` | issues a JWT for the demo subject, signed ES256, valid 5 minutes |
| `POST /api/decrypt` `{ token }` | decrypts a JWE sent to the server's key, ECDH-ES+A256KW and A256GCM only |
| `POST /api/encrypt` `{ jwk }` | encrypts the server's demo message to the browser's public JWK |

Each answers `{ "ok": true, …, "steps": [...] }` or `{ "ok": false, "code": "InvalidSignature", "steps": [...] }`. `steps` are the server's log lines for that request.

- **The WebAssembly module.** `@polyjose/wasm` fetches `polyjose_wasm_bg.wasm` on its first call, with Subresource Integrity, so the browser refuses any other bytes. Next.js's default bundler (Turbopack) copies the file to `.next/static/media/` unchanged. polyjose runs only in event handlers and effects of client components (`"use client"`), never while the server renders the page.
- **The native addon.** `next.config.mjs` lists `@polyjose/node` in `serverExternalPackages`, so Node.js loads it from `node_modules` at run time and the bundler never touches it. Every route handler declares `export const runtime = "nodejs"`.
- **The server's keys** are made on the first request and live until the server stops. To keep them across restarts, set `POLYJOSE_SERVER_JWKS` to a private JWK Set (JSON text) with one P-256 key whose `alg` is `ES256` and one whose `alg` is `ECDH-ES+A256KW`. Keep it in your secret store, never in the repository. Only the keys' `kid`s are logged. `keys.ts` starts with `import "server-only"`, so a client component that imports it fails the build.
- **The browser's keys** are software keys in page memory. polyjose 0.4.0 has no browser key store and no non-extractable WebCrypto keys, so a private key here is a JWK object in JavaScript.

## Why not the edge runtime

`@polyjose/node` is a native addon, and the edge runtime can't load native addons, so the route handlers run on Node.js. On an edge or Workers host you would use `@polyjose/wasm` on the server too; this app doesn't show that.

## What keeps it safe

- **Allow-lists are the code's own.** Every verify and decrypt names its algorithms (`allowedAlgs`, and `allowedEnc` for JWE) as constants, never read from the token's header (RFC 8725 §3.1). `none` is never in a list, so an Unsecured JWS is refused with `AlgorithmNotAllowed` (RFC 8725 §3.2).
- **Codes only.** A failure is answered and logged as its polyjose code (`PolyjoseError.code`), or an app code (`BadRequest`, `BodyTooLarge`, `PrivateKeySent`), never as an error message.
- **No key material in a page, response or log.** Every JWK that is logged passes one gate (`publicOnly` in `lib/shared.ts`), and the routes refuse a JWK with a private member (`PrivateKeySent`). The content key and the ECDH shared secret never leave polyjose.
- **Fixed demo messages.** Every token carries one of the messages in `lib/shared.ts`, never typed text, so every token on screen or in a log is a demo token.
- **Demo shortcut.** `/api/verify` takes the browser's public key from the request to show the crossing. A real service takes a client's key from its own registry; the allow-list still decides the algorithm.

## The checks

In order. `npm run verify` and **Run the checks** run them.

| Check | What it shows |
|---|---|
| `nextjs/browser-signs/server-verifies-es256` | an ES256 JWS signed in the browser verifies on the server |
| `nextjs/server-issues-jwt/browser-verifies-with-jwks` | a JWT from the server validates in the browser against `/api/jwks` (alg, `iss`, `aud`, `exp`) |
| `nextjs/browser-encrypts/server-decrypts-p-256` | a JWE (ECDH-ES+A256KW, A256GCM) from the browser decrypts on the server |
| `nextjs/server-encrypts/browser-decrypts-p-256` | a JWE from the server decrypts in the browser |
| `nextjs/server/rejects-alg-not-allowed` | an ES384 token → `AlgorithmNotAllowed` |
| `nextjs/server/rejects-tampered` | a changed payload → `InvalidSignature` |
| `nextjs/server/rejects-none` | `alg: none` → `AlgorithmNotAllowed` |
| `nextjs/jwks/public-only` | `/api/jwks` has two keys with `kid`s and no private member |

## Check it by hand

1. `npm run build && npm start`, then open `http://localhost:3000` in Chrome, Safari and Firefox.
2. Press each crossing button. The log shows the browser's steps (`LOG <tap>.<n>`) and the server's (`LOG <tap>.s<n>`), and the server's terminal shows the same server lines.
3. Press **Run the checks**: the last line is `POLYJOSE-VERIFY: 8/8 PASS`.
4. Search the page log and the server output for `"d":`: there is no match.

## Versions

Exact versions with a committed `package-lock.json`: `next` 16.4.5, `react` and `react-dom` 19.3.1, `@polyjose/wasm` and `@polyjose/node` 0.4.0, `server-only` 0.0.1; for development, `typescript` 6.0.3, `@types/node` 22.x and `@types/react`, `@types/react-dom` 19.3.x. Next.js 16.4.4 has two open advisories, so don't go below 16.4.5; run `npm audit` after any change.
