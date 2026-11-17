# polyjose in Next.js: the browser and the server

A Next.js (App Router) app: an interactive playground in the browser, and route handlers on the server, with the same tokens crossing between them:

- the browser signs a JWS and the server verifies it;
- the server issues a JWT and the browser validates it against the server's JWK Set;
- the browser encrypts a JWE to the server, and the server encrypts one to the browser.

The playground has the tabs **Checks**, **Sign**, **Encrypt**, **Server**, **Keys** and **Log**: every algorithm polyjose offers in a browser, the failure actions, an explanation for each, and a log of every step that you can copy and share.

The browser side uses [`@polyjose/wasm`](https://www.npmjs.com/package/@polyjose/wasm) (WebAssembly). The server side uses [`@polyjose/node`](https://www.npmjs.com/package/@polyjose/node) (a native Node.js addon) in route handlers. Both are polyjose 0.4.0.

## Run it

Needs Node.js 22.12 or later. `npm run verify` also needs Google Chrome or Chromium.

```sh
npm ci --ignore-scripts
npm run verify             # build, start, run the 8 checks and the demo walk in headless Chrome
```

`npm run verify` builds the app (`next build`), starts it on a free port of 127.0.0.1 (`next start`), opens `/?verify=1&demo=1` in headless Chrome and prints the page's lines:

```
# polyjose 0.4.0 through @polyjose/wasm in HeadlessChrome …, and @polyjose/node in the route handlers
PASS nextjs/browser-signs/server-verifies-es256
…
POLYJOSE-VERIFY: 8/8 PASS
# polyjose playground demo walk: 330 steps, every one through the tabs' code
POLYJOSE-PLAYGROUND: 330/330 OK
```

- `?verify=1` runs the 8 checks below. `?demo=1` runs the [demo walk](#the-demo-walk). Each also works on its own.
- Of the walk's lines, only a step that didn't give its expected outcome is printed (`PLAYGROUND bad <step>: expected <Code>, got <Code>`); the page and the console have every step.
- It exits 0 only when all 8 checks pass, all 330 walk steps give their expected outcome, each result line agrees with the lines above it, and the secrets scan of the browser console and the server output finds nothing. The scan reads each log entry with its continuation lines joined back, and looks for a private or symmetric JWK member as JSON (`"d":`, `"k":`, …), an unhandled polyjose error, and the key values themselves: the `d` of the server's two keys (the script generates them and starts the server with them as `POLYJOSE_SERVER_JWKS`) and the private values of the RSA test key. It prints counts only.
- It also checks that the `.wasm` file Next.js emitted is the package's file, byte for byte.
- `CHROME` names the Chrome binary. `RUN_TIMEOUT` (seconds, default 120) bounds the run; when it runs out, the result lines are `POLYJOSE-VERIFY: 0/8 PASS (timeout)` and `POLYJOSE-PLAYGROUND: 0/330 OK (timeout)`, and the exit is 1.

To use the app yourself:

```sh
npm run build && npm start # then open http://localhost:3000
```

Every tap writes its steps to the Log tab and the browser console, and the route handlers write theirs to the server's stdout. **Run the checks** and **Run the demo walk** (Checks tab) run what `npm run verify` runs.

## The playground

It follows the repository's [PLAYGROUND.md](../PLAYGROUND.md): its Browser column and [web notes](../PLAYGROUND.md#web-notes) say what differs in a browser.

| Tab | What it does |
|---|---|
| **Checks** | The 8 checks, and the demo walk. The page opens on this tab. |
| **Sign** | JWS compact or JWT; the key store; one row per algorithm, each with an info button; a new key or one from the Keys tab; the fixed payload. **Sign**, **Verify**, **Sign and verify**. **Try a failure**: tamper, other algorithm allowed, wrong key, expired. |
| **Encrypt** | The key-management `alg`, the curve (ECDH-ES), the `enc`, the key store that decrypts, the key. **Encrypt** (always to the key's public JWK), **Decrypt**, **Round trip**. **Try a failure**: tamper ciphertext, other `alg` allowed, wrong key. |
| **Server** | The four crossings and the server's four refusals, one button each. The log shows the browser's steps (`LOG <tap>.<n>`) and the server's (`LOG <tap>.s<n>`). |
| **Keys** | This browser, the key stores, and the session's software keys: create, show the public JWK and its RFC 7638 thumbprint, copy, delete. |
| **Log** | Every step of every tap, newest tap first. **Copy all**, **Share** (the browser's share sheet where it has one, else a `polyjose-playground-log.txt` download) and **Clear**. |

Each result card shows the token (with a copy button), its protected header, the outcome (the verified `alg`, `kid` and claims, or whether the plaintext equals the input), or the error code with its explanation, where the key lives, and the time of each step.

### What it offers

The matrix is in `lib/matrix.ts`; the tabs and the walk both read it.

| | Rows | Key |
|---|---|---|
| Sign (JWS and JWT) | HS256, HS384, HS512; RS256, RS384, RS512, PS256, PS384, PS512; ES256, ES384, ES512, ES256K; EdDSA, and Ed25519 (its fully specified name) | a new key from the browser's random number generator; RSA uses the RFC 7515 Appendix A.2 test key, because polyjose 0.4.0 can't generate RSA keys |
| Encrypt (JWE compact) | ECDH-ES, ECDH-ES+A128KW, +A192KW, +A256KW, on P-256, P-384, P-521 and X25519; RSA-OAEP-256; A128KW, A192KW, A256KW; A128GCMKW, A192GCMKW, A256GCMKW; `dir`; PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW | the same; a PBES2 password is 16 random bytes, shown like a shared key |
| `enc` | A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512, with every row | |

- **Disabled, with the reason "not in polyjose 0.4.0":** the **Platform key store** and **WebCrypto non-extractable key** rows. polyjose 0.4.0 has no browser key store, and every polyjose key is a JWK, so it can't use a `CryptoKey` that keeps its private part out of JavaScript.
- **Disabled failure actions, each with its reason:** "deleted key" (a software key isn't stored anywhere); "wrong key" and "other algorithm allowed" for RS\*, PS\* and RSA-OAEP-256 (the only RSA private key is the A.2 test key); "other algorithm allowed" for EdDSA and Ed25519 (an Ed25519 key has no other signing algorithm).
- polyjose 0.4.0 refuses RSA-OAEP (SHA-1) and RSA1_5 with `UnsupportedAlgorithm`, so they aren't rows.
- **On the decrypt side, a wrong key and a changed token both give `DecryptionFailed`** (RFC 7516 §11.5). The Encrypt tab's tokens have no `kid` in their header, because they go to one known key: polyjose refuses a decryption key whose `kid` differs from the header's with `KeyAlgorithmMismatch` before it decrypts.
- **The browser note.** In a browser, the software keys live in page memory, and any script on the page can read them. The page says so at the top and on the Keys tab.

The explanation texts are in `lib/explanations.ts`, one per tab, algorithm, `enc`, curve, store, failure action, refusal reason and error code.

### The log

One line per step, the same format on both sides:

```
LOG 7.1 input op=jws-sign-verify store=software alg=ES256 payload=preset
LOG 7.2 key-software kty=EC alg=ES256 kid=… crv=P-256 ms=1
LOG 7.3 jwk {"kty":"EC","crv":"P-256",…}
LOG 7.4 call jwsSignCompact ms=1
LOG 7.5 header {"alg":"ES256","kid":"…"}
LOG 7.6 token eyJ…
LOG 7.7 call jwsVerifyCompact ms=1
LOG 7.8 verify ok alg=ES256 kid=… ms=1
```

- `<tap>` counts taps from 1; tap 0 is the `device` line, logged when the page starts. The server's lines for a tap are `LOG <tap>.s<n>`.
- Values have no spaces. `ms` is whole milliseconds from a monotonic clock, shown and never checked. A line over 800 characters continues on lines `LOG <tap>.<step> + …`.
- Every line goes to the browser console as it is, so a log copied from the console and one copied from the Log tab are the same.

### No secrets on the page, in a response or in a log

- Every JWK and header that is shown or logged passes one gate, `publicOnly` in `lib/shared.ts`, which replaces any object with a private or symmetric member (`d`, `p`, `q`, `dp`, `dq`, `qi`, `oth`, `k`) by `"[withheld]"`. A shared key is shown as its type, `alg`, `kid` and length only, and its `kid` is a page-local name, not its thumbprint.
- An error is shown and logged as its code only (`PolyjoseError.code`), never its message.
- Every verify and decrypt names its own allow-lists (`allowedAlgs`, and `allowedEnc` for JWE), never read from the token; `none` is never in one.

### The demo walk

`/?demo=1`, or **Run the demo walk**, runs 330 steps, each through the same functions the tabs' buttons call (`lib/browser/playground.ts`), one tap each:

- every Sign row as a JWS and as a JWT, and every enabled Sign failure action of each row;
- every Encrypt row on every curve with every `enc`, and every enabled Encrypt failure action of each row and curve (with A256GCM);
- Verify and Decrypt as second taps, the Keys tab (create, public JWK, thumbprint, delete; a shared key has no public JWK), and the Server tab's eight buttons;
- then the secrets check over everything the walk logged: no private member as JSON, and none of the private values of the keys the walk made. While the walk runs, `lib/browser/polyjose.ts` records those values; the recorder answers with counts only and is off outside the walk.

A cell must succeed, and a failure action must give its code. Disabled rows and actions have no call to make, so they aren't steps. The last line is `POLYJOSE-PLAYGROUND: N/M OK`.

## What runs where

| Where | Files | Uses |
|---|---|---|
| Browser | `lib/browser/polyjose.ts`: every polyjose operation of the page (generate a key, public JWK, thumbprint, sign, verify, validate a JWT with a JWK Set, encrypt, decrypt) | `@polyjose/wasm` |
| Browser | `lib/browser/playground.ts`: what each tab's buttons do; `lib/browser/crossings.ts`: the four crossings; `lib/browser/checks.ts`: the checks; `lib/browser/demo.ts`: the demo walk; `lib/browser/test-keys.ts`: the RSA test key; `components/`: the tabs | the module above, and `fetch` to `/api` |
| Server | `app/api/*/route.ts`: the route handlers; `app/api/_server/keys.ts`: the server's private keys | `@polyjose/node` |
| Both | `lib/shared.ts`: algorithms, demo claims, the fixed demo messages, the log line format and the `publicOnly` gate; `lib/matrix.ts`: the playground's matrix; `lib/explanations.ts`: the explanation texts | nothing |

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
- **Demo answers only.** `/api/verify` and `/api/decrypt` answer with the payload or plaintext only when it is the app's fixed demo message; anything else is `BadRequest`, so the routes never echo text they verified or decrypted. The server logs only the header of a JWT it issues (a real service never logs the tokens it issues) and only `kty`, `crv` and `kid` of a JWK it receives.
- **Request bodies.** A route reads at most 64 KiB, counted while it reads, so a chunked body without a `Content-Length` is cut off too (`BodyTooLarge`). A body that isn't UTF-8 JSON is `BadRequest`.
- **The routes' posture: an unauthenticated demo.** The routes are same-origin and send no CORS headers; they use no cookies, so there is nothing for a cross-site request (CSRF) to ride on; there is no rate limiting; `/api/issue` signs a token for anyone who asks; and the app sets no Content Security Policy. A real service adds authentication, rate limits and a CSP before it is exposed.

## The checks

In order. `npm run verify` and **Run the checks** run them. [CATALOG.md](../CATALOG.md#nextjs-checks) specifies them, with the output format and the pass rule.

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

`npm run verify` covers Chrome. These steps cover the browsers and what a headless run can't see.

1. `npm run build && npm start`. Open `http://localhost:3000` in Chrome, Safari and Firefox, and do the steps below in each.
2. **Checks:** press **Run the checks** (last line `POLYJOSE-VERIFY: 8/8 PASS`), then **Run the demo walk** (last line `POLYJOSE-PLAYGROUND: 330/330 OK`).
3. **Sign:** for JWS compact and JWT, pick a few rows (an HS, an RS or PS, an ES, EdDSA) and press **Sign**, **Verify** and **Sign and verify**. Open a few info buttons. Press each failure action and read its code and explanation on the card.
4. **Encrypt:** pick ECDH-ES+A256KW on each curve, RSA-OAEP-256, A256KW, `dir` and a PBES2 row, with two or three `enc`s; **Encrypt**, **Decrypt**, **Round trip**, and each failure action. A wrong key and a changed ciphertext both say `DecryptionFailed`.
5. **The disabled rows:** on Sign, Encrypt and Keys, **Platform key store** and **WebCrypto non-extractable key** are disabled with "not in polyjose 0.4.0". On Sign, pick RS256: "Wrong key" and "Other algorithm allowed" are disabled with their reason; pick EdDSA: "Other algorithm allowed" is disabled; "Deleted key" is disabled everywhere.
6. **Server:** press each of the eight buttons. The Log tab shows the browser's lines and the server's (`LOG <tap>.s<n>`), and the server's terminal shows the same server lines.
7. **Keys:** create an ES256 key, an ECDH-ES+A256KW key on X25519 and an HS256 key; show each one's public JWK and thumbprint (the HS256 key has none); sign with the ES256 key from the Sign tab's Key row; delete one, then **Delete all playground keys**.
8. **Log:** **Copy all** and paste it into a file; **Share** (Safari and some Chrome builds open the share sheet; Firefox downloads `polyjose-playground-log.txt`); **Clear**.
9. **The grep:** search the copied or shared log, and the server's output, for a private member. Both of these find nothing. This is the minimum: it finds a private member written as JSON, not a key value logged some other way, which `npm run verify` also looks for.

   ```sh
   grep -E '"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:' polyjose-playground-log.txt
   npm start 2>&1 | tee server.log   # then, after using the page: grep -E '"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:' server.log
   ```

10. Optionally, a phone's browser on the same network: `npm start -- -H 0.0.0.0`, then open `http://<this computer's address>:3000`. Copy and Share may need HTTPS there, because browsers allow the clipboard and the share sheet in secure contexts only.

## Versions

Exact versions with a committed `package-lock.json`: `next` 16.4.5, `react` and `react-dom` 19.3.1, `@polyjose/wasm` and `@polyjose/node` 0.4.0, `server-only` 0.0.1; for development, `typescript` 6.0.3, `@types/node` 22.x and `@types/react`, `@types/react-dom` 19.3.x. Next.js 16.4.4 has two open advisories, so don't go below 16.4.5; run `npm audit` after any change.
