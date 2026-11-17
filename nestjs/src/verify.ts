// `npm run verify`: boots the service in this process on a free port, runs the 10 `nestjs/*`
// checks of ../CATALOG.md against it over HTTP, and prints one line per check, then the result:
//
//   PASS nestjs/jwks/public-only
//   FAIL nestjs/guard/rejects-expired: expected TokenExpired, got InvalidSignature
//   POLYJOSE-VERIFY: 9/10 PASS
//
// It exits 0 only when all 10 checks ran and passed, and the secrets scan found nothing. The scan
// reads the whole server log, every response body and both printed forms of KeyService
// (`JSON.stringify`, `util.inspect`), and looks for a private JWK member (`"d":`, `"k":` and the
// RSA ones), the signing key's actual `d` value and the client secret; the log must also hold no
// issued access token. A FAIL line never shows key material or token contents.
//
// Environment:
//   RUN_TIMEOUT  seconds the run may take (default 120); then `POLYJOSE-VERIFY: 0/10 PASS (timeout)`
//   VERIFY_LOG   set to 1 to print the captured server log to stderr after a clean scan
import process from "node:process";
import { inspect } from "node:util";

import type { LoggerService } from "@nestjs/common";
import {
  PolyjoseError,
  jwkGenerateEc,
  jwkToPublic,
  jwtSign,
  jwtVerifyWithJwks,
  version,
  type JsonObject,
  type JwkObject,
  type JwkSetObject,
} from "@polyjose/node";

import { createApp } from "./app.js";
import { configFromEnv } from "./config.js";
import { KeyService } from "./polyjose/key.service.js";

/** The number of `nestjs/*` checks CATALOG.md lists. */
const EXPECTED_CHECKS = 10;

const timeout = Number(process.env.RUN_TIMEOUT ?? 120);
if (!Number.isInteger(timeout) || timeout <= 0) {
  console.error("verify: RUN_TIMEOUT must be a whole number of seconds");
  process.exit(2);
}
setTimeout(() => {
  console.log(`POLYJOSE-VERIFY: 0/${EXPECTED_CHECKS} PASS (timeout)`);
  console.error(`verify: no result within ${timeout}s`);
  process.exit(1);
}, timeout * 1000).unref();

// --- the service under test --------------------------------------------------------------------

/** A fixed client secret for this test run only. It is a test value: never deploy it. */
const TEST_CLIENT_SECRET = "verify-only-test-secret-not-for-deployment";
const CLIENT_ID = "demo-client";
const ISSUER = "https://issuer.example";
const AUDIENCE = "https://api.example";
const CURRENT_KID = "verify-key-2";
const PREVIOUS_KID = "verify-key-1";

/** Captures everything the service logs, for the code assertions and the secrets scan. */
class CapturingLogger implements LoggerService {
  readonly lines: string[] = [];
  #write(level: string, message: unknown, params: unknown[]): void {
    const context = typeof params.at(-1) === "string" ? params.at(-1) : "";
    const text = typeof message === "string" ? message : JSON.stringify(message);
    this.lines.push(`${level} [${String(context)}] ${text}`);
  }
  log(message: unknown, ...params: unknown[]): void { this.#write("LOG", message, params); }
  error(message: unknown, ...params: unknown[]): void { this.#write("ERROR", message, params); }
  warn(message: unknown, ...params: unknown[]): void { this.#write("WARN", message, params); }
  debug(message: unknown, ...params: unknown[]): void { this.#write("DEBUG", message, params); }
  verbose(message: unknown, ...params: unknown[]): void { this.#write("VERBOSE", message, params); }
  fatal(message: unknown, ...params: unknown[]): void { this.#write("FATAL", message, params); }
}

// Two runtime-generated keys, given to the service as POLYJOSE_SIGNING_JWKS would be: the current
// key (private, signs) first, then the previous one (public only, still published: rotation).
const withId = async (kid: string): Promise<JwkObject> => ({ ...(await jwkGenerateEc("P-256")), alg: "ES256", use: "sig", kid });
const currentKey = await withId(CURRENT_KID);
const previousKey = await jwkToPublic(await withId(PREVIOUS_KID));
const env = {
  POLYJOSE_SIGNING_JWKS: JSON.stringify({ keys: [currentKey, previousKey] }),
  POLYJOSE_ISSUER: ISSUER,
  POLYJOSE_AUDIENCE: AUDIENCE,
  POLYJOSE_DEMO_CLIENT_ID: CLIENT_ID,
  POLYJOSE_DEMO_CLIENT_SECRET: TEST_CLIENT_SECRET,
};

const logger = new CapturingLogger();
const app = await createApp(configFromEnv(env), logger);
await app.listen(0, "127.0.0.1");
const base = (await app.getUrl()).replace("[::1]", "127.0.0.1");

/** Every response body the checks received, for the secrets scan. */
const bodies: string[] = [];
/** Every access token POST /token issued: none may appear in the server log. */
const issuedTokens: string[] = [];

interface Reply {
  status: number;
  headers: Headers;
  text: string;
  json: () => unknown;
}

async function request(path: string, init: RequestInit = {}): Promise<Reply> {
  const response = await fetch(`${base}${path}`, init);
  const text = await response.text();
  bodies.push(text);
  return { status: response.status, headers: response.headers, text, json: () => JSON.parse(text) as unknown };
}

async function requestToken(secret: string): Promise<Reply> {
  const reply = await request("/token", {
    method: "POST",
    body: new URLSearchParams({ grant_type: "client_credentials", client_id: CLIENT_ID, client_secret: secret }),
  });
  const body: unknown = reply.status === 200 ? reply.json() : undefined;
  if (isObject(body) && typeof body.access_token === "string") issuedTokens.push(body.access_token);
  return reply;
}

const me = (token: string | undefined): Promise<Reply> =>
  request("/me", token === undefined ? {} : { headers: { authorization: `Bearer ${token}` } });

// --- helpers -----------------------------------------------------------------------------------

class CheckFailure extends Error {}

function assert(cond: boolean, what: string): asserts cond {
  if (!cond) throw new CheckFailure(what);
}

/** For public, non-secret values only (status codes, algorithm names, kids): shows both. */
function assertEq(actual: unknown, expected: unknown, what: string): void {
  if (actual !== expected) throw new CheckFailure(`${what}: expected ${String(expected)}, got ${String(actual)}`);
}

const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const PRIVATE_MEMBER_TEXT = /"(d|p|q|dp|dq|qi|oth|k)"\s*:/;
const nowSec = (): number => Math.floor(Date.now() / 1000);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Changes one character in the middle of the payload of a compact JWS. */
function tamperPayload(token: string): string {
  const parts = token.split(".");
  const p = parts[1] ?? "";
  const i = Math.floor(p.length / 2);
  parts[1] = p.slice(0, i) + (p[i] === "A" ? "B" : "A") + p.slice(i + 1);
  return parts.join(".");
}

/** KeyService printed both ways a developer might print it. */
function printedKeyService(): string[] {
  const keyService = app.get(KeyService);
  return [JSON.stringify(keyService), inspect(keyService, { showHidden: true, depth: Infinity })];
}

/** Signs `claims` as a JWT with `key`, outside the service (an attacker's or a test's token). */
const signWith = (claims: JsonObject, key: JwkObject, alg: string): Promise<string> => jwtSign(claims, key, { alg });

/** Claims the service would accept, with `extra` replacing any of them. */
function claims(extra: JsonObject = {}): JsonObject {
  const iat = nowSec();
  return { iss: ISSUER, sub: CLIENT_ID, aud: AUDIENCE, iat, exp: iat + 300, ...extra };
}

/**
 * A guard rejection: 401, the RFC 6750 §3.1 `invalid_token` challenge and fixed body, and `code`
 * in the server log lines written while the request ran (never in the response).
 */
async function assertRejected(token: string, code: string): Promise<void> {
  const from = logger.lines.length;
  const reply = await me(token);
  assertEq(reply.status, 401, "status");
  assertEq(reply.headers.get("www-authenticate"), 'Bearer error="invalid_token"', "WWW-Authenticate");
  assert(reply.text === '{"error":"invalid_token"}', "body differs");
  const logged = logger.lines.slice(from).map((line) => /token rejected code=(\S+)/.exec(line)?.[1]).filter((c) => c !== undefined);
  if (logged.length !== 1 || logged[0] !== code) throw new CheckFailure(`expected ${code}, got ${logged.join(",") || "no log line"}`);
}

/** A token from POST /token, for the checks that need a genuine one. */
async function issuedToken(): Promise<string> {
  const reply = await requestToken(TEST_CLIENT_SECRET);
  assertEq(reply.status, 200, "POST /token status");
  const body = reply.json();
  assert(isObject(body) && typeof body.access_token === "string", "no access_token");
  return body.access_token;
}

// --- the checks, in CATALOG.md order -----------------------------------------------------------

const checks: { id: string; run: () => Promise<void> }[] = [];
const check = (id: string, run: () => Promise<void>): void => void checks.push({ id, run });
let jwks: JwkSetObject | undefined;

check("nestjs/jwks/public-only", async () => {
  const reply = await request("/.well-known/jwks.json");
  assertEq(reply.status, 200, "status");
  assert((reply.headers.get("cache-control") ?? "").includes("max-age="), "no Cache-Control max-age");
  const body = reply.json();
  assert(isObject(body) && Array.isArray(body.keys), "not a JWK Set");
  assertEq(body.keys.map((key) => (isObject(key) ? key.kid : undefined)).join(","), `${CURRENT_KID},${PREVIOUS_KID}`, "kids");
  for (const key of body.keys) {
    assert(isObject(key), "a key is not an object");
    for (const member of PRIVATE_MEMBERS) assert(!Object.hasOwn(key, member), `kid=${String(key.kid)} has "${member}"`);
  }
  // The service object itself never shows a key, however it is printed (the scan reads both forms too).
  for (const shown of printedKeyService()) {
    assert(!PRIVATE_MEMBER_TEXT.test(shown), "KeyService shows a private member when printed");
  }
  jwks = body as JwkSetObject;
});

check("nestjs/token/issues-es256-jwt", async () => {
  const reply = await requestToken(TEST_CLIENT_SECRET);
  assertEq(reply.status, 200, "status");
  assertEq(reply.headers.get("cache-control"), "no-store", "Cache-Control");
  const body = reply.json();
  assert(isObject(body) && typeof body.access_token === "string", "no access_token");
  assertEq(body.token_type, "Bearer", "token_type");
  assertEq(body.expires_in, 300, "expires_in");
  assert(jwks !== undefined, "no JWK Set from the first check");
  // Verified the way any resource server would: with the published JWK Set only.
  const verified = await jwtVerifyWithJwks(body.access_token, jwks, { allowedAlgs: ["ES256"], issuers: [ISSUER], audiences: [AUDIENCE] });
  assertEq(verified.alg, "ES256", "alg");
  assertEq(verified.kid, CURRENT_KID, "kid");
  assertEq(verified.claims.sub, CLIENT_ID, "sub");
  const { iat, exp } = verified.claims;
  assert(typeof iat === "number" && typeof exp === "number", "no iat or exp");
  assertEq(exp - iat, 300, "exp - iat");
});

check("nestjs/token/rejects-bad-client-secret", async () => {
  const reply = await requestToken("not-the-test-secret");
  assertEq(reply.status, 401, "status");
  assert(reply.text === '{"error":"invalid_client"}', "body differs");
});

check("nestjs/guard/accepts-valid", async () => {
  const reply = await me(await issuedToken());
  assertEq(reply.status, 200, "status");
  const body = reply.json();
  assert(isObject(body), "not a JSON object");
  assertEq(body.sub, CLIENT_ID, "sub");
  assertEq(body.iss, ISSUER, "iss");
  assertEq(body.aud, AUDIENCE, "aud");
});

check("nestjs/guard/rejects-missing", async () => {
  const reply = await me(undefined);
  assertEq(reply.status, 401, "status");
  // RFC 6750 §3.1: no token, so the challenge carries no error code.
  assertEq(reply.headers.get("www-authenticate"), "Bearer", "WWW-Authenticate");
});

check("nestjs/guard/rejects-expired", async () => {
  // Expired 120 s ago: outside the service's 30 s leeway.
  const exp = nowSec() - 120;
  await assertRejected(await signWith(claims({ iat: exp - 300, exp }), currentKey, "ES256"), "TokenExpired");
});

check("nestjs/guard/rejects-wrong-audience", async () => {
  await assertRejected(await signWith(claims({ aud: "https://other-api.example" }), currentKey, "ES256"), "InvalidClaim");
});

check("nestjs/guard/rejects-alg-not-allowed", async () => {
  // ES384 under the published kid: the allow-list is the service's own algorithms, ES256.
  const es384 = { ...(await jwkGenerateEc("P-384")), alg: "ES384", kid: CURRENT_KID };
  await assertRejected(await signWith(claims(), es384, "ES384"), "AlgorithmNotAllowed");
});

check("nestjs/guard/rejects-tampered", async () => {
  await assertRejected(tamperPayload(await issuedToken()), "InvalidSignature");
});

check("nestjs/guard/rejects-unknown-kid", async () => {
  await assertRejected(await signWith(claims(), await withId("not-published"), "ES256"), "NoMatchingKey");
});

// --- run ---------------------------------------------------------------------------------------

/** Why a check failed: a polyjose error by its code, any other error by its name only. */
function describe(err: unknown): string {
  if (err instanceof CheckFailure) return err.message;
  if (err instanceof PolyjoseError) return `unexpected ${err.code}`;
  return `unexpected ${err instanceof Error ? err.name : typeof err}`;
}

console.log(`# polyjose ${await version()} through @polyjose/node, NestJS, Node.js ${process.versions.node}`);
let passed = 0;
for (const { id, run } of checks) {
  try {
    await run();
    passed += 1;
    console.log(`PASS ${id}`);
  } catch (err) {
    console.log(`FAIL ${id}: ${describe(err)}`);
  }
}

// Not a check: a request for the secrets scan. There is no GET /token, and Nest's own 404 quotes
// the URL, query and all; the exception filter must answer with a fixed body instead.
const query = new URLSearchParams({ grant_type: "client_credentials", client_id: CLIENT_ID, client_secret: TEST_CLIENT_SECRET });
await request(`/token?${query.toString()}`);
const printed = printedKeyService();
await app.close();

// The secrets scan. The member rule is the same as `grep -E '"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:'`;
// the value rule looks for the signing key's `d` and the client secret themselves; the token rule
// looks for every issued access token in the log. Only counts are printed.
const signingD = currentKey.d;
if (typeof signingD !== "string" || signingD === "") throw new Error("verify: the generated signing key has no d");
const secretValues = [signingD, TEST_CLIENT_SECRET];
const everything = [...logger.lines, ...bodies, ...printed];
const found = {
  member: everything.filter((text) => PRIVATE_MEMBER_TEXT.test(text)).length,
  value: everything.filter((text) => secretValues.some((secret) => text.includes(secret))).length,
  token: logger.lines.filter((line) => issuedTokens.some((token) => line.includes(token))).length,
};
const leaks = found.member + found.value + found.token;
const tokensSeen = issuedTokens.length > 0;
const what = `${logger.lines.length} log lines, ${bodies.length} bodies, ${printed.length} printed forms, ${issuedTokens.length} issued tokens`;
console.log(`# secrets scan: ${leaks === 0 ? "clean" : `FOUND member=${found.member} value=${found.value} token=${found.token}`} (${what})`);
if (!tokensSeen) console.error("verify: no token was issued, so the token rule scanned nothing");
if (leaks === 0 && process.env.VERIFY_LOG === "1") for (const line of logger.lines) console.error(line);

const ran = checks.length;
console.log(`POLYJOSE-VERIFY: ${passed}/${ran} PASS`);
if (ran !== EXPECTED_CHECKS) console.error(`verify: ${ran} checks ran; CATALOG.md lists ${EXPECTED_CHECKS}`);
process.exitCode = passed === ran && ran === EXPECTED_CHECKS && leaks === 0 && tokensSeen ? 0 : 1;
