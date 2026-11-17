"use client";

// The 8 `nextjs/*` checks, in catalog order. Each runs a crossing (or reads the JWK Set) through
// the same functions the buttons use, and prints one line:
//
//   PASS nextjs/browser-signs/server-verifies-es256
//   FAIL nextjs/server/rejects-tampered: expected InvalidSignature, got success
//   POLYJOSE-VERIFY: 7/8 PASS
//
// A FAIL reason never shows key material, plaintext or token contents.
import { AUDIENCE, DEMO_SUBJECT, ISSUER, KEY_MANAGEMENT_ALG, MESSAGES, PRIVATE_MEMBERS, SIGNING_ALG } from "../shared";
import {
  TapLog,
  browserEncryptsServerDecrypts,
  browserSignsServerVerifies,
  fetchJwks,
  serverEncryptsBrowserDecrypts,
  serverIssuesBrowserVerifies,
  type LogSink,
  type Outcome,
} from "./crossings";
import { errorCode, polyjoseVersion } from "./polyjose";

class CheckFailure extends Error {}

function assert(cond: boolean, what: string): asserts cond {
  if (!cond) throw new CheckFailure(what);
}

/** For public values only (algorithm names, kids, counts): shows both. */
function assertEq(actual: unknown, expected: unknown, what: string): void {
  if (actual !== expected) throw new CheckFailure(`${what}: expected ${String(expected)}, got ${String(actual)}`);
}

/** For anything that may be secret or token content: says only that it differs. */
function assertSame(actual: unknown, expected: unknown, what: string): void {
  assert(actual === expected, `${what} differs`);
}

/** The outcome's value; a refusal fails the check with its code. */
function passed<T>(outcome: Outcome<T>): T {
  if (!outcome.ok) throw new CheckFailure(`unexpected ${outcome.code} (${outcome.side})`);
  return outcome.value;
}

/** The check passes only when the server refused with `code`. */
function refusedBy<T>(outcome: Outcome<T>, code: string): void {
  if (outcome.ok) throw new CheckFailure(`expected ${code}, got success`);
  if (outcome.side !== "server") throw new CheckFailure(`expected ${code} from the server, got ${outcome.code} (browser)`);
  if (outcome.code !== code) throw new CheckFailure(`expected ${code}, got ${outcome.code}`);
}

interface Check {
  readonly id: string;
  readonly run: (log: TapLog) => Promise<void>;
}

/** The checks, in catalog order. */
export const CHECKS: readonly Check[] = [
  {
    id: "nextjs/browser-signs/server-verifies-es256",
    run: async (log) => {
      const verified = passed(await browserSignsServerVerifies(log));
      assertEq(verified.alg, SIGNING_ALG, "alg");
      assertSame(verified.payload, MESSAGES.browserSigns, "payload");
    },
  },
  {
    id: "nextjs/server-issues-jwt/browser-verifies-with-jwks",
    run: async (log) => {
      const validated = passed(await serverIssuesBrowserVerifies(log));
      assertEq(validated.alg, SIGNING_ALG, "alg");
      assertEq(validated.claims.iss, ISSUER, "iss");
      assertEq(validated.claims.aud, AUDIENCE, "aud");
      assertEq(validated.claims.sub, DEMO_SUBJECT, "sub");
      assert(typeof validated.kid === "string" && validated.kid !== "", "kid is missing");
    },
  },
  {
    id: "nextjs/browser-encrypts/server-decrypts-p-256",
    run: async (log) => {
      const decrypted = passed(await browserEncryptsServerDecrypts(log));
      assertSame(decrypted.plaintext, MESSAGES.browserEncrypts, "plaintext");
    },
  },
  {
    id: "nextjs/server-encrypts/browser-decrypts-p-256",
    run: async (log) => {
      const decrypted = passed(await serverEncryptsBrowserDecrypts(log));
      assertSame(decrypted.plaintext, MESSAGES.serverEncrypts, "plaintext");
    },
  },
  {
    id: "nextjs/server/rejects-alg-not-allowed",
    run: async (log) => refusedBy(await browserSignsServerVerifies(log, "alg-not-allowed"), "AlgorithmNotAllowed"),
  },
  {
    id: "nextjs/server/rejects-tampered",
    run: async (log) => refusedBy(await browserSignsServerVerifies(log, "tampered"), "InvalidSignature"),
  },
  {
    id: "nextjs/server/rejects-none",
    run: async (log) => refusedBy(await browserSignsServerVerifies(log, "none"), "AlgorithmNotAllowed"),
  },
  {
    id: "nextjs/jwks/public-only",
    run: async (log) => {
      const jwks = await fetchJwks(log);
      assert(Array.isArray(jwks.keys), "keys is not an array");
      assertEq(jwks.keys.length, 2, "key count");
      for (const [index, key] of jwks.keys.entries()) {
        assert(typeof key === "object" && key !== null && !Array.isArray(key), `key ${index} is not an object`);
        for (const member of PRIVATE_MEMBERS) assert(!(member in key), `key ${index} has a private member`);
        assert(typeof key.kid === "string" && key.kid !== "", `key ${index} has no kid`);
      }
      const algs = jwks.keys.map((key) => (key as { alg?: unknown }).alg);
      assert(algs.includes(SIGNING_ALG), `no ${SIGNING_ALG} key`);
      assert(algs.includes(KEY_MANAGEMENT_ALG), `no ${KEY_MANAGEMENT_ALG} key`);
    },
  },
];

function describe(err: unknown): string {
  if (err instanceof CheckFailure) return err.message;
  return `unexpected ${errorCode(err)}`;
}

/** The browser and its version, from the user agent string (for the information line). */
function browserName(): string {
  const ua = navigator.userAgent;
  const m = ua.match(/(Firefox|HeadlessChrome|Chrome)\/([\d.]+)/);
  if (m) return `${m[1]} ${m[2]}`;
  const safari = ua.match(/Version\/([\d.]+).*Safari/);
  return safari ? `Safari ${safari[1]}` : ua;
}

/**
 * Runs every check and writes its lines to `out` (the page and the console), then the result
 * line. Each check's steps go to `log`, one tap per check, starting at `firstTap`.
 */
export async function runChecks(out: (line: string) => void, log: LogSink, firstTap: number): Promise<{ passed: number; ran: number }> {
  let polyjose: string;
  try {
    polyjose = await polyjoseVersion();
  } catch (err) {
    polyjose = `(not loaded: ${errorCode(err)})`; // then every check fails, with its reason
  }
  out(`# polyjose ${polyjose} through @polyjose/wasm in ${browserName()}, and @polyjose/node in the route handlers`);
  let passedCount = 0;
  for (const [index, { id, run }] of CHECKS.entries()) {
    try {
      await run(new TapLog(firstTap + index, log));
      passedCount += 1;
      out(`PASS ${id}`);
    } catch (err) {
      out(`FAIL ${id}: ${describe(err)}`);
    }
  }
  out(`POLYJOSE-VERIFY: ${passedCount}/${CHECKS.length} PASS`);
  return { passed: passedCount, ran: CHECKS.length };
}
