"use client";

// The four crossings between the browser (@polyjose/wasm) and the server (@polyjose/node), one
// function each. A crossing logs every step on both sides to a TapLog: the browser's lines as
// `LOG <tap>.<n> …` and the server's, returned in its answer, as `LOG <tap>.s<n> …`.
import { AUDIENCE, ISSUER, MESSAGES, KEY_MANAGEMENT_ALG, SIGNING_ALG, logLine, type LogValue, type ServerAnswer } from "../shared";
import {
  decrypt,
  encrypt,
  errorCode,
  generateKey,
  selectKey,
  sign,
  tamper,
  unsecuredJws,
  verifyJwtWithJwks,
  type JwkSetObject,
  type JwtValidated,
  type KeyAlg,
} from "./polyjose";

/** Where log lines go: the page's log and the browser console. */
export type LogSink = (line: string) => void;

/** The log of one tap (one button press or one check). */
export class TapLog {
  #step = 0;
  constructor(
    readonly tap: number,
    private readonly sink: LogSink,
  ) {}

  /** A browser step: `LOG <tap>.<n> <event> key=value …` (JWKs pass the publicOnly gate). */
  step(event: string, fields?: Record<string, LogValue>): void {
    this.#step += 1;
    this.sink(logLine(this.tap, String(this.#step), event, fields));
  }

  /** The server's lines for this tap, as its answer returned them. */
  server(lines: readonly unknown[]): void {
    for (const line of lines) if (typeof line === "string" && line.startsWith(`LOG ${this.tap}.s`)) this.sink(line);
  }
}

/** A refusal: the code, and which side refused. */
export type Refusal = { ok: false; code: string; side: "browser" | "server" };

/** A crossing's outcome: its result, or a refusal. */
export type Outcome<T> = { ok: true; value: T } | Refusal;

/** Posts `body` to a route handler and returns its answer; a broken answer is `BadResponse`. */
async function post<T extends object>(log: TapLog, route: string, body: object): Promise<ServerAnswer<T>> {
  log.step("request", { route: `POST /api/${route}` });
  let answer: ServerAnswer<T>;
  try {
    const response = await fetch(`/api/${route}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ tap: log.tap, ...body }),
    });
    answer = (await response.json()) as ServerAnswer<T>;
  } catch (err) {
    log.step("error", { side: "network", code: errorCode(err) });
    return { ok: false, code: "BadResponse", steps: [] };
  }
  log.server(Array.isArray(answer.steps) ? answer.steps : []);
  if (!answer.ok) log.step("server-error", { code: String(answer.code) });
  return answer;
}

/** The server's public JWK Set, from GET /api/jwks. */
export async function fetchJwks(log: TapLog): Promise<JwkSetObject> {
  log.step("request", { route: "GET /api/jwks" });
  const response = await fetch("/api/jwks", { cache: "no-store" });
  const jwks = (await response.json()) as JwkSetObject;
  log.step("jwks", { keys: Array.isArray(jwks.keys) ? jwks.keys.length : 0, value: jwks });
  return jwks;
}

/** Runs a browser step, logging its code when polyjose (or anything else) refuses it. */
async function browser<T>(log: TapLog, run: () => Promise<T>): Promise<Outcome<T>> {
  try {
    return { ok: true, value: await run() };
  } catch (err) {
    const code = errorCode(err);
    log.step("error", { side: "browser", code });
    return { ok: false, code, side: "browser" } satisfies Refusal;
  }
}

function serverOutcome<T extends object>(answer: ServerAnswer<T>): Outcome<T> {
  return answer.ok ? { ok: true, value: answer } : serverRefusal(answer.code);
}

function serverRefusal(code: string): Refusal {
  return { ok: false, code, side: "server" };
}

/** What the browser sends to POST /api/verify. */
export type SignVariant = "valid" | "alg-not-allowed" | "tampered" | "none";

/**
 * Crossing 1: the browser signs a compact JWS and the server verifies it with the browser's
 * public JWK and its own allow-list (ES256 only). The variants are the failure actions:
 * - `alg-not-allowed`: signed with ES384, which the server doesn't allow → AlgorithmNotAllowed;
 * - `tampered`: one payload character changed after signing → InvalidSignature;
 * - `none`: an Unsecured JWS, `alg: none` → AlgorithmNotAllowed (RFC 8725 §3.2).
 */
export async function browserSignsServerVerifies(
  log: TapLog,
  variant: SignVariant = "valid",
): Promise<Outcome<{ alg: string; payload: string }>> {
  const alg: KeyAlg = variant === "alg-not-allowed" ? "ES384" : SIGNING_ALG;
  log.step("input", { op: "jws-sign", alg, variant });
  const made = await browser(log, async () => {
    const key = await generateKey(alg);
    log.step("key-create", { alg, kid: key.kid, jwk: key.publicKey });
    let token = await sign(MESSAGES.browserSigns, key);
    if (variant === "tampered") token = tamper(token, 1);
    if (variant === "none") token = await unsecuredJws(MESSAGES.browserSigns);
    log.step("token", { value: token });
    return { token, jwk: key.publicKey };
  });
  if (!made.ok) return made;
  return serverOutcome(await post<{ alg: string; payload: string }>(log, "verify", made.value));
}

/**
 * Crossing 2: the server issues a JWT and the browser validates it against the server's JWK
 * Set, with its own allow-list (ES256), issuer and audience.
 */
export async function serverIssuesBrowserVerifies(log: TapLog): Promise<Outcome<JwtValidated>> {
  log.step("input", { op: "jwt-verify-with-jwks", allowedAlgs: SIGNING_ALG });
  const issued = await post<{ token: string }>(log, "issue", {});
  if (!issued.ok) return serverRefusal(issued.code);
  return browser(log, async () => {
    const jwks = await fetchJwks(log);
    const validated = await verifyJwtWithJwks(issued.token, jwks, { allowedAlgs: [SIGNING_ALG], issuer: ISSUER, audience: AUDIENCE });
    log.step("verify", { result: "ok", alg: validated.alg, kid: String(validated.kid), sub: String(validated.claims.sub) });
    return validated;
  });
}

/** Crossing 3: the browser encrypts to the server's ECDH-ES key and the server decrypts. */
export async function browserEncryptsServerDecrypts(log: TapLog): Promise<Outcome<{ plaintext: string }>> {
  log.step("input", { op: "jwe-encrypt", alg: KEY_MANAGEMENT_ALG });
  const made = await browser(log, async () => {
    const jwks = await fetchJwks(log);
    const recipient = await selectKey(jwks, KEY_MANAGEMENT_ALG);
    log.step("recipient", { kid: String(recipient.kid) });
    const token = await encrypt(MESSAGES.browserEncrypts, recipient);
    log.step("token", { value: token });
    return token;
  });
  if (!made.ok) return made;
  return serverOutcome(await post<{ plaintext: string }>(log, "decrypt", { token: made.value }));
}

/** Crossing 4: the server encrypts to the browser's new public key and the browser decrypts. */
export async function serverEncryptsBrowserDecrypts(log: TapLog): Promise<Outcome<{ plaintext: string }>> {
  log.step("input", { op: "jwe-decrypt", alg: KEY_MANAGEMENT_ALG });
  const key = await browser(log, async () => {
    const pair = await generateKey(KEY_MANAGEMENT_ALG);
    log.step("key-create", { alg: KEY_MANAGEMENT_ALG, kid: pair.kid, jwk: pair.publicKey });
    return pair;
  });
  if (!key.ok) return key;
  const encrypted = await post<{ token: string }>(log, "encrypt", { jwk: key.value.publicKey });
  if (!encrypted.ok) return serverRefusal(encrypted.code);
  return browser(log, async () => {
    const plaintext = await decrypt(encrypted.token, key.value);
    log.step("decrypt", { result: "ok", bytes: plaintext.length });
    return { plaintext };
  });
}
