"use client";

// The four crossings between the browser (@polyjose/wasm) and the server (@polyjose/node), one
// function each. The checks and the Server tab call them. A crossing logs every step on both
// sides to a TapLog: the browser's lines as `LOG <tap>.<n> …` and the server's, returned in its
// answer, as `LOG <tap>.s<n> …`.
import { AUDIENCE, CONTENT_ENC, ISSUER, MESSAGES, KEY_MANAGEMENT_ALG, SIGNING_ALG, type ServerAnswer } from "../shared";
import {
  decrypt,
  encrypt,
  generateKey,
  readProtectedHeader,
  selectKey,
  sign,
  tamper,
  unsecuredJws,
  verifyJwtWithJwks,
  type JwkSetObject,
  type JwtValidated,
  type KeyAlg,
  type KeyPair,
} from "./polyjose";
import { StepFailed, TapLog, codeOf } from "./tap-log";

export { TapLog, type LogSink } from "./tap-log";

/** A refusal: the code, which side refused, and the token when one was made. */
export type Refusal = { ok: false; code: string; side: "browser" | "server"; token?: string };

/** A crossing's outcome: its result and the token that crossed, or a refusal. */
export type Outcome<T> = { ok: true; value: T; token: string } | Refusal;

/** Posts `body` to a route handler and returns its answer; a broken answer is `BadResponse`. */
async function post<T extends object>(log: TapLog, route: string, body: object): Promise<ServerAnswer<T>> {
  log.step("request", { method: "POST", route: `/api/${route}` });
  try {
    const { value: answer, ms } = await log.run(`POST /api/${route}`, async () => {
      const response = await fetch(`/api/${route}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tap: log.tap, ...body }),
      });
      return { status: response.status, json: (await response.json()) as ServerAnswer<T> };
    });
    log.server(Array.isArray(answer.json.steps) ? answer.json.steps : []);
    log.step("response", { status: answer.status, ok: answer.json.ok === true, ms });
    return answer.json;
  } catch {
    return { ok: false, code: "BadResponse", steps: [] }; // logged by log.run, as its code
  }
}

/** A code from a server answer, if it looks like one (letters and digits); else `fallback`. */
function answerCode(answer: unknown, fallback: string): string {
  const code = typeof answer === "object" && answer !== null ? (answer as { code?: unknown }).code : undefined;
  return typeof code === "string" && /^[A-Za-z0-9]{1,64}$/.test(code) ? code : fallback;
}

/** The server's public JWK Set, from GET /api/jwks; a refusal fails with the server's code. */
export async function fetchJwks(log: TapLog): Promise<JwkSetObject> {
  log.step("request", { method: "GET", route: "/api/jwks" });
  const { value: jwks } = await log.run("GET /api/jwks", async () => {
    const response = await fetch("/api/jwks", { cache: "no-store" });
    if (!response.ok) {
      const answer: unknown = await response.json().catch(() => undefined);
      throw new StepFailed(answerCode(answer, `HTTP${response.status}`));
    }
    return (await response.json()) as JwkSetObject;
  });
  log.step("jwks", { keys: Array.isArray(jwks.keys) ? jwks.keys.length : 0 }, jwks);
  return jwks;
}

/** A software key for a crossing: logged as `key-software` and its public `jwk`. */
async function newKey(log: TapLog, alg: KeyAlg): Promise<KeyPair> {
  const { value: key, ms } = await log.run("key-software", () => generateKey(alg));
  log.step("key-software", { kty: String(key.publicKey.kty), alg, kid: key.kid, ms });
  log.step("jwk", {}, key.publicKey);
  return key;
}

/** Logs a token and its protected header (read for display only). */
async function showToken(log: TapLog, token: string): Promise<void> {
  log.step("header", {}, await readProtectedHeader(token));
  log.step("token", {}, token);
}

/** Runs the browser's steps; a step that fails has logged its code already. */
async function browser<T>(work: () => Promise<T>): Promise<{ ok: true; value: T } | Refusal> {
  try {
    return { ok: true, value: await work() };
  } catch (err) {
    return { ok: false, code: codeOf(err), side: "browser" };
  }
}

function serverRefusal(code: string, token?: string): Refusal {
  return token === undefined ? { ok: false, code, side: "server" } : { ok: false, code, side: "server", token };
}

/** The variants of crossing 1: the valid token, and the server's three JWS refusals. */
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
  log.step("input", {
    op: "crossing",
    crossing: "browser-signs",
    store: "software",
    alg: variant === "none" ? "none" : alg,
    ...(variant === "valid" ? {} : { failure: `server.${variant}` }),
  });
  const made = await browser(async () => {
    const key = await newKey(log, alg);
    let token = await log.call("jwsSignCompact", () => sign(MESSAGES.browserSigns, key));
    if (variant === "tampered") {
      const tampered = tamper(token, 1);
      log.step("tamper", { part: "payload", index: tampered.index });
      token = tampered.token;
    }
    if (variant === "none") token = await log.call("base64urlEncode", () => unsecuredJws(MESSAGES.browserSigns));
    await showToken(log, token);
    return { token, jwk: key.publicKey };
  });
  if (!made.ok) return made;
  const answer = await post<{ alg: string; payload: string }>(log, "verify", made.value);
  const { token } = made.value;
  return answer.ok ? { ok: true, value: answer, token } : serverRefusal(answer.code, token);
}

/**
 * Crossing 2: the server issues a JWT and the browser validates it against the server's JWK
 * Set, with its own allow-list (ES256), issuer and audience.
 */
export async function serverIssuesBrowserVerifies(log: TapLog): Promise<Outcome<JwtValidated>> {
  log.step("input", { op: "crossing", crossing: "server-issues", store: "software", alg: SIGNING_ALG });
  const issued = await post<{ token: string }>(log, "issue", {});
  if (!issued.ok) return serverRefusal(issued.code);
  const { token } = issued;
  const validated = await browser(async () => {
    await showToken(log, token);
    const jwks = await fetchJwks(log);
    const policy = { allowedAlgs: [SIGNING_ALG], issuer: ISSUER, audience: AUDIENCE };
    const { value, ms } = await log.run("jwtVerifyWithJwks", () => verifyJwtWithJwks(token, jwks, policy));
    log.step("call", { ms }, "jwtVerifyWithJwks");
    log.step("verify", { alg: value.alg, kid: String(value.kid), ms }, "ok");
    log.step("claims", {}, value.claims);
    return value;
  });
  return { ...validated, token };
}

/**
 * Crossing 3: the browser encrypts to the server's ECDH-ES key and the server decrypts. With
 * `tampered`, one ciphertext character is changed first, and the server refuses it with
 * DecryptionFailed, the one code of every decryption failure (RFC 7516 §11.5).
 */
export async function browserEncryptsServerDecrypts(log: TapLog, variant: "valid" | "tampered" = "valid"): Promise<Outcome<{ plaintext: string }>> {
  log.step("input", {
    op: "crossing",
    crossing: "browser-encrypts",
    store: "software",
    alg: KEY_MANAGEMENT_ALG,
    ...(variant === "tampered" ? { failure: "server.jwe-tampered" } : {}),
  });
  const made = await browser(async () => {
    const jwks = await fetchJwks(log);
    const recipient = await log.call("jwksSelect", () => selectKey(jwks, KEY_MANAGEMENT_ALG));
    log.step("jwk", {}, recipient);
    let token = await log.call("jweEncryptCompact", () => encrypt(MESSAGES.browserEncrypts, recipient));
    if (variant === "tampered") {
      const tampered = tamper(token, 3); // the ciphertext part (RFC 7516 §7.1)
      log.step("tamper", { part: "ciphertext", index: tampered.index });
      token = tampered.token;
    }
    await showToken(log, token);
    return token;
  });
  if (!made.ok) return made;
  const answer = await post<{ plaintext: string }>(log, "decrypt", { token: made.value });
  return answer.ok ? { ok: true, value: answer, token: made.value } : serverRefusal(answer.code, made.value);
}

/** Crossing 4: the server encrypts to the browser's new public key and the browser decrypts. */
export async function serverEncryptsBrowserDecrypts(log: TapLog): Promise<Outcome<{ plaintext: string }>> {
  log.step("input", { op: "crossing", crossing: "server-encrypts", store: "software", alg: KEY_MANAGEMENT_ALG });
  const key = await browser(() => newKey(log, KEY_MANAGEMENT_ALG));
  if (!key.ok) return key;
  const encrypted = await post<{ token: string }>(log, "encrypt", { jwk: key.value.publicKey });
  if (!encrypted.ok) return serverRefusal(encrypted.code);
  const { token } = encrypted;
  const decrypted = await browser(async () => {
    await showToken(log, token);
    const { value: plaintext, ms } = await log.run("jweDecryptCompact", () => decrypt(token, key.value));
    log.step("call", { ms }, "jweDecryptCompact");
    const equal = plaintext === MESSAGES.serverEncrypts ? "equal" : "differs";
    log.step("decrypt", { alg: KEY_MANAGEMENT_ALG, enc: CONTENT_ENC, plaintext: equal, ms }, "ok");
    return { plaintext };
  });
  return { ...decrypted, token };
}
