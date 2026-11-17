import "server-only";

// What every route handler shares: reading the JSON request, the request's log, and answering
// with a result or an error code. Responses and server log lines carry codes only, never an
// error message, key material or a decrypted secret.
import { PolyjoseError, type JwkObject } from "@polyjose/node";

import { hasPrivateMember, logLine, logLines, type LogValue } from "../../../lib/shared";
import { ServerKeysError } from "./keys";

/** The largest request body a route reads. The tokens and public JWKs here are far smaller. */
const MAX_BODY_BYTES = 64 * 1024;

/** A request this app can't use. `code` is one of the codes below, safe to send and to log. */
export class RequestError extends Error {
  constructor(readonly code: "BadRequest" | "BodyTooLarge" | "PrivateKeySent") {
    super(code);
    this.name = "RequestError";
  }
}

/** The error's code: a polyjose code, an app code, or the error's type name. Never a message. */
export function codeOf(err: unknown): string {
  if (err instanceof PolyjoseError || err instanceof RequestError || err instanceof ServerKeysError) return err.code;
  return err instanceof Error ? err.name : typeof err;
}

/**
 * One request's log. Lines are `LOG <tap>.s<n> <event> key=value …`: the tap number the page
 * sent, then the server's own step numbers. Each line goes to stdout and back to the page.
 */
export class RequestLog {
  readonly lines: string[] = [];
  #step = 0;
  constructor(readonly tap: number) {}

  /** One step; `rest` is a JSON value (through the publicOnly gate) or a token. */
  step(event: string, fields?: Record<string, LogValue>, rest?: LogValue): void {
    this.#step += 1;
    for (const line of logLines(this.tap, `s${this.#step}`, event, fields, rest)) {
      this.lines.push(line);
      console.log(line);
    }
  }

  /** Runs one polyjose call and logs `call <name> ms=<n>`, timed with a monotonic clock. */
  async call<T>(name: string, run: () => Promise<T>): Promise<T> {
    const start = performance.now();
    try {
      return await run();
    } finally {
      this.step("call", { ms: Math.round(performance.now() - start) }, name);
    }
  }
}

type Body = Record<string, unknown>;

/** Reads a JSON object body of at most MAX_BODY_BYTES. */
async function readBody(request: Request): Promise<Body> {
  const declared = Number(request.headers.get("content-length") ?? 0);
  if (declared > MAX_BODY_BYTES) throw new RequestError("BodyTooLarge");
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) throw new RequestError("BodyTooLarge");
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new RequestError("BadRequest");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) throw new RequestError("BadRequest");
  return body as Body;
}

/** The page's tap number, so both sides' lines line up; 0 when absent or not a small number. */
function tapOf(body: Body): number {
  const tap = body.tap;
  return typeof tap === "number" && Number.isSafeInteger(tap) && tap >= 0 && tap < 1_000_000 ? tap : 0;
}

/** `body[name]` as a non-empty string, else BadRequest. */
export function stringField(body: Body, name: string): string {
  const value = body[name];
  if (typeof value !== "string" || value === "") throw new RequestError("BadRequest");
  return value;
}

/**
 * `body[name]` as a public JWK object. A JWK with a private or symmetric member is refused
 * with PrivateKeySent: a client never sends its private key, and the server never logs one.
 */
export function publicJwkField(body: Body, name: string): JwkObject {
  const value = body[name];
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new RequestError("BadRequest");
  if (hasPrivateMember(value)) throw new RequestError("PrivateKeySent");
  if (typeof (value as { kty?: unknown }).kty !== "string") throw new RequestError("BadRequest");
  return value as JwkObject; // parsed from JSON, so every member is a JSON value
}

function json(status: number, body: object): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

/**
 * Runs one POST route: reads the body, opens the request's log, runs `handler` and answers
 * `{ ok: true, …result, steps }`. A failure answers `{ ok: false, code, steps }`: 400 for a
 * request this app can't use, 422 for a token or key polyjose refused, 500 for anything else.
 */
export async function handlePost(
  request: Request,
  route: string,
  handler: (body: Body, log: RequestLog) => Promise<object>,
): Promise<Response> {
  let log = new RequestLog(0);
  try {
    const body = await readBody(request);
    log = new RequestLog(tapOf(body));
    log.step("request", { route });
    const result = await handler(body, log);
    return json(200, { ok: true, ...result, steps: log.lines });
  } catch (err) {
    const code = codeOf(err);
    log.step("error", { route, code });
    const status = err instanceof RequestError ? 400 : err instanceof PolyjoseError ? 422 : 500;
    return json(status, { ok: false, code, steps: log.lines });
  }
}

/** The JSON answer of a GET route, never cached (the keys change at every server start). */
export function getJson(body: object): Response {
  return json(200, body);
}

/** The error answer of a GET route: the code only. */
export function getError(route: string, err: unknown): Response {
  const code = codeOf(err);
  console.log(logLine(0, "s1", "error", { route, code }));
  return json(500, { ok: false, code });
}
