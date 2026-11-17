// What the browser and the server agree on: the algorithms, the demo claims and the fixed demo
// messages. Nothing here is secret, and nothing here calls polyjose, so both sides import it.

/** The JWS algorithm both sides sign with: ECDSA P-256 with SHA-256 (RFC 7518 §3.4). */
export const SIGNING_ALG = "ES256";

/**
 * The JWE key management algorithm: ECDH-ES key agreement, then AES-256 Key Wrap of the
 * content key (RFC 7518 §4.6). The recipient's key is EC P-256 (RFC 7518 §6.2).
 */
export const KEY_MANAGEMENT_ALG = "ECDH-ES+A256KW";

/** The JWE content encryption: AES-256-GCM (RFC 7518 §5.3). */
export const CONTENT_ENC = "A256GCM";

/** The `iss` of the server's JWTs (RFC 7519 §4.1.1). */
export const ISSUER = "https://server.polyjose.example";

/** The `aud` of the server's JWTs (RFC 7519 §4.1.3). */
export const AUDIENCE = "https://browser.polyjose.example";

/** The `sub` of the server's JWTs (RFC 7519 §4.1.2): a demo subject, not a real user. */
export const DEMO_SUBJECT = "demo-user";

/** How long the server's JWTs are valid, in seconds (`exp`, RFC 7519 §4.1.4). */
export const TOKEN_LIFETIME = 300;

/**
 * The fixed demo messages. Every token this app makes carries one of these, never text the
 * user typed, so every token on screen or in a log is a demo token.
 */
export const MESSAGES = {
  /** What the browser signs for the server to verify. */
  browserSigns: "Signed in the browser with @polyjose/wasm",
  /** What the browser encrypts to the server's public key. */
  browserEncrypts: "Encrypted in the browser to the server's public key",
  /** What the server encrypts to the browser's public key. */
  serverEncrypts: "Encrypted on the server to the browser's public key",
} as const;

/**
 * The JWK members that hold private or symmetric key material (RFC 7518 §6.2.2, §6.3.2, §6.4.1;
 * RFC 8037 §2). A JWK with any of them never goes on the page, into a response or into a log.
 */
export const PRIVATE_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] as const;

/**
 * A log line with a private or symmetric JWK member as JSON, the secrets check of PLAYGROUND.md
 * ("Secrets"): `"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:` as `grep -E`.
 */
export const SECRET_LINE = /"(d|p|q|dp|dq|qi|oth|k)"\s*:/;

/** True when `value` is an object with a private or symmetric JWK member. */
export function hasPrivateMember(value: unknown): boolean {
  return (
    typeof value === "object" &&
    value !== null &&
    PRIVATE_MEMBERS.some((member) => Object.prototype.hasOwnProperty.call(value, member))
  );
}

/**
 * The one gate every JWK passes before it is shown or logged: a copy of `value` in which any
 * object with a private or symmetric member is replaced by `"[withheld]"`.
 */
export function publicOnly(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(publicOnly);
  if (typeof value !== "object" || value === null) return value;
  if (hasPrivateMember(value)) return "[withheld]";
  return Object.fromEntries(Object.entries(value).map(([name, member]) => [name, publicOnly(member)]));
}

/** A log field value: text, a number, a flag, or a JSON value that goes through `publicOnly`. */
export type LogValue = string | number | boolean | object;

/** Log lines are split into parts of at most this many characters (PLAYGROUND.md, "Log"). */
export const LOG_PART = 800;

/** A value as the log writes it: JSON after the `publicOnly` gate, or text with no spaces. */
function logValue(value: LogValue): string {
  if (typeof value === "object") return JSON.stringify(publicOnly(value));
  return String(value).replace(/\s+/g, "_");
}

/**
 * One log entry, as the lines PLAYGROUND.md ("Log") describes:
 *
 *   LOG <tap>.<step> <event> key=value …
 *   LOG <tap>.<step> <event> <rest>          (header, jwk, claims, token, call, …)
 *
 * - Values have no spaces; objects are written as JSON after the `publicOnly` gate.
 * - `rest` is the event's JSON (also through the gate) or token, as the rest of the line.
 * - Errors are logged as `code=<Code>` only, never as a message.
 * - An entry longer than LOG_PART characters is split: each further line repeats
 *   `LOG <tap>.<step>` and has `+` in place of the event, and joining the parts gives it back.
 */
export function logLines(
  tap: number,
  step: string,
  event: string,
  fields: Record<string, LogValue> = {},
  rest?: LogValue,
): string[] {
  const words = [event];
  if (rest !== undefined) words.push(typeof rest === "object" ? logValue(rest) : String(rest));
  for (const [name, value] of Object.entries(fields)) words.push(`${name}=${logValue(value)}`);
  const body = words.join(" ");
  const prefix = `LOG ${tap}.${step}`;
  const lines = [`${prefix} ${body.slice(0, LOG_PART)}`];
  for (let at = LOG_PART; at < body.length; at += LOG_PART) lines.push(`${prefix} + ${body.slice(at, at + LOG_PART)}`);
  return lines;
}

/**
 * The log entries of `lines`: each `LOG <tap>.<step> + …` continuation part joined back onto the
 * entry before it, as `logLines` split it. The secrets scans read entries, so a value split
 * across two parts is still found. (run.mjs has the same function for the captured output.)
 */
export function joinLogEntries(lines: readonly string[]): string[] {
  const entries: string[] = [];
  let prefix: string | undefined;
  for (const line of lines) {
    const part = /^(LOG \S+) \+ (.*)$/.exec(line);
    const last = entries.length - 1;
    if (part && part[1] === prefix && last >= 0) {
      entries[last] = `${entries[last] ?? ""}${part[2] ?? ""}`;
      continue;
    }
    entries.push(line);
    prefix = /^(LOG \S+) /.exec(line)?.[1];
  }
  return entries;
}

/** A log entry that fits on one line (a short, fixed set of fields). */
export function logLine(tap: number, step: string, event: string, fields: Record<string, LogValue> = {}): string {
  return logLines(tap, step, event, fields).join("\n");
}

/**
 * What a route handler answers, as JSON: its result or an error code, plus the server's log
 * lines for this request (`steps`), so the page can show both sides of a crossing.
 */
export type ServerAnswer<T> = (({ ok: true } & T) | { ok: false; code: string }) & { steps: string[] };
