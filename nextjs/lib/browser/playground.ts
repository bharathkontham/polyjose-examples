"use client";

// What each playground button does: Sign, Verify, Sign and verify, Encrypt, Decrypt, Round
// trip, the failure actions, the Server tab's crossings and the Keys tab. The tabs and the demo
// walk call these functions, so the walk runs exactly what a tap runs. Every polyjose call goes
// through lib/browser/polyjose.ts, and every step is logged (PLAYGROUND.md, "Log"):
//
//   LOG 7.1 input op=jws-sign-verify store=software alg=ES256 payload=preset
//   LOG 7.2 key-software kty=EC alg=ES256 kid=… ms=1
//   LOG 7.3 jwk {"kty":"EC","crv":"P-256",…}
//   LOG 7.4 call jwsSignCompact ms=1
//   …
import {
  JWT_CLAIMS,
  JWT_LIFETIME,
  KEY_LIVES,
  PAYLOAD,
  type EcdhCurve,
  type EncryptRow,
  type FailureAction,
  type ServerActionId,
  type SignRow,
} from "../matrix";
import type { LogValue } from "../shared";
import {
  browserEncryptsServerDecrypts,
  browserSignsServerVerifies,
  serverEncryptsBrowserDecrypts,
  serverIssuesBrowserVerifies,
  type Outcome,
} from "./crossings";
import {
  counterpart,
  decryptJwe,
  encryptJwe,
  newSoftwareKey,
  polyjoseVersion,
  readProtectedHeader,
  signJws,
  signJwt,
  tamper,
  thumbprint,
  verify,
  verifyJwt,
  type JsonObject,
  type JwkObject,
  type KeyRequest,
  type SoftwareKey,
} from "./polyjose";
import { StepFailed, TapLog, codeOf, type Timing } from "./tap-log";

/** What the result card shows (PLAYGROUND.md, "The result card"). Never a secret. */
export interface Card {
  readonly title: string;
  readonly token?: string;
  /** The protected header, through the publicOnly gate when shown. */
  readonly header?: JsonObject;
  readonly outcome: { readonly ok: true; readonly lines: readonly string[] } | { readonly ok: false; readonly code: string; readonly side: "browser" | "server" };
  /** A failure action's expected code: the card says whether the outcome matched it. */
  readonly expected?: string;
  /** Explanation ids shown with the result (`key.test-rsa`, the failure action's text, …). */
  readonly notes: readonly string[];
  readonly keyLives: string;
  readonly timings: readonly Timing[];
}

/** True when a card's outcome is what its tap expects: success, or the failure action's code. */
export function asExpected(card: Card): boolean {
  if (card.expected === undefined) return card.outcome.ok;
  return !card.outcome.ok && card.outcome.code === card.expected;
}

/** A key's log fields: never a private member (PLAYGROUND.md, "Secrets"). */
function keyFields(key: SoftwareKey): Record<string, LogValue> {
  return {
    kty: key.kty,
    alg: key.alg,
    kid: key.kid,
    ...(key.crv === undefined ? {} : { crv: key.crv }),
    ...(key.enc === undefined ? {} : { enc: key.enc }),
    ...(key.bits === undefined ? {} : { bits: key.bits }),
    ...(key.testKey ? { "test-key": true } : {}),
  };
}

/** Logs a key: `key-software`, then its public `jwk` (a shared key has none), then the test-key note. */
function logKey(log: TapLog, key: SoftwareKey, fields: Record<string, LogValue> = {}): void {
  log.step("key-software", { ...keyFields(key), ...fields });
  if (key.publicKey) log.step("jwk", {}, key.publicKey);
  if (key.testKey) log.step("note", { id: "key.test-rsa" });
}

/** A new software key for `request`, logged; or the Keys tab's key, logged as chosen. */
async function useKey(log: TapLog, request: KeyRequest, chosen?: SoftwareKey): Promise<SoftwareKey> {
  if (chosen) {
    logKey(log, chosen, { from: "keys-tab" });
    return chosen;
  }
  const { value: key, ms } = await log.run("key-software", () => newSoftwareKey(request));
  logKey(log, key, { ms });
  return key;
}

/** Logs a token and its protected header, and returns the header for the card. */
async function showToken(log: TapLog, token: string): Promise<JsonObject> {
  const header = await readProtectedHeader(token);
  log.step("header", {}, header);
  log.step("token", {}, token);
  return header;
}

/** The card of a tap whose steps stopped with a code (already logged by TapLog). */
function refused(err: unknown): { ok: false; code: string; side: "browser" } {
  return { ok: false, code: codeOf(err), side: "browser" };
}

// ---------------------------------------------------------------------------------------------
// Sign tab

export type SignOp = "jws" | "jwt";

export interface SignSpec {
  readonly op: SignOp;
  readonly row: SignRow;
  /** A key from the Keys tab; absent: a new key. */
  readonly key?: SoftwareKey | undefined;
}

/** A token the Sign tab made, which **Verify** verifies again. */
export interface Signed {
  readonly op: SignOp;
  readonly alg: string;
  readonly token: string;
  readonly key: SoftwareKey;
}

export interface SignResult {
  readonly card: Card;
  /** The token this tap signed. */
  readonly signed?: Signed;
}

function signRequest(row: SignRow): KeyRequest {
  return { kind: row.kind, alg: row.alg };
}

/** The claims of a playground JWT, `exp` from `now` (whole seconds, RFC 7519 §2). */
function jwtClaims(exp: number): JsonObject {
  return { ...JWT_CLAIMS, exp };
}

const now = (): number => Math.floor(Date.now() / 1000);

async function signStep(log: TapLog, op: SignOp, key: SoftwareKey, alg: string, exp = now() + JWT_LIFETIME): Promise<{ token: string; header: JsonObject }> {
  const token =
    op === "jws"
      ? await log.call("jwsSignCompact", () => signJws(PAYLOAD, key, alg))
      : await log.call("jwtSign", () => signJwt(jwtClaims(exp), key, alg));
  return { token, header: await showToken(log, token) };
}

/** Verifies with an explicit allow-list (RFC 8725 §3.1) and leeway; returns the card's lines. */
async function verifyStep(log: TapLog, op: SignOp, token: string, key: JwkObject, allowedAlgs: readonly string[], leeway?: number): Promise<string[]> {
  if (op === "jws") {
    const { value, ms } = await log.run("jwsVerifyCompact", () => verify(token, key, allowedAlgs));
    log.step("call", { ms }, "jwsVerifyCompact");
    log.step("verify", { alg: value.alg, kid: String(key.kid ?? ""), ms }, "ok");
    return [`Verified: alg ${value.alg}, kid ${String(key.kid ?? "")}`, value.payload === PAYLOAD ? "The payload equals the input." : "The payload differs from the input."];
  }
  const policy = { allowedAlgs, issuer: JWT_CLAIMS.iss, audience: JWT_CLAIMS.aud, leeway };
  const { value, ms } = await log.run("jwtVerify", () => verifyJwt(token, key, policy));
  log.step("call", { ms }, "jwtVerify");
  log.step("verify", { alg: value.alg, kid: String(value.kid), ms }, "ok");
  log.step("claims", {}, value.claims);
  return [`Verified: alg ${value.alg}, kid ${String(value.kid)}`, `Claims: ${JSON.stringify(value.claims)}`];
}

function signCard(spec: SignSpec, log: TapLog, parts: Partial<Card> & Pick<Card, "outcome">, notes: string[] = []): Card {
  return {
    title: `${spec.op === "jws" ? "JWS" : "JWT"} ${spec.row.alg} · Software`,
    keyLives: KEY_LIVES,
    timings: log.timings,
    notes: [...notes, ...(spec.row.kind === "RSA" ? ["key.test-rsa"] : [])],
    ...parts,
  };
}

/**
 * **Sign**, **Verify** or **Sign and verify**: signs the fixed payload (or the JWT claims) with a
 * new key or the chosen one, and verifies with the key's public JWK (the secret, for HS*) and
 * an allow-list of the row's algorithm only. **Verify** verifies `previous` again.
 */
export async function signTap(log: TapLog, spec: SignSpec, mode: "sign" | "verify" | "sign-verify", previous?: Signed): Promise<SignResult> {
  log.step("input", { op: `${spec.op}-${mode}`, store: "software", alg: spec.row.alg, payload: "preset" });
  let signed: Signed | undefined;
  let header: JsonObject | undefined;
  try {
    if (mode === "verify") {
      if (!previous) throw new StepFailed("NothingToVerify");
      signed = previous;
      header = await showToken(log, previous.token);
    } else {
      const key = await useKey(log, signRequest(spec.row), spec.key);
      const step = await signStep(log, spec.op, key, spec.row.alg);
      signed = { op: spec.op, alg: spec.row.alg, token: step.token, key };
      header = step.header;
    }
    const lines =
      mode === "sign"
        ? ["Signed. Press Verify to verify it."]
        : await verifyStep(log, signed.op, signed.token, counterpart(signed.key), [signed.alg]);
    return { card: signCard(spec, log, { token: signed.token, header, outcome: { ok: true, lines } }), signed };
  } catch (err) {
    const card = signCard(spec, log, { ...(signed ? { token: signed.token } : {}), ...(header ? { header } : {}), outcome: refused(err) });
    return { card, ...(signed ? { signed } : {}) };
  }
}

/** The verification key of `failure.sign.wrong-key`: another key of the same algorithm. */
async function wrongSignKey(log: TapLog, row: SignRow): Promise<JwkObject> {
  const { value: other, ms } = await log.run("key-software", () => newSoftwareKey(signRequest(row)));
  logKey(log, other, { wrong: true, ms });
  return counterpart(other);
}

/** The allow-list of an "other algorithm allowed" action; the matrix disables it for rows without one. */
function otherAlg(row: SignRow | EncryptRow): string {
  if (row.other === undefined) throw new StepFailed("NotOffered");
  return row.other;
}

/**
 * One Sign-tab failure action (PLAYGROUND.md, "Failure actions"): tamper, other algorithm
 * allowed, wrong key, or expired. Each ends with the action's code, shown with its explanation.
 */
export async function signFailureTap(log: TapLog, spec: SignSpec, action: FailureAction): Promise<SignResult> {
  const failure = action.id.replace(/^failure\./, "");
  const op: SignOp = action.id === "failure.sign.expired" ? "jwt" : spec.op;
  log.step("input", { op: `${op}-sign-verify`, store: "software", alg: spec.row.alg, payload: "preset", failure });
  let token: string | undefined;
  let header: JsonObject | undefined;
  const card = (outcome: Card["outcome"]): Card =>
    signCard({ ...spec, op }, log, { outcome, expected: action.code, ...(token ? { token } : {}), ...(header ? { header } : {}) }, [action.id]);
  try {
    const key = await useKey(log, signRequest(spec.row), spec.key);
    const exp = action.id === "failure.sign.expired" ? now() - 3600 : undefined;
    ({ token, header } = await signStep(log, op, key, spec.row.alg, exp));
    let verifyKey = counterpart(key);
    let allowed = [spec.row.alg];
    let leeway: number | undefined;
    switch (action.id) {
      case "failure.sign.tamper": {
        const changed = tamper(token, 1);
        log.step("tamper", { part: "payload", index: changed.index });
        token = changed.token;
        log.step("token", {}, token);
        break;
      }
      case "failure.sign.other-alg":
        allowed = [otherAlg(spec.row)];
        break;
      case "failure.sign.wrong-key":
        verifyKey = await wrongSignKey(log, spec.row);
        break;
      case "failure.sign.expired":
        leeway = 0;
        break;
    }
    log.step("note", { id: action.id });
    const lines = await verifyStep(log, op, token, verifyKey, allowed, leeway);
    return { card: card({ ok: true, lines }) };
  } catch (err) {
    return { card: card(refused(err)) };
  }
}

// ---------------------------------------------------------------------------------------------
// Encrypt tab

export interface EncryptSpec {
  readonly row: EncryptRow;
  readonly enc: string;
  /** ECDH-ES rows only. */
  readonly crv?: EcdhCurve | undefined;
  /** A key from the Keys tab; absent: a new key. */
  readonly key?: SoftwareKey | undefined;
}

/** A token the Encrypt tab made, which **Decrypt** decrypts again. */
export interface Encrypted {
  readonly alg: string;
  readonly enc: string;
  readonly token: string;
  readonly key: SoftwareKey;
}

export interface EncryptResult {
  readonly card: Card;
  readonly encrypted?: Encrypted;
}

function encryptRequest(spec: EncryptSpec): KeyRequest {
  return { kind: spec.row.kind, alg: spec.row.alg, crv: spec.row.kind === "ecdh" ? (spec.crv ?? "P-256") : undefined, enc: spec.enc };
}

function encryptFields(spec: EncryptSpec): Record<string, LogValue> {
  return { store: "software", alg: spec.row.alg, enc: spec.enc, ...(spec.row.kind === "ecdh" ? { crv: spec.crv ?? "P-256" } : {}), payload: "preset" };
}

function encryptCard(spec: EncryptSpec, log: TapLog, parts: Partial<Card> & Pick<Card, "outcome">, notes: string[] = []): Card {
  const crv = spec.row.kind === "ecdh" ? ` ${spec.crv ?? "P-256"}` : "";
  return {
    title: `JWE ${spec.row.alg}${crv} ${spec.enc} · Software`,
    keyLives: KEY_LIVES,
    timings: log.timings,
    notes: [...notes, ...(spec.row.kind === "rsa" ? ["key.test-rsa"] : []), ...(spec.row.kind === "pbes2" ? ["key.password"] : [])],
    ...parts,
  };
}

/** Decrypts with explicit `alg` and `enc` allow-lists (RFC 8725 §3.1); returns the card's lines. */
async function decryptStep(log: TapLog, token: string, key: JwkObject, allowedAlgs: readonly string[], enc: string): Promise<string[]> {
  const { value, ms } = await log.run("jweDecryptCompact", () => decryptJwe(token, key, allowedAlgs, [enc]));
  log.step("call", { ms }, "jweDecryptCompact");
  const equal = value.plaintext === PAYLOAD ? "equal" : "differs";
  log.step("decrypt", { alg: String(value.header.alg), enc: String(value.header.enc), plaintext: equal, ms }, "ok");
  return [`Decrypted: alg ${String(value.header.alg)}, enc ${String(value.header.enc)}`, `The plaintext ${equal === "equal" ? "equals" : "differs from"} the input.`];
}

async function encryptStep(log: TapLog, key: SoftwareKey, spec: EncryptSpec): Promise<{ token: string; header: JsonObject }> {
  // Always in software, to the key's public JWK (the shared key itself, for AES and dir). The
  // header has no `kid`: there is one recipient key (see encryptJwe).
  const token = await log.call("jweEncryptCompact", () => encryptJwe(PAYLOAD, counterpart(key), spec.row.alg, spec.enc, false));
  return { token, header: await showToken(log, token) };
}

/**
 * **Encrypt**, **Decrypt** or **Round trip**: encrypts the fixed payload to a new key (or the
 * chosen one) and decrypts it with the key, allowing only the row's `alg` and the chosen `enc`.
 */
export async function encryptTap(log: TapLog, spec: EncryptSpec, mode: "encrypt" | "decrypt" | "round-trip", previous?: Encrypted): Promise<EncryptResult> {
  log.step("input", { op: `jwe-${mode}`, ...encryptFields(spec) });
  let encrypted: Encrypted | undefined;
  let header: JsonObject | undefined;
  try {
    if (mode === "decrypt") {
      if (!previous) throw new StepFailed("NothingToDecrypt");
      encrypted = previous;
      header = await showToken(log, previous.token);
    } else {
      const key = await useKey(log, encryptRequest(spec), spec.key);
      const step = await encryptStep(log, key, spec);
      encrypted = { alg: spec.row.alg, enc: spec.enc, token: step.token, key };
      header = step.header;
    }
    const lines =
      mode === "encrypt"
        ? ["Encrypted. Press Decrypt to decrypt it."]
        : await decryptStep(log, encrypted.token, encrypted.key.privateKey, [encrypted.alg], encrypted.enc);
    return { card: encryptCard(spec, log, { token: encrypted.token, header, outcome: { ok: true, lines } }), encrypted };
  } catch (err) {
    const card = encryptCard(spec, log, { ...(encrypted ? { token: encrypted.token } : {}), ...(header ? { header } : {}), outcome: refused(err) });
    return { card, ...(encrypted ? { encrypted } : {}) };
  }
}

/**
 * One Encrypt-tab failure action: tamper ciphertext, other `alg` allowed, or wrong key. Each
 * ends with the action's code, shown with its explanation.
 */
export async function encryptFailureTap(log: TapLog, spec: EncryptSpec, action: FailureAction): Promise<EncryptResult> {
  log.step("input", { op: "jwe-round-trip", ...encryptFields(spec), failure: action.id.replace(/^failure\./, "") });
  let token: string | undefined;
  let header: JsonObject | undefined;
  const card = (outcome: Card["outcome"]): Card =>
    encryptCard(spec, log, { outcome, expected: action.code, ...(token ? { token } : {}), ...(header ? { header } : {}) }, [action.id]);
  try {
    const key = await useKey(log, encryptRequest(spec), spec.key);
    ({ token, header } = await encryptStep(log, key, spec));
    let decryptKey = key.privateKey;
    let allowed = [spec.row.alg];
    switch (action.id) {
      case "failure.encrypt.tamper": {
        const changed = tamper(token, 3); // the ciphertext part (RFC 7516 §7.1)
        log.step("tamper", { part: "ciphertext", index: changed.index });
        token = changed.token;
        log.step("token", {}, token);
        break;
      }
      case "failure.encrypt.other-alg":
        allowed = [otherAlg(spec.row)];
        break;
      case "failure.encrypt.wrong-key": {
        const { value: other, ms } = await log.run("key-software", () => newSoftwareKey(encryptRequest(spec)));
        logKey(log, other, { wrong: true, ms });
        decryptKey = other.privateKey;
        break;
      }
    }
    log.step("note", { id: action.id });
    const lines = await decryptStep(log, token, decryptKey, allowed, spec.enc);
    return { card: card({ ok: true, lines }) };
  } catch (err) {
    return { card: card(refused(err)) };
  }
}

// ---------------------------------------------------------------------------------------------
// Server tab

const CROSSINGS: Record<ServerActionId, (log: TapLog) => Promise<Outcome<object>>> = {
  "browser-signs": (log) => browserSignsServerVerifies(log),
  "server-issues": serverIssuesBrowserVerifies,
  "browser-encrypts": (log) => browserEncryptsServerDecrypts(log),
  "server-encrypts": serverEncryptsBrowserDecrypts,
  "failure.server.alg-not-allowed": (log) => browserSignsServerVerifies(log, "alg-not-allowed"),
  "failure.server.tampered": (log) => browserSignsServerVerifies(log, "tampered"),
  "failure.server.none": (log) => browserSignsServerVerifies(log, "none"),
  "failure.server.jwe-tampered": (log) => browserEncryptsServerDecrypts(log, "tampered"),
};

/** What a crossing's result says on the card: public values and demo messages only. */
function crossingLines(value: object): string[] {
  const v = value as { alg?: unknown; payload?: unknown; plaintext?: unknown; claims?: unknown; kid?: unknown };
  const lines: string[] = [];
  if (typeof v.alg === "string") lines.push(`Verified: alg ${v.alg}${typeof v.kid === "string" ? `, kid ${v.kid}` : ""}`);
  if (typeof v.payload === "string") lines.push(`Payload: ${v.payload}`);
  if (typeof v.plaintext === "string") lines.push(`Plaintext: ${v.plaintext}`);
  if (typeof v.claims === "object" && v.claims !== null) lines.push(`Claims: ${JSON.stringify(v.claims)}`);
  return lines;
}

/** One Server-tab button: a crossing, or one of the server's refusals with its expected code. */
export async function serverTap(log: TapLog, id: ServerActionId, label: string, expected?: string): Promise<Card> {
  const outcome = await CROSSINGS[id](log);
  const { token } = outcome;
  let header: JsonObject | undefined;
  if (token !== undefined) {
    try {
      header = await readProtectedHeader(token);
    } catch {
      header = undefined; // the card shows the token without a header
    }
  }
  if (expected) log.step("note", { id });
  return {
    title: `${label} · Software`,
    ...(token === undefined ? {} : { token }),
    ...(header === undefined ? {} : { header }),
    outcome: outcome.ok ? { ok: true, lines: crossingLines(outcome.value) } : { ok: false, code: outcome.code, side: outcome.side },
    ...(expected === undefined ? {} : { expected }),
    notes: expected ? [id] : [],
    keyLives: `${KEY_LIVES}; the server's keys live in the server process`,
    timings: log.timings,
  };
}

// ---------------------------------------------------------------------------------------------
// Keys tab

/** **Create key**: a new software key for one row, kept in page memory until deleted. */
export async function keyCreateTap(log: TapLog, request: KeyRequest): Promise<SoftwareKey | undefined> {
  log.step("input", { op: "key-create", store: "software", alg: request.alg, ...(request.crv ? { crv: request.crv } : {}), ...(request.kind === "dir" && request.enc ? { enc: request.enc } : {}) });
  try {
    return await useKey(log, request);
  } catch {
    return undefined; // logged as its code by TapLog
  }
}

/** What the key detail shows: the public JWK and its RFC 7638 thumbprint; a shared key has neither. */
export interface KeyDetail {
  readonly jwk: JwkObject | null;
  readonly thumbprint: string | null;
}

/** A key's detail: logs its public `jwk` and `thumbprint` (RFC 7638 §3, SHA-256). */
export async function keyShowTap(log: TapLog, key: SoftwareKey): Promise<KeyDetail> {
  log.step("input", { op: "key-show", store: "software", alg: key.alg, kid: key.kid });
  if (!key.publicKey) {
    log.step("note", { id: "store.software", shared: true });
    return { jwk: null, thumbprint: null };
  }
  log.step("jwk", {}, key.publicKey);
  try {
    const value = await log.call("jwkThumbprint", () => thumbprint(key.publicKey as JwkObject));
    log.step("thumbprint", { value });
    return { jwk: key.publicKey, thumbprint: value };
  } catch {
    return { jwk: key.publicKey, thumbprint: null };
  }
}

/**
 * **Delete**: the page drops its reference to the key. JavaScript can't wipe the object's memory;
 * the garbage collector frees it later, and closing the tab ends it.
 */
export function keyDeleteTap(log: TapLog, keys: readonly SoftwareKey[]): void {
  log.step("input", { op: keys.length === 1 ? "key-delete" : "key-delete-all", store: "software", count: keys.length });
  for (const key of keys) log.step("key-delete", { kid: key.kid, alg: key.alg });
}

// ---------------------------------------------------------------------------------------------
// The device line (tap 0)

/** What this browser offers, as the Keys tab's "This device" card and the log's tap 0 show it. */
export interface Device {
  readonly polyjose: string;
  readonly browser: string;
  readonly secureContext: boolean;
  readonly webCrypto: boolean;
}

/** The browser and its version, from the user agent string. */
export function browserName(): string {
  const ua = navigator.userAgent;
  const m = ua.match(/(Firefox|Edg|HeadlessChrome|Chrome)\/([\d.]+)/);
  if (m) return `${m[1]} ${m[2]}`;
  const safari = ua.match(/Version\/([\d.]+).*Safari/);
  return safari ? `Safari ${safari[1]}` : "unknown";
}

/** Logs tap 0, `device …`, once when the page starts. */
export async function deviceTap(log: TapLog): Promise<Device> {
  let polyjose: string;
  try {
    polyjose = await polyjoseVersion();
  } catch (err) {
    polyjose = `not-loaded:${codeOf(err)}`;
  }
  const device: Device = {
    polyjose,
    browser: browserName(),
    secureContext: window.isSecureContext,
    webCrypto: typeof crypto !== "undefined" && typeof crypto.subtle !== "undefined",
  };
  log.step("device", {
    polyjose: device.polyjose,
    browser: device.browser,
    "secure-context": device.secureContext,
    webcrypto: device.webCrypto,
    "platform-key-store": false,
    "non-extractable-keys": false,
  });
  return device;
}
