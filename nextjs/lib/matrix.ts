// The web playground's support matrix: what the Sign and Encrypt tabs offer, which key stores
// are shown and why two are disabled, and the failure actions with the code each must give.
// The tabs and the demo walk both read this table, so a cell where it and the library disagree
// fails the walk. Nothing here calls polyjose.
//
// The rows are PLAYGROUND.md's Software column, plus what @polyjose/wasm 0.4.0 offers beyond
// it (marked `addition`): ES256K, the fully specified `Ed25519` name and PBES2. polyjose 0.4.0
// refuses RSA-OAEP (SHA-1) and RSA1_5 with UnsupportedAlgorithm, so they aren't rows.

/** The payload every JWS signs and every JWE encrypts (PLAYGROUND.md `option.payload`). */
export const PAYLOAD = "polyjose example payload";

/** The claims every playground JWT carries; `exp` is added when it is signed (`option.payload`). */
export const JWT_CLAIMS = { iss: "https://issuer.example", aud: "https://api.example", sub: "user-123" } as const;

/** `exp` of a playground JWT: five minutes from now (RFC 7519 §4.1.4). */
export const JWT_LIFETIME = 300;

/** What a key is: a shared secret, the RSA test key, an EC key or an OKP key (RFC 7518 §6, RFC 8037 §2). */
export type KeyKind = "oct" | "RSA" | "EC" | "OKP";

export interface SignRow {
  readonly alg: string;
  readonly kind: KeyKind;
  /** The allow-list of `failure.sign.other-alg`: another algorithm of the same key type; absent when the action is disabled. */
  readonly other?: string;
  /** Not in PLAYGROUND.md's Software column; offered by @polyjose/wasm 0.4.0. */
  readonly addition?: true;
}

/** JWS algorithms (RFC 7518 §3, RFC 8037 §3.1, RFC 8812 §3.2, RFC 9864 §2.2). */
export const SIGN_ROWS: readonly SignRow[] = [
  { alg: "HS256", kind: "oct", other: "HS384" },
  { alg: "HS384", kind: "oct", other: "HS512" },
  { alg: "HS512", kind: "oct", other: "HS256" },
  { alg: "RS256", kind: "RSA" },
  { alg: "RS384", kind: "RSA" },
  { alg: "RS512", kind: "RSA" },
  { alg: "PS256", kind: "RSA" },
  { alg: "PS384", kind: "RSA" },
  { alg: "PS512", kind: "RSA" },
  { alg: "ES256", kind: "EC", other: "ES384" },
  { alg: "ES384", kind: "EC", other: "ES512" },
  { alg: "ES512", kind: "EC", other: "ES256" },
  { alg: "ES256K", kind: "EC", other: "ES256", addition: true },
  { alg: "EdDSA", kind: "OKP" },
  { alg: "Ed25519", kind: "OKP", addition: true },
];

/** The curves of an ECDH-ES key (`option.curve`; RFC 7518 §6.2.1.1, RFC 8037 §3.2). */
export const ECDH_CURVES = ["P-256", "P-384", "P-521", "X25519"] as const;
export type EcdhCurve = (typeof ECDH_CURVES)[number];

/**
 * How a JWE key-management algorithm gets its key: ECDH-ES with a key pair on a curve, RSA with
 * the test key, a shared key made for the `alg`, a `dir` key made for the `enc`, or a password.
 */
export type EncryptKind = "ecdh" | "rsa" | "oct" | "dir" | "pbes2";

export interface EncryptRow {
  readonly alg: string;
  readonly kind: EncryptKind;
  /** The allow-list of `failure.encrypt.other-alg`: only another `alg`; absent when the action is disabled. */
  readonly other?: string;
  readonly addition?: true;
}

/** JWE key management algorithms (RFC 7518 §4). */
export const ENCRYPT_ROWS: readonly EncryptRow[] = [
  { alg: "ECDH-ES", kind: "ecdh", other: "ECDH-ES+A256KW" },
  { alg: "ECDH-ES+A128KW", kind: "ecdh", other: "ECDH-ES+A192KW" },
  { alg: "ECDH-ES+A192KW", kind: "ecdh", other: "ECDH-ES+A256KW" },
  { alg: "ECDH-ES+A256KW", kind: "ecdh", other: "ECDH-ES+A128KW" },
  { alg: "RSA-OAEP-256", kind: "rsa" },
  { alg: "A128KW", kind: "oct", other: "A192KW" },
  { alg: "A192KW", kind: "oct", other: "A256KW" },
  { alg: "A256KW", kind: "oct", other: "A128KW" },
  { alg: "A128GCMKW", kind: "oct", other: "A192GCMKW" },
  { alg: "A192GCMKW", kind: "oct", other: "A256GCMKW" },
  { alg: "A256GCMKW", kind: "oct", other: "A128GCMKW" },
  { alg: "dir", kind: "dir", other: "A256KW" },
  { alg: "PBES2-HS256+A128KW", kind: "pbes2", other: "PBES2-HS384+A192KW", addition: true },
  { alg: "PBES2-HS384+A192KW", kind: "pbes2", other: "PBES2-HS512+A256KW", addition: true },
  { alg: "PBES2-HS512+A256KW", kind: "pbes2", other: "PBES2-HS256+A128KW", addition: true },
];

/** Content encryption algorithms (RFC 7518 §5), with every row. */
export const ENCS = ["A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"] as const;

export interface Store {
  readonly id: string;
  readonly label: string;
  /** Absent: enabled. Present: the explanation id of why the row is disabled. */
  readonly disabled?: string;
}

/**
 * The key stores of the Sign, Encrypt and Keys tabs. Only software keys exist in polyjose 0.4.0
 * in a browser: there is no browser key store and no non-extractable WebCrypto key, so those
 * rows are shown disabled, with the reason, and there is nothing to "run anyway".
 */
export const STORES: readonly Store[] = [
  { id: "software", label: "Software (page memory)" },
  { id: "platform", label: "Platform key store", disabled: "reason.not-in-polyjose" },
  { id: "webcrypto", label: "WebCrypto non-extractable key", disabled: "reason.not-in-polyjose" },
];

/** Where a software key lives, as the result card says it. */
export const KEY_LIVES = "page memory (software, readable by any script on this page)";

export interface FailureAction {
  /** The explanation id, and the log's `failure` field without the `failure.` prefix. */
  readonly id: string;
  readonly label: string;
  /** The code the action must end with. */
  readonly code: string;
  /** Absent: enabled. Present: why the action is disabled here. */
  readonly disabled?: string;
}

/** The Sign tab's failure actions (PLAYGROUND.md, "Failure actions"). */
export const SIGN_FAILURES: readonly FailureAction[] = [
  { id: "failure.sign.tamper", label: "Tamper", code: "InvalidSignature" },
  { id: "failure.sign.other-alg", label: "Other algorithm allowed", code: "AlgorithmNotAllowed" },
  { id: "failure.sign.wrong-key", label: "Wrong key", code: "InvalidSignature" },
  { id: "failure.sign.expired", label: "Expired (JWT)", code: "TokenExpired" },
  { id: "failure.sign.deleted-key", label: "Deleted key", code: "KeyNotFound", disabled: "reason.software-not-stored" },
];

/** The Encrypt tab's failure actions. */
export const ENCRYPT_FAILURES: readonly FailureAction[] = [
  { id: "failure.encrypt.tamper", label: "Tamper ciphertext", code: "DecryptionFailed" },
  { id: "failure.encrypt.other-alg", label: "Other alg allowed", code: "AlgorithmNotAllowed" },
  { id: "failure.encrypt.wrong-key", label: "Wrong key", code: "DecryptionFailed" },
  { id: "failure.encrypt.deleted-key", label: "Deleted key", code: "KeyNotFound", disabled: "reason.software-not-stored" },
];

const WRONG_KEY = new Set(["failure.sign.wrong-key", "failure.encrypt.wrong-key"]);
const OTHER_ALG = new Set(["failure.sign.other-alg", "failure.encrypt.other-alg"]);

/**
 * Why a failure action is disabled for one row, beyond the table above; undefined when it isn't.
 * - RSA (RS*, PS*, RSA-OAEP-256): the only software RSA private key is the RFC 7515 A.2 test key,
 *   and polyjose 0.4.0 can't generate another, so neither "wrong key" nor "other algorithm
 *   allowed" is offered.
 * - EdDSA (and its fully specified name Ed25519): an Ed25519 key has no other signing algorithm,
 *   so "other algorithm allowed" isn't offered.
 * The demo walk skips a disabled cell, so it doesn't count it.
 */
export function failureDisabled(action: FailureAction, row: EncryptRow | SignRow): string | undefined {
  if (action.disabled) return action.disabled;
  const rsa = row.kind === "RSA" || row.kind === "rsa";
  if (rsa && WRONG_KEY.has(action.id)) return "reason.rsa-wrong-key";
  if (rsa && OTHER_ALG.has(action.id)) return "reason.rsa-other-alg";
  if (row.kind === "OKP" && OTHER_ALG.has(action.id)) return "reason.eddsa-other-alg";
  return undefined;
}

/** The Server tab's crossings and refusals. Each is one round trip between the page and a route. */
export const SERVER_ACTIONS = [
  { id: "browser-signs", label: "Browser signs, server verifies (ES256)" },
  { id: "server-issues", label: "Server issues a JWT, browser verifies it with the JWKS" },
  { id: "browser-encrypts", label: "Browser encrypts, server decrypts (P-256)" },
  { id: "server-encrypts", label: "Server encrypts, browser decrypts (P-256)" },
  { id: "failure.server.alg-not-allowed", label: "Server refuses ES384", code: "AlgorithmNotAllowed" },
  { id: "failure.server.tampered", label: "Server refuses a changed token", code: "InvalidSignature" },
  { id: "failure.server.none", label: "Server refuses alg none", code: "AlgorithmNotAllowed" },
  { id: "failure.server.jwe-tampered", label: "Server refuses a changed JWE", code: "DecryptionFailed" },
] as const satisfies readonly { id: string; label: string; code?: string }[];

export type ServerActionId = (typeof SERVER_ACTIONS)[number]["id"];
