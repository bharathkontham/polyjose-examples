import "server-only"; // a client component that imports this module fails the build

// The server's two private keys: one signs JWTs (ES256), one decrypts JWEs sent to the server
// (ECDH-ES+A256KW). They never leave this process; the JWK Set at /api/jwks has their public
// halves only (RFC 7517 §5).
//
// By default both are generated when the first request needs them and live until the server
// stops, so every `next start` has new keys. To keep keys across restarts, set
// POLYJOSE_SERVER_JWKS to a private JWK Set (JSON text) with one key whose `alg` is ES256 and
// one whose `alg` is ECDH-ES+A256KW, both on P-256. Keep that value in your secret store, never
// in the repository. Only the keys' `kid`s are logged.
import { PolyjoseError, jwkGenerateEc, jwkParse, jwkThumbprint, jwkToPublic, jwksSelect, type JwkObject, type JwkSetObject } from "@polyjose/node";

import { KEY_MANAGEMENT_ALG, SIGNING_ALG, hasPrivateMember, logLine } from "../../../lib/shared";

export interface ServerKeys {
  /** The private ES256 key the server signs JWTs with. Never logged or sent. */
  readonly signing: JwkObject;
  /** The private P-256 key JWEs to the server are decrypted with. Never logged or sent. */
  readonly decryption: JwkObject;
  /** The public halves of both, as served at /api/jwks. */
  readonly jwks: JwkSetObject;
}

/** Thrown when POLYJOSE_SERVER_JWKS can't be used; the code names why, never the value. */
export class ServerKeysError extends Error {
  constructor(readonly code: string) {
    super(`POLYJOSE_SERVER_JWKS: ${code}`);
    this.name = "ServerKeysError";
  }
}

/**
 * Gives `key` the members a JWK Set entry needs: `alg` and `use` (RFC 7517 §4.4, §4.2), and a
 * `kid` (RFC 7517 §4.5), which is the RFC 7638 thumbprint when the key has none.
 */
async function labelled(key: JwkObject, alg: string, use: "sig" | "enc"): Promise<JwkObject> {
  const kid = typeof key.kid === "string" && key.kid !== "" ? key.kid : await jwkThumbprint(key, "sha-256");
  return { ...key, alg, use, kid };
}

/** Two new P-256 keys (RFC 7518 §6.2), from the OS random number generator. */
async function ephemeralKeys(): Promise<[JwkObject, JwkObject]> {
  return [
    await labelled(await jwkGenerateEc("P-256"), SIGNING_ALG, "sig"),
    await labelled(await jwkGenerateEc("P-256"), KEY_MANAGEMENT_ALG, "enc"),
  ];
}

/** The two keys of POLYJOSE_SERVER_JWKS, chosen by `alg` (RFC 7517 §4.4). */
async function configuredKeys(text: string): Promise<[JwkObject, JwkObject]> {
  const pick = async (alg: string, use: "sig" | "enc") => {
    let key: JwkObject;
    try {
      key = await jwksSelect(text, { alg });
      await jwkParse(key);
    } catch (err) {
      throw new ServerKeysError(err instanceof PolyjoseError ? err.code : "InvalidJwks");
    }
    if (key.kty !== "EC" || key.crv !== "P-256") throw new ServerKeysError(`${alg}KeyNotP256`);
    if (!hasPrivateMember(key)) throw new ServerKeysError(`${alg}KeyNotPrivate`);
    return labelled(key, alg, use);
  };
  return [await pick(SIGNING_ALG, "sig"), await pick(KEY_MANAGEMENT_ALG, "enc")];
}

async function loadKeys(): Promise<ServerKeys> {
  const configured = process.env.POLYJOSE_SERVER_JWKS;
  const source = configured ? "POLYJOSE_SERVER_JWKS" : "ephemeral";
  const [signing, decryption] = configured ? await configuredKeys(configured) : await ephemeralKeys();
  const jwks: JwkSetObject = { keys: [await jwkToPublic(signing), await jwkToPublic(decryption)] };
  console.log(logLine(0, "1", "server-keys", { source, signing: String(signing.kid), decryption: String(decryption.kid) }));
  return { signing, decryption, jwks };
}

// One key set per server process. It is kept on `globalThis` so that every route handler sees
// the same keys, however the bundler splits the routes into chunks.
const SLOT = Symbol.for("polyjose.examples.nextjs.serverKeys");
type Slot = { [SLOT]?: Promise<ServerKeys> };

/** The server's keys, created (or read from POLYJOSE_SERVER_JWKS) on the first call. */
export function serverKeys(): Promise<ServerKeys> {
  const slot = globalThis as Slot;
  slot[SLOT] ??= loadKeys().catch((err: unknown) => {
    delete slot[SLOT]; // let a later request try again
    throw err;
  });
  return slot[SLOT];
}
