// The service's signing keys: loaded once at boot, the first key signs, every key is published.
//
// Rotation: put the new key first and keep the old one after it (its public half is enough).
// Tokens signed by the old key keep verifying until they expire, because the JWK Set still
// publishes it and the token's `kid` (RFC 7515 §4.1.4) selects it.
import { readFile } from "node:fs/promises";
import { inspect } from "node:util";

import { Inject, Injectable, Logger, type OnModuleInit } from "@nestjs/common";
import {
  PolyjoseError,
  jwkGenerateEc,
  jwkParse,
  jwkThumbprint,
  jwkToPublic,
  jwtSign,
  type JsonObject,
  type JwkObject,
  type JwkSetObject,
} from "@polyjose/node";

import { POLYJOSE_CONFIG, type PolyjoseConfig } from "../config.js";

/** A boot-time configuration problem. The message never quotes the key material. */
export class KeyConfigError extends Error {
  override readonly name = "KeyConfigError";
}

interface LoadedKey {
  readonly jwk: JwkObject;
  readonly kid: string;
  readonly alg: string;
}

@Injectable()
export class KeyService implements OnModuleInit {
  readonly #logger = new Logger(KeyService.name);
  // Private (#) fields: they are not enumerable properties, so `JSON.stringify` and
  // `util.inspect` never reach them; toJSON and inspect.custom below say so explicitly.
  readonly #source: PolyjoseConfig["signingKeys"];
  #signing: LoadedKey | undefined;
  #publicJwks: JwkSetObject = { keys: [] };
  #allowedAlgs: readonly string[] = [];

  constructor(@Inject(POLYJOSE_CONFIG) config: PolyjoseConfig) {
    this.#source = config.signingKeys;
  }

  async onModuleInit(): Promise<void> {
    const text = await this.#readSource();
    const keys = text === undefined ? [await ephemeralKey()] : await parseKeySet(text);
    const signing = keys[0];
    if (signing === undefined) throw new KeyConfigError("the signing JWK Set has no keys");
    if (typeof signing.jwk.d !== "string") {
      throw new KeyConfigError(`the first key (kid=${signing.kid}) signs, so it must be a private key`);
    }
    this.#signing = signing;
    // RFC 7517 §5: a JWK Set of public keys only; jwkToPublic keeps kid, alg and use.
    this.#publicJwks = { keys: await Promise.all(keys.map((key) => jwkToPublic(key.jwk))) };
    // RFC 8725 §3.1: the verifier's allow-list is the algorithms of our own keys, never the token's.
    this.#allowedAlgs = [...new Set(keys.map((key) => key.alg))];
    if (text === undefined) this.#logger.log(`ephemeral signing key kid=${signing.kid}`);
    this.#logger.log(`signing key kid=${signing.kid} alg=${signing.alg}; publishing ${keys.length} key(s)`);
  }

  /** The `kid` of the key that signs new tokens. */
  get signingKid(): string {
    return this.#loaded().kid;
  }

  /** The public JWK Set to serve at the `jwks_uri` (RFC 7517 §5, RFC 8414 §2). */
  publicJwks(): JwkSetObject {
    return this.#publicJwks;
  }

  /** The JWS `alg` names of the configured keys: the verify allow-list (RFC 8725 §3.1). */
  allowedAlgs(): readonly string[] {
    return this.#allowedAlgs;
  }

  /**
   * Signs a JWT Claims Set with the first key (RFC 7519 §7.1). The header gets the key's `alg`
   * and `kid` (RFC 7515 §4.1.1, §4.1.4) and `typ: "JWT"` (RFC 7519 §5.1). The private key never
   * leaves this service.
   */
  async signJwt(claims: JsonObject): Promise<string> {
    const { jwk, alg } = this.#loaded();
    return jwtSign(claims, jwk, { alg });
  }

  toJSON(): object {
    return { signingKid: this.#signing?.kid, publishedKeys: this.#publicJwks.keys.length };
  }

  [inspect.custom](): string {
    return `KeyService ${JSON.stringify(this.toJSON())}`;
  }

  #loaded(): LoadedKey {
    if (this.#signing === undefined) throw new KeyConfigError("the signing keys are not loaded yet");
    return this.#signing;
  }

  async #readSource(): Promise<string | undefined> {
    if (this.#source.json !== undefined) return this.#source.json;
    if (this.#source.file === undefined) return undefined;
    try {
      return await readFile(this.#source.file, "utf8");
    } catch (err) {
      // The path is configuration, not a secret; the file content is never quoted.
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      throw new KeyConfigError(`POLYJOSE_SIGNING_JWKS_FILE could not be read (${code ?? errorName(err)})`);
    }
  }
}

/** A new ES256 key (RFC 7518 §3.4) for this process only; its `kid` is its RFC 7638 thumbprint. */
async function ephemeralKey(): Promise<LoadedKey> {
  const jwk = await jwkGenerateEc("P-256");
  const kid = await jwkThumbprint(jwk);
  return { jwk: { ...jwk, alg: "ES256", use: "sig", kid }, kid, alg: "ES256" };
}

/**
 * Parses a private JWK Set (RFC 7517 §5). Each key needs a unique `kid` (RFC 7517 §4.5) and an
 * `alg` (§4.4), and must not be symmetric: every key is published. Errors name the key by its
 * position and `kid` only; neither JSON.parse's message (it can quote the input) nor a key
 * member is ever shown.
 */
async function parseKeySet(text: string): Promise<LoadedKey[]> {
  let set: unknown;
  try {
    set = JSON.parse(text);
  } catch {
    throw new KeyConfigError("the signing JWK Set is not valid JSON");
  }
  const members = isObject(set) && Array.isArray(set.keys) ? set.keys : undefined;
  if (members === undefined) throw new KeyConfigError('the signing JWK Set has no "keys" array');
  const keys: LoadedKey[] = [];
  for (const [index, member] of members.entries()) {
    if (!isObject(member)) throw new KeyConfigError(`signing key ${index} is not a JSON object`);
    const { kid, alg, kty } = member;
    if (typeof kid !== "string" || kid === "") throw new KeyConfigError(`signing key ${index} has no "kid"`);
    if (typeof alg !== "string" || alg === "") throw new KeyConfigError(`signing key ${index} (kid=${kid}) has no "alg"`);
    if (kty === "oct") throw new KeyConfigError(`signing key ${index} (kid=${kid}) is symmetric; a JWK Set is public`);
    if (keys.some((key) => key.kid === kid)) throw new KeyConfigError(`signing key ${index}: duplicate kid=${kid}`);
    let jwk: JwkObject;
    try {
      jwk = await jwkParse(member as JwkObject);
    } catch (err) {
      const code = err instanceof PolyjoseError ? err.code : errorName(err);
      throw new KeyConfigError(`signing key ${index} (kid=${kid}) is not a valid JWK (${code})`);
    }
    keys.push({ jwk, kid, alg });
  }
  return keys;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function errorName(err: unknown): string {
  return err instanceof Error ? err.name : typeof err;
}
