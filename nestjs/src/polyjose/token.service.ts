// Issues and validates the service's access tokens: JWTs (RFC 7519) signed by KeyService.
import { Inject, Injectable } from "@nestjs/common";
import { jwtVerifyWithJwks, type JwtVerified } from "@polyjose/node";

import { POLYJOSE_CONFIG, type PolyjoseConfig } from "../config.js";
import { KeyService } from "./key.service.js";

export interface IssuedToken {
  readonly token: string;
  /** Seconds until `exp` (RFC 6749 §5.1 `expires_in`). */
  readonly expiresIn: number;
}

@Injectable()
export class TokenService {
  readonly #issuer: string;
  readonly #audience: string;
  readonly #ttl: number;
  readonly #leeway: number;

  constructor(
    private readonly keys: KeyService,
    @Inject(POLYJOSE_CONFIG) config: PolyjoseConfig,
  ) {
    this.#issuer = config.issuer;
    this.#audience = config.audience;
    this.#ttl = config.tokenTtlSeconds;
    this.#leeway = config.leewaySeconds;
  }

  /**
   * A token for `subject` with the registered claims of RFC 7519 §4.1: `iss` (§4.1.1), `sub`
   * (§4.1.2), `aud` (§4.1.3), `iat` (§4.1.6) and `exp` (§4.1.4) = `iat` + the lifetime.
   */
  async issue(subject: string): Promise<IssuedToken> {
    const iat = Math.floor(Date.now() / 1000);
    const claims = { iss: this.#issuer, sub: subject, aud: this.#audience, iat, exp: iat + this.#ttl };
    return { token: await this.keys.signJwt(claims), expiresIn: this.#ttl };
  }

  /**
   * Validates a token (RFC 7519 §7.2) against the service's own public JWK Set: the `kid` picks
   * the key, `allowedAlgs` is the configured keys' algorithms and never the token's (RFC 8725
   * §3.1), and `iss` and `aud` must be ours (RFC 8725 §3.8, §3.9). `exp` is required, with the
   * configured leeway. Rejects with a `PolyjoseError`; map it to one opaque error for the client.
   */
  async verify(token: string): Promise<JwtVerified> {
    return jwtVerifyWithJwks(token, this.keys.publicJwks(), {
      allowedAlgs: this.keys.allowedAlgs(),
      issuers: [this.#issuer],
      audiences: [this.#audience],
      leeway: this.#leeway,
    });
  }
}
