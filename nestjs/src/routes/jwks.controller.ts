// GET /.well-known/jwks.json: the public JWK Set (RFC 7517 §5) that verifiers fetch.
import { Controller, Get, Header } from "@nestjs/common";
import type { JwkSetObject } from "@polyjose/node";

import { KeyService } from "../polyjose/key.service.js";

@Controller()
export class JwksController {
  constructor(private readonly keys: KeyService) {}

  /** Public members only (RFC 7517 §4, RFC 7518 §6.2.1): KeyService built it with jwkToPublic. */
  @Get(".well-known/jwks.json")
  @Header("Cache-Control", "public, max-age=300")
  jwks(): JwkSetObject {
    return this.keys.publicJwks();
  }
}
