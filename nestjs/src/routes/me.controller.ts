// GET /me: a protected route. It answers only with a valid access token.
import { Controller, Get, UseGuards } from "@nestjs/common";
import type { JsonObject } from "@polyjose/node";

import { Claims } from "../auth/claims.decorator.js";
import { JwtAuthGuard } from "../auth/jwt-auth.guard.js";

@Controller()
export class MeController {
  /** The validated claims of the caller's token (RFC 7519 §4). */
  @Get("me")
  @UseGuards(JwtAuthGuard)
  me(@Claims() claims: JsonObject): JsonObject {
    return claims;
  }
}
