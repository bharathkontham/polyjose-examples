// `@Claims()`: the JWT Claims Set (RFC 7519 §4) that JwtAuthGuard validated for this request.
import { createParamDecorator, type ExecutionContext, InternalServerErrorException } from "@nestjs/common";
import type { JsonObject } from "@polyjose/node";

import type { AuthRequest } from "./jwt-auth.guard.js";

export const Claims = createParamDecorator((_data: unknown, context: ExecutionContext): JsonObject => {
  const claims = context.switchToHttp().getRequest<AuthRequest>().claims;
  // Only reachable on a route without @UseGuards(JwtAuthGuard): a programming error.
  if (claims === undefined) throw new InternalServerErrorException();
  return claims;
});
