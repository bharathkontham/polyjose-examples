// Protects a route with a Bearer access token (RFC 6750) validated by TokenService.
import { type CanActivate, type ExecutionContext, Injectable, Logger } from "@nestjs/common";
import { PolyjoseError, type JsonObject } from "@polyjose/node";

import { TokenService } from "../polyjose/token.service.js";
import { AppHttpException } from "../safe-exception.filter.js";

/** The parts of the HTTP request and response the guard uses. */
export interface AuthRequest {
  headers: Record<string, string | string[] | undefined>;
  /** The validated claims, set by JwtAuthGuard and read by @Claims(). */
  claims?: JsonObject;
}
interface ChallengeResponse {
  setHeader(name: string, value: string): unknown;
}

/** `Authorization: Bearer <token>` (RFC 6750 §2.1; the scheme name is case-insensitive, RFC 9110 §11.1). */
const BEARER = /^Bearer +([A-Za-z0-9\-._~+/]+=*) *$/i;

@Injectable()
export class JwtAuthGuard implements CanActivate {
  readonly #logger = new Logger(JwtAuthGuard.name);

  constructor(private readonly tokens: TokenService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const http = context.switchToHttp();
    const request = http.getRequest<AuthRequest>();
    const response = http.getResponse<ChallengeResponse>();
    const header = request.headers.authorization;
    const token = typeof header === "string" ? BEARER.exec(header)?.[1] : undefined;
    if (token === undefined) {
      // RFC 6750 §3.1: a request with no token gets the challenge without an error code.
      response.setHeader("WWW-Authenticate", "Bearer");
      throw new AppHttpException({ message: "Unauthorized" }, 401);
    }
    try {
      request.claims = (await this.tokens.verify(token)).claims;
      return true;
    } catch (err) {
      // The code goes to the server log only (RFC 8725 §3.1 failures are not explained to the
      // client); the message is never logged, and the token never is.
      const code = err instanceof PolyjoseError ? err.code : `unexpected ${err instanceof Error ? err.name : typeof err}`;
      this.#logger.warn(`token rejected code=${code}`);
      // RFC 6750 §3.1: one opaque `invalid_token` for every invalid, expired or unknown token.
      response.setHeader("WWW-Authenticate", 'Bearer error="invalid_token"');
      throw new AppHttpException({ error: "invalid_token" }, 401);
    }
  }
}
