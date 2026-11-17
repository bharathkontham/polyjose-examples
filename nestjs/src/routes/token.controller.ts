// POST /token: the client credentials grant (RFC 6749 §4.4) for the one configured demo client.
//
//   curl -s -X POST http://localhost:3000/token \
//     -d grant_type=client_credentials -d client_id=demo-client -d client_secret="$SECRET"
import { createHash, timingSafeEqual } from "node:crypto";

import { Body, Controller, HttpCode, HttpException, Inject, Logger, Post, Res } from "@nestjs/common";

import { DEMO_CLIENT_CONFIG, type DemoClientConfig } from "../config.js";
import { TokenService } from "../polyjose/token.service.js";

interface HeaderResponse {
  setHeader(name: string, value: string): unknown;
}

/** RFC 6749 §5.1: the successful response. */
interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
}

/** RFC 6749 §5.2: an error response, with no detail beyond the error code. */
function oauthError(status: 400 | 401, error: "invalid_request" | "invalid_client" | "unsupported_grant_type"): HttpException {
  return new HttpException({ error }, status);
}

/**
 * Compares two strings in constant time: both are hashed first, so the comparison always runs
 * over two equal-length SHA-256 digests (timingSafeEqual needs equal lengths) and its time
 * reveals neither the secret's length nor where the first difference is.
 */
function sameString(given: string, expected: string): boolean {
  const a = createHash("sha256").update(given, "utf8").digest();
  const b = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(a, b);
}

@Controller()
export class TokenController {
  readonly #logger = new Logger(TokenController.name);
  readonly #client: DemoClientConfig;

  constructor(
    private readonly tokens: TokenService,
    @Inject(DEMO_CLIENT_CONFIG) client: DemoClientConfig,
  ) {
    this.#client = client;
    if (client.clientSecret === undefined) {
      this.#logger.warn("POLYJOSE_DEMO_CLIENT_SECRET is not set: POST /token refuses every client");
    }
  }

  @Post("token")
  @HttpCode(200)
  async token(@Body() body: unknown, @Res({ passthrough: true }) response: HeaderResponse): Promise<TokenResponse> {
    // RFC 6749 §5.1: token responses, and so their errors too, are never cached.
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("Pragma", "no-cache");

    // RFC 6749 §4.4.2: an application/x-www-form-urlencoded body; anything else is not parsed.
    const form = typeof body === "object" && body !== null ? (body as Record<string, unknown>) : {};
    const { grant_type: grantType, client_id: clientId, client_secret: clientSecret } = form;
    if (typeof grantType !== "string") throw oauthError(400, "invalid_request");
    if (grantType !== "client_credentials") throw oauthError(400, "unsupported_grant_type");
    if (typeof clientId !== "string" || typeof clientSecret !== "string") throw oauthError(400, "invalid_request");

    // RFC 6749 §2.3.1: client_id and client_secret in the body. Both comparisons always run.
    const expectedSecret = this.#client.clientSecret;
    const idMatches = sameString(clientId, this.#client.clientId);
    const secretMatches = expectedSecret !== undefined && sameString(clientSecret, expectedSecret);
    if (!(idMatches && secretMatches)) {
      this.#logger.warn("client authentication failed");
      throw oauthError(401, "invalid_client");
    }

    const { token, expiresIn } = await this.tokens.issue(this.#client.clientId);
    this.#logger.log(`token issued sub=${this.#client.clientId} expires_in=${expiresIn}`);
    return { access_token: token, token_type: "Bearer", expires_in: expiresIn };
  }
}
