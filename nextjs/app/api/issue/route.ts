// POST /api/issue { tap }: the server issues a JWT (RFC 7519 §7.1) for the demo subject,
// signed with its ES256 key. The header carries the key's `kid` (RFC 7515 §4.1.4), which picks
// the key from /api/jwks when the browser validates the token.
import { decodeProtectedHeaderUnverified, jwtSign } from "@polyjose/node";

import { AUDIENCE, DEMO_SUBJECT, ISSUER, SIGNING_ALG, TOKEN_LIFETIME } from "../../../lib/shared";
import { handlePost } from "../_server/http";
import { serverKeys } from "../_server/keys";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  return handlePost(request, "issue", async (_body, log) => {
    const { signing } = await serverKeys();
    const now = Math.floor(Date.now() / 1000);
    // RFC 7519 §4.1: issuer, audience, subject, issued-at and expiry.
    const claims = { iss: ISSUER, aud: AUDIENCE, sub: DEMO_SUBJECT, iat: now, exp: now + TOKEN_LIFETIME };
    log.step("input", { op: "jwt-sign", store: "software", alg: SIGNING_ALG, kid: String(signing.kid) });
    const token = await log.call("jwtSign", () => jwtSign(claims, signing, { alg: SIGNING_ALG }));
    // Only the token's header is logged. A real service never logs the tokens it issues: anyone
    // who can read the log could use one until it expires.
    log.step("header", {}, await decodeProtectedHeaderUnverified(token));
    return { token };
  });
}
