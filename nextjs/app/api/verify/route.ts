// POST /api/verify { tap, token, jwk }: the server verifies a compact JWS the browser signed
// (RFC 7515 §5.2), with the browser's public JWK.
//
// The allow-list is the server's own, ES256 only, and never comes from the token's header
// (RFC 8725 §3.1). So a token whose `alg` is `none` (RFC 8725 §3.2), or any algorithm other than
// ES256, fails with AlgorithmNotAllowed before its signature is looked at, and a changed token
// fails with InvalidSignature (RFC 7515 §5.2 step 8).
//
// A real service would take the key from its own registry of clients, not from the request.
// The demo takes it from the request to show the crossing; the allow-list still decides.
import { jwsVerifyCompact } from "@polyjose/node";

import { SIGNING_ALG } from "../../../lib/shared";
import { handlePost, publicJwkField, stringField } from "../_server/http";

export const runtime = "nodejs";

/** The only algorithm this route accepts. */
const ALLOWED_ALGS = [SIGNING_ALG] as const;

export async function POST(request: Request): Promise<Response> {
  return handlePost(request, "verify", async (body, log) => {
    const token = stringField(body, "token");
    const jwk = publicJwkField(body, "jwk");
    log.step("input", { op: "jws-verify", allowedAlgs: ALLOWED_ALGS.join(",") });
    const verified = await jwsVerifyCompact(token, jwk, { allowedAlgs: ALLOWED_ALGS });
    const payload = new TextDecoder().decode(verified.payload);
    log.step("verify", { result: "ok", alg: verified.alg, bytes: verified.payload.length });
    return { alg: verified.alg, payload };
  });
}
