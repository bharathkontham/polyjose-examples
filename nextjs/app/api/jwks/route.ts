// GET /api/jwks: the server's public keys as a JWK Set (RFC 7517 §5), the way an identity
// provider publishes its `jwks_uri`. The browser verifies the server's JWTs against it and
// encrypts to its ECDH-ES key. Only public members are served (RFC 7517 §4, RFC 7518 §6.2.1).
import { getError, getJson } from "../_server/http";
import { serverKeys } from "../_server/keys";

/** @polyjose/node is a native addon, so this route runs on Node.js, never on the edge runtime. */
export const runtime = "nodejs";
/** Answered per request: the keys are made when the server starts, not when the app is built. */
export const dynamic = "force-dynamic";

export async function GET(): Promise<Response> {
  try {
    const { jwks } = await serverKeys();
    return getJson(jwks);
  } catch (err) {
    return getError("jwks", err);
  }
}
