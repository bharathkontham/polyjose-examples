// POST /api/encrypt { tap, jwk }: the server encrypts its fixed demo message to the browser's
// public P-256 key in the JWE Compact Serialization (RFC 7516 §5.1, §7.1), with ECDH-ES+A256KW
// (RFC 7518 §4.6) and A256GCM (RFC 7518 §5.3). Only the browser's private key can decrypt it.
import { jweEncryptCompact } from "@polyjose/node";

import { CONTENT_ENC, KEY_MANAGEMENT_ALG, MESSAGES } from "../../../lib/shared";
import { handlePost, jwkSummary, publicJwkField } from "../_server/http";

export const runtime = "nodejs";

export async function POST(request: Request): Promise<Response> {
  return handlePost(request, "encrypt", async (body, log) => {
    const jwk = publicJwkField(body, "jwk");
    const kid = typeof jwk.kid === "string" ? jwk.kid : undefined;
    log.step("input", { op: "jwe-encrypt", store: "software", alg: KEY_MANAGEMENT_ALG, enc: CONTENT_ENC });
    log.step("jwk", {}, jwkSummary(jwk));
    const token = await log.call("jweEncryptCompact", () =>
      jweEncryptCompact(new TextEncoder().encode(MESSAGES.serverEncrypts), {
        enc: CONTENT_ENC,
        // The recipient's `kid` in the protected header tells it which of its keys to use
        // (RFC 7516 §4.1.6).
        protectedHeader: kid === undefined ? undefined : { kid },
        recipients: [{ alg: KEY_MANAGEMENT_ALG, key: jwk }],
      }),
    );
    log.step("token", {}, token);
    return { token };
  });
}
