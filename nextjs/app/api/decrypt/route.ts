// POST /api/decrypt { tap, token }: the server decrypts a compact JWE the browser encrypted to
// the server's public key (RFC 7516 §5.2).
//
// Both allow-lists are the server's own, ECDH-ES+A256KW and A256GCM only (RFC 8725 §3.1). A
// wrong key, a changed token or a bad tag all fail with the one code DecryptionFailed, so the
// answer says nothing about the cause (RFC 7516 §11.5). The content key and the ECDH shared
// secret never leave polyjose.
import { jweDecryptCompact } from "@polyjose/node";

import { CONTENT_ENC, KEY_MANAGEMENT_ALG, MESSAGES } from "../../../lib/shared";
import { RequestError, handlePost, stringField } from "../_server/http";
import { serverKeys } from "../_server/keys";

export const runtime = "nodejs";

const ALLOWED_ALGS = [KEY_MANAGEMENT_ALG] as const;
const ALLOWED_ENC = [CONTENT_ENC] as const;

export async function POST(request: Request): Promise<Response> {
  return handlePost(request, "decrypt", async (body, log) => {
    const token = stringField(body, "token");
    const { decryption } = await serverKeys();
    log.step("input", { op: "jwe-decrypt", store: "software", allowedAlgs: ALLOWED_ALGS.join(","), allowedEnc: ALLOWED_ENC.join(",") });
    const decrypted = await log.call("jweDecryptCompact", () =>
      jweDecryptCompact(token, decryption, { allowedAlgs: ALLOWED_ALGS, allowedEnc: ALLOWED_ENC }),
    );
    let plaintext: string;
    try {
      plaintext = new TextDecoder("utf-8", { fatal: true }).decode(decrypted.plaintext);
    } catch {
      throw new RequestError("BadRequest"); // this demo only exchanges text
    }
    const equal = plaintext === MESSAGES.browserEncrypts ? "equal" : "differs";
    // A compact JWE has only a protected header (RFC 7516 §7.1).
    const header = decrypted.protectedHeader ?? {};
    log.step("decrypt", { alg: String(header.alg), enc: String(header.enc), plaintext: equal }, "ok");
    // Only the app's fixed demo message is answered: any other plaintext is refused, so the route
    // never echoes text it decrypted.
    if (plaintext !== MESSAGES.browserEncrypts) throw new RequestError("BadRequest");
    return { plaintext: MESSAGES.browserEncrypts };
  });
}
