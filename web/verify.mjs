// Runs every check of ../CATALOG.md against @polyjose/wasm, through the example files, and
// shows one line per check, then the result line, in <pre id="result"> and in the console:
//
//   PASS jws/sign-verify/es256
//   FAIL jwt/verify/rejects-expired: expected TokenExpired, got InvalidClaim
//   POLYJOSE-VERIFY: 33/34 PASS
//
// Every check passed only when the result line reads R/R with R > 0. A FAIL line never shows
// key material or token contents. index.html loads this module; run.sh reads the result.
import { PolyjoseError, base64urlEncode, jwkGenerateEc, jwkGenerateForAlg, jwkToPublic, version } from "@polyjose/wasm";

import { recipientKeyPair, encryptTo, decrypt, ALG, ENC } from "./examples/encrypt-decrypt.mjs";
import { generateEcKey, pemRoundTrip, publicJwks, publicKeyOf, selectKey, thumbprint } from "./examples/keys-jwks.mjs";
import { signCompact, signGeneral, signingKeyPair, verifyCompact, verifyJson } from "./examples/sign-verify-jws.mjs";
import { issueToken, validateToken, validateWithJwks } from "./examples/sign-verify-jwt.mjs";
import { RFC7638_3_1 } from "./examples/test-keys.mjs";
import { jwsRejection, jwtRejection, rejectionCode } from "./examples/verify-allow-list.mjs";

// --- helpers --------------------------------------------------------------------------------

class CheckFailure extends Error {}

function assert(cond, what) {
  if (!cond) throw new CheckFailure(what);
}

/** For public, non-secret values only (algorithm names, kids, indexes): shows both. */
function assertEq(actual, expected, what) {
  if (actual !== expected) throw new CheckFailure(`${what}: expected ${expected}, got ${actual}`);
}

/** For anything that may be secret or token content: says only that it differs. */
function assertSame(actual, expected, what) {
  assert(actual === expected, `${what} differs`);
}

function assertBytes(actual, expected, what) {
  assert(actual instanceof Uint8Array, `${what} is not a Uint8Array`);
  assert(actual.length === expected.length && actual.every((b, i) => b === expected[i]), `${what} differs`);
}

/** The check fails unless `code` is what `rejection` (an error code or null) says. */
function assertCode(rejection, code) {
  if (rejection !== code) throw new CheckFailure(`expected ${code}, got ${rejection ?? "success"}`);
}

const utf8 = (s) => new TextEncoder().encode(s);
const nowSec = () => Math.floor(Date.now() / 1000);

/** Changes one character in the middle of part `index` of a compact token. */
function tamper(token, index) {
  const parts = token.split(".");
  const p = parts[index];
  const i = Math.floor(p.length / 2);
  parts[index] = p.slice(0, i) + (p[i] === "A" ? "B" : "A") + p.slice(i + 1);
  return parts.join(".");
}

// --- the catalog, in CATALOG.md order -------------------------------------------------------

const JWS_ALGS = ["HS256", "RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"];
const PAYLOAD = utf8("polyjose example payload");
const ISSUER = "https://issuer.example";
const AUDIENCE = "https://api.example";

/** Claims with `iss`, `aud`, `sub` and an `exp` five minutes from now. */
function claims(exp = nowSec() + 300) {
  return { iss: ISSUER, aud: AUDIENCE, sub: "user-123", exp };
}

/** An ES256 key pair and a compact JWS it signed. */
async function es256Token() {
  const keys = await signingKeyPair("ES256");
  return { ...keys, token: await signCompact(PAYLOAD, keys.signKey, "ES256") };
}

const checks = [];
const check = (id, run) => checks.push({ id, run });

// JWS: sign and verify (sign-verify-jws.mjs)
for (const alg of JWS_ALGS) {
  check(`jws/sign-verify/${alg.toLowerCase()}`, async () => {
    const { signKey, verifyKey } = await signingKeyPair(alg);
    const token = await signCompact(PAYLOAD, signKey, alg);
    const verified = await verifyCompact(token, verifyKey, alg);
    assertEq(verified.alg, alg, "verified alg");
    assertBytes(verified.payload, PAYLOAD, "payload");
  });
}

check("jws/json/general-two-signers", async () => {
  const es = { ...(await signingKeyPair("ES256")), alg: "ES256" };
  const ed = { ...(await signingKeyPair("EdDSA")), alg: "EdDSA" };
  const jws = await signGeneral(PAYLOAD, [es, ed]);
  const byEs = await verifyJson(jws, es.verifyKey, "ES256");
  const byEd = await verifyJson(jws, ed.verifyKey, "EdDSA");
  assertEq(byEs.signatureIndex, 0, "ES256 signatureIndex");
  assertEq(byEd.signatureIndex, 1, "EdDSA signatureIndex");
  assertBytes(byEs.payload, PAYLOAD, "payload (ES256)");
  assertBytes(byEd.payload, PAYLOAD, "payload (EdDSA)");
});

// JWS: rejections (verify-allow-list.mjs)
check("jws/verify/rejects-alg-not-allowed", async () => {
  const { verifyKey, token } = await es256Token();
  assertCode(await jwsRejection(token, verifyKey, ["ES384"]), "AlgorithmNotAllowed");
});

check("jws/verify/rejects-none", async () => {
  // An Unsecured JWS (RFC 7515 Appendix A.5): header {"alg":"none"}, empty signature.
  const header = await base64urlEncode(utf8('{"alg":"none"}'));
  const token = `${header}.${await base64urlEncode(PAYLOAD)}.`;
  const { verifyKey } = await signingKeyPair("ES256");
  assertCode(await jwsRejection(token, verifyKey, ["ES256"]), "AlgorithmNotAllowed");
  assertCode(await jwsRejection(token, verifyKey, ["none"]), "AlgorithmNotAllowed");
  assertCode(await jwsRejection(token, verifyKey, ["ES256", "none"]), "AlgorithmNotAllowed");
});

check("jws/verify/rejects-tampered-payload", async () => {
  const { verifyKey, token } = await es256Token();
  assertCode(await jwsRejection(tamper(token, 1), verifyKey, ["ES256"]), "InvalidSignature");
});

check("jws/verify/rejects-wrong-key", async () => {
  const { token } = await es256Token();
  const other = await signingKeyPair("ES256");
  assertCode(await jwsRejection(token, other.verifyKey, ["ES256"]), "InvalidSignature");
});

check("jws/verify/rejects-key-family-mismatch", async () => {
  const hs = await signingKeyPair("HS256");
  const token = await signCompact(PAYLOAD, hs.signKey, "HS256");
  const ecPublic = await jwkToPublic(await jwkGenerateEc("P-256"));
  assertCode(await jwsRejection(token, ecPublic, ["HS256"]), "KeyAlgorithmMismatch");
});

// JWT: issue and validate (sign-verify-jwt.mjs)
for (const alg of JWS_ALGS) {
  check(`jwt/sign-verify/${alg.toLowerCase()}`, async () => {
    const { signKey, verifyKey } = await signingKeyPair(alg);
    const sent = claims();
    const token = await issueToken(sent, signKey, alg);
    const verified = await validateToken(token, verifyKey, { alg, issuer: ISSUER, audience: AUDIENCE });
    assertEq(verified.alg, alg, "verified alg");
    for (const name of ["iss", "aud", "sub", "exp"]) assertSame(verified.claims[name], sent[name], `claim ${name}`);
  });
}

// JWT: rejections (verify-allow-list.mjs)
check("jwt/verify/rejects-expired", async () => {
  const { signKey, verifyKey } = await signingKeyPair("ES256");
  const exp = nowSec() - 3600;
  const token = await issueToken(claims(exp), signKey, "ES256");
  const options = { allowedAlgs: ["ES256"], issuers: [ISSUER], audiences: [AUDIENCE], now: exp + 1, leeway: 0 };
  assertCode(await jwtRejection(token, verifyKey, options), "TokenExpired");
});

check("jwt/verify/rejects-wrong-audience", async () => {
  const { signKey, verifyKey } = await signingKeyPair("ES256");
  const token = await issueToken(claims(), signKey, "ES256");
  const options = { allowedAlgs: ["ES256"], issuers: [ISSUER], audiences: ["https://other-api.example"] };
  assertCode(await jwtRejection(token, verifyKey, options), "InvalidClaim");
});

check("jwt/verify/rejects-alg-not-allowed", async () => {
  const { signKey, verifyKey } = await signingKeyPair("ES256");
  const token = await issueToken(claims(), signKey, "ES256");
  const options = { allowedAlgs: ["ES384"], issuers: [ISSUER], audiences: [AUDIENCE] };
  assertCode(await jwtRejection(token, verifyKey, options), "AlgorithmNotAllowed");
});

check("jwt/verify-with-jwks/selects-by-kid", async () => {
  const first = await jwkGenerateForAlg("ES256");
  const second = await jwkGenerateForAlg("ES256");
  const jwks = await publicJwks([{ kid: "key-1", key: first }, { kid: "key-2", key: second }]);
  const token = await issueToken(claims(), { ...second, kid: "key-2" }, "ES256");
  const verified = await validateWithJwks(token, jwks, { allowedAlgs: ["ES256"], issuer: ISSUER, audience: AUDIENCE });
  assertEq(verified.kid, "key-2", "kid");
  assertEq(verified.keyIndex, 1, "keyIndex");
});

// JWE: encrypt and decrypt (encrypt-decrypt.mjs)
for (const crv of ["P-256", "P-384", "P-521", "X25519"]) {
  check(`jwe/ecdh-es-a256kw/${crv.toLowerCase()}`, async () => {
    const { privateKey, publicKey } = await recipientKeyPair(crv);
    const token = await encryptTo(PAYLOAD, publicKey);
    const decrypted = await decrypt(token, privateKey);
    assertBytes(decrypted.plaintext, PAYLOAD, "plaintext");
    assertEq(decrypted.header.alg, ALG, "header alg");
    assertEq(decrypted.header.enc, ENC, "header enc");
  });
}

check("jwe/decrypt/rejects-alg-not-allowed", async () => {
  const { privateKey, publicKey } = await recipientKeyPair("P-256");
  const token = await encryptTo(PAYLOAD, publicKey);
  assertCode(await rejectionCode(() => decrypt(token, privateKey, ["ECDH-ES+A128KW"], [ENC])), "AlgorithmNotAllowed");
});

check("jwe/decrypt/rejects-wrong-key", async () => {
  const { publicKey } = await recipientKeyPair("P-256");
  const other = await recipientKeyPair("P-256");
  const token = await encryptTo(PAYLOAD, publicKey);
  assertCode(await rejectionCode(() => decrypt(token, other.privateKey)), "DecryptionFailed");
});

// Keys and JWK Sets (keys-jwks.mjs)
check("jwk/generate/ec-p-256", async () => {
  const key = await generateEcKey("P-256");
  assertEq(key.kty, "EC", "kty");
  assertEq(key.crv, "P-256", "crv");
  assert(typeof key.d === "string", "the private key has no d");
  const pub = await publicKeyOf(key);
  assert(!Object.hasOwn(pub, "d"), "the public key still has d");
  assertSame(pub.x, key.x, "x");
  assertSame(pub.y, key.y, "y");
});

check("jwk/thumbprint/rfc7638", async () => {
  assertEq(await thumbprint(RFC7638_3_1.jwk), RFC7638_3_1.thumbprint, "thumbprint");
});

check("jwk/pem/round-trip", async () => {
  const key = await generateEcKey("P-256");
  const { pem, jwk } = await pemRoundTrip(key);
  assert(pem.startsWith("-----BEGIN PRIVATE KEY-----\n"), "not a PKCS#8 PEM");
  assertSame(jwk.d, key.d, "d");
  assertSame(await thumbprint(jwk), await thumbprint(key), "thumbprint");
});

check("jwks/select/by-kid", async () => {
  const jwks = await publicJwks([
    { kid: "key-1", key: await generateEcKey("P-256") },
    { kid: "key-2", key: await generateEcKey("P-256") },
  ]);
  const selected = await selectKey(jwks, { kid: "key-2" });
  assertEq(selected.kid, "key-2", "kid");
  assertSame(selected.x, jwks.keys[1].x, "x");
  assertCode(await rejectionCode(() => selectKey(jwks, { kid: "key-3" })), "NoMatchingKey");
});

// --- run ------------------------------------------------------------------------------------

/** Why a check failed. A polyjose error is shown by its stable code only. */
function describe(err) {
  if (err instanceof CheckFailure) return err.message;
  if (err instanceof PolyjoseError) return `unexpected ${err.code}`;
  return `unexpected ${err?.name ?? typeof err}: ${err?.message ?? String(err)}`;
}

/** The browser and its version, from the user agent string (for the information line). */
function browserName() {
  const ua = navigator.userAgent;
  const m = ua.match(/(Firefox|HeadlessChrome|Chrome)\/([\d.]+)/);
  if (m) return `${m[1]} ${m[2]}`;
  const safari = ua.match(/Version\/([\d.]+).*Safari/);
  return safari ? `Safari ${safari[1]}` : ua;
}

const result = document.getElementById("result");
result.textContent = "";
/** One output line: on the page and in the console. */
function out(line) {
  result.textContent += `${line}\n`;
  console.log(line);
}

out(`# polyjose ${await version()} through @polyjose/wasm, ${browserName()}`);
out(`# ${checks.length} checks`); // run.sh reports this count if the page stops before the end
let passed = 0;
for (const { id, run } of checks) {
  try {
    await run();
    passed += 1;
    out(`PASS ${id}`);
  } catch (err) {
    out(`FAIL ${id}: ${describe(err)}`);
  }
}
const ran = checks.length;
out(`POLYJOSE-VERIFY: ${passed}/${ran} PASS`);
