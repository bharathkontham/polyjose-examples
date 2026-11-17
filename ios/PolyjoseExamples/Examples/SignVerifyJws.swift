// How do I sign bytes and verify the signature (JWS)?
//
// A JWS (RFC 7515) signs any bytes. For claims about a user or a client, with an expiry, an
// issuer and an audience, use a JWT instead (SignVerifyJwt.swift).
//
// Verification always takes an explicit allow-list, `allowedAlgs`. Never build it from the
// token: whoever made the token chose its header (RFC 8725 §3.1). `alg: none` is never
// accepted, whatever the list says (RFC 8725 §3.2). See VerifyAllowList.swift for the rejections.
//
// Algorithms (RFC 7518 §3, RFC 8037 §3.1) and the keys they take:
//   HS256            a shared secret, `kty: oct`; the same key signs and verifies
//   RS256, PS256     an RSA key pair, 2048 bits or more
//   ES256/384/512    an EC key pair on P-256, P-384 or P-521
//   EdDSA            an Ed25519 key pair (`kty: OKP`)
//
// Keys, headers and claims are JSON text. polyjose calls are synchronous: in an app, run them
// off the main thread, for example in a `Task.detached`.
import Foundation
import Polyjose

enum SignVerifyJws {
    /// `signKey` signs, `verifyKey` verifies. Both are JWK JSON text; `signKey` is secret.
    struct KeyPair: Sendable {
        let signKey: String
        let verifyKey: String
    }

    /// A key pair for a JWS algorithm (RFC 7518 §3).
    /// - HS256: one random secret for both (RFC 7518 §3.2: at least as long as the hash).
    /// - RS256, PS256: polyjose 0.4.0 does not generate RSA keys, so this uses the RFC 7515 A.2
    ///   test key. In your app, load your own key, for example with `jwkFromPem(pem:)`.
    /// - ES256/384/512, EdDSA: `jwkGenerateForAlg` makes a key on the right curve, with `alg` set.
    static func signingKeyPair(alg: String) throws -> KeyPair {
        if alg.hasPrefix("HS") {
            let secret = try jwkGenerateForAlg(alg: alg)
            return KeyPair(signKey: secret, verifyKey: secret)
        }
        let signKey = try alg.hasPrefix("RS") || alg.hasPrefix("PS")
            ? TestKeys.rfc7515A2RsaPrivateJwk
            : jwkGenerateForAlg(alg: alg)
        return KeyPair(signKey: signKey, verifyKey: try jwkToPublic(jwk: signKey))
    }

    /// Signs `payload` in the JWS Compact Serialization, `header.payload.signature`
    /// (RFC 7515 §3.1, §7.1). The protected header carries `alg` (RFC 7515 §4.1.1).
    static func signCompact(_ payload: Data, signKey: String, alg: String) throws -> String {
        try jwsSignCompact(payload: payload, key: signKey, options: JwsSignOptions(protectedHeader: try header(alg)))
    }

    /// Verifies a compact JWS (RFC 7515 §5.2), accepting only `alg`. The result has `alg`,
    /// `payload` and `protectedHeader`. Throws a `PolyjoseError`: `AlgorithmNotAllowed`,
    /// `KeyAlgorithmMismatch`, `InvalidSignature`, ...
    static func verifyCompact(_ token: String, verifyKey: String, alg: String) throws -> JwsVerified {
        try jwsVerifyCompact(token: token, key: verifyKey, options: JwsVerifyOptions(allowedAlgs: [alg]))
    }

    /// The general JWS JSON Serialization (RFC 7515 §7.2.1): several signatures over one payload,
    /// for example an old and a new key during a key rollover. Returns the JSON text.
    static func signGeneral(_ payload: Data, signers: [(signKey: String, alg: String)]) throws -> String {
        let signers = try signers.map { JwsSigner(key: $0.signKey, protectedHeader: try header($0.alg)) }
        return try jwsSignGeneral(payload: payload, signers: signers, detached: false)
    }

    /// Verifies a JWS JSON Serialization (RFC 7515 §7.2, §5.2) with one key, accepting only `alg`.
    /// `signatureIndex` in the result says which signature verified.
    static func verifyJson(_ jws: String, verifyKey: String, alg: String) throws -> JwsVerified {
        try jwsVerifyJson(jws: jws, key: verifyKey, options: JwsVerifyOptions(allowedAlgs: [alg]))
    }

    /// The JWS Protected Header `{"alg": alg}` as JSON text (RFC 7515 §4.1.1).
    private static func header(_ alg: String) throws -> String {
        String(decoding: try JSONSerialization.data(withJSONObject: ["alg": alg]), as: UTF8.self)
    }
}
