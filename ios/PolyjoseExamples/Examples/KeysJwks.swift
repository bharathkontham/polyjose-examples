// How do I create keys, export them, and pick one from a JWK Set?
//
// Keys are JWKs (RFC 7517), passed and returned as JSON text. A private JWK holds secret
// members (`d` for EC, OKP and RSA, `k` for oct): never log it, and call `jwkToPublic` before
// you publish or send one.
import Foundation
import Polyjose

enum KeysJwks {
    /// A random EC private key (RFC 7518 §6.2) on P-256, P-384 or P-521, from the OS CSPRNG.
    static func generateEcKey(crv: String = "P-256") throws -> String {
        try jwkGenerateEc(crv: crv)
    }

    /// The public half of a key (RFC 7517 §4, RFC 7518 §6.2.1): the private members are removed.
    static func publicKeyOf(_ privateJwk: String) throws -> String {
        try jwkToPublic(jwk: privateJwk)
    }

    /// The JWK Thumbprint (RFC 7638 §3), SHA-256, base64url: a stable identifier of a key's public
    /// members, and a good `kid`. Do not publish the thumbprint of a secret `oct` key: it is an
    /// unsalted hash of the secret (RFC 7638 §7).
    static func thumbprint(_ jwk: String) throws -> String {
        try jwkThumbprint(jwk: jwk)
    }

    /// Exports a private key as PKCS#8 PEM (RFC 5958, RFC 7468 §10, "PRIVATE KEY") and imports it
    /// back as a JWK. `jwkToPem` also takes "spki" for a public key (RFC 7468 §13).
    static func pemRoundTrip(_ privateJwk: String) throws -> (pem: String, jwk: String) {
        let pem = try jwkToPem(jwk: privateJwk, format: "pkcs8")
        return (pem, try jwkFromPem(pem: pem))
    }

    /// A public JWK Set (RFC 7517 §5) as JSON text, as a `jwks_uri` endpoint serves it: each key's
    /// public half, with its `kid` (RFC 7517 §4.5).
    static func publicJwks(_ entries: [(kid: String, key: String)]) throws -> String {
        var keys: [Any] = []
        for entry in entries {
            let publicJwk = try jwkToPublic(jwk: entry.key)
            guard var member = try JSONSerialization.jsonObject(with: Data(publicJwk.utf8)) as? [String: Any] else {
                throw CocoaError(.coderReadCorrupt)
            }
            member["kid"] = entry.kid
            keys.append(member)
        }
        return String(decoding: try JSONSerialization.data(withJSONObject: ["keys": keys]), as: UTF8.self)
    }

    /// The one key of a JWK Set that `selector` picks, by `kid`, `alg` and `keyUse` (each
    /// optional; RFC 7517 §4.2, §4.4, §4.5), as JWK JSON text. No match throws `NoMatchingKey`,
    /// more than one `MultipleMatchingKeys` (a set's order has no meaning, RFC 7517 §5).
    static func selectKey(_ jwks: String, selector: JwkSelector) throws -> String {
        try jwksSelect(jwks: jwks, selector: selector)
    }
}
