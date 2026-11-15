// Every check of CATALOG.md (at the root of this repository), in its order, through the example
// files. The ids and the order are the same on every platform.
import Foundation
import Polyjose

enum Catalog {
    static let jwsAlgs = ["HS256", "RS256", "PS256", "ES256", "ES384", "ES512", "EdDSA"]
    static let payload = utf8("polyjose example payload")
    static let issuer = "https://issuer.example"
    static let audience = "https://api.example"

    /// Claims with `iss`, `aud`, `sub` and an `exp` five minutes from now.
    static func claims(exp: Int64 = nowSeconds() + 300) -> [String: Any] {
        ["iss": issuer, "aud": audience, "sub": "user-123", "exp": exp]
    }

    /// An ES256 key pair and a compact JWS it signed.
    static func es256Token() throws -> (keys: SignVerifyJws.KeyPair, token: String) {
        let keys = try SignVerifyJws.signingKeyPair(alg: "ES256")
        return (keys, try SignVerifyJws.signCompact(payload, signKey: keys.signKey, alg: "ES256"))
    }

    static let checks: [Check] = {
        var checks: [Check] = []
        func check(_ id: String, _ run: @escaping @Sendable () throws -> Void) {
            checks.append(Check(id: id, run: run))
        }

        // JWS: sign and verify (SignVerifyJws.swift)
        for alg in jwsAlgs {
            check("jws/sign-verify/\(alg.lowercased())") {
                let keys = try SignVerifyJws.signingKeyPair(alg: alg)
                let token = try SignVerifyJws.signCompact(payload, signKey: keys.signKey, alg: alg)
                let verified = try SignVerifyJws.verifyCompact(token, verifyKey: keys.verifyKey, alg: alg)
                try expectEqual(verified.alg, alg, "verified alg")
                try expectSame(verified.payload, payload, "payload")
            }
        }

        check("jws/json/general-two-signers") {
            let es = try SignVerifyJws.signingKeyPair(alg: "ES256")
            let ed = try SignVerifyJws.signingKeyPair(alg: "EdDSA")
            let jws = try SignVerifyJws.signGeneral(payload, signers: [(es.signKey, "ES256"), (ed.signKey, "EdDSA")])
            let byEs = try SignVerifyJws.verifyJson(jws, verifyKey: es.verifyKey, alg: "ES256")
            let byEd = try SignVerifyJws.verifyJson(jws, verifyKey: ed.verifyKey, alg: "EdDSA")
            try expectEqual(byEs.signatureIndex, 0, "ES256 signatureIndex")
            try expectEqual(byEd.signatureIndex, 1, "EdDSA signatureIndex")
            try expectSame(byEs.payload, payload, "payload (ES256)")
            try expectSame(byEd.payload, payload, "payload (EdDSA)")
        }

        // JWS: rejections (VerifyAllowList.swift)
        check("jws/verify/rejects-alg-not-allowed") {
            let (keys, token) = try es256Token()
            try expectCode(VerifyAllowList.jwsRejection(token, verifyKey: keys.verifyKey, allowedAlgs: ["ES384"]), "AlgorithmNotAllowed")
        }

        check("jws/verify/rejects-none") {
            // An Unsecured JWS (RFC 7515 Appendix A.5): header {"alg":"none"}, empty signature.
            let token = base64urlEncode(data: utf8(#"{"alg":"none"}"#)) + "." + base64urlEncode(data: payload) + "."
            let keys = try SignVerifyJws.signingKeyPair(alg: "ES256")
            for allowed in [["ES256"], ["none"], ["ES256", "none"]] {
                try expectCode(VerifyAllowList.jwsRejection(token, verifyKey: keys.verifyKey, allowedAlgs: allowed), "AlgorithmNotAllowed")
            }
        }

        check("jws/verify/rejects-tampered-payload") {
            let (keys, token) = try es256Token()
            try expectCode(VerifyAllowList.jwsRejection(tamper(token, 1), verifyKey: keys.verifyKey, allowedAlgs: ["ES256"]), "InvalidSignature")
        }

        check("jws/verify/rejects-wrong-key") {
            let (_, token) = try es256Token()
            let other = try SignVerifyJws.signingKeyPair(alg: "ES256")
            try expectCode(VerifyAllowList.jwsRejection(token, verifyKey: other.verifyKey, allowedAlgs: ["ES256"]), "InvalidSignature")
        }

        check("jws/verify/rejects-key-family-mismatch") {
            let hs = try SignVerifyJws.signingKeyPair(alg: "HS256")
            let token = try SignVerifyJws.signCompact(payload, signKey: hs.signKey, alg: "HS256")
            let ecPublic = try jwkToPublic(jwk: jwkGenerateEc(crv: "P-256"))
            try expectCode(VerifyAllowList.jwsRejection(token, verifyKey: ecPublic, allowedAlgs: ["HS256"]), "KeyAlgorithmMismatch")
        }

        // JWT: issue and validate (SignVerifyJwt.swift)
        for alg in jwsAlgs {
            check("jwt/sign-verify/\(alg.lowercased())") {
                let keys = try SignVerifyJws.signingKeyPair(alg: alg)
                let sent = claims()
                let token = try SignVerifyJwt.issueToken(sent, signKey: keys.signKey, alg: alg)
                let verified = try SignVerifyJwt.validateToken(
                    token, verifyKey: keys.verifyKey, alg: alg, issuer: issuer, audience: audience)
                try expectEqual(verified.alg, alg, "verified alg")
                let received = try jsonObject(verified.claims)
                for name in ["iss", "aud", "sub"] {
                    try expectSame(stringMember(received, name), stringMember(sent, name), "claim \(name)")
                }
                try expectSame((received["exp"] as? NSNumber)?.int64Value, sent["exp"] as? Int64, "claim exp")
            }
        }

        // JWT: rejections (VerifyAllowList.swift)
        check("jwt/verify/rejects-expired") {
            let keys = try SignVerifyJws.signingKeyPair(alg: "ES256")
            let exp = nowSeconds() - 3600
            let token = try SignVerifyJwt.issueToken(claims(exp: exp), signKey: keys.signKey, alg: "ES256")
            let options = JwtVerifyOptions(
                allowedAlgs: ["ES256"], now: exp + 1, issuers: [issuer], audiences: [audience], leeway: 0)
            try expectCode(VerifyAllowList.jwtRejection(token, verifyKey: keys.verifyKey, options: options), "TokenExpired")
        }

        check("jwt/verify/rejects-wrong-audience") {
            let keys = try SignVerifyJws.signingKeyPair(alg: "ES256")
            let token = try SignVerifyJwt.issueToken(claims(), signKey: keys.signKey, alg: "ES256")
            let options = JwtVerifyOptions(allowedAlgs: ["ES256"], issuers: [issuer], audiences: ["https://other-api.example"])
            try expectCode(VerifyAllowList.jwtRejection(token, verifyKey: keys.verifyKey, options: options), "InvalidClaim")
        }

        check("jwt/verify/rejects-alg-not-allowed") {
            let keys = try SignVerifyJws.signingKeyPair(alg: "ES256")
            let token = try SignVerifyJwt.issueToken(claims(), signKey: keys.signKey, alg: "ES256")
            let options = JwtVerifyOptions(allowedAlgs: ["ES384"], issuers: [issuer], audiences: [audience])
            try expectCode(VerifyAllowList.jwtRejection(token, verifyKey: keys.verifyKey, options: options), "AlgorithmNotAllowed")
        }

        check("jwt/verify-with-jwks/selects-by-kid") {
            let first = try jwkGenerateForAlg(alg: "ES256")
            let second = try jwkGenerateForAlg(alg: "ES256")
            let jwks = try KeysJwks.publicJwks([("key-1", first), ("key-2", second)])
            let token = try SignVerifyJwt.issueToken(claims(), signKey: withKid(second, "key-2"), alg: "ES256")
            let verified = try SignVerifyJwt.validateWithJwks(
                token, jwks: jwks, allowedAlgs: ["ES256"], issuer: issuer, audience: audience)
            try expectEqual(verified.kid, "key-2", "kid")
            try expectEqual(verified.keyIndex, 1, "keyIndex")
        }

        // JWE: encrypt and decrypt (EncryptDecrypt.swift)
        for crv in ["P-256", "P-384", "P-521", "X25519"] {
            check("jwe/ecdh-es-a256kw/\(crv.lowercased())") {
                let keys = try EncryptDecrypt.recipientKeyPair(crv: crv)
                let token = try EncryptDecrypt.encryptTo(payload, recipientPublicKey: keys.publicKey)
                let decrypted = try EncryptDecrypt.decrypt(token, privateKey: keys.privateKey)
                try expectSame(decrypted.plaintext, payload, "plaintext")
                let header = try jsonObject(decrypted.header)
                try expectEqual(stringMember(header, "alg"), EncryptDecrypt.alg, "header alg")
                try expectEqual(stringMember(header, "enc"), EncryptDecrypt.enc, "header enc")
            }
        }

        check("jwe/decrypt/rejects-alg-not-allowed") {
            let keys = try EncryptDecrypt.recipientKeyPair(crv: "P-256")
            let token = try EncryptDecrypt.encryptTo(payload, recipientPublicKey: keys.publicKey)
            try expectCode(VerifyAllowList.rejectionCode {
                _ = try EncryptDecrypt.decrypt(
                    token, privateKey: keys.privateKey, allowedAlgs: ["ECDH-ES+A128KW"], allowedEnc: [EncryptDecrypt.enc])
            }, "AlgorithmNotAllowed")
        }

        check("jwe/decrypt/rejects-wrong-key") {
            let keys = try EncryptDecrypt.recipientKeyPair(crv: "P-256")
            let other = try EncryptDecrypt.recipientKeyPair(crv: "P-256")
            let token = try EncryptDecrypt.encryptTo(payload, recipientPublicKey: keys.publicKey)
            try expectCode(VerifyAllowList.rejectionCode {
                _ = try EncryptDecrypt.decrypt(token, privateKey: other.privateKey)
            }, "DecryptionFailed")
        }

        // Keys and JWK Sets (KeysJwks.swift)
        check("jwk/generate/ec-p-256") {
            let privateJwk = try KeysJwks.generateEcKey(crv: "P-256")
            let key = try jsonObject(privateJwk)
            try expectEqual(stringMember(key, "kty"), "EC", "kty")
            try expectEqual(stringMember(key, "crv"), "P-256", "crv")
            try expect(stringMember(key, "d") != nil, "the private key has no d")
            let pub = try jsonObject(KeysJwks.publicKeyOf(privateJwk))
            try expect(pub["d"] == nil, "the public key still has d")
            try expectSame(stringMember(pub, "x"), stringMember(key, "x"), "x")
            try expectSame(stringMember(pub, "y"), stringMember(key, "y"), "y")
        }

        check("jwk/thumbprint/rfc7638") {
            try expectEqual(
                KeysJwks.thumbprint(TestKeys.Rfc7638Section3_1.jwk), TestKeys.Rfc7638Section3_1.thumbprint, "thumbprint")
        }

        check("jwk/pem/round-trip") {
            let key = try KeysJwks.generateEcKey(crv: "P-256")
            let (pem, jwk) = try KeysJwks.pemRoundTrip(key)
            try expect(pem.hasPrefix("-----BEGIN PRIVATE KEY-----\n"), "not a PKCS#8 PEM")
            try expectSame(stringMember(jsonObject(jwk), "d"), stringMember(jsonObject(key), "d"), "d")
            try expectSame(KeysJwks.thumbprint(jwk), KeysJwks.thumbprint(key), "thumbprint")
        }

        check("jwks/select/by-kid") {
            let jwks = try KeysJwks.publicJwks([
                ("key-1", KeysJwks.generateEcKey(crv: "P-256")),
                ("key-2", KeysJwks.generateEcKey(crv: "P-256")),
            ])
            let selected = try jsonObject(KeysJwks.selectKey(jwks, selector: JwkSelector(kid: "key-2")))
            let second = (try jsonObject(jwks)["keys"] as? [[String: Any]])?.last ?? [:]
            try expectEqual(stringMember(selected, "kid"), "key-2", "kid")
            try expectSame(stringMember(selected, "x"), stringMember(second, "x"), "x")
            try expectCode(VerifyAllowList.rejectionCode {
                _ = try KeysJwks.selectKey(jwks, selector: JwkSelector(kid: "key-3"))
            }, "NoMatchingKey")
        }

        return checks
    }()
}
