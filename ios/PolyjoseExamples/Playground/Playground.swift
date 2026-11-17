// The playground's actions: sign, verify, encrypt, decrypt, the failure actions and the key
// actions. The tab buttons and the demo walk call these same functions. Each one is a tap: it
// logs every step through `Tap` and returns the tap's result card.
//
// Every polyjose and key store call runs in `offMain` (a `Task.detached`); this type only logs and
// keeps state on the main actor. Verify and decrypt always pass an explicit allow-list
// (RFC 8725 §3.1), never one read from the token.
import Foundation
import Polyjose

/// Which key an action uses.
enum KeyChoice: Hashable, Sendable {
    case new
    case platform(tag: String)
    case software(id: String)
}

/// A key as an action asks for it.
struct KeySpec: Sendable {
    var store: Store = .software
    /// The JWS `alg`, or the JWE `alg`.
    var alg: String = "ES256"
    var crv = "P-256"
    var size = 2048
    var access = AccessOption.none
    var sharedContext = false
    var choice = KeyChoice.new

    /// The algorithm a platform key is bound to: `ECDH-ES` for the whole ECDH-ES family (it
    /// serves the four, RFC 7518 §4.6).
    var keyAlgorithm: String { Matrix.isEcdh(alg) ? "ECDH-ES" : alg }
    /// `keySizeInBits` for `AppleKey.generate`: the curve of an ECDH-ES key, the RSA size.
    var keySizeInBits: Int? { Matrix.isEcdh(alg) ? Matrix.curveBits(crv) : Matrix.isRsa(alg) ? size : nil }
}

/// A key ready to use.
enum UsableKey: Sendable {
    case software(SoftwareKey)
    case platform(tag: String, store: Store, key: AppleKey, publicJwk: String)

    /// What verifies or encrypts: the public JWK, or an `oct` key's secret (passed to polyjose only).
    var verifyOrEncryptKey: String {
        switch self {
        case .software(let key): return key.verifyOrEncryptKey
        case .platform(_, _, _, let jwk): return jwk
        }
    }
}

enum SignAction: Equatable, Sendable {
    case sign, verify, signAndVerify
    case failure(Failure)
}

enum EncryptAction: Equatable, Sendable {
    case encrypt, decrypt, roundTrip
    case failure(Failure)
}

@MainActor
final class Playground: ObservableObject {
    let log = PlaygroundLog()
    @Published private(set) var device: DeviceInfo?
    @Published private(set) var platformKeys: [ListedKey] = []
    @Published private(set) var softwareKeys: [SoftwareKey] = []
    @Published private(set) var busy = false
    /// The authentication of keys created in this run: iOS doesn't report a key's access flags
    /// in its attributes.
    @Published private(set) var knownAccess: [String: AccessOption] = [:]
    @Published private(set) var lastSigned: (token: String, verifyKey: String, alg: String, jwt: Bool, store: Store)?
    @Published private(set) var lastEncrypted: (token: String, key: UsableKey, alg: String, enc: String)?
    /// Every tag created in this run, in order (the demo walk deletes the ones it made).
    private(set) var createdTags: [String] = []
    private var nextSoftware = 1
    private var shared: SharedContext?

    var capabilities: DeviceCapabilities {
        device?.capabilities ?? DeviceCapabilities(secureEnclave: PlatformKeysSecureEnclave.isAvailable, passcodeSet: false, simulator: false)
    }

    /// Reads the device, logs tap 0 and lists the keys.
    func start() async {
        if let starting { return await starting.value }
        let task = Task { await readDevice() }
        starting = task
        await task.value
    }

    private var starting: Task<Void, Never>?

    private func readDevice() async {
        let info = await offMain { DeviceInfo.read() }
        guard case .success(let device) = info.result else { return }
        self.device = device
        log.device(.device(
            polyjose: device.polyjose, os: device.os, model: device.model, simulator: device.simulator,
            secureEnclave: device.secureEnclave, lockScreen: device.passcodeSet))
        await refreshKeys()
    }

    func refreshKeys() async {
        if case .success(let keys) = await offMain({ try KeyListing.list() }).result { platformKeys = keys }
    }

    // MARK: - Sign

    func sign(_ spec: KeySpec, jwt jwtChosen: Bool, _ action: SignAction, anyway: Bool = false) async -> Card {
        busy = true
        defer { busy = false }
        let failure: Failure? = if case .failure(let f) = action { f } else { nil }
        let jwt = jwtChosen || failure == .signExpired
        let op: Op = switch action {
        case .sign: jwt ? .jwtSign : .jwsSign
        case .verify: jwt ? .jwtVerify : .jwsVerify
        default: jwt ? .jwtSignVerify : .jwsSignVerify
        }
        let verb = failure?.title ?? (action == .sign ? "Sign" : action == .verify ? "Verify" : "Sign and verify")
        let tap = log.begin("\(verb) \(jwt ? "JWT" : "JWS") \(spec.alg) · \(spec.store.title)")
        tap.log(.input(input(op, spec, failure: failure, anyway: anyway, payload: jwt ? "jwt-claims" : "jws-text")))

        if action == .verify {
            guard let last = lastSigned else { tap.log(.note("tab.sign")); return tap.card }
            await verify(tap, last.token, key: last.verifyKey, allowed: [last.alg], jwt: last.jwt)
            return tap.card
        }
        if failure == .signDeletedKey {
            await deletedKey(tap, spec)
            return tap.card
        }
        guard let key = await acquire(tap, spec, signing: true, enc: Matrix.defaultEnc) else { return tap.card }
        guard let token = await signToken(tap, key, spec, jwt: jwt, expired: failure == .signExpired) else { return tap.card }
        lastSigned = (token, key.verifyOrEncryptKey, spec.alg, jwt, spec.store)

        switch failure {
        case nil:
            if action == .signAndVerify { await verify(tap, token, key: key.verifyOrEncryptKey, allowed: [spec.alg], jwt: jwt) }
        case .signExpired:
            await verify(tap, token, key: key.verifyOrEncryptKey, allowed: [spec.alg], jwt: true, leeway: 0)
        case .signTamper:
            let changed = tampered(token, part: 1)
            tap.log(.tamper(part: "payload", index: changed.index))
            tap.log(.token(changed.token))
            await verify(tap, changed.token, key: key.verifyOrEncryptKey, allowed: [spec.alg], jwt: jwt)
        case .signOtherAlg:
            await verify(tap, token, key: key.verifyOrEncryptKey, allowed: [Matrix.otherAlg(spec.alg)], jwt: jwt)
        case .signWrongKey:
            guard let other = await otherVerifyKey(tap, alg: spec.alg) else { return tap.card }
            await verify(tap, token, key: other, allowed: [spec.alg], jwt: jwt)
        default:
            break
        }
        return tap.card
    }

    private func signToken(_ tap: Tap, _ key: UsableKey, _ spec: KeySpec, jwt: Bool, expired: Bool) async -> String? {
        let alg = spec.alg
        let function: String
        let made: Timed<(String, String)>
        switch key {
        case .software(let software):
            function = jwt ? "jwtSign" : "jwsSignCompact"
            made = await offMain {
                let token = jwt
                    ? try SignVerifyJwt.issueToken(demoClaims(expired: expired), signKey: software.secretJwk, alg: alg)
                    : try SignVerifyJws.signCompact(Data(demoPayload.utf8), signKey: software.secretJwk, alg: alg)
                return (token, try protectedHeader(of: token))
            }
        case let .platform(_, store, appleKey, _):
            function = jwt ? "jwtSignWithPlatformKey" : "jwsSignCompactWithPlatformKey"
            made = await offMain {
                let token = jwt
                    ? try PlatformStore.signJwt(store, demoClaims(expired: expired), key: appleKey, alg: alg)
                    : try PlatformStore.signJws(store, Data(demoPayload.utf8), key: appleKey, alg: alg)
                return (token, try protectedHeader(of: token))
            }
        }
        switch made.result {
        case .success(let (token, header)):
            tap.log(.call(function, ms: made.ms))
            tap.log(.header(publicOnly(header)))
            tap.log(.token(token))
            return token
        case .failure(let error):
            tap.log(.error(ErrorCode(error), ms: made.ms))
            return nil
        }
    }

    /// Verifies in software with `allowed` (RFC 7515 §5.2; RFC 7519 §7.2 with `iss` and `aud`).
    private func verify(_ tap: Tap, _ token: String, key: String, allowed: [String], jwt: Bool, leeway: UInt32? = nil) async {
        let checked = await offMain { () -> (alg: String, kid: String?, claims: String?) in
            if jwt {
                let verified = try jwtVerify(
                    token: token, key: key,
                    options: JwtVerifyOptions(allowedAlgs: allowed, issuers: [demoIssuer], audiences: [demoAudience], leeway: leeway))
                return (verified.alg, verified.kid, verified.claims)
            }
            let verified = try jwsVerifyCompact(token: token, key: key, options: JwsVerifyOptions(allowedAlgs: allowed))
            let kid = (try? playgroundObject(verified.protectedHeader ?? "{}"))?["kid"] as? String
            return (verified.alg, kid, nil)
        }
        switch checked.result {
        case .success(let verified):
            tap.log(.verify(alg: verified.alg, kid: verified.kid, ms: checked.ms))
            if let claims = verified.claims { tap.log(.claims(publicOnly(claims))) }
        case .failure(let error):
            tap.log(.error(ErrorCode(error), ms: checked.ms))
        }
    }

    /// The verifying key of another key of the same algorithm (`failure.sign.wrong-key`): a new
    /// software secret for HS*, a new software key pair's public JWK for ES* and EdDSA, and for a
    /// platform RSA key the RFC 7515 A.2 test key's public JWK.
    private func otherVerifyKey(_ tap: Tap, alg: String) async -> String? {
        let kid = "playground-\(alg)-other"
        let made = await offMain { () -> (String, SoftwareKeySummary) in
            if Matrix.isRsa(alg) {
                let jwk = try jwkToPublic(jwk: TestKeys.rfc7515A2RsaPrivateJwk)
                return (jwk, SoftwareKeySummary(kty: "RSA", alg: alg, kid: "-", bits: nil, testKey: true))
            }
            let key = try SoftwareKeys.signing(alg: alg, kid: kid)
            return (key.verifyOrEncryptKey, key.summary)
        }
        switch made.result {
        case .success(let (jwk, summary)):
            tap.log(.keySoftware(summary))
            if summary.testKey { tap.log(.note("key.test-rsa")) }
            if !alg.hasPrefix("HS") { tap.log(.jwk(publicOnly(jwk))) }
            return jwk
        case .failure(let error):
            tap.log(.error(ErrorCode(error), ms: made.ms))
            return nil
        }
    }

    // MARK: - Encrypt

    func encrypt(_ spec: KeySpec, enc: String, _ action: EncryptAction, anyway: Bool = false) async -> Card {
        busy = true
        defer { busy = false }
        let failure: Failure? = if case .failure(let f) = action { f } else { nil }
        let op: Op = action == .encrypt ? .jweEncrypt : action == .decrypt ? .jweDecrypt : .jweRoundTrip
        let verb = failure?.title ?? (action == .encrypt ? "Encrypt" : action == .decrypt ? "Decrypt" : "Round trip")
        let curve = Matrix.isEcdh(spec.alg) ? " \(spec.crv)" : ""
        let tap = log.begin("\(verb) \(spec.alg) \(enc)\(curve) · \(spec.store.title)")
        var entry = input(op, spec, failure: failure, anyway: anyway, payload: "jwe-text")
        entry.enc = enc
        tap.log(.input(entry))

        if action == .decrypt {
            guard let last = lastEncrypted else { tap.log(.note("tab.encrypt")); return tap.card }
            await decrypt(tap, last.token, with: last.key, alg: last.alg, enc: last.enc, allowedAlgs: [last.alg])
            return tap.card
        }
        if failure == .encryptDeletedKey {
            await deletedKey(tap, spec)
            return tap.card
        }
        guard let key = await acquire(tap, spec, signing: false, enc: enc) else { return tap.card }
        let alg = spec.alg
        let recipient = key.verifyOrEncryptKey
        let made = await offMain { () -> (String, String) in
            let token = try jweEncryptCompact(
                plaintext: Data(demoPayload.utf8),
                options: JweEncryptOptions(enc: enc, recipients: [JweRecipient(alg: alg, key: recipient)]))
            return (token, try protectedHeader(of: token))
        }
        guard case .success(let (token, header)) = made.result else {
            if case .failure(let error) = made.result { tap.log(.error(ErrorCode(error), ms: made.ms)) }
            return tap.card
        }
        tap.log(.call("jweEncryptCompact", ms: made.ms))
        tap.log(.header(publicOnly(header)))
        tap.log(.token(token))
        lastEncrypted = (token, key, alg, enc)

        switch failure {
        case nil:
            if action == .roundTrip { await decrypt(tap, token, with: key, alg: alg, enc: enc, allowedAlgs: [alg]) }
        case .encryptTamper:
            let changed = tampered(token, part: 3)
            tap.log(.tamper(part: "ciphertext", index: changed.index))
            tap.log(.token(changed.token))
            await decrypt(tap, changed.token, with: key, alg: alg, enc: enc, allowedAlgs: [alg])
        case .encryptOtherAlg:
            await decrypt(tap, token, with: key, alg: alg, enc: enc, allowedAlgs: [Matrix.otherAlg(alg)])
        case .encryptWrongKey:
            var other = spec
            other.choice = .new
            guard let otherKey = await acquire(tap, other, signing: false, enc: enc, keep: false) else { return tap.card }
            await decrypt(tap, token, with: otherKey, alg: alg, enc: enc, allowedAlgs: [alg])
            if case .platform(let tag, let store, _, _) = otherKey { await delete(tap, tag: tag, store: store) }
        default:
            break
        }
        return tap.card
    }

    /// Decrypts with `allowedAlgs` and `[enc]` (RFC 7516 §5.2), and compares the plaintext.
    private func decrypt(_ tap: Tap, _ token: String, with key: UsableKey, alg: String, enc: String, allowedAlgs: [String]) async {
        let done: Timed<Data>
        switch key {
        case .software(let software):
            done = await offMain {
                try EncryptDecrypt.decrypt(token, privateKey: software.secretJwk, allowedAlgs: allowedAlgs, allowedEnc: [enc]).plaintext
            }
        case let .platform(_, store, appleKey, _):
            done = await offMain {
                try PlatformStore.decrypt(store, token, key: appleKey, allowedAlgs: allowedAlgs, allowedEnc: [enc]).plaintext
            }
        }
        switch done.result {
        case .success(let plaintext): tap.log(.decrypt(alg: alg, enc: enc, equal: plaintext == Data(demoPayload.utf8), ms: done.ms))
        case .failure(let error): tap.log(.error(ErrorCode(error), ms: done.ms))
        }
    }

    // MARK: - Keys

    /// Makes a new key or opens the chosen one, and logs it. `keep: false` makes a software key
    /// that isn't added to the Keys tab (the "other key" of a failure action).
    private func acquire(_ tap: Tap, _ spec: KeySpec, signing: Bool, enc: String, keep: Bool = true) async -> UsableKey? {
        if spec.store == .software {
            if case .software(let id) = spec.choice, let key = softwareKeys.first(where: { $0.id == id }) {
                logSoftware(tap, key)
                return .software(key)
            }
            let kid = "playground-\(spec.alg)-\(nextSoftware)"
            nextSoftware += 1
            let alg = spec.alg, crv = spec.crv
            let made = await offMain {
                signing ? try SoftwareKeys.signing(alg: alg, kid: kid) : try SoftwareKeys.decryption(alg: alg, crv: crv, enc: enc, kid: kid)
            }
            switch made.result {
            case .success(let key):
                if keep { softwareKeys.append(key) }
                logSoftware(tap, key)
                return .software(key)
            case .failure(let error):
                tap.log(.error(ErrorCode(error), ms: made.ms))
                return nil
            }
        }

        let store = spec.store, algorithm = spec.keyAlgorithm, size = spec.keySizeInBits
        let shared = spec.sharedContext && spec.access != .none ? sharedContext() : nil
        if case .platform(let tag) = spec.choice {
            let opened = await offMain { () -> (AppleKey, String) in
                let key = try PlatformStore.open(store, tag: tag, algorithm: algorithm, shared: shared)
                return (key, try key.publicJwk())
            }
            switch opened.result {
            case .success(let (key, jwk)):
                tap.log(.keyOpen(tag: tag, reported: PlatformStore.whereItLives(store, key), ms: opened.ms))
                tap.log(.jwk(publicOnly(jwk)))
                return .platform(tag: tag, store: store, key: key, publicJwk: jwk)
            case .failure(let error):
                tap.log(.error(ErrorCode(error), ms: opened.ms))
                return nil
            }
        }

        await refreshKeys()
        let tag = KeyListing.nextTag(algorithm, existing: platformKeys)
        let access = AccessChoice(option: spec.access, shared: shared)
        let created = await offMain { () -> (AppleKey, String) in
            let key = try PlatformStore.create(store, tag: tag, algorithm: algorithm, keySizeInBits: size, access: access)
            return (key, try key.publicJwk())
        }
        // A refused create leaves no key, but record the tag anyway so the walk checks it.
        createdTags.append(tag)
        switch created.result {
        case .success(let (key, jwk)):
            knownAccess[tag] = spec.access
            tap.log(.keyCreate(tag: tag, reported: PlatformStore.whereItLives(store, key), ms: created.ms))
            tap.log(.jwk(publicOnly(jwk)))
            await refreshKeys()
            return .platform(tag: tag, store: store, key: key, publicJwk: jwk)
        case .failure(let error):
            tap.log(.error(ErrorCode(error), ms: created.ms))
            return nil
        }
    }

    private func logSoftware(_ tap: Tap, _ key: SoftwareKey) {
        tap.log(.keySoftware(key.summary))
        if key.summary.testKey { tap.log(.note("key.test-rsa")) }
        if let jwk = key.publicJwk { tap.log(.jwk(publicOnly(jwk))) }
    }

    /// `failure.*.deleted-key`: creates a key, deletes it, opens it again by its tag.
    private func deletedKey(_ tap: Tap, _ spec: KeySpec) async {
        var fresh = spec
        fresh.choice = .new
        guard case .platform(let tag, let store, _, _)? = await acquire(tap, fresh, signing: true, enc: Matrix.defaultEnc) else {
            if spec.store == .software { tap.log(.note("reason.software-not-stored")) }
            return
        }
        guard await delete(tap, tag: tag, store: store) else { return }
        let algorithm = spec.keyAlgorithm
        let opened = await offMain { _ = try PlatformStore.open(store, tag: tag, algorithm: algorithm, shared: nil) }
        switch opened.result {
        case .success: tap.log(.keyOpen(tag: tag, reported: store == .secureEnclave ? .secureEnclave : .keychain, ms: opened.ms))
        case .failure(let error): tap.log(.error(ErrorCode(error), ms: opened.ms))
        }
    }

    @discardableResult
    private func delete(_ tap: Tap, tag: String, store: Store) async -> Bool {
        let deleted = await offMain { try PlatformStore.delete(store, tag: tag) }
        knownAccess[tag] = nil
        switch deleted.result {
        case .success:
            tap.log(.keyDelete(tag: tag, ms: deleted.ms))
            await refreshKeys()
            return true
        case .failure(let error):
            tap.log(.error(ErrorCode(error), ms: deleted.ms))
            return false
        }
    }

    /// Keys tab, **Create key**: a signing key, or a decryption key for the JWE `alg`.
    func createKey(_ spec: KeySpec, anyway: Bool = false) async -> Card {
        busy = true
        defer { busy = false }
        let tap = log.begin("Create key \(spec.alg) · \(spec.store.title)")
        tap.log(.input(input(.keyCreate, spec, failure: nil, anyway: anyway, payload: nil)))
        var fresh = spec
        fresh.choice = .new
        _ = await acquire(tap, fresh, signing: Matrix.signingAlgs.contains(spec.alg), enc: Matrix.defaultEnc)
        return tap.card
    }

    /// Keys tab, **Open again**: opens the key by its tag and shows its public JWK and thumbprint.
    func openAgain(_ listed: ListedKey) async -> (card: Card, thumbprint: String?) {
        busy = true
        defer { busy = false }
        let tap = log.begin("Open key \(listed.algorithm) · \(listed.store.title)")
        tap.log(.input(Input(op: .keyOpen, store: listed.store, alg: listed.algorithm)))
        let spec = KeySpec(store: listed.store, alg: listed.algorithm, choice: .platform(tag: listed.tag))
        guard let key = await acquire(tap, spec, signing: true, enc: Matrix.defaultEnc) else { return (tap.card, nil) }
        return (tap.card, await thumbprint(tap, key.verifyOrEncryptKey))
    }

    /// The RFC 7638 thumbprint of a public JWK (never of an `oct` key: RFC 7638 §7).
    func thumbprint(of key: SoftwareKey) async -> (card: Card, thumbprint: String?) {
        let tap = log.begin("Thumbprint \(key.alg) · Software")
        tap.log(.keySoftware(key.summary))
        guard let jwk = key.publicJwk else { tap.log(.note("reason.symmetric")); return (tap.card, nil) }
        tap.log(.jwk(publicOnly(jwk)))
        return (tap.card, await thumbprint(tap, jwk))
    }

    private func thumbprint(_ tap: Tap, _ publicJwk: String) async -> String? {
        let done = await offMain { try jwkThumbprint(jwk: publicJwk) }
        switch done.result {
        case .success(let value):
            tap.log(.call("jwkThumbprint", ms: done.ms))
            tap.log(.thumbprint(value))
            return value
        case .failure(let error):
            tap.log(.error(ErrorCode(error), ms: done.ms))
            return nil
        }
    }

    /// Logs that a public JWK was copied.
    func copied(_ publicJwk: String, title: String) {
        let tap = log.begin("Copy public JWK · \(title)")
        tap.log(.jwk(publicOnly(publicJwk)))
    }

    func deleteKey(_ listed: ListedKey) async -> Card {
        busy = true
        defer { busy = false }
        let tap = log.begin("Delete key \(listed.algorithm) · \(listed.store.title)")
        tap.log(.input(Input(op: .keyDelete, store: listed.store, alg: listed.algorithm)))
        await delete(tap, tag: listed.tag, store: listed.store)
        return tap.card
    }

    /// Deletes a key the playground created by its tag (the demo walk's clean-up).
    func deleteTag(_ tag: String) async -> Card {
        let tap = log.begin("Delete key · \(tag)")
        tap.log(.input(Input(op: .keyDelete, store: nil, alg: nil)))
        await delete(tap, tag: tag, store: .keychain)
        return tap.card
    }

    func deleteSoftware(_ key: SoftwareKey) {
        let tap = log.begin("Delete key \(key.alg) · Software")
        tap.log(.input(Input(op: .keyDelete, store: .software, alg: key.alg)))
        tap.log(.keySoftware(key.summary))
        softwareKeys.removeAll { $0.id == key.id }
    }

    /// **Delete all playground keys**: every key under the playground prefix, and the software keys.
    func deleteAll() async -> Card {
        busy = true
        defer { busy = false }
        let tap = log.begin("Delete all playground keys")
        tap.log(.input(Input(op: .keyDeleteAll, store: nil, alg: nil)))
        await refreshKeys()
        for key in platformKeys { await delete(tap, tag: key.tag, store: key.store) }
        softwareKeys = []
        lastSigned = nil
        lastEncrypted = nil
        return tap.card
    }

    // MARK: - For the demo walk

    var createdTagCount: Int { createdTags.count }
    var lastCreatedTag: String? { createdTags.last }
    func createdTags(since index: Int) -> [String] { Array(createdTags[index...]) }

    /// Passes a private EC JWK, a symmetric `oct` JWK and a public JWK through the public-only gate
    /// and logs what it lets through: `true` when it withholds the first two and shows the third.
    func secretsGateWithholds() async -> Bool {
        let tap = log.begin("Secrets gate")
        let keys = await offMain { () -> (String, String, String) in
            let ec = try jwkGenerateEc(crv: "P-256")
            return (ec, try jwkGenerateOct(lenBytes: 32), try jwkToPublic(jwk: ec))
        }
        guard case .success(let (ec, oct, ecPublic)) = keys.result else { return false }
        let gated = [publicOnly(ec), publicOnly(oct), publicOnly(ecPublic)]
        gated.forEach { tap.log(.jwk($0)) }
        return gated[0].text == "[withheld]" && gated[1].text == "[withheld]" && gated[2].text.contains("\"x\"")
    }

    /// The one shared `LAContext`, made on first use.
    private func sharedContext() -> SharedContext {
        if let shared { return shared }
        let made = SharedContext()
        shared = made
        return made
    }

    private func input(_ op: Op, _ spec: KeySpec, failure: Failure?, anyway: Bool, payload: String?) -> Input {
        Input(
            op: op, store: spec.store, alg: spec.alg,
            crv: Matrix.isEcdh(spec.alg) ? spec.crv : nil,
            size: spec.store.isPlatform && Matrix.isRsa(spec.alg) ? spec.size : nil,
            auth: spec.store.isPlatform ? spec.access : nil,
            payload: payload, failure: failure, anyway: anyway)
    }
}
