// The playground log (PLAYGROUND.md at the root of this repository, "Log" and "Secrets").
//
//   LOG <tap>.<step> <event> key=value …
//   LOG 12.2 key-create tag=dev.polyjose.examples.playground.ES256.3 reported=secureEnclave ms=41
//
// Every step of every tap is one `LogEvent`: a typed value, never free text. A JSON value (a JWK, a
// header, claims) can only be logged as a `PublicJson`, which exists only through `publicOnly`. An
// error can only be logged as an `ErrorCode`: the `PolyjoseError` code (its case name) or the type
// name of any other error, never its `detail`, `localizedDescription` or platform text.
//
// Each line goes to the Log tab, to stdout (`print`) and to the system log (`os.Logger`, public),
// because `print` doesn't reach Console.app from an iPhone that isn't attached to Xcode. The same
// events fill the result card, so the card shows what the log says.
import Foundation
import os
import Polyjose

// MARK: - The secrets gate

/// The JWK members that are private or symmetric key material (RFC 7518 §6.2.2, §6.3.2, §6.4.1;
/// RFC 8037 §2).
let secretMembers: Set<String> = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]

/// JSON text that is safe to show: every object holding a private or symmetric member is replaced
/// by `"[withheld]"` (PLAYGROUND.md, "Secrets"). Text that isn't a JSON object or array is withheld
/// as a whole.
struct PublicJson: Sendable, CustomStringConvertible {
    let text: String
    var description: String { text }

    fileprivate init(gated text: String) { self.text = text }
}

/// The one public-only gate: every JWK, header or claims set passes it before it is shown or logged.
func publicOnly(_ json: String) -> PublicJson {
    guard let object = try? JSONSerialization.jsonObject(with: Data(json.utf8)), object is [String: Any] || object is [Any] else {
        return PublicJson(gated: "[withheld]")
    }
    let gated = withholdSecrets(object)
    // A top-level object with a secret member is now the string "[withheld]".
    if let text = gated as? String { return PublicJson(gated: text) }
    guard let data = try? JSONSerialization.data(withJSONObject: gated, options: [.withoutEscapingSlashes, .sortedKeys]) else {
        return PublicJson(gated: "[withheld]")
    }
    return PublicJson(gated: String(decoding: data, as: UTF8.self))
}

private func withholdSecrets(_ value: Any) -> Any {
    if let object = value as? [String: Any] {
        if object.keys.contains(where: secretMembers.contains) { return "[withheld]" }
        return object.mapValues(withholdSecrets)
    }
    if let array = value as? [Any] { return array.map(withholdSecrets) }
    return value
}

// MARK: - Typed fields

/// An error as its code only (PLAYGROUND.md, "Secrets").
struct ErrorCode: Sendable, Equatable, CustomStringConvertible {
    let code: String
    var description: String { code }

    init(_ error: any Error) {
        if let error = error as? PolyjoseError {
            code = error.code()
        } else {
            code = String(describing: type(of: error))
        }
    }
}

/// The `op` field.
enum Op: String, Sendable {
    case jwsSign = "jws-sign", jwsVerify = "jws-verify", jwsSignVerify = "jws-sign-verify"
    case jwtSign = "jwt-sign", jwtVerify = "jwt-verify", jwtSignVerify = "jwt-sign-verify"
    case jweEncrypt = "jwe-encrypt", jweDecrypt = "jwe-decrypt", jweRoundTrip = "jwe-round-trip"
    case keyCreate = "key-create", keyOpen = "key-open", keyDelete = "key-delete", keyDeleteAll = "key-delete-all"
}

/// The first line of every tap.
struct Input: Sendable {
    var op: Op
    var store: Store?
    var alg: String?
    var enc: String?
    var crv: String?
    var size: Int?
    var auth: AccessOption?
    var payload: String?
    var failure: Failure?
    var anyway = false
}

/// The software key summary: never the key, only what identifies it (PLAYGROUND.md: an `oct` key is
/// shown as `kty`, `alg`, `kid` and its length only).
struct SoftwareKeySummary: Sendable {
    let kty: String
    let alg: String
    let kid: String
    let bits: Int?
    let testKey: Bool
}

/// Where the platform reports a key lives (`AppleKey.protection`), or software.
func reportedName(_ protection: AppleKey.Protection) -> String {
    protection == .secureEnclave ? "secureEnclave" : "keychain"
}

enum LogEvent: Sendable {
    case device(polyjose: String, os: String, model: String, simulator: Bool, secureEnclave: Bool, lockScreen: Bool)
    case input(Input)
    case keyCreate(tag: String, reported: AppleKey.Protection, ms: Int)
    case keyOpen(tag: String, reported: AppleKey.Protection, ms: Int)
    case keyDelete(tag: String, ms: Int)
    case keySoftware(SoftwareKeySummary)
    case jwk(PublicJson)
    case thumbprint(String)
    case call(String, ms: Int)
    case tamper(part: String, index: Int)
    case header(PublicJson)
    case token(String)
    case verify(alg: String, kid: String?, ms: Int)
    case claims(PublicJson)
    case decrypt(alg: String, enc: String, equal: Bool, ms: Int)
    case error(ErrorCode, ms: Int)
    case note(String)

    /// The event name and the rest of the line. A field value keeps only identifier characters
    /// (any other becomes `_`, an empty value `-`), and a token that isn't base64url parts joined
    /// by dots (RFC 7515 §7.1, RFC 7516 §7.1) is logged as `[not a compact token]`, so a value
    /// can't carry free text into the log.
    var parts: (event: String, rest: String) {
        func fields(_ pairs: [(String, String?)]) -> String {
            pairs.compactMap { key, value in value.map { "\(key)=\(identifier($0))" } }
                .joined(separator: " ")
        }
        switch self {
        case let .device(polyjose, os, model, simulator, secureEnclave, lockScreen):
            return ("device", fields([
                ("polyjose", polyjose), ("os", os), ("model", model), ("simulator", "\(simulator)"),
                ("secure-enclave", "\(secureEnclave)"), ("lock-screen", "\(lockScreen)"),
            ]))
        case let .input(input):
            return ("input", fields([
                ("op", input.op.rawValue), ("store", input.store?.rawValue), ("alg", input.alg), ("enc", input.enc),
                ("crv", input.crv), ("size", input.size.map(String.init)),
                ("auth", input.auth.flatMap { $0 == .none ? nil : $0.rawValue }), ("payload", input.payload),
                ("failure", input.failure?.rawValue), ("anyway", input.anyway ? "true" : nil),
            ]))
        case let .keyCreate(tag, reported, ms):
            return ("key-create", fields([("tag", tag), ("reported", reportedName(reported)), ("ms", "\(ms)")]))
        case let .keyOpen(tag, reported, ms):
            return ("key-open", fields([("tag", tag), ("reported", reportedName(reported)), ("ms", "\(ms)")]))
        case let .keyDelete(tag, ms):
            return ("key-delete", fields([("tag", tag), ("ms", "\(ms)")]))
        case let .keySoftware(key):
            return ("key-software", fields([
                ("kty", key.kty), ("alg", key.alg), ("kid", key.kid), ("bits", key.bits.map(String.init)),
                ("test-key", key.testKey ? "true" : nil),
            ]))
        case let .jwk(json): return ("jwk", json.text)
        case let .thumbprint(value): return ("thumbprint", fields([("value", value)]))
        case let .call(function, ms): return ("call", "\(identifier(function)) " + fields([("ms", "\(ms)")]))
        case let .tamper(part, index): return ("tamper", fields([("part", part), ("index", "\(index)")]))
        case let .header(json): return ("header", json.text)
        case let .token(token): return ("token", isCompactToken(token) ? token : "[not a compact token]")
        case let .verify(alg, kid, ms): return ("verify", "ok " + fields([("alg", alg), ("kid", kid), ("ms", "\(ms)")]))
        case let .claims(json): return ("claims", json.text)
        case let .decrypt(alg, enc, equal, ms):
            return ("decrypt", "ok " + fields([
                ("alg", alg), ("enc", enc), ("plaintext", equal ? "equal" : "differs"), ("ms", "\(ms)"),
            ]))
        case let .error(code, ms): return ("error", fields([("code", code.code), ("ms", "\(ms)")]))
        case let .note(id): return ("note", fields([("id", id)]))
        }
    }
}

/// `value` with every character other than `A-Z a-z 0-9 . _ : + / = @ , -` replaced by `_`, or `-`
/// when it is empty.
private func identifier(_ value: String) -> String {
    let kept = String(value.unicodeScalars.map { identifierCharacters.contains($0) ? Character($0) : "_" })
    return kept.isEmpty ? "-" : kept
}

private let identifierCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:+/=@,-")

/// Two or more base64url parts joined by `.` (a compact JWS or JWE).
private func isCompactToken(_ token: String) -> Bool {
    let parts = token.split(separator: ".", omittingEmptySubsequences: false)
    return parts.count >= 2 && parts.allSatisfy { $0.unicodeScalars.allSatisfy(base64urlCharacters.contains) }
}

private let base64urlCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")

// MARK: - The result card

/// What the result card shows, filled from the tap's events.
struct Card: Sendable {
    struct Timing: Sendable, Identifiable {
        let id: Int
        let step: String
        let ms: Int
    }

    let title: String
    var token: String?
    var header: String?
    var outcome: [String] = []
    var claims: String?
    var errorCode: String?
    /// Where the key lives: the reported protection, or software.
    var livesIn: Store?
    var publicJwk: String?
    var timings: [Timing] = []
    var notes: [String] = []
    /// A decryption that returned other bytes than were encrypted.
    var plaintextDiffers = false

    /// The tap ended without an error and, when it decrypted, with the same plaintext.
    var succeeded: Bool { errorCode == nil && !plaintextDiffers }

    mutating func record(_ event: LogEvent) {
        func time(_ step: String, _ ms: Int) { timings.append(Timing(id: timings.count, step: step, ms: ms)) }
        switch event {
        case let .keyCreate(_, reported, ms):
            livesIn = reported == .secureEnclave ? .secureEnclave : .keychain
            time("key-create", ms)
        case let .keyOpen(_, reported, ms):
            livesIn = reported == .secureEnclave ? .secureEnclave : .keychain
            time("key-open", ms)
        case let .keyDelete(_, ms): time("key-delete", ms)
        // The first key of a tap is the one the card is about: the "other" key of a wrong-key
        // action is a software key also when the tap's key is a platform key.
        case .keySoftware: if livesIn == nil { livesIn = .software }
        case let .jwk(json): publicJwk = json.text
        case let .call(function, ms): time(function, ms)
        case let .header(json): header = json.text
        case let .token(value): token = value
        case let .verify(alg, kid, ms):
            outcome.append("Verified: alg \(alg)" + (kid.map { ", kid \($0)" } ?? ""))
            time("verify", ms)
        case let .claims(json): claims = json.text
        case let .decrypt(alg, enc, equal, ms):
            outcome.append("Decrypted with \(alg) and \(enc): the plaintext " + (equal ? "equals the input" : "differs from the input"))
            plaintextDiffers = !equal
            time("decrypt", ms)
        case let .error(code, ms):
            errorCode = code.code
            time("error", ms)
        case let .note(id): notes.append(id)
        case .thumbprint, .tamper, .input, .device: break
        }
    }
}

// MARK: - The log

/// One tap and its lines, as the Log tab shows it.
struct LogEntry: Identifiable, Sendable {
    let tap: Int
    let title: String
    var lines: [String]
    var id: Int { tap }
}

@MainActor
final class PlaygroundLog: ObservableObject {
    /// Newest first.
    @Published private(set) var entries: [LogEntry] = []
    private var nextTap = 1

    nonisolated private static let logger = Logger(subsystem: "dev.polyjose.examples", category: "playground")

    /// Long lines are split every 800 characters; each continuation repeats `LOG <tap>.<step>` and
    /// has `+` in place of the event.
    nonisolated static let chunk = 800

    /// Starts tap number `nextTap`, titled for example `Sign JWS ES256 · Secure Enclave`.
    func begin(_ title: String) -> Tap {
        defer { nextTap += 1 }
        return start(tap: nextTap, title: title)
    }

    /// Tap 0: the `device` line, logged once at start.
    func device(_ event: LogEvent) {
        start(tap: 0, title: "Device").log(event)
    }

    private func start(tap: Int, title: String) -> Tap {
        entries.insert(LogEntry(tap: tap, title: "#\(tap) \(title)", lines: []), at: 0)
        return Tap(number: tap, title: title, log: self)
    }

    fileprivate func append(_ lines: [String], tap: Int) {
        for line in lines {
            print(line)
            Self.logger.notice("\(line, privacy: .public)")
        }
        fflush(stdout)
        if let index = entries.firstIndex(where: { $0.tap == tap }) { entries[index].lines += lines }
    }

    func clear() { entries = [] }

    /// Every line, oldest first, with each long line's `+` continuations joined back onto it
    /// (PLAYGROUND.md, "Log"), and the number of joined lines: what the demo walk's secrets check
    /// searches.
    var joinedText: (text: String, lines: Int) {
        var joined: [String] = []
        for entry in entries.reversed() {
            for line in entry.lines {
                if !joined.isEmpty, let range = line.range(of: #"^LOG [0-9]+\.[0-9]+ \+ "#, options: .regularExpression) {
                    joined[joined.count - 1] += line[range.upperBound...]
                } else {
                    joined.append(line)
                }
            }
        }
        return (joined.joined(separator: "\n"), joined.count)
    }

    /// Every entry, oldest first, as text for Copy all and Share.
    var exportText: String {
        entries.reversed().map { ([$0.title] + $0.lines).joined(separator: "\n") }.joined(separator: "\n\n") + "\n"
    }
}

/// The lines of one tap. Only `LogEvent`s can be logged.
@MainActor
final class Tap {
    let number: Int
    private var step = 0
    private let log: PlaygroundLog
    private(set) var card: Card

    fileprivate init(number: Int, title: String, log: PlaygroundLog) {
        self.number = number
        self.log = log
        self.card = Card(title: title)
    }

    func log(_ event: LogEvent) {
        step += 1
        card.record(event)
        let (name, rest) = event.parts
        let prefix = "LOG \(number).\(step)"
        var chunks: [Substring] = []
        var remaining = Substring(rest)
        repeat {
            chunks.append(remaining.prefix(PlaygroundLog.chunk))
            remaining = remaining.dropFirst(PlaygroundLog.chunk)
        } while !remaining.isEmpty
        let lines = chunks.enumerated().map { index, part in
            index == 0 ? "\(prefix) \(name)" + (part.isEmpty ? "" : " \(part)") : "\(prefix) + \(part)"
        }
        log.append(lines, tap: number)
    }
}
