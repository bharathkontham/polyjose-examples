// The building blocks of the checks: a check, its expectations and small helpers. A failed
// expectation says what differs; it never shows key material, plaintext or token contents (see
// CATALOG.md at the root of this repository, "Output and pass rule").
import Foundation

/// One check of the catalog: an `area/op/case` id, a body that throws when it fails, and the
/// check's one skip condition: `skip` returns the SKIP reason when the device lacks what the check
/// needs, and the body then doesn't run (CATALOG.md, "Output and pass rule").
struct Check: Identifiable, Sendable {
    let id: String
    let skip: @Sendable () -> String?
    let run: @Sendable () throws -> Void

    init(id: String, skip: @escaping @Sendable () -> String? = { nil }, run: @escaping @Sendable () throws -> Void) {
        self.id = id
        self.skip = skip
        self.run = run
    }

    /// What happened when a check ran.
    enum Outcome: Sendable {
        case pass
        case fail(String)
        case skip(String)
    }
}

/// Thrown by a check whose expectation did not hold. `message` is the FAIL reason.
struct CheckFailure: Error {
    let message: String
}

/// Fails the check with `what` unless `condition` holds.
func expect(_ condition: Bool, _ what: @autoclosure () -> String) throws {
    if !condition { throw CheckFailure(message: what()) }
}

/// For public, non-secret values only (algorithm names, kids, indexes): shows both.
func expectEqual<T: Equatable & CustomStringConvertible>(_ actual: T?, _ expected: T, _ what: String) throws {
    if actual != expected {
        throw CheckFailure(message: "\(what): expected \(expected), got \(actual.map(\.description) ?? "nothing")")
    }
}

/// For anything that may be secret or token content: says only that it differs.
func expectSame<T: Equatable>(_ actual: T?, _ expected: T?, _ what: String) throws {
    try expect(actual == expected, "\(what) differs")
}

/// Like `expectSame`, for a string that must be there: a missing or empty `expected` fails.
func expectSameString(_ actual: String?, _ expected: String?, _ what: String) throws {
    try expect(!(expected ?? "").isEmpty, "\(what) is missing")
    try expectSame(actual, expected, what)
}

/// The check fails unless `rejection` (an error code, or `nil` for success) is `code`.
func expectCode(_ rejection: String?, _ code: String) throws {
    if rejection != code { throw CheckFailure(message: "expected \(code), got \(rejection ?? "success")") }
}

/// Runs `body` with a platform key `tag`, then deletes whatever key is stored under it with
/// `delete`, also when `body` fails, so no key is left behind. A failed delete after a passing
/// body fails the check.
func withKeyTag(_ tag: String, delete: (String) throws -> Void, _ body: (String) throws -> Void) throws {
    do {
        try body(tag)
    } catch {
        try? delete(tag)
        throw error
    }
    try delete(tag)
}

/// The UTF-8 bytes of `text`.
func utf8(_ text: String) -> Data { Data(text.utf8) }

/// The current time as a JWT NumericDate: whole seconds since the epoch (RFC 7519 §2).
func nowSeconds() -> Int64 { Int64(Date().timeIntervalSince1970) }

/// Parses JSON text (a JWK, a header or claims) into a dictionary, to read a member.
func jsonObject(_ text: String) throws -> [String: Any] {
    guard let object = try? JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
        throw CheckFailure(message: "not a JSON object")
    }
    return object
}

/// A string member of a JSON object, or `nil`.
func stringMember(_ object: [String: Any], _ name: String) -> String? { object[name] as? String }

/// JWK JSON text with `kid` set to `kid`.
func withKid(_ jwk: String, _ kid: String) throws -> String {
    var object = try jsonObject(jwk)
    object["kid"] = kid
    return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
}

/// Changes one character in the middle of part `index` of a compact token (`A` and `B` swap).
func tamper(_ token: String, _ index: Int) -> String {
    var parts = token.split(separator: ".", omittingEmptySubsequences: false).map { Array($0) }
    let middle = parts[index].count / 2
    parts[index][middle] = parts[index][middle] == "A" ? "B" : "A"
    return parts.map { String($0) }.joined(separator: ".")
}
