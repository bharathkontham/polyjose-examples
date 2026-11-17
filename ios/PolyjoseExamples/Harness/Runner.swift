// Runs the catalog off the main thread, prints one line per check to stdout and publishes the
// same lines to the screen:
//
//   # polyjose 0.4.0 through the Polyjose Swift package, iOS 27.2 (Simulator)
//   PASS jws/sign-verify/es256
//   FAIL jwt/verify/rejects-expired: expected TokenExpired, got InvalidClaim
//   SKIP platform-key/secure-enclave/es256-sign: no Secure Enclave on this device
//   POLYJOSE-VERIFY: 39/40 PASS (4 skipped)
//
// A FAIL line never shows key material or token contents.
import Foundation
import Polyjose

@MainActor
final class Runner: ObservableObject {
    /// One printed line: an information line (`# ...`), a check line or the result line.
    struct Line: Identifiable, Sendable {
        let id: Int
        let text: String
    }

    @Published private(set) var lines: [Line] = []
    @Published private(set) var isRunning = false
    @Published private(set) var result: (passed: Int, ran: Int)?

    /// Runs every check in catalog order. Returns `true` when every check that ran passed, and
    /// at least one ran. Each run has its own `run` id, so the platform-key checks of one run
    /// use their own key tags.
    @discardableResult
    func runAll() async -> Bool {
        isRunning = true
        defer { isRunning = false }
        lines = []
        result = nil
        emit(Self.infoLine())
        var passed = 0
        var ran = 0
        var skipped = 0
        let run = String(UUID().uuidString.prefix(8)).lowercased()
        for check in Catalog.checks(run: run) {
            let outcome = await Task.detached(priority: .userInitiated) { Self.execute(check) }.value
            switch outcome {
            case .pass:
                passed += 1
                ran += 1
                emit("PASS \(check.id)")
            case .fail(let reason):
                ran += 1
                emit("FAIL \(check.id): \(reason)")
            case .skip(let reason):
                skipped += 1
                emit("SKIP \(check.id): \(reason)")
            }
        }
        result = (passed, ran)
        // CATALOG.md, "Output and pass rule": ` (S skipped)` only when S > 0.
        emit("POLYJOSE-VERIFY: \(passed)/\(ran) PASS" + (skipped > 0 ? " (\(skipped) skipped)" : ""))
        return passed == ran && ran > 0
    }

    private func emit(_ text: String) {
        print(text)
        fflush(stdout)
        lines.append(Line(id: lines.count, text: text))
    }

    /// Runs one check, unless its skip condition holds.
    nonisolated private static func execute(_ check: Check) -> Check.Outcome {
        if let reason = check.skip() { return .skip(reason) }
        do {
            try check.run()
            return .pass
        } catch {
            return .fail(describe(error))
        }
    }

    /// Why a check failed. A polyjose error is shown by its stable code only.
    nonisolated private static func describe(_ error: Error) -> String {
        if let failure = error as? CheckFailure { return failure.message }
        if let error = error as? PolyjoseError { return "unexpected \(error.code())" }
        return "unexpected \(type(of: error))"
    }

    /// The first line: the polyjose version, the package and the runtime.
    nonisolated private static func infoLine() -> String {
        let os = ProcessInfo.processInfo.operatingSystemVersion
        var system = "\(os.majorVersion).\(os.minorVersion)"
        if os.patchVersion > 0 { system += ".\(os.patchVersion)" }
        #if targetEnvironment(simulator)
        let device = "Simulator"
        #else
        let device = "device"
        #endif
        return "# polyjose \(version()) through the Polyjose Swift package, iOS \(system) (\(device))"
    }
}
