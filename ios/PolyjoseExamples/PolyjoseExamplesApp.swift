// polyjose examples: one file per developer task in Examples/, and every check of CATALOG.md (at
// the root of this repository) run through them at launch. The lines are shown on screen and
// printed to stdout.
//
// Launched with the argument `-autorun` (run.sh does this), the app exits when the run is over:
// status 0 when every check passed, 1 otherwise.
import SwiftUI

@main
struct PolyjoseExamplesApp: App {
    @StateObject private var runner = Runner()

    var body: some Scene {
        WindowGroup {
            ContentView(runner: runner)
                .task {
                    let passed = await runner.runAll()
                    if ProcessInfo.processInfo.arguments.contains("-autorun") {
                        exit(passed ? 0 : 1)
                    }
                }
        }
    }
}
