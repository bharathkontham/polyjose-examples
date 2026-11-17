// polyjose examples: one file per developer task in Examples/, every check of CATALOG.md (at the
// root of this repository) run through them at launch, and the playground of PLAYGROUND.md. The
// check lines are shown on the Checks tab and printed to stdout.
//
// Launch arguments:
//   -autorun          (run.sh) the app exits when the check run is over: status 0 when every check
//                     passed, 1 otherwise.
//   -playground-demo  (run.sh --playground) instead of the checks, the app runs the playground's
//                     demo walk and exits: status 0 when every step gave its expected outcome.
import SwiftUI

@main
struct PolyjoseExamplesApp: App {
    @StateObject private var runner = Runner()
    @StateObject private var playground = Playground()

    var body: some Scene {
        WindowGroup {
            ContentView(runner: runner, playground: playground)
                .task {
                    let arguments = ProcessInfo.processInfo.arguments
                    if arguments.contains("-playground-demo") {
                        let ok = await DemoWalk.run(playground)
                        exit(ok ? 0 : 1)
                    }
                    let passed = await runner.runAll()
                    if arguments.contains("-autorun") {
                        exit(passed ? 0 : 1)
                    }
                }
                .task { await playground.start() }
        }
    }
}
