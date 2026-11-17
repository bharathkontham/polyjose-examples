// `npm run verify`: runs verify.mjs, which prints one line per check of ../CATALOG.md and then
// `POLYJOSE-VERIFY: P/R PASS`, and applies the pass rule of CATALOG.md ("Output and pass rule"):
// it exits 0 only when P = R and R is the number of catalog checks (EXPECTED_CHECKS).
//
// Environment:
//   RUN_TIMEOUT   seconds the checks may take (default 120). When it runs out, the run is
//                 stopped, `POLYJOSE-VERIFY: 0/<R> PASS (timeout)` is printed and the exit is 1
//   POLYJOSE_SRC  a polyjose checkout: build @polyjose/node from it first (build.mjs)
import { spawn, spawnSync } from "node:child_process";
import process from "node:process";
import { fileURLToPath } from "node:url";

/** The number of Node.js checks CATALOG.md lists for the pinned polyjose version (0.4.0). */
const EXPECTED_CHECKS = 34;

const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 12)) {
  console.error(`verify: Node.js ${process.versions.node} is too old; @polyjose/node needs 22.12 or later`);
  process.exit(2);
}
const timeout = Number(process.env.RUN_TIMEOUT ?? 120);
if (!Number.isInteger(timeout) || timeout <= 0) {
  console.error("verify: RUN_TIMEOUT must be a whole number of seconds");
  process.exit(2);
}
const file = (name) => fileURLToPath(new URL(name, import.meta.url));

if (process.env.POLYJOSE_SRC) {
  // The build's progress goes to stderr; stdout carries only the check lines.
  const build = spawnSync(process.execPath, [file("build.mjs")], { stdio: ["ignore", 2, 2] });
  if (build.status !== 0) process.exit(build.status ?? 1);
}

const child = spawn(process.execPath, [file("verify.mjs")], { stdio: ["ignore", "pipe", "inherit"] });
let output = "";
child.stdout.setEncoding("utf8");
child.stdout.on("data", (chunk) => {
  output += chunk;
  process.stdout.write(chunk);
});
let timedOut = false;
const timer = setTimeout(() => {
  timedOut = true;
  child.kill("SIGKILL"); // a hung native call may ignore SIGTERM
}, timeout * 1000);

child.on("close", (code) => {
  clearTimeout(timer);
  if (timedOut) {
    console.log(`POLYJOSE-VERIFY: 0/${EXPECTED_CHECKS} PASS (timeout)`);
    console.error(`verify: no result line within ${timeout}s`);
    process.exitCode = 1;
    return;
  }
  const final = output.split("\n").filter((line) => line.startsWith("POLYJOSE-VERIFY: ")).pop();
  const m = final?.match(/^POLYJOSE-VERIFY: (\d+)\/(\d+) PASS/);
  if (!m) {
    console.log(`POLYJOSE-VERIFY: 0/${EXPECTED_CHECKS} PASS (no result)`);
    console.error("verify: verify.mjs stopped before its result line");
    process.exitCode = 1;
    return;
  }
  const [passed, ran] = [Number(m[1]), Number(m[2])];
  if (ran !== EXPECTED_CHECKS) console.error(`verify: ${ran} checks ran; CATALOG.md lists ${EXPECTED_CHECKS}`);
  process.exitCode = code === 0 && passed === ran && ran === EXPECTED_CHECKS ? 0 : 1;
});
