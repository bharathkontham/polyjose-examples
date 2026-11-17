// `npm run verify`: builds the app, starts it, opens /?verify=1 in headless Chrome and prints
// what the page prints: one line per check, then `POLYJOSE-VERIFY: P/R PASS`. Exits 0 only when
// P = R = EXPECTED_CHECKS and the secrets grep over the browser console and the server output
// finds nothing.
//
// Needs Node.js 22.12 or later, the installed packages (`npm ci --ignore-scripts`), and Google
// Chrome or Chromium.
//
// Environment:
//   CHROME        the Chrome binary (default: the macOS Google Chrome app, else google-chrome,
//                 google-chrome-stable, chromium or chromium-browser on PATH)
//   RUN_TIMEOUT   seconds from starting the server to the page's result line (default 120).
//                 When it runs out, `POLYJOSE-VERIFY: 0/<N> PASS (timeout)` is printed and the
//                 exit is 1
//
// The server listens on a free port of 127.0.0.1. Chrome runs with a fresh profile in a
// `.verify-*` folder here, removed afterwards. Only the processes this script started are
// stopped.
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { accessSync, constants, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import path from "node:path";
import process from "node:process";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";

/** The number of `nextjs/*` checks the page runs (lib/browser/checks.ts). */
const EXPECTED_CHECKS = 8;

/** A private or symmetric JWK member as JSON (`"d":`), or an unhandled polyjose error. */
const SECRETS = /"(d|p|q|dp|dq|qi|oth|k)"\s*:|PolyjoseError/;

/** The lines the page prints (CATALOG.md, "Output and pass rule"). */
const PAGE_LINE = /^(# |PASS |FAIL |SKIP |POLYJOSE-VERIFY: )/;

const here = path.dirname(fileURLToPath(import.meta.url));
const say = (line) => console.error(`verify: ${line}`);

const [major, minor] = process.versions.node.split(".").map(Number);
if (major < 22 || (major === 22 && minor < 12)) {
  say(`Node.js ${process.versions.node} is too old; this app needs 22.12 or later`);
  process.exit(2);
}
const timeout = Number(process.env.RUN_TIMEOUT ?? 120);
if (!Number.isInteger(timeout) || timeout <= 0) {
  say("RUN_TIMEOUT must be a whole number of seconds");
  process.exit(2);
}

function isExecutable(file) {
  try {
    accessSync(file, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function findChrome() {
  if (process.env.CHROME) return isExecutable(process.env.CHROME) ? process.env.CHROME : null;
  const mac = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  if (isExecutable(mac)) return mac;
  for (const name of ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"]) {
    for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
      if (dir && isExecutable(path.join(dir, name))) return path.join(dir, name);
    }
  }
  return null;
}

const chrome = findChrome();
if (!chrome) {
  say("Chrome not found; set CHROME to the Chrome or Chromium binary");
  process.exit(2);
}

const next = path.join(here, "node_modules", "next", "dist", "bin", "next");
const env = { ...process.env, NEXT_TELEMETRY_DISABLED: "1" };

// 1. Build. Its progress goes to stderr; stdout carries only the page's lines.
const build = spawnSync(process.execPath, [next, "build"], { cwd: here, env, stdio: ["ignore", 2, 2] });
if (build.status !== 0) {
  say("next build failed");
  process.exit(build.status ?? 1);
}

// 2. The browser fetches the .wasm with Subresource Integrity, so the bundler must emit the
//    package's file byte for byte. Say so here rather than as a failed first call.
const sha384 = (file) => createHash("sha384").update(readFileSync(file)).digest("base64");
const packaged = sha384(path.join(here, "node_modules", "@polyjose", "wasm", "polyjose_wasm_bg.wasm"));
const media = path.join(here, ".next", "static", "media");
const emitted = readdirSync(media).filter((name) => name.endsWith(".wasm"));
if (emitted.length !== 1 || sha384(path.join(media, emitted[0])) !== packaged) {
  say(`.next/static/media has ${emitted.length} .wasm file(s), and not one with the package's SHA-384 ${packaged}`);
  process.exit(1);
}
say(`.next/static/media/${emitted[0]} has the package's SHA-384 (${packaged})`);

/** A free TCP port on 127.0.0.1. */
function freePort() {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/**
 * Starts `command` in its own process group, so that stopping it stops its children too, and
 * collects its output.
 */
function start(command, args, options) {
  const child = spawn(command, args, { ...options, detached: true, stdio: ["ignore", "pipe", "pipe"] });
  const run = { child, output: "", exited: false };
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => {
      run.output += chunk;
    });
  }
  run.done = new Promise((resolve) => child.on("close", resolve));
  child.on("exit", () => {
    run.exited = true;
  });
  return run;
}

/** Stops a process group this script started: SIGTERM, then SIGKILL after 5 s. */
async function stop(run) {
  if (!run || run.exited) return;
  const signal = (name) => {
    try {
      process.kill(-run.child.pid, name);
    } catch {
      // already gone
    }
  };
  signal("SIGTERM");
  const stopped = await Promise.race([run.done.then(() => true), sleep(5000).then(() => false)]);
  if (!stopped) {
    signal("SIGKILL");
    await run.done;
  }
}

const profile = mkdtempSync(path.join(here, ".verify-"));
let server;
let browser;
async function cleanup() {
  await stop(browser);
  await stop(server);
  rmSync(profile, { recursive: true, force: true });
}
for (const name of ["SIGINT", "SIGTERM"]) {
  process.on(name, () => {
    void cleanup().then(() => process.exit(130));
  });
}

/** The page's lines, in order, from Chrome's log of the console:
 *    [...:INFO:CONSOLE:<n>] "PASS nextjs/jwks/public-only", source: http://127.0.0.1:<port>/... (<n>)
 */
function pageLines() {
  const lines = [];
  for (const line of browser.output.split("\n")) {
    const m = line.match(/:CONSOLE[^\]]*\] "(.*)", source: /);
    if (m && PAGE_LINE.test(m[1])) lines.push(m[1]);
  }
  return lines;
}

const deadline = Date.now() + timeout * 1000;
let final;
try {
  // 3. Start the server and wait until it answers.
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  server = start(process.execPath, [next, "start", "-H", "127.0.0.1", "-p", String(port)], { cwd: here, env });
  let up = false;
  while (!up && !server.exited && Date.now() < deadline) {
    try {
      up = (await fetch(`${base}/`)).ok;
    } catch {
      // not listening yet
    }
    if (!up) await sleep(200);
  }

  // 4. Load the page. The flags keep Chrome off the network apart from the page.
  if (up) {
    browser = start(chrome, [
      "--headless=new", `--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check",
      "--disable-extensions", "--disable-background-networking", "--disable-component-update", "--disable-sync",
      "--disable-gpu", "--enable-logging=stderr", "--v=0", `${base}/?verify=1`,
    ], {});
    while (Date.now() < deadline && !browser.exited) {
      final = pageLines().findLast((line) => line.startsWith("POLYJOSE-VERIFY: "));
      if (final) break;
      await sleep(100);
    }
  } else if (!server.exited) {
    say("the server did not answer in time");
  } else {
    say("next start stopped:");
    console.error(server.output.split("\n").slice(-20).join("\n"));
  }
} finally {
  await cleanup();
}

const lines = browser ? pageLines() : [];
for (const line of lines) console.log(line);

if (!final) {
  const timedOut = Date.now() >= deadline;
  console.log(`POLYJOSE-VERIFY: 0/${EXPECTED_CHECKS} PASS (${timedOut ? "timeout" : "no result"})`);
  say(timedOut ? `no result line within ${timeout}s` : "the server or Chrome stopped before the result line");
  process.exit(1);
}

// 5. The secrets grep (PRD "Secrets"): never a private member, and never an unhandled polyjose
//    error, in the browser console or the server output. Only the count is printed, never the
//    lines themselves.
const leaks = [
  ["the browser console", browser.output],
  ["the server output", server.output],
].map(([where, text]) => [where, text.split("\n").filter((line) => SECRETS.test(line)).length]);
let clean = true;
for (const [where, count] of leaks) {
  if (count > 0) {
    clean = false;
    say(`the secrets grep matched ${count} line(s) in ${where}`);
  }
}
if (clean) say("the secrets grep over the browser console and the server output found nothing");

// Exit 0 only for P/R PASS with P = R = EXPECTED_CHECKS (CATALOG.md, "Output and pass rule").
const m = final.match(/^POLYJOSE-VERIFY: (\d+)\/(\d+) PASS/);
const [passed, ran] = m ? [Number(m[1]), Number(m[2])] : [0, 0];
if (ran !== EXPECTED_CHECKS) say(`${ran} checks ran; this app has ${EXPECTED_CHECKS}`);
process.exitCode = clean && passed === ran && ran === EXPECTED_CHECKS ? 0 : 1;
