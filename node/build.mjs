// `npm run build:local`: builds @polyjose/node from a local polyjose checkout and points this app
// at it, instead of the published package that package.json pins. Run `npm ci --ignore-scripts`
// first; `npm run verify` with POLYJOSE_SRC set runs this file before the checks.
//
// The checkout is never written to. Its files (tracked, plus untracked files that git does not
// ignore, so uncommitted work is included) are copied to <build dir>/src, and polyjose's own
// bindings/node/scripts/build.sh runs on the copy, with cargo's output in <build dir>/target.
// Then node_modules/@polyjose/node is replaced by a link to the package built in the copy.
// `npm ci --ignore-scripts` goes back to the published package.
//
// Needs what polyjose's CONTRIBUTING.md lists for the Node binding: Rust (cargo), node, npm.
// A first build compiles polyjose in release mode and takes a few minutes.
//
// Environment:
//   POLYJOSE_SRC        the polyjose checkout to build (required)
//   POLYJOSE_BUILD_DIR  where everything is written (default: .build in this folder); it must be
//                       outside the checkout
// A relative path in either is resolved from this folder.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

function fail(message) {
  console.error(`build:local: ${message}`);
  process.exit(2);
}

const here = fs.realpathSync(path.dirname(fileURLToPath(import.meta.url)));
if (!process.env.POLYJOSE_SRC) fail("set POLYJOSE_SRC to a polyjose checkout");
let checkout;
try {
  checkout = fs.realpathSync(path.resolve(here, process.env.POLYJOSE_SRC));
} catch {
  fail(`${process.env.POLYJOSE_SRC} does not exist`);
}
if (!fs.existsSync(path.join(checkout, "bindings/node/scripts/build.sh"))) {
  fail(`${process.env.POLYJOSE_SRC} is not a polyjose checkout (no bindings/node/scripts/build.sh)`);
}
const modules = path.join(here, "node_modules");
if (!fs.existsSync(modules)) fail("run `npm ci --ignore-scripts` first");

function outsideCheckout(dir) {
  if (`${dir}/`.startsWith(`${checkout}/`)) fail("POLYJOSE_BUILD_DIR must be outside the checkout");
}
let buildDir = path.resolve(here, process.env.POLYJOSE_BUILD_DIR || ".build");
outsideCheckout(buildDir); // before anything is created
fs.mkdirSync(buildDir, { recursive: true });
buildDir = fs.realpathSync(buildDir);
outsideCheckout(buildDir); // again, with symbolic links resolved

// GIT_OPTIONAL_LOCKS=0: git status must not refresh the checkout's index (no write).
const env = { ...process.env, GIT_OPTIONAL_LOCKS: "0" };
const git = (...args) => execFileSync("git", ["-C", checkout, ...args], { env, encoding: "utf8" });
let commit = git("rev-parse", "--short", "HEAD").trim();
if (git("status", "--porcelain") !== "") commit += "+dirty";

const src = path.join(buildDir, "src");
console.log(`==> copy the polyjose checkout (${commit}) to ${src}`);
fs.rmSync(src, { recursive: true, force: true });
for (const name of git("ls-files", "-co", "--exclude-standard", "-z").split("\0")) {
  if (name === "") continue;
  const from = path.join(checkout, name);
  const to = path.join(src, name);
  let stat;
  try {
    stat = fs.lstatSync(from);
  } catch {
    continue; // deleted in the working tree
  }
  if (stat.isDirectory()) continue; // a submodule: polyjose has none
  fs.mkdirSync(path.dirname(to), { recursive: true });
  if (stat.isSymbolicLink()) {
    fs.symlinkSync(fs.readlinkSync(from), to);
  } else {
    fs.copyFileSync(from, to);
    fs.chmodSync(to, stat.mode & 0o777);
  }
}

console.log("==> build @polyjose/node in the copy (bindings/node/scripts/build.sh)");
const pkg = path.join(src, "bindings/node");
execFileSync("scripts/build.sh", [], {
  cwd: pkg,
  stdio: "inherit",
  env: { ...env, CARGO_TARGET_DIR: path.join(buildDir, "target") },
});

console.log("==> link node_modules/@polyjose/node to the local build");
const link = path.join(modules, "@polyjose/node");
fs.rmSync(link, { recursive: true, force: true });
fs.mkdirSync(path.dirname(link), { recursive: true });
fs.symlinkSync(pkg, link, "dir");

const { version } = JSON.parse(fs.readFileSync(path.join(pkg, "package.json"), "utf8"));
console.log(`==> @polyjose/node ${version} built from the polyjose checkout at ${commit}`);
