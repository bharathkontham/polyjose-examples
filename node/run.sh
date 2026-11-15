#!/usr/bin/env bash
# Installs the app and runs every check of ../CATALOG.md, one line per check, then
# `POLYJOSE-VERIFY: P/R PASS`. Exits 0 only when every check passed.
#
#   ./run.sh                               against the published @polyjose/node (package.json)
#   POLYJOSE_SRC=../../polyjose ./run.sh   against a local polyjose checkout (see build.sh)
#
# Needs Node.js 22.12 or later, and npm.
set -euo pipefail
cd "$(dirname "$0")"

node -e '
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 22 || (major === 22 && minor < 12)) {
    console.error(`run.sh: Node.js ${process.versions.node} is too old; @polyjose/node needs 22.12 or later`);
    process.exit(2);
  }'

if [ -n "${POLYJOSE_SRC:-}" ]; then
  ./build.sh
else
  npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
fi
exec node verify.mjs
