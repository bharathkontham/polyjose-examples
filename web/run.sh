#!/usr/bin/env bash
# Installs the app, serves it, loads the page in headless Chrome and prints what it shows: one
# line per check of ../CATALOG.md, then `POLYJOSE-VERIFY: P/R PASS`. Exits 0 only when every
# check passed.
#
#   ./run.sh                               against the published @polyjose/wasm (package.json)
#   POLYJOSE_SRC=../../polyjose ./run.sh   against a local polyjose checkout (see build.sh)
#
# Needs Node.js 22.12 or later, npm, and Google Chrome or Chromium.
#
# Environment:
#   CHROME        the Chrome binary (default: the macOS Google Chrome app, else google-chrome,
#                 google-chrome-stable, chromium or chromium-browser on PATH)
#   RUN_TIMEOUT   seconds to wait for the page's result line (default 120). When it runs out,
#                 run.sh prints `POLYJOSE-VERIFY: 0/<R> PASS (timeout)` and exits 1
#
# The server listens on a free port of 127.0.0.1. Chrome runs with a fresh profile in a
# temporary folder, which is removed afterwards with everything else this script started.
set -euo pipefail
cd "$(dirname "$0")"

node -e '
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 22 || (major === 22 && minor < 12)) {
    console.error(`run.sh: Node.js ${process.versions.node} is too old; this app needs 22.12 or later`);
    process.exit(2);
  }'

chrome=${CHROME:-}
if [ -z "$chrome" ]; then
  mac_chrome="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
  if [ -x "$mac_chrome" ]; then
    chrome=$mac_chrome
  else
    for name in google-chrome google-chrome-stable chromium chromium-browser; do
      if command -v "$name" >/dev/null 2>&1; then chrome=$(command -v "$name"); break; fi
    done
  fi
fi
[ -n "$chrome" ] && [ -x "$chrome" ] \
  || { echo "run.sh: Chrome not found; set CHROME to the Chrome or Chromium binary" >&2; exit 2; }

expected_checks=34 # the number of checks CATALOG.md lists for the pinned polyjose (0.2.0)
timeout=${RUN_TIMEOUT:-120}
case "$timeout" in ''|*[!0-9]*) echo "run.sh: RUN_TIMEOUT must be a number of seconds" >&2; exit 2 ;; esac

if [ -n "${POLYJOSE_SRC:-}" ]; then
  ./build.sh
else
  npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/polyjose-examples-web.XXXXXX")
server_pid=
chrome_pid=
cleanup() {
  [ -z "$chrome_pid" ] || kill "$chrome_pid" 2>/dev/null || true
  [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
  [ -z "$chrome_pid" ] || wait "$chrome_pid" 2>/dev/null || true
  [ -z "$server_pid" ] || wait "$server_pid" 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# The server picks a free port and prints its URL.
node serve.mjs --port 0 >"$tmp/server.log" 2>&1 &
server_pid=$!
url=
for _ in $(seq 1 100); do
  url=$(sed -n 's/^serving \(http:[^ ]*\)$/\1/p' "$tmp/server.log")
  [ -n "$url" ] && break
  kill -0 "$server_pid" 2>/dev/null || break
  sleep 0.1
done
[ -n "$url" ] || { cat "$tmp/server.log" >&2; echo "run.sh: the server did not start" >&2; exit 1; }

# Chrome loads the page and writes the page's console messages to its log, one per line:
#   [...:INFO:CONSOLE:<n>] "PASS jws/sign-verify/hs256", source: http://127.0.0.1:<port>/verify.mjs (<n>)
# The flags keep it off the network apart from the page.
"$chrome" --headless=new --user-data-dir="$tmp/profile" --no-first-run --no-default-browser-check \
  --disable-extensions --disable-background-networking --disable-component-update --disable-sync \
  --disable-gpu --enable-logging=stderr --v=0 "$url" \
  >"$tmp/chrome.out" 2>"$tmp/chrome.log" &
chrome_pid=$!

# The page's output lines, in order.
page_lines() {
  sed -n 's/^.*:CONSOLE[^]]*\] "\(.*\)", source: .*$/\1/p' "$tmp/chrome.log" \
    | grep -E '^(# |PASS |FAIL |SKIP |POLYJOSE-VERIFY: )' || true
}

# Wait for the result line, as long as RUN_TIMEOUT allows, then stop Chrome.
final=
ticks=0
while :; do
  final=$(page_lines | grep '^POLYJOSE-VERIFY: ' | tail -n 1 || true)
  [ -n "$final" ] && break
  kill -0 "$chrome_pid" 2>/dev/null || break
  [ "$ticks" -ge $((timeout * 10)) ] && break
  sleep 0.1
  ticks=$((ticks + 1))
done
kill "$chrome_pid" 2>/dev/null || true
wait "$chrome_pid" 2>/dev/null || true
chrome_pid=

lines=$(page_lines)
[ -z "$lines" ] || printf '%s\n' "$lines"

if [ -z "$final" ]; then
  echo "POLYJOSE-VERIFY: 0/$expected_checks PASS (timeout)"
  echo "run.sh: no result line from the page within ${timeout}s; Chrome's last log lines:" >&2
  { grep -v ':CONSOLE' "$tmp/chrome.log" || true; } | tail -n 20 | sed 's/^/  /' >&2
  exit 1
fi

# Exit 0 only for P/R PASS with P = R = expected_checks (CATALOG.md, "Output and pass rule").
if [[ "$final" =~ ^POLYJOSE-VERIFY:\ ([0-9]+)/([0-9]+)\ PASS ]]; then
  [ "${BASH_REMATCH[2]}" = "$expected_checks" ] \
    || echo "run.sh: ${BASH_REMATCH[2]} checks ran; CATALOG.md lists $expected_checks" >&2
  [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] && [ "${BASH_REMATCH[2]}" = "$expected_checks" ] && exit 0
fi
exit 1
