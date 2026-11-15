#!/usr/bin/env bash
# Builds @polyjose/wasm from a local polyjose checkout and points this app at it, instead of
# the published package that package.json pins.
#
#   POLYJOSE_SRC=../../polyjose ./build.sh     then: node serve.mjs, and open the printed URL
#   POLYJOSE_SRC=../../polyjose ./run.sh       does both, in headless Chrome
#
# The checkout is never written to. Its files (tracked, plus untracked files that git does not
# ignore, so uncommitted work is included) are copied to $POLYJOSE_BUILD_DIR/src, and polyjose's
# own `bindings/wasm/scripts/build-package.sh --no-pack` runs on the copy, with cargo's output in
# $POLYJOSE_BUILD_DIR/target. Then `npm ci` installs this app's dependencies as usual, and
# node_modules/@polyjose/wasm is replaced by a link to the package built from the copy
# (bindings/wasm/pkg).
#
# Needs what polyjose's CONTRIBUTING.md lists for the WASM binding: Rust (cargo) with the
# wasm32-unknown-unknown target, wasm-pack, node, npm, gzip and brotli. A first build compiles
# polyjose in release mode and takes a few minutes.
#
# Environment:
#   POLYJOSE_SRC        the polyjose checkout to build (required); a relative path is resolved
#                       from this folder
#   POLYJOSE_BUILD_DIR  where everything is written (default: .build next to this script)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
[ -n "${POLYJOSE_SRC:-}" ] || { echo "build.sh: set POLYJOSE_SRC to a polyjose checkout" >&2; exit 2; }
checkout=$(cd "$here" && cd "$POLYJOSE_SRC" && pwd -P)
[ -f "$checkout/bindings/wasm/scripts/build-package.sh" ] \
  || { echo "build.sh: $POLYJOSE_SRC is not a polyjose checkout (no bindings/wasm/scripts/build-package.sh)" >&2; exit 2; }

build_dir=${POLYJOSE_BUILD_DIR:-$here/.build}
case "$build_dir" in /*) ;; *) build_dir=$PWD/$build_dir ;; esac
outside_checkout() {
  case "$1/" in
    "$checkout"/*) echo "build.sh: POLYJOSE_BUILD_DIR must be outside the checkout" >&2; exit 2 ;;
  esac
}
outside_checkout "$build_dir"            # before anything is created
mkdir -p "$build_dir"
build_dir=$(cd "$build_dir" && pwd -P)
outside_checkout "$build_dir"            # again, with symbolic links resolved

# GIT_OPTIONAL_LOCKS=0: git status must not refresh the checkout's index (no write).
export GIT_OPTIONAL_LOCKS=0
commit=$(git -C "$checkout" rev-parse --short HEAD)
[ -z "$(git -C "$checkout" status --porcelain)" ] || commit="$commit+dirty"

src=$build_dir/src
echo "==> copy the polyjose checkout ($commit) to $src"
rm -rf "$src"
mkdir -p "$src"
(cd "$checkout" && git ls-files -co --exclude-standard -z \
  | while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done \
  | rsync -a --from0 --files-from=- ./ "$src/")

echo "==> build @polyjose/wasm in the copy (bindings/wasm/scripts/build-package.sh --no-pack)"
export CARGO_TARGET_DIR=$build_dir/target
(cd "$src" && bindings/wasm/scripts/build-package.sh --no-pack)
pkg=$src/bindings/wasm/pkg
for f in browser.mjs polyjose_wasm_bg.wasm package.json; do
  [ -f "$pkg/$f" ] || { echo "build.sh: the build did not produce $pkg/$f" >&2; exit 1; }
done

echo "==> npm ci, then link node_modules/@polyjose/wasm to the local build"
cd "$here"
npm ci --ignore-scripts --no-audit --no-fund --loglevel=error
rm -rf node_modules/@polyjose/wasm
ln -s "$pkg" node_modules/@polyjose/wasm

version=$(node -p 'require(process.argv[1]).version' "$pkg/package.json")
echo "==> @polyjose/wasm $version built from the polyjose checkout at $commit"
