#!/usr/bin/env bash
# Builds dev.polyjose:polyjose from a local polyjose checkout, then this app against it, instead
# of the published release that build.gradle.kts pins.
#
#   POLYJOSE_SRC=../../polyjose ./build.sh     then install build/outputs/apk/debug/*.apk
#   POLYJOSE_SRC=../../polyjose ./run.sh       does both, and runs the checks
#
# The checkout is never written to. Its files (tracked, plus untracked files that git does not
# ignore, so uncommitted work is included) are copied to $POLYJOSE_BUILD_DIR/src, and polyjose's
# own Gradle build publishes the AAR there, to src/bindings/kotlin/build/repo, with cargo's
# output in $POLYJOSE_BUILD_DIR/target. Then this app is built with -PpolyjoseSrc pointing at
# the copy, so dev.polyjose comes only from that repo (settings.gradle.kts).
#
# Needs what polyjose's CONTRIBUTING.md lists for the Android binding: Rust (cargo) with the four
# Android targets, the Android NDK, cargo-ndk, a JDK (JAVA_HOME) and the Android SDK
# (ANDROID_HOME). A first build compiles polyjose for four ABIs and takes several minutes.
#
# Environment:
#   POLYJOSE_SRC        the polyjose checkout to build (required); a relative path is resolved
#                       from this folder
#   POLYJOSE_BUILD_DIR  where the copy and cargo's output go (default: .build next to this script)
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd -P)
[ -n "${POLYJOSE_SRC:-}" ] || { echo "build.sh: set POLYJOSE_SRC to a polyjose checkout" >&2; exit 2; }
checkout=$(cd "$here" && cd "$POLYJOSE_SRC" && pwd -P)
[ -f "$checkout/bindings/kotlin/gradlew" ] \
  || { echo "build.sh: $POLYJOSE_SRC has no bindings/kotlin/gradlew; build.sh needs a polyjose checkout with the bindings/ layout (0.5.0 or later, or main after 0030)" >&2; exit 2; }

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

echo "==> build the polyjose AAR in the copy (publishAllPublicationsToBuildLocalRepository)"
export CARGO_TARGET_DIR=$build_dir/target
(cd "$src/bindings/kotlin" && ./gradlew --quiet :polyjose:publishAllPublicationsToBuildLocalRepository)

echo "==> build this app against it"
cd "$here"
./gradlew --quiet "-PpolyjoseSrc=$src" assembleDebug
echo "==> dev.polyjose:polyjose built from the polyjose checkout at $commit"
