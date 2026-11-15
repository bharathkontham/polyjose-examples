#!/usr/bin/env bash
# Builds the app, runs it on an iOS Simulator and prints every check of ../CATALOG.md, one line
# per check, then `POLYJOSE-VERIFY: P/R PASS`. Exits 0 only when every check passed.
#
#   ./run.sh                               against the published polyjose Swift package (the
#                                          project's package requirement, exact 0.2.0)
#   POLYJOSE_SRC=../../polyjose ./run.sh   against a local polyjose checkout (see README.md)
#
# The Simulator: a device named `polyjose-examples` on the newest installed iOS runtime, created
# the first time and kept for the next runs. When it is not running, run.sh boots it and shuts it
# down again at the end; a device that was already running is left running. Delete it with
# `xcrun simctl delete polyjose-examples`.
#
# Environment:
#   DEVELOPER_DIR          the Xcode to use (default: the one `xcode-select` points at)
#   POLYJOSE_SRC           a polyjose checkout to build against; a relative path is resolved from
#                          this folder
#   POLYJOSE_SIMULATOR     the name or UDID of the Simulator device to use instead
#   POLYJOSE_SIM_RUNTIME   the runtime identifier for a new device, for example
#                          com.apple.CoreSimulator.SimRuntime.iOS-27-2 (default: the newest iOS)
#   POLYJOSE_TIMEOUT       seconds from booting the Simulator to the final line (default: 300)
#
# Needs macOS with Xcode and an iOS Simulator runtime. Everything it writes goes to .build/ next
# to this script (git ignores it).
set -euo pipefail
export LC_ALL=C

here=$(cd "$(dirname "$0")" && pwd -P)
me=run.sh
bundle_id=dev.polyjose.examples
device_name=polyjose-examples
expected_checks=34 # the 0.2.0 catalog (CATALOG.md); printed in the timeout line
timeout=${POLYJOSE_TIMEOUT:-300}
build_dir=$here/.build
logs=$build_dir/logs

for tool in xcodebuild xcrun plutil rsync; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$me: $tool is missing (needs macOS with Xcode)" >&2; exit 2; }
done
mkdir -p "$logs"
: >"$logs/simctl.log"

# --- the package: published, or a polyjose checkout -------------------------------------------

container=(-project "$here/PolyjoseExamples.xcodeproj")
derived=$build_dir/DerivedData
if [ -n "${POLYJOSE_SRC:-}" ]; then
  # The checkout is never written to. Its files (tracked, plus untracked files that git does not
  # ignore) and its built XCFramework are copied to .build/polyjose. A workspace holding the app
  # project and that copy as a local package replaces the published package, which has the same
  # name (Xcode's local package override). POLYJOSE_LOCAL_XCFRAMEWORK=1 makes polyjose's
  # Package.swift use the copied XCFramework instead of the release download.
  checkout=$(cd "$here" && cd "$POLYJOSE_SRC" && pwd -P)
  [ -f "$checkout/Package.swift" ] && [ -d "$checkout/platforms/swift/Sources/Polyjose" ] ||
    { echo "$me: $POLYJOSE_SRC is not a polyjose checkout (no Package.swift, platforms/swift)" >&2; exit 2; }
  xcframework=platforms/swift/build/PolyjoseFFI.xcframework
  [ -d "$checkout/$xcframework" ] || {
    echo "$me: $checkout/$xcframework is missing; build it in the checkout first:" >&2
    echo "  (cd $checkout && platforms/swift/scripts/build-xcframework.sh)" >&2
    exit 2
  }
  export GIT_OPTIONAL_LOCKS=0 # git must not refresh the checkout's index (no write)
  if [ -f "$checkout/platforms/swift/scripts/xcframework-stale.sh" ]; then
    # shellcheck source=/dev/null
    stale=$(. "$checkout/platforms/swift/scripts/xcframework-stale.sh" &&
      xcframework_stale "$checkout" "$checkout/$xcframework" || true)
    [ -z "$stale" ] || echo "$me: warning: the checkout's XCFramework is stale ($stale); rebuild it with platforms/swift/scripts/build-xcframework.sh" >&2
  fi
  commit=$(git -C "$checkout" rev-parse --short HEAD 2>/dev/null || echo unknown)
  echo "==> copy the polyjose checkout ($commit) to .build/polyjose" >&2
  copy=$build_dir/polyjose
  rm -rf "$copy"
  mkdir -p "$copy"
  (cd "$checkout" && git ls-files -co --exclude-standard -z |
    while IFS= read -r -d '' f; do [ -e "$f" ] && printf '%s\0' "$f"; done |
    rsync -a --from0 --files-from=- ./ "$copy/")
  mkdir -p "$copy/$xcframework"
  rsync -a "$checkout/$xcframework/" "$copy/$xcframework/"
  workspace=$build_dir/PolyjoseLink.xcworkspace
  mkdir -p "$workspace"
  cat >"$workspace/contents.xcworkspacedata" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<Workspace
   version = "1.0">
   <FileRef
      location = "group:../PolyjoseExamples.xcodeproj">
   </FileRef>
   <FileRef
      location = "group:polyjose">
   </FileRef>
</Workspace>
EOF
  export POLYJOSE_LOCAL_XCFRAMEWORK=1
  container=(-workspace "$workspace")
  derived=$build_dir/DerivedData-src
fi

# --- the Simulator device ---------------------------------------------------------------------

# device_line <name or UDID>: the `xcrun simctl list devices available` line of that device.
device_line() {
  xcrun simctl list devices available | grep -F -- " $1 (" | head -n 1 || true
  xcrun simctl list devices available | grep -F -- "($1)" | head -n 1 || true
}

# newest_ios_runtime <runtimes.json>: the identifier of the newest available iOS runtime. Of two
# with the same version, the general one (identifier ...iOS-<major>-<minor>) wins over one made
# for a single device model.
newest_ios_runtime() {
  local json=$1 i=0 id version general major minor patch
  while id=$(plutil -extract "runtimes.$i.identifier" raw -o - "$json" 2>/dev/null); do
    if [ "$(plutil -extract "runtimes.$i.platform" raw -o - "$json" 2>/dev/null)" = iOS ] &&
      [ "$(plutil -extract "runtimes.$i.isAvailable" raw -o - "$json" 2>/dev/null)" = true ]; then
      version=$(plutil -extract "runtimes.$i.version" raw -o - "$json")
      general=0
      [ "$id" != "com.apple.CoreSimulator.SimRuntime.iOS-$(echo "$version" | tr . -)" ] || general=1
      IFS=. read -r major minor patch _ <<<"$version.0.0"
      echo "$major ${minor:-0} ${patch:-0} $general $id"
    fi
    i=$((i + 1))
  done | sort -k1,1n -k2,2n -k3,3n -k4,4n | tail -n 1 | cut -d' ' -f5
}

# first_iphone <runtimes.json> <runtime identifier>: the first iPhone device type of the runtime.
first_iphone() {
  local json=$1 want=$2 i=0 j=0 id
  while id=$(plutil -extract "runtimes.$i.identifier" raw -o - "$json" 2>/dev/null); do
    if [ "$id" = "$want" ]; then
      while id=$(plutil -extract "runtimes.$i.supportedDeviceTypes.$j.identifier" raw -o - "$json" 2>/dev/null); do
        if [ "$(plutil -extract "runtimes.$i.supportedDeviceTypes.$j.productFamily" raw -o - "$json" 2>/dev/null)" = iPhone ]; then
          echo "$id"
          return 0
        fi
        j=$((j + 1))
      done
      return 1
    fi
    i=$((i + 1))
  done
  return 1
}

wanted=${POLYJOSE_SIMULATOR:-$device_name}
line=$(device_line "$wanted" | head -n 1)
if [ -z "$line" ]; then
  [ -z "${POLYJOSE_SIMULATOR:-}" ] || { echo "$me: no available Simulator device $POLYJOSE_SIMULATOR" >&2; exit 2; }
  xcrun simctl list runtimes -j >"$build_dir/runtimes.json"
  runtime=${POLYJOSE_SIM_RUNTIME:-$(newest_ios_runtime "$build_dir/runtimes.json")}
  [ -n "$runtime" ] || { echo "$me: no iOS Simulator runtime is installed (Xcode > Settings > Components)" >&2; exit 2; }
  device_type=$(first_iphone "$build_dir/runtimes.json" "$runtime") ||
    { echo "$me: the runtime $runtime is not installed or supports no iPhone" >&2; exit 2; }
  echo "==> create the Simulator device $device_name (${device_type##*.}, ${runtime##*.})" >&2
  xcrun simctl create "$device_name" "$device_type" "$runtime" >/dev/null
  line=$(device_line "$device_name" | head -n 1)
fi
udid=$(echo "$line" | sed -nE 's/.*\(([0-9A-F-]{36})\).*/\1/p')
[ -n "$udid" ] || { echo "$me: could not find the UDID of the Simulator device ($line)" >&2; exit 2; }

# --- build ------------------------------------------------------------------------------------

echo "==> build the app for the Simulator $udid (log: .build/logs/build.log)" >&2
if ! xcodebuild build "${container[@]}" -scheme PolyjoseExamples -configuration Debug \
  -destination "platform=iOS Simulator,id=$udid" \
  -derivedDataPath "$derived" -clonedSourcePackagesDirPath "$build_dir/SourcePackages" \
  >"$logs/build.log" 2>&1; then
  grep -E 'error:|\*\* BUILD FAILED \*\*' "$logs/build.log" | head -n 40 >&2 || true
  echo "$me: the build failed; the full log is .build/logs/build.log" >&2
  exit 1
fi
app=$derived/Build/Products/Debug-iphonesimulator/PolyjoseExamples.app

# --- boot, install, launch --------------------------------------------------------------------

booted_here=
launch_pid=
cleanup() {
  if [ -n "$launch_pid" ] && kill -0 "$launch_pid" 2>/dev/null; then
    xcrun simctl terminate "$udid" "$bundle_id" >/dev/null 2>&1 || true
    kill "$launch_pid" 2>/dev/null || true
  fi
  if [ -n "$booted_here" ]; then
    echo "==> shut down the Simulator $udid (booted by run.sh)" >&2
    xcrun simctl shutdown "$udid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

deadline=$(($(date +%s) + timeout))
timed_out() {
  echo "$me: no result within ${timeout} s (POLYJOSE_TIMEOUT)" >&2
  echo "POLYJOSE-VERIFY: 0/$expected_checks PASS (timeout)"
  exit 1
}

# within_deadline <command...>: runs the command, its output in .build/logs/simctl.log, and stops
# it at the deadline.
within_deadline() {
  "$@" >>"$logs/simctl.log" 2>&1 &
  local pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$(date +%s)" -ge "$deadline" ]; then
      kill "$pid" 2>/dev/null || true
      timed_out
    fi
    sleep 1
  done
  wait "$pid"
}

case "$line" in
*"(Booted)"*) echo "==> use the running Simulator $udid" >&2 ;;
*)
  echo "==> boot the Simulator $udid" >&2
  xcrun simctl boot "$udid"
  booted_here=1
  ;;
esac
within_deadline xcrun simctl bootstatus "$udid"
within_deadline xcrun simctl install "$udid" "$app"

echo "==> launch $bundle_id -autorun" >&2
out=$logs/app.log
: >"$out"
xcrun simctl launch --console-pty --terminate-running-process "$udid" "$bundle_id" -autorun >"$out" 2>&1 &
launch_pid=$!
while ! grep -q '^POLYJOSE-VERIFY: ' <(tr -d '\r' <"$out"); do
  if ! kill -0 "$launch_pid" 2>/dev/null; then break; fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    tr -d '\r' <"$out" | grep -E '^(# |PASS |FAIL |SKIP )' || true
    timed_out
  fi
  sleep 1
done

# The app exits by itself after the final line; give it a moment, then stop it.
for _ in 1 2 3 4 5; do kill -0 "$launch_pid" 2>/dev/null || break; sleep 1; done

tr -d '\r' <"$out" | grep -E '^(# |PASS |FAIL |SKIP |POLYJOSE-VERIFY: )' || true
final=$(tr -d '\r' <"$out" | grep -E '^POLYJOSE-VERIFY: ' | tail -n 1 || true)
if [ -z "$final" ]; then
  echo "$me: the app stopped before its final line (log: .build/logs/app.log)" >&2
  echo "POLYJOSE-VERIFY: 0/$expected_checks PASS (no result)"
  exit 1
fi
counts=$(echo "$final" | sed -nE 's/^POLYJOSE-VERIFY: ([0-9]+)\/([0-9]+) PASS( \([0-9]+ skipped\))?$/\1 \2/p')
passed=${counts% *}
ran=${counts#* }
[ -n "$counts" ] && [ "$passed" = "$ran" ] && [ "$ran" -gt 0 ]
