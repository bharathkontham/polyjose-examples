#!/usr/bin/env bash
# Builds the app, runs every check of ../CATALOG.md on an Android device or emulator without a
# tap, and prints the lines the app writes to logcat (tag POLYJOSE): one line per check, then
# `POLYJOSE-VERIFY: P/R PASS`. Exits 0 only when every check passed.
#
#   ./run.sh                               against the published dev.polyjose:polyjose
#                                          (the version pin is in build.gradle.kts)
#   POLYJOSE_SRC=../../polyjose ./run.sh   against a local polyjose checkout (see build.sh)
#
# Which device it runs on:
#   ANDROID_SERIAL set   that device: a phone over USB, or an emulator you started (`adb devices`
#                        lists the serials). run.sh never stops it.
#   otherwise            the emulator running the AVD named POLYJOSE_AVD (default polyjose-api34).
#                        When none is running, run.sh starts that AVD without a window, on console
#                        port POLYJOSE_EMULATOR_PORT (default 5580, serial emulator-5580), and stops
#                        that emulator, and only that one, when it ends.
#
# Environment:
#   JAVA_HOME              a JDK, 17 or later (Gradle runs on it)
#   ANDROID_HOME           the Android SDK, with platform-tools, the emulator and the AVD's image
#   POLYJOSE_TIMEOUT       seconds to wait for the result line once the app starts (default 300)
#   POLYJOSE_BOOT_TIMEOUT  seconds to wait for a started emulator to boot (default 300)
# Build output goes to stderr; the check lines go to stdout.
set -euo pipefail
cd "$(dirname "$0")"

app_id=dev.polyjose.examples
activity=$app_id/.app.MainActivity
apk=build/outputs/apk/debug/polyjose-examples-android-debug.apk
checks=34 # the number of checks in CATALOG.md, for the timeout line
avd=${POLYJOSE_AVD:-polyjose-api34}
port=${POLYJOSE_EMULATOR_PORT:-5580}
timeout=${POLYJOSE_TIMEOUT:-300}
boot_timeout=${POLYJOSE_BOOT_TIMEOUT:-300}

[ -n "${ANDROID_HOME:-}" ] || { echo "run.sh: set ANDROID_HOME to the Android SDK" >&2; exit 2; }
[ -n "${JAVA_HOME:-}" ] || { echo "run.sh: set JAVA_HOME to a JDK (17 or later)" >&2; exit 2; }
adb=$ANDROID_HOME/platform-tools/adb
emulator=$ANDROID_HOME/emulator/emulator
[ -x "$adb" ] || { echo "run.sh: no adb in $ANDROID_HOME/platform-tools" >&2; exit 2; }

timed_out() {
  echo "run.sh: $1" >&2
  echo "POLYJOSE-VERIFY: 0/$checks PASS (timeout)"
  exit 1
}

# The emulator this script started, if any; stopped on exit, by its serial (then its PID).
emu_pid=""
serial=""
stop_emulator() {
  [ -n "$emu_pid" ] || return 0
  "$adb" -s "$serial" emu kill >/dev/null 2>&1 || true
  for _ in $(seq 1 30); do kill -0 "$emu_pid" 2>/dev/null || return 0; sleep 1; done
  kill "$emu_pid" 2>/dev/null || true
}
trap stop_emulator EXIT

# The serial of the attached emulator that runs AVD $1, if there is one.
emulator_running() {
  local s name
  for s in $("$adb" devices | awk 'NR > 1 && $2 == "device" && $1 ~ /^emulator-/ { print $1 }'); do
    name=$("$adb" -s "$s" emu avd name 2>/dev/null | head -n 1 | tr -d '\r')
    [ "$name" = "$1" ] && { echo "$s"; return 0; }
  done
  return 0
}

# 1. Pick the device; start the emulator now, so it boots while the app builds.
if [ -n "${ANDROID_SERIAL:-}" ]; then
  serial=$ANDROID_SERIAL
  [ "$("$adb" -s "$serial" get-state 2>/dev/null)" = device ] \
    || { echo "run.sh: ANDROID_SERIAL=$serial is not an attached device (adb devices)" >&2; exit 2; }
  where="device $serial"
else
  serial=$(emulator_running "$avd")
  if [ -z "$serial" ]; then
    [ -x "$emulator" ] || { echo "run.sh: no emulator in $ANDROID_HOME/emulator" >&2; exit 2; }
    if "$adb" devices | awk 'NR > 1 { print $1 }' | grep -qx "emulator-$port"; then
      echo "run.sh: emulator-$port runs another AVD; set POLYJOSE_EMULATOR_PORT to a free even port" >&2
      exit 2
    fi
    serial=emulator-$port
    mkdir -p build
    echo "==> starting AVD $avd as $serial (no window; log in build/emulator.log)" >&2
    "$emulator" -avd "$avd" -port "$port" -no-window -no-audio -no-boot-anim -no-snapshot-save \
      >build/emulator.log 2>&1 &
    emu_pid=$!
  fi
  where="device $serial, AVD $avd"
fi

# 2. Build.
if [ -n "${POLYJOSE_SRC:-}" ]; then
  ./build.sh >&2
else
  echo "==> ./gradlew assembleDebug (dev.polyjose:polyjose from Maven Central)" >&2
  ./gradlew --quiet assembleDebug >&2
fi
[ -f "$apk" ] || { echo "run.sh: no $apk after the build" >&2; exit 1; }

# 3. Wait until the device has booted.
deadline=$((SECONDS + boot_timeout))
until [ "$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do
  if [ -n "$emu_pid" ] && ! kill -0 "$emu_pid" 2>/dev/null; then
    echo "run.sh: the emulator exited; see build/emulator.log" >&2
    emu_pid=""
    exit 1
  fi
  [ "$SECONDS" -lt "$deadline" ] || timed_out "$serial did not boot within $boot_timeout s"
  sleep 2
done

# 4. Install, clear the log so no line of an earlier run is read, start the run.
echo "==> installing on $serial" >&2
"$adb" -s "$serial" install -r "$apk" >/dev/null
"$adb" -s "$serial" shell am force-stop "$app_id"
"$adb" -s "$serial" logcat -c || true
"$adb" -s "$serial" shell am start -n "$activity" --ez autorun true >/dev/null

# 5. Print the app's lines as they arrive, until the result line.
echo "==> running the checks on $where" >&2
printed=0
result=""
deadline=$((SECONDS + timeout))
while [ -z "$result" ]; do
  lines=$("$adb" -s "$serial" logcat -d -v raw -s POLYJOSE:I | tr -d '\r' \
    | grep -E '^(# |PASS |FAIL |SKIP |POLYJOSE-VERIFY: )' || true)
  count=$(printf '%s' "$lines" | grep -c '' || true)
  if [ "$count" -gt "$printed" ]; then
    printf '%s\n' "$lines" | sed -n "$((printed + 1)),\$p"
    printed=$count
  fi
  result=$(printf '%s\n' "$lines" | grep '^POLYJOSE-VERIFY: ' | tail -n 1 || true)
  [ -n "$result" ] && break
  [ "$SECONDS" -lt "$deadline" ] || timed_out "no result line within $timeout s (adb -s $serial logcat -s POLYJOSE)"
  sleep 1
done

# 6. Exit 0 only when P = R and R > 0.
if [[ "$result" =~ ^POLYJOSE-VERIFY:\ ([0-9]+)/([0-9]+)\ PASS ]] \
  && [ "${BASH_REMATCH[1]}" = "${BASH_REMATCH[2]}" ] && [ "${BASH_REMATCH[2]}" -gt 0 ]; then
  exit 0
fi
exit 1
