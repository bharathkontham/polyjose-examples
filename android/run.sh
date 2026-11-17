#!/usr/bin/env bash
# Builds the app, runs every check of ../CATALOG.md on an Android device or emulator without a
# tap, and prints the lines the app writes to logcat (tag POLYJOSE): one line per check, then
# `POLYJOSE-VERIFY: P/R PASS`. Exits 0 only when every check that ran passed and every check of
# the catalog either ran or was skipped (CATALOG.md, "Output and pass rule").
#
#   ./run.sh                               against the published dev.polyjose:polyjose
#                                          (the version pin is in build.gradle.kts)
#   POLYJOSE_SRC=../../polyjose ./run.sh   against a local polyjose checkout (see build.sh)
#   ./run.sh --playground                  the playground's demo walk instead of the checks
#                                          (../PLAYGROUND.md, "Demo walk"): prints one line per
#                                          step and `POLYJOSE-PLAYGROUND: N/M OK`, and exits 0 only
#                                          when N = M and no captured POLYJOSE line holds a private
#                                          or symmetric JWK member. The whole capture is kept in
#                                          build/playground-logcat.txt.
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
#   POLYJOSE_TIMEOUT       seconds to wait for the result line once the app starts (default 300;
#                          900 with --playground)
#   POLYJOSE_BOOT_TIMEOUT  seconds to wait for a started emulator to boot (default 300)
# Build output goes to stderr; the check lines go to stdout.
set -euo pipefail
cd "$(dirname "$0")"

mode=checks
case "${1:-}" in
  "") ;;
  --playground) mode=playground ;;
  *) echo "usage: run.sh [--playground]" >&2; exit 2 ;;
esac

app_id=dev.polyjose.examples
activity=$app_id/.app.MainActivity
apk=build/outputs/apk/debug/polyjose-examples-android-debug.apk
expected_checks=44 # N: the number of Android checks CATALOG.md lists for the pinned polyjose (0.4.0)
min_ran=34         # checks 1-34 never skip, so at least that many must run
avd=${POLYJOSE_AVD:-polyjose-api34}
port=${POLYJOSE_EMULATOR_PORT:-5580}
if [ "$mode" = playground ]; then timeout=${POLYJOSE_TIMEOUT:-900}; else timeout=${POLYJOSE_TIMEOUT:-300}; fi
boot_timeout=${POLYJOSE_BOOT_TIMEOUT:-300}

[ -n "${ANDROID_HOME:-}" ] || { echo "run.sh: set ANDROID_HOME to the Android SDK" >&2; exit 2; }
[ -n "${JAVA_HOME:-}" ] || { echo "run.sh: set JAVA_HOME to a JDK (17 or later)" >&2; exit 2; }
adb=$ANDROID_HOME/platform-tools/adb
emulator=$ANDROID_HOME/emulator/emulator
[ -x "$adb" ] || { echo "run.sh: no adb in $ANDROID_HOME/platform-tools" >&2; exit 2; }

timed_out() {
  echo "run.sh: $1" >&2
  if [ "$mode" = playground ]; then echo "POLYJOSE-PLAYGROUND: 0/0 OK (timeout)"; else echo "POLYJOSE-VERIFY: 0/$expected_checks PASS (timeout)"; fi
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
# The `adb logcat` that --playground starts to capture every line, stopped by its PID.
capture_pid=""
cleanup() {
  [ -z "$capture_pid" ] || kill "$capture_pid" 2>/dev/null || true
  stop_emulator
}
trap cleanup EXIT

# The serial of the attached emulator that runs AVD $1, if there is one.
emulator_running() {
  local s name
  for s in $("$adb" devices | awk 'NR > 1 && $2 == "device" && $1 ~ /^emulator-/ { print $1 }'); do
    name=$("$adb" -s "$s" emu avd name 2>/dev/null | head -n 1 | tr -d '\r')
    [ "$name" = "$1" ] && { echo "$s"; return 0; }
  done
  return 0
}

# --playground, after step 4's `logcat -c`: start the demo walk, capture every POLYJOSE line until
# the walk's last line, and apply its pass rule (PLAYGROUND.md "Demo walk", "Secrets").
playground_walk() {
  mkdir -p build
  local capture=build/playground-logcat.txt
  "$adb" -s "$serial" logcat -v raw -s POLYJOSE:I >"$capture" 2>/dev/null &
  capture_pid=$!
  "$adb" -s "$serial" shell am start -n "$activity" --ez playgroundDemo true >/dev/null
  echo "==> running the playground demo walk on $where (every line in $capture)" >&2
  local printed=0 count final="" lines
  local deadline=$((SECONDS + timeout))
  while [ -z "$final" ]; do
    lines=$(tr -d '\r' <"$capture" | grep -E '^(# |PLAYGROUND |POLYJOSE-PLAYGROUND: )' || true)
    count=$(printf '%s' "$lines" | grep -c '' || true)
    if [ "$count" -gt "$printed" ]; then
      printf '%s\n' "$lines" | sed -n "$((printed + 1)),\$p"
      printed=$count
    fi
    final=$(printf '%s\n' "$lines" | grep '^POLYJOSE-PLAYGROUND: ' | tail -n 1 || true)
    [ -n "$final" ] && break
    [ "$SECONDS" -lt "$deadline" ] || timed_out "no POLYJOSE-PLAYGROUND line within $timeout s (adb -s $serial logcat -s POLYJOSE)"
    sleep 2
  done
  sleep 1
  kill "$capture_pid" 2>/dev/null || true
  wait "$capture_pid" 2>/dev/null || true
  capture_pid=""
  local ok_lines fail_lines n m status=0
  ok_lines=$(printf '%s\n' "$lines" | grep -c '^PLAYGROUND OK ' || true)
  fail_lines=$(printf '%s\n' "$lines" | grep -c '^PLAYGROUND FAIL ' || true)
  if [[ "$final" =~ ^POLYJOSE-PLAYGROUND:\ ([0-9]+)/([0-9]+)\ OK$ ]]; then
    n=${BASH_REMATCH[1]}
    m=${BASH_REMATCH[2]}
    if [ "$n" != "$ok_lines" ] || [ "$m" != "$((ok_lines + fail_lines))" ]; then
      echo "run.sh: the final line does not match the $ok_lines OK and $fail_lines FAIL lines" >&2
      status=1
    fi
    [ "$n" = "$m" ] && [ "$m" -gt 0 ] || status=1
  else
    echo "run.sh: unexpected final line: $final" >&2
    status=1
  fi
  # Every LOG line the app mirrored must be in the capture, or the secrets check would miss some.
  local mirrored captured
  mirrored=$(printf '%s\n' "$lines" | sed -n 's/^# LOG lines mirrored: \([0-9]*\)$/\1/p' | tail -n 1)
  captured=$(tr -d '\r' <"$capture" | grep -c '^LOG ' || true)
  if [ -z "$mirrored" ] || [ "$captured" -lt "$mirrored" ]; then
    echo "run.sh: the capture holds $captured LOG lines; the app mirrored ${mirrored:-an unknown number}" >&2
    status=1
  fi
  # The secrets check: no private or symmetric JWK member in any captured line, also across the
  # `LOG <tap>.<step> + ` continuation lines, joined back first.
  local secrets
  secrets=$(tr -d '\r' <"$capture" | awk '
    /^LOG [0-9]+\.[0-9]+ \+ / { sub(/^LOG [0-9]+\.[0-9]+ \+ /, ""); line = line $0; next }
    { if (NR > 1) print line; line = $0 }
    END { print line }' | grep -E '"(d|p|q|dp|dq|qi|oth|k)"[[:space:]]*:' || true)
  if [ -n "$secrets" ]; then
    echo "run.sh: the secrets check found $(printf '%s\n' "$secrets" | grep -c '') captured lines with a private or symmetric JWK member" >&2
    status=1
  else
    echo "==> secrets check: no private or symmetric JWK member in $(grep -c '' "$capture") captured lines" >&2
  fi
  exit "$status"
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
if [ "$mode" = playground ]; then
  playground_walk # below; it exits
fi
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

# 6. The pass rule (CATALOG.md, "Output and pass rule"): exit 0 only when P = R and R + S = N,
# where P and R come from the final line, S is the number of SKIP lines and N is expected_checks.
# The final line must also agree with the lines above it, so a skip can't hide a missing check.
count_lines() { printf '%s\n' "$lines" | grep -c "^$1 " || true; }
pass_lines=$(count_lines PASS)
fail_lines=$(count_lines FAIL)
skip_lines=$(count_lines SKIP)
duplicates=$(printf '%s\n' "$lines" | awk '/^(PASS|FAIL|SKIP) / { sub(/:$/, "", $2); print $2 }' | sort | uniq -d)
if [ -n "$duplicates" ]; then
  echo "run.sh: duplicate check ids: $(printf '%s' "$duplicates" | tr '\n' ' ')" >&2
  exit 1
fi
if [[ "$result" =~ ^POLYJOSE-VERIFY:\ ([0-9]+)/([0-9]+)\ PASS(\ \(([0-9]+)\ skipped\))?$ ]]; then
  passed=${BASH_REMATCH[1]}
  ran=${BASH_REMATCH[2]}
  skipped=${BASH_REMATCH[4]:-0}
  if [ "$passed" != "$pass_lines" ] || [ "$ran" != "$((pass_lines + fail_lines))" ] || [ "$skipped" != "$skip_lines" ]; then
    echo "run.sh: the final line does not match the $pass_lines PASS, $fail_lines FAIL and $skip_lines SKIP lines" >&2
    exit 1
  fi
  [ "$((ran + skip_lines))" = "$expected_checks" ] \
    || echo "run.sh: $ran checks ran and $skip_lines were skipped; CATALOG.md lists $expected_checks" >&2
  [ "$ran" -ge "$min_ran" ] || echo "run.sh: $ran checks ran; checks 1-$min_ran never skip" >&2
  [ "$passed" = "$ran" ] && [ "$((ran + skip_lines))" = "$expected_checks" ] && [ "$ran" -ge "$min_ran" ] && exit 0
else
  echo "run.sh: unexpected final line: $result" >&2
fi
exit 1
