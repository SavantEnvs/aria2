#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# aria2's own cppunit suite (test/*Test.cc, ~975 tests: torrent/metalink/cookie/HTTP/JSON/
# XML-RPC/BitTorrent message/DHT/URI parsers and the rest), built by mayhem/build.sh with normal
# flags into mayhem/build-test/test/aria2c-offline (upstream's test objects with
# mayhem/cppunit_offline_main.cc as main(): it skips the two LPD multicast fixtures that need a
# network interface, since the suite runs offline). Its A2_TEST_DIR is relative to that directory, so run
# it from there. CppUnit's TextUi runner prints "OK (<n>)" when every test passes, or
# "Run: <n>   Failure total: <f+e>   Failures: <f>   Errors: <e>" otherwise; each assertion
# compares parsed values against expected ones, so a neutered program cannot produce either line with all passing.
RUNNER_DIR="$SRC/mayhem/build-test/test"
if [ ! -x "$RUNNER_DIR/aria2c-offline" ]; then
  echo "test runner $RUNNER_DIR/aria2c-offline missing — mayhem/build.sh must build it" >&2
  emit_ctrf "cppunit" 0 1 0
  exit 1
fi
log=$(mktemp)
( cd "$RUNNER_DIR" && ./aria2c-offline ) >"$log" 2>&1
rc=$?
summary=$(grep -aE '^OK \([0-9]+\)|^Run: +[0-9]+' "$log" | tail -1)
grep -aE -A3 '^Test name:' "$log" | tail -60   # each failing test, if any
grep -aE '^(OK \(|Run: |Failures !!!|skipped )' "$log"
rm -f "$log"
if [[ "$summary" =~ ^OK\ \(([0-9]+)\) ]] && [ "$rc" -eq 0 ]; then
  emit_ctrf "cppunit" "${BASH_REMATCH[1]}" 0 0
elif [[ "$summary" =~ ^Run:\ +([0-9]+)\ +Failure\ total:\ +([0-9]+) ]]; then
  run=${BASH_REMATCH[1]}; bad=${BASH_REMATCH[2]}
  emit_ctrf "cppunit" $(( run - bad )) "$bad" 0
else
  echo "cppunit runner exited $rc without a result line" >&2
  emit_ctrf "cppunit" 0 1 0
fi
