#!/usr/bin/env bash
#
# mayhem/test.sh — run MTA:SA's own gtest suite (Tests/client: sync structures, SharedUtil, vector/matrix
# math, ...) as built by mayhem/build.sh with normal flags. Results are mapped to CTRF.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

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

RUNNER="$SRC/mayhem/_build/mta_tests"
if [ ! -x "$RUNNER" ]; then
  echo "test runner $RUNNER missing: mayhem/build.sh did not build it" >&2
  emit_ctrf "gtest" 0 1 0
  exit 1
fi

out=$(timeout 600 "$RUNNER" 2>&1)
rc=$?
printf '%s\n' "$out"

passed=$(printf '%s\n' "$out" | grep -c '^\[       OK \] ')
failed=$(printf '%s\n' "$out" | grep -c '^\[  FAILED  \] .*(.* ms)$')
skipped=$(printf '%s\n' "$out" | grep -c '^\[  SKIPPED \] .*(.* ms)$')
ran=$(printf '%s\n' "$out" | sed -n 's/^\[==========\] \([0-9]*\) tests\{0,1\} from .* ran\..*/\1/p' | tail -1)

# A run that exited non-zero without a failed assertion, or that never reached gtest's closing summary
# (a runner replaced by exit(0), a crash mid-suite), must not read as a pass.
if [ "$rc" -ne 0 ] && [ "$failed" -eq 0 ]; then failed=1; fi
if [ -z "$ran" ] || [ "$ran" -eq 0 ] || [ $(( passed + failed + skipped )) -ne "$ran" ]; then failed=$(( failed + 1 )); fi

emit_ctrf "gtest" "$passed" "$failed" "$skipped"
