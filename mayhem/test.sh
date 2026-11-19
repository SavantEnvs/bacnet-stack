#!/usr/bin/env bash
#
# mayhem/test.sh — RUN bacnet-stack's own ztest suite (built by mayhem/build.sh in test/build) and a
# known-answer probe. Does not compile anything. A test binary that exits 0 without printing its
# PASS lines (a no-op) contributes nothing, so the PASS-line floor and the byte-exact KAT both fail.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"
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

TESTDIR="$SRC/test/build"
PASS_FLOOR=300
passed=0 failed=0

mapfile -t bins < <(find "$TESTDIR" -type f -name 'test_*' -perm -u+x | sort)
if [ "${#bins[@]}" -eq 0 ]; then
  echo "no test_* binaries under $TESTDIR (mayhem/build.sh should have built them)" >&2
  emit_ctrf ztest 0 1
  exit 1
fi

for b in "${bins[@]}"; do
  out=$(cd "$(dirname "$b")" && timeout 120 "$b" 2>&1)
  rc=$?
  p=$(printf '%s\n' "$out" | grep -c '^ PASS - ')
  f=$(printf '%s\n' "$out" | grep -c '^ FAIL - ')
  passed=$((passed + p))
  failed=$((failed + f))
  if [ "$rc" -ne 0 ] && [ "$f" -eq 0 ]; then
    echo "FAIL: $b exited $rc without a FAIL line" >&2
    failed=$((failed + 1))
  fi
  if [ "$f" -ne 0 ] || [ "$rc" -ne 0 ]; then
    printf '%s\n' "$out" | tail -20
  fi
done

if [ "$passed" -lt "$PASS_FLOOR" ]; then
  echo "only $passed ztest cases passed (expected at least $PASS_FLOOR)" >&2
  failed=$((failed + 1))
fi

# Known-answer probe: BACnet encodings with values fixed by the standard (ASHRAE 135 clause 20).
expected='UNSIGNED_1000: 22 03 E8
SIGNED_-2: 31 FE
REAL_1.0: 44 3F 80 00 00
CHARSTRING_abc: 74 00 61 62 63
WHOIS_10_20: 10 08 09 0A 19 14
RP_AI5_PV: 00 05 01 0C 0C 00 00 00 05 19 55
RP_DECODE: 7 type=0 instance=5 property=85'
actual=$("$TESTDIR/kat_probe" 2>&1)
if [ "$actual" = "$expected" ]; then
  echo "KAT probe: 7/7 known answers match"
  passed=$((passed + 7))
else
  echo "KAT probe mismatch" >&2
  printf 'expected:\n%s\nactual:\n%s\n' "$expected" "$actual" >&2
  failed=$((failed + 1))
fi

echo "ztest: $passed passed, $failed failed across ${#bins[@]} test binaries"
emit_ctrf "ztest+kat" "$passed" "$failed"
