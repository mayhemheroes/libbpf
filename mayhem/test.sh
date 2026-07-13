#!/usr/bin/env bash
#
# mayhem/test.sh — run libbpf's functional oracle (built by mayhem/build.sh).
#
# NOTE: upstream libbpf ships NO in-repo runnable test suite — its CI (libbpf-ci)
# boots a VM with a custom kernel and runs the KERNEL tree's selftests/bpf, which
# needs KVM/root/kernel sources (impossible in the commit image). The suite run
# here is the AUTHORED known-answer oracle mayhem/libbpf_oracle.c (18 behavioral
# assertions over libbpf's ELF/BTF parsing API — the same paths the fuzz target
# drives). See that file's header for the full rationale.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
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

ORACLE=/mayhem/libbpf-oracle
BPF_OBJ="$SRC/build-test/oracle_prog.bpf.o"
EXPECTED=18   # the oracle prints exactly 18 PASS/FAIL check lines

if [ ! -x "$ORACLE" ] || [ ! -f "$BPF_OBJ" ]; then
  echo "FATAL: oracle runner or BPF object missing — mayhem/build.sh must build them" >&2
  emit_ctrf "libbpf-oracle" 0 "$EXPECTED"
  exit 1
fi

out="$("$ORACLE" "$BPF_OBJ" 2>&1)"; rc=$?
printf '%s\n' "$out"

passed=$(printf '%s\n' "$out" | grep -c '^PASS ' || true)
[ "$passed" -gt "$EXPECTED" ] && passed=$EXPECTED
failed=$(( EXPECTED - passed ))
# a nonzero exit with all checks apparently passing still counts as a failure
[ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && failed=1

emit_ctrf "libbpf-oracle" "$passed" "$failed"
