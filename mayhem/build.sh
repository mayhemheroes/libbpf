#!/usr/bin/env bash
#
# mayhem/build.sh — build libbpf's fuzz harness (bpf-object-fuzzer) + the oracle test build.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# exports the build contract: CC, CXX, LIB_FUZZING_ENGINE, SANITIZER_FLAGS, DEBUG_FLAGS, SRC.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

FUZZ_DIR="$SRC/build-fuzz"
TEST_DIR="$SRC/build-test"
mkdir -p "$FUZZ_DIR" "$TEST_DIR"

COMMON_INC="-Isrc -Iinclude -Iinclude/uapi -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"

# 1) Sanitized + coverage-instrumented static libbpf for the fuzz targets.
#    -fsanitize=fuzzer-no-link instruments the LIBRARY code for libFuzzer coverage; the final
#    fuzzer links $LIB_FUZZING_ENGINE, the standalone links fuzzer-no-link (no_main runtime).
FUZZ_CFLAGS="-O1 -fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=fuzzer-no-link $SANITIZER_FLAGS $DEBUG_FLAGS"
make -C src -j"$MAYHEM_JOBS" OBJDIR="$FUZZ_DIR" BUILD_STATIC_ONLY=y \
    CC="$CC" CFLAGS="$FUZZ_CFLAGS" V=1

$CC $FUZZ_CFLAGS $COMMON_INC -c fuzz/bpf-object-fuzzer.c -o "$FUZZ_DIR/bpf-object-fuzzer.o"
$CC $FUZZ_CFLAGS $LIB_FUZZING_ENGINE \
    "$FUZZ_DIR/bpf-object-fuzzer.o" "$FUZZ_DIR/libbpf.a" -lelf -lz \
    -o /mayhem/bpf-object-fuzzer

# Standalone run-once reproducer (no libFuzzer main; fuzzer-no-link pulls the no_main runtime
# so the sancov-instrumented objects still link).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_DIR/standalone_main.o"
$CC $FUZZ_CFLAGS \
    "$FUZZ_DIR/standalone_main.o" "$FUZZ_DIR/bpf-object-fuzzer.o" "$FUZZ_DIR/libbpf.a" -lelf -lz \
    -o /mayhem/bpf-object-fuzzer-standalone

# 2) Oracle/test build with the project's NORMAL flags (independent, unsanitized) so
#    mayhem/test.sh only RUNS it.
TEST_CFLAGS="-g -O2 $COVERAGE_FLAGS"
make -C src -j"$MAYHEM_JOBS" OBJDIR="$TEST_DIR" BUILD_STATIC_ONLY=y \
    CC="$CC" CFLAGS="$TEST_CFLAGS" V=1

$CC $TEST_CFLAGS $COMMON_INC -c mayhem/libbpf_oracle.c -o "$TEST_DIR/libbpf_oracle.o"
$CC $TEST_CFLAGS "$TEST_DIR/libbpf_oracle.o" "$TEST_DIR/libbpf.a" -lelf -lz \
    -o /mayhem/libbpf-oracle

# 3) A known BPF object for the oracle's known-answer checks (clang's built-in bpf target).
$CC -g -O2 -target bpf -c mayhem/oracle_prog.bpf.c -o "$TEST_DIR/oracle_prog.bpf.o"

echo "build.sh: done"
