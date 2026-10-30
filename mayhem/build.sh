#!/usr/bin/env bash
#
# mayhem/build.sh — build the MTA:SA fuzz harnesses and its unit-test oracle.
#
# MTA's own build is a Windows-centric premake tree that needs a game SDK and a pile of network-fetched
# dependencies, so this compiles just the portable Shared/ sources the harnesses exercise (SharedUtil, the
# network sync structures, the XML layer over vendored tinyxml2), straight from the checkout. Nothing is
# fetched: every input is in the repo, so the script runs offline and can be re-run on a dirty tree.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/_build"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/sa" "$B/test"

INC="-I$SRC/mayhem/shim -I$SRC/Shared/sdk -I$SRC/Tests/client -I$SRC/vendor -I$SRC/vendor/sparsehash/src"
XMLINC="-I$SRC/Shared/XML -I$SRC/Shared -I$SRC/vendor/tinyxml2"
GTESTINC="-I$SRC/vendor/googletest/include -I$SRC/vendor/googletest"
DEFS="-DSHARED_UTIL_WITH_HASH_MAP"
STD="-std=c++20 -w"

CMDS="$B/compile-commands.txt"
: > "$CMDS"
# add <outdir> <flags> <source>: queue one compile
add() { printf '%s -c %s -o %s/%s.o\n' "$CXX $STD $2 $INC $XMLINC $GTESTINC $DEFS" "$3" "$1" "$(basename "$3")" >> "$CMDS"; }

# Every fuzz/standalone object is sanitized with DWARF 3. The network sync structures live in #pragma
# pack(1) headers, so their ISyncStructure vptr members are misaligned by design (harmless on x86, and it
# would halt every input on the first constructor call): relax just UBSan's alignment check. ASan and the
# rest of UBSan stay halting.
FUZZFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fno-sanitize=alignment"

XML_SRCS="$(ls "$SRC"/Shared/XML/CXML*.cpp) $SRC/vendor/tinyxml2/tinyxml2.cpp"
COMMON_SRCS="$SRC/mayhem/sharedutil_impl.cc $SRC/mayhem/lsan_off.cc"
HARNESS_SRCS="$SRC/mayhem/fuzz_sync_structs.cc $SRC/mayhem/fuzz_sharedutil.cc $SRC/mayhem/fuzz_xml.cc"

for s in $COMMON_SRCS $HARNESS_SRCS $XML_SRCS; do
    add "$B/fuzz" "$FUZZFLAGS $LIB_FUZZING_ENGINE" "$s"
    add "$B/sa" "$FUZZFLAGS" "$s"
done

# The unit-test oracle: NORMAL flags (no sanitizers). -O0 matters: SRotationDegreesSync's negative-angle
# test relies on float->unsigned-short wraparound that the optimizer is free to fold differently.
TESTFLAGS="-O0 $COVERAGE_FLAGS -DGTEST_HAS_PTHREAD=0"
for s in $(ls "$SRC"/Tests/client/*.cpp | grep -v -e PdbDirectory -e SharedUtil_Impl -e SharedUtilHash_Tests) \
         "$SRC/vendor/googletest/src/gtest-all.cc" "$SRC/mayhem/sharedutil_impl.cc"; do
    add "$B/test" "$TESTFLAGS" "$s"
done

xargs -P "$MAYHEM_JOBS" -d '\n' -I{} sh -c '{}' < "$CMDS"

# Standalone driver, compiled as C so its LLVMFuzzerTestOneInput reference keeps C linkage.
# shellcheck disable=SC2086
"$CC" $FUZZFLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/sa/standalone_main.o"

link_harness() { # <name> <extra objects...>
    local name="$1"; shift
    local fuzzobjs="" saobjs="" o
    for o in "$@"; do fuzzobjs="$fuzzobjs $B/fuzz/$o.o"; saobjs="$saobjs $B/sa/$o.o"; done
    # shellcheck disable=SC2086
    "$CXX" $FUZZFLAGS $LIB_FUZZING_ENGINE "$B/fuzz/$name.cc.o" $fuzzobjs -o "$SRC/$name"
    # shellcheck disable=SC2086
    "$CXX" $FUZZFLAGS "$B/sa/$name.cc.o" "$B/sa/standalone_main.o" $saobjs -o "$SRC/$name-standalone"
}

link_harness fuzz_sync_structs sharedutil_impl.cc lsan_off.cc
link_harness fuzz_sharedutil sharedutil_impl.cc lsan_off.cc
xmlobjs="lsan_off.cc"
for s in $XML_SRCS; do xmlobjs="$xmlobjs $(basename "$s")"; done
# shellcheck disable=SC2086
link_harness fuzz_xml $xmlobjs

# shellcheck disable=SC2046
"$CXX" $COVERAGE_FLAGS $(ls "$B"/test/*.o) -o "$B/mta_tests"
