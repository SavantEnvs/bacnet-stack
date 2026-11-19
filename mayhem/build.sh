#!/usr/bin/env bash
#
# mayhem/build.sh — build bacnet-stack's fuzz harnesses (sanitized library + one binary per harness,
# plus a -standalone reproducer each) and, separately, the project's own ztest unit tests.
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem, air-gapped and re-runnable.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT=/mayhem
B="$SRC/build/fuzz"   # `build/*` is gitignored upstream; build.sh recreates it on every run

# 1) The library, sanitized, with SanCov edges on the fuzzed code (-fsanitize=fuzzer-no-link is
#    unconditional: without it Mayhem sees 0 edges in the library). CMake picks up $CC.
#    - Release type with -O1 (no -DNDEBUG, no DEBUG_ENABLED chatter); asserts stay live.
#    - BBMD6_ENABLED stays at its default 0: upstream's h_bbmd6.c does not compile with it set to 1.
#    - BACNET_BACKUP_RESTORE=OFF: no atomic-file handlers, so the NPDU target does no file I/O.
cmake -S . -B "$B" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS_RELEASE=-O1 \
    -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -Wno-error" \
    -DBACNET_STACK_BUILD_APPS=OFF \
    -DBACNET_BACKUP_RESTORE=OFF \
    -DBACDL_BIP=ON -DBACDL_BIP6=ON -DBACDL_ZIGBEE=OFF -DBACDL_MSTP=OFF -DBACDL_BSC=OFF

cmake --build "$B" -j"$MAYHEM_JOBS" --target bacnet-stack
LIB="$B/libbacnet-stack.a"

# Harness-side flags: must match the library's definitions (struct layouts depend on them).
HDEFS="-DBACNET_PROTOCOL_REVISION=28 -DBACDL_BIP -DBACDL_BIP6 -DBAC_ROUTING \
 -DBACNET_SEGMENTATION_ENABLED=1 -DBACNET_PROPERTY_LISTS=1 -DBACNET_ADDRESS_CACHE \
 -DBACNET_STACK_STATIC_DEFINE -DBACNET_STACK_DEPRECATED_DISABLE -DPRINT_ENABLED=1 \
 -DBACNET_PORT=linux"
INC="-I$SRC/src -I$SRC/ports/linux -I$SRC/ports/posix"
CFLAGS_H="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -Wno-error $HDEFS $INC"

# Sources that upstream's CMake leaves out of the library (MS/TP, BACnet/SC, cJSON and the
# server-basic device) but the harnesses need. Compiled once, with the same flags.
EXTRA="$B/extra"
mkdir -p "$EXTRA"
compile_extra() {
    local obj="$EXTRA/$(basename "$1" .c).o"
    $CC $CFLAGS_H -c "$SRC/$1" -o "$obj"
}
for f in \
    src/bacnet/basic/sys/cJSON.c \
    src/bacnet/datalink/bsc/bvlc-sc.c \
    src/bacnet/datalink/dlmstp.c src/bacnet/datalink/mstp.c \
    src/bacnet/basic/server/bacnet_basic.c src/bacnet/basic/server/bacnet_device.c; do
    compile_extra "$f"
done
# crc.c / cobs.c / mstptext.c may or may not already be in the library
for f in src/bacnet/datalink/crc.c src/bacnet/datalink/cobs.c src/bacnet/datalink/mstptext.c; do
    if ! ar t "$LIB" | grep -q "^$(basename "$f").o\$"; then compile_extra "$f"; fi
done
OBJ_MSTP="$EXTRA/dlmstp.o $EXTRA/mstp.o"
for f in crc cobs mstptext; do [ -f "$EXTRA/$f.o" ] && OBJ_MSTP="$OBJ_MSTP $EXTRA/$f.o"; done

# LeakSanitizer is switched off at build time for every binary (leaks are not what is fuzzed here).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$EXTRA/lsan_off.o"

# 2) Each harness twice: libFuzzer, and a run-once -standalone reproducer.
build_harness() {
    local name="$1"; shift
    local src="$SRC/mayhem/$name/$name.c"
    $CC $CFLAGS_H $LIB_FUZZING_ENGINE "$src" "$@" "$EXTRA/lsan_off.o" "$LIB" -lm -lpthread -o "$OUT/$name"
    $CC $CFLAGS_H "$STANDALONE_FUZZ_MAIN" "$src" "$@" "$EXTRA/lsan_off.o" "$LIB" -lm -lpthread -o "$OUT/$name-standalone"
}
build_harness fuzz_decoders
build_harness fuzz_bacapp_text
build_harness fuzz_cjson "$EXTRA/cJSON.o"
build_harness fuzz_bvlc
build_harness fuzz_bvlc6
build_harness fuzz_bvlc_sc "$EXTRA/bvlc-sc.o"
build_harness fuzz_mstp $OBJ_MSTP
build_harness fuzz_npdu "$EXTRA/bacnet_basic.o" "$EXTRA/bacnet_device.o"
# The gateway (apps/gateway): routing_npdu_handler() over device.c + gw_device.c, all in the library
build_harness fuzz_gateway

# 2b) Upstream's own libFuzzer harness (apps/fuzz-libfuzzer, `make fuzz-libfuzzer`), wrapped by
#     mayhem/fuzz_libfuzzer/fuzz_libfuzzer.c for a per-input router-table reset. It is NOT linked
#     against the CMake library: like upstream, it gets the source set and the defines of
#     apps/fuzz-libfuzzer/Makefile + apps/lib (BACDL=bip, BBMD=full, -DFUZZING=1), with our
#     sanitizer and DWARF flags in place of upstream's -fsanitize=fuzzer,address -g3 -Og.
RB="$B/router"
mkdir -p "$RB/obj"
RDEFS="-DBACDL_BIP=1 -DBBMD_ENABLED=1 -DBBMD_CLIENT_ENABLED -DWEAK_FUNC= -DINTRINSIC_REPORTING \
 -DPRINT_ENABLED=1 -DBACAPP_ALL -DBACNET_TIME_MASTER -DBACNET_BACKUP_RESTORE -DBACNET_ADDRESS_CACHE \
 -DBACNET_PROPERTY_LISTS=1 -DBACNET_PROTOCOL_REVISION=28 -DFUZZING=1 -DBAC_ROUTING"
RFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 -std=gnu89 -w $RDEFS \
 -ffunction-sections -fdata-sections \
 -I$SRC/src -I$SRC/ports/linux -I$SRC/ports/posix"
S=src/bacnet
# apps/fuzz-libfuzzer/Makefile SRC + BACNET_SRC + PORT_MSTP_SRC + PORT_BIP_SRC (linked directly)
# (upstream's $(wildcard ...) dirs; src/bacnet/basic/*.c matches nothing at this revision)
RSRCS="$(shopt -s nullglob; echo $S/*.c $S/basic/*.c $S/basic/binding/*.c $S/basic/service/*.c $S/basic/sys/*.c)
 $S/basic/npdu/h_routed_npdu.c $S/basic/npdu/s_router.c $S/basic/tsm/tsm.c
 $S/basic/object/netport.c $S/basic/object/bacfile.c $S/basic/object/gateway/gw_device.c
 $S/basic/object/client/device-client.c
 ports/linux/rs485.c ports/linux/dlmstp.c $S/datalink/cobs.c $S/datalink/mstp.c
 $S/datalink/mstptext.c $S/datalink/crc.c ports/linux/bip-init.c $S/datalink/bvlc.c
 $S/basic/bbmd/h_bbmd.c"
# the rest of apps/lib (libbacnet.a) that the link needs, as an archive like upstream's -lbacnet
RLIB_SRCS="$S/datalink/bvlc6.c $S/datalink/datalink.c $S/datalink/dlenv.c ports/linux/mstimer-init.c
 ports/linux/datetime-init.c ports/posix/bacfile-posix.c $S/basic/npdu/h_npdu.c
 mayhem/fuzz_libfuzzer/link_stubs.c"
r_obj() { echo "$RB/obj/$(echo "$1" | tr / _ | sed 's/\.c$/.o/')"; }
ROBJS=""
# Upstream's target does not build as shipped at this revision, so three things are added (none
# edits a file): -DBAC_ROUTING, without which gw_device.c does not compile (devObj_s has no
# Vendor_Name etc.); upstream's own -Wl,--gc-sections, which drops the backup/create/delete code
# whose Device_* callees the harness does not link (with SanCov it
# keeps them, so mayhem/fuzz_libfuzzer/link_stubs.c defines them); and a rename of the three functions that both
# apps/fuzz-libfuzzer/main.c (as no-op "FIXME" link stubs) and device-client.c define, so the
# stubs win as upstream's harness intends (device-client.c keeps its own copies under new names).
DEVCLIENT_RENAMES="-DDevice_Objects_RR_Info=device_client_Device_Objects_RR_Info \
 -DDevice_Reinitialize=device_client_Device_Reinitialize \
 -DDevice_Write_Property=device_client_Device_Write_Property"
for f in $RSRCS; do
    o="$(r_obj "$f")"; extra=""
    [ "$f" = "$S/basic/object/client/device-client.c" ] && extra="$DEVCLIENT_RENAMES"
    $CC $RFLAGS $extra -c "$SRC/$f" -o "$o"; ROBJS="$ROBJS $o"
done
RLIBOBJS=""
for f in $RLIB_SRCS; do o="$(r_obj "$f")"; $CC $RFLAGS -c "$SRC/$f" -o "$o"; RLIBOBJS="$RLIBOBJS $o"; done
rm -f "$RB/librouterlib.a"
ar rcs "$RB/librouterlib.a" $RLIBOBJS
$CC $RFLAGS -c "$SRC/mayhem/fuzz_libfuzzer/fuzz_libfuzzer.c" -o "$RB/fuzz_libfuzzer.o"
$CC $RFLAGS $LIB_FUZZING_ENGINE "$RB/fuzz_libfuzzer.o" $ROBJS "$EXTRA/lsan_off.o" \
    "$RB/librouterlib.a" -lm -lrt -pthread -Wl,--gc-sections -o "$OUT/fuzz_libfuzzer"
$CC $RFLAGS "$STANDALONE_FUZZ_MAIN" "$RB/fuzz_libfuzzer.o" $ROBJS "$EXTRA/lsan_off.o" \
    "$RB/librouterlib.a" -lm -lrt -pthread -Wl,--gc-sections -o "$OUT/fuzz_libfuzzer-standalone"

# 3) The project's own ztest suite, built with NORMAL flags (no sanitizer, no -gdwarf-3) by gcc: clang
#    trips upstream's -Werror=double-promotion. mayhem/test.sh only runs the resulting test_* binaries.
(
    export CC=gcc CXX=g++
    unset SANITIZER_FLAGS DEBUG_FLAGS LIB_FUZZING_ENGINE
    cmake -S test -B test/build -G Ninja -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
    cmake --build test/build -j"$MAYHEM_JOBS"
    # known-answer probe (normal flags): encodes fixed values; test.sh compares the bytes
    gcc -O2 $COVERAGE_FLAGS -Isrc -DBACNET_STACK_STATIC_DEFINE -DBACNET_STACK_DEPRECATED_DISABLE \
        mayhem/kat/kat_probe.c \
        src/bacnet/bacdcode.c src/bacnet/bacint.c src/bacnet/bacreal.c src/bacnet/bacstr.c \
        src/bacnet/whois.c src/bacnet/rp.c src/bacnet/npdu.c src/bacnet/bacdest.c \
        src/bacnet/bacaddr.c src/bacnet/datetime.c src/bacnet/basic/sys/days.c \
        src/bacnet/bactext.c src/bacnet/proplist.c src/bacnet/indtext.c \
        -lm -o test/build/kat_probe
)
