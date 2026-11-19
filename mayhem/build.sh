#!/usr/bin/env bash
#
# mayhem/build.sh — build aria2's fuzz harnesses and its cppunit test suite.
#
# Runs inside the commit image as `mayhem` in /mayhem; the base image exports CC/CXX,
# SANITIZER_FLAGS (ASan+UBSan, halting), LIB_FUZZING_ENGINE, STANDALONE_FUZZ_MAIN and SRC.
#
#  1. autoreconf (only when configure is missing: everything it generates is gitignored).
#  2. mayhem/build-fuzz: libaria2 (src/.libs/libaria2.a) configured with
#     $SANITIZER_FLAGS $DEBUG_FLAGS + SanCov, out of tree.
#  3. Every mayhem/harnesses/fuzz_*.cc linked twice against it: /mayhem/out/<name>
#     (libFuzzer) and /mayhem/out/<name>-standalone (run-once reproducer).
#  4. mayhem/build-test: a second, independent configure with normal flags, and the
#     cppunit runner test/aria2c that mayhem/test.sh runs.
# Re-runnable (configure only runs when the build dir has no config.status) and offline
# (all dependencies are apt packages already in the image).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# aria2's optional features this integration builds: OpenSSL (TLS + message digests,
# BitTorrent needs them), expat (Metalink, XML-RPC), zlib (gzip). Everything else off so
# the build only depends on apt packages in the image; SQLite off so cookie files always
# reach aria2's own Netscape parser.
CONFIGURE_ARGS=(
  --disable-shared --enable-static --disable-nls
  --with-openssl --without-gnutls --without-libnettle --without-libgcrypt --without-libgmp
  --with-libexpat --without-libxml2 --with-libz
  --without-sqlite3 --without-libcares --without-libssh2 --disable-websocket
)

# 1) Generate configure (gitignored, so absent on a `git clean -ffdX` tree).
if [ ! -x configure ]; then
  autoreconf -i
fi

# 2) Sanitized, SanCov-instrumented libaria2.
FUZZ_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
mkdir -p mayhem/build-fuzz
(
  cd mayhem/build-fuzz
  if [ ! -f config.status ]; then
    ../../configure "${CONFIGURE_ARGS[@]}" CFLAGS="$FUZZ_FLAGS" CXXFLAGS="$FUZZ_FLAGS"
  fi
  make -j"$MAYHEM_JOBS" -C src libaria2.la
)
B="$SRC/mayhem/build-fuzz"
LIBS=$(make -s -C "$B/src" -f Makefile -f "$SRC/mayhem/print-libs.mk" print-libs)

# 3) Harnesses: libFuzzer binary + standalone reproducer each.
OUT="$SRC/mayhem/out"
mkdir -p "$OUT"
INCLUDES=(-DHAVE_CONFIG_H -I"$B" -I"$SRC/src" -I"$SRC/src/includes" -I"$SRC/lib" -I"$SRC/mayhem/harnesses")
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"
for src in "$SRC"/mayhem/harnesses/fuzz_*.cc; do
  name=$(basename "$src" .cc)
  $CXX -std=c++11 $FUZZ_FLAGS "${INCLUDES[@]}" -c "$src" -o "$OUT/$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/$name.o" "$OUT/lsan_off.o" \
    "$B/src/.libs/libaria2.a" $LIBS -lpthread -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/$name.o" "$OUT/lsan_off.o" \
    "$B/src/.libs/libaria2.a" $LIBS -lpthread -o "$OUT/$name-standalone"
done

# 4) The upstream cppunit suite, normal flags, separate tree.
mkdir -p mayhem/build-test
(
  cd mayhem/build-test
  if [ ! -f config.status ]; then
    ../../configure "${CONFIGURE_ARGS[@]}" CFLAGS="-O1 $COVERAGE_FLAGS" CXXFLAGS="-O1 $COVERAGE_FLAGS" \
      LDFLAGS="$COVERAGE_FLAGS"
  fi
  make -j"$MAYHEM_JOBS" -C src libaria2.la
  make -j"$MAYHEM_JOBS" -C test aria2c
  # test.sh's runner: upstream's test objects with mayhem/cppunit_offline_main.cc as main()
  # (skips the two LPD fixtures that need a multicast-capable interface; the suite runs offline).
  cd test
  mk=(make -s -f Makefile -f "$SRC/mayhem/print-test.mk")
  objs=$("${mk[@]}" print-test-objects)
  libs=$("${mk[@]}" print-test-libs | sed 's|\.\./src/libaria2\.la|../src/.libs/libaria2.a|')
  # shellcheck disable=SC2046
  $CXX -std=c++11 $("${mk[@]}" print-test-cxxflags) -c "$SRC/mayhem/cppunit_offline_main.cc" \
    -o cppunit_offline_main.o
  # shellcheck disable=SC2086
  $CXX -O1 $COVERAGE_FLAGS cppunit_offline_main.o $objs $libs -lpthread -o aria2c-offline
)
