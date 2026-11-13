#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Regression test: the forkserver must start when the target defines its own
# instrumented getenv() and its map is larger than MAP_SIZE (65536). Then
# __afl_map_shm() calls getenv("AFL_MAP_SIZE") before it attaches the SysV map,
# and the coverage callback in that getenv() must not see a NULL
# __afl_area_ptr. USEMMAP builds (macOS, Android) do not take this path.

MAP_SIZE=65536
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AFL_DIR="$SCRIPT_DIR/.."
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

if ! [ -x "$AFL_DIR/afl-clang-fast" -a -x "$AFL_DIR/afl-showmap" ]; then

  echo "SKIP: afl-clang-fast or afl-showmap not built"
  exit 0

fi

cat > "$TEMP_DIR/getenv-override.c" << 'EOF'
#include <stdlib.h>
#include <string.h>

extern char **environ;

/* Instrumented replacement for the libc getenv(). */
char *getenv(const char *name) {

  size_t n = strlen(name);
  for (char **e = environ; e && *e; e++)
    if (!strncmp(*e, name, n) && (*e)[n] == '=') return *e + n + 1;
  return NULL;

}

/* 36 functions with 1024 branches each give about 73000 edges. The volatile
   operand stops the compiler from merging them. */
volatile int sink;

#define B1 if (x == sink) sink++;
#define B4 B1 B1 B1 B1
#define B16 B4 B4 B4 B4
#define B64 B16 B16 B16 B16
#define B256 B64 B64 B64 B64
#define B1K B256 B256 B256 B256

#define F(n) void n(int x) { B1K }
#define F6(p) F(p##0) F(p##1) F(p##2) F(p##3) F(p##4) F(p##5)

F6(f0) F6(f1) F6(f2) F6(f3) F6(f4) F6(f5)

int main(void) {

  return 0;

}
EOF

# PCGUARD gives one map entry per edge. AFL_DONT_OPTIMIZE drops the -g that
# afl-cc adds, which makes the build about 30% faster.
if ! AFL_QUIET=1 AFL_LLVM_INSTRUMENT=PCGUARD AFL_DONT_OPTIMIZE=1 \
    "$AFL_DIR/afl-clang-fast" -O0 -o "$TEMP_DIR/getenv-override" \
    "$TEMP_DIR/getenv-override.c"; then

  echo "FAIL: afl-clang-fast could not build the test target"
  exit 1

fi

# Make sure that the target really takes the large-map path.
MAP=$(AFL_DUMP_MAP_SIZE=1 "$TEMP_DIR/getenv-override" 2> /dev/null | tail -1)
if ! [ "$MAP" -gt "$MAP_SIZE" ] 2> /dev/null; then

  echo "FAIL: map size '$MAP' is not larger than $MAP_SIZE, the test is not valid"
  exit 1

fi

if ! OUT=$(echo hello | "$AFL_DIR/afl-showmap" -o /dev/null -- \
           "$TEMP_DIR/getenv-override" 2>&1); then

  echo "$OUT"
  echo "FAIL: afl-showmap failed with an instrumented getenv() override"
  exit 1

fi

echo "OK: instrumented getenv() override with map size $MAP"
exit 0
