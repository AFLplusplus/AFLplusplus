#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: never-zero counter behavior"

# Test with each available compiler that supports never-zero
for AFL_COMPILER in afl-clang-fast afl-clang-lto; do

  test -e ../${AFL_COMPILER} || continue

  $ECHO "$GREY[*] Testing ${AFL_COMPILER} never-zero counters"

  # Write a test program whose loop body executes exactly 256 times,
  # which wraps an 8-bit counter back to 0.  With never-zero the
  # counter must stay non-zero and therefore appear in afl-showmap
  # output.
  cat > test-neverzero.c <<'EOF'
#include <stdlib.h>
int main(void) {
    volatile int x = 0;
    /* 256 iterations wraps an 8-bit counter to 0. */
    for (int i = 0; i < 256; i++) { x++; }
    for (int i = 0; i < 256; i++) { x--; }
    for (int i = 0; i < 256; i++) { x ^= i; }
    /* 255 iterations must show 255 in both modes. */
    for (int i = 0; i < 255; i++) { x++; }
    for (int i = 0; i < 255; i++) { x--; }
    for (int i = 0; i < 255; i++) { x ^= i; }
    return 0;
}
EOF

  # Build with never-zero enabled (default)
  ../${AFL_COMPILER} -O0 -o test-neverzero-nz test-neverzero.c \
      > /dev/null 2>&1
  test -e test-neverzero-nz || {
    $ECHO "$YELLOW[-] ${AFL_COMPILER} compilation failed, skipping"
    continue
  }

  # Build with never-zero disabled
  AFL_LLVM_SKIP_NEVERZERO=1 \
      ../${AFL_COMPILER} -O0 -o test-neverzero-skip test-neverzero.c \
      > /dev/null 2>&1
  test -e test-neverzero-skip || {
    $ECHO "$YELLOW[-] ${AFL_COMPILER} compilation (skip-nz) failed, skipping"
    rm -f test-neverzero-nz
    continue
  }

  # Run both through afl-showmap.  Output contains only non-zero
  # edge:count pairs, so any counter that wrapped to 0 disappears.
  echo | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} \
      -o test-neverzero-nz.map -- ./test-neverzero-nz > /dev/null 2>&1
  echo | AFL_QUIET=1 ../afl-showmap -m ${MEM_LIMIT} \
      -o test-neverzero-skip.map -- ./test-neverzero-skip > /dev/null 2>&1

  test -s test-neverzero-nz.map -a -s test-neverzero-skip.map || {
    $ECHO "$RED[!] ${AFL_COMPILER} afl-showmap produced no output"
    CODE=1
    rm -f test-neverzero-nz test-neverzero-skip test-neverzero-nz.map \
          test-neverzero-skip.map test-neverzero.c
    continue
  }

  NZ_EDGES=$(wc -l < test-neverzero-nz.map)
  SKIP_EDGES=$(wc -l < test-neverzero-skip.map)

  if [ "$NZ_EDGES" -gt "$SKIP_EDGES" ]; then
    $ECHO "$GREEN[+] ${AFL_COMPILER} never-zero counters work: $NZ_EDGES edges vs $SKIP_EDGES without ($((NZ_EDGES - SKIP_EDGES)) preserved)"
  else
    $ECHO "$RED[!] ${AFL_COMPILER} never-zero counters BROKEN: $NZ_EDGES edges (should be more than $SKIP_EDGES)"
    CODE=1
  fi

  rm -f test-neverzero-nz test-neverzero-skip test-neverzero-nz.map \
        test-neverzero-skip.map test-neverzero.c

done

. ./test-post.sh
