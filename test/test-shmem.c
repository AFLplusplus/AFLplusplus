/*
   AFL++ combined CMPLOG + IJON + BUG target for test-shmem.sh.

   The crash is only reachable when all three cooperate: CMPLOG/RedQueen solves
   the magic header, IJON max-feedback climbs the branchless state lock (which
   has no edge-coverage gradient), and the AFL_LLVM_BUG ALLOCSIZE oracle reports
   the final data-dependent heap overflow via _exit(134). afl-fuzz only records
   that as a crash with AFL_CRASH_EXITCODE (see test-shmem.sh).
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LOCK_LEN 9
#define MAGIC 0x41464c2bU

static uint8_t *volatile g_sink;

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

  if (size < 4 + LOCK_LEN + 1) { return 0; }

  uint32_t magic;
  memcpy(&magic, data, 4);
  if (magic != MAGIC) { return 0; }

  uint32_t state = 0x811c9dc5u, good = 1, depth = 0;
  for (uint32_t i = 0; i < LOCK_LEN; ++i) {

    state = (state ^ data[4 + i]) * 16777619u;
    state ^= state >> 15;
    good &= (uint32_t)((state & 3u) == 0u);
    depth += good;

  }

  IJON_MAX(depth);

  if (depth >= LOCK_LEN) {

    uint32_t n = 64u + ((uint32_t)data[4 + LOCK_LEN] & 15u);
    uint8_t *p = (uint8_t *)malloc(16);
    if (!p) { return 0; }
    for (uint32_t i = 0; i < n; ++i) {

      p[i] = (uint8_t)(data[0] + i);

    }

    g_sink = p;
    free(p);

  }

  return 0;

}

/*
int main(void) {

  unsigned char buf[1024];
  ssize_t       i;

  while (__AFL_LOOP(1000)) {

    i = read(0, buf, sizeof(buf));
    if (i < 0) { i = 0; }
    LLVMFuzzerTestOneInput(buf, (size_t)i);

  }

  return 0;

}

*/

