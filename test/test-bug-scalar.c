// test/test-bug-scalar.c
// Reads a 4-byte input as little-endian u32 n, runs a loop n times.
// Both arithmetic-max and loop-iteration-count fitness should grow with n.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
               ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
  if (n > 100000) n = 100000;

  uint64_t acc = 0;
  for (uint32_t i = 0; i < n; ++i)
    acc += (uint64_t)i * (uint64_t)i;

  if (__afl_bug_active && __afl_bug_map) {

    uint32_t maxval = 0;
    for (uint32_t i = 0; i < (1U << 14); ++i)
      if (__afl_bug_map[i] > maxval) maxval = __afl_bug_map[i];
    fprintf(stderr, "BUG_SCALAR: maxval=%u acc=%llu n=%u\n", maxval,
            (unsigned long long)acc, n);

  } else {

    fprintf(stderr, "BUG_SCALAR: inactive acc=%llu n=%u\n",
            (unsigned long long)acc, n);

  }

  return 0;

}

