// test/test-bug-slack-int.c
// Integer SLACK should reward inputs that get closer to a guarded magic value.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;

__attribute__((noinline, optnone))
int target_cmp(uint64_t x) {

  return x == 0x12345678ULL;

}

int main(int argc, char **argv) {

  if (argc != 2) return 2;
  uint64_t x = strtoull(argv[1], NULL, 0);
  int      r = target_cmp(x);

  uint32_t maxval = 0;
  if (__afl_bug_active && __afl_bug_map) {

    for (uint32_t i = 0; i < (1U << 14); ++i)
      if (__afl_bug_map[i] > maxval) maxval = __afl_bug_map[i];

  }

  fprintf(stderr, "BUG_SLACK_INT: x=%llu maxval=%u result=%d\n",
          (unsigned long long)x, maxval, r);
  return 0;

}
