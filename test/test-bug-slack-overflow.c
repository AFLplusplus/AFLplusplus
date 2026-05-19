// test/test-bug-slack-overflow.c
// SLACK on *.with.overflow.* flag bit — overflow → tightest bucket,
// no-overflow → no signal.
//
// Test: run the same target with non-overflowing and overflowing
// inputs and observe a slot diff (overflow input lights up at
// least one slot that the non-overflow input does not).

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;

__attribute__((noinline, optnone)) static uint64_t target_overflow(uint64_t a,
                                                                   uint64_t b) {

  uint64_t out;
  if (__builtin_mul_overflow(a, b, &out)) {

    /* On overflow, the *WithOverflow intrinsic's flag is 1; SLACK
       must see this as a tight (slack=0) update to its slot. */
    return 0;

  }

  return out;

}

int main(int argc, char **argv) {

  uint64_t a = 0, b = 0;
  if (argc > 1) a = (uint64_t)strtoull(argv[1], NULL, 0);
  if (argc > 2) b = (uint64_t)strtoull(argv[2], NULL, 0);
  uint64_t r = target_overflow(a, b);
  /* Dump every non-zero map slot so the test script can compare
     overflow vs non-overflow runs. */
  if (__afl_bug_active && __afl_bug_map) {

    for (uint32_t i = 0; i < (1U << 14); ++i)
      if (__afl_bug_map[i])
        fprintf(stderr, "slot %u = %u\n", i, __afl_bug_map[i]);

  }

  fprintf(stderr, "BUG_SLACK_OVERFLOW: a=%llu b=%llu r=%llu\n",
          (unsigned long long)a, (unsigned long long)b, (unsigned long long)r);
  return 0;

}

