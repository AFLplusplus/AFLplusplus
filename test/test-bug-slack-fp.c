// test/test-bug-slack-fp.c
//
// Exercises SLACK on an FCmpInst with a sub-1.0 |diff|. Without the
// scaling fix, fptoui_sat(|diff|) truncates any diff in [0, 1) to 0,
// so "barely-equal" and "exactly-equal" both produce inv=64 at the
// same map slot — the FP slack channel has no gradient near zero.
//
// The test dumps the SLACK map slot to stderr; the harness runs it
// twice (exactly equal vs slightly unequal) and verifies the slot
// values DIFFER. They do when scaling is in place; they coincide
// otherwise.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern uint32_t *__afl_bug_map;
extern uint8_t   __afl_bug_active;

// Sole FCmp site in the program — only one SLACK slot will be touched,
// so the harness can find it by scanning for the non-zero entry.
__attribute__((noinline, optnone)) static int compare_floats(double a,
                                                             double b) {

  if (a < b) return 1;
  return 0;

}

int main(int argc, char **argv) {

  if (argc != 3) return 2;
  double a = atof(argv[1]);
  double b = atof(argv[2]);
  int    r = compare_floats(a, b);

  if (__afl_bug_active && __afl_bug_map) {

    uint32_t hits = 0;
    for (uint32_t i = 0; i < (1U << 14); ++i) {

      if (__afl_bug_map[i]) {

        fprintf(stderr, "FP_SLOT=%u VAL=%u\n", i, __afl_bug_map[i]);
        ++hits;

      }

    }

    if (hits == 0) fprintf(stderr, "FP_SLOT=none\n");

  } else {

    fprintf(stderr, "FP_SLOT=inactive\n");

  }

  return r;

}

