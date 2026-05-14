// test/test-bug-budget-outparam-errcode.c
// Bug 26 TN: a `parse(buf, int *err)` shape — int* error param, not a
// size — must NOT be matched as a BUDGET out-param. findOutSizeParam's
// 2-arg-form rule requires the written value's bit-width to be >=
// ptr_bits (64 on x86_64), which excludes int. We verify two ways:
//
//   (a) Static IR check: with BUDGET+SIZEFILL enabled, no ws_begin /
//       ws_check_budget should be emitted for the call to parse_err().
//   (b) Runtime: the program runs cleanly (rc=0) regardless of what
//       parse_err returns.
//
// We also DO the `p += err` cast so that, IF the matcher were buggy and
// matched this shape, ws_check_budget would see ret_size==42 vs
// max_off~=0 and silently accept (no FP). The static IR check is the
// load-bearing assertion.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone))
static void parse_err(uint8_t *buf, int *err) {

  /* Touch buf so the optimizer keeps the call; write err with a small
     non-zero code. */
  buf[0] = 0x55;
  *err = 42;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;

  uint8_t  buf[256] = {0};
  uint8_t *p = buf;
  int      err = 0;

  parse_err(p, &err);
  p += err;  /* would be matched if BUDGET were over-permissive */

  fprintf(stderr,
          "BUG_BUDGET_OUTPARAM_ERRCODE: err=%d, advanced_to_offset=%ld\n",
          err, (long)(p - buf));
  return 0;

}
