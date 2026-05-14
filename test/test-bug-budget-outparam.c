// test/test-bug-budget-outparam.c
// Bug 26 (Tier 3 item 1): BUDGET catches `ptr += *out_n` after a call that
// writes through the buffer AND through an out-size pointer. The classic
// iconv/libxml2 streaming-parser shape:
//
//     void fill(buf, size_t *out_n);
//     fill(p, &n);  p += n;
//
// TP: fill_lying() writes 32 bytes to buf but reports *out_n = 16. With
// AFL_LLVM_BUG_BUDGET=1 AFL_LLVM_BUG_SIZEFILL=1, ws_store inside the
// callee records max_off=32; ws_check_budget(buf_before, 16) sees
// max_off (32) > ret_size (16) → "BUDGET violation" and _exit(134).
//
// Gating: this matcher only runs when BOTH BUDGET and SIZEFILL modes are
// active — same FP-surface gating decided in the future-work review.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone))
static void fill_lying(uint8_t *buf, size_t *out_n) {

  /* Pretend a streaming parser that grew bytes beyond the size it
     reports to the caller. */
  for (int i = 0; i < 32; ++i) buf[i] = (uint8_t)(0xc0 | i);
  *out_n = 16;  /* LIE: callee wrote 32 bytes but claims 16. */

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;

  uint8_t  buf[256] = {0};
  uint8_t *p = buf;
  size_t   n = 0;

  /* Tiny data-dependent perturbation so the optimizer can't fold the
     call away. */
  p += (in[0] & 3);

  fill_lying(p, &n);
  p += n;  /* advance by the (lying) reported size */

  fprintf(stderr,
          "BUG_BUDGET_OUTPARAM: reported_n=%zu, advanced_to_offset=%ld\n",
          n, (long)(p - buf));
  return 0;

}
