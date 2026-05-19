// test/test-bug-sizefill-vla.c
// SIZEFILL's buffer-size inference for VLAs must saturate the
// arrSize*eltBytes mul on overflow.
//
// Test: a VLA with a small element type can't overflow under any
// runtime input; sentinel-API call must NOT spuriously abort.
// IR-level check (in test-bug-pass.sh) verifies umul_with_overflow
// intrinsics appear.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static long parse_honest(char  *buf,
                                                            size_t cap) {

  if (!buf) return 16;
  /* Honest fill — write exactly 16 bytes (what the sentinel promised). */
  for (size_t i = 0; i < 16 && i < cap; ++i)
    buf[i] = (char)i;
  return 16;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  size_t n = ((size_t)in[0]) % 96 + 32;                          /* 32..127 */
  /* int VLA: eltBytes=4, arrSize=n.  inferBufferSizeValue emits
     `umul_with_overflow(n, 4)` after the fix, saturating to
     UINT64_MAX on overflow (cannot happen here but the SAT logic
     must compile and run cleanly). */
  int vla[n];
  memset(vla, 0, sizeof vla);
  (void)parse_honest((char *)vla, sizeof vla);
  fprintf(stderr, "BUG_SIZEFILL_VLA: n=%zu sizeof=%zu\n", n, sizeof vla);
  return 0;

}

