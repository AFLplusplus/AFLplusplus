// SIZEFILL in/out semantics: when the callee passes the out-pointer
// to a helper that READS through it (escape), the pass must treat the
// parameter as in/out and skip its pre-call zero so the caller's
// initial hint survives.  The helper prints the hint it observed —
// with the fix it shows 0x12345678, without it shows 0.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>

__attribute__((noinline, optnone)) static size_t read_hint(size_t *p) {

  // Escape: the pass sees only that `p` is passed to a CallBase; it
  // can't prove the callee doesn't read through it. Must treat the
  // caller-side arg as in/out.
  return *p;

}

__attribute__((noinline, optnone)) static void parse(uint8_t *buf, uint32_t n,
                                                     size_t *inout_size) {

  if (buf == NULL) {

    // size-only mode: writes the size and returns. (Storing through
    // a NON-sentinel arg is fine for findSentinelParam — only the
    // sentinel arg `buf` must not be written on the null path.)
    *inout_size = 8;
    return;

  }

  // Read the caller-provided hint via a helper. The helper's load
  // through *inout_size is what makes this an in/out param.
  size_t hint = read_hint(inout_size);
  fprintf(stderr, "INOUT_HINT_SEEN=%zu\n", hint);
  size_t bytes = (hint < 8) ? hint : 8;
  for (size_t i = 0; i < bytes; ++i)
    buf[i] = (uint8_t)(i + n);
  *inout_size = bytes;

}

int main(void) {

  uint8_t buf_in[4] = {0};
  if (read(0, buf_in, 4) != 4) return 1;

  size_t need;
  parse(NULL, 0, &need);

  uint8_t *p = (uint8_t *)malloc(64);
  if (!p) return 2;
  size_t inout = (size_t)0x12345678u;
  parse(p, (uint32_t)buf_in[0], &inout);
  fprintf(stderr, "BUG_INOUT: need=%zu inout=%zu\n", need, inout);
  free(p);
  return 0;

}

