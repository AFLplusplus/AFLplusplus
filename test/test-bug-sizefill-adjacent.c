// test/test-bug-sizefill-adjacent.c
//
// Exercises the false-positive class where, during a SIZEFILL-tracked
// sentinel call, the callee writes into an UNRELATED allocation that
// happens to live at a higher heap address. With the heuristic-only
// 64 KiB UNRELATED_SLACK, those writes get charged against the
// tracked buffer's max_off and trip a spurious abort.
//
// To make the layout deterministic regardless of allocator we use
// nested SIZEFILL: outer takes the small tracked buffer, inner is
// called from within outer with a different (larger) buffer. Both
// buffers are sentinel-traced; inner's writes are sf_store'd; the
// outer frame's cap decides whether the inner writes pollute outer's
// max_off.
//
// With the shadow-aware fix (cap derived from ALLOCSIZE shadow when
// available), outer's frame caps at the END of its own allocation —
// inner's writes are filtered out as a different allocation.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t inner(uint32_t *p,
                                                         uint32_t  n) {

  if (p == NULL) return 64;
  // Inner writes the full extent of its OWN (large) buffer.
  for (uint32_t i = 0; i < 64; ++i)
    p[i] = i + n;
  return 64;

}

__attribute__((noinline, optnone)) static uint32_t outer(uint32_t *p,
                                                         uint32_t  n) {

  if (p == NULL) return 4;
  // Allocate a separate, larger buffer and run the inner sentinel
  // call against it. Inner's writes (256 bytes total) happen INSIDE
  // outer's SIZEFILL window — they must NOT be charged to outer's
  // own 16-byte buffer.
  uint32_t *inner_buf = (uint32_t *)malloc(64 * sizeof(uint32_t));
  if (!inner_buf) return 0;
  (void)inner(inner_buf, n);
  // Outer's own honest write: 4 entries, exactly its declared size.
  for (uint32_t i = 0; i < 4; ++i)
    p[i] = i;
  free(inner_buf);
  return 4;

}

int main(void) {

  uint8_t buf[4] = {0};
  if (read(0, buf, 4) != 4) return 1;
  uint32_t n = (uint32_t)buf[0];
  uint32_t need = outer(NULL, n);

  uint32_t *p = (uint32_t *)malloc(4 * sizeof(uint32_t));
  if (!p) return 2;
  uint32_t got = outer(p, n);
  fprintf(stderr, "BUG_SIZEFILL_ADJACENT: need=%u got=%u\n", need, got);
  free(p);
  return 0;

}

