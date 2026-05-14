// test/test-bug-budget-returned.c
// Bug 20: BUDGET must catch lying calls even when LLVM applies the
// `returned` attribute to the callee's size argument. The optimizer
// substitutes the arg for the call result at every use, so the GEP
// indexes by the arg directly — the call result is invisible. We must
// rediscover it via the returned-attribute on the callee.
//
// Compile at -O2 (returned attribute is only emitted under opt).
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* noinline keeps the call from being inlined; the body `return n`
 * causes opt to mark arg1 with `returned`. */
__attribute__((noinline))
static uint32_t fill_lying(uint8_t *p, uint32_t n) {

  uint32_t doubled = 2 * n;
  for (uint32_t i = 0; i < doubled; ++i) p[i] = (uint8_t)i;
  return n;  /* lies */

}

int main(int argc, char **argv) {

  (void)argv;
  uint8_t *buf = (uint8_t *)malloc(256);
  if (!buf) return 2;
  uint8_t *p = buf;
  uint32_t s = fill_lying(p, (uint32_t)argc);
  p += s;
  fprintf(stderr, "BUG_BUDGET_RETURNED: s=%u final=%p\n", s, (void *)p);
  free(buf);
  return 0;

}
