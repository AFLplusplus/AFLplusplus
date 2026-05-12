/* __afl_track_realloc must handle:
 *   (a) realloc(p, 0)            -- glibc frees p and returns NULL;
 *                                   runtime must NOT keep p in_use.
 *   (b) realloc(p, HUGE) failure  -- p still valid per C11;
 *                                   runtime must keep p tracked.
 *   (c) realloc(NULL, sz)         -- equivalent to malloc;
 *                                   runtime must register the result.
 *
 * Compiled with AFL_LLVM_BUG_ALLOCSIZE=1; the test exits 0 on success
 * and relies on the absence of "ALLOCSIZE soft-OOB" on stderr to assert
 * no false aborts. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
  char *p = (char *)malloc(64);
  if (!p) return 1;
  memset(p, 0xab, 64);

  /* (a) shrink-to-zero. On glibc this frees p; q is NULL. */
  char *q = (char *)realloc(p, 0);
  (void)q;  /* do not touch p afterwards regardless of q */

  /* (c) realloc(NULL, sz) */
  char *r = (char *)realloc(NULL, 128);
  if (!r) return 1;
  memset(r, 0x5a, 128);

  /* (b) realloc-failure: huge request usually fails on 64-bit too. */
  char *s = (char *)realloc(r, ((size_t)-1) / 2);
  if (s) {
    /* libc actually allocated; just free and exit. */
    free(s);
  } else {
    /* r still valid; writes must not trigger spurious abort. */
    memset(r, 0x33, 128);
    free(r);
  }
  return 0;
}
