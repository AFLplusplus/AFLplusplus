/* __afl_track_realloc must handle:
 *   (a) realloc(p, 0)            -- glibc frees p and returns NULL;
 *                                   runtime must NOT keep p in_use.
 *   (b) realloc(p, HUGE) failure -- p still valid per C11;
 *                                   runtime must keep p tracked and
 *                                   subsequent writes must not abort.
 *   (c) realloc(NULL, sz)         -- equivalent to malloc;
 *                                   runtime must register the result.
 *
 * Emits path-{a,b,c} markers on stderr so the driver can assert which
 * branches actually ran (overcommit makes path-b's failure case skip
 * on Linux when realloc succeeds against a huge request — that's still
 * useful; we just want to know which side fired and that no spurious
 * ALLOCSIZE soft-OOB string appears). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {

  /* (a) shrink-to-zero */
  char *p = (char *)malloc(64);
  if (!p) return 1;
  memset(p, 0xab, 64);
  char *q = (char *)realloc(p, 0);
  fputs("path-a\n", stderr);
  (void)q;

  /* (c) realloc(NULL, sz) */
  char *r = (char *)realloc(NULL, 128);
  if (!r) return 1;
  memset(r, 0x5a, 128);
  fputs("path-c\n", stderr);

  /* (b) attempt a huge grow; outcome depends on overcommit. */
  size_t huge = ((size_t)-1) / 2;
  char  *s = (char *)realloc(r, huge);
  if (s) {

    fputs("path-b-succ\n", stderr);
    free(s);

  } else {

    /* r still valid per C11; write must NOT abort. */
    fputs("path-b-fail\n", stderr);
    memset(r, 0x33, 128);
    free(r);

  }

  return 0;

}

