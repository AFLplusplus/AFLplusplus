/* Regression for the granule-collision unregister fix.
 *
 * Two small allocations land in the same 64-byte shadow granule (glibc
 * malloc returns 16-byte-aligned chunks).  The shadow holds only the
 * MOST RECENTLY registered idx for the granule.  Without the fallback
 * scan, freeing the older allocation reads the shadow byte, finds the
 * newer allocation's idx, sees base != older_ptr, and silently leaks
 * the older slot (in_use stays 1 forever).
 *
 * We inspect __afl_alloc_records directly: before the frees, two slots
 * are in_use; after both frees, both must be FREE.  Without the fix,
 * one slot stays LIVE. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "../include/bug-pass.h"

extern AllocSizeRecord __afl_alloc_records[];

static unsigned count_live(void) {

  unsigned n = 0;
  for (unsigned i = 1; i < 4096; ++i)
    if (__afl_alloc_records[i].in_use) ++n;
  return n;

}

int main(void) {

  /* Two small allocations: likely to share a granule. */
  char *a = (char *)malloc(8);
  char *b = (char *)malloc(8);
  if (!a || !b) {

    fputs("alloc-failed\n", stderr);
    return 1;

  }

  a[0] = 1;
  b[0] = 2;

  unsigned live_after_alloc = count_live();
  fprintf(stderr, "live_after_alloc=%u\n", live_after_alloc);

  free(a);
  free(b);

  unsigned live_after_free = count_live();
  fprintf(stderr, "live_after_free=%u\n", live_after_free);

  /* live_after_free MUST be 0; if the unregister leaked, it's 1. */
  if (live_after_free != 0) {

    fputs("LEAK: stale records still live after both frees\n", stderr);
    return 2;

  }

  fputs("ok\n", stderr);
  return 0;

}

