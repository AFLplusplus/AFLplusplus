// test/test-bug-allocsize-persistent.c
// Persistent-mode regression: a long-lived tracked allocation must keep its
// record, but per-input fields such as max_observed_off must reset at the
// __AFL_LOOP boundary.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "bug-pass.h"

/* Unsized extern: see test-bug-allocsize-track.c for rationale. */
extern AllocSizeRecord __afl_alloc_records[];

static AllocSizeRecord *find_record(void *p) {

  uintptr_t a = (uintptr_t)p;
  /* 256 is a sufficient scan bound for this test (single long-lived
     allocation lands at idx=1). */
  for (unsigned i = 1; i < 256; ++i) {

    AllocSizeRecord *r = &__afl_alloc_records[i];
    if (r->in_use && r->base == a) return r;

  }

  return NULL;

}

static void write_marker(const char *path) {

  if (!path) return;
  FILE *f = fopen(path, "w");
  if (!f) return;
  fputs("persistent-reset\n", f);
  fclose(f);

}

int main(void) {

  char *p = (char *)malloc(64);
  if (!p) return 0;

  const char *marker = getenv("AFL_BUG_PERSISTENT_RESET_MARKER");
  int         iter = 0;
  int         saw_nonzero = 0;
  int         saw_reset = 0;

  while (__AFL_LOOP(8)) {

    AllocSizeRecord *r = find_record(p);
    if (iter > 0 && r && r->max_observed_off == 0) saw_reset = 1;

    uint8_t b = 0;
    (void)read(0, &b, 1);
    p[b & 7] = (char)b;

    r = find_record(p);
    if (r && r->max_observed_off != 0) saw_nonzero = 1;

    if (saw_nonzero && saw_reset) write_marker(marker);
    ++iter;

  }

  free(p);
  return 0;

}

