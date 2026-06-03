// test/test-cmplog-size-derive-option.c
// The test harness sets AFL_CMPLOG_LZ_MARKER to an absolute path. A run
// under `afl-fuzz -l Z` should enable __afl_size_derive_active in the child.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern uint8_t __afl_size_derive_active;
extern uint8_t __afl_allocsize_active;

int main(void) {

  uint8_t b = 0;
  (void)read(0, &b, 1);

  char *p = (char *)malloc(32 + (b & 7));
  if (!p) return 0;
  p[0] = (char)b;
  free(p);

  const char *marker = getenv("AFL_CMPLOG_LZ_MARKER");
  if (marker && __afl_size_derive_active && __afl_allocsize_active) {

    FILE *f = fopen(marker, "w");
    if (f) {

      fputs("derive-active\n", f);
      fclose(f);

    }

  }

  return 0;

}

