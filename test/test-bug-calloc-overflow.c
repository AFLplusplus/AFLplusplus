/* __afl_track_calloc must check (nmemb*size) for overflow in size_t
 * BEFORE the calloc call, so the runtime does not register a fictitious
 * oversized region.  Calling calloc with SIZE_MAX/2 * 4 always overflows
 * and must yield rc==0 — clean NULL return, no false ALLOCSIZE abort,
 * no fictitious shadow entry. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/* Use noinline so the compiler can't strip the calloc call after
   constant-folding the size. */
__attribute__((noinline)) static void *call_calloc(size_t n, size_t s) {

  return calloc(n, s);

}

/* Read a multiplier from stdin so clang can't constant-fold the call. */
int main(int argc, char **argv) {

  (void)argc;
  (void)argv;
  size_t nmemb = 0;
  if (fread(&nmemb, sizeof(nmemb), 1, stdin) != 1) {

    /* Default to an overflowing value if no stdin is provided. */
    nmemb = ((size_t)-1) / 2;

  }

  void *p = call_calloc(nmemb, 4);
  if (p) {

    /* Should not happen for an overflowing pair on a sane system. */
    fprintf(stderr, "calloc returned non-NULL for overflowing size\n");
    free(p);
    return 2;

  }

  return 0;

}

