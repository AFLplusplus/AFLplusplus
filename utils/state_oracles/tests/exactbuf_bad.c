/* Deliberately broken example for the exact-size buffer: one byte past the
   end. In a malloc'd buffer this lands in slack and nothing happens; here it
   hits the guard page, so the process must die on SIGSEGV (exit 139 under a
   shell). The overrun goes through volatile so it survives -O0 and above. */

#include <stdio.h>
#include "../afl-oracles.h"

#define N 8

int main(void) {

  volatile size_t n = N;
  unsigned char  *buf = (unsigned char *)afl_exact_alloc(n);
  volatile size_t i;

  if (!buf) {

    fprintf(stderr, "exactbuf_bad: allocation failed\n");
    return 1;

  }

  for (i = 0; i <= n; i++) {

    buf[i] = (unsigned char)i;

  }

  printf("exactbuf_bad: NOT DETECTED\n");

  afl_exact_free(buf, N);

  return 0;

}
