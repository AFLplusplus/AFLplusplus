/* Correct counterpart for the exact-size buffer: writes exactly as many bytes
   as were asked for. Exits 0. */

#include <stdio.h>
#include "../afl-oracles.h"

#define N 8

int main(void) {

  volatile size_t   n = N;
  unsigned char    *buf = (unsigned char *)afl_exact_alloc(n);
  volatile size_t   i;
  volatile unsigned sum = 0;

  if (!buf) {

    fprintf(stderr, "exactbuf_good: allocation failed\n");
    return 1;

  }

  for (i = 0; i < n; i++) {

    buf[i] = (unsigned char)i;

  }

  for (i = 0; i < n; i++) {

    sum += buf[i];

  }

  printf("exactbuf_good: clean, sum %u\n", sum);

  afl_exact_free(buf, N);

  return 0;

}
