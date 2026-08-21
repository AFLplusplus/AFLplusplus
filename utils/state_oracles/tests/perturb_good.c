/* Correct counterpart for the uninitialised-memory probe: the buffer is
   initialised before it is read, so the output is the same at every
   MALLOC_PERTURB_ value. afl-perturb-check.sh must exit 0 on this. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {

  volatile size_t n = 32;
  unsigned char  *buf = (unsigned char *)malloc(n);
  volatile size_t i;

  if (!buf) { return 1; }

  memset(buf, 0, n);

  for (i = 0; i < n; i++) {

    printf("%02x", buf[i]);

  }

  printf("\n");

  free(buf);

  return 0;

}
