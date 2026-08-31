/* Deliberately broken example for the uninitialised-memory probe: the buffer
   is printed without ever being initialised, so the output follows
   MALLOC_PERTURB_. afl-perturb-check.sh must exit 1 on this.

   The buffer is freed and re-allocated first: glibc only perturbs the bytes
   it hands back out, and reading a chunk that was never recycled can be all
   zeroes at every setting, which would hide the defect. */

#include <stdio.h>
#include <stdlib.h>

int main(void) {

  volatile size_t n = 32;
  unsigned char  *warm = (unsigned char *)malloc(n);
  unsigned char  *buf;
  volatile size_t i;

  if (!warm) { return 1; }
  free(warm);

  buf = (unsigned char *)malloc(n);
  if (!buf) { return 1; }

  for (i = 0; i < n; i++) {

    printf("%02x", buf[i]);

  }

  printf("\n");

  free(buf);

  return 0;

}
