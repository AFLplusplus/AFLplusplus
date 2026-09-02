/* Correct counterpart for allocation-failure injection: every allocation is
   checked, so no value of AFL_ALLOCFAIL_N can turn this into a crash. Exits 0
   whether or not the injected failure lands on one of its allocations. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {

  volatile size_t n = 64;
  char           *a = (char *)malloc(n);
  char           *b;

  if (!a) {

    printf("allocfail_good: handled malloc failure\n");
    return 0;

  }

  memset(a, 'x', n);
  a[n - 1] = 0;

  b = strdup(a);

  if (!b) {

    printf("allocfail_good: handled strdup failure\n");
    free(a);
    return 0;

  }

  printf("allocfail_good: clean, %zu bytes\n", strlen(b));

  free(b);
  free(a);

  return 0;

}
