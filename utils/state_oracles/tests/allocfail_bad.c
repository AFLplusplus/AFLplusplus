/* Deliberately broken example for allocation-failure injection: the return
   value of malloc() is never checked, so the injected failure turns into a
   NULL write and the process dies on SIGSEGV (exit 139 under a shell). The
   write goes through volatile so it is not optimised away.

   Without the interposer this program is well behaved and exits 0, which is
   the point: the defect only becomes visible when the error path is taken. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {

  volatile size_t n = 64;
  char           *a = (char *)malloc(n);
  volatile size_t i;

  for (i = 0; i < n; i++) {

    a[i] = 'x';

  }

  a[n - 1] = 0;

  printf("allocfail_bad: NOT DETECTED, %zu bytes\n", strlen(a));

  free(a);

  return 0;

}
