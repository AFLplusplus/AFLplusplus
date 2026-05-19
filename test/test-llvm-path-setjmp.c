/* setjmp/longjmp interferes with the path_reg stack alloca: a longjmp
   back into setjmp leaves path_reg with an indeterminate value, so the
   next exit-point write can index outside the reserved bitmap range.
   PATH instrumentation must skip such functions. */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static jmp_buf jb;

__attribute__((noinline)) int with_setjmp(unsigned char x) {

  int v = setjmp(jb);
  if (v) return v;                                       /* longjmp landing */
  if (x & 1) { longjmp(jb, 42); }
  return x + 1;

}

__attribute__((noinline)) int normal(unsigned char x) {

  if (x & 1) return 1;
  if (x & 2) return 2;
  return 0;

}

int main(int argc, char **argv) {

  unsigned char buf[1] = {0};
  if (read(0, buf, 1) <= 0) return 2;
  int s = with_setjmp(buf[0]);
  s += normal(buf[0]);
  return s & 0xff;

}

