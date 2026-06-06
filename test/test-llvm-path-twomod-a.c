/* TU A for the multi-module __afl_final_loc duplicate-def regression test.
   See test-llvm-lto-path.sh for the link scenario this guards against. */

#include <unistd.h>

extern int b_func(unsigned char x);

__attribute__((noinline)) int a_func(unsigned char x) {

  if (x & 1) return x + 10;
  if (x & 2) return x + 20;
  return x + 30;

}

int main(int argc, char **argv) {

  unsigned char buf[1] = {0};
  if (read(0, buf, 1) <= 0) return 2;
  return (a_func(buf[0]) + b_func(buf[0])) & 0xff;

}

