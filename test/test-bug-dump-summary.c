// test/test-bug-dump-summary.c
// AFL_LLVM_BUG_DUMP_SUMMARY=1 must emit per-function summary
// lines at compile time.  The test script compiles this with the
// env set and greps the compiler stderr; the program itself does
// nothing useful at runtime.

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

__attribute__((noinline, optnone)) static uint32_t func_a(uint32_t x) {

  uint32_t y = 0;
  for (uint32_t i = 0; i < x; ++i)
    y += i * i;
  return y;

}

__attribute__((noinline, optnone)) static uint32_t func_b(uint32_t x) {

  if (x > 100) x = 100;
  return x * 7;

}

int main(void) {

  uint8_t in[4] = {0};
  if (read(0, in, 4) != 4) return 1;
  uint32_t n = (uint32_t)in[0];
  uint32_t a = func_a(n);
  uint32_t b = func_b(n);
  fprintf(stderr, "BUG_DUMP_SUMMARY: a=%u b=%u\n", a, b);
  return 0;

}

