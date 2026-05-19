/* TU B paired with test-llvm-path-twomod-a.c. */

__attribute__((noinline)) int b_func(unsigned char x) {

  if (x & 4) return x + 40;
  if (x & 8) return x + 50;
  return x + 60;

}

