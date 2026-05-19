// SCALAR+SLACK TP: an equality using a computed scalar value should keep
// SLACK distance guidance even when SCALAR also tracks the computed value.
#include <stdint.h>

__attribute__((noinline)) int target_scalar_slack(uint32_t n) {

  uint32_t x = n * 3u + 7u;
  if (x == 0x12345678u) return 1;
  return (int)(x & 7u);

}

int main(int argc, char **argv) {

  (void)argv;
  return target_scalar_slack((uint32_t)argc);

}

