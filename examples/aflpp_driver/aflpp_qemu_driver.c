#include <stdint.h>
#include <stdlib.h>

// libFuzzer interface is thin, so we don't include any libFuzzer headers.
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

int main(int argc, char **argv) {
  if (LLVMFuzzerInitialize)
    LLVMFuzzerInitialize(&argc, &argv);
  // Do any other expensive one-time initialization here.

  uint8_t dummy_input[1] = {0};
  LLVMFuzzerTestOneInput(dummy_input, 1);
  
  return 0;
}
