#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  fprintf(stderr, "Received size %lu\n", Size);
  
  if (Size < 4)
    return 0;

  if (Data[0] == 'F')
    if (Data[1] == 'A')
      if (Data[2] == '$')
        if (Data[3] == '$')
          abort();
          
  return 0;

}
