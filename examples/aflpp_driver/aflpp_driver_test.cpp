#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "hash.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  fprintf(stderr, "FUNC crc: %08x len: %lu\n", hash32(Data, Size, 0xa5b35705), Size);
  
  if (Size < 5)
    return 0;

  if (Data[0] == 'F')
    if (Data[1] == 'A')
      if (Data[2] == '$')
        if (Data[3] == '$')
          if (Data[4] == '$')
            abort();
          
  return 0;

}
