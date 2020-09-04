#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "hash.h"

void __attribute__((noinline)) crashme(const uint8_t *Data, size_t Size) {

  if (Size < 5) return;

  if (Data[0] == 'F')
    if (Data[1] == 'A')
      if (Data[2] == '$')
        if (Data[3] == '$')
          if (Data[4] == '$') abort();

}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Size)
    fprintf(stderr, "FUNC crc: %016llx len: %lu\n",
            hash64((u8 *)Data, (unsigned int)Size,
                   (unsigned long long int)0xa5b35705),
            Size);

  crashme(Data, Size);

  return 0;

}

