#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

char *foo = NULL;

int __attribute__((noinline)) crashme(const uint8_t *Data, size_t Size) {

  if (Size < 5) return -1;

  if (Data[0] == 'F')
    if (Data[1] == 'A')
      if (Data[2] == '$')
        if (Data[3] == '$')
          if (Data[4] == '$') *foo = 1;

  return 0;

}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  if (Size)
    return crashme(Data, Size);
  else
    return -1;

}

