#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


void __attribute__((noinline)) crashme(const uint8_t *Data, size_t Size) {

  if (Size < 5) return;

  if (Data[0] == 'F')
    if (Data[1] == 'A')
      if (Data[2] == '$')
        if (Data[3] == '$')
          if (Data[4] == '$') abort();


}
