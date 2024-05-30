#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define T1HA0_AESNI_AVAILABLE 1
#define T1HA_USE_FAST_ONESHOT_READ 1
#define T1HA_USE_INDIRECT_FUNCTIONS 1
#define T1HA_IA32AES_NAME t1ha0_ia32aes
#include "t1ha0_ia32aes_b.h"

#define XXH_INLINE_ALL
#include "xxhash.h"
#undef XXH_INLINE_ALL

int main() {

  char           *data = malloc(4097);
  struct timespec start, end;
  long long       duration;
  int             i;
  uint64_t        res;

  clock_gettime(CLOCK_MONOTONIC, &start);
  for (i = 0; i < 100000000; ++i) {

    res = XXH3_64bits(data, 4097);
    memcpy(data + 16, (char *)&res, 8);

  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  duration = (end.tv_sec - start.tv_sec) * 1000000000LL +
             (end.tv_nsec - start.tv_nsec);
  printf("xxh3 duration:          %lld ns\n", duration);

  memset(data, 0, 4097);
  clock_gettime(CLOCK_MONOTONIC, &start);
  for (i = 0; i < 100000000; ++i) {

    res = t1ha0_ia32aes(data, 4097);
    memcpy(data + 16, (char *)&res, 8);

  }

  clock_gettime(CLOCK_MONOTONIC, &end);
  duration = (end.tv_sec - start.tv_sec) * 1000000000LL +
             (end.tv_nsec - start.tv_nsec);
  printf("t1ha0_ia32aes duration: %lld ns\n", duration);

  return 0;

}

