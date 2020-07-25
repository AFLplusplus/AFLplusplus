#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdint.h>

__AFL_FUZZ_INIT();

int main(void) {

  ssize_t bytes_read;
  
  __AFL_INIT();
  float *magic = (float*)__AFL_FUZZ_TESTCASE_BUF;
  
  while (__AFL_LOOP(INT_MAX)) {

    if (__AFL_FUZZ_TESTCASE_LEN != sizeof(float)) return 1;
    /* 15 + 1/2 + 1/8 + 1/32 + 1/128 */
    if ((-*magic == 15.0 + 0.5 + 0.125 + 0.03125 + 0.0078125)) abort();
  
  }

  return 0;

}

