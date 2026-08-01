#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef __AFL_COVERAGE_DISCARD
  #define __AFL_COVERAGE_DISCARD() ((void)0)
#endif

#ifdef __AFL_COMPILER
void __afl_coverage_discard(void);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *buf, size_t len) {

  if (len < 2) return 0;

  uint16_t v = 0;
  memcpy(&v, buf, sizeof(v));
  if (v == 0xffff) abort();

  return 0;

}

#ifdef __AFL_COMPILER
int main(int argc, char *argv[]) {

  (void)argc;
  (void)argv;

  unsigned char buf[1024];
  ssize_t       i;
  while (__AFL_LOOP(1000)) {

    __AFL_COVERAGE_DISCARD();
    i = read(0, (char *)buf, sizeof(buf));
    if (i < 1) continue;
    LLVMFuzzerTestOneInput(buf, (size_t)i);

  }

  return 0;

}

#endif

