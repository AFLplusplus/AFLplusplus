#include <stdio.h>
#include <string.h>
#include "argv-fuzz-inl.h"

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(100000)) {
    int len = __AFL_FUZZ_TESTCASE_LEN;

    if (len < 8) continue;

    AFL_INIT_ARGV_PERSISTENT(buf);

    if (argc > 1 && strcmp(argv[1], "XYZ") == 0) {
      if (strcmp(argv[2], "TEST2") == 0) { abort(); }
    } else {
      printf("Bad number of arguments!\n");
    }
  }

  return 0;
}