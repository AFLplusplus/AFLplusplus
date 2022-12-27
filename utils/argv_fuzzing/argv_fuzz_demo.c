#include <stdio.h>
#include <string.h>
#include "argv-fuzz-inl.h"

int main(int argc, char **argv) {
AFL_INIT_ARGV();
  if (argc > 1 && strcmp(argv[1], "XYZ") == 0) {
    if (strcmp(argv[2], "TEST2") == 0) {
      abort();
    }
  } else {
    printf("Bad number of arguments!\n");
  }

  return 0;
}