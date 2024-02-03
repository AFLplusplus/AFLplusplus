/*
   american fuzzy lop++ - a trivial program to test the build
   --------------------------------------------------------
   Originally written by Michal Zalewski
   Copyright 2014 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:
     http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>

__AFL_FUZZ_INIT();

/* To ensure checks are not optimized out it is recommended to disable
   code optimization for the fuzzer harness main() */
#pragma clang optimize off
#pragma GCC            optimize("O0")

int main(int argc, char **argv) {

  __AFL_INIT();
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(UINT_MAX)) {  // if you have 100% stability

    unsigned int len = __AFL_FUZZ_TESTCASE_LEN;

#ifdef _AFL_DOCUMENT_MUTATIONS
    static unsigned int counter = 0;
    char                fn[32];
    sprintf(fn, "%09u:test-instr", counter);
    int fd_doc = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd_doc >= 0) {

      if (write(fd_doc, buf, len) != __afl_fuzz_len) {

        fprintf(stderr, "write of mutation file failed: %s\n", fn);
        unlink(fn);

      }

      close(fd_doc);

    }

    counter++;
#endif

    // fprintf(stderr, "len: %u\n", len);

    if (!len) continue;

    if (buf[0] == '0')
      printf("Looks like a zero to me!\n");
    else if (buf[0] == '1')
      printf("Pretty sure that is a one!\n");
    else
      printf("Neither one or zero? How quaint!\n");

  }

  return 0;

}

