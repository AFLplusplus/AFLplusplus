/*
   american fuzzy lop++ - persistent mode example
   --------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file demonstrates the high-performance "persistent mode" that may be
   suitable for fuzzing certain fast and well-behaved libraries, provided that
   they are stateless or that their internal state can be easily reset
   across runs.

   To make this work, the library and this shim need to be compiled in LLVM
   mode using afl-clang-fast (other compiler wrappers will *not* work).

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

__AFL_FUZZ_INIT();

unsigned int crc32_for_byte(unsigned int r) {

  for (int j = 0; j < 8; ++j)
    r = (r & 1 ? 0 : (unsigned int)0xEDB88320L) ^ r >> 1;
  return r ^ (unsigned int)0xFF000000L;

}

unsigned int crc32(unsigned char *data, unsigned int n_bytes) {

  static unsigned char table[0x100];
  unsigned int         crc = 0;
  if (!*table)
    for (unsigned int i = 0; i < 0x100; ++i)
      table[i] = crc32_for_byte(i);
  for (unsigned int i = 0; i < n_bytes; ++i)
    crc = table[(unsigned char)crc ^ (data)[i]] ^ crc >> 8;
  return crc;

}

/* Main entry point. */

int main(int argc, char **argv) {

  ssize_t        len;                        /* how much input did we read? */
  unsigned char *buf;                        /* test case buffer pointer    */

  /* The number passed to __AFL_LOOP() controls the maximum number of
     iterations before the loop exits and the program is allowed to
     terminate normally. This limits the impact of accidental memory leaks
     and similar hiccups. */

  buf = __AFL_FUZZ_TESTCASE_BUF;

  while (__AFL_LOOP(1000)) {

    len = __AFL_FUZZ_TESTCASE_LEN;

    /* do we have enough data? */
    if (len < 8) return 0;

    if (buf[0] == 'f') {

      printf("one\n");
      if (buf[1] == 'o') {

        printf("two\n");
        if (buf[2] == 'o') {

          printf("three\n");
          if (buf[3] == '!') {

            printf("four\n");
            if (buf[4] == '!') {

              printf("five\n");
              if (buf[6] == '!') {

                printf("six\n");
                abort();

              }

            }

          }

        }

      }

    }

    /*** END PLACEHOLDER CODE ***/

  }

  /* Once the loop is exited, terminate normally - AFL will restart the process
     when this happens, with a clean slate when it comes to allocated memory,
     leftover file descriptors, etc. */

  return 0;

}

