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
#include <limits.h>

#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
  #include <sys/stat.h>
  #include <fcntl.h>
#endif

/* this lets the source compile without afl-clang-fast/lto */
#ifndef __AFL_FUZZ_TESTCASE_LEN
  #include "afl-record-compat.h"
#endif

__AFL_FUZZ_INIT();

/* Main entry point. */

/* To ensure checks are not optimized out it is recommended to disable
   code optimization for the fuzzer harness main() */
#pragma clang optimize off
#pragma GCC optimize("O0")

int main(int argc, char **argv) {

  ssize_t        len;                        /* how much input did we read? */
  unsigned char *buf;                        /* test case buffer pointer    */

#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
  int fd;

  if (argc < 2) { printf("Need an input file!"); }
#endif

  /* The number passed to __AFL_LOOP() controls the maximum number of
     iterations before the loop exits and the program is allowed to
     terminate normally. This limits the impact of accidental memory leaks
     and similar hiccups. */

  __AFL_INIT();

#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
  buf = malloc(1000);
#else
  buf = __AFL_FUZZ_TESTCASE_BUF;  // this must be assigned before __AFL_LOOP!
#endif

  while (__AFL_LOOP(UINT_MAX)) {  // increase if you have good stability

#ifdef AFL_PERSISTENT_REPLAY_ARGPARSE
    fd = open(argv[1], O_RDONLY);
    len = read(fd, buf, 1000);
    close(fd);
#else
    len = __AFL_FUZZ_TESTCASE_LEN;  // do not use the macro directly in a call!
#endif

    // fprintf(stderr, "input: %zd \"%s\"\n", len, buf);

    /* do we have enough data? */
    if (len < 8) continue;

    if (strcmp((char *)buf, "thisisateststring") == 0) printf("teststring\n");

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
              if (buf[5] == '!') {

                printf("six\n");
                abort();

              } else {

                if (buf[5] == 'O') {

                  // hang
                  while (1) {

                    continue;

                  };

                }

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

