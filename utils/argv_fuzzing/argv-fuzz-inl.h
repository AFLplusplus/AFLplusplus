/*
   american fuzzy lop++ - sample argv fuzzing wrapper
   ------------------------------------------------

   Originally written by Michal Zalewski

   Copyright 2015 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This file shows a simple way to fuzz command-line parameters with stock
   afl-fuzz. To use, add:

   #include "/path/to/argv-fuzz-inl.h"

   ...to the file containing main(), ideally placing it after all the
   standard includes. Next, put AFL_INIT_ARGV(); near the very beginning of
   main().

   This will cause the program to read NUL-delimited input from stdin and
   put it in argv[]. Two subsequent NULs terminate the array. Empty
   params are encoded as a lone 0x02. Lone 0x02 can't be generated, but
   that shouldn't matter in real life.

   If you would like to always preserve argv[0], use this instead:
   AFL_INIT_SET0("prog_name");

*/

#ifndef _HAVE_ARGV_FUZZ_INL
#define _HAVE_ARGV_FUZZ_INL

#include <string.h>
#include <unistd.h>

#define AFL_INIT_ARGV()          \
  do {                           \
                                 \
    argv = afl_init_argv(&argc); \
                                 \
  } while (0)

#define AFL_INIT_SET0(_p)        \
  do {                           \
                                 \
    argv = afl_init_argv(&argc); \
    argv[0] = (_p);              \
    if (!argc) argc = 1;         \
                                 \
  } while (0)

#define MAX_CMDLINE_LEN 100000
#define MAX_CMDLINE_PAR 50000

static char **afl_init_argv(int *argc) {

  static char  in_buf[MAX_CMDLINE_LEN];
  static char *ret[MAX_CMDLINE_PAR];

  char *ptr = in_buf;
  int   rc = 0;

  ssize_t num = 0;
  if ((num = read(0, in_buf, MAX_CMDLINE_LEN - 2)) < 0) {}
  if (in_buf[num - 1] == '\n') {
      in_buf[num - 1] = 0;
  }

  char delim = ' ';
  char *curarg = strtok(ptr, &delim);
  while (curarg && rc < MAX_CMDLINE_PAR) {
    ret[rc] = curarg;
    if (ret[rc][0] == 0x02 && !ret[rc][1]) ret[rc]++;
    rc++;
    curarg = strtok(NULL, &delim);
  }

  *argc = rc;

  return ret;

}

#undef MAX_CMDLINE_LEN
#undef MAX_CMDLINE_PAR

#endif                                              /* !_HAVE_ARGV_FUZZ_INL */
