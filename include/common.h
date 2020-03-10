/*
   american fuzzy lop++ - common routines header
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Gather some functions common to multiple executables

   - detect_file_args

 */

#ifndef __AFLCOMMON_H
#define __AFLCOMMON_H

#include <sys/time.h>
#include "types.h"
#include "stdbool.h"

void detect_file_args(char **argv, u8 *prog_in, u8 *use_stdin);
void check_environment_vars(char **env);

char **argv_cpy_dup(int argc, char **argv);
void   argv_cpy_free(char **argv);

char **get_qemu_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char **get_wine_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char * get_afl_env(char *env);

/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

#endif

