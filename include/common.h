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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "types.h"
#include "stdbool.h"

/* STRINGIFY_VAL_SIZE_MAX will fit all stringify_ strings. */

#define STRINGIFY_VAL_SIZE_MAX (16)

void detect_file_args(char **argv, u8 *prog_in, u8 *use_stdin);
void check_environment_vars(char **env);

char **argv_cpy_dup(int argc, char **argv);
void   argv_cpy_free(char **argv);

char **get_qemu_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char **get_wine_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char * get_afl_env(char *env);

extern u8  be_quiet;
extern u8 *doc_path;                    /* path to documentation dir        */

/* Get unix time in milliseconds */

u64 get_cur_time(void);

/* Get unix time in microseconds */

u64 get_cur_time_us(void);

/* Describe integer. The buf should be
   at least 6 bytes to fit all ints we randomly see.
   Will return buf for convenience. */

u8 *stringify_int(u8 *buf, size_t len, u64 val);

/* Describe float. Similar as int. */

u8 *stringify_float(u8 *buf, size_t len, double val);

/* Describe integer as memory size. */

u8 *stringify_mem_size(u8 *buf, size_t len, u64 val);

/* Describe time delta as string.
   Returns a pointer to buf for convenience. */

u8 *stringify_time_diff(u8 *buf, size_t len, u64 cur_ms, u64 event_ms);

/* Unsafe Describe integer. The buf sizes are not checked.
   This is unsafe but fast.
   Will return buf for convenience. */

u8 *u_stringify_int(u8 *buf, u64 val);

/* Unsafe describe float. Similar as unsafe int. */

u8 *u_stringify_float(u8 *buf, double val);

/* Unsafe describe integer as memory size. */

u8 *u_stringify_mem_size(u8 *buf, u64 val);

/* Unsafe describe time delta as string.
   Returns a pointer to buf for convenience. */

u8 *u_stringify_time_diff(u8 *buf, u64 cur_ms, u64 event_ms);

/* Wrapper for select() and read(), reading exactly len bytes.
  Returns the time passed to read.
  If the wait times out, returns timeout_ms + 1;
  Returns 0 if an error occurred (fd closed, signal, ...); */
u32 read_timed(s32 fd, void *buf, size_t len, u32 timeout_ms);

#endif

