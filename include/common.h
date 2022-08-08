/*
   american fuzzy lop++ - common routines header
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Gather some functions common to multiple executables

   - detect_file_args

 */

#ifndef __AFLCOMMON_H
#define __AFLCOMMON_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>
#include "types.h"

/* STRINGIFY_VAL_SIZE_MAX will fit all stringify_ strings. */

#define STRINGIFY_VAL_SIZE_MAX (16)

u32  check_binary_signatures(u8 *fn);
void detect_file_args(char **argv, u8 *prog_in, bool *use_stdin);
void print_suggested_envs(char *mispelled_env);
void check_environment_vars(char **env);

char **argv_cpy_dup(int argc, char **argv);
void   argv_cpy_free(char **argv);

char **get_cs_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char **get_qemu_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char **get_wine_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char  *get_afl_env(char *env);

/* Extract env vars from input string and set them using setenv()
   For use with AFL_TARGET_ENV, ... */
bool extract_and_set_env(u8 *env_str);

extern u8  be_quiet;
extern u8 *doc_path;                    /* path to documentation dir        */

/* Find binary, used by analyze, showmap, tmin
   @returns the path, allocating the string */

u8 *find_binary(u8 *fname);

/* find an afl binary */

u8 *find_afl_binary(u8 *own_loc, u8 *fname);

/* Parses the kill signal environment variable, FATALs on error.
  If the env is not set, sets the env to default_signal for the signal handlers
  and returns the default_signal. */
int parse_afl_kill_signal_env(u8 *afl_kill_signal_env, int default_signal);

/* Read a bitmap from file fname to memory
   This is for the -B option again. */

void read_bitmap(u8 *fname, u8 *map, size_t len);

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

/* Reads the map size from ENV */
u32 get_map_size(void);

/* create a stream file */
FILE *create_ffile(u8 *fn);

/* create a file */
s32 create_file(u8 *fn);

#endif

