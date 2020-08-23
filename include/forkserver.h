/*
   american fuzzy lop++ - forkserver header
   ----------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#ifndef __AFL_FORKSERVER_H
#define __AFL_FORKSERVER_H

#include <stdio.h>
#include <stdbool.h>

#include "types.h"

typedef struct afl_forkserver {

  /* a program that includes afl-forkserver needs to define these */

  u8  uses_asan;                        /* Target uses ASAN?                */
  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */
  u8  use_stdin;                        /* use stdin for sending data       */

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      child_status,                     /* waitpid result for the child     */
      out_dir_fd;                       /* FD of the lock file              */

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */
      dev_urandom_fd,                   /* Persistent fd for /dev/urandom   */

      dev_null_fd,                      /* Persistent fd for /dev/null      */
      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u8 no_unlink;                         /* do not unlink cur_input          */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 init_tmout;                       /* Configurable init timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */
  u32 snapshot;                         /* is snapshot feature used         */
  u64 mem_limit;                        /* Memory cap for child (MB)        */

  u64 total_execs;                      /* How often run_target was called  */

  u8 *out_file,                         /* File to fuzz, if any             */
      *target_path;                     /* Path of the target               */

  FILE *plot_file;                      /* Gnuplot output file              */

  /* Note: lat_run_timed_out is u32 to send it to the child as 4 byte array */
  u32 last_run_timed_out;               /* Traced process timed out?        */

  u8 last_kill_signal;                  /* Signal that killed the child     */

  u8 use_shmem_fuzz;                    /* use shared mem for test cases    */

  u8 support_shmem_fuzz;                /* set by afl-fuzz                  */

  u8 use_fauxsrv;                       /* Fauxsrv for non-forking targets? */

  u8 qemu_mode;                         /* if running in qemu mode or not   */

  u32 *shmem_fuzz_len;                  /* length of the fuzzing test case  */

  u8 *shmem_fuzz;                       /* allocated memory for fuzzing     */

  char *cmplog_binary;                  /* the name of the cmplog binary    */

  /* Function to kick off the forkserver child */
  void (*init_child_func)(struct afl_forkserver *fsrv, char **argv);

  u8 *afl_ptr;                          /* for autodictionary: afl ptr      */

  void (*add_extra_func)(void *afl_ptr, u8 *mem, u32 len);

} afl_forkserver_t;

typedef enum fsrv_run_result {

  /* 00 */ FSRV_RUN_OK = 0,
  /* 01 */ FSRV_RUN_TMOUT,
  /* 02 */ FSRV_RUN_CRASH,
  /* 03 */ FSRV_RUN_ERROR,
  /* 04 */ FSRV_RUN_NOINST,
  /* 05 */ FSRV_RUN_NOBITS,

} fsrv_run_result_t;

void afl_fsrv_init(afl_forkserver_t *fsrv);
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from);
void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output);
void afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len);
fsrv_run_result_t afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
                                      volatile u8 *stop_soon_p);
void              afl_fsrv_killall(void);
void              afl_fsrv_deinit(afl_forkserver_t *fsrv);

#ifdef __APPLE__
  #define MSG_FORK_ON_APPLE                                                    \
    "    - On MacOS X, the semantics of fork() syscalls are non-standard and " \
    "may\n"                                                                    \
    "      break afl-fuzz performance optimizations when running "             \
    "platform-specific\n"                                                      \
    "      targets. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"
#else
  #define MSG_FORK_ON_APPLE ""
#endif

#ifdef RLIMIT_AS
  #define MSG_ULIMIT_USAGE "      ( ulimit -Sv $[%llu << 10];"
#else
  #define MSG_ULIMIT_USAGE "      ( ulimit -Sd $[%llu << 10];"
#endif                                                        /* ^RLIMIT_AS */

#endif

