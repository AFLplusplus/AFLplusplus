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

typedef struct afl_forkserver {

  /* a program that includes afl-forkserver needs to define these */

  u8  uses_asan;                        /* Target uses ASAN?                */
  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */
  u8  use_stdin;                        /* use stdin for sending data       */

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      out_dir_fd;                       /* FD of the lock file              */

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */
#ifndef HAVE_ARC4RANDOM
      dev_urandom_fd,                   /* Persistent fd for /dev/urandom   */
#endif
      dev_null_fd,                      /* Persistent fd for /dev/null      */
      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */
  u32 snapshot;                         /* is snapshot feature used         */
  u64 mem_limit;                        /* Memory cap for child (MB)        */

  u8 *out_file,                         /* File to fuzz, if any             */
      *target_path;                                   /* Path of the target */

  FILE *plot_file;                      /* Gnuplot output file              */

  u8 child_timed_out;                   /* Traced process timed out?        */

  u8 use_fauxsrv;                       /* Fauxsrv for non-forking targets? */

  u32 prev_timed_out;                   /* if prev forkserver run timed out */

  u8 qemu_mode;                         /* if running in qemu mode or not   */

  char *cmplog_binary;                  /* the name of the cmplog binary    */

  /* Function to kick off the forkserver child */
  void (*init_child_func)(struct afl_forkserver *fsrv, char **argv);

  u8 *function_opt;                     /* for autodictionary: afl ptr      */

  void (*function_ptr)(void *afl_tmp, u8 *mem, u32 len);

} afl_forkserver_t;

void afl_fsrv_init(afl_forkserver_t *fsrv);
void afl_fsrv_init_dup(afl_forkserver_t *fsrv_to, afl_forkserver_t *from);
void afl_fsrv_start(afl_forkserver_t *fsrv, char **argv,
                    volatile u8 *stop_soon_p, u8 debug_child_output);
void afl_fsrv_killall(void);
void afl_fsrv_deinit(afl_forkserver_t *fsrv);

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

