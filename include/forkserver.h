/*
   american fuzzy lop++ - forkserver header
   ----------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code that implements a forkserver. This is used by the fuzzer
   as well the other components like afl-tmin.

 */

#ifndef __AFL_FORKSERVER_H
#define __AFL_FORKSERVER_H

#include <stdio.h>
#include <stdbool.h>

#include "types.h"

#ifdef __linux__
/**
 * Nyx related typedefs taken from libnyx.h
 */

typedef enum NyxReturnValue {

  Normal,
  Crash,
  Asan,
  Timeout,
  InvalidWriteToPayload,
  Error,
  IoError,
  Abort,

} NyxReturnValue;

typedef enum NyxProcessRole {

  StandAlone,
  Parent,
  Child,

} NyxProcessRole;

typedef struct {

  void *(*nyx_config_load)(const char *sharedir);
  void (*nyx_config_set_workdir_path)(void *config, const char *workdir);
  void (*nyx_config_set_input_buffer_size)(void    *config,
                                           uint32_t input_buffer_size);
  void (*nyx_config_set_input_buffer_write_protection)(
      void *config, bool input_buffer_write_protection);
  void (*nyx_config_set_hprintf_fd)(void *config, int32_t hprintf_fd);
  void (*nyx_config_set_process_role)(void *config, enum NyxProcessRole role);
  void (*nyx_config_set_reuse_snapshot_path)(void       *config,
                                             const char *reuse_snapshot_path);

  void *(*nyx_new)(void *config, uint32_t worker_id);
  void (*nyx_shutdown)(void *qemu_process);
  void (*nyx_option_set_reload_mode)(void *qemu_process, bool enable);
  void (*nyx_option_set_timeout)(void *qemu_process, uint8_t timeout_sec,
                                 uint32_t timeout_usec);
  void (*nyx_option_apply)(void *qemu_process);
  void (*nyx_set_afl_input)(void *qemu_process, uint8_t *buffer, uint32_t size);
  enum NyxReturnValue (*nyx_exec)(void *qemu_process);
  uint8_t *(*nyx_get_bitmap_buffer)(void *qemu_process);
  size_t (*nyx_get_bitmap_buffer_size)(void *qemu_process);
  uint32_t (*nyx_get_aux_string)(void *nyx_process, uint8_t *buffer,
                                 uint32_t size);

  bool (*nyx_remove_work_dir)(const char *workdir);
  bool (*nyx_config_set_aux_buffer_size)(void    *config,
                                         uint32_t aux_buffer_size);

} nyx_plugin_handler_t;

/* Imports helper functions to enable Nyx mode (Linux only )*/
nyx_plugin_handler_t *afl_load_libnyx_plugin(u8 *libnyx_binary);

#endif

typedef struct afl_forkserver {

  /* a program that includes afl-forkserver needs to define these */

  u8 *trace_bits;                       /* SHM with instrumentation bitmap  */

  s32 fsrv_pid,                         /* PID of the fork server           */
      child_pid,                        /* PID of the fuzzed program        */
      child_status,                     /* waitpid result for the child     */
      out_dir_fd;                       /* FD of the lock file              */

  s32 out_fd,                           /* Persistent fd for fsrv->out_file */
      dev_urandom_fd,                   /* Persistent fd for /dev/urandom   */

      dev_null_fd,                      /* Persistent fd for /dev/null      */
      fsrv_ctl_fd,                      /* Fork server control pipe (write) */
      fsrv_st_fd;                       /* Fork server status pipe (read)   */

  u32 exec_tmout;                       /* Configurable exec timeout (ms)   */
  u32 init_tmout;                       /* Configurable init timeout (ms)   */
  u32 map_size;                         /* map size used by the target      */
  u32 real_map_size;                    /* real map size, unaligned         */
  u32 snapshot;                         /* is snapshot feature used         */
  u64 mem_limit;                        /* Memory cap for child (MB)        */

  u64 total_execs;                      /* How often run_target was called  */

  u8 *out_file,                         /* File to fuzz, if any             */
      *target_path;                     /* Path of the target               */

  FILE *plot_file,                      /* Gnuplot output file              */
      *det_plot_file;

  /* Note: last_run_timed_out is u32 to send it to the child as 4 byte array */
  u32 last_run_timed_out;               /* Traced process timed out?        */

  u8 last_kill_signal;                  /* Signal that killed the child     */

  bool use_shmem_fuzz;                  /* use shared mem for test cases    */

  bool support_shmem_fuzz;              /* set by afl-fuzz                  */

  bool use_fauxsrv;                     /* Fauxsrv for non-forking targets? */

  bool qemu_mode;                       /* if running in qemu mode or not   */

  bool frida_mode;                     /* if running in frida mode or not   */

  bool frida_asan;                    /* if running with asan in frida mode */

  bool cs_mode;                      /* if running in CoreSight mode or not */

  bool use_stdin;                       /* use stdin for sending data       */

  bool no_unlink;                       /* do not unlink cur_input          */

  bool uses_asan;                       /* Target uses ASAN?                */

  bool debug;                           /* debug mode?                      */

  bool uses_crash_exitcode;             /* Custom crash exitcode specified? */
  u8   crash_exitcode;                  /* The crash exitcode specified     */

  u32 *shmem_fuzz_len;                  /* length of the fuzzing test case  */

  u8 *shmem_fuzz;                       /* allocated memory for fuzzing     */

  char *cmplog_binary;                  /* the name of the cmplog binary    */

  /* persistent mode replay functionality */
  u32 persistent_record;                /* persistent replay setting        */
#ifdef AFL_PERSISTENT_RECORD
  u32  persistent_record_idx;           /* persistent replay cache ptr      */
  u32  persistent_record_cnt;           /* persistent replay counter        */
  u8  *persistent_record_dir;
  u8 **persistent_record_data;
  u32 *persistent_record_len;
  s32  persistent_record_pid;
#endif

  /* Function to kick off the forkserver child */
  void (*init_child_func)(struct afl_forkserver *fsrv, char **argv);

  u8 *afl_ptr;                          /* for autodictionary: afl ptr      */

  void (*add_extra_func)(void *afl_ptr, u8 *mem, u32 len);

  u8 child_kill_signal;
  u8 fsrv_kill_signal;

  u8 persistent_mode;

  u32 max_length;

#ifdef __linux__
  nyx_plugin_handler_t *nyx_handlers;
  char                 *out_dir_path;    /* path to the output directory     */
  u8                    nyx_mode;        /* if running in nyx mode or not    */
  bool                  nyx_parent;      /* create initial snapshot          */
  bool                  nyx_standalone;  /* don't serialize the snapshot     */
  void                 *nyx_runner;      /* nyx runner object                */
  u32                   nyx_id;          /* nyx runner id (0 -> master)      */
  u32                   nyx_bind_cpu_id; /* nyx runner cpu id                */
  char                 *nyx_aux_string;
  u32                   nyx_aux_string_len;
  bool                  nyx_use_tmp_workdir;
  char                 *nyx_tmp_workdir_path;
  s32                   nyx_log_fd;
#endif

#ifdef __AFL_CODE_COVERAGE
  u8 *persistent_trace_bits;                   /* Persistent copy of bitmap */
#endif

  void *custom_data_ptr;
  u8   *custom_input;
  u32   custom_input_len;
  void (*late_send)(void *, const u8 *, size_t);

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
u32  afl_fsrv_get_mapsize(afl_forkserver_t *fsrv, char **argv,
                          volatile u8 *stop_soon_p, u8 debug_child_output);
void afl_fsrv_write_to_testcase(afl_forkserver_t *fsrv, u8 *buf, size_t len);
fsrv_run_result_t afl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout,
                                      volatile u8 *stop_soon_p);
void              afl_fsrv_killall(void);
void              afl_fsrv_deinit(afl_forkserver_t *fsrv);
void              afl_fsrv_kill(afl_forkserver_t *fsrv);

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

