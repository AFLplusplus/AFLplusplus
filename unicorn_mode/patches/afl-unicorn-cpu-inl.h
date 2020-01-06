/*
   american fuzzy lop++ - unicorn instrumentation
   ----------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   Adapted for afl-unicorn by Dominik Maier <mail@dmnk.co>

   CompareCoverage and NeverZero counters by Andrea Fioraldi
                                  <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of Unicorn 1.0.1. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting libunicorn binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "afl-unicorn-common.h"

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* A snippet patched into tb_find_slow to inform the parent process that
   we have hit a new block that hasn't been translated yet, and to tell
   it to translate within its own context, too (this avoids translation
   overhead in the next forked-off copy). */

#define AFL_UNICORN_CPU_SNIPPET1         \
  do {                                   \
                                         \
    afl_request_tsl(pc, cs_base, flags); \
                                         \
  } while (0)

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_UNICORN_CPU_SNIPPET2          \
  do {                                    \
                                          \
    if (unlikely(afl_first_instr == 0)) { \
                                          \
      afl_setup(env->uc);                 \
      afl_forkserver(env);                \
      afl_first_instr = 1;                \
                                          \
    }                                     \
    afl_maybe_log(env->uc, tb->pc);       \
                                          \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* Set in the child process in forkserver mode: */

static unsigned char afl_fork_child;
static unsigned int  afl_forksrv_pid;

/* Function declarations. */

static void        afl_setup(struct uc_struct* uc);
static void        afl_forkserver(CPUArchState*);
static inline void afl_maybe_log(struct uc_struct* uc, unsigned long);

static void afl_wait_tsl(CPUArchState*, int);
static void afl_request_tsl(target_ulong, target_ulong, uint64_t);

static TranslationBlock* tb_find_slow(CPUArchState*, target_ulong, target_ulong,
                                      uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {

  target_ulong pc;
  target_ulong cs_base;
  uint64_t     flags;

};

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(struct uc_struct* uc) {

  char *id_str = getenv(SHM_ENV_VAR), *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    uc->afl_inst_rms = MAP_SIZE * r / 100;

  } else {

    uc->afl_inst_rms = MAP_SIZE;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    uc->afl_area_ptr = shmat(shm_id, NULL, 0);

    if (uc->afl_area_ptr == (void*)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) uc->afl_area_ptr[0] = 1;

  }

  /* Maintain for compatibility */
  if (getenv("AFL_QEMU_COMPCOV")) { uc->afl_compcov_level = 1; }
  if (getenv("AFL_COMPCOV_LEVEL")) {

    uc->afl_compcov_level = atoi(getenv("AFL_COMPCOV_LEVEL"));

  }

}

/* Fork server logic, invoked once we hit first emulated instruction. */

static void afl_forkserver(CPUArchState* env) {

  static unsigned char tmp[4];

  if (!env->uc->afl_area_ptr) return;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    pid_t child_pid;
    int   status, t_fd[2];

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, tmp, 4) != 4) exit(2);

    /* Establish a channel with child to grab translation commands. We'll
       read from t_fd[0], child will write to TSL_FD. */

    if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) exit(3);
    close(t_fd[1]);

    child_pid = fork();
    if (child_pid < 0) exit(4);

    if (!child_pid) {

      /* Child process. Close descriptors and run free. */

      afl_fork_child = 1;
      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);
      close(t_fd[0]);
      return;

    }

    /* Parent. */

    close(TSL_FD);

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, 0) < 0) exit(6);
    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

/* The equivalent of the tuple logging routine from afl-as.h. */

static inline void afl_maybe_log(struct uc_struct* uc, unsigned long cur_loc) {

  static __thread unsigned long prev_loc;

  u8* afl_area_ptr = uc->afl_area_ptr;

  if (!afl_area_ptr) return;

  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  /* Implement probabilistic instrumentation by looking at scrambled block
     address. This keeps the instrumented locations stable across runs. */

  if (cur_loc >= uc->afl_inst_rms) return;

  register uintptr_t afl_idx = cur_loc ^ prev_loc;

  INC_AFL_AREA(afl_idx);

  prev_loc = cur_loc >> 1;

}

/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it. When this happens,
   we tell the parent to mirror the operation, so that the next fork() has a
   cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint64_t flags) {

  struct afl_tsl t;

  if (!afl_fork_child) return;

  t.pc = pc;
  t.cs_base = cb;
  t.flags = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUArchState* env, int fd) {

  struct afl_tsl t;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) break;

    tb_find_slow(env, t.pc, t.cs_base, t.flags);

  }

  close(fd);

}

