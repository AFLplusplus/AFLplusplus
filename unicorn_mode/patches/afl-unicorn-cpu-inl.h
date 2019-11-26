/*
   american fuzzy lop++ - unicorn instrumentation
   ----------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   Adapted for afl-unicorn by Dominik Maier <mail@dmnk.co>

   CompareCoverage and NeverZero counters by Andrea Fioraldi
                                  <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

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
#include <unicorn.h>
#include "afl-unicorn-common.h"

/* We use one additional file descriptor to relay "needs translation"
   or "child done" messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

#define FF16 (0xFFFFFFFFFFFFFFFF)

/* Function declarations. */

static void        afl_setup(struct uc_struct*);
static inline uc_afl_ret afl_forkserver(CPUArchState*);
static inline void afl_maybe_log(struct uc_struct*, unsigned long);

static bool afl_wait_tsl(CPUArchState*, int);
static void afl_request_tsl(struct uc_struct* uc, target_ulong, target_ulong, uint64_t);
static uc_afl_ret afl_request_next(void);

static TranslationBlock* tb_find_slow(CPUArchState*, target_ulong, target_ulong, uint64_t);

/* Data structure passed around by the translate handlers: */

struct afl_tsl {

  target_ulong pc;
  target_ulong cs_base;
  uint64_t     flags;

};

/* Instead of adding a field, reuse this special one.
  this should have less overhead. */

static const struct afl_tsl AFL_NEXT_TESTCASE_REQUEST = {
  .pc = (target_ulong) FF16,
  .cs_base = (target_ulong) FF16,
  .flags = FF16,
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
    
    /* Not sure if this does anything.
      Also, for persistent mode, we want the map to be emtpy on every fork.
      As far as I can see, afl clears the map it after each testcase.
      So there is no reason why it shouldn't be empty on new forked children.
      In contrast to "normal" instrumentation, we never count branches before forking.
      */
    memset(uc->afl_area_ptr, 0, MAP_SIZE); 

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


/* Fork server logic, invoked by calling uc_afl_forkserver_start.
   Roughly follows https://github.com/vanhauser-thc/AFLplusplus/blob/c83e8e1e6255374b085292ba8673efdca7388d76/llvm_mode/afl-llvm-rt.o.c#L130 
   */

static inline uc_afl_ret afl_forkserver(CPUArchState* env) {

  static unsigned char tmp[4];
  pid_t   child_pid;
  int     t_fd[2];  // Channel between child and parent for tcg translation cache
  bool child_alive = false;

  if (!env->uc->afl_area_ptr) return UC_AFL_RET_NO_AFL;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return UC_AFL_RET_NO_AFL;

  void (*old_sigchld_handler)(int) = signal(SIGCHLD, SIG_DFL);

  while (1) {

    uint32_t was_killed;
    int      status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) return UC_AFL_RET_FINISHED;

    /* If we stopped the child in persistent mode, but there was a race
    condition and afl-fuzz already issued SIGKILL, write off the old
    process. */

    if (child_alive && was_killed) {

      child_alive = false;
      if (waitpid(child_pid, &status, 0) < 0) {
        perror("[!] Error waiting for child! ");
        return UC_AFL_RET_ERROR;
      }

    }

    if (!child_alive) {

      /* Child dead. Establish new a channel with child to grab translation commands.
        We'll read from t_fd[0], child will write to TSL_FD. */

      if (pipe(t_fd) || dup2(t_fd[1], TSL_FD) < 0) {
        perror("[!] Error creating pipe to child. ");
        return UC_AFL_RET_ERROR;
      }
      close(t_fd[1]);

      /* Create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) {
        perror("[!] Could not fork! ");
        return UC_AFL_RET_ERROR;
      }

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        signal(SIGCHLD, old_sigchld_handler);

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        close(t_fd[0]);
        env->uc->afl_child_request_next = afl_request_next;
        return UC_AFL_RET_CHILD;

      } else {

        /* If we don't close this in parent, we don't get notified on t_fd once child is gone. */

        close(TSL_FD);

      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      if (kill(child_pid, SIGCONT) < 0) {

        perror("[!] Child didn't continue. ");
        return UC_AFL_RET_ERROR;

      }
      child_alive = false;

    }

    /* In parent process: write PID to AFL. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) {
      return UC_AFL_RET_FINISHED;
    }

    /* Collect translation requests until child is finished (true) 
       or 0xdead (false) */

    child_alive = afl_wait_tsl(env, t_fd[0]);

    /* Get and relay exit status to parent. 
       No need to wait for WUNTRACED if child is not alive. */

    if (waitpid(child_pid, &status, child_alive ? WUNTRACED: 0) < 0) {

      // Zombie Child could not be collected. Scary!
      perror("[!] The child's exit code could not be determined. ");
      return UC_AFL_RET_ERROR;

    }


    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    child_alive = child_alive && WIFSTOPPED(status);

    /* Relay wait status to AFL pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) return UC_AFL_RET_FINISHED;

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

static inline void afl_request_tsl(struct uc_struct* uc, target_ulong pc, target_ulong cb, uint64_t flags) {

  /* Dual use: if this func is NULL, we're not a child process */

  if (!uc->afl_child_request_next) return;

  struct afl_tsl t = {0};

  t.pc = pc;
  t.cs_base = cb;
  t.flags = flags;

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

}

/* This code is invoked whenever the child decides that it is done with one fuzz-case. */

static uc_afl_ret afl_request_next(void) {

  if (write(TSL_FD, &AFL_NEXT_TESTCASE_REQUEST, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) return UC_AFL_RET_ERROR;

  return UC_AFL_RET_CHILD;

}


/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks.
   For returns true if child is still alive, else false */

static bool afl_wait_tsl(CPUArchState* env, int fd) {

  struct afl_tsl t;

  while (1) {

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) return false; // child is dead.

    /* We chose FF16 (MAX_INT64) for each member of our afl_next_testcase_request struct. */

    if (t.pc == AFL_NEXT_TESTCASE_REQUEST.pc && t.cs_base == AFL_NEXT_TESTCASE_REQUEST.cs_base 
        && t.flags == AFL_NEXT_TESTCASE_REQUEST.flags) return true; // child is still alive!

    tb_find_slow(env, t.pc, t.cs_base, t.flags);

  }

  close(fd);

}

