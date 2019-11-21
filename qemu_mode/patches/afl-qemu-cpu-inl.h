/*
   american fuzzy lop++ - high-performance binary-only instrumentation
   -------------------------------------------------------------------

   Originally written by Andrew Griffiths <agriffiths@google.com> and
                         Michal Zalewski

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>

   QEMU 3.1.1 port, TCG thread-safety, CompareCoverage and NeverZero
   counters by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 3.1.1. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#include <sys/shm.h>
#include "../../config.h"
#include "afl-qemu-common.h"

#define PERSISTENT_DEFAULT_MAX_CNT 1000

/***************************
 * VARIOUS AUXILIARY STUFF *
 ***************************/

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2         \
  do {                                \
                                      \
    if (itb->pc == afl_entry_point) { \
                                      \
      afl_setup();                    \
      afl_forkserver(cpu);            \
                                      \
    }                                 \
                                      \
  } while (0)

/* We use one additional file descriptor to relay "needs translation"
   messages between the child and the fork server. */

#define TSL_FD (FORKSRV_FD - 1)

/* This is equivalent to afl-as.h: */

static unsigned char
               dummy[MAP_SIZE]; /* costs MAP_SIZE but saves a few instructions */
unsigned char *afl_area_ptr = dummy;          /* Exported for afl_gen_trace */

/* Exported variables populated by the code patched into elfload.c: */

abi_ulong afl_entry_point,                      /* ELF entry point (_start) */
    afl_start_code,                             /* .text start pointer      */
    afl_end_code;                               /* .text end pointer        */

abi_ulong    afl_persistent_addr, afl_persistent_ret_addr;
unsigned int afl_persistent_cnt;

u8 afl_compcov_level;

__thread abi_ulong afl_prev_loc;

/* Set in the child process in forkserver mode: */

static int    forkserver_installed = 0;
unsigned char afl_fork_child;
unsigned int  afl_forksrv_pid;
unsigned char is_persistent;
target_long   persistent_stack_offset;
unsigned char persistent_first_pass = 1;
unsigned char persistent_save_gpr;
target_ulong  persistent_saved_gpr[AFL_REGS_NUM];
int           persisent_retaddr_offset;

/* Instrumentation ratio: */

unsigned int afl_inst_rms = MAP_SIZE;         /* Exported for afl_gen_trace */

/* Function declarations. */

static void afl_setup(void);
static void afl_forkserver(CPUState *);

static void afl_wait_tsl(CPUState *, int);
static void afl_request_tsl(target_ulong, target_ulong, uint32_t, uint32_t,
                            TranslationBlock *, int);

/* Data structures passed around by the translate handlers: */

struct afl_tb {

  target_ulong pc;
  target_ulong cs_base;
  uint32_t     flags;
  uint32_t     cf_mask;

};

struct afl_tsl {

  struct afl_tb tb;
  char          is_chain;

};

struct afl_chain {

  struct afl_tb last_tb;
  uint32_t      cf_mask;
  int           tb_exit;

};

/* Some forward decls: */

TranslationBlock *tb_htable_lookup(CPUState *, target_ulong, target_ulong,
                                   uint32_t, uint32_t);
static inline TranslationBlock *tb_find(CPUState *, TranslationBlock *, int,
                                        uint32_t);
static inline void              tb_add_jump(TranslationBlock *tb, int n,
                                            TranslationBlock *tb_next);

/*************************
 * ACTUAL IMPLEMENTATION *
 *************************/

/* Set up SHM region and initialize other stuff. */

static void afl_setup(void) {

  char *id_str = getenv(SHM_ENV_VAR), *inst_r = getenv("AFL_INST_RATIO");

  int shm_id;

  if (inst_r) {

    unsigned int r;

    r = atoi(inst_r);

    if (r > 100) r = 100;
    if (!r) r = 1;

    afl_inst_rms = MAP_SIZE * r / 100;

  }

  if (id_str) {

    shm_id = atoi(id_str);
    afl_area_ptr = shmat(shm_id, NULL, 0);

    if (afl_area_ptr == (void *)-1) exit(1);

    /* With AFL_INST_RATIO set to a low value, we want to touch the bitmap
       so that the parent doesn't give up on us. */

    if (inst_r) afl_area_ptr[0] = 1;

  }

  if (getenv("AFL_INST_LIBS")) {

    afl_start_code = 0;
    afl_end_code = (abi_ulong)-1;

  }

  if (getenv("AFL_CODE_START"))
    afl_start_code = strtoll(getenv("AFL_CODE_START"), NULL, 16);
  if (getenv("AFL_CODE_END"))
    afl_end_code = strtoll(getenv("AFL_CODE_END"), NULL, 16);

  /* Maintain for compatibility */
  if (getenv("AFL_QEMU_COMPCOV")) { afl_compcov_level = 1; }
  if (getenv("AFL_COMPCOV_LEVEL")) {

    afl_compcov_level = atoi(getenv("AFL_COMPCOV_LEVEL"));

  }

  /* pthread_atfork() seems somewhat broken in util/rcu.c, and I'm
     not entirely sure what is the cause. This disables that
     behaviour, and seems to work alright? */

  rcu_disable_atfork();

  is_persistent = getenv("AFL_QEMU_PERSISTENT_ADDR") != NULL;

  if (is_persistent) {

    afl_persistent_addr = strtoll(getenv("AFL_QEMU_PERSISTENT_ADDR"), NULL, 0);
    if (getenv("AFL_QEMU_PERSISTENT_RET"))
      afl_persistent_ret_addr =
          strtoll(getenv("AFL_QEMU_PERSISTENT_RET"), NULL, 0);
    /* If AFL_QEMU_PERSISTENT_RET is not specified patch the return addr */

  }

  if (getenv("AFL_QEMU_PERSISTENT_GPR")) persistent_save_gpr = 1;

  if (getenv("AFL_QEMU_PERSISTENT_RETADDR_OFFSET"))
    persisent_retaddr_offset =
        strtoll(getenv("AFL_QEMU_PERSISTENT_RETADDR_OFFSET"), NULL, 0);

  if (getenv("AFL_QEMU_PERSISTENT_CNT"))
    afl_persistent_cnt = strtoll(getenv("AFL_QEMU_PERSISTENT_CNT"), NULL, 0);
  else
    afl_persistent_cnt = PERSISTENT_DEFAULT_MAX_CNT;

}

static void print_mappings(void) {

  u8    buf[MAX_LINE];
  FILE *f = fopen("/proc/self/maps", "r");

  if (!f) return;

  while (fgets(buf, MAX_LINE, f))
    printf("%s", buf);

  fclose(f);

}

/* Fork server logic, invoked once we hit _start. */

static void afl_forkserver(CPUState *cpu) {

  static unsigned char tmp[4];

  if (forkserver_installed == 1) return;
  forkserver_installed = 1;

  if (getenv("AFL_QEMU_DEBUG_MAPS")) print_mappings();

  // if (!afl_area_ptr) return; // not necessary because of fixed dummy buffer

  pid_t child_pid;
  int   t_fd[2];
  u8    child_stopped = 0;

  /* Tell the parent that we're alive. If the parent doesn't want
     to talk, assume that we're not running in forkserver mode. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  afl_forksrv_pid = getpid();

  /* All right, let's await orders... */

  while (1) {

    int status;
    u32 was_killed;

    /* Whoops, parent dead? */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) exit(2);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {

      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) exit(8);

    }

    if (!child_stopped) {

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

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* Parent. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) exit(5);

    /* Collect translation requests until child dies and closes the pipe. */

    afl_wait_tsl(cpu, t_fd[0]);

    /* Get and relay exit status to parent. */

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0) exit(6);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    if (write(FORKSRV_FD + 1, &status, 4) != 4) exit(7);

  }

}

/* A simplified persistent mode handler, used as explained in README.llvm. */

void afl_persistent_loop() {

  static u32            cycle_cnt;
  static struct afl_tsl exit_cmd_tsl = {{-1, 0, 0, 0}, NULL};

  if (!afl_fork_child) return;

  if (persistent_first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(afl_area_ptr, 0, MAP_SIZE);
      afl_area_ptr[0] = 1;
      afl_prev_loc = 0;

    }

    cycle_cnt = afl_persistent_cnt;
    persistent_first_pass = 0;
    persistent_stack_offset = TARGET_LONG_BITS / 8;

    return;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      if (write(TSL_FD, &exit_cmd_tsl, sizeof(struct afl_tsl)) !=
          sizeof(struct afl_tsl)) {

        /* Exit the persistent loop on pipe error */
        afl_area_ptr = dummy;
        exit(0);

      }

      raise(SIGSTOP);

      afl_area_ptr[0] = 1;
      afl_prev_loc = 0;

    } else {

      afl_area_ptr = dummy;
      exit(0);

    }

  }

}

/* This code is invoked whenever QEMU decides that it doesn't have a
   translation of a particular block and needs to compute it, or when it
   decides to chain two TBs together. When this happens, we tell the parent to
   mirror the operation, so that the next fork() has a cached copy. */

static void afl_request_tsl(target_ulong pc, target_ulong cb, uint32_t flags,
                            uint32_t cf_mask, TranslationBlock *last_tb,
                            int tb_exit) {

  struct afl_tsl   t;
  struct afl_chain c;

  if (!afl_fork_child) return;

  t.tb.pc = pc;
  t.tb.cs_base = cb;
  t.tb.flags = flags;
  t.tb.cf_mask = cf_mask;
  t.is_chain = (last_tb != NULL);

  if (write(TSL_FD, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl))
    return;

  if (t.is_chain) {

    c.last_tb.pc = last_tb->pc;
    c.last_tb.cs_base = last_tb->cs_base;
    c.last_tb.flags = last_tb->flags;
    c.cf_mask = cf_mask;
    c.tb_exit = tb_exit;

    if (write(TSL_FD, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
      return;

  }

}

/* This is the other side of the same channel. Since timeouts are handled by
   afl-fuzz simply killing the child, we can just wait until the pipe breaks. */

static void afl_wait_tsl(CPUState *cpu, int fd) {

  struct afl_tsl    t;
  struct afl_chain  c;
  TranslationBlock *tb, *last_tb;

  while (1) {

    u8 invalid_pc = 0;

    /* Broken pipe means it's time to return to the fork server routine. */

    if (read(fd, &t, sizeof(struct afl_tsl)) != sizeof(struct afl_tsl)) break;

    /* Exit command for persistent */

    if (t.tb.pc == (target_ulong)(-1)) return;

    tb = tb_htable_lookup(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);

    if (!tb) {

      /* The child may request to transate a block of memory that is not
         mapped in the parent (e.g. jitted code or dlopened code).
         This causes a SIGSEV in gen_intermediate_code() and associated
         subroutines. We simply avoid caching of such blocks. */

      if (is_valid_addr(t.tb.pc)) {

        mmap_lock();
        tb = tb_gen_code(cpu, t.tb.pc, t.tb.cs_base, t.tb.flags, t.tb.cf_mask);
        mmap_unlock();

      } else {

        invalid_pc = 1;

      }

    }

    if (t.is_chain) {

      if (read(fd, &c, sizeof(struct afl_chain)) != sizeof(struct afl_chain))
        break;

      if (!invalid_pc) {

        last_tb = tb_htable_lookup(cpu, c.last_tb.pc, c.last_tb.cs_base,
                                   c.last_tb.flags, c.cf_mask);
        if (last_tb) { tb_add_jump(last_tb, c.tb_exit, tb); }

      }

    }

  }

  close(fd);

}

