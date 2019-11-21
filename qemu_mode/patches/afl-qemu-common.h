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
   code of QEMU 3.1.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */

#ifndef __AFL_QEMU_COMMON
#define __AFL_QEMU_COMMON

#include "../../config.h"

#ifndef CPU_NB_REGS
#define AFL_REGS_NUM 1000
#else
#define AFL_REGS_NUM CPU_NB_REGS
#endif

/* NeverZero */

#if (defined(__x86_64__) || defined(__i386__)) && defined(AFL_QEMU_NOT_ZERO)
#define INC_AFL_AREA(loc)           \
  asm volatile(                     \
      "incb (%0, %1, 1)\n"          \
      "adcb $0, (%0, %1, 1)\n"      \
      : /* no out */                \
      : "r"(afl_area_ptr), "r"(loc) \
      : "memory", "eax")
#else
#define INC_AFL_AREA(loc) afl_area_ptr[loc]++
#endif

/* Declared in afl-qemu-cpu-inl.h */

extern unsigned char *afl_area_ptr;
extern unsigned int   afl_inst_rms;
extern abi_ulong      afl_start_code, afl_end_code;
extern abi_ulong      afl_persistent_addr;
extern abi_ulong      afl_persistent_ret_addr;
extern u8             afl_compcov_level;
extern unsigned char  afl_fork_child;
extern unsigned char  is_persistent;
extern target_long    persistent_stack_offset;
extern unsigned char  persistent_first_pass;
extern unsigned char  persistent_save_gpr;
extern target_ulong   persistent_saved_gpr[AFL_REGS_NUM];
extern int            persisent_retaddr_offset;

extern __thread abi_ulong afl_prev_loc;

void afl_debug_dump_saved_regs();

void afl_persistent_loop();

void tcg_gen_afl_call0(void *func);
void tcg_gen_afl_compcov_log_call(void *func, target_ulong cur_loc,
                                  TCGv_i64 arg1, TCGv_i64 arg2);

void tcg_gen_afl_maybe_log_call(target_ulong cur_loc);

void afl_float_compcov_log_32(target_ulong cur_loc, float32 arg1, float32 arg2,
                              void *status);
void afl_float_compcov_log_64(target_ulong cur_loc, float64 arg1, float64 arg2,
                              void *status);
void afl_float_compcov_log_80(target_ulong cur_loc, floatx80 arg1,
                              floatx80 arg2);

/* Check if an address is valid in the current mapping */

static inline int is_valid_addr(target_ulong addr) {

  int          l, flags;
  target_ulong page;
  void *       p;

  page = addr & TARGET_PAGE_MASK;
  l = (page + TARGET_PAGE_SIZE) - addr;

  flags = page_get_flags(page);
  if (!(flags & PAGE_VALID) || !(flags & PAGE_READ)) return 0;

  return 1;

}

#endif

