/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   TCG instrumentation and block chaining support by Andrea Biondo
                                      <andrea.biondo965@gmail.com>
   
   QEMU 3.1.0 port, TCG thread-safety and CompareCoverage by Andrea Fioraldi
                                      <andreafioraldi@gmail.com>

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

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

#include "../../config.h"
#include "tcg.h"
#include "tcg-op.h"

/* Declared in afl-qemu-cpu-inl.h */
extern unsigned char *afl_area_ptr;
extern unsigned int afl_inst_rms;
extern abi_ulong afl_start_code, afl_end_code;
extern u8 afl_enable_compcov;

void tcg_gen_afl_compcov_log_call(void *func, target_ulong cur_loc,
                                  TCGv_i64 arg1, TCGv_i64 arg2);

static void afl_compcov_log_16(target_ulong cur_loc, target_ulong arg1,
                               target_ulong arg2) {

  if ((arg1 & 0xff) == (arg2 & 0xff)) {
    afl_area_ptr[cur_loc]++;
  }
}

static void afl_compcov_log_32(target_ulong cur_loc, target_ulong arg1,
                               target_ulong arg2) {

  if ((arg1 & 0xff) == (arg2 & 0xff)) {
    afl_area_ptr[cur_loc]++;
    if ((arg1 & 0xffff) == (arg2 & 0xffff)) {
      afl_area_ptr[cur_loc +1]++;
      if ((arg1 & 0xffffff) == (arg2 & 0xffffff)) {
        afl_area_ptr[cur_loc +2]++;
      }
    }
  }
}

static void afl_compcov_log_64(target_ulong cur_loc, target_ulong arg1,
                               target_ulong arg2) {

  if ((arg1 & 0xff) == (arg2 & 0xff)) {
    afl_area_ptr[cur_loc]++;
    if ((arg1 & 0xffff) == (arg2 & 0xffff)) {
      afl_area_ptr[cur_loc +1]++;
      if ((arg1 & 0xffffff) == (arg2 & 0xffffff)) {
        afl_area_ptr[cur_loc +2]++;
        if ((arg1 & 0xffffffff) == (arg2 & 0xffffffff)) {
          afl_area_ptr[cur_loc +3]++;
          if ((arg1 & 0xffffffffff) == (arg2 & 0xffffffffff)) {
            afl_area_ptr[cur_loc +4]++;
            if ((arg1 & 0xffffffffffff) == (arg2 & 0xffffffffffff)) {
              afl_area_ptr[cur_loc +5]++;
              if ((arg1 & 0xffffffffffffff) == (arg2 & 0xffffffffffffff)) {
                afl_area_ptr[cur_loc +6]++;
              }
            }
          }
        }
      }
    }
  }
}


static void afl_gen_compcov(target_ulong cur_loc, TCGv_i64 arg1, TCGv_i64 arg2,
                            TCGMemOp ot) {

  void *func;
  
  if (!afl_enable_compcov || cur_loc > afl_end_code || cur_loc < afl_start_code)
    return;

  switch (ot) {
    case MO_64:
      func = &afl_compcov_log_64;
      break;
    case MO_32: 
      func = &afl_compcov_log_32;
      break;
    case MO_16:
      func = &afl_compcov_log_16;
      break;
    default:
      return;
  }
  
  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;
  
  if (cur_loc >= afl_inst_rms) return;
  
  tcg_gen_afl_compcov_log_call(func, cur_loc, arg1, arg2);
}
