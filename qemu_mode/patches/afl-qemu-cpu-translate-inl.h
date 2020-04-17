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
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

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

#include "afl-qemu-common.h"
#include "tcg.h"
#include "tcg-op.h"

#if TCG_TARGET_LONG_BITS == 64
#define _DEFAULT_MO MO_64
#else
#define _DEFAULT_MO MO_32
#endif

static void afl_gen_compcov(target_ulong cur_loc, TCGv arg1, TCGv arg2,
                            TCGMemOp ot, int is_imm) {

  if (cur_loc > afl_end_code || cur_loc < afl_start_code) return;

  if (__afl_cmp_map) {

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= CMP_MAP_W - 1;

    TCGv cur_loc_v = tcg_const_tl(cur_loc);

    switch (ot & MO_SIZE) {

      case MO_64:
        gen_helper_afl_cmplog_64(cur_loc_v, arg1, arg2);
        break;
      case MO_32:
        gen_helper_afl_cmplog_32(cur_loc_v, arg1, arg2);
        break;
      case MO_16:
        gen_helper_afl_cmplog_16(cur_loc_v, arg1, arg2);
        break;
      case MO_8:
        gen_helper_afl_cmplog_8(cur_loc_v, arg1, arg2);
        break;
      default:
        break;

    }

    tcg_temp_free(cur_loc_v);

  } else if (afl_compcov_level) {

    if (!is_imm && afl_compcov_level < 2) return;

    cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
    cur_loc &= MAP_SIZE - 7;

    TCGv cur_loc_v = tcg_const_tl(cur_loc);

    if (cur_loc >= afl_inst_rms) return;

    switch (ot & MO_SIZE) {

      case MO_64:
        gen_helper_afl_compcov_64(cur_loc_v, arg1, arg2);
        break;
      case MO_32:
        gen_helper_afl_compcov_32(cur_loc_v, arg1, arg2);
        break;
      case MO_16:
        gen_helper_afl_compcov_16(cur_loc_v, arg1, arg2);
        break;
      default:
        break;

    }

    tcg_temp_free(cur_loc_v);

  }

}

/* Routines for debug */
/*
static void log_x86_saved_gpr(void) {

  static const char reg_names[CPU_NB_REGS][4] = {

#ifdef TARGET_X86_64
        [R_EAX] = "rax",
        [R_EBX] = "rbx",
        [R_ECX] = "rcx",
        [R_EDX] = "rdx",
        [R_ESI] = "rsi",
        [R_EDI] = "rdi",
        [R_EBP] = "rbp",
        [R_ESP] = "rsp",
        [8]  = "r8",
        [9]  = "r9",
        [10] = "r10",
        [11] = "r11",
        [12] = "r12",
        [13] = "r13",
        [14] = "r14",
        [15] = "r15",
#else
        [R_EAX] = "eax",
        [R_EBX] = "ebx",
        [R_ECX] = "ecx",
        [R_EDX] = "edx",
        [R_ESI] = "esi",
        [R_EDI] = "edi",
        [R_EBP] = "ebp",
        [R_ESP] = "esp",
#endif

    };

  int i;
  for (i = 0; i < CPU_NB_REGS; ++i) {

    fprintf(stderr, "%s = %lx\n", reg_names[i], persistent_saved_gpr[i]);

  }

}

static void log_x86_sp_content(void) {

  fprintf(stderr, ">> SP = %lx -> %lx\n", persistent_saved_gpr[R_ESP],
*(unsigned long*)persistent_saved_gpr[R_ESP]);

}*/

static void callback_to_persistent_hook(void) {

  afl_persistent_hook_ptr(persistent_saved_gpr, guest_base);

}

static void gpr_saving(TCGv *cpu_regs, int regs_num) {

  int      i;
  TCGv_ptr gpr_sv;

  TCGv_ptr first_pass_ptr = tcg_const_ptr(&persistent_first_pass);
  TCGv     first_pass = tcg_temp_local_new();
  TCGv     one = tcg_const_tl(1);
  tcg_gen_ld8u_tl(first_pass, first_pass_ptr, 0);

  TCGLabel *lbl_restore_gpr = gen_new_label();
  tcg_gen_brcond_tl(TCG_COND_NE, first_pass, one, lbl_restore_gpr);

  // save GPR registers
  for (i = 0; i < regs_num; ++i) {

    gpr_sv = tcg_const_ptr(&persistent_saved_gpr[i]);
    tcg_gen_st_tl(cpu_regs[i], gpr_sv, 0);
    tcg_temp_free_ptr(gpr_sv);

  }

  gen_set_label(lbl_restore_gpr);

  afl_gen_tcg_plain_call(&afl_persistent_loop);

  if (afl_persistent_hook_ptr)
    afl_gen_tcg_plain_call(callback_to_persistent_hook);

  // restore GPR registers
  for (i = 0; i < regs_num; ++i) {

    gpr_sv = tcg_const_ptr(&persistent_saved_gpr[i]);
    tcg_gen_ld_tl(cpu_regs[i], gpr_sv, 0);
    tcg_temp_free_ptr(gpr_sv);

  }

  tcg_temp_free_ptr(first_pass_ptr);
  tcg_temp_free(first_pass);
  tcg_temp_free(one);

}

static void restore_state_for_persistent(TCGv *cpu_regs, int regs_num, int sp) {

  if (persistent_save_gpr) {

    gpr_saving(cpu_regs, regs_num);

  } else if (afl_persistent_ret_addr == 0) {

    TCGv_ptr stack_off_ptr = tcg_const_ptr(&persistent_stack_offset);
    TCGv     stack_off = tcg_temp_new();
    tcg_gen_ld_tl(stack_off, stack_off_ptr, 0);
    tcg_gen_sub_tl(cpu_regs[sp], cpu_regs[sp], stack_off);
    tcg_temp_free(stack_off);

  }

}

#define AFL_QEMU_TARGET_I386_SNIPPET                                          \
  if (is_persistent) {                                                        \
                                                                              \
    if (s->pc == afl_persistent_addr) {                                       \
                                                                              \
      restore_state_for_persistent(cpu_regs, AFL_REGS_NUM, R_ESP);            \
      /*afl_gen_tcg_plain_call(log_x86_saved_gpr);                            \
      afl_gen_tcg_plain_call(log_x86_sp_content);*/                           \
                                                                              \
      if (afl_persistent_ret_addr == 0) {                                     \
                                                                              \
        TCGv paddr = tcg_const_tl(afl_persistent_addr);                       \
        tcg_gen_qemu_st_tl(paddr, cpu_regs[R_ESP], persisent_retaddr_offset,  \
                           _DEFAULT_MO);                                      \
        tcg_temp_free(paddr);                                                 \
                                                                              \
      }                                                                       \
                                                                              \
      if (!persistent_save_gpr) afl_gen_tcg_plain_call(&afl_persistent_loop); \
      /*afl_gen_tcg_plain_call(log_x86_sp_content);*/                         \
                                                                              \
    } else if (afl_persistent_ret_addr && s->pc == afl_persistent_ret_addr) { \
                                                                              \
      gen_jmp_im(s, afl_persistent_addr);                                     \
      gen_eob(s);                                                             \
                                                                              \
    }                                                                         \
                                                                              \
  }

// SP = 13, LINK = 14

#define AFL_QEMU_TARGET_ARM_SNIPPET                                            \
  if (is_persistent) {                                                         \
                                                                               \
    if (dc->pc == afl_persistent_addr) {                                       \
                                                                               \
      if (persistent_save_gpr) gpr_saving(cpu_R, AFL_REGS_NUM);                \
                                                                               \
      if (afl_persistent_ret_addr == 0) {                                      \
                                                                               \
        tcg_gen_movi_tl(cpu_R[14], afl_persistent_addr);                       \
                                                                               \
      }                                                                        \
                                                                               \
      if (!persistent_save_gpr) afl_gen_tcg_plain_call(&afl_persistent_loop);  \
                                                                               \
    } else if (afl_persistent_ret_addr && dc->pc == afl_persistent_ret_addr) { \
                                                                               \
      gen_bx_im(dc, afl_persistent_addr);                                      \
                                                                               \
    }                                                                          \
                                                                               \
  }

// SP = 31, LINK = 30

#define AFL_QEMU_TARGET_ARM64_SNIPPET                                         \
  if (is_persistent) {                                                        \
                                                                              \
    if (s->pc == afl_persistent_addr) {                                       \
                                                                              \
      if (persistent_save_gpr) gpr_saving(cpu_X, AFL_REGS_NUM);               \
                                                                              \
      if (afl_persistent_ret_addr == 0) {                                     \
                                                                              \
        tcg_gen_movi_tl(cpu_X[30], afl_persistent_addr);                      \
                                                                              \
      }                                                                       \
                                                                              \
      if (!persistent_save_gpr) afl_gen_tcg_plain_call(&afl_persistent_loop); \
                                                                              \
    } else if (afl_persistent_ret_addr && s->pc == afl_persistent_ret_addr) { \
                                                                              \
      gen_goto_tb(s, 0, afl_persistent_addr);                                 \
                                                                              \
    }                                                                         \
                                                                              \
  }

