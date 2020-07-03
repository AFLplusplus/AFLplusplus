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
#include "tcg-op.h"

void HELPER(afl_maybe_log)(target_ulong afl_idx) {

  INC_AFL_AREA(afl_idx);

}

/* Called with mmap_lock held for user mode emulation.  */
TranslationBlock *afl_gen_edge(CPUState *cpu, unsigned long edge_id)
{
    CPUArchState *env = cpu->env_ptr;
    TranslationBlock *tb;
    tcg_insn_unit *gen_code_buf;
    int gen_code_size, search_size;

    assert_memory_lock();

 buffer_overflow:
    tb = tb_alloc(0);
    if (unlikely(!tb)) {
        /* flush must be done */
        tb_flush(cpu);
        mmap_unlock();
        /* Make the execution loop process the flush as soon as possible.  */
        cpu->exception_index = EXCP_INTERRUPT;
        cpu_loop_exit(cpu);
    }

    gen_code_buf = tcg_ctx->code_gen_ptr;
    tb->tc.ptr = gen_code_buf;
    tb->pc = 0;
    tb->cs_base = 0;
    tb->flags = 0;
    tb->cflags = 0;
    tb->trace_vcpu_dstate = *cpu->trace_dstate;
    tcg_ctx->tb_cflags = 0;

    tcg_func_start(tcg_ctx);

    tcg_ctx->cpu = ENV_GET_CPU(env);
    
    target_ulong afl_idx = edge_id & (MAP_SIZE -1);
    TCGv tmp0 = tcg_const_tl(afl_idx);
    gen_helper_afl_maybe_log(tmp0);
    tcg_temp_free(tmp0);
    tcg_gen_goto_tb(0);
    tcg_gen_exit_tb(tb, 0);

    tcg_ctx->cpu = NULL;

    trace_translate_block(tb, tb->pc, tb->tc.ptr);

    /* generate machine code */
    tb->jmp_reset_offset[0] = TB_JMP_RESET_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_RESET_OFFSET_INVALID;
    tcg_ctx->tb_jmp_reset_offset = tb->jmp_reset_offset;
    if (TCG_TARGET_HAS_direct_jump) {
        tcg_ctx->tb_jmp_insn_offset = tb->jmp_target_arg;
        tcg_ctx->tb_jmp_target_addr = NULL;
    } else {
        tcg_ctx->tb_jmp_insn_offset = NULL;
        tcg_ctx->tb_jmp_target_addr = tb->jmp_target_arg;
    }

    /* ??? Overflow could be handled better here.  In particular, we
       don't need to re-do gen_intermediate_code, nor should we re-do
       the tcg optimization currently hidden inside tcg_gen_code.  All
       that should be required is to flush the TBs, allocate a new TB,
       re-initialize it per above, and re-do the actual code generation.  */
    gen_code_size = tcg_gen_code(tcg_ctx, tb);
    if (unlikely(gen_code_size < 0)) {
        goto buffer_overflow;
    }
    search_size = encode_search(tb, (void *)gen_code_buf + gen_code_size);
    if (unlikely(search_size < 0)) {
        goto buffer_overflow;
    }
    tb->tc.size = gen_code_size;

    atomic_set(&tcg_ctx->code_gen_ptr, (void *)
        ROUND_UP((uintptr_t)gen_code_buf + gen_code_size + search_size,
                 CODE_GEN_ALIGN));

    /* init jump list */
    qemu_spin_init(&tb->jmp_lock);
    tb->jmp_list_head = (uintptr_t)NULL;
    tb->jmp_list_next[0] = (uintptr_t)NULL;
    tb->jmp_list_next[1] = (uintptr_t)NULL;
    tb->jmp_dest[0] = (uintptr_t)NULL;
    tb->jmp_dest[1] = (uintptr_t)NULL;

    /* init original jump addresses which have been set during tcg_gen_code() */
    if (tb->jmp_reset_offset[0] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }

    return tb;
}

