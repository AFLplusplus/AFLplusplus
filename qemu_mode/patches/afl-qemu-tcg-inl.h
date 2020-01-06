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

void afl_maybe_log(void *cur_loc);

/* Note: we convert the 64 bit args to 32 bit and do some alignment
   and endian swap. Maybe it would be better to do the alignment
   and endian swap in tcg_reg_alloc_call(). */
void tcg_gen_afl_maybe_log_call(target_ulong cur_loc) {

  int      real_args, pi;
  unsigned sizemask, flags;
  TCGOp *  op;

#if TARGET_LONG_BITS == 64
  TCGTemp *arg = tcgv_i64_temp(tcg_const_tl(cur_loc));
  sizemask = dh_sizemask(void, 0) | dh_sizemask(i64, 1);
#else
  TCGTemp *arg = tcgv_i32_temp(tcg_const_tl(cur_loc));
  sizemask = dh_sizemask(void, 0) | dh_sizemask(i32, 1);
#endif

  flags = 0;

#if defined(__sparc__) && !defined(__arch64__) && \
    !defined(CONFIG_TCG_INTERPRETER)
  /* We have 64-bit values in one register, but need to pass as two
     separate parameters.  Split them.  */
  int      orig_sizemask = sizemask;
  TCGv_i64 retl, reth;
  TCGTemp *split_args[MAX_OPC_PARAM];

  retl = NULL;
  reth = NULL;
  if (sizemask != 0) {

    real_args = 0;
    int is_64bit = sizemask & (1 << 2);
    if (is_64bit) {

      TCGv_i64 orig = temp_tcgv_i64(arg);
      TCGv_i32 h = tcg_temp_new_i32();
      TCGv_i32 l = tcg_temp_new_i32();
      tcg_gen_extr_i64_i32(l, h, orig);
      split_args[real_args++] = tcgv_i32_temp(h);
      split_args[real_args++] = tcgv_i32_temp(l);

    } else {

      split_args[real_args++] = arg;

    }

    nargs = real_args;
    args = split_args;
    sizemask = 0;

  }

#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
  int is_64bit = sizemask & (1 << 2);
  int is_signed = sizemask & (2 << 2);
  if (!is_64bit) {

    TCGv_i64 temp = tcg_temp_new_i64();
    TCGv_i64 orig = temp_tcgv_i64(arg);
    if (is_signed) {

      tcg_gen_ext32s_i64(temp, orig);

    } else {

      tcg_gen_ext32u_i64(temp, orig);

    }

    arg = tcgv_i64_temp(temp);

  }

#endif                                            /* TCG_TARGET_EXTEND_ARGS */

  op = tcg_emit_op(INDEX_op_call);

  pi = 0;

  TCGOP_CALLO(op) = 0;

  real_args = 0;
  int is_64bit = sizemask & (1 << 2);
  if (TCG_TARGET_REG_BITS < 64 && is_64bit) {

#ifdef TCG_TARGET_CALL_ALIGN_ARGS
    /* some targets want aligned 64 bit args */
    if (real_args & 1) {

      op->args[pi++] = TCG_CALL_DUMMY_ARG;
      real_args++;

    }

#endif
    /* If stack grows up, then we will be placing successive
       arguments at lower addresses, which means we need to
       reverse the order compared to how we would normally
       treat either big or little-endian.  For those arguments
       that will wind up in registers, this still works for
       HPPA (the only current STACK_GROWSUP target) since the
       argument registers are *also* allocated in decreasing
       order.  If another such target is added, this logic may
       have to get more complicated to differentiate between
       stack arguments and register arguments.  */
#if defined(HOST_WORDS_BIGENDIAN) != defined(TCG_TARGET_STACK_GROWSUP)
    op->args[pi++] = temp_arg(arg + 1);
    op->args[pi++] = temp_arg(arg);
#else
    op->args[pi++] = temp_arg(arg);
    op->args[pi++] = temp_arg(arg + 1);
#endif
    real_args += 2;

  }

  op->args[pi++] = temp_arg(arg);
  real_args++;

  op->args[pi++] = (uintptr_t)&afl_maybe_log;
  op->args[pi++] = flags;
  TCGOP_CALLI(op) = real_args;

  /* Make sure the fields didn't overflow.  */
  tcg_debug_assert(TCGOP_CALLI(op) == real_args);
  tcg_debug_assert(pi <= ARRAY_SIZE(op->args));

#if defined(__sparc__) && !defined(__arch64__) && \
    !defined(CONFIG_TCG_INTERPRETER)
  /* Free all of the parts we allocated above.  */
  real_args = 0;
  int is_64bit = orig_sizemask & (1 << 2);
  if (is_64bit) {

    tcg_temp_free_internal(args[real_args++]);
    tcg_temp_free_internal(args[real_args++]);

  } else {

    real_args++;

  }

  if (orig_sizemask & 1) {

    /* The 32-bit ABI returned two 32-bit pieces.  Re-assemble them.
       Note that describing these as TCGv_i64 eliminates an unnecessary
       zero-extension that tcg_gen_concat_i32_i64 would create.  */
    tcg_gen_concat32_i64(temp_tcgv_i64(NULL), retl, reth);
    tcg_temp_free_i64(retl);
    tcg_temp_free_i64(reth);

  }

#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
  int is_64bit = sizemask & (1 << 2);
  if (!is_64bit) { tcg_temp_free_internal(arg); }
#endif                                            /* TCG_TARGET_EXTEND_ARGS */

}

/* Note: we convert the 64 bit args to 32 bit and do some alignment
   and endian swap. Maybe it would be better to do the alignment
   and endian swap in tcg_reg_alloc_call(). */
void tcg_gen_afl_call0(void *func) {

  int      i, real_args, nb_rets, pi;
  unsigned sizemask, flags;
  TCGOp *  op;

  const int nargs = 0;
  TCGTemp **args;

  flags = 0;
  sizemask = dh_sizemask(void, 0);

#if defined(__sparc__) && !defined(__arch64__) && \
    !defined(CONFIG_TCG_INTERPRETER)
  /* We have 64-bit values in one register, but need to pass as two
     separate parameters.  Split them.  */
  int      orig_sizemask = sizemask;
  int      orig_nargs = nargs;
  TCGv_i64 retl, reth;
  TCGTemp *split_args[MAX_OPC_PARAM];

  retl = NULL;
  reth = NULL;
  if (sizemask != 0) {

    for (i = real_args = 0; i < nargs; ++i) {

      int is_64bit = sizemask & (1 << (i + 1) * 2);
      if (is_64bit) {

        TCGv_i64 orig = temp_tcgv_i64(args[i]);
        TCGv_i32 h = tcg_temp_new_i32();
        TCGv_i32 l = tcg_temp_new_i32();
        tcg_gen_extr_i64_i32(l, h, orig);
        split_args[real_args++] = tcgv_i32_temp(h);
        split_args[real_args++] = tcgv_i32_temp(l);

      } else {

        split_args[real_args++] = args[i];

      }

    }

    nargs = real_args;
    args = split_args;
    sizemask = 0;

  }

#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
  for (i = 0; i < nargs; ++i) {

    int is_64bit = sizemask & (1 << (i + 1) * 2);
    int is_signed = sizemask & (2 << (i + 1) * 2);
    if (!is_64bit) {

      TCGv_i64 temp = tcg_temp_new_i64();
      TCGv_i64 orig = temp_tcgv_i64(args[i]);
      if (is_signed) {

        tcg_gen_ext32s_i64(temp, orig);

      } else {

        tcg_gen_ext32u_i64(temp, orig);

      }

      args[i] = tcgv_i64_temp(temp);

    }

  }

#endif                                            /* TCG_TARGET_EXTEND_ARGS */

  op = tcg_emit_op(INDEX_op_call);

  pi = 0;
  nb_rets = 0;
  TCGOP_CALLO(op) = nb_rets;

  real_args = 0;
  for (i = 0; i < nargs; i++) {

    int is_64bit = sizemask & (1 << (i + 1) * 2);
    if (TCG_TARGET_REG_BITS < 64 && is_64bit) {

#ifdef TCG_TARGET_CALL_ALIGN_ARGS
      /* some targets want aligned 64 bit args */
      if (real_args & 1) {

        op->args[pi++] = TCG_CALL_DUMMY_ARG;
        real_args++;

      }

#endif
      /* If stack grows up, then we will be placing successive
         arguments at lower addresses, which means we need to
         reverse the order compared to how we would normally
         treat either big or little-endian.  For those arguments
         that will wind up in registers, this still works for
         HPPA (the only current STACK_GROWSUP target) since the
         argument registers are *also* allocated in decreasing
         order.  If another such target is added, this logic may
         have to get more complicated to differentiate between
         stack arguments and register arguments.  */
#if defined(HOST_WORDS_BIGENDIAN) != defined(TCG_TARGET_STACK_GROWSUP)
      op->args[pi++] = temp_arg(args[i] + 1);
      op->args[pi++] = temp_arg(args[i]);
#else
      op->args[pi++] = temp_arg(args[i]);
      op->args[pi++] = temp_arg(args[i] + 1);
#endif
      real_args += 2;
      continue;

    }

    op->args[pi++] = temp_arg(args[i]);
    real_args++;

  }

  op->args[pi++] = (uintptr_t)func;
  op->args[pi++] = flags;
  TCGOP_CALLI(op) = real_args;

  /* Make sure the fields didn't overflow.  */
  tcg_debug_assert(TCGOP_CALLI(op) == real_args);
  tcg_debug_assert(pi <= ARRAY_SIZE(op->args));

#if defined(__sparc__) && !defined(__arch64__) && \
    !defined(CONFIG_TCG_INTERPRETER)
  /* Free all of the parts we allocated above.  */
  for (i = real_args = 0; i < orig_nargs; ++i) {

    int is_64bit = orig_sizemask & (1 << (i + 1) * 2);
    if (is_64bit) {

      tcg_temp_free_internal(args[real_args++]);
      tcg_temp_free_internal(args[real_args++]);

    } else {

      real_args++;

    }

  }

  if (orig_sizemask & 1) {

    /* The 32-bit ABI returned two 32-bit pieces.  Re-assemble them.
       Note that describing these as TCGv_i64 eliminates an unnecessary
       zero-extension that tcg_gen_concat_i32_i64 would create.  */
    tcg_gen_concat32_i64(temp_tcgv_i64(NULL), retl, reth);
    tcg_temp_free_i64(retl);
    tcg_temp_free_i64(reth);

  }

#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
  for (i = 0; i < nargs; ++i) {

    int is_64bit = sizemask & (1 << (i + 1) * 2);
    if (!is_64bit) { tcg_temp_free_internal(args[i]); }

  }

#endif                                            /* TCG_TARGET_EXTEND_ARGS */

}

void tcg_gen_afl_compcov_log_call(void *func, target_ulong cur_loc, TCGv arg1,
                                  TCGv arg2) {

  int      i, real_args, nb_rets, pi;
  unsigned sizemask, flags;
  TCGOp *  op;

  const int nargs = 3;
#if TARGET_LONG_BITS == 64
  TCGTemp *args[3] = {tcgv_i64_temp(tcg_const_tl(cur_loc)), tcgv_i64_temp(arg1),
                      tcgv_i64_temp(arg2)};
  sizemask = dh_sizemask(void, 0) | dh_sizemask(i64, 1) | dh_sizemask(i64, 2) |
             dh_sizemask(i64, 3);
#else
  TCGTemp *args[3] = {tcgv_i32_temp(tcg_const_tl(cur_loc)), tcgv_i32_temp(arg1),
                      tcgv_i32_temp(arg2)};
  sizemask = dh_sizemask(void, 0) | dh_sizemask(i32, 1) | dh_sizemask(i32, 2) |
             dh_sizemask(i32, 3);
#endif

  flags = 0;

#if defined(__sparc__) && !defined(__arch64__) && \
    !defined(CONFIG_TCG_INTERPRETER)
  /* We have 64-bit values in one register, but need to pass as two
     separate parameters.  Split them.  */
  int      orig_sizemask = sizemask;
  int      orig_nargs = nargs;
  TCGv_i64 retl, reth;
  TCGTemp *split_args[MAX_OPC_PARAM];

  retl = NULL;
  reth = NULL;
  if (sizemask != 0) {

    for (i = real_args = 0; i < nargs; ++i) {

      int is_64bit = sizemask & (1 << (i + 1) * 2);
      if (is_64bit) {

        TCGv_i64 orig = temp_tcgv_i64(args[i]);
        TCGv_i32 h = tcg_temp_new_i32();
        TCGv_i32 l = tcg_temp_new_i32();
        tcg_gen_extr_i64_i32(l, h, orig);
        split_args[real_args++] = tcgv_i32_temp(h);
        split_args[real_args++] = tcgv_i32_temp(l);

      } else {

        split_args[real_args++] = args[i];

      }

    }

    nargs = real_args;
    args = split_args;
    sizemask = 0;

  }

#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
  for (i = 0; i < nargs; ++i) {

    int is_64bit = sizemask & (1 << (i + 1) * 2);
    int is_signed = sizemask & (2 << (i + 1) * 2);
    if (!is_64bit) {

      TCGv_i64 temp = tcg_temp_new_i64();
      TCGv_i64 orig = temp_tcgv_i64(args[i]);
      if (is_signed) {

        tcg_gen_ext32s_i64(temp, orig);

      } else {

        tcg_gen_ext32u_i64(temp, orig);

      }

      args[i] = tcgv_i64_temp(temp);

    }

  }

#endif                                            /* TCG_TARGET_EXTEND_ARGS */

  op = tcg_emit_op(INDEX_op_call);

  pi = 0;
  nb_rets = 0;
  TCGOP_CALLO(op) = nb_rets;

  real_args = 0;
  for (i = 0; i < nargs; i++) {

    int is_64bit = sizemask & (1 << (i + 1) * 2);
    if (TCG_TARGET_REG_BITS < 64 && is_64bit) {

#ifdef TCG_TARGET_CALL_ALIGN_ARGS
      /* some targets want aligned 64 bit args */
      if (real_args & 1) {

        op->args[pi++] = TCG_CALL_DUMMY_ARG;
        real_args++;

      }

#endif
      /* If stack grows up, then we will be placing successive
         arguments at lower addresses, which means we need to
         reverse the order compared to how we would normally
         treat either big or little-endian.  For those arguments
         that will wind up in registers, this still works for
         HPPA (the only current STACK_GROWSUP target) since the
         argument registers are *also* allocated in decreasing
         order.  If another such target is added, this logic may
         have to get more complicated to differentiate between
         stack arguments and register arguments.  */
#if defined(HOST_WORDS_BIGENDIAN) != defined(TCG_TARGET_STACK_GROWSUP)
      op->args[pi++] = temp_arg(args[i] + 1);
      op->args[pi++] = temp_arg(args[i]);
#else
      op->args[pi++] = temp_arg(args[i]);
      op->args[pi++] = temp_arg(args[i] + 1);
#endif
      real_args += 2;
      continue;

    }

    op->args[pi++] = temp_arg(args[i]);
    real_args++;

  }

  op->args[pi++] = (uintptr_t)func;
  op->args[pi++] = flags;
  TCGOP_CALLI(op) = real_args;

  /* Make sure the fields didn't overflow.  */
  tcg_debug_assert(TCGOP_CALLI(op) == real_args);
  tcg_debug_assert(pi <= ARRAY_SIZE(op->args));

#if defined(__sparc__) && !defined(__arch64__) && \
    !defined(CONFIG_TCG_INTERPRETER)
  /* Free all of the parts we allocated above.  */
  for (i = real_args = 0; i < orig_nargs; ++i) {

    int is_64bit = orig_sizemask & (1 << (i + 1) * 2);
    if (is_64bit) {

      tcg_temp_free_internal(args[real_args++]);
      tcg_temp_free_internal(args[real_args++]);

    } else {

      real_args++;

    }

  }

  if (orig_sizemask & 1) {

    /* The 32-bit ABI returned two 32-bit pieces.  Re-assemble them.
       Note that describing these as TCGv_i64 eliminates an unnecessary
       zero-extension that tcg_gen_concat_i32_i64 would create.  */
    tcg_gen_concat32_i64(temp_tcgv_i64(NULL), retl, reth);
    tcg_temp_free_i64(retl);
    tcg_temp_free_i64(reth);

  }

#elif defined(TCG_TARGET_EXTEND_ARGS) && TCG_TARGET_REG_BITS == 64
  for (i = 0; i < nargs; ++i) {

    int is_64bit = sizemask & (1 << (i + 1) * 2);
    if (!is_64bit) { tcg_temp_free_internal(args[i]); }

  }

#endif                                            /* TCG_TARGET_EXTEND_ARGS */

}

