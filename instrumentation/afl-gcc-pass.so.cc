/* GCC plugin for instrumentation of code for american fuzzy lop.

   Copyright 2014-2019 Free Software Foundation, Inc
   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2024 AdaCore

   Written by Alexandre Oliva <oliva@adacore.com>, based on the AFL
   LLVM pass by Laszlo Szekeres <lszekeres@google.com> and Michal
   Zalewski <lcamtuf@google.com>, and copying a little boilerplate
   from GCC's libcc1 plugin and GCC proper.  Aside from the
   boilerplate, namely includes and the pass data structure, and pass
   initialization code and output messages borrowed and adapted from
   the LLVM pass into plugin_init and plugin_finalize, the
   implementation of the GCC pass proper is written from scratch,
   aiming at similar behavior and performance to that of the LLVM
   pass, and also at compatibility with the out-of-line
   instrumentation and run times of AFL++, as well as of an earlier
   GCC plugin implementation by Austin Seipp <aseipp@pobox.com>.  The
   implementation of Allow/Deny Lists is adapted from that in the LLVM
   plugin.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.

 */

/* This file implements a GCC plugin that introduces an
   instrumentation pass for AFL.  What follows is the specification
   used to rewrite it, extracted from the functional llvm_mode pass
   and from an implementation of the gcc_plugin started by Austin
   Seipp <aseipp@pobox.com>.

   Declare itself as GPL-compatible.

   Define a 'plugin_init' function.

   Check version against the global gcc_version.

   Register a PLUGIN_INFO object with .version and .help.

   Initialize the random number generator seed with GCC's
   random seed.

   Set quiet mode depending on whether stderr is a terminal and
   AFL_QUIET is set.

   Output some identification message if not in quiet mode.

   Parse AFL_INST_RATIO, if set, as a number between 0 and 100.  Error
   out if it's not in range; set up an instrumentation ratio global
   otherwise.

   Introduce a single instrumentation pass after SSA.

   The new pass is to be a GIMPLE_PASS.  Given the sort of
   instrumentation it's supposed to do, its todo_flags_finish will
   certainly need TODO_update_ssa, and TODO_cleanup_cfg.
   TODO_verify_il is probably desirable, at least during debugging.
   TODO_rebuild_cgraph_edges is required only in the out-of-line
   instrumentation mode.

   The instrumentation pass amounts to iterating over all basic blocks
   and optionally inserting one of the instrumentation sequences below
   after its labels, to indicate execution entered the block.

   A block should be skipped if R(100) (from ../types.h) is >= the
   global instrumentation ratio.

   A block may be skipped for other reasons, such as if all of its
   predecessors have a single successor.

   For an instrumented block, a R(MAP_SIZE) say <N> should be
   generated to be used as its location number.  Let <C> be a compiler
   constant built out of it.

   Count instrumented blocks and print a message at the end of the
   compilation, if not in quiet mode.

   Instrumentation in "dumb" or "out-of-line" mode requires calling a
   function, passing it the location number.  The function to be
   called is __afl_trace, implemented in afl-gcc-rt.o.c.  Its
   declaration <T> needs only be created once.

   Build the call statement <T> (<C>), then add it to the seq to be
   inserted.

   Instrumentation in "fast" or "inline" mode performs the computation
   of __afl_trace as part of the function.

   It needs to read and write __afl_prev_loc, a TLS u32 variable.  Its
   declaration <P> needs only be created once.

   It needs to read and dereference __afl_area_ptr, a pointer to (an
   array of) char.  Its declaration <M> needs only be created once.

   The instrumentation sequence should then be filled with the
   following statements:

   Load from <P> to a temporary (<TP>) of the same type.

   Compute <TP> ^ <C> in sizetype, converting types as needed.

   Pointer-add <B> (to be introduced at a later point) and <I> into
   another temporary <A>.

   Increment the <*A> MEM_REF.

   Store <C> >> 1 in <P>.

   Temporaries used above need only be created once per function.

   If any block was instrumented in a function, an initializer for <B>
   needs to be introduced, loading it from <M> and inserting it in the
   entry edge for the entry block.
*/

#include "afl-gcc-common.h"
#if (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__) >= \
    60200                                               /* >= version 6.2.0 */
  #include "memmodel.h"
#endif

/* This plugin, being under the same license as GCC, satisfies the
   "GPL-compatible Software" definition in the GCC RUNTIME LIBRARY
   EXCEPTION, so it can be part of an "Eligible" "Compilation
   Process".  */
int plugin_is_GPL_compatible = 1;

namespace {

static constexpr struct pass_data afl_pass_data = {

    .type = GIMPLE_PASS,
    .name = "afl",
    .optinfo_flags = OPTGROUP_NONE,
    .tv_id = TV_NONE,
    .properties_required = 0,
    .properties_provided = 0,
    .properties_destroyed = 0,
    .todo_flags_start = 0,
    .todo_flags_finish = (TODO_update_ssa | TODO_cleanup_cfg | TODO_verify_il),

};

struct afl_pass : afl_base_pass {

  afl_pass(bool quiet, unsigned int ratio)
      : afl_base_pass(quiet, !!getenv("AFL_DEBUG"), afl_pass_data),
        inst_ratio(ratio),
#ifdef AFL_GCC_OUT_OF_LINE
        out_of_line(!!(AFL_GCC_OUT_OF_LINE)),
#else
        out_of_line(getenv("AFL_GCC_OUT_OF_LINE")),
#endif
        neverZero(!getenv("AFL_GCC_SKIP_NEVERZERO")),
        inst_blocks(0) {

    initInstrumentList();

  }

  /* How likely (%) is a block to be instrumented?  */
  const unsigned int inst_ratio;

  /* Should we use slow, out-of-line call-based instrumentation?  */
  const bool out_of_line;

  /* Should we make sure the map edge-crossing counters never wrap
     around to zero?  */
  const bool neverZero;

  /* Count instrumented blocks. */
  unsigned int inst_blocks;

  virtual unsigned int execute(function *fn) {

    if (!isInInstrumentList(fn)) return 0;

    int blocks = 0;

    /* These are temporaries used by inline instrumentation only, that
       are live throughout the function.  */
    tree ploc = NULL, indx = NULL, map = NULL, map_ptr = NULL, ntry = NULL,
         cntr = NULL, xaddc = NULL, xincr = NULL;

    basic_block bb;
    FOR_EACH_BB_FN(bb, fn) {

      if (!instrument_block_p(bb)) continue;

      /* Generate the block identifier.  */
      unsigned bid = R(MAP_SIZE);
      tree     bidt = build_int_cst(sizetype, bid);

      gimple_seq seq = NULL;

      if (out_of_line) {

        static tree afl_trace = get_afl_trace_decl();

        /* Call __afl_trace with bid, the new location;  */
        gcall *call = gimple_build_call(afl_trace, 1, bidt);
        gimple_seq_add_stmt(&seq, call);

      } else {

        static tree afl_prev_loc = get_afl_prev_loc_decl();
        static tree afl_area_ptr = get_afl_area_ptr_decl();

        /* Load __afl_prev_loc to a temporary ploc.  */
        if (blocks == 0)
          ploc = create_tmp_var(TREE_TYPE(afl_prev_loc), ".afl_prev_loc");
        auto load_loc = gimple_build_assign(ploc, afl_prev_loc);
        gimple_seq_add_stmt(&seq, load_loc);

        /* Compute the index into the map referenced by area_ptr
           that we're to update: indx = (sizetype) ploc ^ bid.  */
        if (blocks == 0) indx = create_tmp_var(TREE_TYPE(bidt), ".afl_index");
        auto conv_ploc =
            gimple_build_assign(indx, fold_convert(TREE_TYPE(indx), ploc));
        gimple_seq_add_stmt(&seq, conv_ploc);
        auto xor_loc = gimple_build_assign(indx, BIT_XOR_EXPR, indx, bidt);
        gimple_seq_add_stmt(&seq, xor_loc);

        /* Compute the address of that map element.  */
        if (blocks == 0) {

          map = afl_area_ptr;
          map_ptr = create_tmp_var(TREE_TYPE(afl_area_ptr), ".afl_map_ptr");
          ntry = create_tmp_var(TREE_TYPE(afl_area_ptr), ".afl_map_entry");

        }

        /* .map_ptr is initialized at the function entry point, if we
           instrument any blocks, see below.  */

        /* .entry = &map_ptr[.index]; */
        auto idx_map =
            gimple_build_assign(ntry, POINTER_PLUS_EXPR, map_ptr, indx);
        gimple_seq_add_stmt(&seq, idx_map);

        /* Prepare to add constant 1 to it.  */
        tree incrv = build_one_cst(TREE_TYPE(TREE_TYPE(ntry)));

        if (neverZero) {

          /* Increment the counter in idx_map.  */
          tree memref = build2(MEM_REF, TREE_TYPE(TREE_TYPE(ntry)), ntry,
                               build_zero_cst(TREE_TYPE(ntry)));

          if (blocks == 0)
            cntr = create_tmp_var(TREE_TYPE(memref), ".afl_edge_count");

          /* Load the count from the entry.  */
          auto load_cntr = gimple_build_assign(cntr, memref);
          gimple_seq_add_stmt(&seq, load_cntr);

          /* NeverZero: if count wrapped around to zero, advance to
             one.  */
          if (blocks == 0) {

            xaddc = create_tmp_var(build_complex_type(TREE_TYPE(memref)),
                                   ".afl_edge_xaddc");
            xincr = create_tmp_var(TREE_TYPE(memref), ".afl_edge_xincr");

          }

          /* Call the ADD_OVERFLOW builtin, to add 1 (in incrv) to
             count.  The builtin yields a complex pair: the result of
             the add in the real part, and the overflow flag in the
             imaginary part, */
          auto_vec<tree> vargs(2);
          vargs.quick_push(cntr);
          vargs.quick_push(incrv);
          gcall *add1_cntr =
              gimple_build_call_internal_vec(IFN_ADD_OVERFLOW, vargs);
          gimple_call_set_lhs(add1_cntr, xaddc);
          gimple_seq_add_stmt(&seq, add1_cntr);

          /* Extract the real part into count.  */
          tree cntrb = build1(REALPART_EXPR, TREE_TYPE(cntr), xaddc);
          auto xtrct_cntr = gimple_build_assign(cntr, cntrb);
          gimple_seq_add_stmt(&seq, xtrct_cntr);

          /* Extract the imaginary part into xincr.  */
          tree incrb = build1(IMAGPART_EXPR, TREE_TYPE(xincr), xaddc);
          auto xtrct_xincr = gimple_build_assign(xincr, incrb);
          gimple_seq_add_stmt(&seq, xtrct_xincr);

          /* Arrange for the add below to use the overflow flag stored
             in xincr.  */
          incrv = xincr;

          /* Add the increment (1 or the overflow bit) to count.  */
          auto incr_cntr = gimple_build_assign(cntr, PLUS_EXPR, cntr, incrv);
          gimple_seq_add_stmt(&seq, incr_cntr);

          /* Store count in the map entry.  */
          auto store_cntr = gimple_build_assign(unshare_expr(memref), cntr);
          gimple_seq_add_stmt(&seq, store_cntr);

        } else {

          /* Use a serialized memory model.  */
          tree memmod = build_int_cst(integer_type_node, MEMMODEL_SEQ_CST);

          tree fadd = builtin_decl_explicit(BUILT_IN_ATOMIC_FETCH_ADD_1);
          auto incr_cntr = gimple_build_call(fadd, 3, ntry, incrv, memmod);
          gimple_seq_add_stmt(&seq, incr_cntr);

        }

        /* Store bid >> 1 in __afl_prev_loc.  */
        auto shift_loc =
            gimple_build_assign(ploc, build_int_cst(TREE_TYPE(ploc), bid >> 1));
        gimple_seq_add_stmt(&seq, shift_loc);
        auto store_loc = gimple_build_assign(afl_prev_loc, ploc);
        gimple_seq_add_stmt(&seq, store_loc);

      }

      /* Insert the generated sequence.  */
      gimple_stmt_iterator insp = gsi_after_labels(bb);
      gsi_insert_seq_before(&insp, seq, GSI_SAME_STMT);

      /* Bump this function's instrumented block counter.  */
      blocks++;

    }

    /* Aggregate the instrumented block count.  */
    inst_blocks += blocks;

    if (blocks) {

      if (out_of_line) return TODO_rebuild_cgraph_edges;

      gimple_seq seq = NULL;

      /* Load afl_area_ptr into map_ptr.  We want to do this only
         once per function.  */
      auto load_ptr = gimple_build_assign(map_ptr, map);
      gimple_seq_add_stmt(&seq, load_ptr);

      /* Insert it in the edge to the entry block.  We don't want to
         insert it in the first block, since there might be a loop
         or a goto back to it.  Insert in the edge, which may create
         another block.  */
      edge e = single_succ_edge(ENTRY_BLOCK_PTR_FOR_FN(fn));
      gsi_insert_seq_on_edge_immediate(e, seq);

    }

    return 0;

  }

  /* Decide whether to instrument block BB.  Skip it due to the random
     distribution, or if it's the single successor of all its
     predecessors.  */
  inline bool instrument_block_p(basic_block bb) {

    if (R(100) >= (long int)inst_ratio) return false;

    edge          e;
    edge_iterator ei;
    FOR_EACH_EDGE(e, ei, bb->preds)
    if (!single_succ_p(e->src)) return true;

    return false;

  }

  /* Create and return a declaration for the __afl_trace rt function.  */
  static inline tree get_afl_trace_decl() {

    tree type =
        build_function_type_list(void_type_node, uint16_type_node, NULL_TREE);
    tree decl = build_fn_decl("__afl_trace", type);

    TREE_PUBLIC(decl) = 1;
    DECL_EXTERNAL(decl) = 1;
    DECL_ARTIFICIAL(decl) = 1;

    return decl;

  }

  /* Create and return a declaration for the __afl_prev_loc
     thread-local variable.  */
  static inline tree get_afl_prev_loc_decl() {

    tree decl = build_decl(BUILTINS_LOCATION, VAR_DECL,
                           get_identifier("__afl_prev_loc"), uint32_type_node);
    TREE_PUBLIC(decl) = 1;
    DECL_EXTERNAL(decl) = 1;
    DECL_ARTIFICIAL(decl) = 1;
    TREE_STATIC(decl) = 1;
#if !defined(__ANDROID__) && !defined(__HAIKU__)
    set_decl_tls_model(
        decl, (flag_pic ? TLS_MODEL_INITIAL_EXEC : TLS_MODEL_LOCAL_EXEC));
#endif
    return decl;

  }

  /* Create and return a declaration for the __afl_prev_loc
     thread-local variable.  */
  static inline tree get_afl_area_ptr_decl() {

    /* If type changes, the size N in FETCH_ADD_<N> must be adjusted
       in builtin calls above.  */
    tree type = build_pointer_type(unsigned_char_type_node);
    tree decl = build_decl(BUILTINS_LOCATION, VAR_DECL,
                           get_identifier("__afl_area_ptr"), type);
    TREE_PUBLIC(decl) = 1;
    DECL_EXTERNAL(decl) = 1;
    DECL_ARTIFICIAL(decl) = 1;
    TREE_STATIC(decl) = 1;

    return decl;

  }

  /* This is registered as a plugin finalize callback, to print an
     instrumentation summary unless in quiet mode.  */
  static void plugin_finalize(void *, void *p) {

    opt_pass *op = (opt_pass *)p;
    afl_pass &self = (afl_pass &)*op;

    if (!self.be_quiet) {

      if (!self.inst_blocks)
        WARNF("No instrumentation targets found.");
      else
        OKF("Instrumented %u locations (%s mode, %s, ratio %u%%).",
            self.inst_blocks,
            getenv("AFL_HARDEN") ? G_("hardened") : G_("non-hardened"),
            self.out_of_line ? G_("out of line") : G_("inline"),
            self.inst_ratio);

    }

  }

};

static struct plugin_info afl_plugin = {

    .version = "20220420",
    .help = G_("AFL gcc plugin\n\
\n\
Set AFL_QUIET in the environment to silence it.\n\
\n\
Set AFL_INST_RATIO in the environment to a number from 0 to 100\n\
to control how likely a block will be chosen for instrumentation.\n\
\n\
Specify -frandom-seed for reproducible instrumentation.\n\
"),

};

}  // namespace

/* This is the function GCC calls when loading a plugin.  Initialize
   and register further callbacks.  */
int plugin_init(struct plugin_name_args   *info,
                struct plugin_gcc_version *version) {

  if (!plugin_default_version_check(version, &gcc_version) &&
      !getenv("AFL_GCC_DISABLE_VERSION_CHECK"))
    FATAL(G_("GCC and plugin have incompatible versions, expected GCC %s, "
             "is %s"),
          gcc_version.basever, version->basever);

  /* Show a banner.  */
  bool quiet = false;
  if (isatty(2) && !getenv("AFL_QUIET"))
    SAYF(cCYA "afl-gcc-pass " cBRI VERSION cRST " by <oliva@adacore.com>\n");
  else
    quiet = true;

  /* Decide instrumentation ratio.  */
  unsigned int inst_ratio = 100U;
  if (char *inst_ratio_str = getenv("AFL_INST_RATIO"))
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL(G_("Bad value of AFL_INST_RATIO (must be between 1 and 100)"));

  /* Initialize the random number generator with GCC's random seed, in
     case it was specified in the command line's -frandom-seed for
     reproducible instrumentation.  */
  srandom(get_random_seed(false));

  const char *name = info->base_name;
  register_callback(name, PLUGIN_INFO, NULL, &afl_plugin);

  afl_pass                 *aflp = new afl_pass(quiet, inst_ratio);
  struct register_pass_info pass_info = {

      .pass = aflp,
      .reference_pass_name = "ssa",
      .ref_pass_instance_number = 1,
      .pos_op = PASS_POS_INSERT_AFTER,

  };

  register_callback(name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);
  register_callback(name, PLUGIN_FINISH, afl_pass::plugin_finalize,
                    pass_info.pass);

  if (!quiet)
    ACTF(G_("%s instrumentation at ratio of %u%% in %s mode."),
         aflp->out_of_line ? G_("Call-based") : G_("Inline"), inst_ratio,
         getenv("AFL_HARDEN") ? G_("hardened") : G_("non-hardened"));

  return 0;

}

