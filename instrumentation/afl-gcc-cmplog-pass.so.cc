/* GCC plugin for cmplog instrumentation of code for AFL++.

   Copyright 2014-2019 Free Software Foundation, Inc
   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Copyright 2019-2022 AdaCore

   Written by Alexandre Oliva <oliva@adacore.com>, based on the AFL++
   LLVM CmpLog pass by Andrea Fioraldi <andreafioraldi@gmail.com>, and
   on the AFL GCC pass.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

 */

#include "afl-gcc-common.h"

/* This plugin, being under the same license as GCC, satisfies the
   "GPL-compatible Software" definition in the GCC RUNTIME LIBRARY
   EXCEPTION, so it can be part of an "Eligible" "Compilation
   Process".  */
int plugin_is_GPL_compatible = 1;

namespace {

static const struct pass_data afl_cmplog_pass_data = {

    .type = GIMPLE_PASS,
    .name = "aflcmplog",
    .optinfo_flags = OPTGROUP_NONE,
    .tv_id = TV_NONE,
    .properties_required = 0,
    .properties_provided = 0,
    .properties_destroyed = 0,
    .todo_flags_start = 0,
    .todo_flags_finish = (TODO_update_ssa | TODO_cleanup_cfg | TODO_verify_il |
                          TODO_rebuild_cgraph_edges),

};

struct afl_cmplog_pass : afl_base_pass {

  afl_cmplog_pass(bool quiet)
      : afl_base_pass(quiet, /*debug=*/false, afl_cmplog_pass_data),
        t8u(),
        cmplog_hooks() {

  }

  /* An unsigned 8-bit integral type.  */
  tree t8u;

  /* Declarations for the various cmplog hook functions, allocated on demand..
     [0] is for __cmplog_ins_hookN, that accepts non-power-of-2 sizes.
     [n in 1..5] are for unsigned ints of 2^{n-1} bytes.  */
  tree cmplog_hooks[6];

  tree cmplog_hook(unsigned i) {

    tree t, fnt;

    if (!t8u) {

      if (BITS_PER_UNIT == 8)
        t8u = unsigned_char_type_node;
      else
        t8u = build_nonstandard_integer_type(8, 1);

    }

    if (i <= ARRAY_SIZE(cmplog_hooks) && cmplog_hooks[i])
      return cmplog_hooks[i];

    switch (i) {

      case 0:
#ifdef uint128_type_node
        t = uint128_type_node;
#else
        t = build_nonstandard_integer_type(128, 1);
#endif
        fnt =
            build_function_type_list(void_type_node, t, t, t8u, t8u, NULL_TREE);
        t = cmplog_hooks[0] = build_fn_decl("__cmplog_ins_hookN", fnt);
        break;

      case 1:
        t = t8u;
        fnt = build_function_type_list(void_type_node, t, t, t8u, NULL_TREE);
        t = cmplog_hooks[1] = build_fn_decl("__cmplog_ins_hook1", fnt);
        break;

      case 2:
        t = uint16_type_node;
        fnt = build_function_type_list(void_type_node, t, t, t8u, NULL_TREE);
        t = cmplog_hooks[2] = build_fn_decl("__cmplog_ins_hook2", fnt);
        break;

      case 3:
        t = uint32_type_node;
        fnt = build_function_type_list(void_type_node, t, t, t8u, NULL_TREE);
        t = cmplog_hooks[3] = build_fn_decl("__cmplog_ins_hook4", fnt);
        break;

      case 4:
        t = uint64_type_node;
        fnt = build_function_type_list(void_type_node, t, t, t8u, NULL_TREE);
        t = cmplog_hooks[4] = build_fn_decl("__cmplog_ins_hook8", fnt);
        break;

      case 5:
#ifdef uint128_type_node
        t = uint128_type_node;
#else
        t = build_nonstandard_integer_type(128, 1);
#endif
        fnt = build_function_type_list(void_type_node, t, t, t8u, NULL_TREE);
        t = cmplog_hooks[5] = build_fn_decl("__cmplog_ins_hook16", fnt);
        break;

      default:
        gcc_unreachable();

    }

    /* Mark the newly-created decl as non-throwing, so that we can
       insert call within basic blocks.  */
    TREE_NOTHROW(t) = 1;

    return t;

  }

  /* Insert a cmplog hook call before GSI for a CODE compare between
     LHS and RHS.  */
  void insert_cmplog_call(gimple_stmt_iterator gsi, tree_code code, tree lhs,
                          tree rhs) {

    gcc_checking_assert(TYPE_MAIN_VARIANT(TREE_TYPE(lhs)) ==
                        TYPE_MAIN_VARIANT(TREE_TYPE(rhs)));

    tree fn;
    bool pass_n = false;

    /* Obtain the compare operand size as a constant.  */
    tree st = TREE_TYPE(lhs);
    tree szt = TYPE_SIZE(st);

    if (!tree_fits_uhwi_p(szt)) return;

    unsigned HOST_WIDE_INT sz = tree_to_uhwi(szt);

    /* Round it up.  */
    if (sz % 8) sz = (((sz - 1) / 8) + 1) * 8;

    /* Select the hook function to call, based on the size.  */
    switch (sz) {

      default:
        fn = cmplog_hook(0);
        pass_n = true;
        break;

      case 8:
        fn = cmplog_hook(1);
        break;

      case 16:
        fn = cmplog_hook(2);
        break;

      case 32:
        fn = cmplog_hook(3);
        break;

      case 64:
        fn = cmplog_hook(4);
        break;

      case 128:
        fn = cmplog_hook(5);
        break;

    }

    /* Set attr according to the compare operation.  */
    unsigned char attr = 0;

    switch (code) {

      case UNORDERED_EXPR:
      case ORDERED_EXPR:
        /* ??? */
        /* Fallthrough.  */
      case NE_EXPR:
      case LTGT_EXPR:
        break;

      case EQ_EXPR:
      case UNEQ_EXPR:
        attr += 1;
        break;

      case GT_EXPR:
      case UNGT_EXPR:
        attr += 2;
        break;

      case GE_EXPR:
      case UNGE_EXPR:
        attr += 3;
        break;

      case LT_EXPR:
      case UNLT_EXPR:
        attr += 4;
        break;

      case LE_EXPR:
      case UNLE_EXPR:
        attr += 5;
        break;

      default:
        gcc_unreachable();

    }

    if (FLOAT_TYPE_P(TREE_TYPE(lhs))) {

      attr += 8;

      tree t = build_nonstandard_integer_type(sz, 1);

      tree    s = make_ssa_name(t);
      gimple *g = gimple_build_assign(s, VIEW_CONVERT_EXPR,
                                      build1(VIEW_CONVERT_EXPR, t, lhs));
      lhs = s;
      gsi_insert_before(&gsi, g, GSI_SAME_STMT);

      s = make_ssa_name(t);
      g = gimple_build_assign(s, VIEW_CONVERT_EXPR,
                              build1(VIEW_CONVERT_EXPR, t, rhs));
      rhs = s;
      gsi_insert_before(&gsi, g, GSI_SAME_STMT);

    }

    /* Convert the operands to the hook arg type, if needed.  */
    tree t = TREE_VALUE(TYPE_ARG_TYPES(TREE_TYPE(fn)));

    lhs = fold_convert_loc(UNKNOWN_LOCATION, t, lhs);
    if (!is_gimple_val(lhs)) {

      tree    s = make_ssa_name(t);
      gimple *g = gimple_build_assign(s, lhs);
      lhs = s;
      gsi_insert_before(&gsi, g, GSI_SAME_STMT);

    }

    rhs = fold_convert_loc(UNKNOWN_LOCATION, t, rhs);
    if (!is_gimple_val(rhs)) {

      tree    s = make_ssa_name(t);
      gimple *g = gimple_build_assign(s, rhs);
      rhs = s;
      gsi_insert_before(&gsi, g, GSI_SAME_STMT);

    }

    /* Insert the call.  */
    tree    att = build_int_cst(t8u, attr);
    gimple *call;
    if (pass_n)
      call = gimple_build_call(fn, 4, lhs, rhs, att,
                               build_int_cst(t8u, sz / 8 - 1));
    else
      call = gimple_build_call(fn, 3, lhs, rhs, att);

    gsi_insert_before(&gsi, call, GSI_SAME_STMT);

  }

  virtual unsigned int execute(function *fn) {

    if (!isInInstrumentList(fn)) return 0;

    basic_block bb;
    FOR_EACH_BB_FN(bb, fn) {

      /* A GIMPLE_COND or GIMPLE_SWITCH will always be the last stmt
         in a BB.  */
      gimple_stmt_iterator gsi = gsi_last_bb(bb);
      if (gsi_end_p(gsi)) continue;

      gimple *stmt = gsi_stmt(gsi);

      if (gimple_code(stmt) == GIMPLE_COND) {

        tree_code code = gimple_cond_code(stmt);
        tree      lhs = gimple_cond_lhs(stmt);
        tree      rhs = gimple_cond_rhs(stmt);

        insert_cmplog_call(gsi, code, lhs, rhs);

      } else if (gimple_code(stmt) == GIMPLE_SWITCH) {

        gswitch *sw = as_a<gswitch *>(stmt);
        tree     lhs = gimple_switch_index(sw);

        for (int i = 0, e = gimple_switch_num_labels(sw); i < e; i++) {

          tree clx = gimple_switch_label(sw, i);
          tree rhsl = CASE_LOW(clx);
          /* Default case labels exprs don't have a CASE_LOW.  */
          if (!rhsl) continue;
          tree rhsh = CASE_HIGH(clx);
          /* If there is a CASE_HIGH, issue range compares.  */
          if (rhsh) {

            insert_cmplog_call(gsi, GE_EXPR, lhs, rhsl);
            insert_cmplog_call(gsi, LE_EXPR, lhs, rhsh);

          }

          /* Otherwise, use a single equality compare.  */
          else
            insert_cmplog_call(gsi, EQ_EXPR, lhs, rhsl);

        }

      } else

        continue;

    }

    return 0;

  }

};

static struct plugin_info afl_cmplog_plugin = {

    .version = "20220420",
    .help = G_("AFL gcc cmplog plugin\n\
\n\
Set AFL_QUIET in the environment to silence it.\n\
"),

};

}  // namespace

/* This is the function GCC calls when loading a plugin.  Initialize
   and register further callbacks.  */
int plugin_init(struct plugin_name_args   *info,
                struct plugin_gcc_version *version) {

  if (!plugin_default_version_check(version, &gcc_version))
    FATAL(G_("GCC and plugin have incompatible versions, expected GCC %s, "
             "is %s"),
          gcc_version.basever, version->basever);

  /* Show a banner.  */
  bool quiet = false;
  if (isatty(2) && !getenv("AFL_QUIET"))
    SAYF(cCYA "afl-gcc-cmplog-pass " cBRI VERSION cRST
              " by <oliva@adacore.com>\n");
  else
    quiet = true;

  const char *name = info->base_name;
  register_callback(name, PLUGIN_INFO, NULL, &afl_cmplog_plugin);

  afl_cmplog_pass          *aflp = new afl_cmplog_pass(quiet);
  struct register_pass_info pass_info = {

      .pass = aflp,
      .reference_pass_name = "ssa",
      .ref_pass_instance_number = 1,
      .pos_op = PASS_POS_INSERT_AFTER,

  };

  register_callback(name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  return 0;

}

