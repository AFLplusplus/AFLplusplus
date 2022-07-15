/* GCC plugin for cmplog routines instrumentation of code for AFL++.

   Copyright 2014-2019 Free Software Foundation, Inc
   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.
   Copyright 2019-2022 AdaCore

   Written by Alexandre Oliva <oliva@adacore.com>, based on the AFL++
   LLVM CmpLog Routines pass by Andrea Fioraldi
   <andreafioraldi@gmail.com>, and on the AFL GCC CmpLog pass.

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

static const struct pass_data afl_cmptrs_pass_data = {

    .type = GIMPLE_PASS,
    .name = "aflcmptrs",
    .optinfo_flags = OPTGROUP_NONE,
    .tv_id = TV_NONE,
    .properties_required = 0,
    .properties_provided = 0,
    .properties_destroyed = 0,
    .todo_flags_start = 0,
    .todo_flags_finish = (TODO_update_ssa | TODO_cleanup_cfg | TODO_verify_il |
                          TODO_rebuild_cgraph_edges),

};

struct afl_cmptrs_pass : afl_base_pass {

  afl_cmptrs_pass(bool quiet)
      : afl_base_pass(quiet, /*debug=*/false, afl_cmptrs_pass_data),
        tp8u(),
        cmptrs_hooks() {

  }

  /* A pointer type to a unsigned 8-bit integral type.  */
  tree tp8u;

  /* Declarations for the various cmptrs hook functions, allocated on
     demand..  [0] is for compares between any pointers, [1] is for
     compares between G++ std::string, [2] is for compares between G++
     std::string and GCC C strings, [3] and [4] are analogous to [1]
     and [2] but for LLVM C++ strings.  */
  tree cmptrs_hooks[5];

  tree cmptrs_hook(unsigned i) {

    if (!tp8u) {

      tree t8u;
      if (BITS_PER_UNIT == 8)
        t8u = unsigned_char_type_node;
      else
        t8u = build_nonstandard_integer_type(8, 1);
      tp8u = build_pointer_type(t8u);

    }

    if (i <= ARRAY_SIZE(cmptrs_hooks) && cmptrs_hooks[i])
      return cmptrs_hooks[i];

    const char *n = NULL;

    switch (i) {

      case 0:
        n = "__cmplog_rtn_hook";
        break;

      case 1:
        n = "__cmplog_rtn_gcc_stdstring_stdstring";
        break;

      case 2:
        n = "__cmplog_rtn_gcc_stdstring_cstring";
        break;

      case 3:
        n = "__cmplog_rtn_llvm_stdstring_stdstring";
        break;

      case 4:
        n = "__cmplog_rtn_llvm_stdstring_cstring";
        break;

      default:
        gcc_unreachable();

    }

    tree fnt = build_function_type_list(void_type_node, tp8u, tp8u, NULL_TREE);
    tree t = cmptrs_hooks[i] = build_fn_decl(n, fnt);

    /* Mark the newly-created decl as non-throwing, so that we can
       insert call within basic blocks.  */
    TREE_NOTHROW(t) = 1;

    return t;

  }

  /* Return true if T is the char* type.  */
  bool is_c_string(tree t) {

    return (POINTER_TYPE_P(t) &&
            TYPE_MAIN_VARIANT(TREE_TYPE(t)) == char_type_node);

  }

  /* Return true if T is an indirect std::string type.  The LLVM pass
     tests portions of the mangled name of the callee.  We could do
     that in GCC too, but computing the mangled name may cause
     template instantiations and get symbols defined that could
     otherwise be considered unused.  We check for compatible layout,
     and class, namespace, and field names.  These have been unchanged
     since at least GCC 7, probably longer, up to GCC 11.  Odds are
     that, if it were to change in significant ways, mangling would
     also change to flag the incompatibility, and we'd have to use a
     different hook anyway.  */
  bool is_gxx_std_string(tree t) {

    /* We need a pointer or reference type.  */
    if (!POINTER_TYPE_P(t)) return false;

    /* Get to the pointed-to type.  */
    t = TREE_TYPE(t);
    if (!t) return false;

    /* Select the main variant, so that can compare types with pointers.  */
    t = TYPE_MAIN_VARIANT(t);

    /* We expect it to be a record type.  */
    if (TREE_CODE(t) != RECORD_TYPE) return false;

    /* The type of the template is basic_string.  */
    if (strcmp(IDENTIFIER_POINTER(TYPE_IDENTIFIER(t)), "basic_string") != 0)
      return false;

    /* It's declared in an internal namespace named __cxx11.  */
    tree c = DECL_CONTEXT(TYPE_NAME(t));
    if (!c || TREE_CODE(c) != NAMESPACE_DECL ||
        strcmp(IDENTIFIER_POINTER(DECL_NAME(c)), "__cxx11") != 0)
      return false;

    /* The __cxx11 namespace is a member of namespace std.  */
    c = DECL_CONTEXT(c);
    if (!c || TREE_CODE(c) != NAMESPACE_DECL ||
        strcmp(IDENTIFIER_POINTER(DECL_NAME(c)), "std") != 0)
      return false;

    /* And the std namespace is in the global namespace.  */
    c = DECL_CONTEXT(c);
    if (c && TREE_CODE(c) != TRANSLATION_UNIT_DECL) return false;

    /* Check that the first nonstatic data member of the record type
       is named _M_dataplus.  */
    for (c = TYPE_FIELDS(t); c; c = DECL_CHAIN(c))
      if (TREE_CODE(c) == FIELD_DECL) break;
    if (!c || !integer_zerop(DECL_FIELD_BIT_OFFSET(c)) ||
        strcmp(IDENTIFIER_POINTER(DECL_NAME(c)), "_M_dataplus") != 0)
      return false;

    /* Check that the second nonstatic data member of the record type
       is named _M_string_length.  */
    tree f2;
    for (f2 = DECL_CHAIN(c); f2; f2 = DECL_CHAIN(f2))
      if (TREE_CODE(f2) == FIELD_DECL) break;
    if (!f2                       /* No need to check this field's offset.  */
        || strcmp(IDENTIFIER_POINTER(DECL_NAME(f2)), "_M_string_length") != 0)
      return false;

    /* The type of the second data member is size_t.  */
    if (!TREE_TYPE(f2) || TYPE_MAIN_VARIANT(TREE_TYPE(f2)) != size_type_node)
      return false;

    /* Now go back to the first data member.  Its type should be a
       record type named _Alloc_hider.  */
    c = TREE_TYPE(c);
    if (!c || TREE_CODE(c) != RECORD_TYPE ||
        strcmp(IDENTIFIER_POINTER(TYPE_IDENTIFIER(c)), "_Alloc_hider") != 0)
      return false;

    /* And its first data member is named _M_p.  */
    for (c = TYPE_FIELDS(c); c; c = DECL_CHAIN(c))
      if (TREE_CODE(c) == FIELD_DECL) break;
    if (!c || !integer_zerop(DECL_FIELD_BIT_OFFSET(c)) ||
        strcmp(IDENTIFIER_POINTER(DECL_NAME(c)), "_M_p") != 0)
      return false;

    /* For the basic_string<char> type we're interested in, the type
       of the data member is the C string type.  */
    if (!is_c_string(TREE_TYPE(c))) return false;

    /* This might not be the real thing, but the bits that matter for
       the hook are there.  */

    return true;

  }

  /* ??? This is not implemented.  What would the point be of
     recognizing LLVM's string type in GCC?  */
  bool is_llvm_std_string(tree t) {

    return false;

  }

  virtual unsigned int execute(function *fn) {

    if (!isInInstrumentList(fn)) return 0;

    basic_block bb;
    FOR_EACH_BB_FN(bb, fn) {

      for (gimple_stmt_iterator gsi = gsi_after_labels(bb); !gsi_end_p(gsi);
           gsi_next(&gsi)) {

        gimple *stmt = gsi_stmt(gsi);

        /* We're only interested in GIMPLE_CALLs.  */
        if (gimple_code(stmt) != GIMPLE_CALL) continue;

        if (gimple_call_num_args(stmt) < 2) continue;

        gcall *c = as_a<gcall *>(stmt);

        tree callee_type = gimple_call_fntype(c);

        if (!callee_type || !TYPE_ARG_TYPES(callee_type) ||
            !TREE_CHAIN(TYPE_ARG_TYPES(callee_type)))
          continue;

        tree arg_type[2] = {

            TYPE_MAIN_VARIANT(TREE_VALUE(TYPE_ARG_TYPES(callee_type))),
            TYPE_MAIN_VARIANT(
                TREE_VALUE(TREE_CHAIN(TYPE_ARG_TYPES(callee_type))))};

        tree fn = NULL;
        /* Callee arglist starts with two GCC std::string arguments.  */
        if (arg_type[0] == arg_type[1] && is_gxx_std_string(arg_type[0]))
          fn = cmptrs_hook(1);
        /* Callee arglist starts with GCC std::string and C string.  */
        else if (is_gxx_std_string(arg_type[0]) && is_c_string(arg_type[1]))
          fn = cmptrs_hook(2);
        /* Callee arglist starts with two LLVM std::string arguments.  */
        else if (arg_type[0] == arg_type[1] && is_llvm_std_string(arg_type[0]))
          fn = cmptrs_hook(3);
        /* Callee arglist starts with LLVM std::string and C string.  */
        else if (is_llvm_std_string(arg_type[0]) && is_c_string(arg_type[1]))
          fn = cmptrs_hook(4);
        /* Callee arglist starts with two pointers to the same type,
           and callee returns a value.  */
        else if (arg_type[0] == arg_type[1] && POINTER_TYPE_P(arg_type[0]) &&
                 (TYPE_MAIN_VARIANT(gimple_call_return_type(c)) !=
                  void_type_node))
          fn = cmptrs_hook(0);
        else
          continue;

        tree arg[2] = {gimple_call_arg(c, 0), gimple_call_arg(c, 1)};

        for (unsigned i = 0; i < ARRAY_SIZE(arg); i++) {

          tree c = fold_convert_loc(UNKNOWN_LOCATION, tp8u, arg[i]);
          if (!is_gimple_val(c)) {

            tree    s = make_ssa_name(tp8u);
            gimple *g = gimple_build_assign(s, c);
            c = s;
            gsi_insert_before(&gsi, g, GSI_SAME_STMT);

          }

          arg[i] = c;

        }

        gimple *call = gimple_build_call(fn, 2, arg[0], arg[1]);
        gsi_insert_before(&gsi, call, GSI_SAME_STMT);

      }

    }

    return 0;

  }

};

static struct plugin_info afl_cmptrs_plugin = {

    .version = "20220420",
    .help = G_("AFL gcc cmptrs plugin\n\
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
    SAYF(cCYA "afl-gcc-cmptrs-pass " cBRI VERSION cRST
              " by <oliva@adacore.com>\n");
  else
    quiet = true;

  const char *name = info->base_name;
  register_callback(name, PLUGIN_INFO, NULL, &afl_cmptrs_plugin);

  afl_cmptrs_pass          *aflp = new afl_cmptrs_pass(quiet);
  struct register_pass_info pass_info = {

      .pass = aflp,
      .reference_pass_name = "ssa",
      .ref_pass_instance_number = 1,
      .pos_op = PASS_POS_INSERT_AFTER,

  };

  register_callback(name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

  return 0;

}

