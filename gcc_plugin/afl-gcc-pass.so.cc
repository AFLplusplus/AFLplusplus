//
// There are some TODOs in this file:
//   - fix instrumentation via external call
//   - fix inline instrumentation
//   - implement whitelist feature
//   - dont instrument blocks that are uninteresting
//   - implement neverZero
//

/*
   american fuzzy lop++ - GCC instrumentation pass
   ---------------------------------------------

   Written by Austin Seipp <aseipp@pobox.com> with bits from
              Emese Revfy <re.emese@gmail.com>

   Fixed by Heiko Eißfeldt 2019-2020 for AFL++

   GCC integration design is based on the LLVM design, which comes
   from Laszlo Szekeres. Some of the boilerplate code below for
   afl_pass to adapt to different GCC versions was taken from Emese
   Revfy's Size Overflow plugin for GCC, licensed under the GPLv2/v3.

   (NOTE: this plugin code is under GPLv3, in order to comply with the
   GCC runtime library exception, which states that you may distribute
   "Target Code" from the compiler under a license of your choice, as
   long as the "Compilation Process" is "Eligible", and contains no
   GPL-incompatible software in GCC "during the process of
   transforming high level code to target code". In this case, the
   plugin will be used to generate "Target Code" during the
   "Compilation Process", and thus it must be GPLv3 to be "eligible".)

   Copyright (C) 2015 Austin Seipp

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

#define BUILD_INLINE_INST

#include "../config.h"
#include "../include/debug.h"

/* clear helper macros AFL types pull in, which intervene with gcc-plugin
 * headers from GCC-8 */
#ifdef likely
#undef likely
#endif
#ifdef unlikely
#undef unlikely
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <list>
#include <string>
#include <fstream>

#include <gcc-plugin.h>
#include <plugin-version.h>
#include <diagnostic.h>
#include <tree.h>
#include <tree-ssa.h>
#include <tree-pass.h>
#include <tree-ssa-alias.h>
#include <basic-block.h>
#include <gimple-expr.h>
#include <gimple.h>
#include <gimple-iterator.h>
#include <gimple-ssa.h>
#include <version.h>
#include <toplev.h>
#include <intl.h>
#include <context.h>
#include <stringpool.h>
#include <cgraph.h>
#include <cfgloop.h>

/* -------------------------------------------------------------------------- */
/* -- AFL instrumentation pass ---------------------------------------------- */

static int                    be_quiet = 0;
static unsigned int           inst_ratio = 100;
static bool                   inst_ext = true;
static std::list<std::string> myWhitelist;

static unsigned int ext_call_instrument(function *fun) {

  /* Instrument all the things! */
  basic_block bb;
  unsigned    finst_blocks = 0;
  unsigned    fcnt_blocks = 0;

  tree fntype = build_function_type_list(void_type_node,          /* return */
                                         uint32_type_node,          /* args */
                                         NULL_TREE);                /* done */
  tree fndecl = build_fn_decl("__afl_trace", fntype);
  TREE_STATIC(fndecl) = 1;                             /* Defined elsewhere */
  TREE_PUBLIC(fndecl) = 1;                                        /* Public */
  DECL_EXTERNAL(fndecl) = 1;                            /* External linkage */
  DECL_ARTIFICIAL(fndecl) = 1;                      /* Injected by compiler */

  FOR_EACH_BB_FN(bb, fun) {

    gimple_seq           fcall;
    gimple_seq           seq = NULL;
    gimple_stmt_iterator bentry;
    ++fcnt_blocks;

    // only instrument if this basic block is the destination of a previous
    // basic block that has multiple successors
    // this gets rid of ~5-10% of instrumentations that are unnecessary
    // result: a little more speed and less map pollution

    int           more_than_one = -1;
    edge          ep;
    edge_iterator eip;

    FOR_EACH_EDGE(ep, eip, bb->preds) {

      int count = 0;
      if (more_than_one == -1) more_than_one = 0;

      basic_block   Pred = ep->src;
      edge          es;
      edge_iterator eis;
      FOR_EACH_EDGE(es, eis, Pred->succs) {

        basic_block Succ = es->dest;
        if (Succ != NULL) count++;

      }

      if (count > 1) more_than_one = 1;

    }

    if (more_than_one != 1) continue;

    /* Bail on this block if we trip the specified ratio */
    if (R(100) >= inst_ratio) continue;

    /* Make up cur_loc */
    unsigned int rand_loc = R(MAP_SIZE);
    tree         cur_loc = build_int_cst(uint32_type_node, rand_loc);

    /* Update bitmap via external call */
    /* to quote:
     * /+ Trace a basic block with some ID +/
     * void __afl_trace(u32 x);
     */

    fcall = gimple_build_call(
        fndecl, 1,
        cur_loc); /* generate the function _call_ to above built reference, with
                   *1* parameter -> the random const for the location */
    gimple_seq_add_stmt(&seq, fcall);         /* and insert into a sequence */

    /* Done - grab the entry to the block and insert sequence */
    bentry = gsi_after_labels(bb);
    gsi_insert_seq_before(&bentry, seq, GSI_SAME_STMT);

    ++finst_blocks;

  }

  /* Say something nice. */
  if (!be_quiet) {

    if (!finst_blocks)
      WARNF(G_("No instrumentation targets found in " cBRI "%s" cRST),
            function_name(fun));
    else if (finst_blocks < fcnt_blocks)
      OKF(G_("Instrumented %2u /%2u locations in " cBRI "%s" cRST),
          finst_blocks, fcnt_blocks, function_name(fun));
    else
      OKF(G_("Instrumented %2u locations in " cBRI "%s" cRST), finst_blocks,
          function_name(fun));

  }

  return 0;

}

static unsigned int inline_instrument(function *fun) {

  /* Instrument all the things! */
  basic_block bb;
  unsigned    finst_blocks = 0;
  unsigned    fcnt_blocks = 0;
  tree        one = build_int_cst(unsigned_char_type_node, 1);
  // tree zero = build_int_cst(unsigned_char_type_node, 0);

  /* Set up global type declarations */
  tree map_type = build_pointer_type(unsigned_char_type_node);
  tree map_ptr_g =
      build_decl(UNKNOWN_LOCATION, VAR_DECL,
                 get_identifier_with_length("__afl_area_ptr", 14), map_type);
  TREE_USED(map_ptr_g) = 1;
  TREE_STATIC(map_ptr_g) = 1;                          /* Defined elsewhere */
  DECL_EXTERNAL(map_ptr_g) = 1;                         /* External linkage */
  DECL_PRESERVE_P(map_ptr_g) = 1;
  DECL_ARTIFICIAL(map_ptr_g) = 1;                   /* Injected by compiler */
  rest_of_decl_compilation(map_ptr_g, 1, 0);

  tree prev_loc_g = build_decl(UNKNOWN_LOCATION, VAR_DECL,
                               get_identifier_with_length("__afl_prev_loc", 14),
                               uint32_type_node);
  TREE_USED(prev_loc_g) = 1;
  TREE_STATIC(prev_loc_g) = 1;                         /* Defined elsewhere */
  DECL_EXTERNAL(prev_loc_g) = 1;                        /* External linkage */
  DECL_PRESERVE_P(prev_loc_g) = 1;
  DECL_ARTIFICIAL(prev_loc_g) = 1;                  /* Injected by compiler */
  set_decl_tls_model(prev_loc_g, TLS_MODEL_REAL);          /* TLS attribute */
  rest_of_decl_compilation(prev_loc_g, 1, 0);

  FOR_EACH_BB_FN(bb, fun) {

    gimple_seq           seq = NULL;
    gimple_stmt_iterator bentry;
    ++fcnt_blocks;

    // only instrument if this basic block is the destination of a previous
    // basic block that has multiple successors
    // this gets rid of ~5-10% of instrumentations that are unnecessary
    // result: a little more speed and less map pollution

    int           more_than_one = -1;
    edge          ep;
    edge_iterator eip;
    FOR_EACH_EDGE(ep, eip, bb->preds) {

      int count = 0;
      if (more_than_one == -1) more_than_one = 0;

      basic_block   Pred = ep->src;
      edge          es;
      edge_iterator eis;
      FOR_EACH_EDGE(es, eis, Pred->succs) {

        basic_block Succ = es->dest;
        if (Succ != NULL) count++;

      }

      if (count > 1) more_than_one = 1;

    }

    if (more_than_one != 1) continue;

    /* Bail on this block if we trip the specified ratio */
    if (R(100) >= inst_ratio) continue;

    /* Make up cur_loc */

    unsigned int rand_loc = R(MAP_SIZE);
    tree         cur_loc = build_int_cst(uint32_type_node, rand_loc);

    /* Load prev_loc, xor with cur_loc */
    // gimple_assign <var_decl, prev_loc.0_1, prev_loc, NULL, NULL>
    tree     prev_loc = create_tmp_var_raw(uint32_type_node, "prev_loc");
    gassign *g = gimple_build_assign(prev_loc, VAR_DECL, prev_loc_g);
    gimple_seq_add_stmt(&seq, g);  // load prev_loc
    update_stmt(g);

    // gimple_assign <bit_xor_expr, _2, prev_loc.0_1, 47231, NULL>
    tree area_off = create_tmp_var_raw(uint32_type_node, "area_off");
    g = gimple_build_assign(area_off, BIT_XOR_EXPR, prev_loc, cur_loc);
    gimple_seq_add_stmt(&seq, g);  // area_off = prev_loc ^ cur_loc
    update_stmt(g);

    /* Update bitmap */

    // gimple_assign <addr_expr, p_6, &map[_2], NULL, NULL>
    tree map_ptr = create_tmp_var(map_type, "map_ptr");
    tree map_ptr2 = create_tmp_var(map_type, "map_ptr2");

    g = gimple_build_assign(map_ptr, map_ptr_g);
    gimple_seq_add_stmt(&seq, g);  // map_ptr = __afl_area_ptr
    update_stmt(g);

#if 1
#if 0
		tree addr = build2(ADDR_EXPR, map_type, map_ptr, area_off);
		g = gimple_build_assign(map_ptr2, MODIFY_EXPR, addr);
		gimple_seq_add_stmt(&seq, g); // map_ptr2 = map_ptr + area_off
		update_stmt(g);
#else
    g = gimple_build_assign(map_ptr2, PLUS_EXPR, map_ptr, area_off);
    gimple_seq_add_stmt(&seq, g);  // map_ptr2 = map_ptr + area_off
    update_stmt(g);
#endif

    // gimple_assign <mem_ref, _3, *p_6, NULL, NULL>
    tree tmp1 = create_tmp_var_raw(unsigned_char_type_node, "tmp1");
    g = gimple_build_assign(tmp1, MEM_REF, map_ptr2);
    gimple_seq_add_stmt(&seq, g);  // tmp1 = *map_ptr2
    update_stmt(g);
#else
    tree atIndex = build2(PLUS_EXPR, uint32_type_node, map_ptr, area_off);
    tree array_address = build1(ADDR_EXPR, map_type, atIndex);
    tree array_access = build1(INDIRECT_REF, map_type, array_address);
    tree tmp1 = create_tmp_var(unsigned_char_type_node, "tmp1");
    g = gimple_build_assign(tmp1, array_access);
    gimple_seq_add_stmt(&seq, g);  // tmp1 = *(map_ptr + area_off)
    update_stmt(g);
#endif
    // gimple_assign <plus_expr, _4, _3, 1, NULL>
    tree tmp2 = create_tmp_var_raw(unsigned_char_type_node, "tmp2");
    g = gimple_build_assign(tmp2, PLUS_EXPR, tmp1, one);
    gimple_seq_add_stmt(&seq, g);  // tmp2 = tmp1 + 1
    update_stmt(g);

    // TODO: neverZero: here we have to check if tmp3 == 0
    //                  and add 1 if so

    // gimple_assign <ssa_name, *p_6, _4, NULL, NULL>
    //		tree map_ptr3 = create_tmp_var_raw(map_type, "map_ptr3");
    g = gimple_build_assign(map_ptr2, INDIRECT_REF, tmp2);
    gimple_seq_add_stmt(&seq, g);  // *map_ptr2 = tmp2
    update_stmt(g);

    /* Set prev_loc to cur_loc >> 1 */

    // gimple_assign <integer_cst, prev_loc, 23615, NULL, NULL>
    tree shifted_loc = build_int_cst(TREE_TYPE(prev_loc_g), rand_loc >> 1);
    tree prev_loc2 = create_tmp_var_raw(uint32_type_node, "prev_loc2");
    g = gimple_build_assign(prev_loc2, shifted_loc);
    gimple_seq_add_stmt(&seq, g);  // __afl_prev_loc = cur_loc >> 1
    update_stmt(g);
    g = gimple_build_assign(prev_loc_g, prev_loc2);
    gimple_seq_add_stmt(&seq, g);  // __afl_prev_loc = cur_loc >> 1
    update_stmt(g);

    /* Done - grab the entry to the block and insert sequence */

    bentry = gsi_after_labels(bb);
    gsi_insert_seq_before(&bentry, seq, GSI_NEW_STMT);

    ++finst_blocks;

  }

  /* Say something nice. */
  if (!be_quiet) {

    if (!finst_blocks)
      WARNF(G_("No instrumentation targets found in " cBRI "%s" cRST),
            function_name(fun));
    else if (finst_blocks < fcnt_blocks)
      OKF(G_("Instrumented %2u /%2u locations in " cBRI "%s" cRST),
          finst_blocks, fcnt_blocks, function_name(fun));
    else
      OKF(G_("Instrumented   %2u   locations in " cBRI "%s" cRST), finst_blocks,
          function_name(fun));

  }

  return 0;

}

/* -------------------------------------------------------------------------- */
/* -- Boilerplate and initialization ---------------------------------------- */

static const struct pass_data afl_pass_data = {

    .type = GIMPLE_PASS,
    .name = "afl-inst",
    .optinfo_flags = OPTGROUP_NONE,

    .tv_id = TV_NONE,
    .properties_required = 0,
    .properties_provided = 0,
    .properties_destroyed = 0,
    .todo_flags_start = 0,
    // NOTE(aseipp): it's very, very important to include
    // at least 'TODO_update_ssa' here so that GCC will
    // properly update the resulting SSA form, e.g., to
    // include new PHI nodes for newly added symbols or
    // names. Do not remove this. Do not taunt Happy Fun
    // Ball.
    .todo_flags_finish = TODO_update_ssa | TODO_verify_il | TODO_cleanup_cfg,

};

namespace {

class afl_pass : public gimple_opt_pass {

 private:
  bool do_ext_call;

 public:
  afl_pass(bool ext_call, gcc::context *g)
      : gimple_opt_pass(afl_pass_data, g), do_ext_call(ext_call) {

  }

  unsigned int execute(function *fun) override {

    if (!myWhitelist.empty()) {

      bool         instrumentBlock = false;
      std::string  instFilename;
      unsigned int instLine = 0;

      /* EXPR_FILENAME
      This macro returns the name of the file in which the entity was declared,
      as a char*. For an entity declared implicitly by the compiler (like
      __builtin_ memcpy), this will be the string "<internal>".
      */
      const char *fname = DECL_SOURCE_FILE(fun->decl);

      if (0 != strncmp("<internal>", fname, 10) &&
          0 != strncmp("<built-in>", fname, 10)) {

        instFilename = fname;
        instLine = DECL_SOURCE_LINE(fun->decl);

        /* Continue only if we know where we actually are */
        if (!instFilename.empty()) {

          for (std::list<std::string>::iterator it = myWhitelist.begin();
               it != myWhitelist.end(); ++it) {

            /* We don't check for filename equality here because
             * filenames might actually be full paths. Instead we
             * check that the actual filename ends in the filename
             * specified in the list. */
            if (instFilename.length() >= it->length()) {

              if (instFilename.compare(instFilename.length() - it->length(),
                                       it->length(), *it) == 0) {

                instrumentBlock = true;
                break;

              }

            }

          }

        }

      }

      /* Either we couldn't figure out our location or the location is
       * not whitelisted, so we skip instrumentation. */
      if (!instrumentBlock) {

        if (!be_quiet) {

          if (!instFilename.empty())
            SAYF(cYEL "[!] " cBRI "Not in whitelist, skipping %s line %u...\n",
                 instFilename.c_str(), instLine);
          else
            SAYF(cYEL "[!] " cBRI "No filename information found, skipping it");

        }

        return 0;

      }

    }

    return do_ext_call ? ext_call_instrument(fun) : inline_instrument(fun);

  }

};                                                        /* class afl_pass */

}  // namespace

static struct opt_pass *make_afl_pass(bool ext_call, gcc::context *ctxt) {

  return new afl_pass(ext_call, ctxt);

}

/* -------------------------------------------------------------------------- */
/* -- Initialization -------------------------------------------------------- */

int plugin_is_GPL_compatible = 1;

static struct plugin_info afl_plugin_info = {

    .version = "20191015",
    .help = "AFL++ gcc plugin\n",

};

int plugin_init(struct plugin_name_args *  plugin_info,
                struct plugin_gcc_version *version) {

  struct register_pass_info afl_pass_info;
  struct timeval            tv;
  struct timezone           tz;
  u32                       rand_seed;

  /* Setup random() so we get Actually Random(TM) outputs from R() */
  gettimeofday(&tv, &tz);
  rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
  SR(rand_seed);

  /* Pass information */
  afl_pass_info.pass = make_afl_pass(inst_ext, g);
  afl_pass_info.reference_pass_name = "ssa";
  afl_pass_info.ref_pass_instance_number = 1;
  afl_pass_info.pos_op = PASS_POS_INSERT_AFTER;

  if (!plugin_default_version_check(version, &gcc_version)) {

    FATAL(G_("Incompatible gcc/plugin versions!"));

  }

  /* Show a banner */
  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(G_(cCYA "afl-gcc-pass" VERSION cRST
                 " initially by <aseipp@pobox.com>, maintainer: hexcoder-\n"));

  } else

    be_quiet = 1;

  /* Decide instrumentation ratio */
  char *inst_ratio_str = getenv("AFL_INST_RATIO");

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL(G_("Bad value of AFL_INST_RATIO (must be between 1 and 100)"));
    else {

      if (!be_quiet)
        ACTF(G_("%s instrumentation at ratio of %u%% in %s mode."),
             inst_ext ? G_("Call-based") : G_("Inline"), inst_ratio,
             getenv("AFL_HARDEN") ? G_("hardened") : G_("non-hardened"));

    }

  }

  char *instWhiteListFilename = getenv("AFL_GCC_WHITELIST");
  if (instWhiteListFilename) {

    std::string   line;
    std::ifstream fileStream;
    fileStream.open(instWhiteListFilename);
    if (!fileStream) PFATAL("Unable to open AFL_GCC_WHITELIST");
    getline(fileStream, line);
    while (fileStream) {

      myWhitelist.push_back(line);
      getline(fileStream, line);

    }

  } else if (!be_quiet && getenv("AFL_LLVM_WHITELIST"))

    SAYF(cYEL "[-] " cRST
              "AFL_LLVM_WHITELIST environment variable detected - did you mean "
              "AFL_GCC_WHITELIST?\n");

  /* Go go gadget */
  register_callback(plugin_info->base_name, PLUGIN_INFO, NULL,
                    &afl_plugin_info);
  register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL,
                    &afl_pass_info);
  return 0;

}

