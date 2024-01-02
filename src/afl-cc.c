/*
   american fuzzy lop++ - compiler instrumentation wrapper
   -------------------------------------------------------

   Written by Michal Zalewski, Laszlo Szekeres and Marc Heuse

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#include "afl-cc.h"

void parse_fsanitize(char *string) {

  char *p, *ptr = string + strlen("-fsanitize=");
  char *new = malloc(strlen(string) + 1);
  char *tmp = malloc(strlen(ptr) + 1);
  u32   count = 0, len, ende = 0;

  if (!new || !tmp) { FATAL("could not acquire memory"); }
  strcpy(new, "-fsanitize=");

  do {

    p = strchr(ptr, ',');
    if (!p) {

      p = ptr + strlen(ptr) + 1;
      ende = 1;

    }

    len = p - ptr;
    if (len) {

      strncpy(tmp, ptr, len);
      tmp[len] = 0;
      // fprintf(stderr, "Found: %s\n", tmp);
      ptr += len + 1;
      if (*tmp) {

        u32 copy = 1;
        if (!strcmp(tmp, "fuzzer")) {

          need_aflpplib = 1;
          copy = 0;

        } else if (!strncmp(tmp, "fuzzer", 6)) {

          copy = 0;

        }

        if (copy) {

          if (count) { strcat(new, ","); }
          strcat(new, tmp);
          ++count;

        }

      }

    } else {

      ptr++;                                    /*fprintf(stderr, "NO!\n"); */

    }

  } while (!ende);

  strcpy(string, new);
  // fprintf(stderr, "string: %s\n", string);
  // fprintf(stderr, "new: %s\n", new);

}

static void maybe_usage(aflcc_state_t *aflcc, int argc, char **argv) {

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) {

    printf("afl-cc" VERSION
           " by Michal Zalewski, Laszlo Szekeres, Marc Heuse\n");

    SAYF(
        "\n"
        "afl-cc/afl-c++ [options]\n"
        "\n"
        "This is a helper application for afl-fuzz. It serves as a drop-in "
        "replacement\n"
        "for gcc and clang, letting you recompile third-party code with the "
        "required\n"
        "runtime instrumentation. A common use pattern would be one of the "
        "following:\n\n"

        "  CC=afl-cc CXX=afl-c++ ./configure --disable-shared\n"
        "  cmake -DCMAKE_C_COMPILERC=afl-cc -DCMAKE_CXX_COMPILER=afl-c++ .\n"
        "  CC=afl-cc CXX=afl-c++ meson\n\n");

    SAYF(
        "                                       |------------- FEATURES "
        "-------------|\n"
        "MODES:                                  NCC PERSIST DICT   LAF "
        "CMPLOG SELECT\n"
        "  [LLVM] LLVM:             %s%s\n"
        "      PCGUARD              %s      yes yes     module yes yes    "
        "yes\n"
        "      NATIVE               AVAILABLE      no  yes     no     no  "
        "part.  yes\n"
        "      CLASSIC              %s      no  yes     module yes yes    "
        "yes\n"
        "        - NORMAL\n"
        "        - CALLER\n"
        "        - CTX\n"
        "        - NGRAM-{2-16}\n"
        "  [LTO] LLVM LTO:          %s%s\n"
        "      PCGUARD              DEFAULT      yes yes     yes    yes yes "
        "   yes\n"
        "      CLASSIC                           yes yes     yes    yes yes "
        "   yes\n"
        "  [GCC_PLUGIN] gcc plugin: %s%s\n"
        "      CLASSIC              DEFAULT      no  yes     no     no  no     "
        "yes\n"
        "  [GCC/CLANG] simple gcc/clang: %s%s\n"
        "      CLASSIC              DEFAULT      no  no      no     no  no     "
        "no\n\n",
        aflcc->have_llvm ? "AVAILABLE" : "unavailable!",
        aflcc->compiler_mode == LLVM ? " [SELECTED]" : "",
        aflcc->have_llvm ? "AVAILABLE" : "unavailable!",
        aflcc->have_llvm ? "AVAILABLE" : "unavailable!",
        aflcc->have_lto ? "AVAILABLE" : "unavailable!",
        aflcc->compiler_mode == LTO ? " [SELECTED]" : "",
        aflcc->have_gcc_plugin ? "AVAILABLE" : "unavailable!",
        aflcc->compiler_mode == GCC_PLUGIN ? " [SELECTED]" : "",
        aflcc->have_gcc ? "AVAILABLE" : "unavailable!",
        (aflcc->compiler_mode == GCC || aflcc->compiler_mode == CLANG)
            ? " [SELECTED]"
            : "");

    SAYF(
        "Modes:\n"
        "  To select the compiler mode use a symlink version (e.g. "
        "afl-clang-fast), set\n"
        "  the environment variable AFL_CC_COMPILER to a mode (e.g. LLVM) or "
        "use the\n"
        "  command line parameter --afl-MODE (e.g. --afl-llvm). If none is "
        "selected,\n"
        "  afl-cc will select the best available (LLVM -> GCC_PLUGIN -> GCC).\n"
        "  The best is LTO but it often needs RANLIB and AR settings outside "
        "of afl-cc.\n\n");

#if LLVM_MAJOR > 10 || (LLVM_MAJOR == 10 && LLVM_MINOR > 0)
  #define NATIVE_MSG                                                   \
    "  LLVM-NATIVE:  use llvm's native PCGUARD instrumentation (less " \
    "performant)\n"
#else
  #define NATIVE_MSG ""
#endif

    SAYF(
        "Sub-Modes: (set via env AFL_LLVM_INSTRUMENT, afl-cc selects the best "
        "available)\n"
        "  PCGUARD: Dominator tree instrumentation (best!) (README.llvm.md)\n"

        NATIVE_MSG

        "  CLASSIC: decision target instrumentation (README.llvm.md)\n"
        "  CALLER:  CLASSIC + single callee context "
        "(instrumentation/README.ctx.md)\n"
        "  CTX:     CLASSIC + full callee context "
        "(instrumentation/README.ctx.md)\n"
        "  NGRAM-x: CLASSIC + previous path "
        "((instrumentation/README.ngram.md)\n\n");

#undef NATIVE_MSG

    SAYF(
        "Features: (see documentation links)\n"
        "  NCC:    non-colliding coverage [automatic] (that is an amazing "
        "thing!)\n"
        "          (instrumentation/README.lto.md)\n"
        "  PERSIST: persistent mode support [code] (huge speed increase!)\n"
        "          (instrumentation/README.persistent_mode.md)\n"
        "  DICT:   dictionary in the target [yes=automatic or LLVM module "
        "pass]\n"
        "          (instrumentation/README.lto.md + "
        "instrumentation/README.llvm.md)\n"
        "  LAF:    comparison splitting [env] "
        "(instrumentation/README.laf-intel.md)\n"
        "  CMPLOG: input2state exploration [env] "
        "(instrumentation/README.cmplog.md)\n"
        "  SELECT: selective instrumentation (allow/deny) on filename or "
        "function [env]\n"
        "          (instrumentation/README.instrument_list.md)\n\n");

    if (argc < 2 || strncmp(argv[1], "-hh", 3)) {

      SAYF(
          "To see all environment variables for the configuration of afl-cc "
          "use \"-hh\".\n");

    } else {

      SAYF(
          "Environment variables used:\n"
          "  AFL_CC: path to the C compiler to use\n"
          "  AFL_CXX: path to the C++ compiler to use\n"
          "  AFL_DEBUG: enable developer debugging output\n"
          "  AFL_DONT_OPTIMIZE: disable optimization instead of -O3\n"
          "  AFL_NO_BUILTIN: no builtins for string compare functions (for "
          "libtokencap.so)\n"
          "  AFL_NOOP: behave like a normal compiler (to pass configure "
          "tests)\n"
          "  AFL_PATH: path to instrumenting pass and runtime  "
          "(afl-compiler-rt.*o)\n"
          "  AFL_IGNORE_UNKNOWN_ENVS: don't warn on unknown env vars\n"
          "  AFL_INST_RATIO: percentage of branches to instrument\n"
          "  AFL_QUIET: suppress verbose output\n"
          "  AFL_HARDEN: adds code hardening to catch memory bugs\n"
          "  AFL_USE_ASAN: activate address sanitizer\n"
          "  AFL_USE_CFISAN: activate control flow sanitizer\n"
          "  AFL_USE_MSAN: activate memory sanitizer\n"
          "  AFL_USE_UBSAN: activate undefined behaviour sanitizer\n"
          "  AFL_USE_TSAN: activate thread sanitizer\n"
          "  AFL_USE_LSAN: activate leak-checker sanitizer\n");

      if (aflcc->have_gcc_plugin)
        SAYF(
            "\nGCC Plugin-specific environment variables:\n"
            "  AFL_GCC_CMPLOG: log operands of comparisons (RedQueen mutator)\n"
            "  AFL_GCC_OUT_OF_LINE: disable inlined instrumentation\n"
            "  AFL_GCC_SKIP_NEVERZERO: do not skip zero on trace counters\n"
            "  AFL_GCC_INSTRUMENT_FILE: enable selective instrumentation by "
            "filename\n");

#if LLVM_MAJOR >= 9
  #define COUNTER_BEHAVIOUR \
    "  AFL_LLVM_SKIP_NEVERZERO: do not skip zero on trace counters\n"
#else
  #define COUNTER_BEHAVIOUR \
    "  AFL_LLVM_NOT_ZERO: use cycling trace counters that skip zero\n"
#endif
      if (aflcc->have_llvm)
        SAYF(
            "\nLLVM/LTO/afl-clang-fast/afl-clang-lto specific environment "
            "variables:\n"
            "  AFL_LLVM_THREADSAFE_INST: instrument with thread safe counters, "
            "disables neverzero\n"

            COUNTER_BEHAVIOUR

            "  AFL_LLVM_DICT2FILE: generate an afl dictionary based on found "
            "comparisons\n"
            "  AFL_LLVM_DICT2FILE_NO_MAIN: skip parsing main() for the "
            "dictionary\n"
            "  AFL_LLVM_INJECTIONS_ALL: enables all injections hooking\n"
            "  AFL_LLVM_INJECTIONS_SQL: enables SQL injections hooking\n"
            "  AFL_LLVM_INJECTIONS_LDAP: enables LDAP injections hooking\n"
            "  AFL_LLVM_INJECTIONS_XSS: enables XSS injections hooking\n"
            "  AFL_LLVM_LAF_ALL: enables all LAF splits/transforms\n"
            "  AFL_LLVM_LAF_SPLIT_COMPARES: enable cascaded comparisons\n"
            "  AFL_LLVM_LAF_SPLIT_COMPARES_BITW: size limit (default 8)\n"
            "  AFL_LLVM_LAF_SPLIT_SWITCHES: cascaded comparisons on switches\n"
            "  AFL_LLVM_LAF_SPLIT_FLOATS: cascaded comparisons on floats\n"
            "  AFL_LLVM_LAF_TRANSFORM_COMPARES: cascade comparisons for string "
            "functions\n"
            "  AFL_LLVM_ALLOWLIST/AFL_LLVM_DENYLIST: enable "
            "instrument allow/\n"
            "    deny listing (selective instrumentation)\n");

      if (aflcc->have_llvm)
        SAYF(
            "  AFL_LLVM_CMPLOG: log operands of comparisons (RedQueen "
            "mutator)\n"
            "  AFL_LLVM_INSTRUMENT: set instrumentation mode:\n"
            "    CLASSIC, PCGUARD, LTO, GCC, CLANG, CALLER, CTX, NGRAM-2 "
            "..-16\n"
            " You can also use the old environment variables instead:\n"
            "  AFL_LLVM_USE_TRACE_PC: use LLVM trace-pc-guard instrumentation\n"
            "  AFL_LLVM_CALLER: use single context sensitive coverage (for "
            "CLASSIC)\n"
            "  AFL_LLVM_CTX: use full context sensitive coverage (for "
            "CLASSIC)\n"
            "  AFL_LLVM_NGRAM_SIZE: use ngram prev_loc count coverage (for "
            "CLASSIC)\n"
            "  AFL_LLVM_NO_RPATH: disable rpath setting for custom LLVM "
            "locations\n");

#ifdef AFL_CLANG_FLTO
      if (aflcc->have_lto)
        SAYF(
            "\nLTO/afl-clang-lto specific environment variables:\n"
            "  AFL_LLVM_MAP_ADDR: use a fixed coverage map address (speed), "
            "e.g. "
            "0x10000\n"
            "  AFL_LLVM_DOCUMENT_IDS: write all edge IDs and the corresponding "
            "functions\n"
            "    into this file (LTO mode)\n"
            "  AFL_LLVM_LTO_DONTWRITEID: don't write the highest ID used to a "
            "global var\n"
            "  AFL_LLVM_LTO_STARTID: from which ID to start counting from for "
            "a "
            "bb\n"
            "  AFL_REAL_LD: use this lld linker instead of the compiled in "
            "path\n"
            "  AFL_LLVM_LTO_SKIPINIT: don't inject initialization code "
            "(used in WAFL mode)\n"
            "If anything fails - be sure to read README.lto.md!\n");
#endif

      SAYF(
          "\nYou can supply --afl-noopt to not instrument, like AFL_NOOPT. "
          "(this is helpful\n"
          "in some build systems if you do not want to instrument "
          "everything.\n");

    }

    SAYF(
        "\nFor any information on the available instrumentations and options "
        "please \n"
        "consult the README.md, especially section 3.1 about instrumenting "
        "targets.\n\n");

#if (LLVM_MAJOR >= 3)
    if (aflcc->have_lto)
      SAYF("afl-cc LTO with ld=%s %s\n", AFL_REAL_LD, AFL_CLANG_FLTO);
    if (aflcc->have_llvm)
      SAYF("afl-cc LLVM version %d using the binary path \"%s\".\n", LLVM_MAJOR,
           LLVM_BINDIR);
#endif

#ifdef USEMMAP
  #if !defined(__HAIKU__)
    SAYF("Compiled with shm_open support.\n");
  #else
    SAYF("Compiled with shm_open support (adds -lrt when linking).\n");
  #endif
#else
    SAYF("Compiled with shmat support.\n");
#endif
    SAYF("\n");

    SAYF(
        "Do not be overwhelmed :) afl-cc uses good defaults if no options are "
        "selected.\n"
        "Read the documentation for FEATURES though, all are good but few are "
        "defaults.\n"
        "Recommended is afl-clang-lto with AFL_LLVM_CMPLOG or afl-clang-fast "
        "with\n"
        "AFL_LLVM_CMPLOG and "
        "AFL_LLVM_DICT2FILE+AFL_LLVM_DICT2FILE_NO_MAIN.\n\n");

    if (LLVM_MAJOR < 13) {

      SAYF(
          "Warning: It is highly recommended to use at least LLVM version 13 "
          "(or better, higher) rather than %d!\n\n",
          LLVM_MAJOR);

    }

    exit(1);

  }

}

static void process_params(u32 argc, char **argv) {

  if (cc_par_cnt + argc >= MAX_PARAMS_NUM) {

    FATAL("Too many command line parameters, please increase MAX_PARAMS_NUM.");

  }

  // reset
  have_instr_list = 0;
  have_c = 0;

  if (lto_mode && argc > 1) {

    u32 idx;
    for (idx = 1; idx < argc; idx++) {

      if (!strncasecmp(argv[idx], "-fpic", 5)) { have_pic = 1; }

    }

  }

  // for (u32 x = 0; x < argc; ++x) fprintf(stderr, "[%u] %s\n", x, argv[x]);

  /* Process the argument list. */

  u8 skip_next = 0;
  while (--argc) {

    u8 *cur = *(++argv);

    if (skip_next) {

      skip_next = 0;
      continue;

    }

    if (cur[0] != '-') { non_dash = 1; }
    if (!strncmp(cur, "--afl", 5)) continue;
    if (!strncmp(cur, "-fno-unroll", 11)) continue;

    if (compiler_mode == GCC_PLUGIN && !strcmp(cur, "-pipe")) { continue; }

    if ((compiler_mode == GCC || compiler_mode == GCC_PLUGIN) &&
        !strncmp(cur, "-stdlib=", 8)) {

      if (!be_quiet) { WARNF("Found '%s' - stripping!", cur); }
      continue;

    }

    if (!strncmp(cur, "-fsanitize-coverage-", 20) && strstr(cur, "list=")) {

      have_instr_list = 1;

    }

    if (!strncmp(cur, "-fsanitize=", strlen("-fsanitize=")) &&
        strchr(cur, ',')) {

      parse_fsanitize(cur);
      if (!cur || strlen(cur) <= strlen("-fsanitize=")) { continue; }

    } else if ((!strncmp(cur, "-fsanitize=fuzzer-",

                         strlen("-fsanitize=fuzzer-")) ||
                !strncmp(cur, "-fsanitize-coverage",
                         strlen("-fsanitize-coverage"))) &&
               (strncmp(cur, "sanitize-coverage-allow",
                        strlen("sanitize-coverage-allow")) &&
                strncmp(cur, "sanitize-coverage-deny",
                        strlen("sanitize-coverage-deny")) &&
                instrument_mode != INSTRUMENT_LLVMNATIVE)) {

      if (!be_quiet) { WARNF("Found '%s' - stripping!", cur); }
      continue;

    }

    if (need_aflpplib || !strcmp(cur, "-fsanitize=fuzzer")) {

      u8 *afllib = find_object("libAFLDriver.a", argv[0]);

      if (!be_quiet) {

        OKF("Found '-fsanitize=fuzzer', replacing with libAFLDriver.a");

      }

      if (!afllib) {

        if (!be_quiet) {

          WARNF(
              "Cannot find 'libAFLDriver.a' to replace '-fsanitize=fuzzer' in "
              "the flags - this will fail!");

        }

      } else {

        cc_params[cc_par_cnt++] = afllib;

#ifdef __APPLE__
        cc_params[cc_par_cnt++] = "-undefined";
        cc_params[cc_par_cnt++] = "dynamic_lookup";
#endif

      }

      if (need_aflpplib) {

        need_aflpplib = 0;

      } else {

        continue;

      }

    }

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
      asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-x")) x_set = 1;
    if (!strcmp(cur, "-E")) preprocessor_only = 1;
    if (!strcmp(cur, "--target=wasm32-wasi")) passthrough = 1;
    if (!strcmp(cur, "-c")) have_c = 1;

    if (!strncmp(cur, "-O", 2)) have_o = 1;
    if (!strncmp(cur, "-funroll-loop", 13)) have_unroll = 1;

    if (*cur == '@') {

      // response file support.
      // we have two choices - move everything to the command line or
      // rewrite the response files to temporary files and delete them
      // afterwards. We choose the first for easiness.
      // We do *not* support quotes in the rsp files to cope with spaces in
      // filenames etc! If you need that then send a patch!
      u8 *filename = cur + 1;
      if (debug) { DEBUGF("response file=%s\n", filename); }
      FILE       *f = fopen(filename, "r");
      struct stat st;

      // Check not found or empty? let the compiler complain if so.
      if (!f || fstat(fileno(f), &st) < 0 || st.st_size < 1) {

        cc_params[cc_par_cnt++] = cur;
        continue;

      }

      u8    *tmpbuf = malloc(st.st_size + 2), *ptr;
      char **args = malloc(sizeof(char *) * (st.st_size >> 1));
      int    count = 1, cont = 0, cont_act = 0;

      while (fgets(tmpbuf, st.st_size + 1, f)) {

        ptr = tmpbuf;
        // fprintf(stderr, "1: %s\n", ptr);
        //  no leading whitespace
        while (isspace(*ptr)) {

          ++ptr;
          cont_act = 0;

        }

        // no comments, no empty lines
        if (*ptr == '#' || *ptr == '\n' || !*ptr) { continue; }
        // remove LF
        if (ptr[strlen(ptr) - 1] == '\n') { ptr[strlen(ptr) - 1] = 0; }
        // remove CR
        if (*ptr && ptr[strlen(ptr) - 1] == '\r') { ptr[strlen(ptr) - 1] = 0; }
        // handle \ at end of line
        if (*ptr && ptr[strlen(ptr) - 1] == '\\') {

          cont = 1;
          ptr[strlen(ptr) - 1] = 0;

        }

        // fprintf(stderr, "2: %s\n", ptr);

        // remove whitespace at end
        while (*ptr && isspace(ptr[strlen(ptr) - 1])) {

          ptr[strlen(ptr) - 1] = 0;
          cont = 0;

        }

        // fprintf(stderr, "3: %s\n", ptr);
        if (*ptr) {

          do {

            u8 *value = ptr;
            while (*ptr && !isspace(*ptr)) {

              ++ptr;

            }

            while (*ptr && isspace(*ptr)) {

              *ptr++ = 0;

            }

            if (cont_act) {

              u32 len = strlen(args[count - 1]) + strlen(value) + 1;
              u8 *tmp = malloc(len);
              snprintf(tmp, len, "%s%s", args[count - 1], value);
              free(args[count - 1]);
              args[count - 1] = tmp;
              cont_act = 0;

            } else {

              args[count++] = strdup(value);

            }

          } while (*ptr);

        }

        if (cont) {

          cont_act = 1;
          cont = 0;

        }

      }

      if (count) { process_params(count, args); }

      // we cannot free args[]
      free(tmpbuf);

      continue;

    }

    cc_params[cc_par_cnt++] = cur;

  }

}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(aflcc_state_t *aflcc, u32 argc, char **argv,
                        char **envp) {

  add_real_argv0(aflcc);

  for (u32 c = 1; c < argc; ++c) {

    if (!strcmp(argv[c], "-c")) have_c = 1;
    if (!strncmp(argv[c], "-fsanitize-coverage-", 20) &&
        strstr(argv[c], "list=")) {

      have_instr_list = 1;

    }

  }

  if (lto_mode) {

    if (lto_flag[0] != '-')
      FATAL(
          "Using afl-clang-lto is not possible because Makefile magic did not "
          "identify the correct -flto flag");
    else
      compiler_mode = LTO;

  }

  if (plusplus_mode) {

    u8 *alt_cxx = getenv("AFL_CXX");

    if (!alt_cxx) {

      if (compiler_mode >= GCC_PLUGIN) {

        if (compiler_mode == GCC) {

          alt_cxx = clang_mode ? "clang++" : "g++";

        } else if (compiler_mode == CLANG) {

          alt_cxx = "clang++";

        } else {

          alt_cxx = "g++";

        }

      } else {

        if (USE_BINDIR)
          snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang++",
                   LLVM_BINDIR);
        else
          snprintf(llvm_fullpath, sizeof(llvm_fullpath), CLANGPP_BIN);
        alt_cxx = llvm_fullpath;

      }

    }

    cc_params[0] = alt_cxx;

  } else {

    u8 *alt_cc = getenv("AFL_CC");

    if (!alt_cc) {

      if (compiler_mode >= GCC_PLUGIN) {

        if (compiler_mode == GCC) {

          alt_cc = clang_mode ? "clang" : "gcc";

        } else if (compiler_mode == CLANG) {

          alt_cc = "clang";

        } else {

          alt_cc = "gcc";

        }

      } else {

        if (USE_BINDIR)
          snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang",
                   LLVM_BINDIR);
        else
          snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s", CLANG_BIN);
        alt_cc = llvm_fullpath;

      }

    }

    cc_params[0] = alt_cc;

  }

  if (compiler_mode == GCC || compiler_mode == CLANG) {

    cc_params[cc_par_cnt++] = "-B";
    cc_params[cc_par_cnt++] = obj_path;

    if (clang_mode || compiler_mode == CLANG) {

      cc_params[cc_par_cnt++] = "-no-integrated-as";

    }

  }

  if (compiler_mode == GCC_PLUGIN) {

    char *fplugin_arg;

    if (cmplog_mode) {

      fplugin_arg =
          alloc_printf("-fplugin=%s/afl-gcc-cmplog-pass.so", obj_path);
      cc_params[cc_par_cnt++] = fplugin_arg;
      fplugin_arg =
          alloc_printf("-fplugin=%s/afl-gcc-cmptrs-pass.so", obj_path);
      cc_params[cc_par_cnt++] = fplugin_arg;

    }

    fplugin_arg = alloc_printf("-fplugin=%s/afl-gcc-pass.so", obj_path);
    cc_params[cc_par_cnt++] = fplugin_arg;
    cc_params[cc_par_cnt++] = "-fno-if-conversion";
    cc_params[cc_par_cnt++] = "-fno-if-conversion2";

  }

  if (compiler_mode == LLVM || compiler_mode == LTO) {

    cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";

    if (lto_mode && have_instr_env) {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] = alloc_printf(
          "-fpass-plugin=%s/afl-llvm-lto-instrumentlist.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/afl-llvm-lto-instrumentlist.so", obj_path);
#endif

    }

    if (getenv("AFL_LLVM_DICT2FILE")) {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/afl-llvm-dict2file.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/afl-llvm-dict2file.so", obj_path);
#endif

    }

    // laf
    if (getenv("LAF_SPLIT_SWITCHES") || getenv("AFL_LLVM_LAF_SPLIT_SWITCHES")) {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/split-switches-pass.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/split-switches-pass.so", obj_path);
#endif

    }

    if (getenv("LAF_TRANSFORM_COMPARES") ||
        getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES")) {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/compare-transform-pass.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/compare-transform-pass.so", obj_path);
#endif

    }

    if (getenv("LAF_SPLIT_COMPARES") || getenv("AFL_LLVM_LAF_SPLIT_COMPARES") ||
        getenv("AFL_LLVM_LAF_SPLIT_FLOATS")) {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/split-compares-pass.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/split-compares-pass.so", obj_path);
#endif

    }

    // /laf

    if (cmplog_mode) {

      cc_params[cc_par_cnt++] = "-fno-inline";

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/cmplog-switches-pass.so", obj_path);
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/split-switches-pass.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/cmplog-switches-pass.so", obj_path);

      // reuse split switches from laf
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/split-switches-pass.so", obj_path);
#endif

    }

    // #if LLVM_MAJOR >= 13
    //     // Use the old pass manager in LLVM 14 which the AFL++ passes still
    //     use. cc_params[cc_par_cnt++] = "-flegacy-pass-manager";
    // #endif

    if (lto_mode && !have_c) {

      add_lto_linker(aflcc);
      add_lto_passes(aflcc);

    } else {

      if (instrument_mode == INSTRUMENT_PCGUARD) {

#if LLVM_MAJOR >= 13
  #if defined __ANDROID__ || ANDROID
        cc_params[cc_par_cnt++] = "-fsanitize-coverage=trace-pc-guard";
        instrument_mode = INSTRUMENT_LLVMNATIVE;
  #else
        if (have_instr_list) {

          if (!be_quiet)
            SAYF(
                "Using unoptimized trace-pc-guard, due usage of "
                "-fsanitize-coverage-allow/denylist, you can use "
                "AFL_LLVM_ALLOWLIST/AFL_LLMV_DENYLIST instead.\n");
          cc_params[cc_par_cnt++] = "-fsanitize-coverage=trace-pc-guard";
          instrument_mode = INSTRUMENT_LLVMNATIVE;

        } else {

    #if LLVM_MAJOR >= 13                            /* use new pass manager */
      #if LLVM_MAJOR < 16
          cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
      #endif
          cc_params[cc_par_cnt++] = alloc_printf(
              "-fpass-plugin=%s/SanitizerCoveragePCGUARD.so", obj_path);
    #else
          cc_params[cc_par_cnt++] = "-Xclang";
          cc_params[cc_par_cnt++] = "-load";
          cc_params[cc_par_cnt++] = "-Xclang";
          cc_params[cc_par_cnt++] =
              alloc_printf("%s/SanitizerCoveragePCGUARD.so", obj_path);
    #endif

        }

  #endif
#else
  #if LLVM_MAJOR >= 4
        if (!be_quiet)
          SAYF(
              "Using unoptimized trace-pc-guard, upgrade to LLVM 13+ for "
              "enhanced version.\n");
        cc_params[cc_par_cnt++] = "-fsanitize-coverage=trace-pc-guard";
        instrument_mode = INSTRUMENT_LLVMNATIVE;
  #else
        FATAL("pcguard instrumentation requires LLVM 4.0.1+");
  #endif
#endif

      } else if (instrument_mode == INSTRUMENT_LLVMNATIVE) {

#if LLVM_MAJOR >= 4
        if (instrument_opt_mode & INSTRUMENT_OPT_CODECOV) {

  #if LLVM_MAJOR >= 6
          cc_params[cc_par_cnt++] =
              "-fsanitize-coverage=trace-pc-guard,bb,no-prune,pc-table";
  #else
          FATAL("pcguard instrumentation with pc-table requires LLVM 6.0.1+");
  #endif

        } else {

          cc_params[cc_par_cnt++] = "-fsanitize-coverage=trace-pc-guard";

        }

#else
        FATAL("pcguard instrumentation requires LLVM 4.0.1+");
#endif

      } else {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
  #if LLVM_MAJOR < 16
        cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
        cc_params[cc_par_cnt++] =
            alloc_printf("-fpass-plugin=%s/afl-llvm-pass.so", obj_path);
#else

        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] = "-load";
        cc_params[cc_par_cnt++] = "-Xclang";
        cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-pass.so", obj_path);
#endif

      }

    }

    if (cmplog_mode) {

#if LLVM_MAJOR >= 11
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] = alloc_printf(
          "-fpass-plugin=%s/cmplog-instructions-pass.so", obj_path);
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/cmplog-routines-pass.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/cmplog-instructions-pass.so", obj_path);

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/cmplog-routines-pass.so", obj_path);
#endif

    }

    if (getenv("AFL_LLVM_INJECTIONS_ALL") ||
        getenv("AFL_LLVM_INJECTIONS_SQL") ||
        getenv("AFL_LLVM_INJECTIONS_LDAP") ||
        getenv("AFL_LLVM_INJECTIONS_XSS")) {

#if LLVM_MAJOR >= 11
  #if LLVM_MAJOR < 16
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
  #endif
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/injection-pass.so", obj_path);
#else
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = alloc_printf("%s/injection-pass.so", obj_path);
#endif

    }

    // cc_params[cc_par_cnt++] = "-Qunused-arguments";

  }

  /* Inspect the command line parameters. */

  process_params(argc, argv);

  if (!have_pic) {

    cc_params[cc_par_cnt++] = "-fPIC";
    have_pic = 1;

  }

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set) cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2";

  }

  if (!asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      if (getenv("AFL_USE_MSAN")) FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("ASAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=address";

    } else if (getenv("AFL_USE_MSAN")) {

      if (getenv("AFL_USE_ASAN")) FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("MSAN and AFL_HARDEN are mutually exclusive");

      cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
      cc_params[cc_par_cnt++] = "-fsanitize=memory";

    }

  }

  if (getenv("AFL_USE_UBSAN")) {

    cc_params[cc_par_cnt++] = "-fsanitize=undefined";
    cc_params[cc_par_cnt++] = "-fsanitize-undefined-trap-on-error";
    cc_params[cc_par_cnt++] = "-fno-sanitize-recover=all";
    cc_params[cc_par_cnt++] = "-fno-omit-frame-pointer";

  }

  if (getenv("AFL_USE_TSAN")) {

    cc_params[cc_par_cnt++] = "-fsanitize=thread";
    cc_params[cc_par_cnt++] = "-fno-omit-frame-pointer";

  }

  if (getenv("AFL_USE_LSAN")) {

    cc_params[cc_par_cnt++] = "-fsanitize=leak";
    cc_params[cc_par_cnt++] = "-includesanitizer/lsan_interface.h";
    cc_params[cc_par_cnt++] =
        "-D__AFL_LEAK_CHECK()={if(__lsan_do_recoverable_leak_check() > 0) "
        "_exit(23); }";
    cc_params[cc_par_cnt++] = "-D__AFL_LSAN_OFF()=__lsan_disable();";
    cc_params[cc_par_cnt++] = "-D__AFL_LSAN_ON()=__lsan_enable();";

  }

  if (getenv("AFL_USE_CFISAN")) {

    if (compiler_mode == GCC_PLUGIN || compiler_mode == GCC) {

      cc_params[cc_par_cnt++] = "-fcf-protection=full";

    } else {

      if (!lto_mode) {

        uint32_t i = 0, found = 0;
        while (envp[i] != NULL && !found)
          if (strncmp("-flto", envp[i++], 5) == 0) found = 1;
        if (!found) cc_params[cc_par_cnt++] = "-flto";

      }

      cc_params[cc_par_cnt++] = "-fsanitize=cfi";
      cc_params[cc_par_cnt++] = "-fvisibility=hidden";

    }

  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    if (!have_o) cc_params[cc_par_cnt++] = "-O3";
    if (!have_unroll) cc_params[cc_par_cnt++] = "-funroll-loops";
    // if (strlen(march_opt) > 1 && march_opt[0] == '-')
    //  cc_params[cc_par_cnt++] = march_opt;

  }

  if (getenv("AFL_NO_BUILTIN") || getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES") ||
      getenv("LAF_TRANSFORM_COMPARES") || getenv("AFL_LLVM_LAF_ALL") ||
      lto_mode) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-bcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }

  add_defs_common(aflcc);
  add_defs_selective_instr(aflcc);
  add_defs_persistent_mode(aflcc);

  if (x_set) {

    cc_params[cc_par_cnt++] = "-x";
    cc_params[cc_par_cnt++] = "none";

  }

  // prevent unnecessary build errors
  if (compiler_mode != GCC_PLUGIN && compiler_mode != GCC) {

    cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";

  }

  add_runtime(aflcc);

  insert_param(aflcc, NULL);

}

/* Main entry point */

int main(int argc, char **argv, char **envp) {

  aflcc_state_t *aflcc = malloc(sizeof(aflcc_state_t));
  aflcc_state_init(aflcc, (u8 *)argv[0]);

  check_environment_vars(envp);

  find_built_deps(aflcc);

  compiler_mode_by_callname(aflcc);
  compiler_mode_by_environ(aflcc);
  compiler_mode_by_cmdline(aflcc, argc, argv);

  instrument_mode_by_environ(aflcc);

  mode_final_checkout(aflcc, argc, argv);

  maybe_usage(aflcc, argc, argv);

  mode_notification(aflcc);

  if (aflcc->debug) debugf_args(argc, argv);

  edit_params(aflcc, argc, argv, envp);

  if (aflcc->debug)
    debugf_args((s32)aflcc->cc_par_cnt, (char **)aflcc->cc_params);

  if (aflcc->passthrough) {

    argv[0] = aflcc->cc_params[0];
    execvp(aflcc->cc_params[0], (char **)argv);

  } else {

    execvp(aflcc->cc_params[0], (char **)aflcc->cc_params);

  }

  FATAL("Oops, failed to execute '%s' - check your PATH", aflcc->cc_params[0]);

  return 0;

}

