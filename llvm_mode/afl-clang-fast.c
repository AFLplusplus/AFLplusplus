/*
   american fuzzy lop++ - LLVM-mode wrapper for clang
   ------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This program is a drop-in replacement for clang, similar in most respects
   to ../afl-gcc. It tries to figure out compilation mode, adds a bunch
   of flags, and then calls the real compiler.

 */

#define AFL_MAIN

#include "common.h"
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

static u8 * obj_path;                  /* Path to runtime libraries         */
static u8 **cc_params;                 /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;            /* Param count, including argv0      */
static u8   llvm_fullpath[PATH_MAX];
static u8   lto_mode;
static u8 * lto_flag = AFL_CLANG_FLTO;
static u8 * march_opt = CFLAGS_OPT;
static u8   debug;
static u8   cwd[4096];
static u8   cmplog_mode;
u8          use_stdin = 0;                                         /* dummy */
u8          be_quiet = 0;

u8 *getthecwd() {

  static u8 fail[] = "";
  if (getcwd(cwd, sizeof(cwd)) == NULL) return fail;
  return cwd;

}

/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8 *argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

#ifdef __ANDROID__
    tmp = alloc_printf("%s/afl-llvm-rt.so", afl_path);
#else
    tmp = alloc_printf("%s/afl-llvm-rt.o", afl_path);
#endif

    if (!access(tmp, R_OK)) {

      obj_path = afl_path;
      ck_free(tmp);
      return;

    }

    ck_free(tmp);

  }

  slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

#ifdef __ANDROID__
    tmp = alloc_printf("%s/afl-llvm-rt.so", dir);
#else
    tmp = alloc_printf("%s/afl-llvm-rt.o", dir);
#endif

    if (!access(tmp, R_OK)) {

      obj_path = dir;
      ck_free(tmp);
      return;

    }

    ck_free(tmp);
    ck_free(dir);

  }

#ifdef __ANDROID__
  if (!access(AFL_PATH "/afl-llvm-rt.so", R_OK)) {

#else
  if (!access(AFL_PATH "/afl-llvm-rt.o", R_OK)) {

#endif

    obj_path = AFL_PATH;
    return;

  }

  FATAL(
      "Unable to find 'afl-llvm-rt.o' or 'afl-llvm-pass.so'. Please set "
      "AFL_PATH");

}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char **argv, char **envp) {

  u8  fortify_set = 0, asan_set = 0, x_set = 0, maybe_linking = 1, bit_mode = 0;
  u8  has_llvm_config = 0;
  u8 *name;

  cc_params = ck_alloc((argc + 128) * sizeof(u8 *));

  name = strrchr(argv[0], '/');
  if (!name)
    name = argv[0];
  else
    ++name;

  has_llvm_config = (strlen(LLVM_BINDIR) > 0);

  if (!strncmp(name, "afl-clang-lto", strlen("afl-clang-lto"))) {

#ifdef USE_TRACE_PC
    FATAL("afl-clang-lto does not work with TRACE_PC mode");
#endif
    if (lto_flag[0] != '-')
      FATAL(
          "Using afl-clang-lto is not possible because Makefile magic did not "
          "identify the correct -flto flag");
    if (getenv("AFL_LLVM_INSTRIM") != NULL)
      FATAL("afl-clang-lto does not work with InsTrim mode");
    if (getenv("AFL_LLVM_NGRAM_SIZE") != NULL)
      FATAL("afl-clang-lto does not work with ngram coverage mode");
    lto_mode = 1;

  }

  if (getenv("AFL_LLVM_NGRAM_SIZE") != NULL &&
      getenv("AFL_LLVM_INSTRIM") != NULL)
    FATAL("AFL_LLVM_NGRAM_SIZE and AFL_LLVM_INSTRIM cannot be used together");

  if (!strcmp(name, "afl-clang-fast++") || !strcmp(name, "afl-clang-lto++")) {

    u8 *alt_cxx = getenv("AFL_CXX");
    if (has_llvm_config)
      snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang++", LLVM_BINDIR);
    else
      sprintf(llvm_fullpath, "clang++");
    cc_params[0] = alt_cxx ? alt_cxx : (u8 *)llvm_fullpath;

  } else {

    u8 *alt_cc = getenv("AFL_CC");
    if (has_llvm_config)
      snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang", LLVM_BINDIR);
    else
      sprintf(llvm_fullpath, "clang");
    cc_params[0] = alt_cc ? alt_cc : (u8 *)llvm_fullpath;

  }

  /* There are three ways to compile with afl-clang-fast. In the traditional
     mode, we use afl-llvm-pass.so, then there is libLLVMInsTrim.so which is
     much faster but has less coverage. Finally there is the experimental
     'trace-pc-guard' mode, we use native LLVM instrumentation callbacks
     instead. For trace-pc-guard see:
     http://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
   */

  // laf
  if (getenv("LAF_SPLIT_SWITCHES") || getenv("AFL_LLVM_LAF_SPLIT_SWITCHES")) {

    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/split-switches-pass.so", obj_path);

  }

  if (getenv("LAF_TRANSFORM_COMPARES") ||
      getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES")) {

    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/compare-transform-pass.so", obj_path);

  }

  if (getenv("LAF_SPLIT_COMPARES") || getenv("AFL_LLVM_LAF_SPLIT_COMPARES")) {

    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/split-compares-pass.so", obj_path);

  }

  // /laf

  unsetenv("AFL_LD");
  unsetenv("AFL_LD_CALLER");
  if (cmplog_mode) {

    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/cmplog-routines-pass.so", obj_path);

    // reuse split switches from laf
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/split-switches-pass.so", obj_path);

    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] =
        alloc_printf("%s/cmplog-instructions-pass.so", obj_path);

    cc_params[cc_par_cnt++] = "-fno-inline";

  }

#ifdef USE_TRACE_PC

  cc_params[cc_par_cnt++] =
      "-fsanitize-coverage=trace-pc-guard";  // edge coverage by default
  // cc_params[cc_par_cnt++] = "-mllvm";
  // cc_params[cc_par_cnt++] =
  // "-fsanitize-coverage=trace-cmp,trace-div,trace-gep";
  // cc_params[cc_par_cnt++] = "-sanitizer-coverage-block-threshold=0";
#else

  if (lto_mode) {

    char *old_path = getenv("PATH");
    char *new_path = alloc_printf("%s:%s", AFL_PATH, old_path);

    setenv("PATH", new_path, 1);
    setenv("AFL_LD", "1", 1);

    if (getenv("AFL_LLVM_WHITELIST") != NULL) {

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/afl-llvm-lto-whitelist.so", obj_path);

    }

#ifdef AFL_CLANG_FUSELD
    cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s/afl-ld", AFL_PATH);
#endif

    cc_params[cc_par_cnt++] = "-B";
    cc_params[cc_par_cnt++] = AFL_PATH;

    cc_params[cc_par_cnt++] = lto_flag;

  } else

      if (getenv("USE_TRACE_PC") || getenv("AFL_USE_TRACE_PC") ||
          getenv("AFL_LLVM_USE_TRACE_PC") || getenv("AFL_TRACE_PC")) {

    cc_params[cc_par_cnt++] =
        "-fsanitize-coverage=trace-pc-guard";  // edge coverage by default

  } else {

    cc_params[cc_par_cnt++] = "-Xclang";
    cc_params[cc_par_cnt++] = "-load";
    cc_params[cc_par_cnt++] = "-Xclang";
    if (getenv("AFL_LLVM_INSTRIM") != NULL || getenv("INSTRIM_LIB") != NULL)
      cc_params[cc_par_cnt++] = alloc_printf("%s/libLLVMInsTrim.so", obj_path);
    else
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-pass.so", obj_path);

  }

#endif                                                     /* ^USE_TRACE_PC */

  cc_params[cc_par_cnt++] = "-Qunused-arguments";

  /* Detect stray -v calls from ./configure scripts. */

  if (argc == 1 && !strcmp(argv[1], "-v")) maybe_linking = 0;

  while (--argc) {

    u8 *cur = *(++argv);

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
      maybe_linking = 0;

    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
      asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-shared")) maybe_linking = 0;

    if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
      continue;

    cc_params[cc_par_cnt++] = cur;

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

  }

  if (getenv("AFL_USE_CFISAN")) {

    if (!lto_mode) { 
    
      uint32_t i = 0, found = 0;
      while (envp[i] != NULL && !found)
        if (strncmp("-flto", envp[i++], 5) == 0)
          found = 1;
      if (!found) cc_params[cc_par_cnt++] = "-flto";
      
    }
    cc_params[cc_par_cnt++] = "-fsanitize=cfi";
    cc_params[cc_par_cnt++] = "-fvisibility=hidden";

  }

#ifdef USE_TRACE_PC

  if (getenv("USE_TRACE_PC") || getenv("AFL_USE_TRACE_PC") ||
      getenv("AFL_LLVM_USE_TRACE_PC") || getenv("AFL_TRACE_PC"))
    if (getenv("AFL_INST_RATIO"))
      FATAL("AFL_INST_RATIO not available at compile time with 'trace-pc'.");

#endif                                                      /* USE_TRACE_PC */

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";
    if (strlen(march_opt) > 1 && march_opt[0] == '-')
      cc_params[cc_par_cnt++] = march_opt;

  }

  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-bcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }

#ifdef USEMMAP
  cc_params[cc_par_cnt++] = "-lrt";
#endif

  cc_params[cc_par_cnt++] = "-D__AFL_HAVE_MANUAL_CONTROL=1";
  cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
  cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

  /* When the user tries to use persistent or deferred forkserver modes by
     appending a single line to the program, we want to reliably inject a
     signature into the binary (to be picked up by afl-fuzz) and we want
     to call a function from the runtime .o file. This is unnecessarily
     painful for three reasons:

     1) We need to convince the compiler not to optimize out the signature.
        This is done with __attribute__((used)).

     2) We need to convince the linker, when called with -Wl,--gc-sections,
        not to do the same. This is done by forcing an assignment to a
        'volatile' pointer.

     3) We need to declare __afl_persistent_loop() in the global namespace,
        but doing this within a method in a class is hard - :: and extern "C"
        are forbidden and __attribute__((alias(...))) doesn't work. Hence the
        __asm__ aliasing trick.

   */

  cc_params[cc_par_cnt++] =
      "-D__AFL_LOOP(_A)="
      "({ static volatile char *_B __attribute__((used)); "
      " _B = (char*)\"" PERSIST_SIG
      "\"; "
#ifdef __APPLE__
      "__attribute__((visibility(\"default\"))) "
      "int _L(unsigned int) __asm__(\"___afl_persistent_loop\"); "
#else
      "__attribute__((visibility(\"default\"))) "
      "int _L(unsigned int) __asm__(\"__afl_persistent_loop\"); "
#endif                                                        /* ^__APPLE__ */
      "_L(_A); })";

  cc_params[cc_par_cnt++] =
      "-D__AFL_INIT()="
      "do { static volatile char *_A __attribute__((used)); "
      " _A = (char*)\"" DEFER_SIG
      "\"; "
#ifdef __APPLE__
      "__attribute__((visibility(\"default\"))) "
      "void _I(void) __asm__(\"___afl_manual_init\"); "
#else
      "__attribute__((visibility(\"default\"))) "
      "void _I(void) __asm__(\"__afl_manual_init\"); "
#endif                                                        /* ^__APPLE__ */
      "_I(); } while (0)";

  // if (maybe_linking) {

  if (x_set) {

    cc_params[cc_par_cnt++] = "-x";
    cc_params[cc_par_cnt++] = "none";

  }

#ifndef __ANDROID__
  switch (bit_mode) {

    case 0:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt.o", obj_path);
      break;

    case 32:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt-32.o", obj_path);

      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m32 is not supported by your compiler");

      break;

    case 64:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt-64.o", obj_path);

      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m64 is not supported by your compiler");

      break;

  }

#endif

  // }

  cc_params[cc_par_cnt] = NULL;

}

/* Main entry point */

int main(int argc, char **argv, char **envp) {

  int   i;
  char *callname = "afl-clang-fast";

  if (getenv("AFL_DEBUG")) {

    debug = 1;
    if (strcmp(getenv("AFL_DEBUG"), "0") == 0) unsetenv("AFL_DEBUG");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  if (strstr(argv[0], "afl-clang-lto") != NULL) callname = "afl-clang-lto";

  if (argc < 2 || strcmp(argv[1], "-h") == 0) {

#ifdef USE_TRACE_PC
    printf(cCYA "afl-clang-fast" VERSION cRST
                " [tpcg] by <lszekeres@google.com>\n")
#else
    if (strstr(argv[0], "afl-clang-lto") == NULL)

      printf("afl-clang-fast" VERSION " by <lszekeres@google.com>\n");

    else {

      printf("afl-clang-lto" VERSION
             "  by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

    }

#endif                                                     /* ^USE_TRACE_PC */

        SAYF(
            "\n"
            "%s[++] [options]\n"
            "\n"
            "This is a helper application for afl-fuzz. It serves as a drop-in "
            "replacement\n"
            "for clang, letting you recompile third-party code with the "
            "required "
            "runtime\n"
            "instrumentation. A common use pattern would be one of the "
            "following:\n\n"

            "  CC=%s/afl-clang-fast ./configure\n"
            "  CXX=%s/afl-clang-fast++ ./configure\n\n"

            "In contrast to the traditional afl-clang tool, this version is "
            "implemented as\n"
            "an LLVM pass and tends to offer improved performance with slow "
            "programs.\n\n"

            "Environment variables used:\n"
            "AFL_CC: path to the C compiler to use\n"
            "AFL_CXX: path to the C++ compiler to use\n"
            "AFL_PATH: path to instrumenting pass and runtime "
            "(afl-llvm-rt.*o)\n"
            "AFL_DONT_OPTIMIZE: disable optimization instead of -O3\n"
            "AFL_NO_BUILTIN: compile for use with libtokencap.so\n"
            "AFL_INST_RATIO: percentage of branches to instrument\n"
            "AFL_QUIET: suppress verbose output\n"
            "AFL_DEBUG: enable developer debugging output\n"
            "AFL_HARDEN: adds code hardening to catch memory bugs\n"
            "AFL_USE_ASAN: activate address sanitizer\n"
            "AFL_USE_MSAN: activate memory sanitizer\n"
            "AFL_USE_UBSAN: activate undefined behaviour sanitizer\n"
            "AFL_USE_CFISAN: activate control flow sanitizer\n"
            "AFL_LLVM_WHITELIST: enable whitelisting (selective "
            "instrumentation)\n"
            "AFL_LLVM_NOT_ZERO: use cycling trace counters that skip zero\n"
            "AFL_LLVM_USE_TRACE_PC: use LLVM trace-pc-guard instrumentation\n"
            "AFL_LLVM_LAF_SPLIT_COMPARES: enable cascaded comparisons\n"
            "AFL_LLVM_LAF_SPLIT_SWITCHES: casc. comp. in 'switch'\n"
            "AFL_LLVM_LAF_TRANSFORM_COMPARES: transform library comparison "
            "function calls\n"
            " to cascaded comparisons\n"
            "AFL_LLVM_LAF_SPLIT_FLOATS: transform floating point comp. to "
            "cascaded "
            "comp.\n"
            "AFL_LLVM_LAF_SPLIT_COMPARES_BITW: size limit (default 8)\n",
            callname, BIN_PATH, BIN_PATH);

    SAYF(
        "\nafl-clang-fast specific environment variables:\n"
        "AFL_LLVM_INSTRIM: use light weight instrumentation InsTrim\n"
        "AFL_LLVM_INSTRIM_LOOPHEAD: optimize loop tracing for speed\n"
        "AFL_LLVM_NGRAM_SIZE: use ngram prev_loc coverage\n"
        "AFL_LLVM_CMPLOG: log operands of comparisons (RedQueen mutator)\n");

#ifdef AFL_CLANG_FLTO
    SAYF(
        "\nafl-clang-lto specific environment variables:\n"
        "AFL_LLVM_LTO_STARTID: from which ID to start counting from for a "
        "bb\n"
        "AFL_LLVM_LTO_DONTWRITEID: don't write the highest ID used to a "
        "global var\n"
        "AFL_REAL_LD: use this linker instead of the compiled in path\n"
        "AFL_LD_PASSTHROUGH: do not perform instrumentation (for configure "
        "scripts)\n"
        "\nafl-clang-lto was built with linker target \"%s\" and LTO flags "
        "\"%s\"\n"
        "If anything fails - be sure to read README.lto.md!\n",
        AFL_REAL_LD, AFL_CLANG_FLTO);
#endif

    SAYF(
        "\nafl-clang-fast was built for llvm %s with the llvm binary path "
        "of \"%s\".\n",
        LLVM_VERSION, LLVM_BINDIR);

    SAYF("\n");

    exit(1);

  } else if ((isatty(2) && !be_quiet) ||

             getenv("AFL_DEBUG") != NULL) {

#ifdef USE_TRACE_PC
    SAYF(cCYA "afl-clang-fast" VERSION cRST
              " [tpcg] by <lszekeres@google.com>\n");
#warning \
    "You do not need to specifically compile with USE_TRACE_PC anymore, setting the environment variable AFL_LLVM_USE_TRACE_PC is enough."
#else
    if (strstr(argv[0], "afl-clang-lto") == NULL)

      SAYF(cCYA "afl-clang-fast" VERSION cRST " by <lszekeres@google.com>\n");

    else

      SAYF(cCYA "afl-clang-lto" VERSION cRST
                " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

#endif                                                     /* ^USE_TRACE_PC */

  }

  if (debug) {

    SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
    for (i = 0; i < argc; i++)
      SAYF(" \"%s\"", argv[i]);
    SAYF("\n");

  }

  check_environment_vars(envp);

  cmplog_mode = getenv("AFL_CMPLOG") || getenv("AFL_LLVM_CMPLOG");
  if (!be_quiet && cmplog_mode)
    printf("CmpLog mode by <andreafioraldi@gmail.com>\n");

#ifndef __ANDROID__
  find_obj(argv[0]);
#endif

  edit_params(argc, argv, envp);

  if (debug) {

    SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
    for (i = 0; i < cc_par_cnt; i++)
      SAYF(" \"%s\"", cc_params[i]);
    SAYF("\n");

  }

  execvp(cc_params[0], (char **)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}

