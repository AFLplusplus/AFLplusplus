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

static u8*  obj_path;                  /* Path to runtime libraries         */
static u8** cc_params;                 /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;            /* Param count, including argv0      */
static u8   llvm_fullpath[PATH_MAX];

/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8* argv0) {

  u8* afl_path = getenv("AFL_PATH");
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

    u8* dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

#ifdef __ANDROID__
    tmp = alloc_printf("%s/afl-llvm-rt.so", afl_path);
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
      "Unable to find 'afl-llvm-rt.o' or 'afl-llvm-pass.so.cc'. Please set "
      "AFL_PATH");

}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char** argv) {

  u8  fortify_set = 0, asan_set = 0, x_set = 0, maybe_linking = 1, bit_mode = 0;
  u8  has_llvm_config = 0;
  u8* name;

  cc_params = ck_alloc((argc + 128) * sizeof(u8*));

  name = strrchr(argv[0], '/');
  if (!name)
    name = argv[0];
  else
    ++name;

  has_llvm_config = (strlen(LLVM_BINDIR) > 0);

  if (!strcmp(name, "afl-clang-fast++")) {

    u8* alt_cxx = getenv("AFL_CXX");
    if (has_llvm_config)
      snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang++", LLVM_BINDIR);
    else
      sprintf(llvm_fullpath, "clang++");
    cc_params[0] = alt_cxx ? alt_cxx : (u8*)llvm_fullpath;

  } else {

    u8* alt_cc = getenv("AFL_CC");
    if (has_llvm_config)
      snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang", LLVM_BINDIR);
    else
      sprintf(llvm_fullpath, "clang");
    cc_params[0] = alt_cc ? alt_cc : (u8*)llvm_fullpath;

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

#ifdef USE_TRACE_PC
  cc_params[cc_par_cnt++] =
      "-fsanitize-coverage=trace-pc-guard";  // edge coverage by default
  // cc_params[cc_par_cnt++] = "-mllvm";
  // cc_params[cc_par_cnt++] =
  // "-fsanitize-coverage=trace-cmp,trace-div,trace-gep";
  // cc_params[cc_par_cnt++] = "-sanitizer-coverage-block-threshold=0";
#else
  cc_params[cc_par_cnt++] = "-Xclang";
  cc_params[cc_par_cnt++] = "-load";
  cc_params[cc_par_cnt++] = "-Xclang";
  if (getenv("AFL_LLVM_INSTRIM") != NULL || getenv("INSTRIM_LIB") != NULL)
    cc_params[cc_par_cnt++] = alloc_printf("%s/libLLVMInsTrim.so", obj_path);
  else
    cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-pass.so", obj_path);
#endif                                                     /* ^USE_TRACE_PC */

  cc_params[cc_par_cnt++] = "-Qunused-arguments";

  /* Detect stray -v calls from ./configure scripts. */

  if (argc == 1 && !strcmp(argv[1], "-v")) maybe_linking = 0;

  while (--argc) {

    u8* cur = *(++argv);

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

#ifdef USE_TRACE_PC

  if (getenv("AFL_INST_RATIO"))
    FATAL("AFL_INST_RATIO not available at compile time with 'trace-pc'.");

#endif                                                      /* USE_TRACE_PC */

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

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

  if (maybe_linking) {

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

  }

  cc_params[cc_par_cnt] = NULL;

}

/* Main entry point */

int main(int argc, char** argv) {

  if (argc < 2 || strcmp(argv[1], "-h") == 0) {

#ifdef USE_TRACE_PC
    printf(
        cCYA
        "afl-clang-fast" VERSION cRST
        " [tpcg] by <lszekeres@google.com>\n"
#else
    printf(
        cCYA
        "afl-clang-fast" VERSION cRST
        " by <lszekeres@google.com>\n"
#endif                                                     /* ^USE_TRACE_PC */
        "\n"
        "afl-clang-fast[++] [options]\n"
        "\n"
        "This is a helper application for afl-fuzz. It serves as a drop-in "
        "replacement\n"
        "for clang, letting you recompile third-party code with the required "
        "runtime\n"
        "instrumentation. A common use pattern would be one of the "
        "following:\n\n"

        "  CC=%s/afl-clang-fast ./configure\n"
        "  CXX=%s/afl-clang-fast++ ./configure\n\n"

        "In contrast to the traditional afl-clang tool, this version is "
        "implemented as\n"
        "an LLVM pass and tends to offer improved performance with slow "
        "programs.\n\n"

        "You can specify custom next-stage toolchain via AFL_CC and AFL_CXX. "
        "Setting\n"
        "AFL_HARDEN enables hardening optimizations in the compiled code.\n\n"
        "afl-clang-fast was built for llvm %s with the llvm binary path of "
        "\"%s\".\n\n",
        BIN_PATH, BIN_PATH, LLVM_VERSION, LLVM_BINDIR);

    exit(1);

  } else if (isatty(2) && !getenv("AFL_QUIET")) {

#ifdef USE_TRACE_PC
    SAYF(cCYA "afl-clang-fast" VERSION cRST
              " [tpcg] by <lszekeres@google.com>\n");
#else
    SAYF(cCYA "afl-clang-fast" VERSION cRST " by <lszekeres@google.com>\n");
#endif                                                     /* ^USE_TRACE_PC */

  }

#ifndef __ANDROID__
  find_obj(argv[0]);
#endif

  edit_params(argc, argv);

  /*
    int i = 0;
    printf("EXEC:");
    while (cc_params[i] != NULL)
      printf(" %s", cc_params[i++]);
    printf("\n");
  */

  execvp(cc_params[0], (char**)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}

