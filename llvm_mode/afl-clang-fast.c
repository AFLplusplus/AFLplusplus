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
#include "llvm-ngram-coverage.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <assert.h>

#include "llvm/Config/llvm-config.h"

static u8 * obj_path;                  /* Path to runtime libraries         */
static u8 **cc_params;                 /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;            /* Param count, including argv0      */
static u8   llvm_fullpath[PATH_MAX];
static u8  instrument_mode, instrument_opt_mode, ngram_size, lto_mode, cpp_mode;
static u8 *lto_flag = AFL_CLANG_FLTO;
static u8  debug;
static u8  cwd[4096];
static u8  cmplog_mode;
u8         use_stdin = 0;                                          /* dummy */
// static u8 *march_opt = CFLAGS_OPT;

enum {

  INSTURMENT_DEFAULT = 0,
  INSTRUMENT_CLASSIC = 1,
  INSTRUMENT_AFL = 1,
  INSTRUMENT_PCGUARD = 2,
  INSTRUMENT_INSTRIM = 3,
  INSTRUMENT_CFG = 3,
  INSTRUMENT_LTO = 4,
  INSTRUMENT_OPT_CTX = 8,
  INSTRUMENT_OPT_NGRAM = 16

};

char instrument_mode_string[18][18] = {

    "DEFAULT", "CLASSIC", "PCGUARD", "CFG", "LTO", "", "",      "", "CTX", "",
    "",        "",        "",        "",    "",    "", "NGRAM", ""

};

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

  u8 fortify_set = 0, asan_set = 0, x_set = 0, bit_mode = 0, shared_linking = 0,
     preprocessor_only = 0;
  u8  have_pic = 0;
  u8 *name;

  cc_params = ck_alloc((argc + 128) * sizeof(u8 *));

  name = strrchr(argv[0], '/');
  if (!name)
    name = argv[0];
  else
    ++name;

  if (lto_mode)
    if (lto_flag[0] != '-')
      FATAL(
          "Using afl-clang-lto is not possible because Makefile magic did not "
          "identify the correct -flto flag");

  if (!strcmp(name, "afl-clang-fast++") || !strcmp(name, "afl-clang-lto++") ||
      !strcmp(name, "afl-clang++")) {

    u8 *alt_cxx = getenv("AFL_CXX");
    if (USE_BINDIR)
      snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang++", LLVM_BINDIR);
    else
      sprintf(llvm_fullpath, CLANGPP_BIN);
    cc_params[0] = alt_cxx && *alt_cxx ? alt_cxx : (u8 *)llvm_fullpath;
    cpp_mode = 1;

  } else if (!strcmp(name, "afl-clang-fast") ||

             !strcmp(name, "afl-clang-lto") || !strcmp(name, "afl-clang")) {

    u8 *alt_cc = getenv("AFL_CC");
    if (USE_BINDIR)
      snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang", LLVM_BINDIR);
    else
      sprintf(llvm_fullpath, CLANG_BIN);
    cc_params[0] = alt_cc && *alt_cc ? alt_cc : (u8 *)llvm_fullpath;

  } else {

    fprintf(stderr, "Name of the binary: %s\n", argv[0]);
    FATAL(
        "Name of the binary is not a known name, expected afl-clang-fast(++) "
        "or afl-clang-lto(++)");

  }

  cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";

  if (lto_mode && cpp_mode)
    cc_params[cc_par_cnt++] = "-lc++";  // needed by fuzzbench, early

  /* There are several ways to compile with afl-clang-fast. In the traditional
     mode, we use afl-llvm-pass.so, then there is libLLVMInsTrim.so which is
     faster and creates less map pollution.
     Then there is the 'trace-pc-guard' mode, we use native LLVM
     instrumentation callbacks instead. For trace-pc-guard see:
     http://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs-with-guards
     The best instrumentatation is with the LTO modes, the classic and
     InsTrimLTO, the latter is faster. The LTO modes are activated by using
     afl-clang-lto(++)
   */

  if (lto_mode) {

    if (getenv("AFL_LLVM_INSTRUMENT_FILE") != NULL ||
        getenv("AFL_LLVM_WHITELIST") || getenv("AFL_LLVM_ALLOWLIST") ||
        getenv("AFL_LLVM_DENYLIST") || getenv("AFL_LLVM_BLOCKLIST")) {

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/afl-llvm-lto-instrumentlist.so", obj_path);

    }

  }

  // laf
  if (getenv("LAF_SPLIT_SWITCHES") || getenv("AFL_LLVM_LAF_SPLIT_SWITCHES")) {

    if (lto_mode) {

      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,-mllvm=-load=%s/split-switches-pass.so", obj_path);

    } else {

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/split-switches-pass.so", obj_path);

    }

  }

  if (getenv("LAF_TRANSFORM_COMPARES") ||
      getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES")) {

    if (lto_mode) {

      cc_params[cc_par_cnt++] = alloc_printf(
          "-Wl,-mllvm=-load=%s/compare-transform-pass.so", obj_path);

    } else {

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/compare-transform-pass.so", obj_path);

    }

  }

  if (getenv("LAF_SPLIT_COMPARES") || getenv("AFL_LLVM_LAF_SPLIT_COMPARES") ||
      getenv("AFL_LLVM_LAF_SPLIT_FLOATS")) {

    if (lto_mode) {

      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,-mllvm=-load=%s/split-compares-pass.so", obj_path);

    } else {

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] =
          alloc_printf("%s/split-compares-pass.so", obj_path);

    }

  }

  // /laf

  unsetenv("AFL_LD");
  unsetenv("AFL_LD_CALLER");
  if (cmplog_mode) {

    if (lto_mode) {

      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,-mllvm=-load=%s/cmplog-routines-pass.so", obj_path);
      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,-mllvm=-load=%s/split-switches-pass.so", obj_path);
      cc_params[cc_par_cnt++] = alloc_printf(
          "-Wl,-mllvm=-load=%s/cmplog-instructions-pass.so", obj_path);

    } else {

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

    }

    cc_params[cc_par_cnt++] = "-fno-inline";

  }

  if (lto_mode) {

#if defined(AFL_CLANG_LDPATH) && LLVM_VERSION_MAJOR >= 12
    u8 *ld_ptr = strrchr(AFL_REAL_LD, '/');
    if (!ld_ptr) ld_ptr = "ld.lld";
    cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s", ld_ptr);
    cc_params[cc_par_cnt++] = alloc_printf("--ld-path=%s", AFL_REAL_LD);
#else
    cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s", AFL_REAL_LD);
#endif

    cc_params[cc_par_cnt++] = "-Wl,--allow-multiple-definition";

    if (instrument_mode == INSTRUMENT_CFG)
      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,-mllvm=-load=%s/SanitizerCoverageLTO.so", obj_path);
    else

      cc_params[cc_par_cnt++] = alloc_printf(
          "-Wl,-mllvm=-load=%s/afl-llvm-lto-instrumentation.so", obj_path);
    cc_params[cc_par_cnt++] = lto_flag;

  } else {

    if (instrument_mode == INSTRUMENT_PCGUARD) {

#if LLVM_VERSION_MAJOR > 4 ||   \
    (LLVM_VERSION_MAJOR == 4 && \
     (LLVM_VERSION_MINOR > 0 || LLVM_VERSION_PATCH >= 1))
      cc_params[cc_par_cnt++] =
          "-fsanitize-coverage=trace-pc-guard";  // edge coverage by default
#else
      FATAL("pcguard instrumentation requires llvm 4.0.1+");
#endif

    } else {

      cc_params[cc_par_cnt++] = "-Xclang";
      cc_params[cc_par_cnt++] = "-load";
      cc_params[cc_par_cnt++] = "-Xclang";
      if (instrument_mode == INSTRUMENT_CFG)
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/libLLVMInsTrim.so", obj_path);
      else
        cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-pass.so", obj_path);

    }

  }

  // cc_params[cc_par_cnt++] = "-Qunused-arguments";

  // in case LLVM is installed not via a package manager or "make install"
  // e.g. compiled download or compiled from github then it's ./lib directory
  // might not be in the search path. Add it if so.
  u8 *libdir = strdup(LLVM_LIBDIR);
  if (cpp_mode && strlen(libdir) && strncmp(libdir, "/usr", 4) &&
      strncmp(libdir, "/lib", 4)) {

    cc_params[cc_par_cnt++] = "-rpath";
    cc_params[cc_par_cnt++] = libdir;

  } else {

    free(libdir);

  }

  u32 idx;
  if (lto_mode && argc > 1) {

    for (idx = 1; idx < argc; idx++) {

      if (!strncasecmp(argv[idx], "-fpic", 5)) have_pic = 1;

    }

    if (!have_pic) cc_params[cc_par_cnt++] = "-fPIC";

  }

  /* Detect stray -v calls from ./configure scripts. */

  while (--argc) {

    u8 *cur = *(++argv);

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strcmp(cur, "-x")) x_set = 1;

    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
      asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
      continue;

    if (lto_mode && !strncmp(cur, "-fuse-ld=", 9)) continue;
    if (lto_mode && !strncmp(cur, "--ld-path=", 10)) continue;

    if (!strcmp(cur, "-E")) preprocessor_only = 1;
    if (!strcmp(cur, "-shared")) shared_linking = 1;

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
        if (strncmp("-flto", envp[i++], 5) == 0) found = 1;
      if (!found) cc_params[cc_par_cnt++] = "-flto";

    }

    cc_params[cc_par_cnt++] = "-fsanitize=cfi";
    cc_params[cc_par_cnt++] = "-fvisibility=hidden";

  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    cc_params[cc_par_cnt++] = "-g";
    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";
    // if (strlen(march_opt) > 1 && march_opt[0] == '-')
    //  cc_params[cc_par_cnt++] = march_opt;

  }

  if (getenv("AFL_NO_BUILTIN") || getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES") ||
      getenv("LAF_TRANSFORM_COMPARES") || lto_mode) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-bcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }

#if defined(USEMMAP) && !defined(__HAIKU__)
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
      "-D__AFL_FUZZ_INIT()="
      "int __afl_sharedmem_fuzzing = 1;"
      "extern unsigned int *__afl_fuzz_len;"
      "extern unsigned char *__afl_fuzz_ptr;"
      "unsigned char __afl_fuzz_alt[1024000];"
      "unsigned char *__afl_fuzz_alt_ptr = __afl_fuzz_alt;";
  cc_params[cc_par_cnt++] =
      "-D__AFL_FUZZ_TESTCASE_BUF=(__afl_fuzz_ptr ? __afl_fuzz_ptr : "
      "__afl_fuzz_alt_ptr)";
  cc_params[cc_par_cnt++] =
      "-D__AFL_FUZZ_TESTCASE_LEN=(__afl_fuzz_ptr ? *__afl_fuzz_len : "
      "(*__afl_fuzz_len = read(0, __afl_fuzz_alt_ptr, 1024000)) == 0xffffffff "
      "? 0 : *__afl_fuzz_len)";

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

  if (x_set) {

    cc_params[cc_par_cnt++] = "-x";
    cc_params[cc_par_cnt++] = "none";

  }

  if (preprocessor_only) {

    /* In the preprocessor_only case (-E), we are not actually compiling at
       all but requesting the compiler to output preprocessed sources only.
       We must not add the runtime in this case because the compiler will
       simply output its binary content back on stdout, breaking any build
       systems that rely on a separate source preprocessing step. */
    cc_params[cc_par_cnt] = NULL;
    return;

  }

#ifndef __ANDROID__
  switch (bit_mode) {

    case 0:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt.o", obj_path);
      if (lto_mode)
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/afl-llvm-rt-lto.o", obj_path);
      break;

    case 32:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt-32.o", obj_path);
      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m32 is not supported by your compiler");
      if (lto_mode) {

        cc_params[cc_par_cnt++] =
            alloc_printf("%s/afl-llvm-rt-lto-32.o", obj_path);
        if (access(cc_params[cc_par_cnt - 1], R_OK))
          FATAL("-m32 is not supported by your compiler");

      }

      break;

    case 64:
      cc_params[cc_par_cnt++] = alloc_printf("%s/afl-llvm-rt-64.o", obj_path);
      if (access(cc_params[cc_par_cnt - 1], R_OK))
        FATAL("-m64 is not supported by your compiler");
      if (lto_mode) {

        cc_params[cc_par_cnt++] =
            alloc_printf("%s/afl-llvm-rt-lto-64.o", obj_path);
        if (access(cc_params[cc_par_cnt - 1], R_OK))
          FATAL("-m64 is not supported by your compiler");

      }

      break;

  }

  if (!shared_linking)
    cc_params[cc_par_cnt++] =
        alloc_printf("-Wl,--dynamic-list=%s/dynamic_list.txt", obj_path);

#endif

  cc_params[cc_par_cnt] = NULL;

}

/* Main entry point */

int main(int argc, char **argv, char **envp) {

  int   i;
  char *callname = "afl-clang-fast", *ptr = NULL;

  if (getenv("AFL_DEBUG")) {

    debug = 1;
    if (strcmp(getenv("AFL_DEBUG"), "0") == 0) unsetenv("AFL_DEBUG");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  if (getenv("USE_TRACE_PC") || getenv("AFL_USE_TRACE_PC") ||
      getenv("AFL_LLVM_USE_TRACE_PC") || getenv("AFL_TRACE_PC")) {

    if (instrument_mode == 0)
      instrument_mode = INSTRUMENT_PCGUARD;
    else if (instrument_mode != INSTRUMENT_PCGUARD)
      FATAL("you can not set AFL_LLVM_INSTRUMENT and AFL_TRACE_PC together");

  }

  if ((getenv("AFL_LLVM_INSTRUMENT_FILE") != NULL ||
       getenv("AFL_LLVM_WHITELIST") || getenv("AFL_LLVM_ALLOWLIST") ||
       getenv("AFL_LLVM_DENYLIST") || getenv("AFL_LLVM_BLOCKLIST")) &&
      getenv("AFL_DONT_OPTIMIZE"))
    WARNF(
        "AFL_LLVM_ALLOWLIST/DENYLIST and AFL_DONT_OPTIMIZE cannot be combined "
        "for file matching, only function matching!");

  if (getenv("AFL_LLVM_INSTRIM") || getenv("INSTRIM") ||
      getenv("INSTRIM_LIB")) {

    if (instrument_mode == 0)
      instrument_mode = INSTRUMENT_CFG;
    else if (instrument_mode != INSTRUMENT_CFG)
      FATAL(
          "you can not set AFL_LLVM_INSTRUMENT and AFL_LLVM_INSTRIM together");

  }

  if (getenv("AFL_LLVM_CTX")) instrument_opt_mode |= INSTRUMENT_OPT_CTX;

  if (getenv("AFL_LLVM_NGRAM_SIZE")) {

    instrument_opt_mode |= INSTRUMENT_OPT_NGRAM;
    ngram_size = atoi(getenv("AFL_LLVM_NGRAM_SIZE"));
    if (ngram_size < 2 || ngram_size > NGRAM_SIZE_MAX)
      FATAL(
          "NGRAM instrumentation mode must be between 2 and NGRAM_SIZE_MAX "
          "(%u)",
          NGRAM_SIZE_MAX);

  }

  if (getenv("AFL_LLVM_INSTRUMENT")) {

    u8 *ptr = strtok(getenv("AFL_LLVM_INSTRUMENT"), ":,;");

    while (ptr) {

      if (strncasecmp(ptr, "afl", strlen("afl")) == 0 ||
          strncasecmp(ptr, "classic", strlen("classic")) == 0) {

        if (instrument_mode == INSTRUMENT_LTO) {

          instrument_mode = INSTRUMENT_CLASSIC;
          lto_mode = 1;

        } else if (!instrument_mode || instrument_mode == INSTRUMENT_AFL)

          instrument_mode = INSTRUMENT_AFL;
        else
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strncasecmp(ptr, "pc-guard", strlen("pc-guard")) == 0 ||
          strncasecmp(ptr, "pcguard", strlen("pcguard")) == 0) {

        if (!instrument_mode || instrument_mode == INSTRUMENT_PCGUARD)
          instrument_mode = INSTRUMENT_PCGUARD;
        else
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strncasecmp(ptr, "cfg", strlen("cfg")) == 0 ||
          strncasecmp(ptr, "instrim", strlen("instrim")) == 0) {

        if (instrument_mode == INSTRUMENT_LTO) {

          instrument_mode = INSTRUMENT_CFG;
          lto_mode = 1;

        } else if (!instrument_mode || instrument_mode == INSTRUMENT_CFG)

          instrument_mode = INSTRUMENT_CFG;
        else
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strncasecmp(ptr, "lto", strlen("lto")) == 0) {

        lto_mode = 1;
        if (!instrument_mode || instrument_mode == INSTRUMENT_LTO)
          instrument_mode = INSTRUMENT_LTO;
        else if (instrument_mode != INSTRUMENT_CFG)
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strncasecmp(ptr, "ctx", strlen("ctx")) == 0) {

        instrument_opt_mode |= INSTRUMENT_OPT_CTX;
        setenv("AFL_LLVM_CTX", "1", 1);

      }

      if (strncasecmp(ptr, "ngram", strlen("ngram")) == 0) {

        ptr += strlen("ngram");
        while (*ptr && (*ptr < '0' || *ptr > '9'))
          ptr++;
        if (!*ptr)
          if ((ptr = getenv("AFL_LLVM_NGRAM_SIZE")) != NULL)
            FATAL(
                "you must set the NGRAM size with (e.g. for value 2) "
                "AFL_LLVM_INSTRUMENT=ngram-2");
        ngram_size = atoi(ptr);
        if (ngram_size < 2 || ngram_size > NGRAM_SIZE_MAX)
          FATAL(
              "NGRAM instrumentation option must be between 2 and "
              "NGRAM_SIZE_MAX "
              "(%u)",
              NGRAM_SIZE_MAX);
        instrument_opt_mode |= (INSTRUMENT_OPT_NGRAM);
        ptr = alloc_printf("%u", ngram_size);
        setenv("AFL_LLVM_NGRAM_SIZE", ptr, 1);

      }

      ptr = strtok(NULL, ":,;");

    }

  }

  if (strstr(argv[0], "afl-clang-lto") != NULL) {

    if (instrument_mode == 0 || instrument_mode == INSTRUMENT_LTO ||
        instrument_mode == INSTRUMENT_CFG) {

      lto_mode = 1;
      callname = "afl-clang-lto";
      if (!instrument_mode) {

        instrument_mode = INSTRUMENT_CFG;
        ptr = instrument_mode_string[instrument_mode];

      }

    } else if (instrument_mode == INSTRUMENT_LTO ||

               instrument_mode == INSTRUMENT_CLASSIC) {

      lto_mode = 1;
      callname = "afl-clang-lto";

    } else {

      if (!be_quiet)
        WARNF("afl-clang-lto called with mode %s, using that mode instead",
              instrument_mode_string[instrument_mode]);

    }

  }

  if (instrument_mode == 0) {

#if LLVM_VERSION_MAJOR <= 6
    instrument_mode = INSTRUMENT_AFL;
#else
    if (getenv("AFL_LLVM_INSTRUMENT_FILE") != NULL ||
        getenv("AFL_LLVM_WHITELIST") || getenv("AFL_LLVM_ALLOWLIST") ||
        getenv("AFL_LLVM_DENYLIST") || getenv("AFL_LLVM_BLOCKLIST")) {

      instrument_mode = INSTRUMENT_AFL;
      WARNF(
          "switching to classic instrumentation because "
          "AFL_LLVM_ALLOWLIST/DENYLIST does not work with PCGUARD. Use "
          "-fsanitize-coverage-allowlist=allowlist.txt or "
          "-fsanitize-coverage-blocklist=denylist.txt if you want to use "
          "PCGUARD. Requires llvm 12+. See https://clang.llvm.org/docs/ "
          "SanitizerCoverage.html#partially-disabling-instrumentation");

    } else

      instrument_mode = INSTRUMENT_PCGUARD;
#endif

  }

  if (instrument_opt_mode && lto_mode)
    FATAL(
        "CTX and NGRAM can not be used in LTO mode (and would make LTO "
        "useless)");

  if (!instrument_opt_mode) {

    if (lto_mode && instrument_mode == INSTRUMENT_CFG)
      ptr = alloc_printf("InsTrimLTO");
    else
      ptr = instrument_mode_string[instrument_mode];

  } else if (instrument_opt_mode == INSTRUMENT_OPT_CTX)

    ptr = alloc_printf("%s + CTX", instrument_mode_string[instrument_mode]);
  else if (instrument_opt_mode == INSTRUMENT_OPT_NGRAM)
    ptr = alloc_printf("%s + NGRAM-%u", instrument_mode_string[instrument_mode],
                       ngram_size);
  else
    ptr = alloc_printf("%s + CTX + NGRAM-%u",
                       instrument_mode_string[instrument_mode], ngram_size);

#ifndef AFL_CLANG_FLTO
  if (lto_mode)
    FATAL(
        "instrumentation mode LTO specified but LLVM support not available "
        "(requires LLVM 11 or higher)");
#endif

  if (instrument_opt_mode && instrument_mode != INSTRUMENT_CLASSIC &&
      instrument_mode != INSTRUMENT_CFG)
    FATAL(
        "CTX and NGRAM instrumentation options can only be used with CFG "
        "(recommended) and CLASSIC instrumentation modes!");

  if (getenv("AFL_LLVM_SKIP_NEVERZERO") && getenv("AFL_LLVM_NOT_ZERO"))
    FATAL(
        "AFL_LLVM_NOT_ZERO and AFL_LLVM_SKIP_NEVERZERO can not be set "
        "together");

  if (instrument_mode == INSTRUMENT_PCGUARD &&
      (getenv("AFL_LLVM_INSTRUMENT_FILE") != NULL ||
       getenv("AFL_LLVM_WHITELIST") || getenv("AFL_LLVM_ALLOWLIST") ||
       getenv("AFL_LLVM_DENYLIST") || getenv("AFL_LLVM_BLOCKLIST")))
    FATAL(
        "Instrumentation type PCGUARD does not support "
        "AFL_LLVM_ALLOWLIST/DENYLIST! Use "
        "-fsanitize-coverage-allowlist=allowlist.txt or "
        "-fsanitize-coverage-blocklist=denylist.txt instead (requires llvm "
        "12+), see "
        "https://clang.llvm.org/docs/"
        "SanitizerCoverage.html#partially-disabling-instrumentation");

  if (argc < 2 || strcmp(argv[1], "-h") == 0) {

    if (!lto_mode)
      printf("afl-clang-fast" VERSION " by <lszekeres@google.com> in %s mode\n",
             ptr);
    else
      printf("afl-clang-lto" VERSION
             "  by Marc \"vanHauser\" Heuse <mh@mh-sec.de> in %s mode\n",
             ptr);

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
        "AFL_DEBUG: enable developer debugging output\n"
        "AFL_DONT_OPTIMIZE: disable optimization instead of -O3\n"
        "AFL_HARDEN: adds code hardening to catch memory bugs\n"
        "AFL_INST_RATIO: percentage of branches to instrument\n"
#if LLVM_VERSION_MAJOR < 9
        "AFL_LLVM_NOT_ZERO: use cycling trace counters that skip zero\n"
#else
        "AFL_LLVM_SKIP_NEVERZERO: do not skip zero on trace counters\n"
#endif
        "AFL_LLVM_LAF_SPLIT_COMPARES: enable cascaded comparisons\n"
        "AFL_LLVM_LAF_SPLIT_COMPARES_BITW: size limit (default 8)\n"
        "AFL_LLVM_LAF_SPLIT_SWITCHES: casc. comp. in 'switch'\n"
        " to cascaded comparisons\n"
        "AFL_LLVM_LAF_SPLIT_FLOATS: transform floating point comp. to "
        "cascaded comp.\n"
        "AFL_LLVM_LAF_TRANSFORM_COMPARES: transform library comparison "
        "function calls\n"
        "AFL_LLVM_LAF_ALL: enables all LAF splits/transforms\n"
        "AFL_LLVM_INSTRUMENT_ALLOW/AFL_LLVM_INSTRUMENT_DENY: enable instrument"
        "allow/deny listing (selective instrumentation)\n"
        "AFL_NO_BUILTIN: compile for use with libtokencap.so\n"
        "AFL_PATH: path to instrumenting pass and runtime "
        "(afl-llvm-rt.*o)\n"
        "AFL_LLVM_DOCUMENT_IDS: document edge IDs given to which function (LTO "
        "only)\n"
        "AFL_QUIET: suppress verbose output\n"
        "AFL_USE_ASAN: activate address sanitizer\n"
        "AFL_USE_CFISAN: activate control flow sanitizer\n"
        "AFL_USE_MSAN: activate memory sanitizer\n"
        "AFL_USE_UBSAN: activate undefined behaviour sanitizer\n",
        callname, BIN_PATH, BIN_PATH);

    SAYF(
        "\nafl-clang-fast specific environment variables:\n"
        "AFL_LLVM_CMPLOG: log operands of comparisons (RedQueen mutator)\n"
        "AFL_LLVM_INSTRUMENT: set instrumentation mode: AFL, CFG "
        "(INSTRIM), PCGUARD [DEFAULT], LTO, CTX, NGRAM-2 ... NGRAM-16\n"
        " You can also use the old environment variables instead:\n"
        "  AFL_LLVM_USE_TRACE_PC: use LLVM trace-pc-guard instrumentation "
        "[DEFAULT]\n"
        "  AFL_LLVM_INSTRIM: use light weight instrumentation InsTrim\n"
        "  AFL_LLVM_INSTRIM_LOOPHEAD: optimize loop tracing for speed ("
        "option to INSTRIM)\n"
        "  AFL_LLVM_CTX: use context sensitive coverage\n"
        "  AFL_LLVM_NGRAM_SIZE: use ngram prev_loc count coverage\n");

#ifdef AFL_CLANG_FLTO
    SAYF(
        "\nafl-clang-lto specific environment variables:\n"
        "AFL_LLVM_MAP_ADDR: use a fixed coverage map address (speed), e.g. "
        "0x10000\n"
        "AFL_LLVM_DOCUMENT_IDS: write all edge IDs and the corresponding "
        "functions they are in into this file\n"
        "AFL_LLVM_LTO_DONTWRITEID: don't write the highest ID used to a "
        "global var\n"
        "AFL_LLVM_LTO_STARTID: from which ID to start counting from for a "
        "bb\n"
        "AFL_REAL_LD: use this lld linker instead of the compiled in path\n"
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

    if (!lto_mode)

      SAYF(cCYA "afl-clang-fast" VERSION cRST
                " by <lszekeres@google.com> in %s mode\n",
           ptr);

    else

      SAYF(cCYA "afl-clang-lto" VERSION cRST
                " by Marc \"vanHauser\" Heuse <mh@mh-sec.de> in mode %s\n",
           ptr);

  }

  u8 *ptr2;
  if (!be_quiet && !lto_mode &&
      ((ptr2 = getenv("AFL_MAP_SIZE")) || (ptr2 = getenv("AFL_MAPSIZE")))) {

    u32 map_size = atoi(ptr2);
    if (map_size != MAP_SIZE)
      WARNF("AFL_MAP_SIZE is not supported by afl-clang-fast");

  }

  if (debug) {

    SAYF(cMGN "[D]" cRST " cd \"%s\";", getthecwd());
    for (i = 0; i < argc; i++)
      SAYF(" \"%s\"", argv[i]);
    SAYF("\n");

  }

  check_environment_vars(envp);

  if (getenv("AFL_LLVM_LAF_ALL")) {

    setenv("AFL_LLVM_LAF_SPLIT_SWITCHES", "1", 1);
    setenv("AFL_LLVM_LAF_SPLIT_COMPARES", "1", 1);
    setenv("AFL_LLVM_LAF_SPLIT_FLOATS", "1", 1);
    setenv("AFL_LLVM_LAF_TRANSFORM_COMPARES", "1", 1);

  }

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

