/*
   american fuzzy lop++ - compiler instrumentation wrapper
   -------------------------------------------------------

   Written by Michal Zalewski, Laszlo Szekeres and Marc Heuse

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

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

static u8 * obj_path;                  /* Path to runtime libraries         */
static u8 **cc_params;                 /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;            /* Param count, including argv0      */
static u8   llvm_fullpath[PATH_MAX];
static u8   instrument_mode, instrument_opt_mode, ngram_size, lto_mode,
    compiler_mode, plusplus_mode;
static u8  have_gcc, have_llvm, have_gcc_plugin, have_lto;
static u8  selected_gcc, selected_lto, selected_gcc_plugin, selected_llvm;
static u8 *lto_flag = AFL_CLANG_FLTO, *argvnull;
static u8  debug;
static u8  cwd[4096];
static u8  cmplog_mode;
u8         use_stdin;                                              /* dummy */
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

enum {

  UNSET = 0,
  LTO = 1,
  LLVM = 2,
  GCC_PLUGIN = 3,
  GCC = 4

};

char compiler_mode_string[6][12] = {

    "UNSET", "LLVM-LTO", "LLVM", "GCC-PLUGIN",
    "GCC",   ""

};

u8 *getthecwd() {

  static u8 fail[] = "";
  if (getcwd(cwd, sizeof(cwd)) == NULL) return fail;
  return cwd;

}

/* Try to find the runtime libraries. If that fails, abort. */

static u8 *find_object(u8 *obj, u8 *argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash = NULL, *tmp;

  if (afl_path) {

#ifdef __ANDROID__
    tmp = alloc_printf("%s/%s", afl_path, obj);
#else
    tmp = alloc_printf("%s/%s", afl_path, obj);
#endif

    if (!access(tmp, R_OK)) {

      obj_path = afl_path;
      return tmp;

    }

    ck_free(tmp);

  }

  if (argv0) slash = strrchr(argv0, '/');

  if (slash) {

    u8 *dir;

    *slash = 0;
    dir = ck_strdup(argv0);
    *slash = '/';

#ifdef __ANDROID__
    tmp = alloc_printf("%s/%s", dir, obj);
#else
    tmp = alloc_printf("%s/%s", dir, obj);
#endif

    if (!access(tmp, R_OK)) {

      obj_path = dir;
      return tmp;

    }

    ck_free(tmp);
    ck_free(dir);

  }

  tmp = alloc_printf("%s/%s", AFL_PATH, obj);
#ifdef __ANDROID__
  if (!access(tmp, R_OK)) {

#else
  if (!access(tmp, R_OK)) {

#endif

    obj_path = AFL_PATH;
    return tmp;

  }

  ck_free(tmp);
  return NULL;

}

/* Try to find the runtime libraries. If that fails, abort. */

static void find_obj(u8 *argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

#ifdef __ANDROID__
    tmp = alloc_printf("%s/afl-llvm-rt.so", afl_path);
#else
    tmp = alloc_printf("%s/afl-compiler-rt.o", afl_path);
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
    tmp = alloc_printf("%s/afl-compiler-rt.o", dir);
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
  if (!access(AFL_PATH "/afl-compiler-rt.o", R_OK)) {

#endif

    obj_path = AFL_PATH;
    return;

  }

  FATAL(
      "Unable to find 'afl-compiler-rt.o' or 'afl-llvm-pass.so'. Please set "
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

  if (lto_mode) {

    if (lto_flag[0] != '-')
      FATAL(
          "Using afl-clang-lto is not possible because Makefile magic did not "
          "identify the correct -flto flag");
    else
      compiler_mode = LTO;

  }

  if (!compiler_mode) {

    // lto is not a default because outside of afl-cc RANLIB and AR have to
    // be set to llvm versions so this would work
    if (have_llvm)
      compiler_mode = LLVM;
    else if (have_gcc_plugin)
      compiler_mode = GCC_PLUGIN;
    else if (have_gcc)
      compiler_mode = GCC;
    else
      FATAL("no compiler mode available");

  }

  if (plusplus_mode) {

    u8 *alt_cxx = getenv("AFL_CXX");

    if (!alt_cxx) {

      if (compiler_mode >= GCC_PLUGIN) {

        alt_cxx = "g++";

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

        alt_cc = "gcc";

      } else {

        if (USE_BINDIR)
          snprintf(llvm_fullpath, sizeof(llvm_fullpath), "%s/clang",
                   LLVM_BINDIR);
        else
          snprintf(llvm_fullpath, sizeof(llvm_fullpath), CLANGPP_BIN);
        alt_cc = llvm_fullpath;

      }

    }

    cc_params[0] = alt_cc;

  }

  if (compiler_mode == GCC) {

    cc_params[cc_par_cnt++] = "-B";
    cc_params[cc_par_cnt++] = obj_path;

  }

  if (compiler_mode == GCC_PLUGIN) {

    char *fplugin_arg =
        alloc_printf("-fplugin=%s", find_object("afl-gcc-pass.so", argvnull));
    cc_params[cc_par_cnt++] = fplugin_arg;

  }

  if (compiler_mode == LLVM || compiler_mode == LTO) {

    cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";

    if (lto_mode && plusplus_mode)
      cc_params[cc_par_cnt++] = "-lc++";  // needed by fuzzbench, early

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

        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/split-switches-pass.so", obj_path);

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

        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/split-compares-pass.so", obj_path);

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

        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/cmplog-routines-pass.so", obj_path);
        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/split-switches-pass.so", obj_path);
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

#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 12
      u8 *ld_ptr = strrchr(AFL_REAL_LD, '/');
      if (!ld_ptr) ld_ptr = "ld.lld";
      cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s", ld_ptr);
      cc_params[cc_par_cnt++] = alloc_printf("--ld-path=%s", AFL_REAL_LD);
#else
      cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s", AFL_REAL_LD);
#endif

      cc_params[cc_par_cnt++] = "-Wl,--allow-multiple-definition";

      if (instrument_mode == INSTRUMENT_CFG)
        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/SanitizerCoverageLTO.so", obj_path);
      else

        cc_params[cc_par_cnt++] = alloc_printf(
            "-Wl,-mllvm=-load=%s/afl-llvm-lto-instrumentation.so", obj_path);
      cc_params[cc_par_cnt++] = lto_flag;

    } else {

      if (instrument_mode == INSTRUMENT_PCGUARD) {

#if LLVM_MAJOR >= 4
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
          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-pass.so", obj_path);

      }

    }

    // cc_params[cc_par_cnt++] = "-Qunused-arguments";

    // in case LLVM is installed not via a package manager or "make install"
    // e.g. compiled download or compiled from github then it's ./lib directory
    // might not be in the search path. Add it if so.
    u8 *libdir = strdup(LLVM_LIBDIR);
    if (plusplus_mode && strlen(libdir) && strncmp(libdir, "/usr", 4) &&
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

  if (compiler_mode != GCC) {

    switch (bit_mode) {

      case 0:
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/afl-compiler-rt.o", obj_path);
        if (lto_mode)
          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-rt-lto.o", obj_path);
        break;

      case 32:
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/afl-compiler-rt-32.o", obj_path);
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
        cc_params[cc_par_cnt++] =
            alloc_printf("%s/afl-compiler-rt-64.o", obj_path);
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

  }

#endif

  cc_params[cc_par_cnt] = NULL;

}

/* Main entry point */

int main(int argc, char **argv, char **envp) {

  int   i;
  char *callname = argv[0], *ptr = NULL;

  if (getenv("AFL_DEBUG")) {

    debug = 1;
    if (strcmp(getenv("AFL_DEBUG"), "0") == 0) unsetenv("AFL_DEBUG");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  if ((ptr = strrchr(callname, '/')) != NULL) callname = ptr + 1;
  argvnull = (u8 *)argv[0];
  check_environment_vars(envp);

  if ((ptr = find_object("as", argv[0])) != NULL) {

    have_gcc = 1;
    ck_free(ptr);

  }

  if ((ptr = find_object("SanitizerCoverageLTO.so", argv[0])) != NULL) {

    have_lto = 1;
    ck_free(ptr);

  }

  if ((ptr = find_object("cmplog-routines-pass.so", argv[0])) != NULL) {

    have_llvm = 1;
    ck_free(ptr);

  }

  if ((ptr = find_object("afl-gcc-pass.so", argv[0])) != NULL) {

    have_gcc_plugin = 1;
    ck_free(ptr);

  }

  if (strncmp(callname, "afl-clang-fast", 14) == 0) {

    selected_llvm = 1;
    compiler_mode = LLVM;

  } else if (strncmp(callname, "afl-clang-lto", 13) == 0) {

    selected_lto = 1;
    compiler_mode = LTO;

  } else if (strncmp(callname, "afl-gcc-fast", 12) == 0 ||

             strncmp(callname, "afl-g++-fast", 12) == 0) {

    selected_gcc_plugin = 1;
    compiler_mode = GCC_PLUGIN;

  } else if (strncmp(callname, "afl-gcc", 7) == 0 ||

             strncmp(callname, "afl-g++", 7) == 0) {

    selected_gcc = 1;
    compiler_mode = GCC;

  }

  if (strlen(callname) > 2 &&
      (strncmp(callname + strlen(callname) - 2, "++", 2) == 0 ||
       strstr(callname, "-g++") != NULL))
    plusplus_mode = 1;

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

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0) {

    char *fp;
    fp = realpath(argv[0], NULL);

    printf("afl-cc" VERSION
           " by Michal Zalewski, Laszlo Szekeres, Marc Heuse\n");

    SAYF(
        "\n"
        "%s[++] [options]\n"
        "\n"
        "This is a helper application for afl-fuzz. It serves as a drop-in "
        "replacement\n"
        "for gcc and clang, letting you recompile third-party code with the "
        "required\n"
        "runtime instrumentation. A common use pattern would be one of the "
        "following:\n\n"

        "  CC=%s CXX=%s ./configure --disable-shared\n\n",
        callname, fp, fp);

    SAYF(
        "Modes:\n"
        "  llvm LTO instrumentation:   %s%s\n"
        "      PCGUARD                     DEFAULT\n"
        "      CLASSIC\n"
        "  llvm instrumentation:       %s%s\n"
        "      PCGUARD                     %s\n"
        "      CLASSIC                     %s\n"
        "        - NORMAL\n"
        "        - CTX\n"
        "        - NGRAM2-16\n"
        "      INSTRIM\n"
        "        - NORMAL\n"
        "        - CTX\n"
        "        - NGRAM2-16\n"
        "  gcc intrumentation:         %s%s\n"
        "    CLASSIC                       DEFAULT\n"
        "  simple gcc instrumentation: %s%s\n"
        "    CLASSIC                       DEFAULT\n\n",
        have_lto ? "AVAILABLE" : "unavailable", selected_lto ? " SELECTED" : "",
        have_llvm ? "AVAILABLE" : "unavailable",
        selected_llvm ? " SELECTED" : "", LLVM_MAJOR > 6 ? "DEFAULT" : "",
        LLVM_MAJOR > 6 ? "" : "DEFAULT",
        have_gcc_plugin ? "AVAILABLE" : "unavailable",
        selected_gcc_plugin ? " SELECTED" : "",
        have_gcc ? "AVAILABLE" : "unavailable",
        selected_gcc ? " SELECTED" : "");

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
          "  AFL_HARDEN: adds code hardening to catch memory bugs\n"
          "  AFL_INST_RATIO: percentage of branches to instrument\n"
#if LLVM_MAJOR < 9
          "  AFL_LLVM_NOT_ZERO: use cycling trace counters that skip zero\n"
#else
          "  AFL_LLVM_SKIP_NEVERZERO: do not skip zero on trace counters\n"
#endif
          "  AFL_LLVM_LAF_ALL: enables all LAF splits/transforms\n"
          "  AFL_LLVM_LAF_SPLIT_COMPARES: enable cascaded comparisons\n"
          "  AFL_LLVM_LAF_SPLIT_COMPARES_BITW: size limit (default 8)\n"
          "  AFL_LLVM_LAF_SPLIT_SWITCHES: cascaded comparisons on switches\n"
          "  AFL_LLVM_LAF_SPLIT_FLOATS: cascaded comparisons on floats\n"
          "  AFL_LLVM_LAF_TRANSFORM_COMPARES: cascade comparisons for string "
          "functions\n"
          "  AFL_LLVM_INSTRUMENT_ALLOW/AFL_LLVM_INSTRUMENT_DENY: enable "
          "instrument allow/\n"
          "    deny listing (selective instrumentation)\n"
          "  AFL_NO_BUILTIN: no builtins for string compare functions (for "
          "libtokencap.so)\n"
          "  AFL_PATH: path to instrumenting pass and runtime  "
          "(afl-llvm-rt.*o)\n"
          "  AFL_LLVM_DOCUMENT_IDS: document edge IDs given to which function "
          "(LTO only)\n"
          "  AFL_QUIET: suppress verbose output\n"
          "  AFL_USE_ASAN: activate address sanitizer\n"
          "  AFL_USE_CFISAN: activate control flow sanitizer\n"
          "  AFL_USE_MSAN: activate memory sanitizer\n"
          "  AFL_USE_UBSAN: activate undefined behaviour sanitizer\n",
          callname, BIN_PATH, BIN_PATH);

      SAYF(
          "\nLLVM/LTO/afl-clang-fast/afl-clang-lto specific environment "
          "variables:\n"
          "  AFL_LLVM_CMPLOG: log operands of comparisons (RedQueen mutator)\n"
          "  AFL_LLVM_INSTRUMENT: set instrumentation mode: CLASSIC, INSTRIM, "
          "PCGUARD, LTO, CTX, NGRAM-2 ... NGRAM-16\n"
          " You can also use the old environment variables instead:\n"
          "  AFL_LLVM_USE_TRACE_PC: use LLVM trace-pc-guard instrumentation\n"
          "  AFL_LLVM_INSTRIM: use light weight instrumentation InsTrim\n"
          "  AFL_LLVM_INSTRIM_LOOPHEAD: optimize loop tracing for speed "
          "(option to INSTRIM)\n"
          "  AFL_LLVM_CTX: use context sensitive coverage (for CLASSIC and "
          "INSTRIM)\n"
          "  AFL_LLVM_NGRAM_SIZE: use ngram prev_loc count coverage (for "
          "CLASSIC and INSTRIM)\n");

#ifdef AFL_CLANG_FLTO
      SAYF(
          "\nLTO/afl-clang-lto specific environment variables:\n"
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

    }

    SAYF(
        "For any information on the available instrumentations and options "
        "please \n"
        "consult the README.md, especially section 3.1 about instrumenting "
        "targets.\n\n");

    SAYF(
        "afl-cc was built for llvm %d with the llvm binary path "
        "of \"%s\".\n",
        LLVM_MAJOR, LLVM_BINDIR);

    SAYF("\n");

    exit(1);

  }

  if (selected_lto) {

    if (instrument_mode == 0 || instrument_mode == INSTRUMENT_LTO ||
        instrument_mode == INSTRUMENT_CFG) {

      lto_mode = 1;
      if (!instrument_mode) {

        instrument_mode = INSTRUMENT_CFG;
        ptr = instrument_mode_string[instrument_mode];

      }

    } else if (instrument_mode == INSTRUMENT_LTO ||

               instrument_mode == INSTRUMENT_CLASSIC) {

      lto_mode = 1;

    } else {

      if (!be_quiet)
        WARNF("afl-clang-lto called with mode %s, using that mode instead",
              instrument_mode_string[instrument_mode]);

    }

  }

  if (instrument_mode == 0 && compiler_mode < GCC_PLUGIN) {

#if LLVM_MAJOR <= 6
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

  if (instrument_opt_mode && compiler_mode != LLVM)
    FATAL("CTX and NGRAM can only be used in LLVM mode");

  if (!instrument_opt_mode) {

    if (lto_mode && instrument_mode == INSTRUMENT_CFG)
      instrument_mode = INSTRUMENT_PCGUARD;
    ptr = instrument_mode_string[instrument_mode];

  } else {

    if (instrument_opt_mode == INSTRUMENT_OPT_CTX)

      ptr = alloc_printf("%s + CTX", instrument_mode_string[instrument_mode]);
    else if (instrument_opt_mode == INSTRUMENT_OPT_NGRAM)
      ptr = alloc_printf("%s + NGRAM-%u",
                         instrument_mode_string[instrument_mode], ngram_size);
    else
      ptr = alloc_printf("%s + CTX + NGRAM-%u",
                         instrument_mode_string[instrument_mode], ngram_size);

  }

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

  if ((isatty(2) && !be_quiet) || debug) {

    SAYF(cCYA
         "afl-cc " VERSION cRST
         " by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: %s\n",
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

