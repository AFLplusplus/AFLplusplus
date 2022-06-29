/*
   american fuzzy lop++ - compiler instrumentation wrapper
   -------------------------------------------------------

   Written by Michal Zalewski, Laszlo Szekeres and Marc Heuse

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#define AFL_MAIN

#include "common.h"
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "llvm-alternative-coverage.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <assert.h>

#if (LLVM_MAJOR - 0 == 0)
  #undef LLVM_MAJOR
#endif
#if !defined(LLVM_MAJOR)
  #define LLVM_MAJOR 0
#endif
#if (LLVM_MINOR - 0 == 0)
  #undef LLVM_MINOR
#endif
#if !defined(LLVM_MINOR)
  #define LLVM_MINOR 0
#endif

static u8 * obj_path;                  /* Path to runtime libraries         */
static u8 **cc_params;                 /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;            /* Param count, including argv0      */
static u8   clang_mode;                /* Invoked as afl-clang*?            */
static u8   llvm_fullpath[PATH_MAX];
static u8   instrument_mode, instrument_opt_mode, ngram_size, ctx_k, lto_mode;
static u8   compiler_mode, plusplus_mode, have_instr_env = 0;
static u8   have_gcc, have_llvm, have_gcc_plugin, have_lto, have_instr_list = 0;
static u8 * lto_flag = AFL_CLANG_FLTO, *argvnull;
static u8   debug;
static u8   cwd[4096];
static u8   cmplog_mode;
u8          use_stdin;                                             /* dummy */
static int  passthrough;
// static u8 *march_opt = CFLAGS_OPT;

enum {

  INSTRUMENT_DEFAULT = 0,
  INSTRUMENT_CLASSIC = 1,
  INSTRUMENT_AFL = 1,
  INSTRUMENT_PCGUARD = 2,
  INSTRUMENT_CFG = 3,
  INSTRUMENT_LTO = 4,
  INSTRUMENT_LLVMNATIVE = 5,
  INSTRUMENT_GCC = 6,
  INSTRUMENT_CLANG = 7,
  INSTRUMENT_OPT_CTX = 8,
  INSTRUMENT_OPT_NGRAM = 16,
  INSTRUMENT_OPT_CALLER = 32,
  INSTRUMENT_OPT_CTX_K = 64,

};

char instrument_mode_string[18][18] = {

    "DEFAULT",
    "CLASSIC",
    "PCGUARD",
    "CFG",
    "LTO",
    "PCGUARD-NATIVE",
    "GCC",
    "CLANG",
    "CTX",
    "CALLER",
    "",
    "",
    "",
    "",
    "",
    "",
    "NGRAM",
    ""

};

enum {

  UNSET = 0,
  LTO = 1,
  LLVM = 2,
  GCC_PLUGIN = 3,
  GCC = 4,
  CLANG = 5

};

char compiler_mode_string[7][12] = {

    "AUTOSELECT", "LLVM-LTO", "LLVM", "GCC_PLUGIN",
    "GCC",        "CLANG",    ""

};

u8 *getthecwd() {

  if (getcwd(cwd, sizeof(cwd)) == NULL) {

    static u8 fail[] = "";
    return fail;

  }

  return cwd;

}

/* Try to find a specific runtime we need, returns NULL on fail. */

/*
  in find_object() we look here:

  1. if obj_path is already set we look there first
  2. then we check the $AFL_PATH environment variable location if set
  3. next we check argv[0] if it has path information and use it
    a) we also check ../lib/afl
  4. if 3. failed we check /proc (only Linux, Android, NetBSD, DragonFly, and
     FreeBSD with procfs)
    a) and check here in ../lib/afl too
  5. we look into the AFL_PATH define (usually /usr/local/lib/afl)
  6. we finally try the current directory

  if all these attempts fail - we return NULL and the caller has to decide
  what to do.
*/

static u8 *find_object(u8 *obj, u8 *argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash = NULL, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/%s", afl_path, obj);

    if (debug) DEBUGF("Trying %s\n", tmp);

    if (!access(tmp, R_OK)) {

      obj_path = afl_path;
      return tmp;

    }

    ck_free(tmp);

  }

  if (argv0) {

    slash = strrchr(argv0, '/');

    if (slash) {

      u8 *dir = ck_strdup(argv0);

      slash = strrchr(dir, '/');
      *slash = 0;

      tmp = alloc_printf("%s/%s", dir, obj);

      if (debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

        obj_path = dir;
        return tmp;

      }

      ck_free(tmp);
      tmp = alloc_printf("%s/../lib/afl/%s", dir, obj);

      if (debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

        u8 *dir2 = alloc_printf("%s/../lib/afl", dir);
        obj_path = dir2;
        ck_free(dir);
        return tmp;

      }

      ck_free(tmp);
      ck_free(dir);

    }

#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__linux__) || \
    defined(__ANDROID__) || defined(__NetBSD__)
  #define HAS_PROC_FS 1
#endif
#ifdef HAS_PROC_FS
    else {

      char *procname = NULL;
  #if defined(__FreeBSD__) || defined(__DragonFly__)
      procname = "/proc/curproc/file";
  #elif defined(__linux__) || defined(__ANDROID__)
      procname = "/proc/self/exe";
  #elif defined(__NetBSD__)
      procname = "/proc/curproc/exe";
  #endif
      if (procname) {

        char    exepath[PATH_MAX];
        ssize_t exepath_len = readlink(procname, exepath, sizeof(exepath));
        if (exepath_len > 0 && exepath_len < PATH_MAX) {

          exepath[exepath_len] = 0;
          slash = strrchr(exepath, '/');

          if (slash) {

            *slash = 0;
            tmp = alloc_printf("%s/%s", exepath, obj);

            if (!access(tmp, R_OK)) {

              u8 *dir = alloc_printf("%s", exepath);
              obj_path = dir;
              return tmp;

            }

            ck_free(tmp);
            tmp = alloc_printf("%s/../lib/afl/%s", exepath, obj);

            if (debug) DEBUGF("Trying %s\n", tmp);

            if (!access(tmp, R_OK)) {

              u8 *dir = alloc_printf("%s/../lib/afl/", exepath);
              obj_path = dir;
              return tmp;

            }

          }

        }

      }

    }

#endif
#undef HAS_PROC_FS

  }

  tmp = alloc_printf("%s/%s", AFL_PATH, obj);

  if (debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) {

    obj_path = AFL_PATH;
    return tmp;

  }

  ck_free(tmp);

  tmp = alloc_printf("./%s", obj);

  if (debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) {

    obj_path = ".";
    return tmp;

  }

  ck_free(tmp);

  if (debug) DEBUGF("Trying ... giving up\n");

  return NULL;

}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char **argv, char **envp) {

  u8 fortify_set = 0, asan_set = 0, x_set = 0, bit_mode = 0, shared_linking = 0,
     preprocessor_only = 0, have_unroll = 0, have_o = 0, have_pic = 0,
     have_c = 0, partial_linking = 0;

  cc_params = ck_alloc((argc + 128) * sizeof(u8 *));

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

    char *fplugin_arg = alloc_printf("-fplugin=%s/afl-gcc-pass.so", obj_path);
    cc_params[cc_par_cnt++] = fplugin_arg;
    cc_params[cc_par_cnt++] = "-fno-if-conversion";
    cc_params[cc_par_cnt++] = "-fno-if-conversion2";

  }

  if (compiler_mode == LLVM || compiler_mode == LTO) {

    cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";

    if (lto_mode && have_instr_env) {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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

    unsetenv("AFL_LD");
    unsetenv("AFL_LD_CALLER");

    if (cmplog_mode) {

      cc_params[cc_par_cnt++] = "-fno-inline";

#if LLVM_MAJOR >= 11                                /* use new pass manager */
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
      cc_params[cc_par_cnt++] =
          alloc_printf("-fpass-plugin=%s/cmplog-switches-pass.so", obj_path);
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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

    //#if LLVM_MAJOR >= 13
    //    // Use the old pass manager in LLVM 14 which the afl++ passes still
    //    use. cc_params[cc_par_cnt++] = "-flegacy-pass-manager";
    //#endif

    if (lto_mode && !have_c) {

      u8 *ld_path = NULL;
      if (getenv("AFL_REAL_LD")) {

        ld_path = strdup(getenv("AFL_REAL_LD"));

      } else {

        ld_path = strdup(AFL_REAL_LD);

      }

      if (!ld_path || !*ld_path) {

        if (ld_path) {

          // Freeing empty string
          free(ld_path);

        }

        ld_path = strdup("ld.lld");

      }

      if (!ld_path) { PFATAL("Could not allocate mem for ld_path"); }
#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 12
      cc_params[cc_par_cnt++] = alloc_printf("--ld-path=%s", ld_path);
#else
      cc_params[cc_par_cnt++] = alloc_printf("-fuse-ld=%s", ld_path);
#endif
      free(ld_path);

#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 13
      cc_params[cc_par_cnt++] = "-Wl,--lto-legacy-pass-manager";
#else
      cc_params[cc_par_cnt++] = "-fno-experimental-new-pass-manager";
#endif

      cc_params[cc_par_cnt++] = "-Wl,--allow-multiple-definition";
      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,-mllvm=-load=%s/SanitizerCoverageLTO.so", obj_path);
      cc_params[cc_par_cnt++] = lto_flag;

    } else {

      if (instrument_mode == INSTRUMENT_PCGUARD) {

#if LLVM_MAJOR >= 11
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

    #if LLVM_MAJOR >= 11                            /* use new pass manager */
          cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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
              "Using unoptimized trace-pc-guard, upgrade to llvm 10.0.1+ for "
              "enhanced version.\n");
        cc_params[cc_par_cnt++] = "-fsanitize-coverage=trace-pc-guard";
        instrument_mode = INSTRUMENT_LLVMNATIVE;
  #else
        FATAL("pcguard instrumentation requires llvm 4.0.1+");
  #endif
#endif

      } else if (instrument_mode == INSTRUMENT_LLVMNATIVE) {

#if LLVM_MAJOR >= 4
        cc_params[cc_par_cnt++] = "-fsanitize-coverage=trace-pc-guard";
#else
        FATAL("pcguard instrumentation requires llvm 4.0.1+");
#endif

      } else {

#if LLVM_MAJOR >= 11                                /* use new pass manager */
        cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
      cc_params[cc_par_cnt++] = alloc_printf(
          "-fpass-plugin=%s/cmplog-instructions-pass.so", obj_path);
      cc_params[cc_par_cnt++] = "-fexperimental-new-pass-manager";
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

    // cc_params[cc_par_cnt++] = "-Qunused-arguments";

    if (lto_mode && argc > 1) {

      u32 idx;
      for (idx = 1; idx < argc; idx++) {

        if (!strncasecmp(argv[idx], "-fpic", 5)) have_pic = 1;

      }

      if (!have_pic) cc_params[cc_par_cnt++] = "-fPIC";

    }

  }

  /* Detect stray -v calls from ./configure scripts. */

  u8 skip_next = 0, non_dash = 0;
  while (--argc) {

    u8 *cur = *(++argv);

    if (skip_next) {

      skip_next = 0;
      continue;

    }

    if (cur[0] != '-') { non_dash = 1; }
    if (!strncmp(cur, "--afl", 5)) continue;
    if (lto_mode && !strncmp(cur, "-fuse-ld=", 9)) continue;
    if (lto_mode && !strncmp(cur, "--ld-path=", 10)) continue;
    if (!strncmp(cur, "-fno-unroll", 11)) continue;
    if (strstr(cur, "afl-compiler-rt") || strstr(cur, "afl-llvm-rt")) continue;
    if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined") ||
        !strcmp(cur, "--no-undefined")) {

      continue;

    }

    if (!strcmp(cur, "-z") || !strcmp(cur, "-Wl,-z")) {

      u8 *param = *(argv + 1);
      if (!strcmp(param, "defs") || !strcmp(param, "-Wl,defs")) {

        skip_next = 1;
        continue;

      }

    }

    if ((compiler_mode == GCC || compiler_mode == GCC_PLUGIN) &&
        !strncmp(cur, "-stdlib=", 8)) {

      if (!be_quiet) { WARNF("Found '%s' - stripping!", cur); }
      continue;

    }

    if ((!strncmp(cur, "-fsanitize=fuzzer-", strlen("-fsanitize=fuzzer-")) ||
         !strncmp(cur, "-fsanitize-coverage", strlen("-fsanitize-coverage"))) &&
        (strncmp(cur, "sanitize-coverage-allow",
                 strlen("sanitize-coverage-allow")) &&
         strncmp(cur, "sanitize-coverage-deny",
                 strlen("sanitize-coverage-deny")) &&
         instrument_mode != INSTRUMENT_LLVMNATIVE)) {

      if (!be_quiet) { WARNF("Found '%s' - stripping!", cur); }
      continue;

    }

    if (!strcmp(cur, "-fsanitize=fuzzer")) {

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

      continue;

    }

    if (!strcmp(cur, "-m32")) bit_mode = 32;
    if (!strcmp(cur, "armv7a-linux-androideabi")) bit_mode = 32;
    if (!strcmp(cur, "-m64")) bit_mode = 64;

    if (!strncmp(cur, "-fsanitize-coverage-", 20) && strstr(cur, "list="))
      have_instr_list = 1;

    if (!strcmp(cur, "-fsanitize=address") || !strcmp(cur, "-fsanitize=memory"))
      asan_set = 1;

    if (strstr(cur, "FORTIFY_SOURCE")) fortify_set = 1;

    if (!strcmp(cur, "-x")) x_set = 1;
    if (!strcmp(cur, "-E")) preprocessor_only = 1;
    if (!strcmp(cur, "-shared")) shared_linking = 1;
    if (!strcmp(cur, "-dynamiclib")) shared_linking = 1;
    if (!strcmp(cur, "--target=wasm32-wasi")) passthrough = 1;
    if (!strcmp(cur, "-Wl,-r")) partial_linking = 1;
    if (!strcmp(cur, "-Wl,-i")) partial_linking = 1;
    if (!strcmp(cur, "-Wl,--relocatable")) partial_linking = 1;
    if (!strcmp(cur, "-r")) partial_linking = 1;
    if (!strcmp(cur, "--relocatable")) partial_linking = 1;
    if (!strcmp(cur, "-c")) have_c = 1;

    if (!strncmp(cur, "-O", 2)) have_o = 1;
    if (!strncmp(cur, "-funroll-loop", 13)) have_unroll = 1;

    cc_params[cc_par_cnt++] = cur;

  }

  // in case LLVM is installed not via a package manager or "make install"
  // e.g. compiled download or compiled from github then its ./lib directory
  // might not be in the search path. Add it if so.
  u8 *libdir = strdup(LLVM_LIBDIR);
  if (plusplus_mode && strlen(libdir) && strncmp(libdir, "/usr", 4) &&
      strncmp(libdir, "/lib", 4)) {

    cc_params[cc_par_cnt++] = "-rpath";
    cc_params[cc_par_cnt++] = libdir;

  } else {

    free(libdir);

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

#if defined(USEMMAP) && !defined(__HAIKU__) && !__APPLE__
  if (!have_c) cc_params[cc_par_cnt++] = "-lrt";
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
      "unsigned char __afl_fuzz_alt[1048576];"
      "unsigned char *__afl_fuzz_alt_ptr = __afl_fuzz_alt;";

  if (plusplus_mode) {

    cc_params[cc_par_cnt++] =
        "-D__AFL_COVERAGE()=int __afl_selective_coverage = 1;"
        "extern \"C\" void __afl_coverage_discard();"
        "extern \"C\" void __afl_coverage_skip();"
        "extern \"C\" void __afl_coverage_on();"
        "extern \"C\" void __afl_coverage_off();";

  } else {

    cc_params[cc_par_cnt++] =
        "-D__AFL_COVERAGE()=int __afl_selective_coverage = 1;"
        "void __afl_coverage_discard();"
        "void __afl_coverage_skip();"
        "void __afl_coverage_on();"
        "void __afl_coverage_off();";

  }

  cc_params[cc_par_cnt++] =
      "-D__AFL_COVERAGE_START_OFF()=int __afl_selective_coverage_start_off = "
      "1;";
  cc_params[cc_par_cnt++] = "-D__AFL_COVERAGE_ON()=__afl_coverage_on()";
  cc_params[cc_par_cnt++] = "-D__AFL_COVERAGE_OFF()=__afl_coverage_off()";
  cc_params[cc_par_cnt++] =
      "-D__AFL_COVERAGE_DISCARD()=__afl_coverage_discard()";
  cc_params[cc_par_cnt++] = "-D__AFL_COVERAGE_SKIP()=__afl_coverage_skip()";
  cc_params[cc_par_cnt++] =
      "-D__AFL_FUZZ_TESTCASE_BUF=(__afl_fuzz_ptr ? __afl_fuzz_ptr : "
      "__afl_fuzz_alt_ptr)";
  cc_params[cc_par_cnt++] =
      "-D__AFL_FUZZ_TESTCASE_LEN=(__afl_fuzz_ptr ? *__afl_fuzz_len : "
      "(*__afl_fuzz_len = read(0, __afl_fuzz_alt_ptr, 1048576)) == 0xffffffff "
      "? 0 : *__afl_fuzz_len)";

  cc_params[cc_par_cnt++] =
      "-D__AFL_LOOP(_A)="
      "({ static volatile char *_B __attribute__((used,unused)); "
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
      "do { static volatile char *_A __attribute__((used,unused)); "
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

  // prevent unnecessary build errors
  if (compiler_mode != GCC_PLUGIN && compiler_mode != GCC) {

    cc_params[cc_par_cnt++] = "-Wno-unused-command-line-argument";

  }

  if (preprocessor_only || have_c || !non_dash) {

    /* In the preprocessor_only case (-E), we are not actually compiling at
       all but requesting the compiler to output preprocessed sources only.
       We must not add the runtime in this case because the compiler will
       simply output its binary content back on stdout, breaking any build
       systems that rely on a separate source preprocessing step. */
    cc_params[cc_par_cnt] = NULL;
    return;

  }

#ifndef __ANDROID__

  if (compiler_mode != GCC && compiler_mode != CLANG) {

    switch (bit_mode) {

      case 0:
        if (!shared_linking && !partial_linking)
          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-compiler-rt.o", obj_path);
        if (lto_mode)
          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-rt-lto.o", obj_path);
        break;

      case 32:
        if (!shared_linking && !partial_linking) {

          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-compiler-rt-32.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m32 is not supported by your compiler");

        }

        if (lto_mode) {

          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-rt-lto-32.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m32 is not supported by your compiler");

        }

        break;

      case 64:
        if (!shared_linking && !partial_linking) {

          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-compiler-rt-64.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m64 is not supported by your compiler");

        }

        if (lto_mode) {

          cc_params[cc_par_cnt++] =
              alloc_printf("%s/afl-llvm-rt-lto-64.o", obj_path);
          if (access(cc_params[cc_par_cnt - 1], R_OK))
            FATAL("-m64 is not supported by your compiler");

        }

        break;

    }

  #if !defined(__APPLE__) && !defined(__sun)
    if (!shared_linking && !partial_linking)
      cc_params[cc_par_cnt++] =
          alloc_printf("-Wl,--dynamic-list=%s/dynamic_list.txt", obj_path);
  #endif

  #if defined(__APPLE__)
    if (shared_linking || partial_linking) {

      cc_params[cc_par_cnt++] = "-Wl,-U";
      cc_params[cc_par_cnt++] = "-Wl,___afl_area_ptr";
      cc_params[cc_par_cnt++] = "-Wl,-U";
      cc_params[cc_par_cnt++] = "-Wl,___sanitizer_cov_trace_pc_guard_init";

    }

  #endif

  }

  #if defined(USEMMAP) && !defined(__HAIKU__) && !__APPLE__
  cc_params[cc_par_cnt++] = "-lrt";
  #endif

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

  if (getenv("AFL_LLVM_INSTRUMENT_FILE") || getenv("AFL_LLVM_WHITELIST") ||
      getenv("AFL_LLVM_ALLOWLIST") || getenv("AFL_LLVM_DENYLIST") ||
      getenv("AFL_LLVM_BLOCKLIST")) {

    have_instr_env = 1;

  }

  if (getenv("AFL_PASSTHROUGH") || getenv("AFL_NOOPT")) {

    passthrough = 1;
    if (!debug) { be_quiet = 1; }

  }

  if ((ptr = strrchr(callname, '/')) != NULL) callname = ptr + 1;
  argvnull = (u8 *)argv[0];
  check_environment_vars(envp);

  if ((ptr = find_object("as", argv[0])) != NULL) {

    have_gcc = 1;
    ck_free(ptr);

  }

#if (LLVM_MAJOR >= 3)

  if ((ptr = find_object("SanitizerCoverageLTO.so", argv[0])) != NULL) {

    have_lto = 1;
    ck_free(ptr);

  }

  if ((ptr = find_object("cmplog-routines-pass.so", argv[0])) != NULL) {

    have_llvm = 1;
    ck_free(ptr);

  }

#endif

#ifdef __ANDROID__
  have_llvm = 1;
#endif

  if ((ptr = find_object("afl-gcc-pass.so", argv[0])) != NULL) {

    have_gcc_plugin = 1;
    ck_free(ptr);

  }

#if (LLVM_MAJOR >= 3)

  if (strncmp(callname, "afl-clang-fast", 14) == 0) {

    compiler_mode = LLVM;

  } else if (strncmp(callname, "afl-clang-lto", 13) == 0 ||

             strncmp(callname, "afl-lto", 7) == 0) {

    compiler_mode = LTO;

  } else

#endif
      if (strncmp(callname, "afl-gcc-fast", 12) == 0 ||

          strncmp(callname, "afl-g++-fast", 12) == 0) {

    compiler_mode = GCC_PLUGIN;

  } else if (strncmp(callname, "afl-gcc", 7) == 0 ||

             strncmp(callname, "afl-g++", 7) == 0) {

    compiler_mode = GCC;

  } else if (strcmp(callname, "afl-clang") == 0 ||

             strcmp(callname, "afl-clang++") == 0) {

    compiler_mode = CLANG;

  }

  if ((ptr = getenv("AFL_CC_COMPILER"))) {

    if (compiler_mode) {

      if (!be_quiet) {

        WARNF(
            "\"AFL_CC_COMPILER\" is set but a specific compiler was already "
            "selected by command line parameter or symlink, ignoring the "
            "environment variable!");

      }

    } else {

      if (strncasecmp(ptr, "LTO", 3) == 0) {

        compiler_mode = LTO;

      } else if (strncasecmp(ptr, "LLVM", 4) == 0) {

        compiler_mode = LLVM;

      } else if (strncasecmp(ptr, "GCC_P", 5) == 0 ||

                 strncasecmp(ptr, "GCC-P", 5) == 0 ||
                 strncasecmp(ptr, "GCCP", 4) == 0) {

        compiler_mode = GCC_PLUGIN;

      } else if (strcasecmp(ptr, "GCC") == 0) {

        compiler_mode = GCC;

      } else

        FATAL("Unknown AFL_CC_COMPILER mode: %s\n", ptr);

    }

  }

  if (strcmp(callname, "afl-clang") == 0 ||
      strcmp(callname, "afl-clang++") == 0) {

    clang_mode = 1;
    compiler_mode = CLANG;

    if (strcmp(callname, "afl-clang++") == 0) { plusplus_mode = 1; }

  }

  for (i = 1; i < argc; i++) {

    if (strncmp(argv[i], "--afl", 5) == 0) {

      if (!strcmp(argv[i], "--afl_noopt") || !strcmp(argv[i], "--afl-noopt")) {

        passthrough = 1;
        argv[i] = "-g";  // we have to overwrite it, -g is always good
        continue;

      }

      if (compiler_mode && !be_quiet) {

        WARNF(
            "--afl-... compiler mode supersedes the AFL_CC_COMPILER and "
            "symlink compiler selection!");

      }

      ptr = argv[i];
      ptr += 5;
      while (*ptr == '-')
        ptr++;

      if (strncasecmp(ptr, "LTO", 3) == 0) {

        compiler_mode = LTO;

      } else if (strncasecmp(ptr, "LLVM", 4) == 0) {

        compiler_mode = LLVM;

      } else if (strncasecmp(ptr, "PCGUARD", 7) == 0 ||

                 strncasecmp(ptr, "PC-GUARD", 8) == 0) {

        compiler_mode = LLVM;
        instrument_mode = INSTRUMENT_PCGUARD;

      } else if (strcasecmp(ptr, "INSTRIM") == 0 ||

                 strcasecmp(ptr, "CFG") == 0) {

        FATAL(
            "InsTrim instrumentation was removed. Use a modern LLVM and "
            "PCGUARD (default in afl-cc).\n");

      } else if (strcasecmp(ptr, "AFL") == 0 ||

                 strcasecmp(ptr, "CLASSIC") == 0) {

        compiler_mode = LLVM;
        instrument_mode = INSTRUMENT_CLASSIC;

      } else if (strcasecmp(ptr, "LLVMNATIVE") == 0 ||

                 strcasecmp(ptr, "NATIVE") == 0 ||
                 strcasecmp(ptr, "LLVM-NATIVE") == 0) {

        compiler_mode = LLVM;
        instrument_mode = INSTRUMENT_LLVMNATIVE;

      } else if (strncasecmp(ptr, "GCC_P", 5) == 0 ||

                 strncasecmp(ptr, "GCC-P", 5) == 0 ||
                 strncasecmp(ptr, "GCCP", 4) == 0) {

        compiler_mode = GCC_PLUGIN;

      } else if (strcasecmp(ptr, "GCC") == 0) {

        compiler_mode = GCC;

      } else if (strncasecmp(ptr, "CLANG", 5) == 0) {

        compiler_mode = CLANG;

      } else

        FATAL("Unknown --afl-... compiler mode: %s\n", argv[i]);

    }

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
      FATAL("you cannot set AFL_LLVM_INSTRUMENT and AFL_TRACE_PC together");

  }

  if (have_instr_env && getenv("AFL_DONT_OPTIMIZE") && !be_quiet) {

    WARNF(
        "AFL_LLVM_ALLOWLIST/DENYLIST and AFL_DONT_OPTIMIZE cannot be combined "
        "for file matching, only function matching!");

  }

  if (getenv("AFL_LLVM_INSTRIM") || getenv("INSTRIM") ||
      getenv("INSTRIM_LIB")) {

    FATAL(
        "InsTrim instrumentation was removed. Use a modern LLVM and PCGUARD "
        "(default in afl-cc).\n");

  }

  if (getenv("AFL_LLVM_CTX")) instrument_opt_mode |= INSTRUMENT_OPT_CTX;
  if (getenv("AFL_LLVM_CALLER")) instrument_opt_mode |= INSTRUMENT_OPT_CALLER;

  if (getenv("AFL_LLVM_NGRAM_SIZE")) {

    instrument_opt_mode |= INSTRUMENT_OPT_NGRAM;
    ngram_size = atoi(getenv("AFL_LLVM_NGRAM_SIZE"));
    if (ngram_size < 2 || ngram_size > NGRAM_SIZE_MAX)
      FATAL(
          "NGRAM instrumentation mode must be between 2 and NGRAM_SIZE_MAX "
          "(%u)",
          NGRAM_SIZE_MAX);

  }

  if (getenv("AFL_LLVM_CTX_K")) {

    ctx_k = atoi(getenv("AFL_LLVM_CTX_K"));
    if (ctx_k < 1 || ctx_k > CTX_MAX_K)
      FATAL("K-CTX instrumentation mode must be between 1 and CTX_MAX_K (%u)",
            CTX_MAX_K);
    if (ctx_k == 1) {

      setenv("AFL_LLVM_CALLER", "1", 1);
      unsetenv("AFL_LLVM_CTX_K");
      instrument_opt_mode |= INSTRUMENT_OPT_CALLER;

    } else {

      instrument_opt_mode |= INSTRUMENT_OPT_CTX_K;

    }

  }

  if (getenv("AFL_LLVM_INSTRUMENT")) {

    u8 *ptr2 = strtok(getenv("AFL_LLVM_INSTRUMENT"), ":,;");

    while (ptr2) {

      if (strncasecmp(ptr2, "afl", strlen("afl")) == 0 ||
          strncasecmp(ptr2, "classic", strlen("classic")) == 0) {

        if (instrument_mode == INSTRUMENT_LTO) {

          instrument_mode = INSTRUMENT_CLASSIC;
          lto_mode = 1;

        } else if (!instrument_mode || instrument_mode == INSTRUMENT_AFL)

          instrument_mode = INSTRUMENT_AFL;
        else
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strncasecmp(ptr2, "pc-guard", strlen("pc-guard")) == 0 ||
          strncasecmp(ptr2, "pcguard", strlen("pcguard")) == 0) {

        if (!instrument_mode || instrument_mode == INSTRUMENT_PCGUARD)
          instrument_mode = INSTRUMENT_PCGUARD;
        else
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strncasecmp(ptr2, "llvmnative", strlen("llvmnative")) == 0 ||
          strncasecmp(ptr2, "llvm-native", strlen("llvm-native")) == 0) {

        if (!instrument_mode || instrument_mode == INSTRUMENT_LLVMNATIVE)
          instrument_mode = INSTRUMENT_LLVMNATIVE;
        else
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strncasecmp(ptr2, "cfg", strlen("cfg")) == 0 ||
          strncasecmp(ptr2, "instrim", strlen("instrim")) == 0) {

        FATAL(
            "InsTrim instrumentation was removed. Use a modern LLVM and "
            "PCGUARD (default in afl-cc).\n");

      }

      if (strncasecmp(ptr2, "lto", strlen("lto")) == 0) {

        lto_mode = 1;
        if (!instrument_mode || instrument_mode == INSTRUMENT_LTO)
          instrument_mode = INSTRUMENT_LTO;
        else
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);

      }

      if (strcasecmp(ptr2, "gcc") == 0) {

        if (!instrument_mode || instrument_mode == INSTRUMENT_GCC)
          instrument_mode = INSTRUMENT_GCC;
        else if (instrument_mode != INSTRUMENT_GCC)
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);
        compiler_mode = GCC;

      }

      if (strcasecmp(ptr2, "clang") == 0) {

        if (!instrument_mode || instrument_mode == INSTRUMENT_CLANG)
          instrument_mode = INSTRUMENT_CLANG;
        else if (instrument_mode != INSTRUMENT_CLANG)
          FATAL("main instrumentation mode already set with %s",
                instrument_mode_string[instrument_mode]);
        compiler_mode = CLANG;

      }

      if (strncasecmp(ptr2, "ctx-", strlen("ctx-")) == 0 ||
          strncasecmp(ptr2, "kctx-", strlen("c-ctx-")) == 0 ||
          strncasecmp(ptr2, "k-ctx-", strlen("k-ctx-")) == 0) {

        u8 *ptr3 = ptr2;
        while (*ptr3 && (*ptr3 < '0' || *ptr3 > '9'))
          ptr3++;

        if (!*ptr3) {

          if ((ptr3 = getenv("AFL_LLVM_CTX_K")) == NULL)
            FATAL(
                "you must set the K-CTX K with (e.g. for value 2) "
                "AFL_LLVM_INSTRUMENT=ctx-2");

        }

        ctx_k = atoi(ptr3);
        if (ctx_k < 1 || ctx_k > CTX_MAX_K)
          FATAL(
              "K-CTX instrumentation option must be between 1 and CTX_MAX_K "
              "(%u)",
              CTX_MAX_K);

        if (ctx_k == 1) {

          instrument_opt_mode |= INSTRUMENT_OPT_CALLER;
          setenv("AFL_LLVM_CALLER", "1", 1);
          unsetenv("AFL_LLVM_CTX_K");

        } else {

          instrument_opt_mode |= (INSTRUMENT_OPT_CTX_K);
          u8 *ptr4 = alloc_printf("%u", ctx_k);
          setenv("AFL_LLVM_CTX_K", ptr4, 1);

        }

      }

      if (strcasecmp(ptr2, "ctx") == 0) {

        instrument_opt_mode |= INSTRUMENT_OPT_CTX;
        setenv("AFL_LLVM_CTX", "1", 1);

      }

      if (strncasecmp(ptr2, "caller", strlen("caller")) == 0) {

        instrument_opt_mode |= INSTRUMENT_OPT_CALLER;
        setenv("AFL_LLVM_CALLER", "1", 1);

      }

      if (strncasecmp(ptr2, "ngram", strlen("ngram")) == 0) {

        u8 *ptr3 = ptr2 + strlen("ngram");
        while (*ptr3 && (*ptr3 < '0' || *ptr3 > '9'))
          ptr3++;

        if (!*ptr3) {

          if ((ptr3 = getenv("AFL_LLVM_NGRAM_SIZE")) == NULL)
            FATAL(
                "you must set the NGRAM size with (e.g. for value 2) "
                "AFL_LLVM_INSTRUMENT=ngram-2");

        }

        ngram_size = atoi(ptr3);
        if (ngram_size < 2 || ngram_size > NGRAM_SIZE_MAX)
          FATAL(
              "NGRAM instrumentation option must be between 2 and "
              "NGRAM_SIZE_MAX (%u)",
              NGRAM_SIZE_MAX);
        instrument_opt_mode |= (INSTRUMENT_OPT_NGRAM);
        u8 *ptr4 = alloc_printf("%u", ngram_size);
        setenv("AFL_LLVM_NGRAM_SIZE", ptr4, 1);

      }

      ptr2 = strtok(NULL, ":,;");

    }

  }

  if ((instrument_opt_mode & INSTRUMENT_OPT_CTX) &&
      (instrument_opt_mode & INSTRUMENT_OPT_CALLER)) {

    FATAL("you cannot set CTX and CALLER together");

  }

  if ((instrument_opt_mode & INSTRUMENT_OPT_CTX) &&
      (instrument_opt_mode & INSTRUMENT_OPT_CTX_K)) {

    FATAL("you cannot set CTX and K-CTX together");

  }

  if ((instrument_opt_mode & INSTRUMENT_OPT_CALLER) &&
      (instrument_opt_mode & INSTRUMENT_OPT_CTX_K)) {

    FATAL("you cannot set CALLER and K-CTX together");

  }

  if (instrument_opt_mode && instrument_mode == INSTRUMENT_DEFAULT &&
      (compiler_mode == LLVM || compiler_mode == UNSET)) {

    instrument_mode = INSTRUMENT_CLASSIC;
    compiler_mode = LLVM;

  }

  if (!compiler_mode) {

    // lto is not a default because outside of afl-cc RANLIB and AR have to
    // be set to llvm versions so this would work
    if (have_llvm)
      compiler_mode = LLVM;
    else if (have_gcc_plugin)
      compiler_mode = GCC_PLUGIN;
    else if (have_gcc)
#ifdef __APPLE__
      // on OSX clang masquerades as GCC
      compiler_mode = CLANG;
#else
      compiler_mode = GCC;
#endif
    else if (have_lto)
      compiler_mode = LTO;
    else
      FATAL("no compiler mode available");

  }

  if (compiler_mode == GCC) {

    if (clang_mode) {

      instrument_mode = INSTRUMENT_CLANG;

    } else {

      instrument_mode = INSTRUMENT_GCC;

    }

  }

  if (compiler_mode == CLANG) {

    instrument_mode = INSTRUMENT_CLANG;
    setenv(CLANG_ENV_VAR, "1", 1);  // used by afl-as

  }

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
        "  [LTO] llvm LTO:          %s%s\n"
        "      PCGUARD              DEFAULT      yes yes     yes    yes yes "
        "   yes\n"
        "      CLASSIC                           yes yes     yes    yes yes "
        "   yes\n"
        "  [LLVM] llvm:             %s%s\n"
        "      PCGUARD              %s      yes yes     module yes yes    "
        "yes\n"
        "      CLASSIC              %s      no  yes     module yes yes    "
        "yes\n"
        "        - NORMAL\n"
        "        - CALLER\n"
        "        - CTX\n"
        "        - NGRAM-{2-16}\n"
        "  [GCC_PLUGIN] gcc plugin: %s%s\n"
        "      CLASSIC              DEFAULT      no  yes     no     no  no     "
        "yes\n"
        "  [GCC/CLANG] simple gcc/clang: %s%s\n"
        "      CLASSIC              DEFAULT      no  no      no     no  no     "
        "no\n\n",
        have_lto ? "AVAILABLE" : "unavailable!",
        compiler_mode == LTO ? " [SELECTED]" : "",
        have_llvm ? "AVAILABLE" : "unavailable!",
        compiler_mode == LLVM ? " [SELECTED]" : "",
        LLVM_MAJOR >= 7 ? "DEFAULT" : "       ",
        LLVM_MAJOR >= 7 ? "       " : "DEFAULT",
        have_gcc_plugin ? "AVAILABLE" : "unavailable!",
        compiler_mode == GCC_PLUGIN ? " [SELECTED]" : "",
        have_gcc ? "AVAILABLE" : "unavailable!",
        (compiler_mode == GCC || compiler_mode == CLANG) ? " [SELECTED]" : "");

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
        "  DICT:   dictionary in the target [yes=automatic or llvm module "
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

      if (have_gcc_plugin)
        SAYF(
            "\nGCC Plugin-specific environment variables:\n"
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
      if (have_llvm)
        SAYF(
            "\nLLVM/LTO/afl-clang-fast/afl-clang-lto specific environment "
            "variables:\n"
            "  AFL_LLVM_THREADSAFE_INST: instrument with thread safe counters, "
            "disables neverzero\n"

            COUNTER_BEHAVIOUR

            "  AFL_LLVM_DICT2FILE: generate an afl dictionary based on found "
            "comparisons\n"
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

      if (have_llvm)
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
            "CLASSIC)\n");

#ifdef AFL_CLANG_FLTO
      if (have_lto)
        SAYF(
            "\nLTO/afl-clang-lto specific environment variables:\n"
            "  AFL_LLVM_MAP_ADDR: use a fixed coverage map address (speed), "
            "e.g. "
            "0x10000\n"
            "  AFL_LLVM_DOCUMENT_IDS: write all edge IDs and the corresponding "
            "functions\n"
            "    into this file\n"
            "  AFL_LLVM_LTO_DONTWRITEID: don't write the highest ID used to a "
            "global var\n"
            "  AFL_LLVM_LTO_STARTID: from which ID to start counting from for "
            "a "
            "bb\n"
            "  AFL_REAL_LD: use this lld linker instead of the compiled in "
            "path\n"
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
    if (have_lto)
      SAYF("afl-cc LTO with ld=%s %s\n", AFL_REAL_LD, AFL_CLANG_FLTO);
    if (have_llvm)
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
        "AFL_LLVM_CMPLOG and AFL_LLVM_DICT2FILE.\n\n");

    exit(1);

  }

  if (compiler_mode == LTO) {

    if (instrument_mode == 0 || instrument_mode == INSTRUMENT_LTO ||
        instrument_mode == INSTRUMENT_CFG ||
        instrument_mode == INSTRUMENT_PCGUARD) {

      lto_mode = 1;
      // force CFG
      // if (!instrument_mode) {

      instrument_mode = INSTRUMENT_PCGUARD;
      // ptr = instrument_mode_string[instrument_mode];
      // }

    } else if (instrument_mode == INSTRUMENT_CLASSIC) {

      lto_mode = 1;

    } else {

      if (!be_quiet) {

        WARNF("afl-clang-lto called with mode %s, using that mode instead",
              instrument_mode_string[instrument_mode]);

      }

    }

  }

  if (instrument_mode == 0 && compiler_mode < GCC_PLUGIN) {

#if LLVM_MAJOR >= 7
  #if LLVM_MAJOR < 11 && (LLVM_MAJOR < 10 || LLVM_MINOR < 1)
    if (have_instr_env) {

      instrument_mode = INSTRUMENT_AFL;
      if (!be_quiet) {

        WARNF(
            "Switching to classic instrumentation because "
            "AFL_LLVM_ALLOWLIST/DENYLIST does not work with PCGUARD < 10.0.1.");

      }

    } else

  #endif
      instrument_mode = INSTRUMENT_PCGUARD;

#else
    instrument_mode = INSTRUMENT_AFL;
#endif

  }

  if (instrument_opt_mode && compiler_mode != LLVM)
    FATAL("CTX, CALLER and NGRAM can only be used in LLVM mode");

  if (!instrument_opt_mode) {

    if (lto_mode && instrument_mode == INSTRUMENT_CFG)
      instrument_mode = INSTRUMENT_PCGUARD;
    ptr = instrument_mode_string[instrument_mode];

  } else {

    char *ptr2 = alloc_printf(" + NGRAM-%u", ngram_size);
    char *ptr3 = alloc_printf(" + K-CTX-%u", ctx_k);

    ptr = alloc_printf(
        "%s%s%s%s%s", instrument_mode_string[instrument_mode],
        (instrument_opt_mode & INSTRUMENT_OPT_CTX) ? " + CTX" : "",
        (instrument_opt_mode & INSTRUMENT_OPT_CALLER) ? " + CALLER" : "",
        (instrument_opt_mode & INSTRUMENT_OPT_NGRAM) ? ptr2 : "",
        (instrument_opt_mode & INSTRUMENT_OPT_CTX_K) ? ptr3 : "");

    ck_free(ptr2);
    ck_free(ptr3);

  }

#ifndef AFL_CLANG_FLTO
  if (lto_mode)
    FATAL(
        "instrumentation mode LTO specified but LLVM support not available "
        "(requires LLVM 11 or higher)");
#endif

  if (instrument_opt_mode && instrument_mode != INSTRUMENT_CLASSIC)
    FATAL(
        "CALLER, CTX and NGRAM instrumentation options can only be used with "
        "the LLVM CLASSIC instrumentation mode.");

  if (getenv("AFL_LLVM_SKIP_NEVERZERO") && getenv("AFL_LLVM_NOT_ZERO"))
    FATAL(
        "AFL_LLVM_NOT_ZERO and AFL_LLVM_SKIP_NEVERZERO can not be set "
        "together");

#if LLVM_MAJOR < 11 && (LLVM_MAJOR < 10 || LLVM_MINOR < 1)
  if (instrument_mode == INSTRUMENT_PCGUARD && have_instr_env) {

    FATAL(
        "Instrumentation type PCGUARD does not support "
        "AFL_LLVM_ALLOWLIST/DENYLIST! Use LLVM 10.0.1+ instead.");

  }

#endif

  u8 *ptr2;

  if ((ptr2 = getenv("AFL_LLVM_DICT2FILE")) != NULL && *ptr2 != '/')
    FATAL("AFL_LLVM_DICT2FILE must be set to an absolute file path");

  if ((isatty(2) && !be_quiet) || debug) {

    SAYF(cCYA
         "afl-cc" VERSION cRST
         " by Michal Zalewski, Laszlo Szekeres, Marc Heuse - mode: %s-%s\n",
         compiler_mode_string[compiler_mode], ptr);

  }

  if (!be_quiet && (compiler_mode == GCC || compiler_mode == CLANG)) {

    WARNF(
        "You are using outdated instrumentation, install LLVM and/or "
        "gcc-plugin and use afl-clang-fast/afl-clang-lto/afl-gcc-fast "
        "instead!");

  }

  if (debug) {

    DEBUGF("cd '%s';", getthecwd());
    for (i = 0; i < argc; i++)
      SAYF(" '%s'", argv[i]);
    SAYF("\n");
    fflush(stdout);
    fflush(stderr);

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

#if !defined(__ANDROID__) && !defined(ANDROID)
  ptr = find_object("afl-compiler-rt.o", argv[0]);

  if (!ptr) {

    FATAL(
        "Unable to find 'afl-compiler-rt.o'. Please set the AFL_PATH "
        "environment variable.");

  }

  if (debug) { DEBUGF("rt=%s obj_path=%s\n", ptr, obj_path); }

  ck_free(ptr);
#endif

  edit_params(argc, argv, envp);

  if (debug) {

    DEBUGF("cd '%s';", getthecwd());
    for (i = 0; i < (s32)cc_par_cnt; i++)
      SAYF(" '%s'", cc_params[i]);
    SAYF("\n");
    fflush(stdout);
    fflush(stderr);

  }

  if (passthrough) {

    argv[0] = cc_params[0];
    execvp(cc_params[0], (char **)argv);

  } else {

    execvp(cc_params[0], (char **)cc_params);

  }

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}

