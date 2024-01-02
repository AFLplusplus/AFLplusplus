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

param_st parse_linking_params(aflcc_state_t *aflcc, u8 *cur_argv, u8 scan,
                              u8 *skip_next, char **argv) {

  if (aflcc->lto_mode && !strncmp(cur_argv, "-flto=thin", 10)) {

    FATAL(
        "afl-clang-lto cannot work with -flto=thin. Switch to -flto=full or "
        "use afl-clang-fast!");

  }

  param_st final_ = PARAM_MISS;

  if (!strcmp(cur_argv, "-shared") || !strcmp(cur_argv, "-dynamiclib")) {

    if (scan) {

      aflcc->shared_linking = 1;
      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_KEEP;

    }

  } else if (!strcmp(cur_argv, "-Wl,-r") || !strcmp(cur_argv, "-Wl,-i") ||

             !strcmp(cur_argv, "-Wl,--relocatable") ||
             !strcmp(cur_argv, "-r") || !strcmp(cur_argv, "--relocatable")) {

    if (scan) {

      aflcc->partial_linking = 1;
      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_KEEP;

    }

  } else if (!strncmp(cur_argv, "-fuse-ld=", 9) ||

             !strncmp(cur_argv, "--ld-path=", 10)) {

    if (scan) {

      final_ = PARAM_SCAN;

    } else {

      if (aflcc->lto_mode)
        final_ = PARAM_DROP;
      else
        final_ = PARAM_KEEP;

    }

  } else if (!strcmp(cur_argv, "-Wl,-z,defs") ||

             !strcmp(cur_argv, "-Wl,--no-undefined") ||
             !strcmp(cur_argv, "--no-undefined") ||
             strstr(cur_argv, "afl-compiler-rt") ||
             strstr(cur_argv, "afl-llvm-rt")) {

    if (scan) {

      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_DROP;

    }

  } else if (!strcmp(cur_argv, "-z") || !strcmp(cur_argv, "-Wl,-z")) {

    u8 *param = *(argv + 1);
    if (!strcmp(param, "defs") || !strcmp(param, "-Wl,defs")) {

      *skip_next = 1;

      if (scan) {

        final_ = PARAM_SCAN;

      } else {

        final_ = PARAM_DROP;

      }

    }

  }

  if (final_ == PARAM_KEEP) insert_param(aflcc, cur_argv);

  return final_;

}

void add_lto_linker(aflcc_state_t *aflcc) {

  unsetenv("AFL_LD");
  unsetenv("AFL_LD_CALLER");

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
  insert_param(aflcc, alloc_printf("--ld-path=%s", ld_path));
#else
  insert_param(aflcc, alloc_printf("-fuse-ld=%s", ld_path));
#endif
  free(ld_path);

}

void add_lto_passes(aflcc_state_t *aflcc) {

#if defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 15
  // The NewPM implementation only works fully since LLVM 15.
  insert_object(aflcc, "SanitizerCoverageLTO.so", "-Wl,--load-pass-plugin=%s",
                0);
#elif defined(AFL_CLANG_LDPATH) && LLVM_MAJOR >= 13
  insert_param(aflcc, "-Wl,--lto-legacy-pass-manager");
  insert_object(aflcc, "SanitizerCoverageLTO.so", "-Wl,-mllvm=-load=%s", 0);
#else
  insert_param(aflcc, "-fno-experimental-new-pass-manager");
  insert_object(aflcc, "SanitizerCoverageLTO.so", "-Wl,-mllvm=-load=%s", 0);
#endif

  insert_param(aflcc, "-Wl,--allow-multiple-definition");
  insert_param(aflcc, aflcc->lto_flag);

}

static void add_aflpplib(aflcc_state_t *aflcc) {

  if (!aflcc->need_aflpplib) return;

  u8 *afllib = find_object(aflcc, "libAFLDriver.a");

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

    insert_param(aflcc, afllib);

#ifdef __APPLE__
    insert_param(aflcc, "-Wl,-undefined");
    insert_param(aflcc, "dynamic_lookup");
#endif

  }

}

void add_runtime(aflcc_state_t *aflcc) {

  if (aflcc->preprocessor_only || aflcc->have_c || !aflcc->non_dash) {

    /* In the preprocessor_only case (-E), we are not actually compiling at
       all but requesting the compiler to output preprocessed sources only.
       We must not add the runtime in this case because the compiler will
       simply output its binary content back on stdout, breaking any build
       systems that rely on a separate source preprocessing step. */
    return;

  }

  if (aflcc->compiler_mode != GCC_PLUGIN && aflcc->compiler_mode != GCC &&
      !getenv("AFL_LLVM_NO_RPATH")) {

    // in case LLVM is installed not via a package manager or "make install"
    // e.g. compiled download or compiled from github then its ./lib directory
    // might not be in the search path. Add it if so.
    const char *libdir = LLVM_LIBDIR;
    if (aflcc->plusplus_mode && strlen(libdir) && strncmp(libdir, "/usr", 4) &&
        strncmp(libdir, "/lib", 4)) {

      u8 *libdir_opt = strdup("-Wl,-rpath=" LLVM_LIBDIR);
      insert_param(aflcc, libdir_opt);

    }

  }

#ifndef __ANDROID__

  #define M32_ERR_MSG "-m32 is not supported by your compiler"
  #define M64_ERR_MSG "-m64 is not supported by your compiler"

  if (aflcc->compiler_mode != GCC && aflcc->compiler_mode != CLANG) {

    switch (aflcc->bit_mode) {

      case 0:
        if (!aflcc->shared_linking && !aflcc->partial_linking)
          insert_object(aflcc, "afl-compiler-rt.o", 0, 0);
        if (aflcc->lto_mode)
          insert_object(aflcc, "afl-llvm-rt-lto.o", 0, 0);
        break;

      case 32:
        if (!aflcc->shared_linking && !aflcc->partial_linking)
          insert_object(aflcc, "afl-compiler-rt-32.o", 0, M32_ERR_MSG);
        if (aflcc->lto_mode)
          insert_object(aflcc, "afl-llvm-rt-lto-32.o", 0, M32_ERR_MSG);
        break;

      case 64:
        if (!aflcc->shared_linking && !aflcc->partial_linking)
          insert_object(aflcc, "afl-compiler-rt-64.o", 0, M64_ERR_MSG);
        if (aflcc->lto_mode)
          insert_object(aflcc, "afl-llvm-rt-lto-64.o", 0, M64_ERR_MSG);
        break;

    }

  #if !defined(__APPLE__) && !defined(__sun)
    if (!aflcc->shared_linking && !aflcc->partial_linking)
      insert_object(aflcc, "dynamic_list.txt", "-Wl,--dynamic-list=%s", 0);
  #endif

  #if defined(__APPLE__)
    if (aflcc->shared_linking || aflcc->partial_linking) {

      insert_param(aflcc, "-Wl,-U");
      insert_param(aflcc, "-Wl,___afl_area_ptr");
      insert_param(aflcc, "-Wl,-U");
      insert_param(aflcc, "-Wl,___sanitizer_cov_trace_pc_guard_init");

    }
  #endif

  }

#endif

  add_aflpplib(aflcc);

#if defined(USEMMAP) && !defined(__HAIKU__) && !__APPLE__
  insert_param(aflcc, "-Wl,-lrt");
#endif

}

