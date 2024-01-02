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

void add_assembler(aflcc_state_t *aflcc) {

  u8 *afl_as = find_object(aflcc, "as");

  if (!afl_as) FATAL("Cannot find 'as' (symlink to 'afl-as').");

  u8 *slash = strrchr(afl_as, '/');
  if (slash) *slash = 0;

  insert_param(aflcc, "-B");
  insert_param(aflcc, afl_as);

  if (aflcc->compiler_mode == CLANG) insert_param(aflcc, "-no-integrated-as");

}

void add_gcc_plugin(aflcc_state_t *aflcc) {

  if (aflcc->cmplog_mode) {

    insert_object(aflcc, "afl-gcc-cmplog-pass.so", "-fplugin=%s", 0);
    insert_object(aflcc, "afl-gcc-cmptrs-pass.so", "-fplugin=%s", 0);

  }

  insert_object(aflcc, "afl-gcc-pass.so", "-fplugin=%s", 0);

  insert_param(aflcc, "-fno-if-conversion");
  insert_param(aflcc, "-fno-if-conversion2");

}

void add_misc_params(aflcc_state_t *aflcc) {

  if (getenv("AFL_NO_BUILTIN") || getenv("AFL_LLVM_LAF_TRANSFORM_COMPARES") ||
      getenv("LAF_TRANSFORM_COMPARES") || getenv("AFL_LLVM_LAF_ALL") ||
      aflcc->lto_mode) {

    insert_param(aflcc, "-fno-builtin-strcmp");
    insert_param(aflcc, "-fno-builtin-strncmp");
    insert_param(aflcc, "-fno-builtin-strcasecmp");
    insert_param(aflcc, "-fno-builtin-strncasecmp");
    insert_param(aflcc, "-fno-builtin-memcmp");
    insert_param(aflcc, "-fno-builtin-bcmp");
    insert_param(aflcc, "-fno-builtin-strstr");
    insert_param(aflcc, "-fno-builtin-strcasestr");

  }

  if (!aflcc->have_pic) { insert_param(aflcc, "-fPIC"); }

  if (getenv("AFL_HARDEN")) {

    insert_param(aflcc, "-fstack-protector-all");

    if (!aflcc->fortify_set) add_defs_fortify(aflcc, 2);

  }

  if (!getenv("AFL_DONT_OPTIMIZE")) {

    insert_param(aflcc, "-g");
    if (!aflcc->have_o) insert_param(aflcc, "-O3");
    if (!aflcc->have_unroll) insert_param(aflcc, "-funroll-loops");
    // if (strlen(aflcc->march_opt) > 1 && aflcc->march_opt[0] == '-')
    //     insert_param(aflcc, aflcc->march_opt);

  }

  if (aflcc->x_set) {

    insert_param(aflcc, "-x");
    insert_param(aflcc, "none");

  }

}

param_st parse_misc_params(aflcc_state_t *aflcc, u8 *cur_argv, u8 scan) {

  param_st final_ = PARAM_MISS;

#define SCAN_KEEP(dst, src) \
  do {                      \
                            \
    if (scan) {             \
                            \
      dst = src;            \
      final_ = PARAM_SCAN;  \
                            \
    } else {                \
                            \
      final_ = PARAM_KEEP;  \
                            \
    }                       \
                            \
  } while (0)

  if (!strncasecmp(cur_argv, "-fpic", 5)) {

    SCAN_KEEP(aflcc->have_pic, 1);

  } else if (cur_argv[0] != '-') {

    SCAN_KEEP(aflcc->non_dash, 1);

  } else if (!strcmp(cur_argv, "-m32") ||

             !strcmp(cur_argv, "armv7a-linux-androideabi")) {

    SCAN_KEEP(aflcc->bit_mode, 32);

  } else if (!strcmp(cur_argv, "-m64")) {

    SCAN_KEEP(aflcc->bit_mode, 64);

  } else if (strstr(cur_argv, "FORTIFY_SOURCE")) {

    SCAN_KEEP(aflcc->fortify_set, 1);

  } else if (!strcmp(cur_argv, "-x")) {

    SCAN_KEEP(aflcc->x_set, 1);

  } else if (!strcmp(cur_argv, "-E")) {

    SCAN_KEEP(aflcc->preprocessor_only, 1);

  } else if (!strcmp(cur_argv, "--target=wasm32-wasi")) {

    SCAN_KEEP(aflcc->passthrough, 1);

  } else if (!strcmp(cur_argv, "-c")) {

    SCAN_KEEP(aflcc->have_c, 1);

  } else if (!strncmp(cur_argv, "-O", 2)) {

    SCAN_KEEP(aflcc->have_o, 1);

  } else if (!strncmp(cur_argv, "-funroll-loop", 13)) {

    SCAN_KEEP(aflcc->have_unroll, 1);

  } else if (!strncmp(cur_argv, "--afl", 5)) {

    if (scan)
      final_ = PARAM_SCAN;
    else
      final_ = PARAM_DROP;

  } else if (!strncmp(cur_argv, "-fno-unroll", 11)) {

    if (scan)
      final_ = PARAM_SCAN;
    else
      final_ = PARAM_DROP;

  } else if (!strcmp(cur_argv, "-pipe") && aflcc->compiler_mode == GCC_PLUGIN) {

    if (scan)
      final_ = PARAM_SCAN;
    else
      final_ = PARAM_DROP;

  } else if (!strncmp(cur_argv, "-stdlib=", 8) &&

             (aflcc->compiler_mode == GCC ||
              aflcc->compiler_mode == GCC_PLUGIN)) {

    if (scan) {

      final_ = PARAM_SCAN;

    } else {

      if (!be_quiet) WARNF("Found '%s' - stripping!", cur_argv);
      final_ = PARAM_DROP;

    }

  }

#undef SCAN_KEEP

  if (final_ == PARAM_KEEP) insert_param(aflcc, cur_argv);

  return final_;

}

