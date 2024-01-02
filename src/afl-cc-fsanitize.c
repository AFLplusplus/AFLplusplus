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

/* For input "-fsanitize=...", it:

  1. may have various OOB traps :) if ... doesn't contain ',' or
    the input has bad syntax such as "-fsantiz=,"
  2. strips any fuzzer* in ... and writes back (may result in "-fsanitize=")
  3. rets 1 if exactly "fuzzer" found, otherwise rets 0
*/
static u8 fsanitize_fuzzer_comma(char *string) {

  u8 detect_single_fuzzer = 0;

  char *p, *ptr = string + strlen("-fsanitize=");
  // ck_alloc will check alloc failure
  char *new = ck_alloc(strlen(string) + 1);
  char *tmp = ck_alloc(strlen(ptr) + 1);
  u32   count = 0, len, ende = 0;

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

          detect_single_fuzzer = 1;
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

  ck_free(tmp);
  ck_free(new);

  return detect_single_fuzzer;

}

param_st parse_fsanitize(aflcc_state_t *aflcc, u8 *cur_argv, u8 scan) {

  param_st final_ = PARAM_MISS;

  if (!strncmp(cur_argv, "-fsanitize-coverage-", 20) &&
      strstr(cur_argv, "list=")) {

    if (scan) {

      aflcc->have_instr_list = 1;
      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_KEEP;  // may be set to DROP next

    }

  }

  if (!strcmp(cur_argv, "-fsanitize=fuzzer")) {

    if (scan) {

      aflcc->need_aflpplib = 1;
      final_ = PARAM_SCAN;

    } else {

      final_ = PARAM_DROP;

    }

  } else if (!strncmp(cur_argv, "-fsanitize=", strlen("-fsanitize=")) &&

             strchr(cur_argv, ',') &&
             !strstr(cur_argv, "=,")) {  // avoid OOB errors

    if (scan) {

      u8 *cur_argv_ = ck_strdup(cur_argv);

      if (fsanitize_fuzzer_comma(cur_argv_)) {

        aflcc->need_aflpplib = 1;
        final_ = PARAM_SCAN;

      }

      ck_free(cur_argv_);

    } else {

      fsanitize_fuzzer_comma(cur_argv);
      if (!cur_argv || strlen(cur_argv) <= strlen("-fsanitize="))
        final_ = PARAM_DROP;  // this means it only has "fuzzer" previously.

    }

  } else if ((!strncmp(cur_argv, "-fsanitize=fuzzer-",
                          strlen("-fsanitize=fuzzer-")) ||
              !strncmp(cur_argv, "-fsanitize-coverage",
                          strlen("-fsanitize-coverage"))) &&
              (strncmp(cur_argv, "sanitize-coverage-allow",
                          strlen("sanitize-coverage-allow")) &&
              strncmp(cur_argv, "sanitize-coverage-deny",
                         strlen("sanitize-coverage-deny")) &&
              aflcc->instrument_mode != INSTRUMENT_LLVMNATIVE)) {

    if (scan) {

      final_ = PARAM_SCAN;

    } else {

      if (!be_quiet) { WARNF("Found '%s' - stripping!", cur_argv); }
      final_ = PARAM_DROP;

    }

  }

  if (!strcmp(cur_argv, "-fsanitize=address") ||
      !strcmp(cur_argv, "-fsanitize=memory")) {

    if (scan) {

      // "-fsanitize=undefined,address" may be un-treated, but it's OK.
      aflcc->asan_set = 1;
      final_ = PARAM_SCAN;

    } else {

      // It's impossible that final_ is PARAM_DROP before,
      // so no checks are needed here.
      final_ = PARAM_KEEP;

    }

  }

  if (final_ == PARAM_KEEP) insert_param(aflcc, cur_argv);

  return final_;

}

void add_sanitizers(aflcc_state_t *aflcc, char **envp) {

  if (!aflcc->asan_set) {

    if (getenv("AFL_USE_ASAN")) {

      if (getenv("AFL_USE_MSAN")) FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("ASAN and AFL_HARDEN are mutually exclusive");

      set_fortification(aflcc, 0);
      insert_param(aflcc, "-fsanitize=address");

    } else if (getenv("AFL_USE_MSAN")) {

      if (getenv("AFL_USE_ASAN")) FATAL("ASAN and MSAN are mutually exclusive");

      if (getenv("AFL_HARDEN"))
        FATAL("MSAN and AFL_HARDEN are mutually exclusive");

      set_fortification(aflcc, 0);
      insert_param(aflcc, "-fsanitize=memory");

    }

  }

  if (getenv("AFL_USE_UBSAN")) {

    insert_param(aflcc, "-fsanitize=undefined");
    insert_param(aflcc, "-fsanitize-undefined-trap-on-error");
    insert_param(aflcc, "-fno-sanitize-recover=all");
    insert_param(aflcc, "-fno-omit-frame-pointer");

  }

  if (getenv("AFL_USE_TSAN")) {

    insert_param(aflcc, "-fsanitize=thread");
    insert_param(aflcc, "-fno-omit-frame-pointer");

  }

  if (getenv("AFL_USE_LSAN")) {

    insert_param(aflcc, "-fsanitize=leak");
    add_lsan_ctrl(aflcc);

  }

  if (getenv("AFL_USE_CFISAN")) {

    if (aflcc->compiler_mode == GCC_PLUGIN || aflcc->compiler_mode == GCC) {

      insert_param(aflcc, "-fcf-protection=full");

    } else {

      if (!aflcc->lto_mode) {

        uint32_t i = 0, found = 0;
        while (envp[i] != NULL && !found)
          if (strncmp("-flto", envp[i++], 5) == 0) found = 1;
        if (!found) insert_param(aflcc, "-flto");

      }

      insert_param(aflcc, "-fsanitize=cfi");
      insert_param(aflcc, "-fvisibility=hidden");

    }

  }

}

void add_native_pcguard(aflcc_state_t *aflcc) {

  /* If llvm-config doesn't figure out LLVM_MAJOR, just
   go on anyway and let compiler complain if doesn't work. */

  if (aflcc->instrument_opt_mode & INSTRUMENT_OPT_CODECOV) {

#if LLVM_MAJOR > 0 && LLVM_MAJOR < 6
    FATAL("pcguard instrumentation with pc-table requires LLVM 6.0.1+");
#else
  #if LLVM_MAJOR == 0
    WARNF(
        "pcguard instrumentation with pc-table requires LLVM 6.0.1+"
        " otherwise the compiler will fail");
  #endif
    insert_param(aflcc,
                 "-fsanitize-coverage=trace-pc-guard,bb,no-prune,pc-table");
#endif

  } else {

#if LLVM_MAJOR > 0 && LLVM_MAJOR < 4
    FATAL("pcguard instrumentation requires LLVM 4.0.1+");
#else
  #if LLVM_MAJOR == 0
    WARNF(
        "pcguard instrumentation requires LLVM 4.0.1+"
        " otherwise the compiler will fail");
  #endif
    insert_param(aflcc, "-fsanitize-coverage=trace-pc-guard");
#endif

  }

}

void add_optimized_pcguard(aflcc_state_t *aflcc) {

#if LLVM_MAJOR >= 13
  #if defined __ANDROID__ || ANDROID

  insert_param(aflcc, "-fsanitize-coverage=trace-pc-guard");
  aflcc->instrument_mode = INSTRUMENT_LLVMNATIVE;

  #else

  if (aflcc->have_instr_list) {

    if (!be_quiet)
      SAYF(
          "Using unoptimized trace-pc-guard, due usage of "
          "-fsanitize-coverage-allow/denylist, you can use "
          "AFL_LLVM_ALLOWLIST/AFL_LLMV_DENYLIST instead.\n");

    insert_param(aflcc, "-fsanitize-coverage=trace-pc-guard");
    aflcc->instrument_mode = INSTRUMENT_LLVMNATIVE;

  } else {

    /* Since LLVM_MAJOR >= 13 we use new pass manager */
    #if LLVM_MAJOR < 16
    insert_param(aflcc, "-fexperimental-new-pass-manager");
    #endif
    insert_object(aflcc, "SanitizerCoveragePCGUARD.so", "-fpass-plugin=%s", 0);

  }

  #endif  // defined __ANDROID__ || ANDROID
#else     // LLVM_MAJOR < 13
  #if LLVM_MAJOR >= 4

  if (!be_quiet)
    SAYF(
        "Using unoptimized trace-pc-guard, upgrade to LLVM 13+ for "
        "enhanced version.\n");
  insert_param(aflcc, "-fsanitize-coverage=trace-pc-guard");
  aflcc->instrument_mode = INSTRUMENT_LLVMNATIVE;

  #else

  FATAL("pcguard instrumentation requires LLVM 4.0.1+");

  #endif
#endif

}

