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

static u8 cwd[4096];

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

char compiler_mode_string[7][12] = {

    "AUTOSELECT", "LLVM-LTO", "LLVM", "GCC_PLUGIN",
    "GCC",        "CLANG",    ""

};

u8 *instrument_mode_2str(instrument_mode_id i) {

  return instrument_mode_string[i];

}

u8 *compiler_mode_2str(compiler_mode_id i) {

  return compiler_mode_string[i];

}

u8 *getthecwd() {

  if (getcwd(cwd, sizeof(cwd)) == NULL) {

    static u8 fail[] = "";
    return fail;

  }

  return cwd;

}

void aflcc_state_init(aflcc_state_t *aflcc, u8 *argv0) {

  // Default NULL/0 is a good start
  memset(aflcc, 0, sizeof(aflcc_state_t));

  aflcc->cc_params = ck_alloc(MAX_PARAMS_NUM * sizeof(u8 *));
  aflcc->cc_par_cnt = 1;

  aflcc->lto_flag = AFL_CLANG_FLTO;

  // aflcc->march_opt = CFLAGS_OPT;

  /* callname & if C++ mode */

  aflcc->argv0 = ck_strdup(argv0);

  char *cname = NULL;

  if ((cname = strrchr(aflcc->argv0, '/')) != NULL)
    cname++;
  else
    cname = aflcc->argv0;

  aflcc->callname = cname;

  if (strlen(cname) > 2 && (strncmp(cname + strlen(cname) - 2, "++", 2) == 0 ||
                            strstr(cname, "-g++") != NULL))
    aflcc->plusplus_mode = 1;

  /* debug */

  if (getenv("AFL_DEBUG")) {

    aflcc->debug = 1;
    if (strcmp(getenv("AFL_DEBUG"), "0") == 0) unsetenv("AFL_DEBUG");

  } else if (getenv("AFL_QUIET"))

    be_quiet = 1;

  if ((getenv("AFL_PASSTHROUGH") || getenv("AFL_NOOPT")) && (!aflcc->debug))

    be_quiet = 1;

}

/*
  in find_object() we look here:

  1. firstly we check the $AFL_PATH environment variable location if set
  2. next we check argv[0] if it has path information and use it
    a) we also check ../lib/afl
  3. if 2. failed we check /proc (only Linux, Android, NetBSD, DragonFly, and
     FreeBSD with procfs)
    a) and check here in ../lib/afl too
  4. we look into the AFL_PATH define (usually /usr/local/lib/afl)
  5. we finally try the current directory

  if all these attempts fail - we return NULL and the caller has to decide
  what to do. Otherwise the path to obj would be allocated and returned.
*/

u8 *find_object(aflcc_state_t *aflcc, u8 *obj) {

  u8 *argv0 = aflcc->argv0;

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash = NULL, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/%s", afl_path, obj);

    if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

    if (!access(tmp, R_OK)) { return tmp; }

    ck_free(tmp);

  }

  if (argv0) {

    slash = strrchr(argv0, '/');

    if (slash) {

      u8 *dir = ck_strdup(argv0);

      slash = strrchr(dir, '/');
      *slash = 0;

      tmp = alloc_printf("%s/%s", dir, obj);

      if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

        ck_free(dir);
        return tmp;

      }

      ck_free(tmp);
      tmp = alloc_printf("%s/../lib/afl/%s", dir, obj);

      if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

      if (!access(tmp, R_OK)) {

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

            if (!access(tmp, R_OK)) { return tmp; }

            ck_free(tmp);
            tmp = alloc_printf("%s/../lib/afl/%s", exepath, obj);

            if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

            if (!access(tmp, R_OK)) { return tmp; }

            ck_free(tmp);

          }

        }

      }

    }

#endif
#undef HAS_PROC_FS

  }

  tmp = alloc_printf("%s/%s", AFL_PATH, obj);

  if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) { return tmp; }

  ck_free(tmp);

  tmp = alloc_printf("./%s", obj);

  if (aflcc->debug) DEBUGF("Trying %s\n", tmp);

  if (!access(tmp, R_OK)) { return tmp; }

  ck_free(tmp);

  if (aflcc->debug) DEBUGF("Trying ... giving up\n");

  return NULL;

}

void find_built_deps(aflcc_state_t *aflcc) {

  char *ptr = NULL;

  if ((ptr = find_object(aflcc, "as")) != NULL) {

    aflcc->have_gcc = 1;
    ck_free(ptr);

  }

  if ((ptr = find_object(aflcc, "SanitizerCoveragePCGUARD.so")) != NULL) {

    aflcc->have_optimized_pcguard = 1;
    ck_free(ptr);

  }

#if (LLVM_MAJOR >= 3)

  if ((ptr = find_object(aflcc, "SanitizerCoverageLTO.so")) != NULL) {

    aflcc->have_lto = 1;
    ck_free(ptr);

  }

  if ((ptr = find_object(aflcc, "cmplog-routines-pass.so")) != NULL) {

    aflcc->have_llvm = 1;
    ck_free(ptr);

  }

#endif

#ifdef __ANDROID__
  aflcc->have_llvm = 1;
#endif

  if ((ptr = find_object(aflcc, "afl-gcc-pass.so")) != NULL) {

    aflcc->have_gcc_plugin = 1;
    ck_free(ptr);

  }

#if !defined(__ANDROID__) && !defined(ANDROID)
  ptr = find_object(aflcc, "afl-compiler-rt.o");

  if (!ptr) {

    FATAL(
        "Unable to find 'afl-compiler-rt.o'. Please set the AFL_PATH "
        "environment variable.");

  }

  if (aflcc->debug) { DEBUGF("rt=%s\n", ptr); }

  ck_free(ptr);
#endif

}

