/*
   american fuzzy lop++ - wrapper for GCC and clang
   ------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This program is a drop-in replacement for GCC or clang. The most common way
   of using it is to pass the path to afl-gcc or afl-clang via CC when invoking
   ./configure.

   (Of course, use CXX and point it to afl-g++ / afl-clang++ for C++ code.)

   The wrapper needs to know the path to afl-as (renamed to 'as'). The default
   is /usr/local/lib/afl/. A convenient way to specify alternative directories
   would be to set AFL_PATH.

   If AFL_HARDEN is set, the wrapper will compile the target app with various
   hardening options that may help detect memory management issues more
   reliably. You can also specify AFL_USE_ASAN to enable ASAN.

   If you want to call a non-default compiler as a next step of the chain,
   specify its location via AFL_CC or AFL_CXX.

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

static u8 * as_path;                   /* Path to the AFL 'as' wrapper      */
static u8 **cc_params;                 /* Parameters passed to the real CC  */
static u32  cc_par_cnt = 1;            /* Param count, including argv0      */
static u8   be_quiet,                  /* Quiet mode                        */
    clang_mode;                        /* Invoked as afl-clang*?            */

/* Try to find our "fake" GNU assembler in AFL_PATH or at the location derived
   from argv[0]. If that fails, abort. */

static void find_as(u8 *argv0) {

  u8 *afl_path = getenv("AFL_PATH");
  u8 *slash, *tmp;

  if (afl_path) {

    tmp = alloc_printf("%s/as", afl_path);

    if (!access(tmp, X_OK)) {

      as_path = afl_path;
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

    tmp = alloc_printf("%s/afl-as", dir);

    if (!access(tmp, X_OK)) {

      as_path = dir;
      ck_free(tmp);
      return;

    }

    ck_free(tmp);
    ck_free(dir);

  }

  if (!access(AFL_PATH "/as", X_OK)) {

    as_path = AFL_PATH;
    return;

  }

  FATAL("Unable to find AFL wrapper binary for 'as'. Please set AFL_PATH");

}

/* Copy argv to cc_params, making the necessary edits. */

static void edit_params(u32 argc, char **argv) {

  u8  fortify_set = 0, asan_set = 0;
  u8 *name;

#if defined(__FreeBSD__) && defined(WORD_SIZE_64)
  u8 m32_set = 0;
#endif

  cc_params = ck_alloc((argc + 128) * sizeof(u8 *));

  name = strrchr(argv[0], '/');
  if (!name) {

    name = argv[0];

  } else {

    ++name;

  }

  if (!strncmp(name, "afl-clang", 9)) {

    clang_mode = 1;

    setenv(CLANG_ENV_VAR, "1", 1);

    if (!strcmp(name, "afl-clang++")) {

      u8 *alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx && *alt_cxx ? alt_cxx : (u8 *)"clang++";

    } else if (!strcmp(name, "afl-clang")) {

      u8 *alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc && *alt_cc ? alt_cc : (u8 *)"clang";

    } else {

      fprintf(stderr, "Name of the binary: %s\n", argv[0]);
      FATAL("Name of the binary is not a known name, expected afl-clang(++)");

    }

  } else {

    /* With GCJ and Eclipse installed, you can actually compile Java! The
       instrumentation will work (amazingly). Alas, unhandled exceptions do
       not call abort(), so afl-fuzz would need to be modified to equate
       non-zero exit codes with crash conditions when working with Java
       binaries. Meh. */

#ifdef __APPLE__

    if (!strcmp(name, "afl-g++")) {

      cc_params[0] = getenv("AFL_CXX");

    } else if (!strcmp(name, "afl-gcj")) {

      cc_params[0] = getenv("AFL_GCJ");

    } else if (!strcmp(name, "afl-gcc")) {

      cc_params[0] = getenv("AFL_CC");

    } else {

      fprintf(stderr, "Name of the binary: %s\n", argv[0]);
      FATAL("Name of the binary is not a known name, expected afl-gcc/g++/gcj");

    }

    if (!cc_params[0]) {

      SAYF("\n" cLRD "[-] " cRST
           "On Apple systems, 'gcc' is usually just a wrapper for clang. "
           "Please use the\n"
           "    'afl-clang' utility instead of 'afl-gcc'. If you really have "
           "GCC installed,\n"
           "    set AFL_CC or AFL_CXX to specify the correct path to that "
           "compiler.\n");

      FATAL("AFL_CC or AFL_CXX required on MacOS X");

    }

#else

    if (!strcmp(name, "afl-g++")) {

      u8 *alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx && *alt_cxx ? alt_cxx : (u8 *)"g++";

    } else if (!strcmp(name, "afl-gcj")) {

      u8 *alt_cc = getenv("AFL_GCJ");
      cc_params[0] = alt_cc && *alt_cc ? alt_cc : (u8 *)"gcj";

    } else if (!strcmp(name, "afl-gcc")) {

      u8 *alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc && *alt_cc ? alt_cc : (u8 *)"gcc";

    } else {

      fprintf(stderr, "Name of the binary: %s\n", argv[0]);
      FATAL("Name of the binary is not a known name, expected afl-gcc/g++/gcj");

    }

#endif                                                         /* __APPLE__ */

  }

  while (--argc) {

    u8 *cur = *(++argv);

    if (!strncmp(cur, "-B", 2)) {

      if (!be_quiet) { WARNF("-B is already set, overriding"); }

      if (!cur[2] && argc > 1) {

        argc--;
        argv++;

      }

      continue;

    }

    if (!strcmp(cur, "-integrated-as")) { continue; }

    if (!strcmp(cur, "-pipe")) { continue; }

#if defined(__FreeBSD__) && defined(WORD_SIZE_64)
    if (!strcmp(cur, "-m32")) m32_set = 1;
#endif

    if (!strcmp(cur, "-fsanitize=address") ||
        !strcmp(cur, "-fsanitize=memory")) {

      asan_set = 1;

    }

    if (strstr(cur, "FORTIFY_SOURCE")) { fortify_set = 1; }

    cc_params[cc_par_cnt++] = cur;

  }

  cc_params[cc_par_cnt++] = "-B";
  cc_params[cc_par_cnt++] = as_path;

  if (clang_mode) { cc_params[cc_par_cnt++] = "-no-integrated-as"; }

  if (getenv("AFL_HARDEN")) {

    cc_params[cc_par_cnt++] = "-fstack-protector-all";

    if (!fortify_set) { cc_params[cc_par_cnt++] = "-D_FORTIFY_SOURCE=2"; }

  }

  if (asan_set) {

    /* Pass this on to afl-as to adjust map density. */

    setenv("AFL_USE_ASAN", "1", 1);

  } else if (getenv("AFL_USE_ASAN")) {

    if (getenv("AFL_USE_MSAN")) {

      FATAL("ASAN and MSAN are mutually exclusive");

    }

    if (getenv("AFL_HARDEN")) {

      FATAL("ASAN and AFL_HARDEN are mutually exclusive");

    }

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=address";

  } else if (getenv("AFL_USE_MSAN")) {

    if (getenv("AFL_USE_ASAN")) {

      FATAL("ASAN and MSAN are mutually exclusive");

    }

    if (getenv("AFL_HARDEN")) {

      FATAL("MSAN and AFL_HARDEN are mutually exclusive");

    }

    cc_params[cc_par_cnt++] = "-U_FORTIFY_SOURCE";
    cc_params[cc_par_cnt++] = "-fsanitize=memory";

  }

  if (getenv("AFL_USE_UBSAN")) {

    cc_params[cc_par_cnt++] = "-fsanitize=undefined";
    cc_params[cc_par_cnt++] = "-fsanitize-undefined-trap-on-error";
    cc_params[cc_par_cnt++] = "-fno-sanitize-recover=all";

  }

#ifdef USEMMAP
  cc_params[cc_par_cnt++] = "-lrt";
#endif

  if (!getenv("AFL_DONT_OPTIMIZE")) {

#if defined(__FreeBSD__) && defined(WORD_SIZE_64)

    /* On 64-bit FreeBSD systems, clang -g -m32 is broken, but -m32 itself
       works OK. This has nothing to do with us, but let's avoid triggering
       that bug. */

    if (!clang_mode || !m32_set) cc_params[cc_par_cnt++] = "-g";

#else

    cc_params[cc_par_cnt++] = "-g";

#endif

    cc_params[cc_par_cnt++] = "-O3";
    cc_params[cc_par_cnt++] = "-funroll-loops";

    /* Two indicators that you're building for fuzzing; one of them is
       AFL-specific, the other is shared with libfuzzer. */

    cc_params[cc_par_cnt++] = "-D__AFL_COMPILER=1";
    cc_params[cc_par_cnt++] = "-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1";

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

  cc_params[cc_par_cnt] = NULL;

}

/* Main entry point */

int main(int argc, char **argv) {

  char *env_info =
      "Environment variables used by afl-gcc:\n"
      "AFL_CC: path to the C compiler to use\n"
      "AFL_CXX: path to the C++ compiler to use\n"
      "AFL_GCJ: path to the java compiler to use\n"
      "AFL_PATH: path to the instrumenting assembler\n"
      "AFL_DONT_OPTIMIZE: disable optimization instead of -O3\n"
      "AFL_NO_BUILTIN: compile for use with libtokencap.so\n"
      "AFL_QUIET: suppress verbose output\n"
      "AFL_CAL_FAST: speed up the initial calibration\n"
      "AFL_HARDEN: adds code hardening to catch memory bugs\n"
      "AFL_USE_ASAN: activate address sanitizer\n"
      "AFL_USE_MSAN: activate memory sanitizer\n"
      "AFL_USE_UBSAN: activate undefined behaviour sanitizer\n"

      "\nEnvironment variables used by afl-as (called by afl-gcc):\n"
      "AFL_AS: path to the assembler to use\n"
      "TMPDIR: set the directory for temporary files of afl-as\n"
      "TEMP: fall back path to directory for temporary files\n"
      "TMP: fall back path to directory for temporary files\n"
      "AFL_INST_RATIO: percentage of branches to instrument\n"
      "AFL_QUIET: suppress verbose output\n"
      "AFL_KEEP_ASSEMBLY: leave instrumented assembly files\n"
      "AFL_AS_FORCE_INSTRUMENT: force instrumentation for asm sources\n";

  if (argc == 2 && strcmp(argv[1], "-h") == 0) {

    printf("afl-cc" VERSION " by Michal Zalewski\n\n");
    printf("%s \n\n", argv[0]);
    printf("afl-gcc has no command line options\n\n%s\n", env_info);
    printf(
        "NOTE: afl-gcc is deprecated, llvm_mode is much faster and has more "
        "options\n");
    return -1;

  }

  if ((isatty(2) && !getenv("AFL_QUIET")) || getenv("AFL_DEBUG") != NULL) {

    SAYF(cCYA "afl-cc" VERSION cRST " by Michal Zalewski\n");
    SAYF(cYEL "[!] " cBRI "NOTE: " cRST
              "afl-gcc is deprecated, llvm_mode is much faster and has more "
              "options\n");

  } else {

    be_quiet = 1;

  }

  if (argc < 2) {

    SAYF(
        "\n"
        "This is a helper application for afl-fuzz. It serves as a drop-in "
        "replacement\n"
        "for gcc or clang, letting you recompile third-party code with the "
        "required\n"
        "runtime instrumentation. A common use pattern would be one of the "
        "following:\n\n"

        "  CC=%s/afl-gcc ./configure\n"
        "  CXX=%s/afl-g++ ./configure\n\n%s"

        ,
        BIN_PATH, BIN_PATH, env_info);

    exit(1);

  }

  u8 *ptr;
  if (!be_quiet &&
      ((ptr = getenv("AFL_MAP_SIZE")) || (ptr = getenv("AFL_MAPSIZE")))) {

    u32 map_size = atoi(ptr);
    if (map_size != MAP_SIZE) {

      FATAL("AFL_MAP_SIZE is not supported by afl-gcc");

    }

  }

  find_as(argv[0]);

  edit_params(argc, argv);

  execvp(cc_params[0], (char **)cc_params);

  FATAL("Oops, failed to execute '%s' - check your PATH", cc_params[0]);

  return 0;

}

