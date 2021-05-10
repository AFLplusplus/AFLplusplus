/*
  american fuzzy lop++ - wrapper for llvm 11+ lld
  -----------------------------------------------

  Written by Marc Heuse <mh@mh-sec.de> for afl++

  Maintained by Marc Heuse <mh@mh-sec.de>,
                Heiko Eißfeldt <heiko.eissfeldt@hexco.de>
                Andrea Fioraldi <andreafioraldi@gmail.com>
                Dominik Maier <domenukk@gmail.com>

  Copyright 2019-2020 AFLplusplus Project. All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  The sole purpose of this wrapper is to preprocess clang LTO files when
  linking with lld and performing the instrumentation on the whole program.

*/

#define AFL_MAIN
#define _GNU_SOURCE

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>

#include <dirent.h>

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || \
    defined(__DragonFly__)
  #include <limits.h>
#endif

#ifdef __APPLE__
  #include <sys/syslimits.h>
#endif

#define MAX_PARAM_COUNT 4096

static u8 **ld_params;              /* Parameters passed to the real 'ld'   */

static u8 *afl_path = AFL_PATH;
static u8 *real_ld = AFL_REAL_LD;

static u8 be_quiet,                 /* Quiet mode (no stderr output)        */
    debug,                          /* AFL_DEBUG                            */
    passthrough,                    /* AFL_LD_PASSTHROUGH - no link+optimize*/
    just_version;                   /* Just show version?                   */

static u32 ld_param_cnt = 1;        /* Number of params to 'ld'             */

/* Examine and modify parameters to pass to 'ld', 'llvm-link' and 'llmv-ar'.
   Note that the file name is always the last parameter passed by GCC,
   so we exploit this property to keep the code "simple". */
static void edit_params(int argc, char **argv) {

  u32 i, gold_pos = 0, gold_present = 0, rt_present = 0, rt_lto_present = 0,
         inst_present = 0;
  char *ptr;

  ld_params = ck_alloc(4096 * sizeof(u8 *));

  ld_params[0] = (u8 *)real_ld;

  if (!passthrough) {

    for (i = 1; i < (u32)argc; i++) {

      if (strstr(argv[i], "/afl-llvm-rt-lto.o") != NULL) rt_lto_present = 1;
      if (strstr(argv[i], "/afl-llvm-rt.o") != NULL) rt_present = 1;
      if (strstr(argv[i], "/afl-llvm-lto-instr") != NULL) inst_present = 1;

    }

    for (i = 1; i < (u32)argc && !gold_pos; i++) {

      if (strcmp(argv[i], "-plugin") == 0) {

        if (strncmp(argv[i], "-plugin=", strlen("-plugin=")) == 0) {

          if (strcasestr(argv[i], "LLVMgold.so") != NULL)
            gold_present = gold_pos = i + 1;

        } else if (i < (u32)argc &&

                   strcasestr(argv[i + 1], "LLVMgold.so") != NULL) {

          gold_present = gold_pos = i + 2;

        }

      }

    }

    if (!gold_pos) {

      for (i = 1; i + 1 < (u32)argc && !gold_pos; i++) {

        if (argv[i][0] != '-') {

          if (argv[i - 1][0] == '-') {

            switch (argv[i - 1][1]) {

              case 'b':
                break;
              case 'd':
                break;
              case 'e':
                break;
              case 'F':
                break;
              case 'f':
                break;
              case 'I':
                break;
              case 'l':
                break;
              case 'L':
                break;
              case 'm':
                break;
              case 'o':
                break;
              case 'O':
                break;
              case 'p':
                if (index(argv[i - 1], '=') == NULL) gold_pos = i;
                break;
              case 'R':
                break;
              case 'T':
                break;
              case 'u':
                break;
              case 'y':
                break;
              case 'z':
                break;
              case '-': {

                if (strcmp(argv[i - 1], "--oformat") == 0) break;
                if (strcmp(argv[i - 1], "--output") == 0) break;
                if (strncmp(argv[i - 1], "--opt-remarks-", 14) == 0) break;
                gold_pos = i;
                break;

              }

              default:
                gold_pos = i;

            }

          } else

            gold_pos = i;

        }

      }

    }

    if (!gold_pos) gold_pos = 1;

  }

  if (getenv("AFL_LLVM_INSTRIM") ||
      ((ptr = getenv("AFL_LLVM_INSTRUMENT")) &&
       (strcasestr(ptr, "CFG") == 0 || strcasestr(ptr, "INSTRIM") == 0)))
    FATAL(
        "InsTrim was removed because it is not effective. Use a modern LLVM "
        "and PCGUARD (which is the default in afl-cc).\n");

  if (debug)
    DEBUGF(
        "passthrough=%s, gold_pos=%u, gold_present=%s "
        "inst_present=%s rt_present=%s rt_lto_present=%s\n",
        passthrough ? "true" : "false", gold_pos,
        gold_present ? "true" : "false", inst_present ? "true" : "false",
        rt_present ? "true" : "false", rt_lto_present ? "true" : "false");

  for (i = 1; i < (u32)argc; i++) {

    if (ld_param_cnt >= MAX_PARAM_COUNT)
      FATAL(
          "Too many command line parameters because of unpacking .a archives, "
          "this would need to be done by hand ... sorry! :-(");

    if (strcmp(argv[i], "--afl") == 0) {

      if (!be_quiet) OKF("afl++ test command line flag detected, exiting.");
      exit(0);

    }

    if (i == gold_pos && !passthrough) {

      ld_params[ld_param_cnt++] = alloc_printf("-L%s/../lib", LLVM_BINDIR);

      if (!gold_present) {

        ld_params[ld_param_cnt++] = "-plugin";
        ld_params[ld_param_cnt++] =
            alloc_printf("%s/../lib/LLVMgold.so", LLVM_BINDIR);

      }

      ld_params[ld_param_cnt++] = "--allow-multiple-definition";

      if (!inst_present) {

        ld_params[ld_param_cnt++] = alloc_printf(
            "-mllvm=-load=%s/afl-llvm-lto-instrumentation.so", afl_path);

      }

      if (!rt_present)
        ld_params[ld_param_cnt++] = alloc_printf("%s/afl-llvm-rt.o", afl_path);
      if (!rt_lto_present)
        ld_params[ld_param_cnt++] =
            alloc_printf("%s/afl-llvm-rt-lto.o", afl_path);

    }

    ld_params[ld_param_cnt++] = argv[i];

  }

  ld_params[ld_param_cnt] = NULL;

}

/* Main entry point */

int main(int argc, char **argv) {

  s32  pid, i, status;
  char thecwd[PATH_MAX];

  if (getenv("AFL_LD_CALLER") != NULL) {

    FATAL("ld loop detected! Set AFL_REAL_LD!\n");

  }

  if (isatty(2) && !getenv("AFL_QUIET") && !getenv("AFL_DEBUG")) {

    SAYF(cCYA "afl-ld-to" VERSION cRST
              " by Marc \"vanHauser\" Heuse <mh@mh-sec.de>\n");

  } else

    be_quiet = 1;

  if (getenv("AFL_DEBUG") != NULL) debug = 1;
  if (getenv("AFL_PATH") != NULL) afl_path = getenv("AFL_PATH");
  if (getenv("AFL_LD_PASSTHROUGH") != NULL) passthrough = 1;
  if (getenv("AFL_REAL_LD") != NULL) real_ld = getenv("AFL_REAL_LD");

  if (!afl_path || !*afl_path) afl_path = "/usr/local/lib/afl";

  setenv("AFL_LD_CALLER", "1", 1);

  if (debug) {

    if (getcwd(thecwd, sizeof(thecwd)) != 0) strcpy(thecwd, ".");

    DEBUGF("cd \"%s\";", thecwd);
    for (i = 0; i < argc; i++)
      SAYF(" \"%s\"", argv[i]);
    SAYF("\n");

  }

  if (argc < 2) {

    SAYF(
        "\n"
        "This is a helper application for afl-clang-lto.\n"
        "It is a wrapper around llvm's 'lld' in case afl-clang-lto cannot be "
        "used.\n"
        "Note that the target still has to be compiled with -flto=full!\n"
        "You probably don't want to run this program directly but rather pass "
        "it as LD\nparameter to e.g. configure scripts.\n\n"

        "Environment variables:\n"
        "  AFL_LD_PASSTHROUGH   do not link+optimize == no instrumentation\n"
        "  AFL_REAL_LD          point to the real llvm 11 lld if necessary\n"

        "\nafl-ld-to was compiled with the fixed real 'ld' of %s and the "
        "binary path of %s\n\n",
        real_ld, LLVM_BINDIR);

    exit(1);

  }

  edit_params(argc, argv);  // here most of the magic happens :-)

  if (debug) {

    DEBUGF("cd \"%s\";", thecwd);
    for (i = 0; i < (s32)ld_param_cnt; i++)
      SAYF(" \"%s\"", ld_params[i]);
    SAYF("\n");

  }

  if (!(pid = fork())) {

    if (strlen(real_ld) > 1) execvp(real_ld, (char **)ld_params);
    execvp("ld", (char **)ld_params);  // fallback
    FATAL("Oops, failed to execute 'ld' - check your PATH");

  }

  if (pid < 0) PFATAL("fork() failed");

  if (waitpid(pid, &status, 0) <= 0) PFATAL("waitpid() failed");
  if (debug) DEBUGF("linker result: %d\n", status);

  if (!just_version) {

    if (status == 0) {

      if (!be_quiet) OKF("Linker was successful");

    } else {

      SAYF(cLRD "[-] " cRST
                "Linker failed, please investigate and send a bug report. Most "
                "likely an 'ld' option is incompatible with %s.\n",
           AFL_CLANG_FLTO);

    }

  }

  exit(WEXITSTATUS(status));

}

