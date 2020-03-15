/*
   american fuzzy lop++ - common routines
   --------------------------------------

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

   Gather some functions common to multiple executables

   - detect_file_args

 */

#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include "debug.h"
#include "alloc-inl.h"
#include "envs.h"

/* Detect @@ in args. */
#ifndef __glibc__
#include <unistd.h>
#endif
#include <limits.h>

extern u8 be_quiet;
char *    afl_environment_variables[] = {

    "AFL_ALIGNED_ALLOC", "AFL_ALLOW_TMP", "AFL_ANALYZE_HEX", "AFL_AS",
    "AFL_AUTORESUME", "AFL_AS_FORCE_INSTRUMENT", "AFL_BENCH_JUST_ONE",
    "AFL_BENCH_UNTIL_CRASH", "AFL_CAL_FAST", "AFL_CC", "AFL_CMIN_ALLOW_ANY",
    "AFL_CMIN_CRASHES_ONLY", "AFL_CODE_END", "AFL_CODE_START",
    "AFL_COMPCOV_BINNAME", "AFL_COMPCOV_LEVEL", "AFL_CUSTOM_MUTATOR_LIBRARY",
    "AFL_CUSTOM_MUTATOR_ONLY", "AFL_CXX", "AFL_DEBUG", "AFL_DEBUG_CHILD_OUTPUT",
    //"AFL_DEFER_FORKSRV", // not implemented anymore, so warn additionally
    "AFL_DISABLE_TRIM", "AFL_DONT_OPTIMIZE", "AFL_DUMB_FORKSRV",
    "AFL_ENTRYPOINT", "AFL_EXIT_WHEN_DONE", "AFL_FAST_CAL", "AFL_FORCE_UI",
    "AFL_GCC_WHITELIST", "AFL_GCJ", "AFL_HANG_TMOUT", "AFL_HARDEN",
    "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "AFL_IMPORT_FIRST",
    "AFL_INST_LIBS", "AFL_INST_RATIO", "AFL_KEEP_TRACES", "AFL_KEEP_ASSEMBLY",
    "AFL_LD_HARD_FAIL", "AFL_LD_LIMIT_MB", "AFL_LD_NO_CALLOC_OVER",
    "AFL_LD_PRELOAD", "AFL_LD_VERBOSE", "AFL_LLVM_CMPLOG", "AFL_LLVM_INSTRIM",
    "AFL_LLVM_INSTRIM_LOOPHEAD", "AFL_LLVM_INSTRIM_SKIPSINGLEBLOCK",
    "AFL_LLVM_LAF_SPLIT_COMPARES", "AFL_LLVM_LAF_SPLIT_COMPARES_BITW",
    "AFL_LLVM_LAF_SPLIT_FLOATS", "AFL_LLVM_LAF_SPLIT_SWITCHES",
    "AFL_LLVM_LAF_TRANSFORM_COMPARES", "AFL_LLVM_NOT_ZERO",
    "AFL_LLVM_WHITELIST", "AFL_NO_AFFINITY", "AFL_LLVM_LTO_STARTID",
    "AFL_LLVM_LTO_DONTWRITEID", "AFL_NO_ARITH", "AFL_NO_BUILTIN",
    "AFL_NO_CPU_RED", "AFL_NO_FORKSRV", "AFL_NO_UI",
    "AFL_NO_X86",  // not really an env but we dont want to warn on it
    "AFL_PATH", "AFL_PERFORMANCE_FILE",
    //"AFL_PERSISTENT", // not implemented anymore, so warn additionally
    "AFL_POST_LIBRARY", "AFL_PRELOAD", "AFL_PYTHON_MODULE", "AFL_QEMU_COMPCOV",
    "AFL_QEMU_COMPCOV_DEBUG", "AFL_QEMU_DEBUG_MAPS", "AFL_QEMU_DISABLE_CACHE",
    "AFL_QEMU_PERSISTENT_ADDR", "AFL_QEMU_PERSISTENT_CNT",
    "AFL_QEMU_PERSISTENT_GPR", "AFL_QEMU_PERSISTENT_HOOK",
    "AFL_QEMU_PERSISTENT_RET", "AFL_QEMU_PERSISTENT_RETADDR_OFFSET",
    "AFL_QUIET", "AFL_RANDOM_ALLOC_CANARY", "AFL_REAL_PATH",
    "AFL_SHUFFLE_QUEUE", "AFL_SKIP_BIN_CHECK", "AFL_SKIP_CPUFREQ",
    "AFL_SKIP_CRASHES", "AFL_TMIN_EXACT", "AFL_TMPDIR", "AFL_TOKEN_FILE",
    "AFL_TRACE_PC", "AFL_USE_ASAN", "AFL_USE_MSAN", "AFL_USE_TRACE_PC",
    "AFL_USE_UBSAN", "AFL_WINE_PATH", NULL};

void detect_file_args(char **argv, u8 *prog_in, u8 *use_stdin) {

  u32 i = 0;
  u8  cwd[PATH_MAX];
  if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }

  /* we are working with libc-heap-allocated argvs. So do not mix them with
   * other allocation APIs like ck_alloc. That would disturb the free() calls.
   */
  while (argv[i]) {

    u8 *aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      if (!prog_in) FATAL("@@ syntax is not supported by this tool.");

      *use_stdin = 0;

      if (prog_in[0] != 0) {  // not afl-showmap special case

        u8 *n_arg;

        /* Be sure that we're always using fully-qualified paths. */

        *aa_loc = 0;

        /* Construct a replacement argv value. */

        if (prog_in[0] == '/') {

          n_arg = alloc_printf("%s%s%s", argv[i], prog_in, aa_loc + 2);

        } else {

          n_arg = alloc_printf("%s%s/%s%s", argv[i], cwd, prog_in, aa_loc + 2);

        }

        ck_free(argv[i]);
        argv[i] = n_arg;

      }

    }

    i++;

  }

  /* argvs are automatically freed at exit. */

}

/* duplicate the system argv so that
  we can edit (and free!) it later */

char **argv_cpy_dup(int argc, char **argv) {

  u32 i = 0;

  char **ret = ck_alloc((argc + 1) * sizeof(char *));

  for (i = 0; i < argc; i++) {

    ret[i] = ck_strdup(argv[i]);

  }

  ret[i] = NULL;

  return ret;

}

/* frees all args in the given argv,
   previously created by argv_cpy_dup */

void argv_cpy_free(char **argv) {

  u32 i = 0;
  while (argv[i]) {

    ck_free(argv[i]);
    i++;

  }

  ck_free(argv);

}

/* Rewrite argv for QEMU. */

char **get_qemu_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv) {

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
  u8 *   tmp, *cp = NULL, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, (int)(sizeof(char *)) * argc);

  new_argv[2] = *target_path_p;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    *target_path_p = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      *target_path_p = new_argv[0] = cp;
      return new_argv;

    }

  } else

    ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {

    if (cp) ck_free(cp);
    *target_path_p = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");

    return new_argv;

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be "
       "built\n"
       "    separately by following the instructions in "
       "afl->qemu_mode/README.md. "
       "If you\n"
       "    already have the binary installed, you may need to specify "
       "AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with "
       "binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to "
       "use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command "
       "line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");

}

/* Rewrite argv for Wine+QEMU. */

char **get_wine_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv) {

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 3));
  u8 *   tmp, *cp = NULL, *rsl, *own_copy;

  memcpy(new_argv + 2, argv + 1, (int)(sizeof(char *)) * argc);

  new_argv[1] = *target_path_p;

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    ck_free(cp);

    cp = alloc_printf("%s/afl-wine-trace", tmp);

    if (access(cp, X_OK)) FATAL("Unable to find '%s'", tmp);

    *target_path_p = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      if (cp != NULL) ck_free(cp);

      cp = alloc_printf("%s/afl-wine-trace", own_copy);

      if (!access(cp, X_OK)) {

        *target_path_p = new_argv[0] = cp;
        return new_argv;

      }

    }

  } else

    ck_free(own_copy);

  u8 *ncp = BIN_PATH "/afl-qemu-trace";

  if (!access(ncp, X_OK)) {

    ncp = BIN_PATH "/afl-wine-trace";

    if (!access(ncp, X_OK)) {

      *target_path_p = new_argv[0] = ck_strdup(ncp);
      return new_argv;

    }

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the '%s' binary. The binary must be "
       "built\n"
       "    separately by following the instructions in "
       "afl->qemu_mode/README.md. "
       "If you\n"
       "    already have the binary installed, you may need to specify "
       "AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with "
       "binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to "
       "use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command "
       "line.\n",
       ncp);

  FATAL("Failed to locate '%s'.", ncp);

}

void check_environment_vars(char **envp) {

  if (be_quiet) return;

  int   index = 0, found = 0;
  char *env;
  while ((env = envp[index++]) != NULL) {

    if (strncmp(env, "ALF_", 4) == 0) {

      WARNF("Potentially mistyped AFL environment variable: %s", env);
      found++;

    } else if (strncmp(env, "AFL_", 4) == 0) {

      int i = 0, match = 0;
      while (match == 0 && afl_environment_variables[i] != NULL)
        if (strncmp(env, afl_environment_variables[i],
                    strlen(afl_environment_variables[i])) == 0 &&
            env[strlen(afl_environment_variables[i])] == '=')
          match = 1;
        else
          i++;
      if (match == 0) {

        WARNF("Mistyped AFL environment variable: %s", env);
        found++;

      }

    }

  }

  if (found) sleep(2);

}

char *get_afl_env(char *env) {

  char *val;

  if ((val = getenv(env)) != NULL)
    if (!be_quiet)
      OKF("Loaded environment variable %s with value %s", env, val);

  return val;

}

