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
#include "common.h"

/* Detect @@ in args. */
#ifndef __glibc__
#include <unistd.h>
#endif
#include <limits.h>

u8  be_quiet = 0;
u8 *doc_path = "";

char *afl_environment_variables[] = {

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
    "AFL_LLVM_CTX", "AFL_LLVM_INSTRUMENT", "AFL_LLVM_INSTRIM_LOOPHEAD",
    "AFL_LLVM_INSTRIM_SKIPSINGLEBLOCK", "AFL_LLVM_LAF_SPLIT_COMPARES",
    "AFL_LLVM_LAF_SPLIT_COMPARES_BITW", "AFL_LLVM_LAF_SPLIT_FLOATS",
    "AFL_LLVM_LAF_SPLIT_SWITCHES", "AFL_LLVM_LAF_TRANSFORM_COMPARES",
    "AFL_LLVM_NGRAM_SIZE", "AFL_NGRAM_SIZE", "AFL_LLVM_NOT_ZERO",
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
    "AFL_USE_UBSAN", "AFL_USE_CFISAN", "AFL_WINE_PATH", "AFL_NO_SNAPSHOT",
    NULL};

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

u64 get_cur_time(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Get unix time in microseconds */

u64 get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

/* Describe integer. The buf should be
   at least 6 bytes to fit all ints we randomly see.
   Will return buf for convenience. */

u8 *stringify_int(u8 *buf, size_t len, u64 val) {
\
#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast)     \
  do {                                                     \
                                                           \
    if (val < (_divisor) * (_limit_mult)) {                \
                                                           \
      snprintf(buf, len, _fmt, ((_cast)val) / (_divisor)); \
      return buf;                                          \
                                                           \
    }                                                      \
                                                           \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strncpy(buf, "infty", len);
  buf[len - 1] = '\0';

  return buf;

}

/* Describe float. Similar as int. */

u8 *stringify_float(u8 *buf, size_t len, double val) {

  if (val < 99.995) {

    snprintf(buf, len, "%0.02f", val);

  } else if (val < 999.95) {

    snprintf(buf, len, "%0.01f", val);

  } else {

    stringify_int(buf, len, (u64)val);

  }

  return buf;

}

/* Describe integer as memory size. */

u8 *stringify_mem_size(u8 *buf, size_t len, u64 val) {

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strncpy(buf, "infty", len - 1);
  buf[len - 1] = '\0';

  return buf;

}

/* Describe time delta as string.
   Returns a pointer to buf for convenience. */

u8 *stringify_time_diff(u8 *buf, size_t len, u64 cur_ms, u64 event_ms) {

  u64 delta;
  s32 t_d, t_h, t_m, t_s;
  u8  val_buf[STRINGIFY_VAL_SIZE_MAX];

  if (!event_ms) {

    snprintf(buf, len, "none seen yet");

  } else {

    delta = cur_ms - event_ms;

    t_d = delta / 1000 / 60 / 60 / 24;
    t_h = (delta / 1000 / 60 / 60) % 24;
    t_m = (delta / 1000 / 60) % 60;
    t_s = (delta / 1000) % 60;

    stringify_int(val_buf, sizeof(val_buf), t_d);
    snprintf(buf, len, "%s days, %d hrs, %d min, %d sec", val_buf, t_h, t_m,
             t_s);

  }

  return buf;

}

/* Unsafe Describe integer. The buf sizes are not checked.
   This is unsafe but fast.
   Will return buf for convenience. */

u8 *u_stringify_int(u8 *buf, u64 val) {
\
#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) \
  do {                                                 \
                                                       \
    if (val < (_divisor) * (_limit_mult)) {            \
                                                       \
      sprintf(buf, _fmt, ((_cast)val) / (_divisor));   \
      return buf;                                      \
                                                       \
    }                                                  \
                                                       \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1000, 99.95, "%0.01fk", double);

  /* 100k - 999k */
  CHK_FORMAT(1000, 1000, "%lluk", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1000 * 1000, 9.995, "%0.02fM", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1000 * 1000, 99.95, "%0.01fM", double);

  /* 100M - 999M */
  CHK_FORMAT(1000 * 1000, 1000, "%lluM", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000, 9.995, "%0.02fG", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1000LL * 1000 * 1000, 99.95, "%0.01fG", double);

  /* 100G - 999G */
  CHK_FORMAT(1000LL * 1000 * 1000, 1000, "%lluG", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 9.995, "%0.02fT", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1000LL * 1000 * 1000 * 1000, 99.95, "%0.01fT", double);

  /* 100T+ */
  strcpy(buf, "infty");

  return buf;

}

/* Unsafe describe float. Similar as unsafe int. */

u8 *u_stringify_float(u8 *buf, double val) {

  if (val < 99.995) {

    sprintf(buf, "%0.02f", val);

  } else if (val < 999.95) {

    sprintf(buf, "%0.01f", val);

  } else {

    return u_stringify_int(buf, (u64)val);

  }

  return buf;

}

/* Unsafe describe integer as memory size. */

u8 *u_stringify_mem_size(u8 *buf, u64 val) {

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(buf, "infty");

  return buf;

}

/* Unsafe describe time delta as string.
   Returns a pointer to buf for convenience. */

u8 *u_stringify_time_diff(u8 *buf, u64 cur_ms, u64 event_ms) {

  u64 delta;
  s32 t_d, t_h, t_m, t_s;
  u8  val_buf[STRINGIFY_VAL_SIZE_MAX];

  if (!event_ms) {

    sprintf(buf, "none seen yet");

  } else {

    delta = cur_ms - event_ms;

    t_d = delta / 1000 / 60 / 60 / 24;
    t_h = (delta / 1000 / 60 / 60) % 24;
    t_m = (delta / 1000 / 60) % 60;
    t_s = (delta / 1000) % 60;

    u_stringify_int(val_buf, t_d);
    sprintf(buf, "%s days, %d hrs, %d min, %d sec", val_buf, t_h, t_m, t_s);

  }

  return buf;

}

/* Wrapper for select() and read(), reading exactly len bytes.
  Returns the time passed to read.
  If the wait times out, returns timeout_ms + 1;
  Returns 0 if an error occurred (fd closed, signal, ...); */
u32 read_timed(s32 fd, void *buf, size_t len, u32 timeout_ms) {

  struct timeval timeout;
  fd_set         readfds;
  FD_ZERO(&readfds);
  FD_SET(fd, &readfds);

  timeout.tv_sec = (timeout_ms / 1000);
  timeout.tv_usec = (timeout_ms % 1000) * 1000;

  size_t read_total = 0;
  size_t len_read = 0;

  while (len_read < len) {

    /* set exceptfds as well to return when a child exited/closed the pipe. */
    int sret = select(fd + 1, &readfds, NULL, NULL, &timeout);

    if (!sret) {

      // printf("Timeout in sret.");
      return timeout_ms + 1;

    } else if (sret < 0) {

      // perror("sret malloc");
      // TODO: catch other (errno == EINTR) than ctrl+c?
      return 0;

    }

    len_read = read(fd, ((u8 *)buf) + len_read, len - len_read);
    if (!len_read) { return 0; }
    read_total += len_read;

  }

  s32 exec_ms =
      MIN(timeout_ms,
          ((u64)timeout_ms - (timeout.tv_sec * 1000 + timeout.tv_usec / 1000)));
  return exec_ms > 0 ? exec_ms
                     : 1;  // at least 1 milli must have passed (0 is an error)

}

