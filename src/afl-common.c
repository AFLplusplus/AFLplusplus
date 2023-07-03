/*
   american fuzzy lop++ - common routines
   --------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Gather some functions common to multiple executables

   - detect_file_args

 */

#include <stdlib.h>
#include <stdio.h>
#include "forkserver.h"
#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif
#ifndef __USE_GNU
  #define __USE_GNU
#endif
#include <string.h>
#include <strings.h>
#include <math.h>
#include <sys/mman.h>

#include "debug.h"
#include "alloc-inl.h"
#include "envs.h"
#include "common.h"

/* Detect @@ in args. */
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

u8  be_quiet = 0;
u8 *doc_path = "";
u8  last_intr = 0;

#ifndef AFL_PATH
  #define AFL_PATH "/usr/local/lib/afl/"
#endif

void *afl_memmem(const void *haystack, size_t haystacklen, const void *needle,
                 size_t needlelen) {

  if (unlikely(needlelen > haystacklen)) { return NULL; }

  for (u32 i = 0; i <= haystacklen - needlelen; ++i) {

    if (unlikely(memcmp(haystack + i, needle, needlelen) == 0)) {

      return (void *)(haystack + i);

    }

  }

  return (void *)NULL;

}

void set_sanitizer_defaults() {

  /* Set sane defaults for ASAN if nothing else is specified. */
  u8 *have_asan_options = getenv("ASAN_OPTIONS");
  u8 *have_ubsan_options = getenv("UBSAN_OPTIONS");
  u8 *have_msan_options = getenv("MSAN_OPTIONS");
  u8 *have_lsan_options = getenv("LSAN_OPTIONS");
  u8  have_san_options = 0;
  u8  default_options[1024] =
      "detect_odr_violation=0:abort_on_error=1:symbolize=0:allocator_may_"
      "return_null=1:handle_segv=0:handle_sigbus=0:handle_abort=0:handle_"
      "sigfpe=0:handle_sigill=0:";

  if (have_asan_options || have_ubsan_options || have_msan_options ||
      have_lsan_options) {

    have_san_options = 1;

  }

  /* LSAN does not support abort_on_error=1. (is this still true??) */

  if (!have_lsan_options) {

    u8 buf[2048] = "";
    if (!have_san_options) { strcpy(buf, default_options); }
    strcat(buf, "exitcode=" STRINGIFY(LSAN_ERROR) ":fast_unwind_on_malloc=0:print_suppressions=0:detect_leaks=1:malloc_context_size=30:");
    setenv("LSAN_OPTIONS", buf, 1);

  }

  /* for everything not LSAN we disable detect_leaks */

  if (!have_lsan_options) {

    strcat(default_options, "detect_leaks=0:malloc_context_size=0:");

  }

  /* Set sane defaults for ASAN if nothing else is specified. */

  if (!have_san_options) { setenv("ASAN_OPTIONS", default_options, 1); }

  /* Set sane defaults for UBSAN if nothing else is specified. */

  if (!have_san_options) { setenv("UBSAN_OPTIONS", default_options, 1); }

  /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
     point. So, we do this in a very hacky way. */

  if (!have_msan_options) {

    u8 buf[2048] = "";
    if (!have_san_options) { strcpy(buf, default_options); }
    strcat(buf, "exit_code=" STRINGIFY(MSAN_ERROR) ":msan_track_origins=0:");
    setenv("MSAN_OPTIONS", buf, 1);

  }

  /* Envs for QASan */
  setenv("QASAN_MAX_CALL_STACK", "0", 0);
  setenv("QASAN_SYMBOLIZE", "0", 0);

}

u32 check_binary_signatures(u8 *fn) {

  int ret = 0, fd = open(fn, O_RDONLY);
  if (fd < 0) { PFATAL("Unable to open '%s'", fn); }
  struct stat st;
  if (fstat(fd, &st) < 0) { PFATAL("Unable to fstat '%s'", fn); }
  u32 f_len = st.st_size;
  u8 *f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);
  if (f_data == MAP_FAILED) { PFATAL("Unable to mmap file '%s'", fn); }
  close(fd);

  if (afl_memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1)) {

    if (!be_quiet) { OKF(cPIN "Persistent mode binary detected."); }
    setenv(PERSIST_ENV_VAR, "1", 1);
    ret = 1;

  } else if (getenv("AFL_PERSISTENT")) {

    if (!be_quiet) { OKF(cPIN "Persistent mode enforced."); }
    setenv(PERSIST_ENV_VAR, "1", 1);
    ret = 1;

  } else if (getenv("AFL_FRIDA_PERSISTENT_ADDR")) {

    if (!be_quiet) {

      OKF("FRIDA Persistent mode configuration options detected.");

    }

    setenv(PERSIST_ENV_VAR, "1", 1);
    ret = 1;

  }

  if (afl_memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1)) {

    if (!be_quiet) { OKF(cPIN "Deferred forkserver binary detected."); }
    setenv(DEFER_ENV_VAR, "1", 1);
    ret += 2;

  } else if (getenv("AFL_DEFER_FORKSRV")) {

    if (!be_quiet) { OKF(cPIN "Deferred forkserver enforced."); }
    setenv(DEFER_ENV_VAR, "1", 1);
    ret += 2;

  }

  if (munmap(f_data, f_len)) { PFATAL("unmap() failed"); }

  return ret;

}

void detect_file_args(char **argv, u8 *prog_in, bool *use_stdin) {

  u32 i = 0;
  u8  cwd[PATH_MAX];
  if (getcwd(cwd, (size_t)sizeof(cwd)) == NULL) { PFATAL("getcwd() failed"); }

  /* we are working with libc-heap-allocated argvs. So do not mix them with
   * other allocation APIs like ck_alloc. That would disturb the free() calls.
   */
  while (argv[i]) {

    u8 *aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      if (!prog_in) { FATAL("@@ syntax is not supported by this tool."); }

      *use_stdin = false;

      /* Be sure that we're always using fully-qualified paths. */

      *aa_loc = 0;

      /* Construct a replacement argv value. */
      u8 *n_arg;

      if (prog_in[0] == '/') {

        n_arg = alloc_printf("%s%s%s", argv[i], prog_in, aa_loc + 2);

      } else {

        n_arg = alloc_printf("%s%s/%s%s", argv[i], cwd, prog_in, aa_loc + 2);

      }

      ck_free(argv[i]);
      argv[i] = n_arg;

    }

    i++;

  }

  /* argvs are automatically freed at exit. */

}

/* duplicate the system argv so that
  we can edit (and free!) it later */

char **argv_cpy_dup(int argc, char **argv) {

  int i = 0;

  char **ret = ck_alloc((argc + 1) * sizeof(char *));
  if (unlikely(!ret)) { FATAL("Amount of arguments specified is too high"); }

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
    argv[i] = NULL;
    i++;

  }

  ck_free(argv);

}

/* Rewrite argv for CoreSight process tracer. */

char **get_cs_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv) {

  if (unlikely(getenv("AFL_CS_CUSTOM_BIN"))) {

    WARNF(
        "AFL_CS_CUSTOM_BIN is enabled. "
        "You must run your target under afl-cs-proxy on your own!");
    return argv;

  }

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 4));
  if (unlikely(!new_argv)) { FATAL("Illegal amount of arguments specified"); }

  memcpy(&new_argv[3], &argv[1], (int)(sizeof(char *)) * (argc - 1));
  new_argv[argc + 3] = NULL;

  new_argv[2] = *target_path_p;
  new_argv[1] = "--";

  /* Now we need to actually find the cs-proxy binary to put in argv[0]. */

  *target_path_p = new_argv[0] = find_afl_binary(own_loc, "afl-cs-proxy");
  return new_argv;

}

/* Rewrite argv for QEMU. */

char **get_qemu_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv) {

  if (unlikely(getenv("AFL_QEMU_CUSTOM_BIN"))) {

    WARNF(
        "AFL_QEMU_CUSTOM_BIN is enabled. "
        "You must run your target under afl-qemu-trace on your own!");
    return argv;

  }

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 3));
  if (unlikely(!new_argv)) { FATAL("Illegal amount of arguments specified"); }

  memcpy(&new_argv[3], &argv[1], (int)(sizeof(char *)) * (argc - 1));

  new_argv[2] = *target_path_p;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  *target_path_p = new_argv[0] = find_afl_binary(own_loc, "afl-qemu-trace");
  return new_argv;

}

/* Rewrite argv for Wine+QEMU. */

char **get_wine_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv) {

  char **new_argv = ck_alloc(sizeof(char *) * (argc + 2));
  if (unlikely(!new_argv)) { FATAL("Illegal amount of arguments specified"); }

  memcpy(&new_argv[2], &argv[1], (int)(sizeof(char *)) * (argc - 1));

  new_argv[1] = *target_path_p;

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  u8 *tmp = find_afl_binary(own_loc, "afl-qemu-trace");
  ck_free(tmp);
  *target_path_p = new_argv[0] = find_afl_binary(own_loc, "afl-wine-trace");
  return new_argv;

}

/* Find binary, used by analyze, showmap, tmin
   @returns the path, allocating the string */

u8 *find_binary(u8 *fname) {

  // TODO: Merge this function with check_binary of afl-fuzz-init.c

  u8 *env_path = NULL;
  u8 *target_path = NULL;

  struct stat st;

  if (unlikely(!fname)) { FATAL("No binary supplied"); }

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);

    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || st.st_size < 4) {

      ck_free(target_path);
      FATAL("Program '%s' not found or not executable", fname);

    }

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        if (unlikely(!cur_elem)) {

          FATAL(
              "Unexpected overflow when processing ENV. This should never "
              "happend.");

        }

        memcpy(cur_elem, env_path, delim - env_path);
        delim++;

      } else {

        cur_elem = ck_strdup(env_path);

      }

      env_path = delim;

      if (cur_elem[0]) {

        target_path = alloc_printf("%s/%s", cur_elem, fname);

      } else {

        target_path = ck_strdup(fname);

      }

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && st.st_size >= 4) {

        break;

      }

      ck_free(target_path);
      target_path = NULL;

    }

    if (!target_path) {

      FATAL("Program '%s' not found or not executable", fname);

    }

  }

  return target_path;

}

u8 *find_afl_binary(u8 *own_loc, u8 *fname) {

  u8 *afl_path = NULL, *target_path, *own_copy, *tmp;
  int perm = X_OK;

  if ((tmp = strrchr(fname, '.'))) {

    if (!strcasecmp(tmp, ".so") || !strcasecmp(tmp, ".dylib")) { perm = R_OK; }

  }

  if ((afl_path = getenv("AFL_PATH"))) {

    target_path = alloc_printf("%s/%s", afl_path, fname);
    if (!access(target_path, perm)) {

      return target_path;

    } else {

      ck_free(target_path);

    }

  }

  if (own_loc) {

    own_copy = ck_strdup(own_loc);
    u8 *rsl = strrchr(own_copy, '/');

    if (rsl) {

      *rsl = 0;

      target_path = alloc_printf("%s/%s", own_copy, fname);
      ck_free(own_copy);

      if (!access(target_path, perm)) {

        return target_path;

      } else {

        ck_free(target_path);

      }

    } else {

      ck_free(own_copy);

    }

  }

  if (perm == X_OK) {

    target_path = alloc_printf("%s/%s", BIN_PATH, fname);

  } else {

    target_path = alloc_printf("%s/%s", AFL_PATH, fname);

  }

  if (!access(target_path, perm)) {

    return target_path;

  } else {

    ck_free(target_path);

  }

  if (perm == X_OK) {

    return find_binary(fname);

  } else {

    FATAL("Library '%s' not found", fname);

  }

}

int parse_afl_kill_signal(u8 *numeric_signal_as_str, int default_signal) {

  if (numeric_signal_as_str && numeric_signal_as_str[0]) {

    char *endptr;
    u8    signal_code;
    signal_code = (u8)strtoul(numeric_signal_as_str, &endptr, 10);
    /* Did we manage to parse the full string? */
    if (*endptr != '\0' || endptr == (char *)numeric_signal_as_str) {

      FATAL("Invalid signal name: %s", numeric_signal_as_str);

    } else {

      return signal_code;

    }

  }

  return default_signal;

}

void configure_afl_kill_signals(afl_forkserver_t *fsrv,
                                char             *afl_kill_signal_env,
                                char             *afl_fsrv_kill_signal_env,
                                int               default_server_kill_signal) {

  afl_kill_signal_env =
      afl_kill_signal_env ? afl_kill_signal_env : getenv("AFL_KILL_SIGNAL");
  afl_fsrv_kill_signal_env = afl_fsrv_kill_signal_env
                                 ? afl_fsrv_kill_signal_env
                                 : getenv("AFL_FORK_SERVER_KILL_SIGNAL");

  fsrv->child_kill_signal = parse_afl_kill_signal(afl_kill_signal_env, SIGKILL);

  if (afl_kill_signal_env && !afl_fsrv_kill_signal_env) {

    /*
    Set AFL_FORK_SERVER_KILL_SIGNAL to the value of AFL_KILL_SIGNAL for
    backwards compatibility. However, if AFL_FORK_SERVER_KILL_SIGNAL is set, is
    takes precedence.
    */
    afl_fsrv_kill_signal_env = afl_kill_signal_env;

  }

  fsrv->fsrv_kill_signal = parse_afl_kill_signal(afl_fsrv_kill_signal_env,
                                                 default_server_kill_signal);

}

static inline unsigned int helper_min3(unsigned int a, unsigned int b,
                                       unsigned int c) {

  return a < b ? (a < c ? a : c) : (b < c ? b : c);

}

// from
// https://en.wikibooks.org/wiki/Algorithm_Implementation/Strings/Levenshtein_distance#C
static int string_distance_levenshtein(char *s1, char *s2) {

  unsigned int s1len, s2len, x, y, lastdiag, olddiag;
  s1len = strlen(s1);
  s2len = strlen(s2);
  unsigned int column[s1len + 1];
  column[s1len] = 1;

  for (y = 1; y <= s1len; y++)
    column[y] = y;
  for (x = 1; x <= s2len; x++) {

    column[0] = x;
    for (y = 1, lastdiag = x - 1; y <= s1len; y++) {

      olddiag = column[y];
      column[y] = helper_min3(column[y] + 1, column[y - 1] + 1,
                              lastdiag + (s1[y - 1] == s2[x - 1] ? 0 : 1));
      lastdiag = olddiag;

    }

  }

  return column[s1len];

}

#define ENV_SIMILARITY_TRESHOLD 3

void print_suggested_envs(char *mispelled_env) {

  size_t env_name_len =
      strcspn(mispelled_env, "=") - 4;  // remove the AFL_prefix
  char *env_name = ck_alloc(env_name_len + 1);
  memcpy(env_name, mispelled_env + 4, env_name_len);

  char *seen = ck_alloc(sizeof(afl_environment_variables) / sizeof(char *));
  int   found = 0;

  int j;
  for (j = 0; afl_environment_variables[j] != NULL; ++j) {

    char *afl_env = afl_environment_variables[j] + 4;
    int   distance = string_distance_levenshtein(afl_env, env_name);
    if (distance < ENV_SIMILARITY_TRESHOLD && seen[j] == 0) {

      SAYF("Did you mean %s?\n", afl_environment_variables[j]);
      seen[j] = 1;
      found = 1;

    }

  }

  if (found) goto cleanup;

  for (j = 0; afl_environment_variables[j] != NULL; ++j) {

    char  *afl_env = afl_environment_variables[j] + 4;
    size_t afl_env_len = strlen(afl_env);
    char  *reduced = ck_alloc(afl_env_len + 1);

    size_t start = 0;
    while (start < afl_env_len) {

      size_t end = start + strcspn(afl_env + start, "_") + 1;
      memcpy(reduced, afl_env, start);
      if (end < afl_env_len) {

        memcpy(reduced + start, afl_env + end, afl_env_len - end);

      }

      if (afl_env_len + start >= end) {

        reduced[afl_env_len - end + start] = 0;

      }

      int distance = string_distance_levenshtein(reduced, env_name);
      if (distance < ENV_SIMILARITY_TRESHOLD && seen[j] == 0) {

        SAYF("Did you mean %s?\n", afl_environment_variables[j]);
        seen[j] = 1;
        found = 1;

      }

      start = end;

    };

    ck_free(reduced);

  }

  if (found) goto cleanup;

  char  *reduced = ck_alloc(env_name_len + 1);
  size_t start = 0;
  while (start < env_name_len) {

    size_t end = start + strcspn(env_name + start, "_") + 1;
    memcpy(reduced, env_name, start);
    if (end < env_name_len)
      memcpy(reduced + start, env_name + end, env_name_len - end);
    reduced[env_name_len - end + start] = 0;

    for (j = 0; afl_environment_variables[j] != NULL; ++j) {

      int distance = string_distance_levenshtein(
          afl_environment_variables[j] + 4, reduced);
      if (distance < ENV_SIMILARITY_TRESHOLD && seen[j] == 0) {

        SAYF("Did you mean %s?\n", afl_environment_variables[j]);
        seen[j] = 1;

      }

    }

    start = end;

  };

  ck_free(reduced);

cleanup:
  ck_free(env_name);
  ck_free(seen);

}

void check_environment_vars(char **envp) {

  if (be_quiet) { return; }

  int   index = 0, issue_detected = 0;
  char *env, *val, *ignore = getenv("AFL_IGNORE_UNKNOWN_ENVS");
  while ((env = envp[index++]) != NULL) {

    if (strncmp(env, "ALF_", 4) == 0 || strncmp(env, "_ALF", 4) == 0 ||
        strncmp(env, "__ALF", 5) == 0 || strncmp(env, "_AFL", 4) == 0 ||
        strncmp(env, "__AFL", 5) == 0) {

      WARNF("Potentially mistyped AFL environment variable: %s", env);
      issue_detected = 1;

    } else if (strncmp(env, "AFL_", 4) == 0) {

      int i = 0, match = 0;
      while (match == 0 && afl_environment_variables[i] != NULL) {

        if (strncmp(env, afl_environment_variables[i],
                    strlen(afl_environment_variables[i])) == 0 &&
            env[strlen(afl_environment_variables[i])] == '=') {

          match = 1;

          if ((val = getenv(afl_environment_variables[i])) && !*val) {

            WARNF(
                "AFL environment variable %s defined but is empty, this can "
                "lead to unexpected consequences",
                afl_environment_variables[i]);
            issue_detected = 1;

          }

        } else {

          i++;

        }

      }

      i = 0;
      while (match == 0 && afl_environment_deprecated[i] != NULL) {

        if (strncmp(env, afl_environment_deprecated[i],
                    strlen(afl_environment_deprecated[i])) == 0 &&
            env[strlen(afl_environment_deprecated[i])] == '=') {

          match = 1;

          WARNF("AFL environment variable %s is deprecated!",
                afl_environment_deprecated[i]);
          issue_detected = 1;

        } else {

          i++;

        }

      }

      if (match == 0 && !ignore) {

        WARNF("Mistyped AFL environment variable: %s", env);
        issue_detected = 1;

        print_suggested_envs(env);

      }

    }

  }

  if (issue_detected) { sleep(2); }

}

char *get_afl_env(char *env) {

  char *val;

  if ((val = getenv(env))) {

    if (*val) {

      if (!be_quiet) {

        OKF("Enabled environment variable %s with value %s", env, val);

      }

      return val;

    }

  }

  return NULL;

}

bool extract_and_set_env(u8 *env_str) {

  if (!env_str) { return false; }

  bool ret = false;  // return false by default

  u8 *p = ck_strdup(env_str);
  u8 *end = p + strlen((char *)p);
  u8 *rest = p;

  u8 closing_sym = ' ';
  u8 c;

  size_t num_pairs = 0;

  while (rest < end) {

    while (*rest == ' ') {

      rest++;

    }

    if (rest + 1 >= end) break;

    u8 *key = rest;
    // env variable names may not start with numbers or '='
    if (*key == '=' || (*key >= '0' && *key <= '9')) { goto free_and_return; }

    while (rest < end && *rest != '=' && *rest != ' ') {

      c = *rest;
      // lowercase is bad but we may still allow it
      if ((c < 'A' || c > 'Z') && (c < 'a' || c > 'z') &&
          (c < '0' || c > '9') && c != '_') {

        goto free_and_return;

      }

      rest++;

    }

    if (*rest != '=') { goto free_and_return; }

    *rest = '\0';  // done with variable name

    rest += 1;
    if (rest >= end || *rest == ' ') { goto free_and_return; }

    u8 *val = rest;
    if (*val == '\'' || *val == '"') {

      closing_sym = *val;
      val += 1;
      rest += 1;
      if (rest >= end) { goto free_and_return; }

    } else {

      closing_sym = ' ';

    }

    while (rest < end && *rest != closing_sym) {

      rest++;

    }

    if (closing_sym != ' ' && *rest != closing_sym) { goto free_and_return; }

    *rest = '\0';  // done with variable value

    rest += 1;
    num_pairs++;
    setenv(key, val, 1);

  }

  if (num_pairs) { ret = true; }

free_and_return:
  ck_free(p);
  return ret;

}

/* Read mask bitmap from file. This is for the -B option. */

void read_bitmap(u8 *fname, u8 *map, size_t len) {

  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_read(fd, map, len, fname);

  close(fd);

}

/* Get unix time in milliseconds */

inline u64 get_cur_time(void) {

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

  } else if (unlikely(isnan(val) || isinf(val))) {

    strcpy(buf, "inf");

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

  if (!event_ms) {

    snprintf(buf, len, "none seen yet");

  } else {

    u64 delta;
    s32 t_d, t_h, t_m, t_s;
    u8  val_buf[STRINGIFY_VAL_SIZE_MAX];

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

  } else if (unlikely(isnan(val) || isinf(val))) {

    strcpy(buf, "infinite");

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

  if (!event_ms) {

    sprintf(buf, "none seen yet");

  } else {

    u64 delta;
    s32 t_d, t_h, t_m, t_s;
    u8  val_buf[STRINGIFY_VAL_SIZE_MAX];

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

/* Unsafe describe time delta as simple string.
   Returns a pointer to buf for convenience. */

u8 *u_simplestring_time_diff(u8 *buf, u64 cur_ms, u64 event_ms) {

  if (!event_ms) {

    sprintf(buf, "00:00:00");

  } else {

    u64 delta;
    s32 t_d, t_h, t_m, t_s;

    delta = cur_ms - event_ms;

    t_d = delta / 1000 / 60 / 60 / 24;
    t_h = (delta / 1000 / 60 / 60) % 24;
    t_m = (delta / 1000 / 60) % 60;
    t_s = (delta / 1000) % 60;

    sprintf(buf, "%d:%02d:%02d:%02d", t_d, t_h, t_m, t_s);

  }

  return buf;

}

/* Reads the map size from ENV */
u32 get_map_size(void) {

  uint32_t map_size = DEFAULT_SHMEM_SIZE;
  char    *ptr;

  if ((ptr = getenv("AFL_MAP_SIZE")) || (ptr = getenv("AFL_MAPSIZE"))) {

    map_size = atoi(ptr);
    if (!map_size || map_size > (1 << 29)) {

      FATAL("illegal AFL_MAP_SIZE %u, must be between %u and %u", map_size, 64U,
            1U << 29);

    }

    if (map_size % 64) { map_size = (((map_size >> 6) + 1) << 6); }

  } else if (getenv("AFL_SKIP_BIN_CHECK")) {

    map_size = MAP_SIZE;

  }

  return map_size;

}

/* Create a stream file */

FILE *create_ffile(u8 *fn) {

  s32   fd;
  FILE *f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }

  f = fdopen(fd, "w");

  if (!f) { PFATAL("fdopen() failed"); }

  return f;

}

/* Create a file */

s32 create_file(u8 *fn) {

  s32 fd;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to create '%s'", fn); }

  return fd;

}

#ifdef __linux__

/* Nyx requires a tmp workdir to access specific files (such as mmapped files,
 * etc.). This helper function basically creates both a path to a tmp workdir
 * and the workdir itself. If the environment variable TMPDIR is set, we use
 * that as the base directory, otherwise we use /tmp. */
char *create_nyx_tmp_workdir(void) {

  char *tmpdir = getenv("TMPDIR");

  if (!tmpdir) { tmpdir = "/tmp"; }

  char *nyx_out_dir_path =
      alloc_printf("%s/.nyx_tmp_%d/", tmpdir, (u32)getpid());

  if (mkdir(nyx_out_dir_path, 0700)) { PFATAL("Unable to create nyx workdir"); }

  return nyx_out_dir_path;

}

/* Vice versa, we remove the tmp workdir for nyx with this helper function. */
void remove_nyx_tmp_workdir(afl_forkserver_t *fsrv, char *nyx_out_dir_path) {

  char *workdir_path = alloc_printf("%s/workdir", nyx_out_dir_path);

  if (access(workdir_path, R_OK) == 0) {

    if (fsrv->nyx_handlers->nyx_remove_work_dir(workdir_path) != true) {

      WARNF("Unable to remove nyx workdir (%s)", workdir_path);

    }

  }

  if (rmdir(nyx_out_dir_path)) {

    WARNF("Unable to remove nyx workdir (%s)", nyx_out_dir_path);

  }

  ck_free(workdir_path);
  ck_free(nyx_out_dir_path);

}

#endif

