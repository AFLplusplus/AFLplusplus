/*
   american fuzzy lop++ - common routines header
   ---------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Heiko Eißfeldt <heiko.eissfeldt@hexco.de>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>,
                     Dominik Maier <mail@dmnk.co>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Gather some functions common to multiple executables

   - detect_file_args

 */

#ifndef __AFLCOMMON_H
#define __AFLCOMMON_H

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "types.h"
#include "stdbool.h"

/* STRINGIFY_VAL_SIZE_MAX will fit all stringify_ strings. */

#define STRINGIFY_VAL_SIZE_MAX (16)

void detect_file_args(char **argv, u8 *prog_in, u8 *use_stdin);
void check_environment_vars(char **env);

char **argv_cpy_dup(int argc, char **argv);
void   argv_cpy_free(char **argv);

char **get_qemu_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char **get_wine_argv(u8 *own_loc, u8 **target_path_p, int argc, char **argv);
char * get_afl_env(char *env);

/* Get unix time in milliseconds */

static u64 get_cur_time(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* Get unix time in microseconds */

static u64 get_cur_time_us(void) {

  struct timeval  tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000000ULL) + tv.tv_usec;

}

/* Describe integer. The buf should be
   at least 6 bytes to fit all ints we randomly see.
   Will return buf for convenience. */

static u8 *stringify_int(u8 *buf, size_t len, u64 val) {
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

static u8 *stringify_float(u8 *buf, size_t len, double val) {

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

static u8 *stringify_mem_size(u8 *buf, size_t len, u64 val) {

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

static u8 *stringify_time_diff(u8 *buf, size_t len, u64 cur_ms, u64 event_ms) {

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

static u8 *u_stringify_int(u8 *buf, u64 val) {
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

static u8 *u_stringify_float(u8 *buf, double val) {

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

static u8 *u_stringify_mem_size(u8 *buf, u64 val) {

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

static u8 *u_stringify_time_diff(u8 *buf, u64 cur_ms, u64 event_ms) {

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
static inline u32 read_timed(s32 fd, void *buf, size_t len, u32 timeout_ms) {

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

#endif

