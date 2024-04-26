/*
   american fuzzy lop++ - free CPU gizmo
   -----------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This tool provides a fairly accurate measurement of CPU preemption rate.
   It is meant to complement the quick-and-dirty load average widget shown
   in the afl-fuzz UI. See docs/fuzzing_in_depth.md#c-using-multiple-cores
   for more info.

   For some work loads, the tool may actually suggest running more instances
   than you have CPU cores. This can happen if the tested program is spending
   a portion of its run time waiting for I/O, rather than being 100%
   CPU-bound.

   The idea for the getrusage()-based approach comes from Jakub Wilk.

 */

#define AFL_MAIN
#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sched.h>

#include <sys/time.h>
#include <sys/times.h>
#include <sys/resource.h>
#include <sys/wait.h>

#include "types.h"
#include "debug.h"
#include "common.h"

#if defined(__linux__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__APPLE__) || defined(__DragonFly__) || defined(__sun)
  #define HAVE_AFFINITY 1
  #if defined(__FreeBSD__) || defined(__DragonFly__)
    #include <pthread.h>
    #include <pthread_np.h>
    #if defined(__FreeBSD__)
      #include <sys/cpuset.h>
    #endif
    #define cpu_set_t cpuset_t
  #elif defined(__NetBSD__)
    #include <pthread.h>
  #elif defined(__APPLE__)
    #include <pthread.h>
    #include <mach/thread_act.h>
    #include <mach/thread_policy.h>
  #elif defined(__sun)
    #include <sys/pset.h>
  #endif
#endif               /* __linux__ || __FreeBSD__ || __NetBSD__ || __APPLE__ */

/* Get CPU usage in microseconds. */

static u64 get_cpu_usage_us(void) {

  struct rusage u;

  getrusage(RUSAGE_SELF, &u);

  return (u.ru_utime.tv_sec * 1000000ULL) + u.ru_utime.tv_usec +
         (u.ru_stime.tv_sec * 1000000ULL) + u.ru_stime.tv_usec;

}

/* Measure preemption rate. */

static u32 measure_preemption(u32 target_ms) {

  volatile u32 v1, v2 = 0;

  u64 st_t, en_t, st_c, en_c, real_delta, slice_delta;
  // s32 loop_repeats = 0;

  st_t = get_cur_time_us();
  st_c = get_cpu_usage_us();

repeat_loop:

  v1 = CTEST_BUSY_CYCLES;

  while (v1--) {

    v2++;

  }

  sched_yield();

  en_t = get_cur_time_us();

  if (en_t - st_t < target_ms * 1000) {

    // loop_repeats++;
    goto repeat_loop;

  }

  /* Let's see what percentage of this time we actually had a chance to
     run, and how much time was spent in the penalty box. */

  en_c = get_cpu_usage_us();

  real_delta = (en_t - st_t) / 1000;
  slice_delta = (en_c - st_c) / 1000;

  return real_delta * 100 / slice_delta;

}

/* Do the benchmark thing. */

int main(int argc, char **argv) {

  if (argc > 1) {

    printf("afl-gotcpu" VERSION " by Michal Zalewski\n");
    printf("\n%s \n\n", argv[0]);
    printf("afl-gotcpu does not have command line options\n");
    printf("afl-gotcpu prints out which CPUs are available\n");
    return -1;

  }

#ifdef HAVE_AFFINITY

  u32 cpu_cnt = sysconf(_SC_NPROCESSORS_ONLN), idle_cpus = 0, maybe_cpus = 0, i;

  SAYF(cCYA "afl-gotcpu" VERSION cRST " by Michal Zalewski\n");

  ACTF("Measuring per-core preemption rate (this will take %0.02f sec)...",
       ((double)CTEST_CORE_TRG_MS) / 1000);

  for (i = 0; i < cpu_cnt; i++) {

    s32 fr = fork();

    if (fr < 0) { PFATAL("fork failed"); }

    if (!fr) {

      u32 util_perc;
  #if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)
      cpu_set_t c;

      CPU_ZERO(&c);
      CPU_SET(i, &c);
  #elif defined(__NetBSD__)
      cpuset_t *c;

      c = cpuset_create();
      if (c == NULL) PFATAL("cpuset_create failed");

      cpuset_set(i, c);
  #elif defined(__APPLE__) && defined(__x86_64__)
      // the api is not workable on arm64, core's principle
      // differs significantly hive of core per type vs individual ones.
      // Possible TODO: For arm64 is to slightly change the meaning
      // of gotcpu since it makes no sense on this platform
      // but rather just displaying current policy ?
      thread_affinity_policy_data_t c = {i};
      thread_port_t native_thread = pthread_mach_thread_np(pthread_self());
      if (thread_policy_set(native_thread, THREAD_AFFINITY_POLICY,
                            (thread_policy_t)&c, 1) != KERN_SUCCESS)
        PFATAL("thread_policy_set failed");
  #elif defined(__sun)
      psetid_t c;

      if (pset_create(&c)) PFATAL("pset_create failed");

      if (pset_assign(c, i, NULL)) PFATAL("pset_assign failed");
  #endif

  #if defined(__FreeBSD__) || defined(__DragonFly__)
      if (pthread_setaffinity_np(pthread_self(), sizeof(c), &c))
        PFATAL("pthread_setaffinity_np failed");
  #endif

  #if defined(__NetBSD__)
      if (pthread_setaffinity_np(pthread_self(), cpuset_size(c), c))
        PFATAL("pthread_setaffinity_np failed");

      cpuset_destroy(c);
  #endif

  #if defined(__sun)
      if (pset_bind(c, P_PID, getpid(), NULL)) PFATAL("pset_bind failed");

      pset_destroy(c);
  #endif

  #if defined(__linux__)
      if (sched_setaffinity(0, sizeof(c), &c)) {

        const char *error_code = "Unkown error code";
        if (errno == EFAULT) error_code = "EFAULT";
        if (errno == EINVAL) error_code = "EINVAL";
        if (errno == EPERM) error_code = "EPERM";
        if (errno == ESRCH) error_code = "ESRCH";

        PFATAL("sched_setaffinity failed for cpu %d, error: %s", i, error_code);

      }

  #endif

      util_perc = measure_preemption(CTEST_CORE_TRG_MS);

      if (util_perc < 110) {

        SAYF("    Core #%u: " cLGN "AVAILABLE" cRST "(%u%%)\n", i, util_perc);
        exit(0);

      } else if (util_perc < 250) {

        SAYF("    Core #%u: " cYEL "CAUTION " cRST "(%u%%)\n", i, util_perc);
        exit(1);

      }

      SAYF("    Core #%u: " cLRD "OVERBOOKED " cRST "(%u%%)\n" cRST, i,
           util_perc);
      exit(2);

    }

  }

  for (i = 0; i < cpu_cnt; i++) {

    int ret;
    if (waitpid(-1, &ret, 0) < 0) { PFATAL("waitpid failed"); }

    if (WEXITSTATUS(ret) == 0) { idle_cpus++; }
    if (WEXITSTATUS(ret) <= 1) { maybe_cpus++; }

  }

  SAYF(cGRA "\n>>> ");

  if (idle_cpus) {

    if (maybe_cpus == idle_cpus) {

      SAYF(cLGN "PASS: " cRST "You can run more processes on %u core%s.",
           idle_cpus, idle_cpus > 1 ? "s" : "");

    } else {

      SAYF(cLGN "PASS: " cRST "You can run more processes on %u to %u core%s.",
           idle_cpus, maybe_cpus, maybe_cpus > 1 ? "s" : "");

    }

    SAYF(cGRA " <<<" cRST "\n\n");
    return 0;

  }

  if (maybe_cpus) {

    SAYF(cYEL "CAUTION: " cRST "You may still have %u core%s available.",
         maybe_cpus, maybe_cpus > 1 ? "s" : "");
    SAYF(cGRA " <<<" cRST "\n\n");
    return 1;

  }

  SAYF(cLRD "FAIL: " cRST "All cores are overbooked.");
  SAYF(cGRA " <<<" cRST "\n\n");
  return 2;

#else

  u32 util_perc;

  SAYF(cCYA "afl-gotcpu" VERSION cRST " by Michal Zalewski\n");

  /* Run a busy loop for CTEST_TARGET_MS. */

  ACTF("Measuring gross preemption rate (this will take %0.02f sec)...",
       ((double)CTEST_TARGET_MS) / 1000);

  util_perc = measure_preemption(CTEST_TARGET_MS);

  /* Deliver the final verdict. */

  SAYF(cGRA "\n>>> ");

  if (util_perc < 105) {

    SAYF(cLGN "PASS: " cRST "You can probably run additional processes.");

  } else if (util_perc < 130) {

    SAYF(cYEL "CAUTION: " cRST "Your CPU may be somewhat overbooked (%u%%).",
         util_perc);

  } else {

    SAYF(cLRD "FAIL: " cRST "Your CPU is overbooked (%u%%).", util_perc);

  }

  SAYF(cGRA " <<<" cRST "\n\n");

  return (util_perc > 105) + (util_perc > 130);

#endif                                                    /* ^HAVE_AFFINITY */

}

