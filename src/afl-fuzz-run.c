/*
   american fuzzy lop++ - target execution related routines
   --------------------------------------------------------

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

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include <sys/time.h>
#include <signal.h>

/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv.trace_bits[]. */

void timeout_handle(union sigval timer_data) {

  pid_t child_pid = timer_data.sival_int;
  if (child_pid > 0) kill(child_pid, SIGKILL);

}

u8 run_target(afl_state_t *afl, u32 timeout) {

  struct sigevent          timer_signal_event;
  static timer_t           timer;
  static struct itimerspec timer_period;
  static struct timeval    it;
  static u32               prev_timed_out = 0;
  static u64               exec_ms = 0;

  int status = 0;
  u32 tb4;
  int timer_status;

  afl->fsrv.child_timed_out = 0;

  /* After this memset, afl->fsrv.trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(afl->fsrv.trace_bits, 0, MAP_SIZE);
  memset(&timer_signal_event, 0, sizeof(struct sigevent));

  timer_signal_event.sigev_notify = SIGEV_THREAD;
  timer_signal_event.sigev_notify_function = timeout_handle;

  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and
     init_forkserver(), but c'est la vie. */

  if (afl->dumb_mode == 1 || afl->no_forkserver) {

    afl->fsrv.child_pid = fork();

    if (afl->fsrv.child_pid < 0) PFATAL("fork() failed");

    if (!afl->fsrv.child_pid) {

      struct rlimit r;

      if (afl->fsrv.mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)afl->fsrv.mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r);                          /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r);                        /* Ignore errors */

#endif                                                        /* ^RLIMIT_AS */

      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r);                          /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If
         afl->fsrv.out_file is specified, stdin is /dev/null; otherwise,
         afl->fsrv.out_fd is cloned instead. */

      setsid();

      dup2(afl->fsrv.dev_null_fd, 1);
      dup2(afl->fsrv.dev_null_fd, 2);

      if (afl->fsrv.out_file) {

        dup2(afl->fsrv.dev_null_fd, 0);

      } else {

        dup2(afl->fsrv.out_fd, 0);
        close(afl->fsrv.out_fd);

      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(afl->fsrv.dev_null_fd);
      close(afl->fsrv.out_dir_fd);
#ifndef HAVE_ARC4RANDOM
      close(afl->fsrv.dev_urandom_fd);
#endif
      close(fileno(afl->fsrv.plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS",
             "abort_on_error=1:"
             "detect_leaks=0:"
             "symbolize=0:"
             "allocator_may_return_null=1",
             0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);

      execv(afl->fsrv.target_path, afl->argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32 *)afl->fsrv.trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }

    /* Configure timeout using POSIX timers in dumb-mode,
        as requested by user, then wait for child to terminate.
     */

    timer_signal_event.sigev_value.sival_int = afl->fsrv.child_pid;
    timer_status = timer_create(CLOCK_MONOTONIC, &timer_signal_event, &timer);

    if (timer_status == -1) { FATAL("Failed to create Timer"); }

    timer_period.it_value.tv_sec = (timeout / 1000);
    timer_period.it_value.tv_nsec = (timeout % 1000) * 1000000;
    timer_period.it_interval.tv_sec = 0;
    timer_period.it_interval.tv_nsec = 0;

    timer_status = timer_settime(timer, 0, &timer_period, NULL);

    if (timer_status == -1) {

      timer_delete(timer);
      if (errno == EINVAL) {

        FATAL("Failed to set the timer. The timeout given is invalid.");

      } else {

        FATAL("Failed to set the timer to the given timeout");

      }

    }

  } else {

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    int res;

    if ((res = write(afl->fsrv.fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (afl->stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(afl->fsrv.fsrv_st_fd, &afl->fsrv.child_pid, 4)) != 4) {

      if (afl->stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (afl->fsrv.child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }

  if (afl->dumb_mode == 1 || afl->no_forkserver) {

    if (waitpid(afl->fsrv.child_pid, &status, 0) <= 0) {

      timer_delete(timer);
      PFATAL("waitpid() failed");

    }

    timer_gettime(timer, &timer_period);
    exec_ms = (u64)timeout - (timer_period.it_value.tv_sec * 1000 +
                              timer_period.it_value.tv_nsec / 1000000);
    timer_period.it_value.tv_sec = 0;
    timer_period.it_value.tv_nsec = 0;

    timer_status = timer_settime(timer, 0, &timer_period, NULL);

    if (timer_status == -1) {

      timer_delete(timer);
      FATAL("Failed to reset the timer.");

    }

    timer_delete(timer);

  } else {

    /* In non-dumb mode, use select to monitor the forkserver for timeouts.
     */

    s32 res;
    int sret;

    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(afl->fsrv.fsrv_st_fd, &readfds);
    it.tv_sec = ((timeout) / 1000);
    it.tv_usec = ((timeout) % 1000) * 1000;

    sret = select(afl->fsrv.fsrv_st_fd + 1, &readfds, NULL, NULL, &it);

    if (sret == 0) {

      kill(afl->fsrv.child_pid, SIGKILL);

    } else {

      if ((res = read(afl->fsrv.fsrv_st_fd, &status, 4)) != 4) {

        if (afl->stop_soon) return 0;
        SAYF(
            "\n" cLRD "[-] " cRST
            "Unable to communicate with fork server. Some possible reasons:\n\n"
            "    - You've run out of memory. Use -m to increase the the memory "
            "limit\n"
            "      to something higher than %lld.\n"
            "    - The binary or one of the libraries it uses manages to "
            "create\n"
            "      threads before the forkserver initializes.\n"
            "    - The binary, at least in some circumstances, exits in a way "
            "that\n"
            "      also kills the parent process - raise() could be the "
            "culprit.\n"
            "    - If using persistent mode with QEMU, "
            "AFL_QEMU_PERSISTENT_ADDR "
            "is\n"
            "      probably not valid (hint: add the base address in case of "
            "PIE)"
            "\n\n"
            "If all else fails you can disable the fork server via "
            "AFL_NO_FORKSRV=1.\n",
            afl->fsrv.mem_limit);
        RPFATAL(res, "Unable to communicate with fork server");

      }

    }

    exec_ms = (u64)timeout - (it.tv_sec * 1000 + it.tv_usec / 1000);
    it.tv_sec = 0;
    it.tv_usec = 0;

  }

  if (!WIFSTOPPED(status)) afl->fsrv.child_pid = 0;

  if (exec_ms >= timeout) { afl->fsrv.child_timed_out = 1; }

  ++afl->total_execs;

  /* Any subsequent operations on afl->fsrv.trace_bits must not be moved by the
     compiler below this point. Past this location, afl->fsrv.trace_bits[]
     behave very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32 *)afl->fsrv.trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64 *)afl->fsrv.trace_bits);
#else
  classify_counts((u32 *)afl->fsrv.trace_bits);
#endif                                                     /* ^WORD_SIZE_64 */

  prev_timed_out = afl->fsrv.child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !afl->stop_soon) {

    afl->kill_signal = WTERMSIG(status);

    if (afl->fsrv.child_timed_out && afl->kill_signal == SIGKILL)
      return FAULT_TMOUT;

    return FAULT_CRASH;

  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (afl->fsrv.uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {

    afl->kill_signal = 0;
    return FAULT_CRASH;

  }

  if ((afl->dumb_mode == 1 || afl->no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  return FAULT_NONE;

}

/* Write modified data to file for testing. If afl->fsrv.out_file is set, the
   old file is unlinked and a new one is created. Otherwise, afl->fsrv.out_fd is
   rewound and truncated. */

void write_to_testcase(afl_state_t *afl, void *mem, u32 len) {

  s32 fd = afl->fsrv.out_fd;

#ifdef _AFL_DOCUMENT_MUTATIONS
  s32   doc_fd;
  char *fn = alloc_printf("%s/mutations/%09u:%s", afl->out_dir,
                          afl->document_counter++, describe_op(0));
  if (fn != NULL) {

    if ((doc_fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600)) >= 0) {

      if (write(doc_fd, mem, len) != len)
        PFATAL("write to mutation file failed: %s", fn);
      close(doc_fd);

    }

    ck_free(fn);

  }

#endif

  if (afl->fsrv.out_file) {

    if (afl->no_unlink) {

      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    } else {

      unlink(afl->fsrv.out_file);                         /* Ignore errors. */
      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    }

    if (fd < 0) PFATAL("Unable to create '%s'", afl->fsrv.out_file);

  } else

    lseek(fd, 0, SEEK_SET);

  if (afl->mutator && afl->mutator->afl_custom_pre_save) {

    u8 *   new_data;
    size_t new_size =
        afl->mutator->afl_custom_pre_save(afl, mem, len, &new_data);
    ck_write(fd, new_data, new_size, afl->fsrv.out_file);
    ck_free(new_data);

  } else {

    ck_write(fd, mem, len, afl->fsrv.out_file);

  }

  if (!afl->fsrv.out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else

    close(fd);

}

/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(afl_state_t *afl, void *mem, u32 len, u32 skip_at,
                           u32 skip_len) {

  s32 fd = afl->fsrv.out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (afl->fsrv.out_file) {

    if (afl->no_unlink) {

      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    } else {

      unlink(afl->fsrv.out_file);                         /* Ignore errors. */
      fd = open(afl->fsrv.out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    }

    if (fd < 0) PFATAL("Unable to create '%s'", afl->fsrv.out_file);

  } else

    lseek(fd, 0, SEEK_SET);

  if (skip_at) ck_write(fd, mem, skip_at, afl->fsrv.out_file);

  u8 *memu8 = mem;
  if (tail_len)
    ck_write(fd, memu8 + skip_at + skip_len, tail_len, afl->fsrv.out_file);

  if (!afl->fsrv.out_file) {

    if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else

    close(fd);

}

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {

  static u8 first_trace[MAP_SIZE];

  u8 fault = 0, new_bits = 0, var_detected = 0,
     first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = afl->stage_cur, old_sm = afl->stage_max;
  u32 use_tmout = afl->fsrv.exec_tmout;
  u8 *old_sn = afl->stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || afl->resuming_fuzz)
    use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);

  ++q->cal_failed;

  afl->stage_name = "calibration";
  afl->stage_max = afl->fast_cal ? 3 : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (afl->dumb_mode != 1 && !afl->no_forkserver && !afl->fsrv.fsrv_pid)
    afl_fsrv_start(&afl->fsrv, afl->argv);
  if (afl->dumb_mode != 1 && !afl->no_forkserver && !afl->cmplog_fsrv_pid &&
      afl->shm.cmplog_mode)
    init_cmplog_forkserver(afl);

  if (q->exec_cksum) memcpy(first_trace, afl->fsrv.trace_bits, MAP_SIZE);

  start_us = get_cur_time_us();

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 cksum;

    if (!first_run && !(afl->stage_cur % afl->stats_update_freq))
      show_stats(afl);

    write_to_testcase(afl, use_mem, q->len);

    fault = run_target(afl, use_tmout);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) goto abort_calibration;

    if (!afl->dumb_mode && !afl->stage_cur &&
        !count_bytes(afl->fsrv.trace_bits)) {

      fault = FAULT_NOINST;
      goto abort_calibration;

    }

    cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {

      u8 hnb = has_new_bits(afl, afl->virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < MAP_SIZE; ++i) {

          if (!afl->var_bytes[i] && first_trace[i] != afl->fsrv.trace_bits[i]) {

            afl->var_bytes[i] = 1;
            afl->stage_max = CAL_CYCLES_LONG;

          }

        }

        var_detected = 1;

      } else {

        q->exec_cksum = cksum;
        memcpy(first_trace, afl->fsrv.trace_bits, MAP_SIZE);

      }

    }

  }

  stop_us = get_cur_time_us();

  afl->total_cal_us += stop_us - start_us;
  afl->total_cal_cycles += afl->stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us = (stop_us - start_us) / afl->stage_max;
  q->bitmap_size = count_bytes(afl->fsrv.trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  afl->total_bitmap_size += q->bitmap_size;
  ++afl->total_bitmap_entries;

  update_bitmap_score(afl, q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!afl->dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {

    q->has_new_cov = 1;
    ++afl->queued_with_cov;

  }

  /* Mark variable paths. */

  if (var_detected) {

    afl->var_byte_count = count_bytes(afl->var_bytes);

    if (!q->var_behavior) {

      mark_as_variable(afl, q);
      ++afl->queued_variable;

    }

  }

  afl->stage_name = old_sn;
  afl->stage_cur = old_sc;
  afl->stage_max = old_sm;

  if (!first_run) show_stats(afl);

  return fault;

}

/* Grab interesting test cases from other fuzzers. */

void sync_fuzzers(afl_state_t *afl) {

  DIR *          sd;
  struct dirent *sd_ent;
  u32            sync_cnt = 0;

  sd = opendir(afl->sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", afl->sync_dir);

  afl->stage_max = afl->stage_cur = 0;
  afl->cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory.
   */

  while ((sd_ent = readdir(sd))) {

    static u8 stage_tmp[128];

    DIR *          qd;
    struct dirent *qd_ent;
    u8 *           qd_path, *qd_synced_path;
    u32            min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(afl->sync_id, sd_ent->d_name))
      continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", afl->sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {

      ck_free(qd_path);
      continue;

    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path =
        alloc_printf("%s/.synced/%s", afl->out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    afl->stage_name = stage_tmp;
    afl->stage_cur = 0;
    afl->stage_max = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked
       at it before; exec a test case if not. */

    while ((qd_ent = readdir(qd))) {

      u8 *        path;
      s32         fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &afl->syncing_case) != 1 ||
          afl->syncing_case < min_accept)
        continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (afl->syncing_case >= next_min_accept)
        next_min_accept = afl->syncing_case + 1;

      path = alloc_printf("%s/%s", qd_path, qd_ent->d_name);

      /* Allow this to fail in case the other fuzzer is resuming or so... */

      fd = open(path, O_RDONLY);

      if (fd < 0) {

        ck_free(path);
        continue;

      }

      if (fstat(fd, &st)) PFATAL("fstat() failed");

      /* Ignore zero-sized or oversized files. */

      if (st.st_size && st.st_size <= MAX_FILE) {

        u8  fault;
        u8 *mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(afl, mem, st.st_size);

        fault = run_target(afl, afl->fsrv.exec_tmout);

        if (afl->stop_soon) goto close_sync;

        afl->syncing_party = sd_ent->d_name;
        afl->queued_imported +=
            save_if_interesting(afl, mem, st.st_size, fault);
        afl->syncing_party = 0;

        munmap(mem, st.st_size);

        if (!(afl->stage_cur++ % afl->stats_update_freq)) show_stats(afl);

      }

      ck_free(path);
      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

  close_sync:
    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);

  }

  closedir(sd);

}

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

u8 trim_case(afl_state_t *afl, struct queue_entry *q, u8 *in_buf) {

  /* Custom mutator trimmer */
  if (afl->mutator && afl->mutator->afl_custom_trim)
    return trim_case_custom(afl, q, in_buf);

  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 remove_len;
  u32 len_p2;

  /* Although the trimmer will be less useful when variable behavior is
     detected, it will still work to some extent, so we don't check for
     this. */

  if (q->len < 5) return 0;

  afl->stage_name = tmp;
  afl->bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_p2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

    afl->stage_cur = 0;
    afl->stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 cksum;

      write_with_gap(afl, in_buf, q->len, remove_pos, trim_avail);

      fault = run_target(afl, afl->fsrv.exec_tmout);
      ++afl->trim_execs;

      if (afl->stop_soon || fault == FAULT_ERROR) goto abort_trimming;

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

      cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2 = next_p2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail,
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */

        if (!needs_write) {

          needs_write = 1;
          memcpy(clean_trace, afl->fsrv.trace_bits, MAP_SIZE);

        }

      } else

        remove_pos += remove_len;

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % afl->stats_update_freq)) show_stats(afl);
      ++afl->stage_cur;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    if (afl->no_unlink) {

      fd = open(q->fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    } else {

      unlink(q->fname);                                    /* ignore errors */
      fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    }

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(afl->fsrv.trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(afl, q);

  }

abort_trimming:

  afl->bytes_trim_out += q->len;
  return fault;

}

/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

u8 common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  u8 fault;

  if (afl->post_handler) {

    out_buf = afl->post_handler(out_buf, &len);
    if (!out_buf || !len) return 0;

  }

  write_to_testcase(afl, out_buf, len);

  fault = run_target(afl, afl->fsrv.exec_tmout);

  if (afl->stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (afl->subseq_tmouts++ > TMOUT_LIMIT) {

      ++afl->cur_skipped_paths;
      return 1;

    }

  } else

    afl->subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (afl->skip_requested) {

    afl->skip_requested = 0;
    ++afl->cur_skipped_paths;
    return 1;

  }

  /* This handles FAULT_ERROR for us: */

  afl->queued_discovered += save_if_interesting(afl, out_buf, len, fault);

  if (!(afl->stage_cur % afl->stats_update_freq) ||
      afl->stage_cur + 1 == afl->stage_max)
    show_stats(afl);

  return 0;

}

