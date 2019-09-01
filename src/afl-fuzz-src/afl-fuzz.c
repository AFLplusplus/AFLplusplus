/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

int select_algorithm(void) {

  int i_puppet, j_puppet;

  double sele = ((double)(UR(10000))*0.0001);
  j_puppet = 0;
  for (i_puppet = 0; i_puppet < operator_num; ++i_puppet) {
      if (unlikely(i_puppet == 0)) {
          if (sele < probability_now[swarm_now][i_puppet])
            break;
      } else {
          if (sele < probability_now[swarm_now][i_puppet]) {
              j_puppet =1;
              break;
          }
      }
  }
  if (j_puppet ==1 && sele < probability_now[swarm_now][i_puppet-1])
    FATAL("error select_algorithm");
  return i_puppet;
}


/* Shuffle an array of pointers. Might be slightly biased. */

static void shuffle_ptrs(void** ptrs, u32 cnt) {

  u32 i;

  for (i = 0; i < cnt - 2; ++i) {

    u32 j = i + UR(cnt - i);
    void *s = ptrs[i];
    ptrs[i] = ptrs[j];
    ptrs[j] = s;

  }

}


#ifdef HAVE_AFFINITY

/* Build a list of processes bound to specific cores. Returns -1 if nothing
   can be found. Assumes an upper bound of 4k CPUs. */

static void bind_to_free_cpu(void) {

  DIR* d;
  struct dirent* de;
  cpu_set_t c;

  u8 cpu_used[4096] = { 0 };
  u32 i;

  if (cpu_core_count < 2) return;

  if (getenv("AFL_NO_AFFINITY")) {

    WARNF("Not binding to a CPU core (AFL_NO_AFFINITY set).");
    return;

  }

  d = opendir("/proc");

  if (!d) {

    WARNF("Unable to access /proc - can't scan for free CPU cores.");
    return;

  }

  ACTF("Checking CPU core loadout...");

  /* Introduce some jitter, in case multiple AFL tasks are doing the same
     thing at the same time... */

  usleep(R(1000) * 250);

  /* Scan all /proc/<pid>/status entries, checking for Cpus_allowed_list.
     Flag all processes bound to a specific CPU using cpu_used[]. This will
     fail for some exotic binding setups, but is likely good enough in almost
     all real-world use cases. */

  while ((de = readdir(d))) {

    u8* fn;
    FILE* f;
    u8 tmp[MAX_LINE];
    u8 has_vmsize = 0;

    if (!isdigit(de->d_name[0])) continue;

    fn = alloc_printf("/proc/%s/status", de->d_name);

    if (!(f = fopen(fn, "r"))) {
      ck_free(fn);
      continue;
    }

    while (fgets(tmp, MAX_LINE, f)) {

      u32 hval;

      /* Processes without VmSize are probably kernel tasks. */

      if (!strncmp(tmp, "VmSize:\t", 8)) has_vmsize = 1;

      if (!strncmp(tmp, "Cpus_allowed_list:\t", 19) &&
          !strchr(tmp, '-') && !strchr(tmp, ',') &&
          sscanf(tmp + 19, "%u", &hval) == 1 && hval < sizeof(cpu_used) &&
          has_vmsize) {

        cpu_used[hval] = 1;
        break;

      }

    }

    ck_free(fn);
    fclose(f);

  }

  closedir(d);

  for (i = 0; i < cpu_core_count; ++i) if (!cpu_used[i]) break;

  if (i == cpu_core_count) {

    SAYF("\n" cLRD "[-] " cRST
         "Uh-oh, looks like all %d CPU cores on your system are allocated to\n"
         "    other instances of afl-fuzz (or similar CPU-locked tasks). Starting\n"
         "    another fuzzer on this machine is probably a bad plan, but if you are\n"
         "    absolutely sure, you can set AFL_NO_AFFINITY and try again.\n",
         cpu_core_count);

    FATAL("No more free CPU cores");

  }

  OKF("Found a free CPU core, binding to #%u.", i);

  cpu_aff = i;

  CPU_ZERO(&c);
  CPU_SET(i, &c);

  if (sched_setaffinity(0, sizeof(c), &c))
    PFATAL("sched_setaffinity failed");

}

#endif /* HAVE_AFFINITY */

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset. We
   use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8* ptr1, u8* ptr2, u32 len, s32* first, s32* last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; ++pos) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) f_loc = pos;
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif /* !IGNORE_FINDS */



/* Load postprocessor, if available. */

static void setup_post(void) {

  void* dh;
  u8* fn = getenv("AFL_POST_LIBRARY");
  u32 tlen = 6;

  if (!fn) return;

  ACTF("Loading postprocessor from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());

  post_handler = dlsym(dh, "afl_postprocess");
  if (!post_handler) FATAL("Symbol 'afl_postprocess' not found.");

  /* Do a quick test. It's better to segfault now than later =) */

  post_handler("hello", &tlen);

  OKF("Postprocessor installed successfully.");

}

static void setup_custom_mutator(void) {
  void* dh;
  u8* fn = getenv("AFL_CUSTOM_MUTATOR_LIBRARY");

  if (!fn) return;

  ACTF("Loading custom mutator library from '%s'...", fn);

  dh = dlopen(fn, RTLD_NOW);
  if (!dh) FATAL("%s", dlerror());

  custom_mutator = dlsym(dh, "afl_custom_mutator");
  if (!custom_mutator) FATAL("Symbol 'afl_custom_mutator' not found.");

  pre_save_handler = dlsym(dh, "afl_pre_save_handler");
//  if (!pre_save_handler) WARNF("Symbol 'afl_pre_save_handler' not found.");

  OKF("Custom mutator installed successfully.");
}


/* Read all testcases from the input directory, then queue them for testing.
   Called at startup. */

static void read_testcases(void) {

  struct dirent **nl;
  s32 nl_cnt;
  u32 i;
  u8* fn1;

  /* Auto-detect non-in-place resumption attempts. */

  fn1 = alloc_printf("%s/queue", in_dir);
  if (!access(fn1, F_OK)) in_dir = fn1; else ck_free(fn1);

  ACTF("Scanning '%s'...", in_dir);

  /* We use scandir() + alphasort() rather than readdir() because otherwise,
     the ordering  of test cases would vary somewhat randomly and would be
     difficult to control. */

  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);

  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)

      SAYF("\n" cLRD "[-] " cRST
           "The input directory does not seem to be valid - try again. The fuzzer needs\n"
           "    one or more test case to start with - ideally, a small file under 1 kB\n"
           "    or so. The cases must be stored as regular files directly in the input\n"
           "    directory.\n");

    PFATAL("Unable to open '%s'", in_dir);

  }

  if (shuffle_queue && nl_cnt > 1) {

    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);

  }

  for (i = 0; i < nl_cnt; ++i) {

    struct stat st;

    u8* fn2 = alloc_printf("%s/%s", in_dir, nl[i]->d_name);
    u8* dfn = alloc_printf("%s/.state/deterministic_done/%s", in_dir, nl[i]->d_name);

    u8  passed_det = 0;

    free(nl[i]); /* not tracked */
 
    if (lstat(fn2, &st) || access(fn2, R_OK))
      PFATAL("Unable to access '%s'", fn2);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn2, "/README.txt")) {

      ck_free(fn2);
      ck_free(dfn);
      continue;

    }

    if (st.st_size > MAX_FILE) 
      FATAL("Test case '%s' is too big (%s, limit is %s)", fn2,
            DMS(st.st_size), DMS(MAX_FILE));

    /* Check for metadata that indicates that deterministic fuzzing
       is complete for this entry. We don't want to repeat deterministic
       fuzzing when resuming aborted scans, because it would be pointless
       and probably very time-consuming. */

    if (!access(dfn, F_OK)) passed_det = 1;
    ck_free(dfn);

    add_to_queue(fn2, st.st_size, passed_det);

  }

  free(nl); /* not tracked */

  if (!queued_paths) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like there are no valid test cases in the input directory! The fuzzer\n"
         "    needs one or more test case to start with - ideally, a small file under\n"
         "    1 kB or so. The cases must be stored as regular files directly in the\n"
         "    input directory.\n");

    FATAL("No usable test cases in '%s'", in_dir);

  }

  last_path_time = 0;
  queued_at_start = queued_paths;

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

static u8 run_target(char** argv, u32 timeout) {

  static struct itimerval it;
  static u32 prev_timed_out = 0;

  int status = 0;
  u32 tb4;

  child_timed_out = 0;

  /* After this memset, trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie. */

  if (dumb_mode == 1 || no_forkserver) {

    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {

        dup2(dev_null_fd, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);

      }

      /* On Linux, would be faster to use O_CLOEXEC. Maybe TODO. */

      close(dev_null_fd);
      close(out_dir_fd);
#ifndef HAVE_ARC4RANDOM
      close(dev_urandom_fd);
#endif
      close(fileno(plot_file));

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "symbolize=0:"
                             "allocator_may_return_null=1", 0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);

      execv(target_path, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }

  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) {

    if (waitpid(child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server (OOM?)");

    }

  }

  if (!WIFSTOPPED(status)) child_pid = 0;

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  ++total_execs;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  prev_timed_out = child_timed_out;

  /* Report outcome to caller. */

  if (WIFSIGNALED(status) && !stop_soon) {

    kill_signal = WTERMSIG(status);

    if (child_timed_out && kill_signal == SIGKILL) return FAULT_TMOUT;

    return FAULT_CRASH;

  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode == 1 || no_forkserver) && tb4 == EXEC_FAIL_SIG)
    return FAULT_ERROR;

  return FAULT_NONE;

}


/* Write modified data to file for testing. If out_file is set, the old file
   is unlinked and a new one is created. Otherwise, out_fd is rewound and
   truncated. */

static void write_to_testcase(void* mem, u32 len) {

  s32 fd = out_fd;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (pre_save_handler) {
    u8* new_data;
    size_t new_size = pre_save_handler(mem, len, &new_data);
    ck_write(fd, new_data, new_size, out_file);
  } else {
    ck_write(fd, mem, len, out_file);
  }

  if (!out_file) {

    if (ftruncate(fd, len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


/* The same, but with an adjustable gap. Used for trimming. */

static void write_with_gap(void* mem, u32 len, u32 skip_at, u32 skip_len) {

  s32 fd = out_fd;
  u32 tail_len = len - skip_at - skip_len;

  if (out_file) {

    unlink(out_file); /* Ignore errors. */

    fd = open(out_file, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", out_file);

  } else lseek(fd, 0, SEEK_SET);

  if (skip_at) ck_write(fd, mem, skip_at, out_file);

  u8 *memu8 = mem;
  if (tail_len) ck_write(fd, memu8 + skip_at + skip_len, tail_len, out_file);

  if (!out_file) {

    if (ftruncate(fd, len - skip_len)) PFATAL("ftruncate() failed");
    lseek(fd, 0, SEEK_SET);

  } else close(fd);

}


static void show_stats(void);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

static u8 calibrate_case(char** argv, struct queue_entry* q, u8* use_mem,
                         u32 handicap, u8 from_queue) {

  static u8 first_trace[MAP_SIZE];

  u8  fault = 0, new_bits = 0, var_detected = 0,
      first_run = (q->exec_cksum == 0);

  u64 start_us, stop_us;

  s32 old_sc = stage_cur, old_sm = stage_max;
  u32 use_tmout = exec_tmout;
  u8* old_sn = stage_name;

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || resuming_fuzz)
    use_tmout = MAX(exec_tmout + CAL_TMOUT_ADD,
                    exec_tmout * CAL_TMOUT_PERC / 100);

  ++q->cal_failed;

  stage_name = "calibration";
  stage_max  = fast_cal ? 3 : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    init_forkserver(argv);

  if (q->exec_cksum) memcpy(first_trace, trace_bits, MAP_SIZE);

  start_us = get_cur_time_us();

  for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

    u32 cksum;

    if (!first_run && !(stage_cur % stats_update_freq)) show_stats();

    write_to_testcase(use_mem, q->len);

    fault = run_target(argv, use_tmout);

    /* stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (stop_soon || fault != crash_mode) goto abort_calibration;

    if (!dumb_mode && !stage_cur && !count_bytes(trace_bits)) {
      fault = FAULT_NOINST;
      goto abort_calibration;
    }

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {

      u8 hnb = has_new_bits(virgin_bits);
      if (hnb > new_bits) new_bits = hnb;

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < MAP_SIZE; ++i) {

          if (!var_bytes[i] && first_trace[i] != trace_bits[i]) {

            var_bytes[i] = 1;
            stage_max    = CAL_CYCLES_LONG;

          }

        }

        var_detected = 1;

      } else {

        q->exec_cksum = cksum;
        memcpy(first_trace, trace_bits, MAP_SIZE);

      }

    }

  }

  stop_us = get_cur_time_us();

  total_cal_us     += stop_us - start_us;
  total_cal_cycles += stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  ++total_bitmap_entries;

  update_bitmap_score(q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!dumb_mode && first_run && !fault && !new_bits) fault = FAULT_NOBITS;

abort_calibration:

  if (new_bits == 2 && !q->has_new_cov) {
    q->has_new_cov = 1;
    ++queued_with_cov;
  }

  /* Mark variable paths. */

  if (var_detected) {

    var_byte_count = count_bytes(var_bytes);

    if (!q->var_behavior) {
      mark_as_variable(q);
      ++queued_variable;
    }

  }

  stage_name = old_sn;
  stage_cur  = old_sc;
  stage_max  = old_sm;

  if (!first_run) show_stats();

  return fault;

}


/* Examine map coverage. Called once, for first test case. */

static void check_map_coverage(void) {

  u32 i;

  if (count_bytes(trace_bits) < 100) return;

  for (i = (1 << (MAP_SIZE_POW2 - 1)); i < MAP_SIZE; ++i)
    if (trace_bits[i]) return;

  WARNF("Recompile binary with newer version of afl to improve coverage!");

}


/* Perform dry run of all test cases to confirm that the app is working as
   expected. This is done only for the initial inputs, and only once. */

static void perform_dry_run(char** argv) {

  struct queue_entry* q = queue;
  u32 cal_failures = 0;
  u8* skip_crashes = getenv("AFL_SKIP_CRASHES");

  while (q) {

    u8* use_mem;
    u8  res;
    s32 fd;

    u8* fn = strrchr(q->fname, '/') + 1;

    ACTF("Attempting dry run with '%s'...", fn);

    fd = open(q->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", q->fname);

    use_mem = ck_alloc_nozero(q->len);

    if (read(fd, use_mem, q->len) != q->len)
      FATAL("Short read from '%s'", q->fname);

    close(fd);

    res = calibrate_case(argv, q, use_mem, 0, 1);
    ck_free(use_mem);

    if (stop_soon) return;

    if (res == crash_mode || res == FAULT_NOBITS)
      SAYF(cGRA "    len = %u, map size = %u, exec speed = %llu us\n" cRST, 
           q->len, q->bitmap_size, q->exec_us);

    switch (res) {

      case FAULT_NONE:

        if (q == queue) check_map_coverage();

        if (crash_mode) FATAL("Test case '%s' does *NOT* crash", fn);

        break;

      case FAULT_TMOUT:

        if (timeout_given) {

          /* The -t nn+ syntax in the command line sets timeout_given to '2' and
             instructs afl-fuzz to tolerate but skip queue entries that time
             out. */

          if (timeout_given > 1) {
            WARNF("Test case results in a timeout (skipping)");
            q->cal_failed = CAL_CHANCES;
            ++cal_failures;
            break;
          }

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    Usually, the right thing to do is to relax the -t option - or to delete it\n"
               "    altogether and allow the fuzzer to auto-calibrate. That said, if you know\n"
               "    what you are doing and want to simply skip the unruly test cases, append\n"
               "    '+' at the end of the value passed to -t ('-t %u+').\n", exec_tmout,
               exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "The program took more than %u ms to process one of the initial test cases.\n"
               "    This is bad news; raising the limit with the -t option is possible, but\n"
               "    will probably make the fuzzing process extremely slow.\n\n"

               "    If this test case is just a fluke, the other option is to just avoid it\n"
               "    altogether, and find one that is less of a CPU hog.\n", exec_tmout);

          FATAL("Test case '%s' results in a timeout", fn);

        }

      case FAULT_CRASH:  

        if (crash_mode) break;

        if (skip_crashes) {
          WARNF("Test case results in a crash (skipping)");
          q->cal_failed = CAL_CHANCES;
          ++cal_failures;
          break;
        }

        if (mem_limit) {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               "    - The current memory limit (%s) is too low for this program, causing\n"
               "      it to die due to OOM when parsing valid files. To fix this, try\n"
               "      bumping it up with the -m setting in the command line. If in doubt,\n"
               "      try something along the lines of:\n\n"

               MSG_ULIMIT_USAGE " /path/to/binary [...] <testcase )\n\n"

               "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
               "      estimate the required amount of virtual memory for the binary. Also,\n"
               "      if you are using ASAN, see %s/notes_for_asan.txt.\n\n"

               MSG_FORK_ON_APPLE

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <afl-users@googlegroups.com> for troubleshooting tips.\n",
               DMS(mem_limit << 20), mem_limit - 1, doc_path);

        } else {

          SAYF("\n" cLRD "[-] " cRST
               "Oops, the program crashed with one of the test cases provided. There are\n"
               "    several possible explanations:\n\n"

               "    - The test case causes known crashes under normal working conditions. If\n"
               "      so, please remove it. The fuzzer should be seeded with interesting\n"
               "      inputs - but not ones that cause an outright crash.\n\n"

               MSG_FORK_ON_APPLE

               "    - Least likely, there is a horrible bug in the fuzzer. If other options\n"
               "      fail, poke <afl-users@googlegroups.com> for troubleshooting tips.\n");

        }
#undef MSG_ULIMIT_USAGE
#undef MSG_FORK_ON_APPLE

        FATAL("Test case '%s' results in a crash", fn);

      case FAULT_ERROR:

        FATAL("Unable to execute target application ('%s')", argv[0]);

      case FAULT_NOINST:

        FATAL("No instrumentation detected");

      case FAULT_NOBITS: 

        ++useless_at_start;

        if (!in_bitmap && !shuffle_queue)
          WARNF("No new instrumentation output, test case may be useless.");

        break;

    }

    if (q->var_behavior) WARNF("Instrumentation output varies across runs.");

    q = q->next;

  }

  if (cal_failures) {

    if (cal_failures == queued_paths)
      FATAL("All test cases time out%s, giving up!",
            skip_crashes ? " or crash" : "");

    WARNF("Skipped %u test cases (%0.02f%%) due to timeouts%s.", cal_failures,
          ((double)cal_failures) * 100 / queued_paths,
          skip_crashes ? " or crashes" : "");

    if (cal_failures * 5 > queued_paths)
      WARNF(cLRD "High percentage of rejected test cases, check settings!");

  }

  OKF("All test cases processed.");

}


/* Helper function: link() if possible, copy otherwise. */

static void link_or_copy(u8* old_path, u8* new_path) {

  s32 i = link(old_path, new_path);
  s32 sfd, dfd;
  u8* tmp;

  if (!i) return;

  sfd = open(old_path, O_RDONLY);
  if (sfd < 0) PFATAL("Unable to open '%s'", old_path);

  dfd = open(new_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (dfd < 0) PFATAL("Unable to create '%s'", new_path);

  tmp = ck_alloc(64 * 1024);

  while ((i = read(sfd, tmp, 64 * 1024)) > 0) 
    ck_write(dfd, tmp, i, new_path);

  if (i < 0) PFATAL("read() failed");

  ck_free(tmp);
  close(sfd);
  close(dfd);

}


static void nuke_resume_dir(void);

/* Create hard links for input test cases in the output directory, choosing
   good names and pivoting accordingly. */

static void pivot_inputs(void) {

  struct queue_entry* q = queue;
  u32 id = 0;

  ACTF("Creating hard links for all input files...");

  while (q) {

    u8  *nfn, *rsl = strrchr(q->fname, '/');
    u32 orig_id;

    if (!rsl) rsl = q->fname; else ++rsl;

    /* If the original file name conforms to the syntax and the recorded
       ID matches the one we'd assign, just use the original file name.
       This is valuable for resuming fuzzing runs. */

#ifndef SIMPLE_FILES
#  define CASE_PREFIX "id:"
#else
#  define CASE_PREFIX "id_"
#endif /* ^!SIMPLE_FILES */

    if (!strncmp(rsl, CASE_PREFIX, 3) &&
        sscanf(rsl + 3, "%06u", &orig_id) == 1 && orig_id == id) {

      u8* src_str;
      u32 src_id;

      resuming_fuzz = 1;
      nfn = alloc_printf("%s/queue/%s", out_dir, rsl);

      /* Since we're at it, let's also try to find parent and figure out the
         appropriate depth for this entry. */

      src_str = strchr(rsl + 3, ':');

      if (src_str && sscanf(src_str + 1, "%06u", &src_id) == 1) {

        struct queue_entry* s = queue;
        while (src_id-- && s) s = s->next;
        if (s) q->depth = s->depth + 1;

        if (max_depth < q->depth) max_depth = q->depth;

      }

    } else {

      /* No dice - invent a new name, capturing the original one as a
         substring. */

#ifndef SIMPLE_FILES

      u8* use_name = strstr(rsl, ",orig:");

      if (use_name) use_name += 6; else use_name = rsl;
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */

    link_or_copy(q->fname, nfn);
    ck_free(q->fname);
    q->fname = nfn;

    /* Make sure that the passed_det value carries over, too. */

    if (q->passed_det) mark_as_det_done(q);

    q = q->next;
    ++id;

  }

  if (in_place_resume) nuke_resume_dir();

}


#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Uses a static buffer. */

static u8* describe_op(u8 hnb) {

  static u8 ret[256];

  if (syncing_party) {

    sprintf(ret, "sync:%s,src:%06u", syncing_party, syncing_case);

  } else {

    sprintf(ret, "src:%06u", current_entry);

    sprintf(ret + strlen(ret), ",time:%llu", get_cur_time() - start_time);

    if (splicing_with >= 0)
      sprintf(ret + strlen(ret), "+%06d", splicing_with);

    sprintf(ret + strlen(ret), ",op:%s", stage_short);

    if (stage_cur_byte >= 0) {

      sprintf(ret + strlen(ret), ",pos:%d", stage_cur_byte);

      if (stage_val_type != STAGE_VAL_NONE)
        sprintf(ret + strlen(ret), ",val:%s%+d", 
                (stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                stage_cur_val);

    } else sprintf(ret + strlen(ret), ",rep:%d", stage_cur_val);

  }

  if (hnb == 2) strcat(ret, ",+cov");

  return ret;

}

#endif /* !SIMPLE_FILES */


/* Write a message accompanying the crash directory :-) */

static void write_crash_readme(void) {

  u8* fn = alloc_printf("%s/crashes/README.txt", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  ck_free(fn);

  /* Do not die on errors here - that would be impolite. */

  if (fd < 0) return;

  f = fdopen(fd, "w");

  if (!f) {
    close(fd);
    return;
  }

  fprintf(f, "Command line used to find this crash:\n\n"

             "%s\n\n"

             "If you can't reproduce a bug outside of afl-fuzz, be sure to set the same\n"
             "memory limit. The limit used for this fuzzing session was %s.\n\n"

             "Need a tool to minimize test cases before investigating the crashes or sending\n"
             "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

             "Found any cool bugs in open-source tools using afl-fuzz? If yes, please drop\n"
             "an mail at <afl-users@googlegroups.com> once the issues are fixed\n\n"

             "  https://github.com/vanhauser-thc/AFLplusplus\n\n",

             orig_cmdline, DMS(mem_limit << 20)); /* ignore errors */

  fclose(f);

}


/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

static u8 save_if_interesting(char** argv, void* mem, u32 len, u8 fault) {

  if (len == 0) return 0;

  u8  *fn = "";
  u8  hnb;
  s32 fd;
  u8  keeping = 0, res;

  /* Update path frequency. */
  u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

  struct queue_entry* q = queue;
  while (q) {
    if (q->exec_cksum == cksum)
      q->n_fuzz = q->n_fuzz + 1;

    q = q->next;

  }

  if (fault == crash_mode) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    if (!(hnb = has_new_bits(virgin_bits))) {
      if (crash_mode) ++total_crashes;
      return 0;
    }    

#ifndef SIMPLE_FILES

    fn = alloc_printf("%s/queue/id:%06u,%s", out_dir, queued_paths,
                      describe_op(hnb));

#else

    fn = alloc_printf("%s/queue/id_%06u", out_dir, queued_paths);

#endif /* ^!SIMPLE_FILES */

    add_to_queue(fn, len, 0);

    if (hnb == 2) {
      queue_top->has_new_cov = 1;
      ++queued_with_cov;
    }

    queue_top->exec_cksum = cksum;

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    res = calibrate_case(argv, queue_top, mem, queue_cycle - 1, 0);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) PFATAL("Unable to create '%s'", fn);
    ck_write(fd, mem, len, fn);
    close(fd);

    keeping = 1;

  }

  switch (fault) {

    case FAULT_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "dumb" mode, we
         just keep everything. */

      ++total_tmouts;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_tmout)) return keeping;

      }

      ++unique_tmouts;

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        new_fault = run_target(argv, hang_tmout);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

      }

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/hangs/id:%06llu,%s", out_dir,
                        unique_hangs, describe_op(0));

#else

      fn = alloc_printf("%s/hangs/id_%06llu", out_dir,
                        unique_hangs);

#endif /* ^!SIMPLE_FILES */

      ++unique_hangs;

      last_hang_time = get_cur_time();

      break;

    case FAULT_CRASH:

keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++total_crashes;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
                        kill_signal);

#endif /* ^!SIMPLE_FILES */

      ++unique_crashes;

      last_crash_time = get_cur_time();
      last_crash_execs = total_execs;

      break;

    case FAULT_ERROR: FATAL("Unable to execute target application");

    default: return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  ck_write(fd, mem, len, fn);
  close(fd);

  ck_free(fn);

  return keeping;

}


/* When resuming, try to find the queue position to start from. This makes sense
   only when resuming, and when we can find the original fuzzer_stats. */

static u32 find_start_position(void) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return 0;

  if (in_place_resume) fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return 0;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "cur_path          : ");
  if (!off) return 0;

  ret = atoi(off + 20);
  if (ret >= queued_paths) ret = 0;
  return ret;

}


/* The same, but for timeouts. The idea is that when resuming sessions without
   -t given, we don't want to keep auto-scaling the timeout over and over
   again to prevent it from growing due to random flukes. */

static void find_timeout(void) {

  static u8 tmp[4096]; /* Ought to be enough for anybody. */

  u8  *fn, *off;
  s32 fd, i;
  u32 ret;

  if (!resuming_fuzz) return;

  if (in_place_resume) fn = alloc_printf("%s/fuzzer_stats", out_dir);
  else fn = alloc_printf("%s/../fuzzer_stats", in_dir);

  fd = open(fn, O_RDONLY);
  ck_free(fn);

  if (fd < 0) return;

  i = read(fd, tmp, sizeof(tmp) - 1); (void)i; /* Ignore errors */
  close(fd);

  off = strstr(tmp, "exec_timeout   : ");
  if (!off) return;

  ret = atoi(off + 17);
  if (ret <= 4) return;

  exec_tmout = ret;
  timeout_given = 3;

}


/* Update stats file for unattended monitoring. */

static void write_stats_file(double bitmap_cvg, double stability, double eps) {

  static double last_bcvg, last_stab, last_eps;

  u8* fn = alloc_printf("%s/fuzzer_stats", out_dir);
  s32 fd;
  FILE* f;

  fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

  f = fdopen(fd, "w");

  if (!f) PFATAL("fdopen() failed");

  /* Keep last values in case we're called from another context
     where exec/sec stats and such are not readily available. */

  if (!bitmap_cvg && !stability && !eps) {
    bitmap_cvg = last_bcvg;
    stability  = last_stab;
    eps        = last_eps;
  } else {
    last_bcvg = bitmap_cvg;
    last_stab = stability;
    last_eps  = eps;
  }

  fprintf(f, "start_time        : %llu\n"
             "last_update       : %llu\n"
             "fuzzer_pid        : %d\n"
             "cycles_done       : %llu\n"
             "execs_done        : %llu\n"
             "execs_per_sec     : %0.02f\n"
             "paths_total       : %u\n"
             "paths_favored     : %u\n"
             "paths_found       : %u\n"
             "paths_imported    : %u\n"
             "max_depth         : %u\n"
             "cur_path          : %u\n" /* Must match find_start_position() */
             "pending_favs      : %u\n"
             "pending_total     : %u\n"
             "variable_paths    : %u\n"
             "stability         : %0.02f%%\n"
             "bitmap_cvg        : %0.02f%%\n"
             "unique_crashes    : %llu\n"
             "unique_hangs      : %llu\n"
             "last_path         : %llu\n"
             "last_crash        : %llu\n"
             "last_hang         : %llu\n"
             "execs_since_crash : %llu\n"
             "exec_timeout      : %u\n"
             "afl_banner        : %s\n"
             "afl_version       : " VERSION "\n"
             "target_mode       : %s%s%s%s%s%s%s%s\n"
             "command_line      : %s\n",
             start_time / 1000, get_cur_time() / 1000, getpid(),
             queue_cycle ? (queue_cycle - 1) : 0, total_execs, eps,
             queued_paths, queued_favored, queued_discovered, queued_imported,
             max_depth, current_entry, pending_favored, pending_not_fuzzed,
             queued_variable, stability, bitmap_cvg, unique_crashes,
             unique_hangs, last_path_time / 1000, last_crash_time / 1000,
             last_hang_time / 1000, total_execs - last_crash_execs,
             exec_tmout, use_banner,
             unicorn_mode ? "unicorn" : "", qemu_mode ? "qemu " : "", dumb_mode ? " dumb " : "",
             no_forkserver ? "no_forksrv " : "", crash_mode ? "crash " : "",
             persistent_mode ? "persistent " : "", deferred_mode ? "deferred " : "",
             (unicorn_mode || qemu_mode || dumb_mode || no_forkserver || crash_mode ||
              persistent_mode || deferred_mode) ? "" : "default",
             orig_cmdline);
             /* ignore errors */

  fclose(f);

}


/* Update the plot file if there is a reason to. */

static void maybe_update_plot_file(double bitmap_cvg, double eps) {

  static u32 prev_qp, prev_pf, prev_pnf, prev_ce, prev_md;
  static u64 prev_qc, prev_uc, prev_uh;

  if (prev_qp == queued_paths && prev_pf == pending_favored && 
      prev_pnf == pending_not_fuzzed && prev_ce == current_entry &&
      prev_qc == queue_cycle && prev_uc == unique_crashes &&
      prev_uh == unique_hangs && prev_md == max_depth) return;

  prev_qp  = queued_paths;
  prev_pf  = pending_favored;
  prev_pnf = pending_not_fuzzed;
  prev_ce  = current_entry;
  prev_qc  = queue_cycle;
  prev_uc  = unique_crashes;
  prev_uh  = unique_hangs;
  prev_md  = max_depth;

  /* Fields in the file:

     unix_time, cycles_done, cur_path, paths_total, paths_not_fuzzed,
     favored_not_fuzzed, unique_crashes, unique_hangs, max_depth,
     execs_per_sec */

  fprintf(plot_file, 
          "%llu, %llu, %u, %u, %u, %u, %0.02f%%, %llu, %llu, %u, %0.02f\n",
          get_cur_time() / 1000, queue_cycle - 1, current_entry, queued_paths,
          pending_not_fuzzed, pending_favored, bitmap_cvg, unique_crashes,
          unique_hangs, max_depth, eps); /* ignore errors */

  fflush(plot_file);

}



/* A helper function for maybe_delete_out_dir(), deleting all prefixed
   files in a directory. */

static u8 delete_files(u8* path, u8* prefix) {

  DIR* d;
  struct dirent* d_ent;

  d = opendir(path);

  if (!d) return 0;

  while ((d_ent = readdir(d))) {

    if (d_ent->d_name[0] != '.' && (!prefix ||
        !strncmp(d_ent->d_name, prefix, strlen(prefix)))) {

      u8* fname = alloc_printf("%s/%s", path, d_ent->d_name);
      if (unlink(fname)) PFATAL("Unable to delete '%s'", fname);
      ck_free(fname);

    }

  }

  closedir(d);

  return !!rmdir(path);

}


/* Get the number of runnable processes, with some simple smoothing. */

static double get_runnable_processes(void) {

  static double res;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  /* I don't see any portable sysctl or so that would quickly give us the
     number of runnable processes; the 1-minute load average can be a
     semi-decent approximation, though. */

  if (getloadavg(&res, 1) != 1) return 0;

#else

  /* On Linux, /proc/stat is probably the best way; load averages are
     computed in funny ways and sometimes don't reflect extremely short-lived
     processes well. */

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];
  u32 val = 0;

  if (!f) return 0;

  while (fgets(tmp, sizeof(tmp), f)) {

    if (!strncmp(tmp, "procs_running ", 14) ||
        !strncmp(tmp, "procs_blocked ", 14)) val += atoi(tmp + 14);

  }
 
  fclose(f);

  if (!res) {

    res = val;

  } else {

    res = res * (1.0 - 1.0 / AVG_SMOOTHING) +
          ((double)val) * (1.0 / AVG_SMOOTHING);

  }

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  return res;

}


/* Delete the temporary directory used for in-place session resume. */

static void nuke_resume_dir(void) {

  u8* fn;

  fn = alloc_printf("%s/_resume/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/_resume", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  return;

dir_cleanup_failed:

  FATAL("_resume directory cleanup failed");

}


/* Delete fuzzer output directory if we recognize it as ours, if the fuzzer
   is not currently running, and if the last run time isn't too great. */

static void maybe_delete_out_dir(void) {

  FILE* f;
  u8 *fn = alloc_printf("%s/fuzzer_stats", out_dir);

  /* See if the output directory is locked. If yes, bail out. If not,
     create a lock that will persist for the lifetime of the process
     (this requires leaving the descriptor open).*/

  out_dir_fd = open(out_dir, O_RDONLY);
  if (out_dir_fd < 0) PFATAL("Unable to open '%s'", out_dir);

#ifndef __sun

  if (flock(out_dir_fd, LOCK_EX | LOCK_NB) && errno == EWOULDBLOCK) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the job output directory is being actively used by another\n"
         "    instance of afl-fuzz. You will need to choose a different %s\n"
         "    or stop the other process first.\n",
         sync_id ? "fuzzer ID" : "output location");

    FATAL("Directory '%s' is in use", out_dir);

  }

#endif /* !__sun */

  f = fopen(fn, "r");

  if (f) {

    u64 start_time2, last_update;

    if (fscanf(f, "start_time     : %llu\n"
                  "last_update    : %llu\n", &start_time2, &last_update) != 2)
      FATAL("Malformed data in '%s'", fn);

    fclose(f);

    /* Let's see how much work is at stake. */

    if (!in_place_resume && last_update - start_time2 > OUTPUT_GRACE * 60) {

      SAYF("\n" cLRD "[-] " cRST
           "The job output directory already exists and contains the results of more\n"
           "    than %d minutes worth of fuzzing. To avoid data loss, afl-fuzz will *NOT*\n"
           "    automatically delete this data for you.\n\n"

           "    If you wish to start a new session, remove or rename the directory manually,\n"
           "    or specify a different output location for this job. To resume the old\n"
           "    session, put '-' as the input directory in the command line ('-i -') and\n"
           "    try again.\n", OUTPUT_GRACE);

       FATAL("At-risk data found in '%s'", out_dir);

    }

  }

  ck_free(fn);

  /* The idea for in-place resume is pretty simple: we temporarily move the old
     queue/ to a new location that gets deleted once import to the new queue/
     is finished. If _resume/ already exists, the current queue/ may be
     incomplete due to an earlier abort, so we want to use the old _resume/
     dir instead, and we let rename() fail silently. */

  if (in_place_resume) {

    u8* orig_q = alloc_printf("%s/queue", out_dir);

    in_dir = alloc_printf("%s/_resume", out_dir);

    rename(orig_q, in_dir); /* Ignore errors */

    OKF("Output directory exists, will attempt session resume.");

    ck_free(orig_q);

  } else {

    OKF("Output directory exists but deemed OK to reuse.");

  }

  ACTF("Deleting old session data...");

  /* Okay, let's get the ball rolling! First, we need to get rid of the entries
     in <out_dir>/.synced/.../id:*, if any are present. */

  if (!in_place_resume) {

    fn = alloc_printf("%s/.synced", out_dir);
    if (delete_files(fn, NULL)) goto dir_cleanup_failed;
    ck_free(fn);

  }

  /* Next, we need to clean up <out_dir>/queue/.state/ subdirectories: */

  fn = alloc_printf("%s/queue/.state/deterministic_done", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/auto_extras", out_dir);
  if (delete_files(fn, "auto_")) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/redundant_edges", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue/.state/variable_behavior", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* Then, get rid of the .state subdirectory itself (should be empty by now)
     and everything matching <out_dir>/queue/id:*. */

  fn = alloc_printf("%s/queue/.state", out_dir);
  if (rmdir(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/queue", out_dir);
  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* All right, let's do <out_dir>/crashes/id:* and <out_dir>/hangs/id:*. */

  if (!in_place_resume) {

    fn = alloc_printf("%s/crashes/README.txt", out_dir);
    unlink(fn); /* Ignore errors */
    ck_free(fn);

  }

  fn = alloc_printf("%s/crashes", out_dir);

  /* Make backup of the crashes directory if it's not empty and if we're
     doing in-place resume. */

  if (in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04d%02d%02d%02d%02d%02d", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/hangs", out_dir);

  /* Backup hangs, too. */

  if (in_place_resume && rmdir(fn)) {

    time_t cur_t = time(0);
    struct tm* t = localtime(&cur_t);

#ifndef SIMPLE_FILES

    u8* nfn = alloc_printf("%s.%04d-%02d-%02d-%02d:%02d:%02d", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#else

    u8* nfn = alloc_printf("%s_%04d%02d%02d%02d%02d%02d", fn,
                           t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                           t->tm_hour, t->tm_min, t->tm_sec);

#endif /* ^!SIMPLE_FILES */

    rename(fn, nfn); /* Ignore errors. */
    ck_free(nfn);

  }

  if (delete_files(fn, CASE_PREFIX)) goto dir_cleanup_failed;
  ck_free(fn);

  /* And now, for some finishing touches. */

  if (file_extension) {
    fn = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);
  } else {
    fn = alloc_printf("%s/.cur_input", out_dir);
  }

  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/fuzz_bitmap", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  if (!in_place_resume) {
    fn  = alloc_printf("%s/fuzzer_stats", out_dir);
    if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
    ck_free(fn);
  }

  fn = alloc_printf("%s/plot_data", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  fn = alloc_printf("%s/cmdline", out_dir);
  if (unlink(fn) && errno != ENOENT) goto dir_cleanup_failed;
  ck_free(fn);

  OKF("Output dir cleanup successful.");

  /* Wow... is that all? If yes, celebrate! */

  return;

dir_cleanup_failed:

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, the fuzzer tried to reuse your output directory, but bumped into\n"
       "    some files that shouldn't be there or that couldn't be removed - so it\n"
       "    decided to abort! This happened while processing this path:\n\n"

       "    %s\n\n"
       "    Please examine and manually delete the files, or specify a different\n"
       "    output location for the tool.\n", fn);

  FATAL("Output directory cleanup failed");

}


static void check_term_size(void);


/* A spiffy retro stats screen! This is called every stats_update_freq
   execve() calls, plus in several other circumstances. */

static void show_stats(void) {

  static u64 last_stats_ms, last_plot_ms, last_ms, last_execs;
  static double avg_exec;
  double t_byte_ratio, stab_ratio;

  u64 cur_ms;
  u32 t_bytes, t_bits;

  u32 banner_len, banner_pad;
  u8  tmp[256];

  cur_ms = get_cur_time();

  /* If not enough time has passed since last UI update, bail out. */

  if (cur_ms - last_ms < 1000 / UI_TARGET_HZ) return;

  /* Check if we're past the 10 minute mark. */

  if (cur_ms - start_time > 10 * 60 * 1000) run_over10m = 1;

  /* Calculate smoothed exec speed stats. */

  if (!last_execs) {

    avg_exec = ((double)total_execs) * 1000 / (cur_ms - start_time);

  } else {

    double cur_avg = ((double)(total_execs - last_execs)) * 1000 /
                     (cur_ms - last_ms);

    /* If there is a dramatic (5x+) jump in speed, reset the indicator
       more quickly. */

    if (cur_avg * 5 < avg_exec || cur_avg / 5 > avg_exec)
      avg_exec = cur_avg;

    avg_exec = avg_exec * (1.0 - 1.0 / AVG_SMOOTHING) +
               cur_avg * (1.0 / AVG_SMOOTHING);

  }

  last_ms = cur_ms;
  last_execs = total_execs;

  /* Tell the callers when to contact us (as measured in execs). */

  stats_update_freq = avg_exec / (UI_TARGET_HZ * 10);
  if (!stats_update_freq) stats_update_freq = 1;

  /* Do some bitmap stats. */

  t_bytes = count_non_255_bytes(virgin_bits);
  t_byte_ratio = ((double)t_bytes * 100) / MAP_SIZE;

  if (t_bytes)
    stab_ratio = 100 - ((double)var_byte_count) * 100 / t_bytes;
  else
    stab_ratio = 100;

  /* Roughly every minute, update fuzzer stats and save auto tokens. */

  if (cur_ms - last_stats_ms > STATS_UPDATE_SEC * 1000) {

    last_stats_ms = cur_ms;
    write_stats_file(t_byte_ratio, stab_ratio, avg_exec);
    save_auto();
    write_bitmap();

  }

  /* Every now and then, write plot data. */

  if (cur_ms - last_plot_ms > PLOT_UPDATE_SEC * 1000) {

    last_plot_ms = cur_ms;
    maybe_update_plot_file(t_byte_ratio, avg_exec);

  }

  /* Honor AFL_EXIT_WHEN_DONE and AFL_BENCH_UNTIL_CRASH. */

  if (!dumb_mode && cycles_wo_finds > 100 && !pending_not_fuzzed &&
      getenv("AFL_EXIT_WHEN_DONE")) stop_soon = 2;

  if (total_crashes && getenv("AFL_BENCH_UNTIL_CRASH")) stop_soon = 2;

  /* If we're not on TTY, bail out. */

  if (not_on_tty) return;

  /* Compute some mildly useful bitmap stats. */

  t_bits = (MAP_SIZE << 3) - count_bits(virgin_bits);

  /* Now, for the visuals... */

  if (clear_screen) {

    SAYF(TERM_CLEAR CURSOR_HIDE);
    clear_screen = 0;

    check_term_size();

  }

  SAYF(TERM_HOME);

  if (term_too_small) {

    SAYF(cBRI "Your terminal is too small to display the UI.\n"
         "Please resize terminal window to at least 79x24.\n" cRST);

    return;

  }

  /* Let's start by drawing a centered banner. */

  banner_len = (crash_mode ? 24 : 22) + strlen(VERSION) + strlen(use_banner) + strlen(power_name) + 3 + 5;
  banner_pad = (79 - banner_len) / 2;
  memset(tmp, ' ', banner_pad);

#ifdef HAVE_AFFINITY
  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s) " cPIN "[%s]" cBLU " {%d}",  crash_mode ? cPIN "peruvian were-rabbit" :
          cYEL "american fuzzy lop", use_banner, power_name, cpu_aff);
#else
  sprintf(tmp + banner_pad, "%s " cLCY VERSION cLGN
          " (%s) " cPIN "[%s]",  crash_mode ? cPIN "peruvian were-rabbit" :
          cYEL "american fuzzy lop", use_banner, power_name);
#endif /* HAVE_AFFINITY */

  SAYF("\n%s\n", tmp);

  /* "Handy" shortcuts for drawing boxes... */

#define bSTG    bSTART cGRA
#define bH2     bH bH
#define bH5     bH2 bH2 bH
#define bH10    bH5 bH5
#define bH20    bH10 bH10
#define bH30    bH20 bH10
#define SP5     "     "
#define SP10    SP5 SP5
#define SP20    SP10 SP10

  /* Lord, forgive me this. */

  SAYF(SET_G1 bSTG bLT bH bSTOP cCYA " process timing " bSTG bH30 bH5 bH bHB
       bH bSTOP cCYA " overall results " bSTG bH2 bH2 bRT "\n");

  if (dumb_mode) {

    strcpy(tmp, cRST);

  } else {

    u64 min_wo_finds = (cur_ms - last_path_time) / 1000 / 60;

    /* First queue cycle: don't stop now! */
    if (queue_cycle == 1 || min_wo_finds < 15) strcpy(tmp, cMGN); else

    /* Subsequent cycles, but we're still making finds. */
    if (cycles_wo_finds < 25 || min_wo_finds < 30) strcpy(tmp, cYEL); else

    /* No finds for a long time and no test cases to try. */
    if (cycles_wo_finds > 100 && !pending_not_fuzzed && min_wo_finds > 120)
      strcpy(tmp, cLGN);

    /* Default: cautiously OK to stop? */
    else strcpy(tmp, cLBL);

  }

  SAYF(bV bSTOP "        run time : " cRST "%-33s " bSTG bV bSTOP
       "  cycles done : %s%-5s " bSTG bV "\n",
       DTD(cur_ms, start_time), tmp, DI(queue_cycle - 1));

  /* We want to warn people about not seeing new paths after a full cycle,
     except when resuming fuzzing or running in non-instrumented mode. */

  if (!dumb_mode && (last_path_time || resuming_fuzz || queue_cycle == 1 ||
      in_bitmap || crash_mode)) {

    SAYF(bV bSTOP "   last new path : " cRST "%-33s ",
         DTD(cur_ms, last_path_time));

  } else {

    if (dumb_mode)

      SAYF(bV bSTOP "   last new path : " cPIN "n/a" cRST
           " (non-instrumented mode)       ");

     else

      SAYF(bV bSTOP "   last new path : " cRST "none yet " cLRD
           "(odd, check syntax!)     ");

  }

  SAYF(bSTG bV bSTOP "  total paths : " cRST "%-5s " bSTG bV "\n",
       DI(queued_paths));

  /* Highlight crashes in red if found, denote going over the KEEP_UNIQUE_CRASH
     limit with a '+' appended to the count. */

  sprintf(tmp, "%s%s", DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  SAYF(bV bSTOP " last uniq crash : " cRST "%-33s " bSTG bV bSTOP
       " uniq crashes : %s%-6s" bSTG bV "\n",
       DTD(cur_ms, last_crash_time), unique_crashes ? cLRD : cRST,
       tmp);

  sprintf(tmp, "%s%s", DI(unique_hangs),
         (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF(bV bSTOP "  last uniq hang : " cRST "%-33s " bSTG bV bSTOP
       "   uniq hangs : " cRST "%-6s" bSTG bV "\n",
       DTD(cur_ms, last_hang_time), tmp);

  SAYF(bVR bH bSTOP cCYA " cycle progress " bSTG bH10 bH5 bH2 bH2 bHB bH bSTOP cCYA
       " map coverage " bSTG bH bHT bH20 bH2 bVL "\n");

  /* This gets funny because we want to print several variable-length variables
     together, but then cram them into a fixed-width field - so we need to
     put them in a temporary buffer first. */

  sprintf(tmp, "%s%s%u (%0.02f%%)", DI(current_entry),
          queue_cur->favored ? "." : "*", queue_cur->fuzz_level,
          ((double)current_entry * 100) / queued_paths);

  SAYF(bV bSTOP "  now processing : " cRST "%-16s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%0.02f%% / %0.02f%%", ((double)queue_cur->bitmap_size) *
          100 / MAP_SIZE, t_byte_ratio);

  SAYF("    map density : %s%-21s" bSTG bV "\n", t_byte_ratio > 70 ? cLRD :
       ((t_bytes < 200 && !dumb_mode) ? cPIN : cRST), tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(cur_skipped_paths),
          ((double)cur_skipped_paths * 100) / queued_paths);

  SAYF(bV bSTOP " paths timed out : " cRST "%-16s " bSTG bV, tmp);

  sprintf(tmp, "%0.02f bits/tuple",
          t_bytes ? (((double)t_bits) / t_bytes) : 0);

  SAYF(bSTOP " count coverage : " cRST "%-21s" bSTG bV "\n", tmp);

  SAYF(bVR bH bSTOP cCYA " stage progress " bSTG bH10 bH5 bH2 bH2 bX bH bSTOP cCYA
       " findings in depth " bSTG bH10 bH5 bH2 bH2 bVL "\n");

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_favored),
          ((double)queued_favored) * 100 / queued_paths);

  /* Yeah... it's still going on... halp? */

  SAYF(bV bSTOP "  now trying : " cRST "%-20s " bSTG bV bSTOP
       " favored paths : " cRST "%-22s" bSTG bV "\n", stage_name, tmp);

  if (!stage_max) {

    sprintf(tmp, "%s/-", DI(stage_cur));

  } else {

    sprintf(tmp, "%s/%s (%0.02f%%)", DI(stage_cur), DI(stage_max),
            ((double)stage_cur) * 100 / stage_max);

  }

  SAYF(bV bSTOP " stage execs : " cRST "%-20s " bSTG bV bSTOP, tmp);

  sprintf(tmp, "%s (%0.02f%%)", DI(queued_with_cov),
          ((double)queued_with_cov) * 100 / queued_paths);

  SAYF("  new edges on : " cRST "%-22s" bSTG bV "\n", tmp);

  sprintf(tmp, "%s (%s%s unique)", DI(total_crashes), DI(unique_crashes),
          (unique_crashes >= KEEP_UNIQUE_CRASH) ? "+" : "");

  if (crash_mode) {

    SAYF(bV bSTOP " total execs : " cRST "%-20s " bSTG bV bSTOP
         "   new crashes : %s%-22s" bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  } else {

    SAYF(bV bSTOP " total execs : " cRST "%-20s " bSTG bV bSTOP
         " total crashes : %s%-22s" bSTG bV "\n", DI(total_execs),
         unique_crashes ? cLRD : cRST, tmp);

  }

  /* Show a warning about slow execution. */

  if (avg_exec < 100) {

    sprintf(tmp, "%s/sec (%s)", DF(avg_exec), avg_exec < 20 ?
            "zzzz..." : "slow!");

    SAYF(bV bSTOP "  exec speed : " cLRD "%-20s ", tmp);

  } else {

    sprintf(tmp, "%s/sec", DF(avg_exec));
    SAYF(bV bSTOP "  exec speed : " cRST "%-20s ", tmp);

  }

  sprintf(tmp, "%s (%s%s unique)", DI(total_tmouts), DI(unique_tmouts),
          (unique_hangs >= KEEP_UNIQUE_HANG) ? "+" : "");

  SAYF (bSTG bV bSTOP "  total tmouts : " cRST "%-22s" bSTG bV "\n", tmp);

  /* Aaaalmost there... hold on! */

  SAYF(bVR bH cCYA bSTOP " fuzzing strategy yields " bSTG bH10 bHT bH10
       bH5 bHB bH bSTOP cCYA " path geometry " bSTG bH5 bH2 bVL "\n");

  if (skip_deterministic) {

    strcpy(tmp, "n/a, n/a, n/a");

  } else {

    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP1]), DI(stage_cycles[STAGE_FLIP1]),
            DI(stage_finds[STAGE_FLIP2]), DI(stage_cycles[STAGE_FLIP2]),
            DI(stage_finds[STAGE_FLIP4]), DI(stage_cycles[STAGE_FLIP4]));

  }

  SAYF(bV bSTOP "   bit flips : " cRST "%-36s " bSTG bV bSTOP "    levels : "
       cRST "%-10s" bSTG bV "\n", tmp, DI(max_depth));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_FLIP8]), DI(stage_cycles[STAGE_FLIP8]),
            DI(stage_finds[STAGE_FLIP16]), DI(stage_cycles[STAGE_FLIP16]),
            DI(stage_finds[STAGE_FLIP32]), DI(stage_cycles[STAGE_FLIP32]));

  SAYF(bV bSTOP "  byte flips : " cRST "%-36s " bSTG bV bSTOP "   pending : "
       cRST "%-10s" bSTG bV "\n", tmp, DI(pending_not_fuzzed));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_ARITH8]), DI(stage_cycles[STAGE_ARITH8]),
            DI(stage_finds[STAGE_ARITH16]), DI(stage_cycles[STAGE_ARITH16]),
            DI(stage_finds[STAGE_ARITH32]), DI(stage_cycles[STAGE_ARITH32]));

  SAYF(bV bSTOP " arithmetics : " cRST "%-36s " bSTG bV bSTOP "  pend fav : "
       cRST "%-10s" bSTG bV "\n", tmp, DI(pending_favored));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_INTEREST8]), DI(stage_cycles[STAGE_INTEREST8]),
            DI(stage_finds[STAGE_INTEREST16]), DI(stage_cycles[STAGE_INTEREST16]),
            DI(stage_finds[STAGE_INTEREST32]), DI(stage_cycles[STAGE_INTEREST32]));

  SAYF(bV bSTOP "  known ints : " cRST "%-36s " bSTG bV bSTOP " own finds : "
       cRST "%-10s" bSTG bV "\n", tmp, DI(queued_discovered));

  if (!skip_deterministic)
    sprintf(tmp, "%s/%s, %s/%s, %s/%s",
            DI(stage_finds[STAGE_EXTRAS_UO]), DI(stage_cycles[STAGE_EXTRAS_UO]),
            DI(stage_finds[STAGE_EXTRAS_UI]), DI(stage_cycles[STAGE_EXTRAS_UI]),
            DI(stage_finds[STAGE_EXTRAS_AO]), DI(stage_cycles[STAGE_EXTRAS_AO]));

  SAYF(bV bSTOP "  dictionary : " cRST "%-36s " bSTG bV bSTOP
       "  imported : " cRST "%-10s" bSTG bV "\n", tmp,
       sync_id ? DI(queued_imported) : (u8*)"n/a");

  sprintf(tmp, "%s/%s, %s/%s, %s/%s",
          DI(stage_finds[STAGE_HAVOC]), DI(stage_cycles[STAGE_HAVOC]),
          DI(stage_finds[STAGE_SPLICE]), DI(stage_cycles[STAGE_SPLICE]),
          DI(stage_finds[STAGE_PYTHON]), DI(stage_cycles[STAGE_PYTHON]));

  SAYF(bV bSTOP "       havoc : " cRST "%-36s " bSTG bV bSTOP, tmp);

  if (t_bytes) sprintf(tmp, "%0.02f%%", stab_ratio);
    else strcpy(tmp, "n/a");

  SAYF(" stability : %s%-10s" bSTG bV "\n", (stab_ratio < 85 && var_byte_count > 40)
       ? cLRD : ((queued_variable && (!persistent_mode || var_byte_count > 20))
       ? cMGN : cRST), tmp);

  if (!bytes_trim_out) {

    sprintf(tmp, "n/a, ");

  } else {

    sprintf(tmp, "%0.02f%%/%s, ",
            ((double)(bytes_trim_in - bytes_trim_out)) * 100 / bytes_trim_in,
            DI(trim_execs));

  }

  if (!blocks_eff_total) {

    u8 tmp2[128];

    sprintf(tmp2, "n/a");
    strcat(tmp, tmp2);

  } else {

    u8 tmp2[128];

    sprintf(tmp2, "%0.02f%%",
            ((double)(blocks_eff_total - blocks_eff_select)) * 100 /
            blocks_eff_total);

    strcat(tmp, tmp2);

  }
  if (custom_mutator) {
    sprintf(tmp, "%s/%s", DI(stage_finds[STAGE_CUSTOM_MUTATOR]), DI(stage_cycles[STAGE_CUSTOM_MUTATOR]));
    SAYF(bV bSTOP " custom mut. : " cRST "%-36s " bSTG bVR bH20 bH2 bH bRB "\n"
             bLB bH30 bH20 bH2 bH bRB bSTOP cRST RESET_G1, tmp);
  } else {
    SAYF(bV bSTOP "        trim : " cRST "%-36s " bSTG bVR bH20 bH2 bH bRB "\n"
       bLB bH30 bH20 bH2 bRB bSTOP cRST RESET_G1, tmp);
  }

  /* Provide some CPU utilization stats. */

  if (cpu_core_count) {

    double cur_runnable = get_runnable_processes();
    u32 cur_utilization = cur_runnable * 100 / cpu_core_count;

    u8* cpu_color = cCYA;

    /* If we could still run one or more processes, use green. */

    if (cpu_core_count > 1 && cur_runnable + 1 <= cpu_core_count)
      cpu_color = cLGN;

    /* If we're clearly oversubscribed, use red. */

    if (!no_cpu_meter_red && cur_utilization >= 150) cpu_color = cLRD;

#ifdef HAVE_AFFINITY

    if (cpu_aff >= 0) {

      SAYF(SP10 cGRA "[cpu%03u:%s%3u%%" cGRA "]\r" cRST, 
           MIN(cpu_aff, 999), cpu_color,
           MIN(cur_utilization, 999));

    } else {

      SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
           cpu_color, MIN(cur_utilization, 999));
 
   }

#else

    SAYF(SP10 cGRA "   [cpu:%s%3u%%" cGRA "]\r" cRST,
         cpu_color, MIN(cur_utilization, 999));

#endif /* ^HAVE_AFFINITY */

  } else SAYF("\r");

  /* Hallelujah! */

  fflush(0);

}


/* Display quick statistics at the end of processing the input directory,
   plus a bunch of warnings. Some calibration stuff also ended up here,
   along with several hardcoded constants. Maybe clean up eventually. */

static void show_init_stats(void) {

  struct queue_entry* q = queue;
  u32 min_bits = 0, max_bits = 0;
  u64 min_us = 0, max_us = 0;
  u64 avg_us = 0;
  u32 max_len = 0;

  if (total_cal_cycles) avg_us = total_cal_us / total_cal_cycles;

  while (q) {

    if (!min_us || q->exec_us < min_us) min_us = q->exec_us;
    if (q->exec_us > max_us) max_us = q->exec_us;

    if (!min_bits || q->bitmap_size < min_bits) min_bits = q->bitmap_size;
    if (q->bitmap_size > max_bits) max_bits = q->bitmap_size;

    if (q->len > max_len) max_len = q->len;

    q = q->next;

  }

  SAYF("\n");

  if (avg_us > ((qemu_mode || unicorn_mode) ? 50000 : 10000))
    WARNF(cLRD "The target binary is pretty slow! See %s/perf_tips.txt.",
          doc_path);

  /* Let's keep things moving with slow binaries. */

  if (avg_us > 50000) havoc_div = 10;     /* 0-19 execs/sec   */
  else if (avg_us > 20000) havoc_div = 5; /* 20-49 execs/sec  */
  else if (avg_us > 10000) havoc_div = 2; /* 50-100 execs/sec */

  if (!resuming_fuzz) {

    if (max_len > 50 * 1024)
      WARNF(cLRD "Some test cases are huge (%s) - see %s/perf_tips.txt!",
            DMS(max_len), doc_path);
    else if (max_len > 10 * 1024)
      WARNF("Some test cases are big (%s) - see %s/perf_tips.txt.",
            DMS(max_len), doc_path);

    if (useless_at_start && !in_bitmap)
      WARNF(cLRD "Some test cases look useless. Consider using a smaller set.");

    if (queued_paths > 100)
      WARNF(cLRD "You probably have far too many input files! Consider trimming down.");
    else if (queued_paths > 20)
      WARNF("You have lots of input files; try starting small.");

  }

  OKF("Here are some useful stats:\n\n"

      cGRA "    Test case count : " cRST "%u favored, %u variable, %u total\n"
      cGRA "       Bitmap range : " cRST "%u to %u bits (average: %0.02f bits)\n"
      cGRA "        Exec timing : " cRST "%s to %s us (average: %s us)\n",
      queued_favored, queued_variable, queued_paths, min_bits, max_bits, 
      ((double)total_bitmap_size) / (total_bitmap_entries ? total_bitmap_entries : 1),
      DI(min_us), DI(max_us), DI(avg_us));

  if (!timeout_given) {

    /* Figure out the appropriate timeout. The basic idea is: 5x average or
       1x max, rounded up to EXEC_TM_ROUND ms and capped at 1 second.

       If the program is slow, the multiplier is lowered to 2x or 3x, because
       random scheduler jitter is less likely to have any impact, and because
       our patience is wearing thin =) */

    if (avg_us > 50000) exec_tmout = avg_us * 2 / 1000;
    else if (avg_us > 10000) exec_tmout = avg_us * 3 / 1000;
    else exec_tmout = avg_us * 5 / 1000;

    exec_tmout = MAX(exec_tmout, max_us / 1000);
    exec_tmout = (exec_tmout + EXEC_TM_ROUND) / EXEC_TM_ROUND * EXEC_TM_ROUND;

    if (exec_tmout > EXEC_TIMEOUT) exec_tmout = EXEC_TIMEOUT;

    ACTF("No -t option specified, so I'll use exec timeout of %u ms.", 
         exec_tmout);

    timeout_given = 1;

  } else if (timeout_given == 3) {

    ACTF("Applying timeout settings from resumed session (%u ms).", exec_tmout);

  }

  /* In dumb mode, re-running every timing out test case with a generous time
     limit is very expensive, so let's select a more conservative default. */

  if (dumb_mode && !getenv("AFL_HANG_TMOUT"))
    hang_tmout = MIN(EXEC_TIMEOUT, exec_tmout * 2 + 100);

  OKF("All set and ready to roll!");

}


#ifdef USE_PYTHON
static u8 trim_case_python(char** argv, struct queue_entry* q, u8* in_buf) {

  static u8 tmp[64];
  static u8 clean_trace[MAP_SIZE];

  u8  needs_write = 0, fault = 0;
  u32 trim_exec = 0;
  u32 orig_len = q->len;

  stage_name = tmp;
  bytes_trim_in += q->len;

  /* Initialize trimming in the Python module */
  stage_cur = 0;
  stage_max = init_trim_py(in_buf, q->len);

  if (not_on_tty && debug)
    SAYF("[Python Trimming] START: Max %d iterations, %u bytes", stage_max, q->len);

  while(stage_cur < stage_max) {
    sprintf(tmp, "ptrim %s", DI(trim_exec));

    u32 cksum;

    char* retbuf = NULL;
    size_t retlen = 0;

    trim_py(&retbuf, &retlen);

    if (retlen > orig_len)
      FATAL("Trimmed data returned by Python module is larger than original data");

    write_to_testcase(retbuf, retlen);

    fault = run_target(argv, exec_tmout);
    ++trim_execs;

    if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (cksum == q->exec_cksum) {

      q->len = retlen;
      memcpy(in_buf, retbuf, retlen);

      /* Let's save a clean trace, which will be needed by
         update_bitmap_score once we're done with the trimming stuff. */

      if (!needs_write) {

        needs_write = 1;
        memcpy(clean_trace, trace_bits, MAP_SIZE);

      }

      /* Tell the Python module that the trimming was successful */
      stage_cur = post_trim_py(1);

      if (not_on_tty && debug)
        SAYF("[Python Trimming] SUCCESS: %d/%d iterations (now at %u bytes)", stage_cur, stage_max, q->len);
    } else {
      /* Tell the Python module that the trimming was unsuccessful */
      stage_cur = post_trim_py(0);
      if (not_on_tty && debug)
        SAYF("[Python Trimming] FAILURE: %d/%d iterations", stage_cur, stage_max);
    }

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % stats_update_freq)) show_stats();
  }

  if (not_on_tty && debug)
    SAYF("[Python Trimming] DONE: %u bytes -> %u bytes", orig_len, q->len);

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname); /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);

  }



abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}
#endif

/* Trim all new test cases to save cycles when doing deterministic checks. The
   trimmer uses power-of-two increments somewhere between 1/16 and 1/1024 of
   file size, to keep the stage short and sweet. */

static u8 trim_case(char** argv, struct queue_entry* q, u8* in_buf) {

#ifdef USE_PYTHON
  if (py_functions[PY_FUNC_TRIM])
    return trim_case_python(argv, q, in_buf);
#endif

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

  stage_name = tmp;
  bytes_trim_in += q->len;

  /* Select initial chunk len, starting with large steps. */

  len_p2 = next_p2(q->len);

  remove_len = MAX(len_p2 / TRIM_START_STEPS, TRIM_MIN_BYTES);

  /* Continue until the number of steps gets too high or the stepover
     gets too small. */

  while (remove_len >= MAX(len_p2 / TRIM_END_STEPS, TRIM_MIN_BYTES)) {

    u32 remove_pos = remove_len;

    sprintf(tmp, "trim %s/%s", DI(remove_len), DI(remove_len));

    stage_cur = 0;
    stage_max = q->len / remove_len;

    while (remove_pos < q->len) {

      u32 trim_avail = MIN(remove_len, q->len - remove_pos);
      u32 cksum;

      write_with_gap(in_buf, q->len, remove_pos, trim_avail);

      fault = run_target(argv, exec_tmout);
      ++trim_execs;

      if (stop_soon || fault == FAULT_ERROR) goto abort_trimming;

      /* Note that we don't keep track of crashes or hangs here; maybe TODO? */

      cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      /* If the deletion had no impact on the trace, make it permanent. This
         isn't perfect for variable-path inputs, but we're just making a
         best-effort pass, so it's not a big deal if we end up with false
         negatives every now and then. */

      if (cksum == q->exec_cksum) {

        u32 move_tail = q->len - remove_pos - trim_avail;

        q->len -= trim_avail;
        len_p2  = next_p2(q->len);

        memmove(in_buf + remove_pos, in_buf + remove_pos + trim_avail, 
                move_tail);

        /* Let's save a clean trace, which will be needed by
           update_bitmap_score once we're done with the trimming stuff. */

        if (!needs_write) {

          needs_write = 1;
          memcpy(clean_trace, trace_bits, MAP_SIZE);

        }

      } else remove_pos += remove_len;

      /* Since this can be slow, update the screen every now and then. */

      if (!(trim_exec++ % stats_update_freq)) show_stats();
      ++stage_cur;

    }

    remove_len >>= 1;

  }

  /* If we have made changes to in_buf, we also need to update the on-disk
     version of the test case. */

  if (needs_write) {

    s32 fd;

    unlink(q->fname); /* ignore errors */

    fd = open(q->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", q->fname);

    ck_write(fd, in_buf, q->len, q->fname);
    close(fd);

    memcpy(trace_bits, clean_trace, MAP_SIZE);
    update_bitmap_score(q);

  }

abort_trimming:

  bytes_trim_out += q->len;
  return fault;

}


/* Write a modified test case, run program, process results. Handle
   error conditions, returning 1 if it's time to bail out. This is
   a helper function for fuzz_one(). */

u8 common_fuzz_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  if (post_handler) {

    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len) return 0;

  }

  write_to_testcase(out_buf, len);

  fault = run_target(argv, exec_tmout);

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (subseq_tmouts++ > TMOUT_LIMIT) {
      ++cur_skipped_paths;
      return 1;
    }

  } else subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {

     skip_requested = 0;
     ++cur_skipped_paths;
     return 1;

  }

  /* This handles FAULT_ERROR for us: */

  queued_discovered += save_if_interesting(argv, out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats();

  return 0;

}


/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(queue_cycle, 3);

  if (!run_over10m) rlim = 1;

  switch (UR(rlim)) {

    case 0:  min_value = 1;
             max_value = HAVOC_BLK_SMALL;
             break;

    case 1:  min_value = HAVOC_BLK_SMALL;
             max_value = HAVOC_BLK_MEDIUM;
             break;

    default: 

             if (UR(10)) {

               min_value = HAVOC_BLK_MEDIUM;
               max_value = HAVOC_BLK_LARGE;

             } else {

               min_value = HAVOC_BLK_LARGE;
               max_value = HAVOC_BLK_XL;

             }

  }

  if (min_value >= limit) min_value = 1;

  return min_value + UR(MIN(max_value, limit) - min_value + 1);

}


/* Calculate case desirability score to adjust the length of havoc fuzzing.
   A helper function for fuzz_one(). Maybe some of these constants should
   go into config.h. */

static u32 calculate_score(struct queue_entry* q) {

  u32 avg_exec_us = total_cal_us / total_cal_cycles;
  u32 avg_bitmap_size = total_bitmap_size / total_bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  if (q->exec_us * 0.1 > avg_exec_us) perf_score = 10;
  else if (q->exec_us * 0.25 > avg_exec_us) perf_score = 25;
  else if (q->exec_us * 0.5 > avg_exec_us) perf_score = 50;
  else if (q->exec_us * 0.75 > avg_exec_us) perf_score = 75;
  else if (q->exec_us * 4 < avg_exec_us) perf_score = 300;
  else if (q->exec_us * 3 < avg_exec_us) perf_score = 200;
  else if (q->exec_us * 2 < avg_exec_us) perf_score = 150;

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) perf_score *= 3;
  else if (q->bitmap_size * 0.5 > avg_bitmap_size) perf_score *= 2;
  else if (q->bitmap_size * 0.75 > avg_bitmap_size) perf_score *= 1.5;
  else if (q->bitmap_size * 3 < avg_bitmap_size) perf_score *= 0.25;
  else if (q->bitmap_size * 2 < avg_bitmap_size) perf_score *= 0.5;
  else if (q->bitmap_size * 1.5 < avg_bitmap_size) perf_score *= 0.75;

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {
    perf_score *= 4;
    q->handicap -= 4;
  } else if (q->handicap) {
    perf_score *= 2;
    --q->handicap;
  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:   break;
    case 4 ... 7:   perf_score *= 2; break;
    case 8 ... 13:  perf_score *= 3; break;
    case 14 ... 25: perf_score *= 4; break;
    default:        perf_score *= 5;

  }

  u64 fuzz = q->n_fuzz;
  u64 fuzz_total;

  u32 n_paths, fuzz_mu;
  u32 factor = 1;

  switch (schedule) {

    case EXPLORE:
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      fuzz_total = 0;
      n_paths = 0;

      struct queue_entry *queue_it = queue;
      while (queue_it) {
        fuzz_total += queue_it->n_fuzz;
        n_paths ++;
        queue_it = queue_it->next;
      }

      fuzz_mu = fuzz_total / n_paths;
      if (fuzz <= fuzz_mu) {
        if (q->fuzz_level < 16)
          factor = ((u32) (1 << q->fuzz_level));
        else
          factor = MAX_FACTOR;
      } else {
        factor = 0;
      }
      break;

    case FAST:
      if (q->fuzz_level < 16) {
         factor = ((u32) (1 << q->fuzz_level)) / (fuzz == 0 ? 1 : fuzz);
      } else
        factor = MAX_FACTOR / (fuzz == 0 ? 1 : next_p2 (fuzz));
      break;

    case LIN:
      factor = q->fuzz_level / (fuzz == 0 ? 1 : fuzz);
      break;

    case QUAD:
      factor = q->fuzz_level * q->fuzz_level / (fuzz == 0 ? 1 : fuzz);
      break;

    default:
      PFATAL ("Unknown Power Schedule");
  }
  if (factor > MAX_FACTOR)
    factor = MAX_FACTOR;

  perf_score *= factor / POWER_BETA;

  // MOpt mode
  if (limit_time_sig != 0 && max_depth - q->depth < 3) perf_score *= 2;
  else if (perf_score < 1) perf_score = 1; // Add a lower bound to AFLFast's energy assignment strategies

  /* Make sure that we don't go over limit. */

  if (perf_score > havoc_max_mult * 100) perf_score = havoc_max_mult * 100;

  return perf_score;

}


/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) { ++sh; xor_val >>= 1; }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
    return 1;

  return 0;

}


/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; ++i) {

    u8 a = old_val >> (8 * i),
       b = new_val >> (8 * i);

    if (a != b) { ++diffs; ov = a; nv = b; }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX ||
        (u8)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; ++i) {

    u16 a = old_val >> (16 * i),
        b = new_val >> (16 * i);

    if (a != b) { ++diffs; ov = a; nv = b; }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov); nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX ||
        (u16)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) return 1;

  }

  return 0;

}


/* Last but not least, a similar helper to see if insertion of an 
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; ++i) {

    for (j = 0; j < sizeof(interesting_8); ++j) {

      u32 tval = (old_val & ~(0xff << (i * 8))) |
                 (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; ++i) {

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; ++j)
      if (new_val == (u32)interesting_32[j]) return 1;

  }

  return 0;

}


/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out. */

static u8 fuzz_one_original(char** argv) {

  s32 len, fd, temp_len, i, j;
  u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued = 0,  orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8  ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (queue_cur->depth > 1) return 1;

#else

  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if (((queue_cur->was_fuzzed > 0 || queue_cur->fuzz_level > 0) || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;

  } else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (queue_cycle > 1 && (queue_cur->fuzz_level == 0 || queue_cur->was_fuzzed)) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

#endif /* ^IGNORE_FINDS */

  if (not_on_tty) {
    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         current_entry, queued_paths, unique_crashes);
    fflush(stdout);
  }

  /* Map the test case into memory. */

  fd = open(queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

  len = queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s' with len %d", queue_cur->fname, len);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_alloc_nozero(len);

  subseq_tmouts = 0;

  cur_depth = queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

      if (res == FAULT_ERROR)
        FATAL("Unable to execute target application");

    }

    if (stop_soon || res != crash_mode) {
      ++cur_skipped_paths;
      goto abandon_entry;
    }

  }

  /************
   * TRIMMING *
   ************/

  if (!dumb_mode && !queue_cur->trim_done && !custom_mutator) {

    u8 res = trim_case(argv, queue_cur, in_buf);

    if (res == FAULT_ERROR)
      FATAL("Unable to execute target application");

    if (stop_soon) {
      ++cur_skipped_paths;
      goto abandon_entry;
    }

    /* Don't retry trimming, even if it failed. */

    queue_cur->trim_done = 1;

    len = queue_cur->len;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(queue_cur);

  if (perf_score == 0) goto abandon_entry;

  if (custom_mutator) {
    stage_short = "custom";
    stage_name = "custom mutator";
    stage_max = len << 3;
    stage_val_type = STAGE_VAL_NONE;

    const u32 max_seed_size = 4096*4096;
    u8* mutated_buf = ck_alloc(max_seed_size);

    orig_hit_cnt = queued_paths + unique_crashes;

    for (stage_cur = 0 ; stage_cur < stage_max ; ++stage_cur) {
      size_t orig_size = (size_t) len;
      size_t mutated_size = custom_mutator(out_buf, orig_size, mutated_buf, max_seed_size, UR(UINT32_MAX));
      if (mutated_size > 0) {
        out_buf = ck_realloc(out_buf, mutated_size);
        memcpy(out_buf, mutated_buf, mutated_size);
        if (common_fuzz_stuff(argv, out_buf, (u32) mutated_size)) {
          goto abandon_entry;
        }
      }
    }

    ck_free(mutated_buf);
    new_hit_cnt = queued_paths + unique_crashes;

    stage_finds[STAGE_CUSTOM_MUTATOR]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_CUSTOM_MUTATOR] += stage_max;
    goto abandon_entry;
  }


  /* Skip right away if -d is given, if it has not been chosen sufficiently
     often to warrant the expensive deterministic stage (fuzz_level), or
     if it has gone through deterministic testing in earlier, resumed runs
     (passed_det). */

  if (skip_deterministic
     || ((!queue_cur->passed_det)
        && perf_score < (
              queue_cur->depth * 30 <= havoc_max_mult * 100
              ? queue_cur->depth * 30
              : havoc_max_mult * 100))
     || queue_cur->passed_det)
#ifdef USE_PYTHON
    goto python_stage;
#else
    goto havoc_stage;
#endif

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
#ifdef USE_PYTHON
    goto python_stage;
#else
    goto havoc_stage;
#endif

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

  /* Single walking bit. */

  stage_short = "flip1";
  stage_max   = len << 3;
  stage_name  = "bitflip 1/1";

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = queued_paths + unique_crashes;

  prev_cksum = queue_cur->exec_cksum;

  for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);

    /* While flipping the least significant bit in every byte, pull of an extra
       trick to detect possible syntax tokens. In essence, the idea is that if
       you have a binary blob like this:

       xxxxxxxxIHDRxxxxxxxx

       ...and changing the leading and trailing bytes causes variable or no
       changes in program flow, but touching any character in the "IHDR" string
       always produces the same, distinctive path, it's highly likely that
       "IHDR" is an atomically-checked magic value of special significance to
       the fuzzed format.

       We do this here, rather than as a separate stage, because it's a nice
       way to keep the operation approximately "free" (i.e., no extra execs).
       
       Empirically, performing the check when flipping the least significant bit
       is advantageous, compared to doing it at the time of more disruptive
       changes, where the program flow may be affected in more violent ways.

       The caveat is that we won't generate dictionaries in the -d mode or -S
       mode - but that's probably a fair trade-off.

       This won't work particularly well with paths that exhibit variable
       behavior, but fails gracefully, so we'll carry out the checks anyway.

      */

    if (!dumb_mode && (stage_cur & 7) == 7) {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
        ++a_len;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];        
        ++a_len;

      }

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP1]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP1] += stage_max;

  /* Two walking bits. */

  stage_name  = "bitflip 2/1";
  stage_short = "flip2";
  stage_max   = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP2]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP2] += stage_max;

  /* Four walking bits. */

  stage_name  = "bitflip 4/1";
  stage_short = "flip4";
  stage_max   = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

    stage_cur_byte = stage_cur >> 3;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, stage_cur);
    FLIP_BIT(out_buf, stage_cur + 1);
    FLIP_BIT(out_buf, stage_cur + 2);
    FLIP_BIT(out_buf, stage_cur + 3);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP4]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP4] += stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map    = ck_alloc(EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {
    eff_map[EFF_APOS(len - 1)] = 1;
    ++eff_cnt;
  }

  /* Walking byte. */

  stage_name  = "bitflip 8/8";
  stage_short = "flip8";
  stage_max   = len;

  orig_hit_cnt = new_hit_cnt;

  for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

    stage_cur_byte = stage_cur;

    out_buf[stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~queue_cur->exec_cksum;

      if (cksum != queue_cur->exec_cksum) {
        eff_map[EFF_APOS(stage_cur)] = 1;
        ++eff_cnt;
      }

    }

    out_buf[stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    blocks_eff_select += EFF_ALEN(len);

  } else {

    blocks_eff_select += eff_cnt;

  }

  blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP8] += stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  stage_name  = "bitflip 16/8";
  stage_short = "flip16";
  stage_cur   = 0;
  stage_max   = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      --stage_max;
      continue;
    }

    stage_cur_byte = i;

    *(u16*)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    ++stage_cur;

    *(u16*)(out_buf + i) ^= 0xFFFF;


  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP16] += stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  stage_name  = "bitflip 32/8";
  stage_short = "flip32";
  stage_cur   = 0;
  stage_max   = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      --stage_max;
      continue;
    }

    stage_cur_byte = i;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    ++stage_cur;

    *(u32*)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_FLIP32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_FLIP32] += stage_max;

skip_bitflip:

  if (no_arith) goto skip_arith;

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  stage_name  = "arith 8/8";
  stage_short = "arith8";
  stage_cur   = 0;
  stage_max   = 2 * len * ARITH_MAX;

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= 2 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      r =  orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH8] += stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  stage_name  = "arith 16/8";
  stage_short = "arith16";
  stage_cur   = 0;
  stage_max   = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u16 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the 
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      stage_val_type = STAGE_VAL_LE; 

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;
 
      } else --stage_max;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      /* Big endian comes next. Same deal. */

      stage_val_type = STAGE_VAL_BE;


      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      *(u16*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH16] += stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  stage_name  = "arith 32/8";
  stage_short = "arith32";
  stage_cur   = 0;
  stage_max   = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= 4 * ARITH_MAX;
      continue;
    }

    stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u32 r1 = orig ^ (orig + j),
          r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      /* Big endian next. */

      stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        stage_cur_val = j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        stage_cur_val = -j;
        *(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      *(u32*)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_ARITH32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ARITH32] += stage_max;

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  stage_name  = "interest 8/8";
  stage_short = "int8";
  stage_cur   = 0;
  stage_max   = len * sizeof(interesting_8);

  stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {
      stage_max -= sizeof(interesting_8);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); ++j) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {
        --stage_max;
        continue;
      }

      stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      ++stage_cur;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST8]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST8] += stage_max;

  /* Setting 16-bit integers, both endians. */

  if (no_arith || len < 2) goto skip_interest;

  stage_name  = "interest 16/8";
  stage_short = "int16";
  stage_cur   = 0;
  stage_max   = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
      stage_max -= sizeof(interesting_16);
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u16*)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

    }

    *(u16*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST16]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST16] += stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  stage_name  = "interest 32/8";
  stage_short = "int32";
  stage_cur   = 0;
  stage_max   = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32*)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
      stage_max -= sizeof(interesting_32) >> 1;
      continue;
    }

    stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        stage_val_type = STAGE_VAL_LE;

        *(u32*)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        stage_val_type = STAGE_VAL_BE;

        *(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
        ++stage_cur;

      } else --stage_max;

    }

    *(u32*)(out_buf + i) = orig;

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_INTEREST32]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_INTEREST32] += stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  stage_name  = "user extras (over)";
  stage_short = "ext_UO";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; ++i) {

    u32 last_len = 0;

    stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < extras_cnt; ++j) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        --stage_max;
        continue;

      }

      last_len = extras[j].len;
      memcpy(out_buf + i, extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      ++stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UO] += stage_max;

  /* Insertion of user-supplied extras. */

  stage_name  = "user extras (insert)";
  stage_short = "ext_UI";
  stage_cur   = 0;
  stage_max   = extras_cnt * len;

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_alloc(len + MAX_DICT_FILE);

  for (i = 0; i <= len; ++i) {

    stage_cur_byte = i;

    for (j = 0; j < extras_cnt; ++j) {

      if (len + extras[j].len > MAX_FILE) {
        --stage_max; 
        continue;
      }

      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

      if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
        ck_free(ex_tmp);
        goto abandon_entry;
      }

      ++stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  ck_free(ex_tmp);

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_UI]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_UI] += stage_max;

skip_user_extras:

  if (!a_extras_cnt) goto skip_extras;

  stage_name  = "auto extras (over)";
  stage_short = "ext_AO";
  stage_cur   = 0;
  stage_max   = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;

  stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; ++i) {

    u32 last_len = 0;

    stage_cur_byte = i;

    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); ++j) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (a_extras[j].len > len - i ||
          !memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

        --stage_max;
        continue;

      }

      last_len = a_extras[j].len;
      memcpy(out_buf + i, a_extras[j].data, last_len);

      if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

      ++stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_EXTRAS_AO]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_EXTRAS_AO] += stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

#ifdef USE_PYTHON
python_stage:
  /**********************************
   * EXTERNAL MUTATORS (Python API) *
   **********************************/

  if (!py_module) goto havoc_stage;

  stage_name  = "python";
  stage_short = "python";
  stage_max   = HAVOC_CYCLES * perf_score / havoc_div / 100;

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  orig_hit_cnt = queued_paths + unique_crashes;

  char* retbuf = NULL;
  size_t retlen = 0;

  for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {
    struct queue_entry* target;
    u32 tid;
    u8* new_buf;

retry_external_pick:
    /* Pick a random other queue entry for passing to external API */
    do { tid = UR(queued_paths); } while (tid == current_entry && queued_paths > 1);

    target = queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur) && queued_paths > 1) {
      target = target->next;
      ++splicing_with;
    }

    if (!target) goto retry_external_pick;

    /* Read the additional testcase into a new buffer. */
    fd = open(target->fname, O_RDONLY);
    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);
    new_buf = ck_alloc_nozero(target->len);
    ck_read(fd, new_buf, target->len, target->fname);
    close(fd);

    fuzz_py(out_buf, len, new_buf, target->len, &retbuf, &retlen);

    ck_free(new_buf);

    if (retbuf) {
      if (!retlen)
        goto abandon_entry;

      if (common_fuzz_stuff(argv, retbuf, retlen)) {
        free(retbuf);
        goto abandon_entry;
      }

      /* Reset retbuf/retlen */
      free(retbuf);
      retbuf = NULL;
      retlen = 0;

      /* If we're finding new stuff, let's run for a bit longer, limits
         permitting. */

      if (queued_paths != havoc_queued) {
        if (perf_score <= havoc_max_mult * 100) {
          stage_max  *= 2;
          perf_score *= 2;
        }

        havoc_queued = queued_paths;
      }
    }
  }

  new_hit_cnt = queued_paths + unique_crashes;

  stage_finds[STAGE_PYTHON]  += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_PYTHON] += stage_max;

  if (python_only) {
    /* Skip other stages */
    ret_val = 0;
    goto abandon_entry;
  }
#endif

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    stage_name  = "havoc";
    stage_short = "havoc";
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;

  } else {

    static u8 tmp[32];

    perf_score = orig_perf;

    sprintf(tmp, "splice %u", splice_cycle);
    stage_name  = tmp;
    stage_short = "splice";
    stage_max   = SPLICE_HAVOC * perf_score / havoc_div / 100;

  }

  if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

  temp_len = len;

  orig_hit_cnt = queued_paths + unique_crashes;

  havoc_queued = queued_paths;

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

    u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

    stage_cur_val = use_stacking;
 
    for (i = 0; i < use_stacking; ++i) {

      switch (UR(15 + ((extras_cnt + a_extras_cnt) ? 2 : 0))) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, UR(temp_len << 3));
          break;

        case 1: 

          /* Set byte to interesting value. */

          out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            *(u16*)(out_buf + UR(temp_len - 1)) =
              interesting_16[UR(sizeof(interesting_16) >> 1)];

          } else {

            *(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
              interesting_16[UR(sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (UR(2)) {
  
            *(u32*)(out_buf + UR(temp_len - 3)) =
              interesting_32[UR(sizeof(interesting_32) >> 2)];

          } else {

            *(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
              interesting_32[UR(sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 1);

            *(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 1);
            u16 num = 1 + UR(ARITH_MAX);

            *(u16*)(out_buf + pos) =
              SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (UR(2)) {

            u32 pos = UR(temp_len - 3);

            *(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);

          } else {

            u32 pos = UR(temp_len - 3);
            u32 num = 1 + UR(ARITH_MAX);

            *(u32*)(out_buf + pos) =
              SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[UR(temp_len)] ^= 1 + UR(255);
          break;

        case 11 ... 12: {

            /* Delete bytes. We're making this a bit more likely
               than insertion (the next option) in hopes of keeping
               files reasonably small. */

            u32 del_from, del_len;

            if (temp_len < 2) break;

            /* Don't delete too much. */

            del_len = choose_block_len(temp_len - 1);

            del_from = UR(temp_len - del_len + 1);

            memmove(out_buf + del_from, out_buf + del_from + del_len,
                    temp_len - del_from - del_len);

            temp_len -= del_len;

            break;

          }

        case 13:

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = UR(4);
            u32 clone_from, clone_to, clone_len;
            u8* new_buf;

            if (actually_clone) {

              clone_len  = choose_block_len(temp_len);
              clone_from = UR(temp_len - clone_len + 1);

            } else {

              clone_len = choose_block_len(HAVOC_BLK_XL);
              clone_from = 0;

            }

            clone_to   = UR(temp_len);

            new_buf = ck_alloc_nozero(temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to,
                     UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            ck_free(out_buf);
            out_buf = new_buf;
            temp_len += clone_len;

          }

          break;

        case 14: {

            /* Overwrite bytes with a randomly selected chunk (75%) or fixed
               bytes (25%). */

            u32 copy_from, copy_to, copy_len;

            if (temp_len < 2) break;

            copy_len  = choose_block_len(temp_len - 1);

            copy_from = UR(temp_len - copy_len + 1);
            copy_to   = UR(temp_len - copy_len + 1);

            if (UR(4)) {

              if (copy_from != copy_to)
                memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

            } else memset(out_buf + copy_to,
                          UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);

            break;

          }

        /* Values 15 and 16 can be selected only if there are any extras
           present in the dictionaries. */

        case 15: {

            /* Overwrite bytes with an extra. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              /* No user-specified extras or odds in our favor. Let's use an
                 auto-detected one. */

              u32 use_extra = UR(a_extras_cnt);
              u32 extra_len = a_extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, a_extras[use_extra].data, extra_len);

            } else {

              /* No auto extras or odds in our favor. Use the dictionary. */

              u32 use_extra = UR(extras_cnt);
              u32 extra_len = extras[use_extra].len;
              u32 insert_at;

              if (extra_len > temp_len) break;

              insert_at = UR(temp_len - extra_len + 1);
              memcpy(out_buf + insert_at, extras[use_extra].data, extra_len);

            }

            break;

          }

        case 16: {

            u32 use_extra, extra_len, insert_at = UR(temp_len + 1);
            u8* new_buf;

            /* Insert an extra. Do the same dice-rolling stuff as for the
               previous case. */

            if (!extras_cnt || (a_extras_cnt && UR(2))) {

              use_extra = UR(a_extras_cnt);
              extra_len = a_extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, a_extras[use_extra].data, extra_len);

	    } else {

              use_extra = UR(extras_cnt);
              extra_len = extras[use_extra].len;

              if (temp_len + extra_len >= MAX_FILE) break;

              new_buf = ck_alloc_nozero(temp_len + extra_len);

              /* Head */
              memcpy(new_buf, out_buf, insert_at);

              /* Inserted part */
              memcpy(new_buf + insert_at, extras[use_extra].data, extra_len);

            }

            /* Tail */
            memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                   temp_len - insert_at);

            ck_free(out_buf);
            out_buf   = new_buf;
            temp_len += extra_len;

            break;

          }

      }

    }

    if (common_fuzz_stuff(argv, out_buf, temp_len))
      goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    if (temp_len < len) out_buf = ck_realloc(out_buf, len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (queued_paths != havoc_queued) {

      if (perf_score <= havoc_max_mult * 100) {
        stage_max  *= 2;
        perf_score *= 2;
      }

      havoc_queued = queued_paths;

    }

  }

  new_hit_cnt = queued_paths + unique_crashes;

  if (!splice_cycle) {
    stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_HAVOC] += stage_max;
  } else {
    stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
    stage_cycles[STAGE_SPLICE] += stage_max;
  }

#ifndef IGNORE_FINDS

  /************
   * SPLICING *
   ************/

  /* This is a last-resort strategy triggered by a full round with no findings.
     It takes the current input file, randomly selects another input, and
     splices them together at some offset, then relies on the havoc
     code to mutate that blob. */

retry_splicing:

  if (use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      queued_paths > 1 && queue_cur->len > 1) {

    struct queue_entry* target;
    u32 tid, split_at;
    u8* new_buf;
    s32 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {
      ck_free(in_buf);
      in_buf = orig_in;
      len = queue_cur->len;
    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do { tid = UR(queued_paths); } while (tid == current_entry);

    splicing_with = tid;
    target = queue;

    while (tid >= 100) { target = target->next_100; tid -= 100; }
    while (tid--) target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == queue_cur)) {
      target = target->next;
      ++splicing_with;
    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_alloc_nozero(target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;

    ck_free(out_buf);
    out_buf = ck_alloc_nozero(len);
    memcpy(out_buf, in_buf, len);

#ifdef USE_PYTHON
    goto python_stage;
#else
    goto havoc_stage;
#endif

  }

#endif /* !IGNORE_FINDS */

  ret_val = 0;

abandon_entry:

  splicing_with = -1;

  /* Update pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!stop_soon && !queue_cur->cal_failed && (queue_cur->was_fuzzed == 0 || queue_cur->fuzz_level == 0)) {
    --pending_not_fuzzed;
    queue_cur->was_fuzzed = 1;
    if (queue_cur->favored) --pending_favored;
  }

  ++queue_cur->fuzz_level;

  munmap(orig_in, queue_cur->len);

  if (in_buf != orig_in) ck_free(in_buf);
  ck_free(out_buf);
  ck_free(eff_map);

  return ret_val;

#undef FLIP_BIT

}

/* MOpt mode */
static u8 pilot_fuzzing(char** argv) {

	s32 len, fd, temp_len, i, j;
	u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
	u64 havoc_queued, orig_hit_cnt, new_hit_cnt, cur_ms_lv;
	u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

	u8  ret_val = 1, doing_det = 0;

	u8  a_collect[MAX_AUTO_EXTRA];
	u32 a_len = 0;

#ifdef IGNORE_FINDS

	/* In IGNORE_FINDS mode, skip any entries that weren't in the
	   initial data set. */

	if (queue_cur->depth > 1) return 1;

#else

	if (pending_favored) {

		/* If we have any favored, non-fuzzed new arrivals in the queue,
		   possibly skip to them at the expense of already-fuzzed or non-favored
		   cases. */

		if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
			UR(100) < SKIP_TO_NEW_PROB) return 1;

	}
	else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

		/* Otherwise, still possibly skip non-favored cases, albeit less often.
		   The odds of skipping stuff are higher for already-fuzzed inputs and
		   lower for never-fuzzed entries. */

		if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

			if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

		}
		else {

			if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

		}

	}

#endif /* ^IGNORE_FINDS */

	if (not_on_tty) {
		ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
			current_entry, queued_paths, unique_crashes);
		fflush(stdout);
	}

	/* Map the test case into memory. */

	fd = open(queue_cur->fname, O_RDONLY);

	if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

	len = queue_cur->len;

	orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

	close(fd);

	/* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
	   single byte anyway, so it wouldn't give us any performance or memory usage
	   benefits. */

	out_buf = ck_alloc_nozero(len);

	subseq_tmouts = 0;

	cur_depth = queue_cur->depth;

	/*******************************************
	 * CALIBRATION (only if failed earlier on) *
	 *******************************************/

	if (queue_cur->cal_failed) {

		u8 res = FAULT_TMOUT;

		if (queue_cur->cal_failed < CAL_CHANCES) {

			res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

			if (res == FAULT_ERROR)
				FATAL("Unable to execute target application");

		}

		if (stop_soon || res != crash_mode) {
			++cur_skipped_paths;
			goto abandon_entry;
		}

	}

	/************
	 * TRIMMING *
	 ************/

	if (!dumb_mode && !queue_cur->trim_done) {

		u8 res = trim_case(argv, queue_cur, in_buf);

		if (res == FAULT_ERROR)
			FATAL("Unable to execute target application");

		if (stop_soon) {
			++cur_skipped_paths;
			goto abandon_entry;
		}

		/* Don't retry trimming, even if it failed. */

		queue_cur->trim_done = 1;

		len = queue_cur->len;

	}

	memcpy(out_buf, in_buf, len);

	/*********************
	 * PERFORMANCE SCORE *
	 *********************/

	orig_perf = perf_score = calculate_score(queue_cur);

	/* Skip right away if -d is given, if we have done deterministic fuzzing on
	   this entry ourselves (was_fuzzed), or if it has gone through deterministic
	   testing in earlier, resumed runs (passed_det). */

	if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
		goto havoc_stage;

	/* Skip deterministic fuzzing if exec path checksum puts this out of scope
	   for this master instance. */

	if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
		goto havoc_stage;


	cur_ms_lv = get_cur_time();
	if (!(key_puppet == 0 && ((cur_ms_lv - last_path_time < limit_time_puppet) ||
		(last_crash_time != 0 && cur_ms_lv - last_crash_time < limit_time_puppet) || last_path_time == 0)))
	{
		key_puppet = 1;
		goto pacemaker_fuzzing;
	}

	doing_det = 1;

		/*********************************************
		 * SIMPLE BITFLIP (+dictionary construction) *
		 *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

		 /* Single walking bit. */

		stage_short = "flip1";
		stage_max = len << 3;
		stage_name = "bitflip 1/1";




		stage_val_type = STAGE_VAL_NONE;

		orig_hit_cnt = queued_paths + unique_crashes;

		prev_cksum = queue_cur->exec_cksum;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur >> 3;

			FLIP_BIT(out_buf, stage_cur);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			FLIP_BIT(out_buf, stage_cur);

			/* While flipping the least significant bit in every byte, pull of an extra
			   trick to detect possible syntax tokens. In essence, the idea is that if
			   you have a binary blob like this:

			   xxxxxxxxIHDRxxxxxxxx

			   ...and changing the leading and trailing bytes causes variable or no
			   changes in program flow, but touching any character in the "IHDR" string
			   always produces the same, distinctive path, it's highly likely that
			   "IHDR" is an atomically-checked magic value of special significance to
			   the fuzzed format.

			   We do this here, rather than as a separate stage, because it's a nice
			   way to keep the operation approximately "free" (i.e., no extra execs).

			   Empirically, performing the check when flipping the least significant bit
			   is advantageous, compared to doing it at the time of more disruptive
			   changes, where the program flow may be affected in more violent ways.

			   The caveat is that we won't generate dictionaries in the -d mode or -S
			   mode - but that's probably a fair trade-off.

			   This won't work particularly well with paths that exhibit variable
			   behavior, but fails gracefully, so we'll carry out the checks anyway.

			  */

			if (!dumb_mode && (stage_cur & 7) == 7) {

				u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

				if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

					/* If at end of file and we are still collecting a string, grab the
					   final character and force output. */

					if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
					++a_len;

					if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
						maybe_add_auto(a_collect, a_len);

				}
				else if (cksum != prev_cksum) {

					/* Otherwise, if the checksum has changed, see if we have something
					   worthwhile queued up, and collect that if the answer is yes. */

					if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
						maybe_add_auto(a_collect, a_len);

					a_len = 0;
					prev_cksum = cksum;

				}

				/* Continue collecting string, but only if the bit flip actually made
				   any difference - we don't want no-op tokens. */

				if (cksum != queue_cur->exec_cksum) {

					if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
					++a_len;

				}

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP1] += stage_max;

		/* Two walking bits. */

		stage_name = "bitflip 2/1";
		stage_short = "flip2";
		stage_max = (len << 3) - 1;

		orig_hit_cnt = new_hit_cnt;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur >> 3;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP2] += stage_max;



		/* Four walking bits. */

		stage_name = "bitflip 4/1";
		stage_short = "flip4";
		stage_max = (len << 3) - 3;





		orig_hit_cnt = new_hit_cnt;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur >> 3;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);
			FLIP_BIT(out_buf, stage_cur + 2);
			FLIP_BIT(out_buf, stage_cur + 3);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);
			FLIP_BIT(out_buf, stage_cur + 2);
			FLIP_BIT(out_buf, stage_cur + 3);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP4] += stage_max;




		/* Effector map setup. These macros calculate:

		   EFF_APOS      - position of a particular file offset in the map.
		   EFF_ALEN      - length of a map with a particular number of bytes.
		   EFF_SPAN_ALEN - map span for a sequence of bytes.

		 */

#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

		 /* Initialize effector map for the next step (see comments below). Always
			flag first and last byte as doing something. */

		eff_map = ck_alloc(EFF_ALEN(len));
		eff_map[0] = 1;

		if (EFF_APOS(len - 1) != 0) {
			eff_map[EFF_APOS(len - 1)] = 1;
			++eff_cnt;
		}

		/* Walking byte. */

		stage_name = "bitflip 8/8";
		stage_short = "flip8";
		stage_max = len;



		orig_hit_cnt = new_hit_cnt;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur;

			out_buf[stage_cur] ^= 0xFF;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			/* We also use this stage to pull off a simple trick: we identify
			   bytes that seem to have no effect on the current execution path
			   even when fully flipped - and we skip them during more expensive
			   deterministic stages, such as arithmetics or known ints. */

			if (!eff_map[EFF_APOS(stage_cur)]) {

				u32 cksum;

				/* If in dumb mode or if the file is very short, just flag everything
				   without wasting time on checksums. */

				if (!dumb_mode && len >= EFF_MIN_LEN)
					cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
				else
					cksum = ~queue_cur->exec_cksum;

				if (cksum != queue_cur->exec_cksum) {
					eff_map[EFF_APOS(stage_cur)] = 1;
					++eff_cnt;
				}

			}

			out_buf[stage_cur] ^= 0xFF;

		}

		/* If the effector map is more than EFF_MAX_PERC dense, just flag the
		   whole thing as worth fuzzing, since we wouldn't be saving much time
		   anyway. */

		if (eff_cnt != EFF_ALEN(len) &&
			eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

			memset(eff_map, 1, EFF_ALEN(len));

			blocks_eff_select += EFF_ALEN(len);

		}
		else {

			blocks_eff_select += eff_cnt;

		}

		blocks_eff_total += EFF_ALEN(len);

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP8] += stage_max;





		/* Two walking bytes. */

		if (len < 2) goto skip_bitflip;

		stage_name = "bitflip 16/8";
		stage_short = "flip16";
		stage_cur = 0;
		stage_max = len - 1;



		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 1; ++i) {

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
				--stage_max;
				continue;
			}

			stage_cur_byte = i;

			*(u16*)(out_buf + i) ^= 0xFFFF;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			++stage_cur;

			*(u16*)(out_buf + i) ^= 0xFFFF;


		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP16] += stage_max;




		if (len < 4) goto skip_bitflip;

		/* Four walking bytes. */

		stage_name = "bitflip 32/8";
		stage_short = "flip32";
		stage_cur = 0;
		stage_max = len - 3;



		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 3; ++i) {

			/* Let's consult the effector map... */
			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
				!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
				--stage_max;
				continue;
			}

			stage_cur_byte = i;

			*(u32*)(out_buf + i) ^= 0xFFFFFFFF;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			++stage_cur;

			*(u32*)(out_buf + i) ^= 0xFFFFFFFF;

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP32] += stage_max;






	skip_bitflip:

		if (no_arith) goto skip_arith;

		/**********************
		 * ARITHMETIC INC/DEC *
		 **********************/

		 /* 8-bit arithmetics. */

		stage_name = "arith 8/8";
		stage_short = "arith8";
		stage_cur = 0;
		stage_max = 2 * len * ARITH_MAX;




		stage_val_type = STAGE_VAL_LE;

		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len; ++i) {

			u8 orig = out_buf[i];

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)]) {
				stage_max -= 2 * ARITH_MAX;
				continue;
			}

			stage_cur_byte = i;

			for (j = 1; j <= ARITH_MAX; ++j) {

				u8 r = orig ^ (orig + j);

				/* Do arithmetic operations only if the result couldn't be a product
				   of a bitflip. */

				if (!could_be_bitflip(r)) {

					stage_cur_val = j;
					out_buf[i] = orig + j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				r = orig ^ (orig - j);

				if (!could_be_bitflip(r)) {

					stage_cur_val = -j;
					out_buf[i] = orig - j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				out_buf[i] = orig;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_ARITH8] += stage_max;





		/* 16-bit arithmetics, both endians. */

		if (len < 2) goto skip_arith;

		stage_name = "arith 16/8";
		stage_short = "arith16";
		stage_cur = 0;
		stage_max = 4 * (len - 1) * ARITH_MAX;




		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 1; ++i) {

			u16 orig = *(u16*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
				stage_max -= 4 * ARITH_MAX;
				continue;
			}

			stage_cur_byte = i;

			for (j = 1; j <= ARITH_MAX; ++j) {

				u16 r1 = orig ^ (orig + j),
					r2 = orig ^ (orig - j),
					r3 = orig ^ SWAP16(SWAP16(orig) + j),
					r4 = orig ^ SWAP16(SWAP16(orig) - j);

				/* Try little endian addition and subtraction first. Do it only
				   if the operation would affect more than one byte (hence the
				   & 0xff overflow checks) and if it couldn't be a product of
				   a bitflip. */

				stage_val_type = STAGE_VAL_LE;

				if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

					stage_cur_val = j;
					*(u16*)(out_buf + i) = orig + j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

					stage_cur_val = -j;
					*(u16*)(out_buf + i) = orig - j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				/* Big endian comes next. Same deal. */

				stage_val_type = STAGE_VAL_BE;


				if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

					stage_cur_val = j;
					*(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((orig >> 8) < j && !could_be_bitflip(r4)) {

					stage_cur_val = -j;
					*(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				*(u16*)(out_buf + i) = orig;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_ARITH16] += stage_max;




		/* 32-bit arithmetics, both endians. */

		if (len < 4) goto skip_arith;

		stage_name = "arith 32/8";
		stage_short = "arith32";
		stage_cur = 0;
		stage_max = 4 * (len - 3) * ARITH_MAX;



		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 3; ++i) {

			u32 orig = *(u32*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
				!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
				stage_max -= 4 * ARITH_MAX;
				continue;
			}

			stage_cur_byte = i;

			for (j = 1; j <= ARITH_MAX; ++j) {

				u32 r1 = orig ^ (orig + j),
					r2 = orig ^ (orig - j),
					r3 = orig ^ SWAP32(SWAP32(orig) + j),
					r4 = orig ^ SWAP32(SWAP32(orig) - j);

				/* Little endian first. Same deal as with 16-bit: we only want to
				   try if the operation would have effect on more than two bytes. */

				stage_val_type = STAGE_VAL_LE;

				if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

					stage_cur_val = j;
					*(u32*)(out_buf + i) = orig + j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

					stage_cur_val = -j;
					*(u32*)(out_buf + i) = orig - j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					stage_cur++;

				} else --stage_max;

				/* Big endian next. */

				stage_val_type = STAGE_VAL_BE;

				if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

					stage_cur_val = j;
					*(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

					stage_cur_val = -j;
					*(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				*(u32*)(out_buf + i) = orig;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_ARITH32] += stage_max;




	skip_arith:

		/**********************
		 * INTERESTING VALUES *
		 **********************/

		stage_name = "interest 8/8";
		stage_short = "int8";
		stage_cur = 0;
		stage_max = len * sizeof(interesting_8);



		stage_val_type = STAGE_VAL_LE;

		orig_hit_cnt = new_hit_cnt;

		/* Setting 8-bit integers. */

		for (i = 0; i < len; ++i) {

			u8 orig = out_buf[i];

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)]) {
				stage_max -= sizeof(interesting_8);
				continue;
			}

			stage_cur_byte = i;

			for (j = 0; j < sizeof(interesting_8); ++j) {

				/* Skip if the value could be a product of bitflips or arithmetics. */

				if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
					could_be_arith(orig, (u8)interesting_8[j], 1)) {
					--stage_max;
					continue;
				}

				stage_cur_val = interesting_8[j];
				out_buf[i] = interesting_8[j];

				if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

				out_buf[i] = orig;
				++stage_cur;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_INTEREST8] += stage_max;




		/* Setting 16-bit integers, both endians. */

		if (no_arith || len < 2) goto skip_interest;

		stage_name = "interest 16/8";
		stage_short = "int16";
		stage_cur = 0;
		stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);



		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 1; ++i) {

			u16 orig = *(u16*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
				stage_max -= sizeof(interesting_16);
				continue;
			}

			stage_cur_byte = i;

			for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

				stage_cur_val = interesting_16[j];

				/* Skip if this could be a product of a bitflip, arithmetics,
				   or single-byte interesting value insertion. */

				if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
					!could_be_arith(orig, (u16)interesting_16[j], 2) &&
					!could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

					stage_val_type = STAGE_VAL_LE;

					*(u16*)(out_buf + i) = interesting_16[j];

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
					!could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
					!could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
					!could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

					stage_val_type = STAGE_VAL_BE;

					*(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

			}

			*(u16*)(out_buf + i) = orig;

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_INTEREST16] += stage_max;





		if (len < 4) goto skip_interest;

		/* Setting 32-bit integers, both endians. */

		stage_name = "interest 32/8";
		stage_short = "int32";
		stage_cur = 0;
		stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);


		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 3; ++i) {

			u32 orig = *(u32*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
				!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
				stage_max -= sizeof(interesting_32) >> 1;
				continue;
			}

			stage_cur_byte = i;

			for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

				stage_cur_val = interesting_32[j];

				/* Skip if this could be a product of a bitflip, arithmetics,
				   or word interesting value insertion. */

				if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
					!could_be_arith(orig, interesting_32[j], 4) &&
					!could_be_interest(orig, interesting_32[j], 4, 0)) {

					stage_val_type = STAGE_VAL_LE;

					*(u32*)(out_buf + i) = interesting_32[j];

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
					!could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
					!could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
					!could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

					stage_val_type = STAGE_VAL_BE;

					*(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

			}

			*(u32*)(out_buf + i) = orig;

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_INTEREST32] += stage_max;





	skip_interest:

		/********************
		 * DICTIONARY STUFF *
		 ********************/

		if (!extras_cnt) goto skip_user_extras;

		/* Overwrite with user-supplied extras. */

		stage_name = "user extras (over)";
		stage_short = "ext_UO";
		stage_cur = 0;
		stage_max = extras_cnt * len;




		stage_val_type = STAGE_VAL_NONE;

		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len; ++i) {

			u32 last_len = 0;

			stage_cur_byte = i;

			/* Extras are sorted by size, from smallest to largest. This means
			   that we don't have to worry about restoring the buffer in
			   between writes at a particular offset determined by the outer
			   loop. */

			for (j = 0; j < extras_cnt; ++j) {

				/* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
				   skip them if there's no room to insert the payload, if the token
				   is redundant, or if its entire span has no bytes set in the effector
				   map. */

				if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
					extras[j].len > len - i ||
					!memcmp(extras[j].data, out_buf + i, extras[j].len) ||
					!memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

					--stage_max;
					continue;

				}

				last_len = extras[j].len;
				memcpy(out_buf + i, extras[j].data, last_len);

				if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

				++stage_cur;

			}

			/* Restore all the clobbered memory. */
			memcpy(out_buf + i, in_buf + i, last_len);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_EXTRAS_UO] += stage_max;

		/* Insertion of user-supplied extras. */

		stage_name = "user extras (insert)";
		stage_short = "ext_UI";
		stage_cur = 0;
		stage_max = extras_cnt * len;




		orig_hit_cnt = new_hit_cnt;

		ex_tmp = ck_alloc(len + MAX_DICT_FILE);

		for (i = 0; i <= len; ++i) {

			stage_cur_byte = i;

			for (j = 0; j < extras_cnt; ++j) {

				if (len + extras[j].len > MAX_FILE) {
					--stage_max;
					continue;
				}

				/* Insert token */
				memcpy(ex_tmp + i, extras[j].data, extras[j].len);

				/* Copy tail */
				memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

				if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
					ck_free(ex_tmp);
					goto abandon_entry;
				}

				++stage_cur;

			}

			/* Copy head */
			ex_tmp[i] = out_buf[i];

		}

		ck_free(ex_tmp);

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_EXTRAS_UI] += stage_max;

	skip_user_extras:

		if (!a_extras_cnt) goto skip_extras;

		stage_name = "auto extras (over)";
		stage_short = "ext_AO";
		stage_cur = 0;
		stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;


		stage_val_type = STAGE_VAL_NONE;

		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len; ++i) {

			u32 last_len = 0;

			stage_cur_byte = i;

			for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); ++j) {

				/* See the comment in the earlier code; extras are sorted by size. */

				if (a_extras[j].len > len - i ||
					!memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
					!memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

					--stage_max;
					continue;

				}

				last_len = a_extras[j].len;
				memcpy(out_buf + i, a_extras[j].data, last_len);

				if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

				++stage_cur;

			}

			/* Restore all the clobbered memory. */
			memcpy(out_buf + i, in_buf + i, last_len);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_EXTRAS_AO] += stage_max;

	skip_extras:

		/* If we made this to here without jumping to havoc_stage or abandon_entry,
		   we're properly done with deterministic steps and can mark it as such
		   in the .state/ directory. */

		if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

		/****************
		 * RANDOM HAVOC *
		 ****************/

	havoc_stage:
	pacemaker_fuzzing:


		stage_cur_byte = -1;

		/* The havoc stage mutation code is also invoked when splicing files; if the
		   splice_cycle variable is set, generate different descriptions and such. */

		if (!splice_cycle) {

			stage_name = "MOpt-havoc";
			stage_short = "MOpt_havoc";
			stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
				perf_score / havoc_div / 100;

		}
		else {

			static u8 tmp[32];

			perf_score = orig_perf;

			sprintf(tmp, "MOpt-splice %u", splice_cycle);
			stage_name = tmp;
			stage_short = "MOpt_splice";
			stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;

		}

		s32 temp_len_puppet;
		cur_ms_lv = get_cur_time();

		{


			if (key_puppet == 1)
			{
				if (unlikely(orig_hit_cnt_puppet == 0))
				{
					orig_hit_cnt_puppet = queued_paths + unique_crashes;
					last_limit_time_start = get_cur_time();
					SPLICE_CYCLES_puppet = (UR(SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) + SPLICE_CYCLES_puppet_low);
				}
			}


			{
#ifndef IGNORE_FINDS
			havoc_stage_puppet:
#endif

				stage_cur_byte = -1;

				/* The havoc stage mutation code is also invoked when splicing files; if the
				   splice_cycle variable is set, generate different descriptions and such. */

				if (!splice_cycle) {

					stage_name = "MOpt avoc";
					stage_short = "MOpt_havoc";
					stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
						perf_score / havoc_div / 100;

				}
				else {
					static u8 tmp[32];
					perf_score = orig_perf;
					sprintf(tmp, "MOpt splice %u", splice_cycle);
					stage_name = tmp;
					stage_short = "MOpt_splice";
					stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
				}



				if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;

				temp_len = len;

				orig_hit_cnt = queued_paths + unique_crashes;

				havoc_queued = queued_paths;



				for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

					u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));

					stage_cur_val = use_stacking;


					for (i = 0; i < operator_num; ++i)
					{
						stage_cycles_puppet_v3[swarm_now][i] = stage_cycles_puppet_v2[swarm_now][i];
					}


					for (i = 0; i < use_stacking; ++i) {

						switch (select_algorithm()) {

						case 0:
							/* Flip a single bit somewhere. Spooky! */
							FLIP_BIT(out_buf, UR(temp_len << 3));
							stage_cycles_puppet_v2[swarm_now][STAGE_FLIP1] += 1;
							break;


						case 1:
							if (temp_len < 2) break;
							temp_len_puppet = UR(temp_len << 3);
							FLIP_BIT(out_buf, temp_len_puppet);
							FLIP_BIT(out_buf, temp_len_puppet + 1);
							stage_cycles_puppet_v2[swarm_now][STAGE_FLIP2] += 1;
							break;

						case 2:
							if (temp_len < 2) break;
							temp_len_puppet = UR(temp_len << 3);
							FLIP_BIT(out_buf, temp_len_puppet);
							FLIP_BIT(out_buf, temp_len_puppet + 1);
							FLIP_BIT(out_buf, temp_len_puppet + 2);
							FLIP_BIT(out_buf, temp_len_puppet + 3);
							stage_cycles_puppet_v2[swarm_now][STAGE_FLIP4] += 1;
							break;

						case 3:
							if (temp_len < 4) break;
							out_buf[UR(temp_len)] ^= 0xFF;
							stage_cycles_puppet_v2[swarm_now][STAGE_FLIP8] += 1;
							break;

						case 4:
							if (temp_len < 8) break;
							*(u16*)(out_buf + UR(temp_len - 1)) ^= 0xFFFF;
							stage_cycles_puppet_v2[swarm_now][STAGE_FLIP16] += 1;
							break;

						case 5:
							if (temp_len < 8) break;
							*(u32*)(out_buf + UR(temp_len - 3)) ^= 0xFFFFFFFF;
							stage_cycles_puppet_v2[swarm_now][STAGE_FLIP32] += 1;
							break;

						case 6:
							out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
							out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
							stage_cycles_puppet_v2[swarm_now][STAGE_ARITH8] += 1;
							break;

						case 7:
							/* Randomly subtract from word, random endian. */
							if (temp_len < 8) break;
							if (UR(2)) {
								u32 pos = UR(temp_len - 1);
								*(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
							}
							else {
								u32 pos = UR(temp_len - 1);
								u16 num = 1 + UR(ARITH_MAX);
								*(u16*)(out_buf + pos) =
									SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);
							}
							/* Randomly add to word, random endian. */
							if (UR(2)) {
								u32 pos = UR(temp_len - 1);
								*(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
							}
							else {
								u32 pos = UR(temp_len - 1);
								u16 num = 1 + UR(ARITH_MAX);
								*(u16*)(out_buf + pos) =
									SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);
							}
							stage_cycles_puppet_v2[swarm_now][STAGE_ARITH16] += 1;
							break;


						case 8:
							/* Randomly subtract from dword, random endian. */
							if (temp_len < 8) break;
							if (UR(2)) {
								u32 pos = UR(temp_len - 3);
								*(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
							}
							else {
								u32 pos = UR(temp_len - 3);
								u32 num = 1 + UR(ARITH_MAX);
								*(u32*)(out_buf + pos) =
									SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);
							}
							/* Randomly add to dword, random endian. */
							//if (temp_len < 4) break;
							if (UR(2)) {
								u32 pos = UR(temp_len - 3);
								*(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
							}
							else {
								u32 pos = UR(temp_len - 3);
								u32 num = 1 + UR(ARITH_MAX);
								*(u32*)(out_buf + pos) =
									SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);
							}
							stage_cycles_puppet_v2[swarm_now][STAGE_ARITH32] += 1;
							break;


						case 9:
							/* Set byte to interesting value. */
							if (temp_len < 4) break;
							out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
							stage_cycles_puppet_v2[swarm_now][STAGE_INTEREST8] += 1;
							break;

						case 10:
							/* Set word to interesting value, randomly choosing endian. */
							if (temp_len < 8) break;
							if (UR(2)) {
								*(u16*)(out_buf + UR(temp_len - 1)) =
									interesting_16[UR(sizeof(interesting_16) >> 1)];
							}
							else {
								*(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
									interesting_16[UR(sizeof(interesting_16) >> 1)]);
							}
							stage_cycles_puppet_v2[swarm_now][STAGE_INTEREST16] += 1;
							break;


						case 11:
							/* Set dword to interesting value, randomly choosing endian. */

							if (temp_len < 8) break;

							if (UR(2)) {
								*(u32*)(out_buf + UR(temp_len - 3)) =
									interesting_32[UR(sizeof(interesting_32) >> 2)];
							}
							else {
								*(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
									interesting_32[UR(sizeof(interesting_32) >> 2)]);
							}
							stage_cycles_puppet_v2[swarm_now][STAGE_INTEREST32] += 1;
							break;


						case 12:

							/* Just set a random byte to a random value. Because,
							   why not. We use XOR with 1-255 to eliminate the
							   possibility of a no-op. */

							out_buf[UR(temp_len)] ^= 1 + UR(255);
							stage_cycles_puppet_v2[swarm_now][STAGE_RANDOMBYTE] += 1;
							break;



						case 13: {

							/* Delete bytes. We're making this a bit more likely
							   than insertion (the next option) in hopes of keeping
							   files reasonably small. */

							u32 del_from, del_len;

							if (temp_len < 2) break;

							/* Don't delete too much. */

							del_len = choose_block_len(temp_len - 1);

							del_from = UR(temp_len - del_len + 1);

							memmove(out_buf + del_from, out_buf + del_from + del_len,
								temp_len - del_from - del_len);

							temp_len -= del_len;
							stage_cycles_puppet_v2[swarm_now][STAGE_DELETEBYTE] += 1;
							break;

						}

						case 14:

							if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

								/* Clone bytes (75%) or insert a block of constant bytes (25%). */

								u8  actually_clone = UR(4);
								u32 clone_from, clone_to, clone_len;
								u8* new_buf;

								if (actually_clone) {

									clone_len = choose_block_len(temp_len);
									clone_from = UR(temp_len - clone_len + 1);

								}
								else {

									clone_len = choose_block_len(HAVOC_BLK_XL);
									clone_from = 0;

								}

								clone_to = UR(temp_len);

								new_buf = ck_alloc_nozero(temp_len + clone_len);

								/* Head */

								memcpy(new_buf, out_buf, clone_to);

								/* Inserted part */

								if (actually_clone)
									memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
								else
									memset(new_buf + clone_to,
										UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

								/* Tail */
								memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
									temp_len - clone_to);

								ck_free(out_buf);
								out_buf = new_buf;
								temp_len += clone_len;
								stage_cycles_puppet_v2[swarm_now][STAGE_Clone75] += 1;
							}

							break;

						case 15: {

							/* Overwrite bytes with a randomly selected chunk (75%) or fixed
							   bytes (25%). */

							u32 copy_from, copy_to, copy_len;

							if (temp_len < 2) break;

							copy_len = choose_block_len(temp_len - 1);

							copy_from = UR(temp_len - copy_len + 1);
							copy_to = UR(temp_len - copy_len + 1);

							if (UR(4)) {

								if (copy_from != copy_to)
									memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

							}
							else memset(out_buf + copy_to,
								UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);
							stage_cycles_puppet_v2[swarm_now][STAGE_OverWrite75] += 1;
							break;

						}


						}

					}


					tmp_pilot_time += 1;




					u64 temp_total_found = queued_paths + unique_crashes;




					if (common_fuzz_stuff(argv, out_buf, temp_len))
						goto abandon_entry_puppet;

					/* out_buf might have been mangled a bit, so let's restore it to its
					   original size and shape. */

					if (temp_len < len) out_buf = ck_realloc(out_buf, len);
					temp_len = len;
					memcpy(out_buf, in_buf, len);

					/* If we're finding new stuff, let's run for a bit longer, limits
					   permitting. */

					if (queued_paths != havoc_queued) {

						if (perf_score <= havoc_max_mult * 100) {
							stage_max *= 2;
							perf_score *= 2;
						}

						havoc_queued = queued_paths;

					}

					if (unlikely(queued_paths + unique_crashes > temp_total_found))
					{
						u64 temp_temp_puppet = queued_paths + unique_crashes - temp_total_found;
						total_puppet_find = total_puppet_find + temp_temp_puppet;
						for (i = 0; i < 16; ++i)
						{
							if (stage_cycles_puppet_v2[swarm_now][i] > stage_cycles_puppet_v3[swarm_now][i])
								stage_finds_puppet_v2[swarm_now][i] += temp_temp_puppet;
						}
					}

				}
				new_hit_cnt = queued_paths + unique_crashes;

				if (!splice_cycle) {
          stage_finds[STAGE_HAVOC]  += new_hit_cnt - orig_hit_cnt;
          stage_cycles[STAGE_HAVOC] += stage_max;
        } else {
          stage_finds[STAGE_SPLICE]  += new_hit_cnt - orig_hit_cnt;
          stage_cycles[STAGE_SPLICE] += stage_max;
        }

#ifndef IGNORE_FINDS

				/************
				 * SPLICING *
				 ************/


			retry_splicing_puppet:

				if (use_splicing && splice_cycle++ < SPLICE_CYCLES_puppet &&
					queued_paths > 1 && queue_cur->len > 1) {

					struct queue_entry* target;
					u32 tid, split_at;
					u8* new_buf;
					s32 f_diff, l_diff;

					/* First of all, if we've modified in_buf for havoc, let's clean that
					   up... */

					if (in_buf != orig_in) {
						ck_free(in_buf);
						in_buf = orig_in;
						len = queue_cur->len;
					}

					/* Pick a random queue entry and seek to it. Don't splice with yourself. */

					do { tid = UR(queued_paths); } while (tid == current_entry);

					splicing_with = tid;
					target = queue;

					while (tid >= 100) { target = target->next_100; tid -= 100; }
					while (tid--) target = target->next;

					/* Make sure that the target has a reasonable length. */

					while (target && (target->len < 2 || target == queue_cur)) {
						target = target->next;
						++splicing_with;
					}

					if (!target) goto retry_splicing_puppet;

					/* Read the testcase into a new buffer. */

					fd = open(target->fname, O_RDONLY);

					if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

					new_buf = ck_alloc_nozero(target->len);

					ck_read(fd, new_buf, target->len, target->fname);

					close(fd);

					/* Find a suitable splicin g location, somewhere between the first and
					   the last differing byte. Bail out if the difference is just a single
					   byte or so. */

					locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

					if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
						ck_free(new_buf);
						goto retry_splicing_puppet;
					}

					/* Split somewhere between the first and last differing byte. */

					split_at = f_diff + UR(l_diff - f_diff);

					/* Do the thing. */

					len = target->len;
					memcpy(new_buf, in_buf, split_at);
					in_buf = new_buf;
					ck_free(out_buf);
					out_buf = ck_alloc_nozero(len);
					memcpy(out_buf, in_buf, len);
					goto havoc_stage_puppet;

				}

#endif /* !IGNORE_FINDS */

				ret_val = 0;

			abandon_entry:
			abandon_entry_puppet:

				if (splice_cycle >= SPLICE_CYCLES_puppet)
					SPLICE_CYCLES_puppet = (UR(SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) + SPLICE_CYCLES_puppet_low);


				splicing_with = -1;

				/* Update pending_not_fuzzed count if we made it through the calibration
				   cycle and have not seen this entry before. */

				   // if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
				   //   queue_cur->was_fuzzed = 1;
				   //   --pending_not_fuzzed;
				   //   if (queue_cur->favored) --pending_favored;
				   // }

				munmap(orig_in, queue_cur->len);

				if (in_buf != orig_in) ck_free(in_buf);
				ck_free(out_buf);
				ck_free(eff_map);


				if (key_puppet == 1) {
					if (unlikely(queued_paths + unique_crashes > ((queued_paths + unique_crashes)*limit_time_bound + orig_hit_cnt_puppet)))	{
						key_puppet = 0;
						cur_ms_lv = get_cur_time();
						new_hit_cnt = queued_paths + unique_crashes;
						orig_hit_cnt_puppet = 0;
						last_limit_time_start = 0;
					}
				}


				if (unlikely(tmp_pilot_time > period_pilot)) {
					total_pacemaker_time += tmp_pilot_time;
					new_hit_cnt = queued_paths + unique_crashes;
					swarm_fitness[swarm_now] = (double)(total_puppet_find - temp_puppet_find) / ((double)(tmp_pilot_time)/ period_pilot_tmp);
					tmp_pilot_time = 0;
					temp_puppet_find = total_puppet_find;

					u64 temp_stage_finds_puppet = 0;
					for (i = 0; i < operator_num; ++i) {
						double temp_eff = 0.0;

						if (stage_cycles_puppet_v2[swarm_now][i] > stage_cycles_puppet[swarm_now][i])
							temp_eff = (double)(stage_finds_puppet_v2[swarm_now][i] - stage_finds_puppet[swarm_now][i]) /
							(double)(stage_cycles_puppet_v2[swarm_now][i] - stage_cycles_puppet[swarm_now][i]);

						if (eff_best[swarm_now][i] < temp_eff) {
							eff_best[swarm_now][i] = temp_eff;
							L_best[swarm_now][i] = x_now[swarm_now][i];
						}

						stage_finds_puppet[swarm_now][i] = stage_finds_puppet_v2[swarm_now][i];
						stage_cycles_puppet[swarm_now][i] = stage_cycles_puppet_v2[swarm_now][i];
						temp_stage_finds_puppet += stage_finds_puppet[swarm_now][i];
					}

					swarm_now = swarm_now + 1;
						if (swarm_now == swarm_num) {
							key_module = 1;
							for (i = 0; i < operator_num; ++i) {
								core_operator_cycles_puppet_v2[i] = core_operator_cycles_puppet[i];
								core_operator_cycles_puppet_v3[i] = core_operator_cycles_puppet[i];
								core_operator_finds_puppet_v2[i] = core_operator_finds_puppet[i];
							}

							double swarm_eff = 0.0;
							swarm_now = 0;
							for (i = 0; i < swarm_num; ++i)	{
								if (swarm_fitness[i] > swarm_eff) {
									swarm_eff = swarm_fitness[i];
									swarm_now = i;
								}
							}
							if (swarm_now <0 || swarm_now > swarm_num - 1)
								PFATAL("swarm_now error number  %d", swarm_now);

						}
				}
				return ret_val;
			}
		}


#undef FLIP_BIT

}


static u8 core_fuzzing(char** argv) {
	int i;

	if (swarm_num == 1) {
		key_module = 2;
		return 0;
	}


		s32 len, fd, temp_len, j;
		u8  *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
		u64 havoc_queued, orig_hit_cnt, new_hit_cnt, cur_ms_lv;
		u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

		u8  ret_val = 1, doing_det = 0;

		u8  a_collect[MAX_AUTO_EXTRA];
		u32 a_len = 0;

#ifdef IGNORE_FINDS

		/* In IGNORE_FINDS mode, skip any entries that weren't in the
		   initial data set. */

		if (queue_cur->depth > 1) return 1;

#else

		if (pending_favored) {

			/* If we have any favored, non-fuzzed new arrivals in the queue,
			   possibly skip to them at the expense of already-fuzzed or non-favored
			   cases. */

			if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
				UR(100) < SKIP_TO_NEW_PROB) return 1;

		} else if (!dumb_mode && !queue_cur->favored && queued_paths > 10) {

			/* Otherwise, still possibly skip non-favored cases, albeit less often.
			   The odds of skipping stuff are higher for already-fuzzed inputs and
			   lower for never-fuzzed entries. */

			if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

				if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

			} else {

				if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

			}

		}

#endif /* ^IGNORE_FINDS */

		if (not_on_tty) {
			ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
				current_entry, queued_paths, unique_crashes);
			fflush(stdout);
		}

		/* Map the test case into memory. */

		fd = open(queue_cur->fname, O_RDONLY);

		if (fd < 0) PFATAL("Unable to open '%s'", queue_cur->fname);

		len = queue_cur->len;

		orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

		if (orig_in == MAP_FAILED) PFATAL("Unable to mmap '%s'", queue_cur->fname);

		close(fd);

		/* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
		   single byte anyway, so it wouldn't give us any performance or memory usage
		   benefits. */

		out_buf = ck_alloc_nozero(len);

		subseq_tmouts = 0;

		cur_depth = queue_cur->depth;

		/*******************************************
		 * CALIBRATION (only if failed earlier on) *
		 *******************************************/

		if (queue_cur->cal_failed) {

			u8 res = FAULT_TMOUT;

			if (queue_cur->cal_failed < CAL_CHANCES) {

				res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);

				if (res == FAULT_ERROR)
					FATAL("Unable to execute target application");

			}

			if (stop_soon || res != crash_mode) {
				++cur_skipped_paths;
				goto abandon_entry;
			}

		}

		/************
		 * TRIMMING *
		 ************/

		if (!dumb_mode && !queue_cur->trim_done) {

			u8 res = trim_case(argv, queue_cur, in_buf);

			if (res == FAULT_ERROR)
				FATAL("Unable to execute target application");

			if (stop_soon) {
				++cur_skipped_paths;
				goto abandon_entry;
			}

			/* Don't retry trimming, even if it failed. */

			queue_cur->trim_done = 1;

			len = queue_cur->len;

		}

		memcpy(out_buf, in_buf, len);

		/*********************
		 * PERFORMANCE SCORE *
		 *********************/

		orig_perf = perf_score = calculate_score(queue_cur);

		/* Skip right away if -d is given, if we have done deterministic fuzzing on
		   this entry ourselves (was_fuzzed), or if it has gone through deterministic
		   testing in earlier, resumed runs (passed_det). */

		if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
			goto havoc_stage;

		/* Skip deterministic fuzzing if exec path checksum puts this out of scope
		   for this master instance. */

		if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
			goto havoc_stage;


		cur_ms_lv = get_cur_time();
		if (!(key_puppet == 0 && ((cur_ms_lv - last_path_time < limit_time_puppet) ||
			(last_crash_time != 0 && cur_ms_lv - last_crash_time < limit_time_puppet) || last_path_time == 0)))
		{
			key_puppet = 1;
			goto pacemaker_fuzzing;
		}

		doing_det = 1;

		/*********************************************
		 * SIMPLE BITFLIP (+dictionary construction) *
		 *********************************************/

#define FLIP_BIT(_ar, _b) do { \
    u8* _arf = (u8*)(_ar); \
    u32 _bf = (_b); \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
  } while (0)

		 /* Single walking bit. */

		stage_short = "flip1";
		stage_max = len << 3;
		stage_name = "bitflip 1/1";

		stage_val_type = STAGE_VAL_NONE;

		orig_hit_cnt = queued_paths + unique_crashes;

		prev_cksum = queue_cur->exec_cksum;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur >> 3;

			FLIP_BIT(out_buf, stage_cur);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			FLIP_BIT(out_buf, stage_cur);

			/* While flipping the least significant bit in every byte, pull of an extra
			   trick to detect possible syntax tokens. In essence, the idea is that if
			   you have a binary blob like this:

			   xxxxxxxxIHDRxxxxxxxx

			   ...and changing the leading and trailing bytes causes variable or no
			   changes in program flow, but touching any character in the "IHDR" string
			   always produces the same, distinctive path, it's highly likely that
			   "IHDR" is an atomically-checked magic value of special significance to
			   the fuzzed format.

			   We do this here, rather than as a separate stage, because it's a nice
			   way to keep the operation approximately "free" (i.e., no extra execs).

			   Empirically, performing the check when flipping the least significant bit
			   is advantageous, compared to doing it at the time of more disruptive
			   changes, where the program flow may be affected in more violent ways.

			   The caveat is that we won't generate dictionaries in the -d mode or -S
			   mode - but that's probably a fair trade-off.

			   This won't work particularly well with paths that exhibit variable
			   behavior, but fails gracefully, so we'll carry out the checks anyway.

			  */

			if (!dumb_mode && (stage_cur & 7) == 7) {

				u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

				if (stage_cur == stage_max - 1 && cksum == prev_cksum) {

					/* If at end of file and we are still collecting a string, grab the
					   final character and force output. */

					if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
					++a_len;

					if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
						maybe_add_auto(a_collect, a_len);

				}
				else if (cksum != prev_cksum) {

					/* Otherwise, if the checksum has changed, see if we have something
					   worthwhile queued up, and collect that if the answer is yes. */

					if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
						maybe_add_auto(a_collect, a_len);

					a_len = 0;
					prev_cksum = cksum;

				}

				/* Continue collecting string, but only if the bit flip actually made
				   any difference - we don't want no-op tokens. */

				if (cksum != queue_cur->exec_cksum) {

					if (a_len < MAX_AUTO_EXTRA) a_collect[a_len] = out_buf[stage_cur >> 3];
					++a_len;

				}

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP1] += stage_max;



		/* Two walking bits. */

		stage_name = "bitflip 2/1";
		stage_short = "flip2";
		stage_max = (len << 3) - 1;

		orig_hit_cnt = new_hit_cnt;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur >> 3;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP2] += stage_max;


		/* Four walking bits. */

		stage_name = "bitflip 4/1";
		stage_short = "flip4";
		stage_max = (len << 3) - 3;


		orig_hit_cnt = new_hit_cnt;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur >> 3;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);
			FLIP_BIT(out_buf, stage_cur + 2);
			FLIP_BIT(out_buf, stage_cur + 3);

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			FLIP_BIT(out_buf, stage_cur);
			FLIP_BIT(out_buf, stage_cur + 1);
			FLIP_BIT(out_buf, stage_cur + 2);
			FLIP_BIT(out_buf, stage_cur + 3);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP4] += stage_max;


		/* Effector map setup. These macros calculate:

		   EFF_APOS      - position of a particular file offset in the map.
		   EFF_ALEN      - length of a map with a particular number of bytes.
		   EFF_SPAN_ALEN - map span for a sequence of bytes.

		 */

#define EFF_APOS(_p)          ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x)           ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l)          (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l) - 1) - EFF_APOS(_p) + 1)

		 /* Initialize effector map for the next step (see comments below). Always
			flag first and last byte as doing something. */

		eff_map = ck_alloc(EFF_ALEN(len));
		eff_map[0] = 1;

		if (EFF_APOS(len - 1) != 0) {
			eff_map[EFF_APOS(len - 1)] = 1;
			++eff_cnt;
		}

		/* Walking byte. */

		stage_name = "bitflip 8/8";
		stage_short = "flip8";
		stage_max = len;


		orig_hit_cnt = new_hit_cnt;

		for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

			stage_cur_byte = stage_cur;

			out_buf[stage_cur] ^= 0xFF;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

			/* We also use this stage to pull off a simple trick: we identify
			   bytes that seem to have no effect on the current execution path
			   even when fully flipped - and we skip them during more expensive
			   deterministic stages, such as arithmetics or known ints. */

			if (!eff_map[EFF_APOS(stage_cur)]) {

				u32 cksum;

				/* If in dumb mode or if the file is very short, just flag everything
				   without wasting time on checksums. */

				if (!dumb_mode && len >= EFF_MIN_LEN)
					cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
				else
					cksum = ~queue_cur->exec_cksum;

				if (cksum != queue_cur->exec_cksum) {
					eff_map[EFF_APOS(stage_cur)] = 1;
					++eff_cnt;
				}

			}

			out_buf[stage_cur] ^= 0xFF;

		}

		/* If the effector map is more than EFF_MAX_PERC dense, just flag the
		   whole thing as worth fuzzing, since we wouldn't be saving much time
		   anyway. */

		if (eff_cnt != EFF_ALEN(len) &&
			eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

			memset(eff_map, 1, EFF_ALEN(len));

			blocks_eff_select += EFF_ALEN(len);

		}
		else {

			blocks_eff_select += eff_cnt;

		}

		blocks_eff_total += EFF_ALEN(len);

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP8] += stage_max;



		/* Two walking bytes. */

		if (len < 2) goto skip_bitflip;

		stage_name = "bitflip 16/8";
		stage_short = "flip16";
		stage_cur = 0;
		stage_max = len - 1;


		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 1; ++i) {

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
				--stage_max;
				continue;
			}

			stage_cur_byte = i;

			*(u16*)(out_buf + i) ^= 0xFFFF;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			++stage_cur;

			*(u16*)(out_buf + i) ^= 0xFFFF;


		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP16] += stage_max;



		if (len < 4) goto skip_bitflip;

		/* Four walking bytes. */

		stage_name = "bitflip 32/8";
		stage_short = "flip32";
		stage_cur = 0;
		stage_max = len - 3;


		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 3; ++i) {

			/* Let's consult the effector map... */
			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
				!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
				--stage_max;
				continue;
			}

			stage_cur_byte = i;

			*(u32*)(out_buf + i) ^= 0xFFFFFFFF;

			if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
			++stage_cur;

			*(u32*)(out_buf + i) ^= 0xFFFFFFFF;

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_FLIP32] += stage_max;




	skip_bitflip:

		if (no_arith) goto skip_arith;

		/**********************
		 * ARITHMETIC INC/DEC *
		 **********************/

		 /* 8-bit arithmetics. */

		stage_name = "arith 8/8";
		stage_short = "arith8";
		stage_cur = 0;
		stage_max = 2 * len * ARITH_MAX;


		stage_val_type = STAGE_VAL_LE;

		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len; ++i) {

			u8 orig = out_buf[i];

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)]) {
				stage_max -= 2 * ARITH_MAX;
				continue;
			}

			stage_cur_byte = i;

			for (j = 1; j <= ARITH_MAX; ++j) {

				u8 r = orig ^ (orig + j);

				/* Do arithmetic operations only if the result couldn't be a product
				   of a bitflip. */

				if (!could_be_bitflip(r)) {

					stage_cur_val = j;
					out_buf[i] = orig + j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				r = orig ^ (orig - j);

				if (!could_be_bitflip(r)) {

					stage_cur_val = -j;
					out_buf[i] = orig - j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				out_buf[i] = orig;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_ARITH8] += stage_max;




		/* 16-bit arithmetics, both endians. */

		if (len < 2) goto skip_arith;

		stage_name = "arith 16/8";
		stage_short = "arith16";
		stage_cur = 0;
		stage_max = 4 * (len - 1) * ARITH_MAX;


		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 1; ++i) {

			u16 orig = *(u16*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
				stage_max -= 4 * ARITH_MAX;
				continue;
			}

			stage_cur_byte = i;

			for (j = 1; j <= ARITH_MAX; ++j) {

				u16 r1 = orig ^ (orig + j),
					r2 = orig ^ (orig - j),
					r3 = orig ^ SWAP16(SWAP16(orig) + j),
					r4 = orig ^ SWAP16(SWAP16(orig) - j);

				/* Try little endian addition and subtraction first. Do it only
				   if the operation would affect more than one byte (hence the
				   & 0xff overflow checks) and if it couldn't be a product of
				   a bitflip. */

				stage_val_type = STAGE_VAL_LE;

				if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

					stage_cur_val = j;
					*(u16*)(out_buf + i) = orig + j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

					stage_cur_val = -j;
					*(u16*)(out_buf + i) = orig - j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				/* Big endian comes next. Same deal. */

				stage_val_type = STAGE_VAL_BE;


				if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

					stage_cur_val = j;
					*(u16*)(out_buf + i) = SWAP16(SWAP16(orig) + j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((orig >> 8) < j && !could_be_bitflip(r4)) {

					stage_cur_val = -j;
					*(u16*)(out_buf + i) = SWAP16(SWAP16(orig) - j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				*(u16*)(out_buf + i) = orig;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_ARITH16] += stage_max;



		/* 32-bit arithmetics, both endians. */

		if (len < 4) goto skip_arith;

		stage_name = "arith 32/8";
		stage_short = "arith32";
		stage_cur = 0;
		stage_max = 4 * (len - 3) * ARITH_MAX;

		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 3; ++i) {

			u32 orig = *(u32*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
				!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
				stage_max -= 4 * ARITH_MAX;
				continue;
			}

			stage_cur_byte = i;

			for (j = 1; j <= ARITH_MAX; ++j) {

				u32 r1 = orig ^ (orig + j),
					r2 = orig ^ (orig - j),
					r3 = orig ^ SWAP32(SWAP32(orig) + j),
					r4 = orig ^ SWAP32(SWAP32(orig) - j);

				/* Little endian first. Same deal as with 16-bit: we only want to
				   try if the operation would have effect on more than two bytes. */

				stage_val_type = STAGE_VAL_LE;

				if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

					stage_cur_val = j;
					*(u32*)(out_buf + i) = orig + j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

					stage_cur_val = -j;
					*(u32*)(out_buf + i) = orig - j;

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				/* Big endian next. */

				stage_val_type = STAGE_VAL_BE;

				if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

					stage_cur_val = j;
					*(u32*)(out_buf + i) = SWAP32(SWAP32(orig) + j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

					stage_cur_val = -j;
					*(u32*)(out_buf + i) = SWAP32(SWAP32(orig) - j);

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				*(u32*)(out_buf + i) = orig;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_ARITH32] += stage_max;



	skip_arith:

		/**********************
		 * INTERESTING VALUES *
		 **********************/

		stage_name = "interest 8/8";
		stage_short = "int8";
		stage_cur = 0;
		stage_max = len * sizeof(interesting_8);



		stage_val_type = STAGE_VAL_LE;

		orig_hit_cnt = new_hit_cnt;

		/* Setting 8-bit integers. */

		for (i = 0; i < len; ++i) {

			u8 orig = out_buf[i];

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)]) {
				stage_max -= sizeof(interesting_8);
				continue;
			}

			stage_cur_byte = i;

			for (j = 0; j < sizeof(interesting_8); ++j) {

				/* Skip if the value could be a product of bitflips or arithmetics. */

				if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
					could_be_arith(orig, (u8)interesting_8[j], 1)) {
					--stage_max;
					continue;
				}

				stage_cur_val = interesting_8[j];
				out_buf[i] = interesting_8[j];

				if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

				out_buf[i] = orig;
				++stage_cur;

			}

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_INTEREST8] += stage_max;



		/* Setting 16-bit integers, both endians. */

		if (no_arith || len < 2) goto skip_interest;

		stage_name = "interest 16/8";
		stage_short = "int16";
		stage_cur = 0;
		stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);


		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 1; ++i) {

			u16 orig = *(u16*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {
				stage_max -= sizeof(interesting_16);
				continue;
			}

			stage_cur_byte = i;

			for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

				stage_cur_val = interesting_16[j];

				/* Skip if this could be a product of a bitflip, arithmetics,
				   or single-byte interesting value insertion. */

				if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
					!could_be_arith(orig, (u16)interesting_16[j], 2) &&
					!could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

					stage_val_type = STAGE_VAL_LE;

					*(u16*)(out_buf + i) = interesting_16[j];

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
					!could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
					!could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
					!could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

					stage_val_type = STAGE_VAL_BE;

					*(u16*)(out_buf + i) = SWAP16(interesting_16[j]);
					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

			}

			*(u16*)(out_buf + i) = orig;

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_INTEREST16] += stage_max;




		if (len < 4) goto skip_interest;

		/* Setting 32-bit integers, both endians. */

		stage_name = "interest 32/8";
		stage_short = "int32";
		stage_cur = 0;
		stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);


		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len - 3; ++i) {

			u32 orig = *(u32*)(out_buf + i);

			/* Let's consult the effector map... */

			if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
				!eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {
				stage_max -= sizeof(interesting_32) >> 1;
				continue;
			}

			stage_cur_byte = i;

			for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

				stage_cur_val = interesting_32[j];

				/* Skip if this could be a product of a bitflip, arithmetics,
				   or word interesting value insertion. */

				if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
					!could_be_arith(orig, interesting_32[j], 4) &&
					!could_be_interest(orig, interesting_32[j], 4, 0)) {

					stage_val_type = STAGE_VAL_LE;

					*(u32*)(out_buf + i) = interesting_32[j];

					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

				if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
					!could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
					!could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
					!could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

					stage_val_type = STAGE_VAL_BE;

					*(u32*)(out_buf + i) = SWAP32(interesting_32[j]);
					if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
					++stage_cur;

				} else --stage_max;

			}

			*(u32*)(out_buf + i) = orig;

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_INTEREST32] += stage_max;



	skip_interest:

		/********************
		 * DICTIONARY STUFF *
		 ********************/

		if (!extras_cnt) goto skip_user_extras;

		/* Overwrite with user-supplied extras. */

		stage_name = "user extras (over)";
		stage_short = "ext_UO";
		stage_cur = 0;
		stage_max = extras_cnt * len;


		stage_val_type = STAGE_VAL_NONE;

		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len; ++i) {

			u32 last_len = 0;

			stage_cur_byte = i;

			/* Extras are sorted by size, from smallest to largest. This means
			   that we don't have to worry about restoring the buffer in
			   between writes at a particular offset determined by the outer
			   loop. */

			for (j = 0; j < extras_cnt; ++j) {

				/* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
				   skip them if there's no room to insert the payload, if the token
				   is redundant, or if its entire span has no bytes set in the effector
				   map. */

				if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
					extras[j].len > len - i ||
					!memcmp(extras[j].data, out_buf + i, extras[j].len) ||
					!memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

					--stage_max;
					continue;

				}

				last_len = extras[j].len;
				memcpy(out_buf + i, extras[j].data, last_len);

				if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

				++stage_cur;

			}

			/* Restore all the clobbered memory. */
			memcpy(out_buf + i, in_buf + i, last_len);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_EXTRAS_UO] += stage_max;

		/* Insertion of user-supplied extras. */

		stage_name = "user extras (insert)";
		stage_short = "ext_UI";
		stage_cur = 0;
		stage_max = extras_cnt * len;




		orig_hit_cnt = new_hit_cnt;

		ex_tmp = ck_alloc(len + MAX_DICT_FILE);

		for (i = 0; i <= len; ++i) {

			stage_cur_byte = i;

			for (j = 0; j < extras_cnt; ++j) {

				if (len + extras[j].len > MAX_FILE) {
					--stage_max;
					continue;
				}

				/* Insert token */
				memcpy(ex_tmp + i, extras[j].data, extras[j].len);

				/* Copy tail */
				memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);

				if (common_fuzz_stuff(argv, ex_tmp, len + extras[j].len)) {
					ck_free(ex_tmp);
					goto abandon_entry;
				}

				++stage_cur;

			}

			/* Copy head */
			ex_tmp[i] = out_buf[i];

		}

		ck_free(ex_tmp);

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_EXTRAS_UI] += stage_max;

	skip_user_extras:

		if (!a_extras_cnt) goto skip_extras;

		stage_name = "auto extras (over)";
		stage_short = "ext_AO";
		stage_cur = 0;
		stage_max = MIN(a_extras_cnt, USE_AUTO_EXTRAS) * len;


		stage_val_type = STAGE_VAL_NONE;

		orig_hit_cnt = new_hit_cnt;

		for (i = 0; i < len; ++i) {

			u32 last_len = 0;

			stage_cur_byte = i;

			for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); ++j) {

				/* See the comment in the earlier code; extras are sorted by size. */

				if (a_extras[j].len > len - i ||
					!memcmp(a_extras[j].data, out_buf + i, a_extras[j].len) ||
					!memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, a_extras[j].len))) {

					--stage_max;
					continue;

				}

				last_len = a_extras[j].len;
				memcpy(out_buf + i, a_extras[j].data, last_len);

				if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;

				++stage_cur;

			}

			/* Restore all the clobbered memory. */
			memcpy(out_buf + i, in_buf + i, last_len);

		}

		new_hit_cnt = queued_paths + unique_crashes;

		stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
		stage_cycles[STAGE_EXTRAS_AO] += stage_max;

	skip_extras:

		/* If we made this to here without jumping to havoc_stage or abandon_entry,
		   we're properly done with deterministic steps and can mark it as such
		   in the .state/ directory. */

		if (!queue_cur->passed_det) mark_as_det_done(queue_cur);

		/****************
		 * RANDOM HAVOC *
		 ****************/

	havoc_stage:
	pacemaker_fuzzing:


		stage_cur_byte = -1;

		/* The havoc stage mutation code is also invoked when splicing files; if the
		   splice_cycle variable is set, generate different descriptions and such. */

		if (!splice_cycle) {

			stage_name = "MOpt-havoc";
			stage_short = "MOpt_havoc";
			stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
				perf_score / havoc_div / 100;

		} else {

			static u8 tmp[32];

			perf_score = orig_perf;

			sprintf(tmp, "MOpt-core-splice %u", splice_cycle);
			stage_name = tmp;
			stage_short = "MOpt_core_splice";
			stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;

		}

		s32 temp_len_puppet;
		cur_ms_lv = get_cur_time();

		//for (; swarm_now < swarm_num; ++swarm_now)
		{
			if (key_puppet == 1) {
				if (unlikely(orig_hit_cnt_puppet == 0)) {
					orig_hit_cnt_puppet = queued_paths + unique_crashes;
					last_limit_time_start = get_cur_time();
					SPLICE_CYCLES_puppet = (UR(SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) + SPLICE_CYCLES_puppet_low);
				}
			}
			{
#ifndef IGNORE_FINDS
			havoc_stage_puppet:
#endif

				stage_cur_byte = -1;

				/* The havoc stage mutation code is also invoked when splicing files; if the
				   splice_cycle variable is set, generate different descriptions and such. */

				if (!splice_cycle) {
					stage_name = "MOpt core avoc";
					stage_short = "MOpt_core_havoc";
					stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
						perf_score / havoc_div / 100;
				} else {
					static u8 tmp[32];
					perf_score = orig_perf;
					sprintf(tmp, "MOpt core splice %u", splice_cycle);
					stage_name = tmp;
					stage_short = "MOpt_core_splice";
					stage_max = SPLICE_HAVOC * perf_score / havoc_div / 100;
				}

				if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
				temp_len = len;
				orig_hit_cnt = queued_paths + unique_crashes;
				havoc_queued = queued_paths;

				for (stage_cur = 0; stage_cur < stage_max; ++stage_cur) {

					u32 use_stacking = 1 << (1 + UR(HAVOC_STACK_POW2));
					stage_cur_val = use_stacking;

					for (i = 0; i < operator_num; ++i) {
						core_operator_cycles_puppet_v3[i] = core_operator_cycles_puppet_v2[i];
					}

					for (i = 0; i < use_stacking; ++i) {

						switch (select_algorithm()) {

						case 0:
							/* Flip a single bit somewhere. Spooky! */
							FLIP_BIT(out_buf, UR(temp_len << 3));
							core_operator_cycles_puppet_v2[STAGE_FLIP1] += 1;
							break;


						case 1:
							if (temp_len < 2) break;
							temp_len_puppet = UR(temp_len << 3);
							FLIP_BIT(out_buf, temp_len_puppet);
							FLIP_BIT(out_buf, temp_len_puppet + 1);
							core_operator_cycles_puppet_v2[STAGE_FLIP2] += 1;
							break;

						case 2:
							if (temp_len < 2) break;
							temp_len_puppet = UR(temp_len << 3);
							FLIP_BIT(out_buf, temp_len_puppet);
							FLIP_BIT(out_buf, temp_len_puppet + 1);
							FLIP_BIT(out_buf, temp_len_puppet + 2);
							FLIP_BIT(out_buf, temp_len_puppet + 3);
							core_operator_cycles_puppet_v2[STAGE_FLIP4] += 1;
							break;

						case 3:
							if (temp_len < 4) break;
							out_buf[UR(temp_len)] ^= 0xFF;
							core_operator_cycles_puppet_v2[STAGE_FLIP8] += 1;
							break;

						case 4:
							if (temp_len < 8) break;
							*(u16*)(out_buf + UR(temp_len - 1)) ^= 0xFFFF;
							core_operator_cycles_puppet_v2[STAGE_FLIP16] += 1;
							break;

						case 5:
							if (temp_len < 8) break;
							*(u32*)(out_buf + UR(temp_len - 3)) ^= 0xFFFFFFFF;
							core_operator_cycles_puppet_v2[STAGE_FLIP32] += 1;
							break;

						case 6:
							out_buf[UR(temp_len)] -= 1 + UR(ARITH_MAX);
							out_buf[UR(temp_len)] += 1 + UR(ARITH_MAX);
							core_operator_cycles_puppet_v2[STAGE_ARITH8] += 1;
							break;

						case 7:
							/* Randomly subtract from word, random endian. */
							if (temp_len < 8) break;
							if (UR(2)) {
								u32 pos = UR(temp_len - 1);
								*(u16*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
							} else {
								u32 pos = UR(temp_len - 1);
								u16 num = 1 + UR(ARITH_MAX);
								*(u16*)(out_buf + pos) =
									SWAP16(SWAP16(*(u16*)(out_buf + pos)) - num);
							}
							/* Randomly add to word, random endian. */
							if (UR(2)) {
								u32 pos = UR(temp_len - 1);
								*(u16*)(out_buf + pos) += 1 + UR(ARITH_MAX);
							} else {
								u32 pos = UR(temp_len - 1);
								u16 num = 1 + UR(ARITH_MAX);
								*(u16*)(out_buf + pos) =
									SWAP16(SWAP16(*(u16*)(out_buf + pos)) + num);
							}
							core_operator_cycles_puppet_v2[STAGE_ARITH16] += 1;
							break;


						case 8:
							/* Randomly subtract from dword, random endian. */
							if (temp_len < 8) break;
							if (UR(2)) {
								u32 pos = UR(temp_len - 3);
								*(u32*)(out_buf + pos) -= 1 + UR(ARITH_MAX);
							} else {
								u32 pos = UR(temp_len - 3);
								u32 num = 1 + UR(ARITH_MAX);
								*(u32*)(out_buf + pos) =
									SWAP32(SWAP32(*(u32*)(out_buf + pos)) - num);
							}
							/* Randomly add to dword, random endian. */
							if (UR(2)) {
								u32 pos = UR(temp_len - 3);
								*(u32*)(out_buf + pos) += 1 + UR(ARITH_MAX);
							} else {
								u32 pos = UR(temp_len - 3);
								u32 num = 1 + UR(ARITH_MAX);
								*(u32*)(out_buf + pos) =
									SWAP32(SWAP32(*(u32*)(out_buf + pos)) + num);
							}
							core_operator_cycles_puppet_v2[STAGE_ARITH32] += 1;
							break;


						case 9:
							/* Set byte to interesting value. */
							if (temp_len < 4) break;
							out_buf[UR(temp_len)] = interesting_8[UR(sizeof(interesting_8))];
							core_operator_cycles_puppet_v2[STAGE_INTEREST8] += 1;
							break;

						case 10:
							/* Set word to interesting value, randomly choosing endian. */
							if (temp_len < 8) break;
							if (UR(2)) {
								*(u16*)(out_buf + UR(temp_len - 1)) =
									interesting_16[UR(sizeof(interesting_16) >> 1)];
							} else {
								*(u16*)(out_buf + UR(temp_len - 1)) = SWAP16(
									interesting_16[UR(sizeof(interesting_16) >> 1)]);
							}
							core_operator_cycles_puppet_v2[STAGE_INTEREST16] += 1;
							break;


						case 11:
							/* Set dword to interesting value, randomly choosing endian. */

							if (temp_len < 8) break;

							if (UR(2)) {
								*(u32*)(out_buf + UR(temp_len - 3)) =
									interesting_32[UR(sizeof(interesting_32) >> 2)];
							} else {
								*(u32*)(out_buf + UR(temp_len - 3)) = SWAP32(
									interesting_32[UR(sizeof(interesting_32) >> 2)]);
							}
							core_operator_cycles_puppet_v2[STAGE_INTEREST32] += 1;
							break;


						case 12:

							/* Just set a random byte to a random value. Because,
							   why not. We use XOR with 1-255 to eliminate the
							   possibility of a no-op. */

							out_buf[UR(temp_len)] ^= 1 + UR(255);
							core_operator_cycles_puppet_v2[STAGE_RANDOMBYTE] += 1;
							break;


						case 13: {

							/* Delete bytes. We're making this a bit more likely
							   than insertion (the next option) in hopes of keeping
							   files reasonably small. */

							u32 del_from, del_len;

							if (temp_len < 2) break;

							/* Don't delete too much. */

							del_len = choose_block_len(temp_len - 1);

							del_from = UR(temp_len - del_len + 1);

							memmove(out_buf + del_from, out_buf + del_from + del_len,
								temp_len - del_from - del_len);

							temp_len -= del_len;
							core_operator_cycles_puppet_v2[STAGE_DELETEBYTE] += 1;
							break;

						}

						case 14:

							if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

								/* Clone bytes (75%) or insert a block of constant bytes (25%). */

								u8  actually_clone = UR(4);
								u32 clone_from, clone_to, clone_len;
								u8* new_buf;

								if (actually_clone) {

									clone_len = choose_block_len(temp_len);
									clone_from = UR(temp_len - clone_len + 1);

								} else {

									clone_len = choose_block_len(HAVOC_BLK_XL);
									clone_from = 0;

								}

								clone_to = UR(temp_len);

								new_buf = ck_alloc_nozero(temp_len + clone_len);

								/* Head */

								memcpy(new_buf, out_buf, clone_to);

								/* Inserted part */

								if (actually_clone)
									memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
								else
									memset(new_buf + clone_to,
										UR(2) ? UR(256) : out_buf[UR(temp_len)], clone_len);

								/* Tail */
								memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
									temp_len - clone_to);

								ck_free(out_buf);
								out_buf = new_buf;
								temp_len += clone_len;
								core_operator_cycles_puppet_v2[STAGE_Clone75] += 1;
							}

							break;

						case 15: {

							/* Overwrite bytes with a randomly selected chunk (75%) or fixed
							   bytes (25%). */

							u32 copy_from, copy_to, copy_len;

							if (temp_len < 2) break;

							copy_len = choose_block_len(temp_len - 1);

							copy_from = UR(temp_len - copy_len + 1);
							copy_to = UR(temp_len - copy_len + 1);

							if (UR(4)) {

								if (copy_from != copy_to)
									memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

							}
							else memset(out_buf + copy_to,
								UR(2) ? UR(256) : out_buf[UR(temp_len)], copy_len);
							core_operator_cycles_puppet_v2[STAGE_OverWrite75] += 1;
							break;

						}


						}

					}

					tmp_core_time += 1;

					u64 temp_total_found = queued_paths + unique_crashes;

					if (common_fuzz_stuff(argv, out_buf, temp_len))
						goto abandon_entry_puppet;

					/* out_buf might have been mangled a bit, so let's restore it to its
					   original size and shape. */

					if (temp_len < len) out_buf = ck_realloc(out_buf, len);
					temp_len = len;
					memcpy(out_buf, in_buf, len);

					/* If we're finding new stuff, let's run for a bit longer, limits
					   permitting. */

					if (queued_paths != havoc_queued) {

						if (perf_score <= havoc_max_mult * 100) {
							stage_max *= 2;
							perf_score *= 2;
						}

						havoc_queued = queued_paths;

					}

					if (unlikely(queued_paths + unique_crashes > temp_total_found))
					{
						u64 temp_temp_puppet = queued_paths + unique_crashes - temp_total_found;
						total_puppet_find = total_puppet_find + temp_temp_puppet;
						for (i = 0; i < 16; ++i)
						{
							if (core_operator_cycles_puppet_v2[i] > core_operator_cycles_puppet_v3[i])
								core_operator_finds_puppet_v2[i] += temp_temp_puppet;
						}
					}

				}

				new_hit_cnt = queued_paths + unique_crashes;


#ifndef IGNORE_FINDS

				/************
				 * SPLICING *
				 ************/


			retry_splicing_puppet:



				if (use_splicing && splice_cycle++ < SPLICE_CYCLES_puppet &&
					queued_paths > 1 && queue_cur->len > 1) {

					struct queue_entry* target;
					u32 tid, split_at;
					u8* new_buf;
					s32 f_diff, l_diff;

					/* First of all, if we've modified in_buf for havoc, let's clean that
					   up... */

					if (in_buf != orig_in) {
						ck_free(in_buf);
						in_buf = orig_in;
						len = queue_cur->len;
					}

					/* Pick a random queue entry and seek to it. Don't splice with yourself. */

					do { tid = UR(queued_paths); } while (tid == current_entry);

					splicing_with = tid;
					target = queue;

					while (tid >= 100) { target = target->next_100; tid -= 100; }
					while (tid--) target = target->next;

					/* Make sure that the target has a reasonable length. */

					while (target && (target->len < 2 || target == queue_cur)) {
						target = target->next;
						++splicing_with;
					}

					if (!target) goto retry_splicing_puppet;

					/* Read the testcase into a new buffer. */

					fd = open(target->fname, O_RDONLY);

					if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

					new_buf = ck_alloc_nozero(target->len);

					ck_read(fd, new_buf, target->len, target->fname);

					close(fd);

					/* Find a suitable splicin g location, somewhere between the first and
					   the last differing byte. Bail out if the difference is just a single
					   byte or so. */

					locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

					if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
						ck_free(new_buf);
						goto retry_splicing_puppet;
					}

					/* Split somewhere between the first and last differing byte. */

					split_at = f_diff + UR(l_diff - f_diff);

					/* Do the thing. */

					len = target->len;
					memcpy(new_buf, in_buf, split_at);
					in_buf = new_buf;
					ck_free(out_buf);
					out_buf = ck_alloc_nozero(len);
					memcpy(out_buf, in_buf, len);

					goto havoc_stage_puppet;

				}

#endif /* !IGNORE_FINDS */

				ret_val = 0;
			abandon_entry:
			abandon_entry_puppet:

				if (splice_cycle >= SPLICE_CYCLES_puppet)
					SPLICE_CYCLES_puppet = (UR(SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) + SPLICE_CYCLES_puppet_low);


				splicing_with = -1;


				munmap(orig_in, queue_cur->len);

				if (in_buf != orig_in) ck_free(in_buf);
				ck_free(out_buf);
				ck_free(eff_map);


				if (key_puppet == 1)
				{
					if (unlikely(queued_paths + unique_crashes > ((queued_paths + unique_crashes)*limit_time_bound + orig_hit_cnt_puppet)))
					{
						key_puppet = 0;
						cur_ms_lv = get_cur_time();
						new_hit_cnt = queued_paths + unique_crashes;
						orig_hit_cnt_puppet = 0;
						last_limit_time_start = 0;
					}
				}


				if (unlikely(tmp_core_time > period_core))
				{
					total_pacemaker_time += tmp_core_time;
					tmp_core_time = 0;
					temp_puppet_find = total_puppet_find;
					new_hit_cnt = queued_paths + unique_crashes;

					u64 temp_stage_finds_puppet = 0;
					for (i = 0; i < operator_num; ++i)
					{

						core_operator_finds_puppet[i] = core_operator_finds_puppet_v2[i];
						core_operator_cycles_puppet[i] = core_operator_cycles_puppet_v2[i];
						temp_stage_finds_puppet += core_operator_finds_puppet[i];
					}

					key_module = 2;

					old_hit_count = new_hit_cnt;
				}
				return ret_val;
			}
		}


#undef FLIP_BIT

}


void pso_updating(void) {

	g_now += 1;
	if (g_now > g_max) g_now = 0;
	w_now = (w_init - w_end)*(g_max - g_now) / (g_max)+w_end;
	int tmp_swarm, i, j;
	u64 temp_operator_finds_puppet = 0;
	for (i = 0; i < operator_num; ++i)
	{
		operator_finds_puppet[i] = core_operator_finds_puppet[i];

		for (j = 0; j < swarm_num; ++j)
		{
			operator_finds_puppet[i] = operator_finds_puppet[i] + stage_finds_puppet[j][i];
		}
		temp_operator_finds_puppet = temp_operator_finds_puppet + operator_finds_puppet[i];
	}

	for (i = 0; i < operator_num; ++i)
	{
		if (operator_finds_puppet[i])
			G_best[i] = (double)((double)(operator_finds_puppet[i]) / (double)(temp_operator_finds_puppet));
	}

	for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm)
	{
		double x_temp = 0.0;
		for (i = 0; i < operator_num; ++i)
		{
			probability_now[tmp_swarm][i] = 0.0;
			v_now[tmp_swarm][i] = w_now * v_now[tmp_swarm][i] + RAND_C * (L_best[tmp_swarm][i] - x_now[tmp_swarm][i]) + RAND_C * (G_best[i] - x_now[tmp_swarm][i]);
			x_now[tmp_swarm][i] += v_now[tmp_swarm][i];
			if (x_now[tmp_swarm][i] > v_max)
				x_now[tmp_swarm][i] = v_max;
			else if (x_now[tmp_swarm][i] < v_min)
				x_now[tmp_swarm][i] = v_min;
			x_temp += x_now[tmp_swarm][i];
		}

		for (i = 0; i < operator_num; ++i)
		{
			x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / x_temp;
			if (likely(i != 0))
				probability_now[tmp_swarm][i] = probability_now[tmp_swarm][i - 1] + x_now[tmp_swarm][i];
			else
				probability_now[tmp_swarm][i] = x_now[tmp_swarm][i];
		}
		if (probability_now[tmp_swarm][operator_num - 1] < 0.99 || probability_now[tmp_swarm][operator_num - 1] > 1.01) FATAL("ERROR probability");
	}
	swarm_now = 0;
	key_module = 0;
}


/* larger change for MOpt implementation: the original fuzz_one was renamed
   to fuzz_one_original. All documentation references to fuzz_one therefore
   mean fuzz_one_original */
static u8 fuzz_one(char** argv) {
	int key_val_lv = 0;
	if (limit_time_sig == 0) {
		key_val_lv = fuzz_one_original(argv);
	} else {
		if (key_module == 0)
			key_val_lv = pilot_fuzzing(argv);
		else if (key_module == 1)
			key_val_lv = core_fuzzing(argv);
		else if (key_module == 2)
			pso_updating();
	}

	return key_val_lv;
}


/* Grab interesting test cases from other fuzzers. */

static void sync_fuzzers(char** argv) {

  DIR* sd;
  struct dirent* sd_ent;
  u32 sync_cnt = 0;

  sd = opendir(sync_dir);
  if (!sd) PFATAL("Unable to open '%s'", sync_dir);

  stage_max = stage_cur = 0;
  cur_depth = 0;

  /* Look at the entries created for every other fuzzer in the sync directory. */

  while ((sd_ent = readdir(sd))) {

    static u8 stage_tmp[128];

    DIR* qd;
    struct dirent* qd_ent;
    u8 *qd_path, *qd_synced_path;
    u32 min_accept = 0, next_min_accept;

    s32 id_fd;

    /* Skip dot files and our own output directory. */

    if (sd_ent->d_name[0] == '.' || !strcmp(sync_id, sd_ent->d_name)) continue;

    /* Skip anything that doesn't have a queue/ subdirectory. */

    qd_path = alloc_printf("%s/%s/queue", sync_dir, sd_ent->d_name);

    if (!(qd = opendir(qd_path))) {
      ck_free(qd_path);
      continue;
    }

    /* Retrieve the ID of the last seen test case. */

    qd_synced_path = alloc_printf("%s/.synced/%s", out_dir, sd_ent->d_name);

    id_fd = open(qd_synced_path, O_RDWR | O_CREAT, 0600);

    if (id_fd < 0) PFATAL("Unable to create '%s'", qd_synced_path);

    if (read(id_fd, &min_accept, sizeof(u32)) > 0) 
      lseek(id_fd, 0, SEEK_SET);

    next_min_accept = min_accept;

    /* Show stats */    

    sprintf(stage_tmp, "sync %u", ++sync_cnt);
    stage_name = stage_tmp;
    stage_cur  = 0;
    stage_max  = 0;

    /* For every file queued by this fuzzer, parse ID and see if we have looked at
       it before; exec a test case if not. */

    while ((qd_ent = readdir(qd))) {

      u8* path;
      s32 fd;
      struct stat st;

      if (qd_ent->d_name[0] == '.' ||
          sscanf(qd_ent->d_name, CASE_PREFIX "%06u", &syncing_case) != 1 || 
          syncing_case < min_accept) continue;

      /* OK, sounds like a new one. Let's give it a try. */

      if (syncing_case >= next_min_accept)
        next_min_accept = syncing_case + 1;

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
        u8* mem = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

        if (mem == MAP_FAILED) PFATAL("Unable to mmap '%s'", path);

        /* See what happens. We rely on save_if_interesting() to catch major
           errors and save the test case. */

        write_to_testcase(mem, st.st_size);

        fault = run_target(argv, exec_tmout);

        if (stop_soon) return;

        syncing_party = sd_ent->d_name;
        queued_imported += save_if_interesting(argv, mem, st.st_size, fault);
        syncing_party = 0;

        munmap(mem, st.st_size);

        if (!(stage_cur++ % stats_update_freq)) show_stats();

      }

      ck_free(path);
      close(fd);

    }

    ck_write(id_fd, &next_min_accept, sizeof(u32), qd_synced_path);

    close(id_fd);
    closedir(qd);
    ck_free(qd_path);
    ck_free(qd_synced_path);
    
  }  

  closedir(sd);

}


/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);

}


/* Handle skip request (SIGUSR1). */

static void handle_skipreq(int sig) {

  skip_requested = 1;

}


/* Do a PATH search and find target binary to see that it exists and
   isn't a shell script - a common and painful mistake. We also check for
   a valid ELF header and for evidence of AFL instrumentation. */

void check_binary(u8* fname) {

  u8* env_path = 0;
  struct stat st;

  s32 fd;
  u8* f_data;
  u32 f_len = 0;

  ACTF("Validating target binary...");

  if (strchr(fname, '/') || !(env_path = getenv("PATH"))) {

    target_path = ck_strdup(fname);
    if (stat(target_path, &st) || !S_ISREG(st.st_mode) ||
        !(st.st_mode & 0111) || (f_len = st.st_size) < 4)
      FATAL("Program '%s' not found or not executable", fname);

  } else {

    while (env_path) {

      u8 *cur_elem, *delim = strchr(env_path, ':');

      if (delim) {

        cur_elem = ck_alloc(delim - env_path + 1);
        memcpy(cur_elem, env_path, delim - env_path);
        ++delim;

      } else cur_elem = ck_strdup(env_path);

      env_path = delim;

      if (cur_elem[0])
        target_path = alloc_printf("%s/%s", cur_elem, fname);
      else
        target_path = ck_strdup(fname);

      ck_free(cur_elem);

      if (!stat(target_path, &st) && S_ISREG(st.st_mode) &&
          (st.st_mode & 0111) && (f_len = st.st_size) >= 4) break;

      ck_free(target_path);
      target_path = 0;

    }

    if (!target_path) FATAL("Program '%s' not found or not executable", fname);

  }

  if (getenv("AFL_SKIP_BIN_CHECK")) return;

  /* Check for blatant user errors. */

  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
     FATAL("Please don't keep binaries in /tmp or /var/tmp");

  fd = open(target_path, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", target_path);

  f_data = mmap(0, f_len, PROT_READ, MAP_PRIVATE, fd, 0);

  if (f_data == MAP_FAILED) PFATAL("Unable to mmap file '%s'", target_path);

  close(fd);

  if (f_data[0] == '#' && f_data[1] == '!') {

    SAYF("\n" cLRD "[-] " cRST
         "Oops, the target binary looks like a shell script. Some build systems will\n"
         "    sometimes generate shell stubs for dynamically linked programs; try static\n"
         "    library mode (./configure --disable-shared) if that's the case.\n\n"

         "    Another possible cause is that you are actually trying to use a shell\n" 
         "    wrapper around the fuzzed component. Invoking shell can slow down the\n" 
         "    fuzzing process by a factor of 20x or more; it's best to write the wrapper\n"
         "    in a compiled language instead.\n");

    FATAL("Program '%s' is a shell script", target_path);

  }

#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else

#if !defined(__arm__) && !defined(__arm64__)
  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);
#endif

#endif /* ^!__APPLE__ */

  if (!qemu_mode && !unicorn_mode && !dumb_mode &&
      !memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "Looks like the target binary is not instrumented! The fuzzer depends on\n"
         "    compile-time instrumentation to isolate interesting test cases while\n"
         "    mutating the input data. For more information, and for tips on how to\n"
         "    instrument binaries, please see %s/README.\n\n"

         "    When source code is not available, you may be able to leverage QEMU\n"
         "    mode support. Consult the README for tips on how to enable this.\n"

         "    (It is also possible to use afl-fuzz as a traditional, \"dumb\" fuzzer.\n"
         "    For that, you can use the -n option - but expect much worse results.)\n",
         doc_path);

    FATAL("No instrumentation detected");

  }

  if ((qemu_mode || unicorn_mode) &&
      memmem(f_data, f_len, SHM_ENV_VAR, strlen(SHM_ENV_VAR) + 1)) {

    SAYF("\n" cLRD "[-] " cRST
         "This program appears to be instrumented with afl-gcc, but is being run in\n"
         "    QEMU or Unicorn mode (-Q or -U). This is probably not what you want -\n"
         "    this setup will be slow and offer no practical benefits.\n");

    FATAL("Instrumentation found in -Q or -U mode");

  }

  if (memmem(f_data, f_len, "libasan.so", 10) ||
      memmem(f_data, f_len, "__msan_init", 11)) uses_asan = 1;

  /* Detect persistent & deferred init signatures in the binary. */

  if (memmem(f_data, f_len, PERSIST_SIG, strlen(PERSIST_SIG) + 1)) {

    OKF(cPIN "Persistent mode binary detected.");
    setenv(PERSIST_ENV_VAR, "1", 1);
    persistent_mode = 1;

  } else if (getenv("AFL_PERSISTENT")) {

    WARNF("AFL_PERSISTENT is no longer supported and may misbehave!");

  }

  if (memmem(f_data, f_len, DEFER_SIG, strlen(DEFER_SIG) + 1)) {

    OKF(cPIN "Deferred forkserver binary detected.");
    setenv(DEFER_ENV_VAR, "1", 1);
    deferred_mode = 1;

  } else if (getenv("AFL_DEFER_FORKSRV")) {

    WARNF("AFL_DEFER_FORKSRV is no longer supported and may misbehave!");

  }

  if (munmap(f_data, f_len)) PFATAL("unmap() failed");

}


/* Trim and possibly create a banner for the run. */

static void fix_up_banner(u8* name) {

  if (!use_banner) {

    if (sync_id) {

      use_banner = sync_id;

    } else {

      u8* trim = strrchr(name, '/');
      if (!trim) use_banner = name; else use_banner = trim + 1;

    }

  }

  if (strlen(use_banner) > 32) {

    u8* tmp = ck_alloc(36);
    sprintf(tmp, "%.32s...", use_banner);
    use_banner = tmp;

  }

}


/* Check if we're on TTY. */

static void check_if_tty(void) {

  struct winsize ws;

  if (getenv("AFL_NO_UI")) {
    OKF("Disabling the UI because AFL_NO_UI is set.");
    not_on_tty = 1;
    return;
  }

  if (ioctl(1, TIOCGWINSZ, &ws)) {

    if (errno == ENOTTY) {
      OKF("Looks like we're not running on a tty, so I'll be a bit less verbose.");
      not_on_tty = 1;
    }

    return;
  }

}


/* Check terminal dimensions after resize. */

static void check_term_size(void) {

  struct winsize ws;

  term_too_small = 0;

  if (ioctl(1, TIOCGWINSZ, &ws)) return;

  if (ws.ws_row == 0 || ws.ws_col == 0) return;
  if (ws.ws_row < 24 || ws.ws_col < 79) term_too_small = 1;

}



/* Display usage hints. */

static void usage(u8* argv0) {

#ifdef USE_PYTHON
#define PHYTON_SUPPORT \
       "Compiled with Python 2.7 module support, see docs/python_mutators.txt\n"
#else
#define PHYTON_SUPPORT ""
#endif

  SAYF("\n%s [ options ] -- /path/to/fuzzed_app [ ... ]\n\n"

       "Required parameters:\n"
       "  -i dir        - input directory with test cases\n"
       "  -o dir        - output directory for fuzzer findings\n\n"

       "Execution control settings:\n"
       "  -p schedule   - power schedules recompute a seed's performance score.\n"
       "                  <explore (default), fast, coe, lin, quad, or exploit>\n"
       "                  see docs/power_schedules.txt\n"
       "  -f file       - location read by the fuzzed program (stdin)\n"
       "  -t msec       - timeout for each run (auto-scaled, 50-%d ms)\n"
       "  -m megs       - memory limit for child process (%d MB)\n"
       "  -Q            - use binary-only instrumentation (QEMU mode)\n"
       "  -U            - use Unicorn-based instrumentation (Unicorn mode)\n\n"
       "  -L minutes    - use MOpt(imize) mode and set the limit time for entering the\n"
       "                  pacemaker mode (minutes of no new paths, 0 = immediately).\n"
       "                  a recommended value is 10-60. see docs/README.MOpt\n\n"
 
       "Fuzzing behavior settings:\n"
       "  -d            - quick & dirty mode (skips deterministic steps)\n"
       "  -n            - fuzz without instrumentation (dumb mode)\n"
       "  -x dir        - optional fuzzer dictionary (see README)\n\n"

       "Testing settings:\n"
       "  -s seed       - use a fixed seed for the RNG\n"
       "  -V seconds    - fuzz for a maximum total time of seconds then terminate\n"
       "  -E execs      - fuzz for a maximum number of total executions then terminate\n\n"

       "Other stuff:\n"
       "  -T text       - text banner to show on the screen\n"
       "  -M / -S id    - distributed mode (see parallel_fuzzing.txt)\n"
       "  -B bitmap.txt - mutate a specific test case, use the out/fuzz_bitmap file\n"
       "  -C            - crash exploration mode (the peruvian rabbit thing)\n"
       "  -e ext        - File extension for the temporarily generated test case\n\n"

       PHYTON_SUPPORT

       "For additional tips, please consult %s/README\n\n",

       argv0, EXEC_TIMEOUT, MEM_LIMIT, doc_path);

  exit(1);
#undef PHYTON_SUPPORT

}


/* Prepare output directories and fds. */

void setup_dirs_fds(void) {

  u8* tmp;
  s32 fd;

  ACTF("Setting up output directories...");

  if (sync_id && mkdir(sync_dir, 0700) && errno != EEXIST)
      PFATAL("Unable to create '%s'", sync_dir);

  if (mkdir(out_dir, 0700)) {

    if (errno != EEXIST) PFATAL("Unable to create '%s'", out_dir);

    maybe_delete_out_dir();

  } else {

    if (in_place_resume)
      FATAL("Resume attempted but old output directory not found");

    out_dir_fd = open(out_dir, O_RDONLY);

#ifndef __sun

    if (out_dir_fd < 0 || flock(out_dir_fd, LOCK_EX | LOCK_NB))
      PFATAL("Unable to flock() output directory.");

#endif /* !__sun */

  }

  /* Queue directory for any starting & discovered paths. */

  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Top-level directory for queue metadata used for session
     resume and related tasks. */

  tmp = alloc_printf("%s/queue/.state/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory for flagging queue entries that went through
     deterministic fuzzing in the past. */

  tmp = alloc_printf("%s/queue/.state/deterministic_done/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Directory with the auto-selected dictionary entries. */

  tmp = alloc_printf("%s/queue/.state/auto_extras/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths currently deemed redundant. */

  tmp = alloc_printf("%s/queue/.state/redundant_edges/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* The set of paths showing variable behavior. */

  tmp = alloc_printf("%s/queue/.state/variable_behavior/", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Sync directory for keeping track of cooperating fuzzers. */

  if (sync_id) {

    tmp = alloc_printf("%s/.synced/", out_dir);

    if (mkdir(tmp, 0700) && (!in_place_resume || errno != EEXIST))
      PFATAL("Unable to create '%s'", tmp);

    ck_free(tmp);

  }

  /* All recorded crashes. */

  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* Generally useful file descriptors. */

  dev_null_fd = open("/dev/null", O_RDWR);
  if (dev_null_fd < 0) PFATAL("Unable to open /dev/null");

#ifndef HAVE_ARC4RANDOM
  dev_urandom_fd = open("/dev/urandom", O_RDONLY);
  if (dev_urandom_fd < 0) PFATAL("Unable to open /dev/urandom");
#endif

  /* Gnuplot output file. */

  tmp = alloc_printf("%s/plot_data", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  plot_file = fdopen(fd, "w");
  if (!plot_file) PFATAL("fdopen() failed");

  fprintf(plot_file, "# unix_time, cycles_done, cur_path, paths_total, "
                     "pending_total, pending_favs, map_size, unique_crashes, "
                     "unique_hangs, max_depth, execs_per_sec\n");
                     /* ignore errors */

}

static void setup_cmdline_file(char** argv) {
  u8* tmp;
  s32 fd;
  u32 i = 0;

  FILE* cmdline_file = NULL;

  /* Store the command line to reproduce our findings */
  tmp = alloc_printf("%s/cmdline", out_dir);
  fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  cmdline_file = fdopen(fd, "w");
  if (!cmdline_file) PFATAL("fdopen() failed");

  while (argv[i]) {
    fprintf(cmdline_file, "%s\n", argv[i]);
    ++i;
  }

  fclose(cmdline_file);
}


/* Setup the output file for fuzzed data, if not using -f. */

void setup_stdio_file(void) {

  u8* fn;
  if (file_extension) {
    fn = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);
  } else {
    fn = alloc_printf("%s/.cur_input", out_dir);
  }

  unlink(fn); /* Ignore errors */

  out_fd = open(fn, O_RDWR | O_CREAT | O_EXCL, 0600);

  if (out_fd < 0) PFATAL("Unable to create '%s'", fn);

  ck_free(fn);

}


/* Make sure that core dumps don't go to a program. */

static void check_crash_handling(void) {

#ifdef __APPLE__

  /* Yuck! There appears to be no simple C API to query for the state of 
     loaded daemons on MacOS X, and I'm a bit hesitant to do something
     more sophisticated, such as disabling crash reporting via Mach ports,
     until I get a box to test the code. So, for now, we check for crash
     reporting the awful way. */
  
  if (system("launchctl list 2>/dev/null | grep -q '\\.ReportCrash$'")) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system is configured to forward crash notifications to an\n"
       "    external crash reporting utility. This will cause issues due to the\n"
       "    extended delay between the fuzzed binary malfunctioning and this fact\n"
       "    being relayed to the fuzzer via the standard waitpid() API.\n\n"
       "    To avoid having crashes misinterpreted as timeouts, please run the\n" 
       "    following commands:\n\n"

       "    SL=/System/Library; PL=com.apple.ReportCrash\n"
       "    launchctl unload -w ${SL}/LaunchAgents/${PL}.plist\n"
       "    sudo launchctl unload -w ${SL}/LaunchDaemons/${PL}.Root.plist\n");

  if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
    FATAL("Crash reporter detected");

#else

  /* This is Linux specific, but I don't think there's anything equivalent on
     *BSD, so we can just let it slide for now. */

  s32 fd = open("/proc/sys/kernel/core_pattern", O_RDONLY);
  u8  fchar;

  if (fd < 0) return;

  ACTF("Checking core_pattern...");

  if (read(fd, &fchar, 1) == 1 && fchar == '|') {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, your system is configured to send core dump notifications to an\n"
         "    external utility. This will cause issues: there will be an extended delay\n"
         "    between stumbling upon a crash and having this information relayed to the\n"
         "    fuzzer via the standard waitpid() API.\n\n"

         "    To avoid having crashes misinterpreted as timeouts, please log in as root\n" 
         "    and temporarily modify /proc/sys/kernel/core_pattern, like so:\n\n"

         "    echo core >/proc/sys/kernel/core_pattern\n");

    if (!getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"))
      FATAL("Pipe at the beginning of 'core_pattern'");

  }
 
  close(fd);

#endif /* ^__APPLE__ */

}


/* Check CPU governor. */

static void check_cpu_governor(void) {
#ifdef __linux__
  FILE* f;
  u8 tmp[128];
  u64 min = 0, max = 0;

  if (getenv("AFL_SKIP_CPUFREQ")) return;

  if (cpu_aff > 0)
    snprintf(tmp, sizeof(tmp), "%s%d%s", "/sys/devices/system/cpu/cpu", cpu_aff, "/cpufreq/scaling_governor");
  else
    snprintf(tmp, sizeof(tmp), "%s", "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor");
  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "r");
  if (!f) {
    if (cpu_aff > 0)
      snprintf(tmp, sizeof(tmp), "%s%d%s", "/sys/devices/system/cpu/cpufreq/policy", cpu_aff, "/scaling_governor");
    else
      snprintf(tmp, sizeof(tmp), "%s", "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor");
    f = fopen(tmp, "r");
  }
  if (!f) {
    WARNF("Could not check CPU scaling governor");
    return;
  }

  ACTF("Checking CPU scaling governor...");

  if (!fgets(tmp, 128, f)) PFATAL("fgets() failed");

  fclose(f);

  if (!strncmp(tmp, "perf", 4)) return;

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &min) != 1) min = 0;
    fclose(f);
  }

  f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "r");

  if (f) {
    if (fscanf(f, "%llu", &max) != 1) max = 0;
    fclose(f);
  }

  if (min == max) return;

  SAYF("\n" cLRD "[-] " cRST
       "Whoops, your system uses on-demand CPU frequency scaling, adjusted\n"
       "    between %llu and %llu MHz. Unfortunately, the scaling algorithm in the\n"
       "    kernel is imperfect and can miss the short-lived processes spawned by\n"
       "    afl-fuzz. To keep things moving, run these commands as root:\n\n"

       "    cd /sys/devices/system/cpu\n"
       "    echo performance | tee cpu*/cpufreq/scaling_governor\n\n"

       "    You can later go back to the original state by replacing 'performance' with\n"
       "    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ\n"
       "    to make afl-fuzz skip this check - but expect some performance drop.\n",
       min / 1024, max / 1024);

  FATAL("Suboptimal CPU scaling governor");
#endif
}


/* Count the number of logical CPU cores. */

static void get_core_count(void) {

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

  size_t s = sizeof(cpu_core_count);

  /* On *BSD systems, we can just use a sysctl to get the number of CPUs. */

#ifdef __APPLE__

  if (sysctlbyname("hw.logicalcpu", &cpu_core_count, &s, NULL, 0) < 0)
    return;

#else

  int s_name[2] = { CTL_HW, HW_NCPU };

  if (sysctl(s_name, 2, &cpu_core_count, &s, NULL, 0) < 0) return;

#endif /* ^__APPLE__ */

#else

#ifdef HAVE_AFFINITY

  cpu_core_count = sysconf(_SC_NPROCESSORS_ONLN);

#else

  FILE* f = fopen("/proc/stat", "r");
  u8 tmp[1024];

  if (!f) return;

  while (fgets(tmp, sizeof(tmp), f))
    if (!strncmp(tmp, "cpu", 3) && isdigit(tmp[3])) ++cpu_core_count;

  fclose(f);

#endif /* ^HAVE_AFFINITY */

#endif /* ^(__APPLE__ || __FreeBSD__ || __OpenBSD__) */

  if (cpu_core_count > 0) {

    u32 cur_runnable = 0;

    cur_runnable = (u32)get_runnable_processes();

#if defined(__APPLE__) || defined(__FreeBSD__) || defined (__OpenBSD__)

    /* Add ourselves, since the 1-minute average doesn't include that yet. */

    ++cur_runnable;

#endif /* __APPLE__ || __FreeBSD__ || __OpenBSD__ */

    OKF("You have %d CPU core%s and %u runnable tasks (utilization: %0.0f%%).",
        cpu_core_count, cpu_core_count > 1 ? "s" : "",
        cur_runnable, cur_runnable * 100.0 / cpu_core_count);

    if (cpu_core_count > 1) {

      if (cur_runnable > cpu_core_count * 1.5) {

        WARNF("System under apparent load, performance may be spotty.");

      } else if (cur_runnable + 1 <= cpu_core_count) {

        OKF("Try parallel jobs - see %s/parallel_fuzzing.txt.", doc_path);
  
      }

    }

  } else {

    cpu_core_count = 0;
    WARNF("Unable to figure out the number of CPU cores.");

  }

}


/* Validate and fix up out_dir and sync_dir when using -S. */

static void fix_up_sync(void) {

  u8* x = sync_id;

  if (dumb_mode)
    FATAL("-S / -M and -n are mutually exclusive");

  if (skip_deterministic) {

    if (force_deterministic)
      FATAL("use -S instead of -M -d");
    //else
    //  FATAL("-S already implies -d");

  }

  while (*x) {

    if (!isalnum(*x) && *x != '_' && *x != '-')
      FATAL("Non-alphanumeric fuzzer ID specified via -S or -M");

    ++x;

  }

  if (strlen(sync_id) > 32) FATAL("Fuzzer ID too long");

  x = alloc_printf("%s/%s", out_dir, sync_id);

  sync_dir = out_dir;
  out_dir  = x;

  if (!force_deterministic) {
    skip_deterministic = 1;
    use_splicing = 1;
  }

}


/* Handle screen resize (SIGWINCH). */

static void handle_resize(int sig) {
  clear_screen = 1;
}


/* Check ASAN options. */

static void check_asan_opts(void) {
  u8* x = getenv("ASAN_OPTIONS");

  if (x) {

    if (!strstr(x, "abort_on_error=1"))
      FATAL("Custom ASAN_OPTIONS set without abort_on_error=1 - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom ASAN_OPTIONS set without symbolize=0 - please fix!");

  }

  x = getenv("MSAN_OPTIONS");

  if (x) {

    if (!strstr(x, "exit_code=" STRINGIFY(MSAN_ERROR)))
      FATAL("Custom MSAN_OPTIONS set without exit_code="
            STRINGIFY(MSAN_ERROR) " - please fix!");

    if (!strstr(x, "symbolize=0"))
      FATAL("Custom MSAN_OPTIONS set without symbolize=0 - please fix!");

  }

} 


/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Exec timeout notifications. */

  sa.sa_handler = handle_timeout;
  sigaction(SIGALRM, &sa, NULL);

  /* Window resize */

  sa.sa_handler = handle_resize;
  sigaction(SIGWINCH, &sa, NULL);

  /* SIGUSR1: skip entry */

  sa.sa_handler = handle_skipreq;
  sigaction(SIGUSR1, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}


/* Rewrite argv for QEMU. */

static char** get_qemu_argv(u8* own_loc, char** argv, int argc) {

  char** new_argv = ck_alloc(sizeof(char*) * (argc + 4));
  u8 *tmp, *cp, *rsl, *own_copy;

  memcpy(new_argv + 3, argv + 1, sizeof(char*) * argc);

  new_argv[2] = target_path;
  new_argv[1] = "--";

  /* Now we need to actually find the QEMU binary to put in argv[0]. */

  tmp = getenv("AFL_PATH");

  if (tmp) {

    cp = alloc_printf("%s/afl-qemu-trace", tmp);

    if (access(cp, X_OK))
      FATAL("Unable to find '%s'", tmp);

    target_path = new_argv[0] = cp;
    return new_argv;

  }

  own_copy = ck_strdup(own_loc);
  rsl = strrchr(own_copy, '/');

  if (rsl) {

    *rsl = 0;

    cp = alloc_printf("%s/afl-qemu-trace", own_copy);
    ck_free(own_copy);

    if (!access(cp, X_OK)) {

      target_path = new_argv[0] = cp;
      return new_argv;

    }

  } else ck_free(own_copy);

  if (!access(BIN_PATH "/afl-qemu-trace", X_OK)) {

    target_path = new_argv[0] = ck_strdup(BIN_PATH "/afl-qemu-trace");
    return new_argv;

  }

  SAYF("\n" cLRD "[-] " cRST
       "Oops, unable to find the 'afl-qemu-trace' binary. The binary must be built\n"
       "    separately by following the instructions in qemu_mode/README.qemu. If you\n"
       "    already have the binary installed, you may need to specify AFL_PATH in the\n"
       "    environment.\n\n"

       "    Of course, even without QEMU, afl-fuzz can still work with binaries that are\n"
       "    instrumented at compile time with afl-gcc. It is also possible to use it as a\n"
       "    traditional \"dumb\" fuzzer by specifying '-n' in the command line.\n");

  FATAL("Failed to locate 'afl-qemu-trace'.");

}

/* Make a copy of the current command line. */

static void save_cmdline(u32 argc, char** argv) {

  u32 len = 1, i;
  u8* buf;

  for (i = 0; i < argc; ++i)
    len += strlen(argv[i]) + 1;
  
  buf = orig_cmdline = ck_alloc(len);

  for (i = 0; i < argc; ++i) {

    u32 l = strlen(argv[i]);

    memcpy(buf, argv[i], l);
    buf += l;

    if (i != argc - 1) *(buf++) = ' ';

  }

  *buf = 0;

}

int stricmp(char const *a, char const *b) {
  for (;; ++a, ++b) {
    int d;
    d = tolower(*a) - tolower(*b);
    if (d != 0 || !*a)
      return d;
  }
}

#ifndef AFL_LIB

/* Main entry point */

int main(int argc, char** argv) {

  s32 opt;
  u64 prev_queued = 0;
  u32 sync_interval_cnt = 0, seek_to;
  u8  *extras_dir = 0;
  u8  mem_limit_given = 0;
  u8  exit_1 = !!getenv("AFL_BENCH_JUST_ONE");
  char** use_argv;
  s64 init_seed;

  struct timeval tv;
  struct timezone tz;

  SAYF(cCYA "afl-fuzz" VERSION cRST " based on afl by <lcamtuf@google.com> and a big online community\n");

  doc_path = access(DOC_PATH, F_OK) ? "docs" : DOC_PATH;

  gettimeofday(&tv, &tz);
  init_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();

  while ((opt = getopt(argc, argv, "+i:o:f:m:t:T:dnCB:S:M:x:QUe:p:s:V:E:L:")) > 0)

    switch (opt) {

      case 's': {
        init_seed = strtoul(optarg, 0L, 10);
        fixed_seed = 1;
        break;
      }

      case 'p': /* Power schedule */

        if (!stricmp(optarg, "fast")) {
          schedule = FAST;
        } else if (!stricmp(optarg, "coe")) {
          schedule = COE;
        } else if (!stricmp(optarg, "exploit")) {
          schedule = EXPLOIT;
        } else if (!stricmp(optarg, "lin")) {
          schedule = LIN;
        } else if (!stricmp(optarg, "quad")) {
          schedule = QUAD;
        } else if (!stricmp(optarg, "explore") || !stricmp(optarg, "default") || !stricmp(optarg, "normal") || !stricmp(optarg, "afl")) {
          schedule = EXPLORE;
        } else {
          FATAL("Unknown -p power schedule");
        }
        break;

      case 'e':

        if (file_extension) FATAL("Multiple -e options not supported");

        file_extension = optarg;

        break;

      case 'i': /* input dir */

        if (in_dir) FATAL("Multiple -i options not supported");
        in_dir = optarg;

        if (!strcmp(in_dir, "-")) in_place_resume = 1;

        break;

      case 'o': /* output dir */

        if (out_dir) FATAL("Multiple -o options not supported");
        out_dir = optarg;
        break;

      case 'M': { /* master sync ID */

          u8* c;

          if (sync_id) FATAL("Multiple -S or -M options not supported");
          sync_id = ck_strdup(optarg);

          if ((c = strchr(sync_id, ':'))) {

            *c = 0;

            if (sscanf(c + 1, "%u/%u", &master_id, &master_max) != 2 ||
                !master_id || !master_max || master_id > master_max ||
                master_max > 1000000) FATAL("Bogus master ID passed to -M");

          }

          force_deterministic = 1;

        }

        break;

      case 'S': 

        if (sync_id) FATAL("Multiple -S or -M options not supported");
        sync_id = ck_strdup(optarg);
        break;

      case 'f': /* target file */

        if (out_file) FATAL("Multiple -f options not supported");
        out_file = optarg;
        break;

      case 'x': /* dictionary */

        if (extras_dir) FATAL("Multiple -x options not supported");
        extras_dir = optarg;
        break;

      case 't': { /* timeout */

          u8 suffix = 0;

          if (timeout_given) FATAL("Multiple -t options not supported");

          if (sscanf(optarg, "%u%c", &exec_tmout, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -t");

          if (exec_tmout < 5) FATAL("Dangerously low value of -t");

          if (suffix == '+') timeout_given = 2; else timeout_given = 1;

          break;

      }

      case 'm': { /* mem limit */

          u8 suffix = 'M';

          if (mem_limit_given) FATAL("Multiple -m options not supported");
          mem_limit_given = 1;

          if (!strcmp(optarg, "none")) {

            mem_limit = 0;
            break;

          }

          if (sscanf(optarg, "%llu%c", &mem_limit, &suffix) < 1 ||
              optarg[0] == '-') FATAL("Bad syntax used for -m");

          switch (suffix) {

            case 'T': mem_limit *= 1024 * 1024; break;
            case 'G': mem_limit *= 1024; break;
            case 'k': mem_limit /= 1024; break;
            case 'M': break;

            default:  FATAL("Unsupported suffix or bad syntax for -m");

          }

          if (mem_limit < 5) FATAL("Dangerously low value of -m");

          if (sizeof(rlim_t) == 4 && mem_limit > 2000)
            FATAL("Value of -m out of range on 32-bit systems");

        }

        break;

      case 'd': /* skip deterministic */

        if (skip_deterministic) FATAL("Multiple -d options not supported");
        skip_deterministic = 1;
        use_splicing = 1;
        break;

      case 'B': /* load bitmap */

        /* This is a secret undocumented option! It is useful if you find
           an interesting test case during a normal fuzzing process, and want
           to mutate it without rediscovering any of the test cases already
           found during an earlier run.

           To use this mode, you need to point -B to the fuzz_bitmap produced
           by an earlier run for the exact same binary... and that's it.

           I only used this once or twice to get variants of a particular
           file, so I'm not making this an official setting. */

        if (in_bitmap) FATAL("Multiple -B options not supported");

        in_bitmap = optarg;
        read_bitmap(in_bitmap);
        break;

      case 'C': /* crash mode */

        if (crash_mode) FATAL("Multiple -C options not supported");
        crash_mode = FAULT_CRASH;
        break;

      case 'n': /* dumb mode */

        if (dumb_mode) FATAL("Multiple -n options not supported");
        if (getenv("AFL_DUMB_FORKSRV")) dumb_mode = 2; else dumb_mode = 1;

        break;

      case 'T': /* banner */

        if (use_banner) FATAL("Multiple -T options not supported");
        use_banner = optarg;
        break;

      case 'Q': /* QEMU mode */

        if (qemu_mode) FATAL("Multiple -Q options not supported");
        qemu_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_QEMU;

        break;

      case 'U': /* Unicorn mode */

        if (unicorn_mode) FATAL("Multiple -U options not supported");
        unicorn_mode = 1;

        if (!mem_limit_given) mem_limit = MEM_LIMIT_UNICORN;

        break;

      case 'V': {
           most_time_key = 1;
           if (sscanf(optarg, "%llu", &most_time) < 1 || optarg[0] == '-')
             FATAL("Bad syntax used for -V");
        }
        break;

      case 'E': {
           most_execs_key = 1;
           if (sscanf(optarg, "%llu", &most_execs) < 1 || optarg[0] == '-')
             FATAL("Bad syntax used for -E");
        }
        break;

      case 'L': { /* MOpt mode */

              if (limit_time_sig)  FATAL("Multiple -L options not supported");
              limit_time_sig = 1;
              havoc_max_mult = HAVOC_MAX_MULT_MOPT;

			if (sscanf(optarg, "%llu", &limit_time_puppet) < 1 ||
				optarg[0] == '-') FATAL("Bad syntax used for -L");

			u64 limit_time_puppet2 = limit_time_puppet * 60 * 1000;

			if (limit_time_puppet2 < limit_time_puppet ) FATAL("limit_time overflow");
				limit_time_puppet = limit_time_puppet2;

			SAYF("limit_time_puppet %llu\n",limit_time_puppet);
			swarm_now = 0;

			if (limit_time_puppet == 0 )
			    key_puppet = 1;

			int i;
			int tmp_swarm = 0;

			if (g_now > g_max) g_now = 0;
			w_now = (w_init - w_end)*(g_max - g_now) / (g_max)+w_end;

			for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm) {
				double total_puppet_temp = 0.0;
				swarm_fitness[tmp_swarm] = 0.0;

				for (i = 0; i < operator_num; ++i) {
					stage_finds_puppet[tmp_swarm][i] = 0;
					probability_now[tmp_swarm][i] = 0.0;
					x_now[tmp_swarm][i] = ((double)(random() % 7000)*0.0001 + 0.1);
					total_puppet_temp += x_now[tmp_swarm][i];
					v_now[tmp_swarm][i] = 0.1;
					L_best[tmp_swarm][i] = 0.5;
					G_best[i] = 0.5;
					eff_best[tmp_swarm][i] = 0.0;

				}

				for (i = 0; i < operator_num; ++i) {
					stage_cycles_puppet_v2[tmp_swarm][i] = stage_cycles_puppet[tmp_swarm][i];
					stage_finds_puppet_v2[tmp_swarm][i] = stage_finds_puppet[tmp_swarm][i];
					x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / total_puppet_temp;
				}

				double x_temp = 0.0;

				for (i = 0; i < operator_num; ++i) {
					probability_now[tmp_swarm][i] = 0.0;
					v_now[tmp_swarm][i] = w_now * v_now[tmp_swarm][i] + RAND_C * (L_best[tmp_swarm][i] - x_now[tmp_swarm][i]) + RAND_C * (G_best[i] - x_now[tmp_swarm][i]);

					x_now[tmp_swarm][i] += v_now[tmp_swarm][i];

					if (x_now[tmp_swarm][i] > v_max)
						x_now[tmp_swarm][i] = v_max;
					else if (x_now[tmp_swarm][i] < v_min)
						x_now[tmp_swarm][i] = v_min;

					x_temp += x_now[tmp_swarm][i];
				}

				for (i = 0; i < operator_num; ++i) {
					x_now[tmp_swarm][i] = x_now[tmp_swarm][i] / x_temp;
					if (likely(i != 0))
						probability_now[tmp_swarm][i] = probability_now[tmp_swarm][i - 1] + x_now[tmp_swarm][i];
					else
						probability_now[tmp_swarm][i] = x_now[tmp_swarm][i];
				}
				if (probability_now[tmp_swarm][operator_num - 1] < 0.99 || probability_now[tmp_swarm][operator_num - 1] > 1.01)
                                    FATAL("ERROR probability");
			}

			for (i = 0; i < operator_num; ++i) {
				core_operator_finds_puppet[i] = 0;
				core_operator_finds_puppet_v2[i] = 0;
				core_operator_cycles_puppet[i] = 0;
				core_operator_cycles_puppet_v2[i] = 0;
				core_operator_cycles_puppet_v3[i] = 0;
			}

        }
        break;

      default:

        usage(argv[0]);

    }

  if (optind == argc || !in_dir || !out_dir) usage(argv[0]);

  if (fixed_seed)
    OKF("Running with fixed seed: %u", (u32)init_seed);
  srandom((u32)init_seed);
  setup_signal_handlers();
  check_asan_opts();

  power_name = power_names[schedule];

  if (sync_id) fix_up_sync();

  if (!strcmp(in_dir, out_dir))
    FATAL("Input and output directories can't be the same");

  if ((tmp_dir = getenv("AFL_TMPDIR")) != NULL) {
    char tmpfile[strlen(tmp_dir + 16)];
    sprintf(tmpfile, "%s/%s", tmp_dir, ".cur_input");
    if (access(tmpfile, F_OK) != -1) // there is still a race condition here, but well ...
      FATAL("TMP_DIR already has an existing temporary input file: %s", tmpfile);
  } else
    tmp_dir = out_dir;

  if (dumb_mode) {

    if (crash_mode) FATAL("-C and -n are mutually exclusive");
    if (qemu_mode)  FATAL("-Q and -n are mutually exclusive");
    if (unicorn_mode) FATAL("-U and -n are mutually exclusive");

  }
  
  if (strchr(argv[optind], '/') == NULL) WARNF(cLRD "Target binary called without a prefixed path, make sure you are fuzzing the right binary: " cRST "%s", argv[optind]);

  OKF("afl++ is maintained by Marc \"van Hauser\" Heuse, Heiko \"hexcoder\" Eissfeldt and Andrea Fioraldi");
  OKF("afl++ is open source, get it at https://github.com/vanhauser-thc/AFLplusplus");
  OKF("Power schedules from github.com/mboehme/aflfast");
  OKF("Python Mutator and llvm_mode whitelisting from github.com/choller/afl");
  OKF("afl-tmin fork server patch from github.com/nccgroup/TriforceAFL");
  OKF("MOpt Mutator from github.com/puppet-meteor/MOpt-AFL");
  ACTF("Getting to work...");

  switch (schedule) {
    case FAST:    OKF ("Using exponential power schedule (FAST)"); break;
    case COE:     OKF ("Using cut-off exponential power schedule (COE)"); break;
    case EXPLOIT: OKF ("Using exploitation-based constant power schedule (EXPLOIT)"); break;
    case LIN:     OKF ("Using linear power schedule (LIN)"); break;
    case QUAD:    OKF ("Using quadratic power schedule (QUAD)"); break;
    case EXPLORE: OKF ("Using exploration-based constant power schedule (EXPLORE)"); break;
    default : FATAL ("Unknown power schedule"); break;
  }

  if (getenv("AFL_NO_FORKSRV"))    no_forkserver    = 1;
  if (getenv("AFL_NO_CPU_RED"))    no_cpu_meter_red = 1;
  if (getenv("AFL_NO_ARITH"))      no_arith         = 1;
  if (getenv("AFL_SHUFFLE_QUEUE")) shuffle_queue    = 1;
  if (getenv("AFL_FAST_CAL"))      fast_cal         = 1;

  if (getenv("AFL_HANG_TMOUT")) {
    hang_tmout = atoi(getenv("AFL_HANG_TMOUT"));
    if (!hang_tmout) FATAL("Invalid value of AFL_HANG_TMOUT");
  }

  if (dumb_mode == 2 && no_forkserver)
    FATAL("AFL_DUMB_FORKSRV and AFL_NO_FORKSRV are mutually exclusive");

  if (getenv("AFL_PRELOAD")) {
    setenv("LD_PRELOAD", getenv("AFL_PRELOAD"), 1);
    setenv("DYLD_INSERT_LIBRARIES", getenv("AFL_PRELOAD"), 1);
  }

  if (getenv("AFL_LD_PRELOAD"))
    FATAL("Use AFL_PRELOAD instead of AFL_LD_PRELOAD");

  save_cmdline(argc, argv);

  fix_up_banner(argv[optind]);

  check_if_tty();

  if (getenv("AFL_CAL_FAST")) {
    /* Use less calibration cycles, for slow applications */
    cal_cycles = 3;
    cal_cycles_long = 5;
  }

  if (getenv("AFL_DEBUG"))
    debug = 1;

  if (getenv("AFL_PYTHON_ONLY")) {
    /* This ensures we don't proceed to havoc/splice */
    python_only = 1;

    /* Ensure we also skip all deterministic steps */
    skip_deterministic = 1;
  }

  get_core_count();

#ifdef HAVE_AFFINITY
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  check_crash_handling();
  check_cpu_governor();

  setup_post();
  setup_custom_mutator();
  setup_shm(dumb_mode);

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);
  memset(virgin_tmout, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  init_count_class16();

  setup_dirs_fds();

#ifdef USE_PYTHON
  if (init_py())
    FATAL("Failed to initialize Python module");
#else
  if (getenv("AFL_PYTHON_MODULE"))
     FATAL("Your AFL binary was built without Python support");
#endif

  setup_cmdline_file(argv + optind);

  read_testcases();
  load_auto();

  pivot_inputs();

  if (extras_dir) load_extras(extras_dir);

  if (!timeout_given) find_timeout();

  /* If we don't have a file name chosen yet, use a safe default. */

  if (!out_file) {
    u32 i = optind + 1;
    while (argv[i]) {

      u8* aa_loc = strstr(argv[i], "@@");

      if (aa_loc && !out_file) {
        if (file_extension) {
          out_file = alloc_printf("%s/.cur_input.%s", out_dir, file_extension);
        } else {
          out_file = alloc_printf("%s/.cur_input", out_dir);
        }
        detect_file_args(argv + optind + 1, out_file);
	break;
      }

      ++i;

    }
  }

  if (!out_file) setup_stdio_file();

  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode)
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;

  perform_dry_run(use_argv);

  cull_queue();

  show_init_stats();

  seek_to = find_start_position();

  write_stats_file(0, 0, 0);
  save_auto();

  if (stop_soon) goto stop_fuzzing;

  /* Woop woop woop */

  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }

  // real start time, we reset, so this works correctly with -V
  start_time = get_cur_time();

  while (1) {

    u8 skipped_fuzz;

    cull_queue();

    if (!queue_cur) {

      ++queue_cycle;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;

      while (seek_to) {
        ++current_entry;
        --seek_to;
        queue_cur = queue_cur->next;
      }

      show_stats();

      if (not_on_tty) {
        ACTF("Entering queue cycle %llu.", queue_cycle);
        fflush(stdout);
      }

      /* If we had a full queue cycle with no new finds, try
         recombination strategies next. */

      if (queued_paths == prev_queued) {

        if (use_splicing) ++cycles_wo_finds; else use_splicing = 1;

      } else cycles_wo_finds = 0;

      prev_queued = queued_paths;

      if (sync_id && queue_cycle == 1 && getenv("AFL_IMPORT_FIRST"))
        sync_fuzzers(use_argv);

    }

    skipped_fuzz = fuzz_one(use_argv);

    if (!stop_soon && sync_id && !skipped_fuzz) {
      
      if (!(sync_interval_cnt++ % SYNC_INTERVAL))
        sync_fuzzers(use_argv);

    }

    if (!stop_soon && exit_1) stop_soon = 2;

    if (stop_soon) break;

    queue_cur = queue_cur->next;
    ++current_entry;

    if (most_time_key == 1) {
      u64 cur_ms_lv = get_cur_time();
      if (most_time * 1000 < cur_ms_lv  - start_time) {
        most_time_key = 2;
        break;
      }
    }
    if (most_execs_key == 1) {
      if (most_execs <= total_execs) {
        most_execs_key = 2;
        break;
      }
    }
  }

  if (queue_cur) show_stats();

  write_bitmap();
  write_stats_file(0, 0, 0);
  save_auto();

stop_fuzzing:

  SAYF(CURSOR_SHOW cLRD "\n\n+++ Testing aborted %s +++\n" cRST,
       stop_soon == 2 ? "programmatically" : "by user");

  if (most_time_key == 2)
    SAYF(cYEL "[!] " cRST "Time limit was reached\n");
  if (most_execs_key == 2)
    SAYF(cYEL "[!] " cRST "Execution limit was reached\n");

  /* Running for more than 30 minutes but still doing first cycle? */

  if (queue_cycle == 1 && get_cur_time() - start_time > 30 * 60 * 1000) {

    SAYF("\n" cYEL "[!] " cRST
           "Stopped during the first cycle, results may be incomplete.\n"
           "    (For info on resuming, see %s/README)\n", doc_path);

  }

  fclose(plot_file);
  destroy_queue();
  destroy_extras();
  ck_free(target_path);
  ck_free(sync_id);

  alloc_report();

#ifdef USE_PYTHON
  finalize_py();
#endif

  OKF("We're done here. Have a nice day!\n");

  exit(0);

}

#endif /* !AFL_LIB */
