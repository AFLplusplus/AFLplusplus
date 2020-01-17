#include "afl-fuzz.h"
#include "cmplog.h"

#define SWAP64(_x)                                                             \
  ({                                                                           \
                                                                               \
    u64 _ret = (_x);                                                           \
    _ret =                                                                     \
        (_ret & 0x00000000FFFFFFFF) << 32 | (_ret & 0xFFFFFFFF00000000) >> 32; \
    _ret =                                                                     \
        (_ret & 0x0000FFFF0000FFFF) << 16 | (_ret & 0xFFFF0000FFFF0000) >> 16; \
    _ret =                                                                     \
        (_ret & 0x00FF00FF00FF00FF) << 8 | (_ret & 0xFF00FF00FF00FF00) >> 8;   \
    _ret;                                                                      \
                                                                               \
  })

u8 common_fuzz_cmplog_stuff(char** argv, u8* out_buf, u32 len);

extern struct cmp_map* cmp_map;  // defined in afl-sharedmem.c

u8*    cmplog_binary;
char** its_argv;

///// Colorization

struct range {

  u32           start;
  u32           end;
  struct range* next;

};

struct range* add_range(struct range* ranges, u32 start, u32 end) {

  struct range* r = ck_alloc_nozero(sizeof(struct range));
  r->start = start;
  r->end = end;
  r->next = ranges;
  return r;

}

struct range* pop_biggest_range(struct range** ranges) {

  struct range* r = *ranges;
  struct range* prev = NULL;
  struct range* rmax = NULL;
  struct range* prev_rmax = NULL;
  u32           max_size = 0;

  while (r) {

    u32 s = r->end - r->start;
    if (s >= max_size) {

      max_size = s;
      prev_rmax = prev;
      rmax = r;

    }

    prev = r;
    r = r->next;

  }

  if (rmax) {

    if (prev_rmax)
      prev_rmax->next = rmax->next;
    else
      *ranges = rmax->next;

  }

  return rmax;

}

u8 get_exec_checksum(u8* buf, u32 len, u32* cksum) {

  if (unlikely(common_fuzz_stuff(its_argv, buf, len))) return 1;

  *cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  return 0;

}

static void rand_replace(u8* buf, u32 len) {

  u32 i;
  for (i = 0; i < len; ++i)
    buf[i] = UR(256);

}

u8 colorization(u8* buf, u32 len, u32 exec_cksum) {

  struct range* ranges = add_range(NULL, 0, len);
  u8*           backup = ck_alloc_nozero(len);

  u64 orig_hit_cnt, new_hit_cnt;
  orig_hit_cnt = queued_paths + unique_crashes;

  stage_name = "colorization";
  stage_short = "colorization";
  stage_max = 1000;

  struct range* rng;
  stage_cur = stage_max;
  while ((rng = pop_biggest_range(&ranges)) != NULL && stage_cur) {

    u32 s = rng->end - rng->start;
    memcpy(backup, buf + rng->start, s);
    rand_replace(buf + rng->start, s);

    u32 cksum;
    if (unlikely(get_exec_checksum(buf, len, &cksum))) return 1;

    if (cksum != exec_cksum) {

      ranges = add_range(ranges, rng->start, rng->start + s / 2);
      ranges = add_range(ranges, rng->start + s / 2 + 1, rng->end);
      memcpy(buf + rng->start, backup, s);

    }

    ck_free(rng);
    --stage_cur;

  }

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_COLORIZATION] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_COLORIZATION] += stage_max - stage_cur;

  while (ranges) {

    rng = ranges;
    ranges = ranges->next;
    ck_free(rng);

  }

  return 0;

}

///// Input to State replacement

u8 its_fuzz(u32 idx, u32 size, u8* buf, u32 len, u8* status) {

  u64 orig_hit_cnt, new_hit_cnt;

  orig_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(common_fuzz_stuff(its_argv, buf, len))) return 1;

  new_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt)) {

    *status = 1;

  } else {

    if (size >= MIN_AUTO_EXTRA && size <= MAX_AUTO_EXTRA)
      maybe_add_auto(&buf[idx], size);
    *status = 2;

  }

  return 0;

}

u8 cmp_extend_encoding(struct cmp_header* h, u64 pattern, u64 repl, u32 idx,
                       u8* orig_buf, u8* buf, u32 len, u8 do_reverse,
                       u8* status) {

  u64* buf_64 = (u64*)&buf[idx];
  u32* buf_32 = (u32*)&buf[idx];
  u16* buf_16 = (u16*)&buf[idx];
  // u8*  buf_8  = &buf[idx];
  u64* o_buf_64 = (u64*)&orig_buf[idx];
  u32* o_buf_32 = (u32*)&orig_buf[idx];
  u16* o_buf_16 = (u16*)&orig_buf[idx];
  // u8*  o_buf_8  = &orig_buf[idx];

  u32 its_len = len - idx;
  *status = 0;

  if (SHAPE_BYTES(h->shape) == 8) {

    if (its_len >= 8 && *buf_64 == pattern && *o_buf_64 == pattern) {

      *buf_64 = repl;
      if (unlikely(its_fuzz(idx, 8, buf, len, status))) return 1;
      *buf_64 = pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(h, SWAP64(pattern), SWAP64(repl), idx,
                                       orig_buf, buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) == 4 || *status == 2) {

    if (its_len >= 4 && *buf_32 == (u32)pattern && *o_buf_32 == (u32)pattern) {

      *buf_32 = (u32)repl;
      if (unlikely(its_fuzz(idx, 4, buf, len, status))) return 1;
      *buf_32 = pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(h, SWAP32(pattern), SWAP32(repl), idx,
                                       orig_buf, buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) == 2 || *status == 2) {

    if (its_len >= 2 && *buf_16 == (u16)pattern && *o_buf_16 == (u16)pattern) {

      *buf_16 = (u16)repl;
      if (unlikely(its_fuzz(idx, 2, buf, len, status))) return 1;
      *buf_16 = (u16)pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(h, SWAP16(pattern), SWAP16(repl), idx,
                                       orig_buf, buf, len, 0, status)))
        return 1;

  }

  /*if (SHAPE_BYTES(h->shape) == 1 || *status == 2) {

    if (its_len >= 2 && *buf_8 == (u8)pattern && *o_buf_8 == (u8)pattern) {

      *buf_8 = (u8)repl;
      if (unlikely(its_fuzz(idx, 1, buf, len, status)))
        return 1;
      *buf_16 = (u16)pattern;

    }

  }*/

  return 0;

}

u8 cmp_fuzz(u32 key, u8* orig_buf, u8* buf, u32 len) {

  struct cmp_header* h = &cmp_map->headers[key];
  u32                i, j, idx;

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_H) loggeds = CMP_MAP_H;

  u8 status;
  // opt not in the paper
  u32 fails = 0;

  for (i = 0; i < loggeds; ++i) {

    struct cmp_operands* o = &cmp_map->log[key][i];

    // opt not in the paper
    for (j = 0; j < i; ++j)
      if (cmp_map->log[key][j].v0 == o->v0 && cmp_map->log[key][i].v1 == o->v1)
        goto cmp_fuzz_next_iter;

    for (idx = 0; idx < len && fails < 8; ++idx) {

      if (unlikely(cmp_extend_encoding(h, o->v0, o->v1, idx, orig_buf, buf, len,
                                       1, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

      if (unlikely(cmp_extend_encoding(h, o->v1, o->v0, idx, orig_buf, buf, len,
                                       1, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

    }

  cmp_fuzz_next_iter:
    stage_cur++;

  }

  return 0;

}

///// Input to State stage

// queue_cur->exec_cksum
u8 input_to_state_stage(char** argv, u8* orig_buf, u8* buf, u32 len,
                        u32 exec_cksum) {

  its_argv = argv;

  if (unlikely(colorization(buf, len, exec_cksum))) return 1;

  // do it manually, forkserver clear only trace_bits
  memset(cmp_map->headers, 0, sizeof(cmp_map->headers));

  if (unlikely(common_fuzz_cmplog_stuff(argv, buf, len))) return 1;

  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs = total_execs;
  orig_hit_cnt = queued_paths + unique_crashes;

  stage_name = "input-to-state";
  stage_short = "its";
  stage_max = 0;
  stage_cur = 0;

  u32 k;
  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!cmp_map->headers[k].hits) continue;
    if (cmp_map->headers[k].hits > CMP_MAP_H)
      stage_max += CMP_MAP_H;
    else
      stage_max += cmp_map->headers[k].hits;

  }

  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!cmp_map->headers[k].hits) continue;
    cmp_fuzz(k, orig_buf, buf, len);

  }

  memcpy(buf, orig_buf, len);

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ITS] += total_execs - orig_execs;

  return 0;

}

//// CmpLog forkserver

s32 cmplog_forksrv_pid, cmplog_child_pid, cmplog_fsrv_ctl_fd, cmplog_fsrv_st_fd;

void init_cmplog_forkserver(char** argv) {

  static struct itimerval it;
  int                     st_pipe[2], ctl_pipe[2];
  int                     status;
  s32                     rlen;

  ACTF("Spinning up the cmplog fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  child_timed_out = 0;
  cmplog_forksrv_pid = fork();

  if (cmplog_forksrv_pid < 0) PFATAL("fork() failed");

  if (!cmplog_forksrv_pid) {

    /* CHILD PROCESS */

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r);                        /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS
      setrlimit(RLIMIT_AS, &r);                            /* Ignore errors */
#else
      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r);                          /* Ignore errors */
#endif                                                        /* ^RLIMIT_AS */

    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    //    r.rlim_max = r.rlim_cur = 0;
    //    setrlimit(RLIMIT_CORE, &r);                      /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    if (!getenv("AFL_DEBUG_CHILD_OUTPUT")) {

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

    }

    if (!use_stdin) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(out_dir_fd);
    close(dev_null_fd);
#ifndef HAVE_ARC4RANDOM
    close(dev_urandom_fd);
#endif
    close(plot_file == NULL ? -1 : fileno(plot_file));

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS",
           "abort_on_error=1:"
           "detect_leaks=0:"
           "malloc_context_size=0:"
           "symbolize=0:"
           "allocator_may_return_null=1",
           0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS",
           "exit_code=" STRINGIFY(MSAN_ERROR) ":"
           "symbolize=0:"
           "abort_on_error=1:"
           "malloc_context_size=0:"
           "allocator_may_return_null=1:"
           "msan_track_origins=0",
           0);

    setenv("__AFL_CMPLOG_MODE__", "1", 1);

    argv[0] = cmplog_binary;
    execv(cmplog_binary, argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32*)trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* PARENT PROCESS */

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  cmplog_fsrv_ctl_fd = ctl_pipe[1];
  cmplog_fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  if (exec_tmout) {

    it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
    it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  }

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(cmplog_fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {

    OKF("All right - fork server is up.");
    return;

  }

  if (child_timed_out)
    FATAL(
        "Timeout while initializing cmplog fork server (adjusting -t may "
        "help)");

  if (waitpid(cmplog_forksrv_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you "
           "have a\n"
           "    restrictive memory limit configured, this is expected; please "
           "read\n"
           "    %s/notes_for_asan.txt for help.\n",
           doc_path);

    } else if (!mem_limit) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The binary is just buggy and explodes entirely on its own. "
           "If so, you\n"
           "      need to fix the underlying problem or find a better "
           "replacement.\n\n"

           MSG_FORK_ON_APPLE

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke <afl-users@googlegroups.com> for troubleshooting "
           "tips.\n");

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing "
           "the\n"
           "      target to hit an OOM condition in the dynamic linker. Try "
           "bumping up\n"
           "      the limit with the -m setting in the command line. A simple "
           "way confirm\n"
           "      this diagnosis would be:\n\n"

           MSG_ULIMIT_USAGE
           " /path/to/fuzzed_app )\n\n"

           "      Tip: you can use http://jwilk.net/software/recidivm to "
           "quickly\n"
           "      estimate the required amount of virtual memory for the "
           "binary.\n\n"

           "    - The binary is just buggy and explodes entirely on its own. "
           "If so, you\n"
           "      need to fix the underlying problem or find a better "
           "replacement.\n\n"

           MSG_FORK_ON_APPLE

           "    - Less likely, there is a horrible bug in the fuzzer. If other "
           "options\n"
           "      fail, poke <afl-users@googlegroups.com> for troubleshooting "
           "tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);

    }

    FATAL("Cmplog fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32*)trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated "
         "before we could complete a\n"
         "    handshake with the injected code. Since it seems to be built "
         "with ASAN and\n"
         "    you have a restrictive memory limit configured, this is "
         "expected; please\n"
         "    read %s/notes_for_asan.txt for help.\n",
         doc_path);

  } else if (!mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated "
         "before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible "
         "bug in the\n"
         "    fuzzer. Poke <afl-users@googlegroups.com> for troubleshooting "
         "tips.\n");

  } else {

    SAYF(
        "\n" cLRD "[-] " cRST
        "Hmm, looks like the target binary terminated "
        "before we could complete a\n"
        "    handshake with the injected code. There are %s probable "
        "explanations:\n\n"

        "%s"
        "    - The current memory limit (%s) is too restrictive, causing an "
        "OOM\n"
        "      fault in the dynamic linker. This can be fixed with the -m "
        "option. A\n"
        "      simple way to confirm the diagnosis may be:\n\n"

        MSG_ULIMIT_USAGE
        " /path/to/fuzzed_app )\n\n"

        "      Tip: you can use http://jwilk.net/software/recidivm to quickly\n"
        "      estimate the required amount of virtual memory for the "
        "binary.\n\n"

        "    - Less likely, there is a horrible bug in the fuzzer. If other "
        "options\n"
        "      fail, poke <afl-users@googlegroups.com> for troubleshooting "
        "tips.\n",
        getenv(DEFER_ENV_VAR) ? "three" : "two",
        getenv(DEFER_ENV_VAR)
            ? "    - You are using deferred forkserver, but __AFL_INIT() is "
              "never\n"
              "      reached before the program terminates.\n\n"
            : "",
        DMS(mem_limit << 20), mem_limit - 1);

  }

  FATAL("Cmplog fork server handshake failed");

}

u8 run_cmplog_target(char** argv, u32 timeout) {

  static struct itimerval it;
  static u32              prev_timed_out = 0;
  static u64              exec_ms = 0;

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

    cmplog_child_pid = fork();

    if (cmplog_child_pid < 0) PFATAL("fork() failed");

    if (!cmplog_child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r);                          /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r);                        /* Ignore errors */

#endif                                                        /* ^RLIMIT_AS */

      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r);                          /* Ignore errors */

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

      setenv("ASAN_OPTIONS",
             "abort_on_error=1:"
             "detect_leaks=0:"
             "symbolize=0:"
             "allocator_may_return_null=1",
             0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "symbolize=0:"
                             "msan_track_origins=0", 0);

      setenv("__AFL_CMPLOG_MODE__", "1", 1);

      argv[0] = cmplog_binary;
      execv(cmplog_binary, argv);

      /* Use a distinctive bitmap value to tell the parent about execv()
         falling through. */

      *(u32*)trace_bits = EXEC_FAIL_SIG;
      exit(0);

    }

  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if ((res = write(cmplog_fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res,
              "Unable to request new process from cmplog fork server (OOM?)");

    }

    if ((res = read(cmplog_fsrv_st_fd, &cmplog_child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res,
              "Unable to request new process from cmplog fork server (OOM?)");

    }

    if (cmplog_child_pid <= 0)
      FATAL("Cmplog fork server is misbehaving (OOM?)");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate.
   */

  it.it_value.tv_sec = (timeout / 1000);
  it.it_value.tv_usec = (timeout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the cmplog_child_pid and sets
   * child_timed_out. */

  if (dumb_mode == 1 || no_forkserver) {

    if (waitpid(cmplog_child_pid, &status, 0) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(cmplog_fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      SAYF(
          "\n" cLRD "[-] " cRST
          "Unable to communicate with fork server. Some possible reasons:\n\n"
          "    - You've run out of memory. Use -m to increase the the memory "
          "limit\n"
          "      to something higher than %lld.\n"
          "    - The binary or one of the libraries it uses manages to create\n"
          "      threads before the forkserver initializes.\n"
          "    - The binary, at least in some circumstances, exits in a way "
          "that\n"
          "      also kills the parent process - raise() could be the "
          "culprit.\n\n"
          "If all else fails you can disable the fork server via "
          "AFL_NO_FORKSRV=1.\n",
          mem_limit);
      RPFATAL(res, "Unable to communicate with fork server");

    }

  }

  if (!WIFSTOPPED(status)) cmplog_child_pid = 0;

  getitimer(ITIMER_REAL, &it);
  exec_ms =
      (u64)timeout - (it.it_value.tv_sec * 1000 + it.it_value.tv_usec / 1000);
  if (slowest_exec_ms < exec_ms) slowest_exec_ms = exec_ms;

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  ++total_execs;

  /* Any subsequent operations on trace_bits must not be moved by the
     compiler below this point. Past this location, trace_bits[] behave
     very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  tb4 = *(u32*)trace_bits;

#ifdef WORD_SIZE_64
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif                                                     /* ^WORD_SIZE_64 */

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

u8 common_fuzz_cmplog_stuff(char** argv, u8* out_buf, u32 len) {

  u8 fault;

  if (post_handler) {

    out_buf = post_handler(out_buf, &len);
    if (!out_buf || !len) return 0;

  }

  write_to_testcase(out_buf, len);

  fault = run_cmplog_target(argv, exec_tmout);

  if (stop_soon) return 1;

  if (fault == FAULT_TMOUT) {

    if (subseq_tmouts++ > TMOUT_LIMIT) {

      ++cur_skipped_paths;
      return 1;

    }

  } else

    subseq_tmouts = 0;

  /* Users can hit us with SIGUSR1 to request the current input
     to be abandoned. */

  if (skip_requested) {

    skip_requested = 0;
    ++cur_skipped_paths;
    return 1;

  }

  /* This handles FAULT_ERROR for us: */

  /* queued_discovered += save_if_interesting(argv, out_buf, len, fault);

  if (!(stage_cur % stats_update_freq) || stage_cur + 1 == stage_max)
    show_stats(); */

  return 0;

}

