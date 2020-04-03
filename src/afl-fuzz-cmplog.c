/*
   american fuzzy lop++ - cmplog execution routines
   ------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#include <sys/select.h>

#include "afl-fuzz.h"
#include "cmplog.h"

void init_cmplog_forkserver(afl_state_t *afl) {

  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the cmplog fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  afl->fsrv.child_timed_out = 0;
  afl->cmplog_fsrv_pid = fork();

  if (afl->cmplog_fsrv_pid < 0) PFATAL("fork() failed");

  if (!afl->cmplog_fsrv_pid) {

    /* CHILD PROCESS */

    struct rlimit r;

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r);                        /* Ignore errors */

    }

    if (afl->fsrv.mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)afl->fsrv.mem_limit) << 20;

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

    /* Isolate the process and configure standard descriptors. If
       afl->fsrv.out_file is specified, stdin is /dev/null; otherwise,
       afl->fsrv.out_fd is cloned instead. */

    setsid();

    if (!(afl->afl_env.afl_debug_child_output)) {

      dup2(afl->fsrv.dev_null_fd, 1);
      dup2(afl->fsrv.dev_null_fd, 2);

    }

    if (!afl->fsrv.use_stdin) {

      dup2(afl->fsrv.dev_null_fd, 0);

    } else {

      dup2(afl->fsrv.out_fd, 0);
      close(afl->fsrv.out_fd);

    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    close(afl->fsrv.out_dir_fd);
    close(afl->fsrv.dev_null_fd);
#ifndef HAVE_ARC4RANDOM
    close(afl->fsrv.dev_urandom_fd);
#endif
    close(afl->fsrv.plot_file == NULL ? -1 : fileno(afl->fsrv.plot_file));

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

    setenv("___AFL_EINS_ZWEI_POLIZEI___", "1", 1);

    if (!afl->qemu_mode && afl->argv[0] != afl->cmplog_binary) {

      ck_free(afl->argv[0]);
      afl->argv[0] = afl->cmplog_binary;

    }

    execv(afl->argv[0], afl->argv);

    /* Use a distinctive bitmap signature to tell the parent about execv()
       falling through. */

    *(u32 *)afl->fsrv.trace_bits = EXEC_FAIL_SIG;
    exit(0);

  }

  /* PARENT PROCESS */

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  afl->cmplog_fsrv_ctl_fd = ctl_pipe[1];
  afl->cmplog_fsrv_st_fd = st_pipe[0];

  /* Wait for the fork server to come up, but don't wait too long. */

  rlen = 0;
  if (afl->fsrv.exec_tmout) {

    rlen = 4;
    u32 timeout_ms = afl->fsrv.exec_tmout * FORK_WAIT_MULT;
    /* Reuse readfds as exceptfds to see when the child closed the pipe */
    u32 exec_ms = read_timed(afl->cmplog_fsrv_st_fd, &status, rlen, timeout_ms);

    if (!exec_ms) {

      PFATAL("Error in timed read");

    } else if (exec_ms > timeout_ms) {

      afl->fsrv.child_timed_out = 1;
      kill(afl->cmplog_fsrv_pid, SIGKILL);
      rlen = read(afl->cmplog_fsrv_st_fd, &status, 4);

    }

  } else {

    rlen = read(afl->cmplog_fsrv_st_fd, &status, 4);

  }

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (afl->fsrv.child_timed_out)
    FATAL(
        "Timeout while initializing cmplog fork server (adjusting -t may "
        "help)");

  if (rlen == 4) {

    OKF("All right - fork server is up.");
    return;

  }

  if (waitpid(afl->cmplog_fsrv_pid, &status, 0) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (afl->fsrv.mem_limit && afl->fsrv.mem_limit < 500 &&
        afl->fsrv.uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, "
           "before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you "
           "have a\n"
           "    restrictive memory limit configured, this is expected; please "
           "read\n"
           "    %s/notes_for_asan.md for help.\n",
           doc_path);

    } else if (!afl->fsrv.mem_limit) {

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

      u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

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
           stringify_mem_size(val_buf, sizeof(val_buf),
                              afl->fsrv.mem_limit << 20),
           afl->fsrv.mem_limit - 1);

    }

    FATAL("Cmplog fork server crashed with signal %d", WTERMSIG(status));

  }

  if (*(u32 *)afl->fsrv.trace_bits == EXEC_FAIL_SIG)
    FATAL("Unable to execute target application ('%s')", afl->argv[0]);

  if (afl->fsrv.mem_limit && afl->fsrv.mem_limit < 500 && afl->fsrv.uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated "
         "before we could complete a\n"
         "    handshake with the injected code. Since it seems to be built "
         "with ASAN and\n"
         "    you have a restrictive memory limit configured, this is "
         "expected; please\n"
         "    read %s/notes_for_asan.md for help.\n",
         doc_path);

  } else if (!afl->fsrv.mem_limit) {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated "
         "before we could complete a\n"
         "    handshake with the injected code. Perhaps there is a horrible "
         "bug in the\n"
         "    fuzzer. Poke <afl-users@googlegroups.com> for troubleshooting "
         "tips.\n");

  } else {

    u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

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
        stringify_mem_size(val_buf, sizeof(val_buf), afl->fsrv.mem_limit << 20),
        afl->fsrv.mem_limit - 1);

  }

  FATAL("Cmplog fork server handshake failed");

}

u8 run_cmplog_target(afl_state_t *afl, u32 timeout) {

  int status = 0;
  u32 exec_ms;

  u32 tb4;
  s32 res;

  afl->fsrv.child_timed_out = 0;

  /* After this memset, afl->fsrv.trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  memset(afl->fsrv.trace_bits, 0, MAP_SIZE);
  MEM_BARRIER();

  /* Since we always have a forkserver (or a fauxserver) running, we can simply
  tell them to have at it and read back the pid from it.*/

  if ((res = write(afl->cmplog_fsrv_ctl_fd, &afl->cmplog_prev_timed_out, 4)) !=
      4) {

    if (afl->stop_soon) return 0;
    RPFATAL(res,
            "Unable to request new process from cmplog fork server (OOM?)");

  }

  if ((res = read(afl->cmplog_fsrv_st_fd, &afl->cmplog_child_pid, 4)) != 4) {

    if (afl->stop_soon) return 0;
    RPFATAL(res,
            "Unable to request new process from cmplog fork server (OOM?)");

  }

  if (afl->cmplog_child_pid <= 0)
    FATAL("Cmplog fork server is misbehaving (OOM?)");

  /* Configure timeout, as requested by user, then wait for child to terminate.
   */
  exec_ms = read_timed(afl->cmplog_fsrv_st_fd, &status, 4, timeout);

  if (exec_ms > timeout) {

    /* If there was no response from forkserver after timeout seconds,
    we kill the child. The forkserver should inform us afterwards */

    kill(afl->cmplog_child_pid, SIGKILL);
    afl->fsrv.child_timed_out = 1;

    /* After killing the child, the forkserver should tell us */
    if (!read(afl->cmplog_fsrv_st_fd, &status, 4)) exec_ms = 0;

  }

  if (!exec_ms) {  // Something went wrong.

    if (afl->stop_soon) return 0;
    SAYF("\n" cLRD "[-] " cRST
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
         afl->fsrv.mem_limit);
    RPFATAL(res, "Unable to communicate with fork server");

  }

  if (!WIFSTOPPED(status)) afl->cmplog_child_pid = 0;

  if (afl->slowest_exec_ms < exec_ms) afl->slowest_exec_ms = exec_ms;

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

  afl->cmplog_prev_timed_out = afl->fsrv.child_timed_out;

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

u8 common_fuzz_cmplog_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  u8 fault;

  if (afl->post_handler) {

    u8 *post_buf = NULL;

    size_t post_len =
        afl->post_handler(afl->post_data, out_buf, len, &post_buf);
    if (!post_buf || !post_len) return 0;
    out_buf = post_buf;
    len = post_len;

  }

  write_to_testcase(afl, out_buf, len);

  fault = run_cmplog_target(afl, afl->fsrv.exec_tmout);

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

  /* afl->queued_discovered += save_if_interesting(afl, argv, out_buf, len,
  fault);

  if (!(afl->stage_cur % afl->stats_update_freq) || afl->stage_cur + 1 ==
  afl->stage_max) show_stats(afl); */

  return 0;

}

