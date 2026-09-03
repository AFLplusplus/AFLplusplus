/*
   american fuzzy lop++ - state fuzzing measurement and admission
   --------------------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   State fuzzing mode (-J): time accounting, the execution cost benchmark,
   the harness self-check, the deep-input shelf keying and the hit-count
   high-water channel.

   Everything here is either off the hot path entirely or guarded by
   afl->state_mode. See docs/fuzzing_stateful_targets.md.

 */

#include "afl-fuzz.h"

void state_alloc(afl_state_t *afl) {

  if (!afl->state_mode) { return; }

  u32 map_size = afl->fsrv.map_size;

  if ((afl->state_mode & STATE_MODE_HIWATER) && !afl->hw_bits) {

    afl->hw_bits = ck_alloc(map_size);
    afl->hw_min_count = HW_MIN_COUNT;
    afl->hw_growth_pct = HW_GROWTH_PCT;

    if (getenv("AFL_HW_MIN_COUNT")) {

      afl->hw_min_count = atoi(getenv("AFL_HW_MIN_COUNT"));
      if (afl->hw_min_count < 2) { afl->hw_min_count = 2; }

    }

    if (getenv("AFL_HW_GROWTH_PCT")) {

      afl->hw_growth_pct = atoi(getenv("AFL_HW_GROWTH_PCT"));

    }

  }

  if ((afl->state_mode & STATE_MODE_DEEP) && !afl->shelf) {

    afl->shelf = ck_alloc(STATE_SHELF_CELLS * STATE_SHELF_WITNESSES *
                          sizeof(struct queue_entry *));
    afl->shelf_avg_exec_us = ck_alloc(STATE_SHELF_CELLS * sizeof(double));
    afl->shelf_avg_len = ck_alloc(STATE_SHELF_CELLS * sizeof(double));
    afl->shelf_count = ck_alloc(STATE_SHELF_CELLS * sizeof(u32));

  }

}

void state_free(afl_state_t *afl) {

  if (afl->shelf) { ck_free(afl->shelf); }
  if (afl->shelf_avg_exec_us) { ck_free(afl->shelf_avg_exec_us); }
  if (afl->shelf_avg_len) { ck_free(afl->shelf_avg_len); }
  if (afl->shelf_count) { ck_free(afl->shelf_count); }
  if (afl->hw_bits) { ck_free(afl->hw_bits); }

  afl->shelf = NULL;
  afl->shelf_avg_exec_us = NULL;
  afl->shelf_avg_len = NULL;
  afl->shelf_count = NULL;
  afl->hw_bits = NULL;

}

/* First queue entry that is still fuzzable, NULL if there is none. */

static struct queue_entry *state_first_entry(afl_state_t *afl) {

  u32 i;

  for (i = 0; i < afl->queued_items; ++i) {

    struct queue_entry *q = afl->queue_buf[i];

    if (q && !q->disabled && q->len) { return q; }

  }

  return NULL;

}

/* One execution of buf outside the fuzzing loop, classified and accounted
   for as slow-path work. */

static void state_exec_once(afl_state_t *afl, u8 *buf, u32 len) {

  void *use_mem = buf;

  (void)write_to_testcase(afl, &use_mem, len, 1);
  (void)fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
  afl->trace_foreign = 1;
  ++afl->slow_path_execs;

  classify_counts(&afl->fsrv);

}

u32 state_shelf_cell(afl_state_t *afl, struct queue_entry *q) {

  /* How much the input achieves. A mutator that speaks the input format
     reports the operation count, which is the quantity depth was always a
     proxy for; without one, fall back to the input length. */

  u32 achieved = q->op_count ? q->op_count : q->len;
  u32 depth_b, cost_b;

  if (achieved > afl->shelf_achieved_max) {

    afl->shelf_achieved_max = achieved;

  }

  if (q->exec_us > afl->shelf_cost_max) { afl->shelf_cost_max = q->exec_us; }

  depth_b = MIN(7U, (u32)((u64)achieved * 8U / (afl->shelf_achieved_max + 1U)));
  cost_b = MIN(7U, (u32)((u64)q->exec_us * 8U / (afl->shelf_cost_max + 1U)));
  return depth_b * STATE_SHELF_COST_BUCKETS + cost_b;

}

void state_calibration_stats(afl_state_t *afl, struct queue_entry *q) {

  if (unlikely(afl->hw_bits)) { q->hw_max = afl->hw_max_last; }

  q->shelf_cell = state_shelf_cell(afl, q);

}

void state_cost_bench(afl_state_t *afl) {

  if (likely(!(afl->state_mode & STATE_MODE_BENCH))) { return; }
  if (unlikely(afl->state_bench_done)) { return; }

  struct queue_entry *q = state_first_entry(afl);

  if (unlikely(!q || !afl->fsrv.target_path)) { return; }

  afl->state_bench_done = 1;

  u8 *buf = queue_testcase_get(afl, q);
  u32 r;
  u64 start_us, stop_us;

  start_us = get_cur_time_us();

  for (r = 0; r < STATE_BENCH_FORK_RUNS; ++r) {

    void *use_mem = buf;

    (void)write_to_testcase(afl, &use_mem, q->len, 1);
    (void)fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
    afl->trace_foreign = 1;
    ++afl->slow_path_execs;

    if (unlikely(afl->stop_soon)) { return; }

  }

  stop_us = get_cur_time_us();
  afl->fork_cost_us = (stop_us - start_us) / MAX(1U, r);

  u64 whole_us = stop_us - start_us;
  u32 whole_runs = MAX(1U, r);

  {

    u32 *offsets = ck_alloc(sizeof(u32) * (POOL_MAX_OPS + 1));
    u32  ops = run_afl_custom_describe_state_ops(afl, buf, q->len, offsets,
                                                 POOL_MAX_OPS + 1);

    if (ops >= 2 && ops <= POOL_MAX_OPS) {

      u32 k = ops / 2;
      u32 plen = offsets[k];

      if (plen && plen < q->len) {

        u64 pstart = get_cur_time_us(), pstop;

        for (r = 0; r < STATE_BENCH_FORK_RUNS && !afl->stop_soon; ++r) {

          void *use_mem = buf;

          (void)write_to_testcase(afl, &use_mem, plen, 1);
          (void)fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
          afl->trace_foreign = 1;
          ++afl->slow_path_execs;

        }

        pstop = get_cur_time_us();

        if (likely(!afl->stop_soon && r)) {

          afl->prefix_cost_us = (pstop - pstart) / r;
          afl->prefix_share_pct = ((double)(pstop - pstart) / (double)r) *
                                  100.0 * (double)whole_runs /
                                  (double)MAX(1ULL, whole_us);

        }

      }

    } else if (!ops) {

      WARNF(
          "-Jb cannot decompose prefix and tail: no mutator reports operation "
          "boundaries (afl_custom_describe_state_ops)");

    }

    ck_free(offsets);

  }

  u8 *bench_fn =
      alloc_printf("%s/.state_bench_input",
                   afl->tmp_dir ? (char *)afl->tmp_dir : (char *)afl->out_dir);
  s32 fd = open((char *)bench_fn, O_WRONLY | O_CREAT | O_TRUNC, afl->fsrv.perm);

  if (unlikely(fd < 0)) {

    WARNF("Unable to create '%s', skipping the cost benchmark",
          (char *)bench_fn);
    ck_free(bench_fn);
    return;

  }

  ck_write(fd, buf, q->len, bench_fn);
  close(fd);

  if (!afl->fsrv.use_stdin && afl->fsrv.out_file) {

    fd = open((char *)afl->fsrv.out_file, O_WRONLY | O_CREAT | O_TRUNC,
              afl->fsrv.perm);

    if (likely(fd >= 0)) {

      ck_write(fd, buf, q->len, afl->fsrv.out_file);
      close(fd);

    }

  }

  /* A target that only hangs when it starts its own process would block the
     campaign here forever, so every setup run gets a deadline generous enough
     for real startup work and runs that hit it are killed and discarded. */

  u32 bench_tmout =
      MAX((u32)1000, MAX(afl->hang_tmout, afl->fsrv.exec_tmout) * 10);
  u64 setup_sum_us = 0;
  u32 setup_ok = 0, setup_slow = 0;

  for (r = 0; r < STATE_BENCH_SETUP_RUNS && !afl->stop_soon && !setup_slow;
       ++r) {

    pid_t pid = fork();

    if (unlikely(pid < 0)) { PFATAL("fork() failed"); }

    if (!pid) {

      struct rlimit rl;

      if (afl->fsrv.mem_limit) {

        rl.rlim_max = rl.rlim_cur = ((rlim_t)afl->fsrv.mem_limit) << 20;
#ifdef RLIMIT_AS
        setrlimit(RLIMIT_AS, &rl);
#else
        setrlimit(RLIMIT_DATA, &rl);
#endif

      }

      rl.rlim_max = rl.rlim_cur = 0;
      setrlimit(RLIMIT_CORE, &rl);

      setsid();

      if (afl->fsrv.dev_null_fd >= 0) {

        dup2(afl->fsrv.dev_null_fd, 1);
        dup2(afl->fsrv.dev_null_fd, 2);

      }

      if (afl->fsrv.use_stdin) {

        s32 in_fd = open((char *)bench_fn, O_RDONLY);

        if (in_fd >= 0) {

          dup2(in_fd, 0);
          close(in_fd);

        }

      } else if (afl->fsrv.dev_null_fd >= 0) {

        dup2(afl->fsrv.dev_null_fd, 0);

      }

      close(FORKSRV_FD);
      close(FORKSRV_FD + 1);

      execv(afl->fsrv.target_path, afl->argv);
      _exit(1);

    }

    int status;
    u64 run_start = get_cur_time_us();
    u8  reaped = 0;

    while (1) {

      pid_t w = waitpid(pid, &status, WNOHANG);

      if (w == pid) {

        reaped = 1;
        break;

      }

      if (unlikely(w < 0 && errno != EINTR)) { break; }

      if (unlikely(afl->stop_soon) ||
          (get_cur_time_us() - run_start) / 1000 >= (u64)bench_tmout) {

        kill(-pid, SIGKILL);
        kill(pid, SIGKILL);
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        setup_slow = 1;
        break;

      }

      usleep(1000);

    }

    ++afl->slow_path_execs;

    if (likely(reaped)) {

      setup_sum_us += get_cur_time_us() - run_start;
      ++setup_ok;

    }

  }

  unlink((char *)bench_fn);
  ck_free(bench_fn);

  if (unlikely(afl->stop_soon)) { return; }

  if (unlikely(!setup_ok)) {

    WARNF(
        "Cost benchmark skipped: the target did not finish a standalone run "
        "within %u ms.\n    It only terminates under the forkserver, so full "
        "process setup cannot be timed.",
        bench_tmout);
    return;

  }

  afl->setup_cost_us = setup_sum_us / setup_ok;

  double ratio =
      (double)afl->setup_cost_us / (double)MAX(1ULL, afl->fork_cost_us);

  ACTF("Execution cost benchmark (%u forkserver runs, %u process starts):",
       STATE_BENCH_FORK_RUNS, setup_ok);

  if (unlikely(setup_slow)) {

    WARNF(
        "A standalone run exceeded %u ms and was killed, so the process "
        "setup cost is measured over %u of %u runs.",
        bench_tmout, setup_ok, STATE_BENCH_SETUP_RUNS);

  }

  SAYF("    fork + run       : %7llu us/exec\n", afl->fork_cost_us);
  SAYF("    full process set : %7llu us/exec  (%.1fx)\n", afl->setup_cost_us,
       ratio);

  if (afl->prefix_cost_us) {

    SAYF("    first half ops   : %7llu us/exec  (%.1f%% of the whole)\n",
         afl->prefix_cost_us, afl->prefix_share_pct);

  }

  if (ratio >= 2.0) {

    SAYF(
        "    => forking is %.0fx cheaper than rebuilding this process. "
        "Snapshotting the\n"
        "       post-setup state would gain at most %.0fx here; measure before "
        "building\n"
        "       it. Persistent mode (if the harness can reset cleanly) is the "
        "cheaper\n"
        "       first move.\n",
        ratio, ratio);

  } else {

    SAYF(
        "    => rebuilding this process is as cheap as forking it (%.1fx). "
        "Neither a\n"
        "       snapshot nor persistent mode can win much here; the setup is "
        "not what\n"
        "       this campaign is paying for.\n",
        ratio);

  }

}

void state_contract_check(afl_state_t *afl) {

  if (likely(!(afl->state_mode & STATE_MODE_CONTRACT))) { return; }
  if (unlikely(afl->contract_checked || afl->non_instrumented_mode)) { return; }

  struct queue_entry *q = state_first_entry(afl);

  if (unlikely(!q)) { return; }

  u8 *buf = queue_testcase_get(afl, q);
  u32 i, map_size = afl->fsrv.map_size, diff = 0;
  u8  have_first = 0;

  if (afl->fsrv.persistent_mode) {

    s32 prev_pid = afl->fsrv.child_pid;
    u32 tries;

    for (tries = 0; tries < 16; ++tries) {

      state_exec_once(afl, buf, q->len);

      if (unlikely(afl->stop_soon)) { return; }

      if (afl->fsrv.child_pid != prev_pid) {

        have_first = 1;
        break;

      }

      prev_pid = afl->fsrv.child_pid;

    }

  }

  if (!have_first) {

    state_exec_once(afl, buf, q->len);
    if (unlikely(afl->stop_soon)) { return; }

  }

  memcpy(afl->clean_trace, afl->fsrv.trace_bits, map_size);

  state_exec_once(afl, buf, q->len);

  if (unlikely(afl->stop_soon)) { return; }

  for (i = 0; i < map_size; ++i) {

    if (unlikely(afl->clean_trace[i] != afl->fsrv.trace_bits[i])) { ++diff; }

  }

  afl->contract_checked = 1;
  afl->contract_diff_edges = diff;
  afl->contract_failed = diff ? 1 : 0;

  if (diff) {

    WARNF("harness self-check FAILED.");
    SAYF(
        "    The same input produced different coverage as execution #1 and "
        "as\n"
        "    execution #2 of the same process: %u edges differ.\n"
        "    In a state harness this is almost always a bug in the harness, "
        "not in\n"
        "    the target: something is not reset between iterations (a static, "
        "a\n"
        "    cached fd, a global parser context, a leaked allocation).\n"
        "    Every crash and every saved input from this campaign is suspect "
        "until\n"
        "    this is fixed.\n",
        diff);

  } else {

    OKF("harness self-check passed (exec #1 == exec #2).");

  }

}

void state_startup_checks(afl_state_t *afl) {

  if (likely(!afl->state_mode)) { return; }
  if (unlikely(!afl->fsrv.fsrv_pid || afl->stop_soon)) { return; }

  struct queue_entry *q = state_first_entry(afl);

  if (unlikely(!q)) { return; }

  state_contract_check(afl);
  state_cost_bench(afl);

}

u8 hw_frontier_check(afl_state_t *afl) {

  u8  *trace = afl->fsrv.trace_bits, *hw = afl->hw_bits;
  u64 *tw = (u64 *)trace;
  u32  map_size = afl->fsrv.map_size;
  u32  w, b, words = map_size >> 3;
  u32  floor_cnt = afl->hw_min_count, growth = afl->hw_growth_pct;
  u8   improved = 0;

  for (w = 0; w <= words; ++w) {

    u32 base = w << 3, top = MIN(base + 8, map_size);

    if (w < words && likely(!tw[w])) { continue; }

    for (b = base; b < top; ++b) {

      u32 c = trace[b], prev = hw[b];

      if (likely(c <= prev)) { continue; }
      if (c < floor_cnt) { continue; }
      if (prev && c * 100 < prev * (100 + growth) + 100) { continue; }

      if (!prev) { ++afl->hw_slots; }

      hw[b] = (u8)c;
      ++afl->hw_credits;
      improved = 1;

    }

  }

  return improved;

}

void hw_absorb(afl_state_t *afl) {

  u8  *trace = afl->fsrv.trace_bits, *hw = afl->hw_bits;
  u64 *tw = (u64 *)trace;
  u32  map_size = afl->fsrv.map_size;
  u32  w, b, words = map_size >> 3;

  afl->hw_max_last = 0;

  for (w = 0; w <= words; ++w) {

    u32 base = w << 3, top = MIN(base + 8, map_size);

    if (w < words && likely(!tw[w])) { continue; }

    for (b = base; b < top; ++b) {

      if (unlikely(trace[b] > afl->hw_max_last)) {

        afl->hw_max_last = trace[b];

      }

      if (unlikely(trace[b] > hw[b])) {

        if (!hw[b]) { ++afl->hw_slots; }
        hw[b] = trace[b];

      }

    }

  }

}

void hw_admit_bound(afl_state_t *afl) {

  u32 cap = (u32)afl->afl_env.afl_state_admit_pct;

  if (!cap || afl->hw_admit_off) { return; }
  if (afl->queued_items < STATE_ADMIT_MIN_ITEMS) { return; }
  if (afl->hw_only_admits * 100 < (u64)afl->queued_items * cap) { return; }

  if (afl->hw_only_admits >= STATE_YIELD_MIN_SAMPLE) {

    u32 yield = (u32)afl->afl_env.afl_state_yield_pct;

    if (yield && afl->hw_only_paid * 100 >= afl->hw_only_admits * yield) {

      return;

    }

  }

  afl->hw_admit_off = 1;

  WARNF(
      "hit-count high-water switched off for saving: it had created %u%% of "
      "the queue\n    and only %llu of its %llu entries went on to find "
      "anything.",
      cap, afl->hw_only_paid, afl->hw_only_admits);

}

