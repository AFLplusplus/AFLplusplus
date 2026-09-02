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

   State fuzzing mode (-J): time accounting, ballast measurement, the repeat
   probe, the execution cost benchmark, the harness self-check, the
   double-run admission gate and the per-input stability number.

   Everything here is either off the hot path entirely or guarded by
   afl->state_mode. See docs/fuzzing_stateful_targets.md.

 */

#include "afl-fuzz.h"
#include <math.h>

void state_alloc(afl_state_t *afl) {

  if ((!afl->state_mode && !afl->time_accounting) || afl->ballast_bits) {

    return;

  }

  u32 map_size = afl->fsrv.map_size;

  afl->ballast_bits = ck_alloc(map_size);

  if (!afl->state_mode) { return; }

  afl->cal_var_map = ck_alloc(map_size);

  if (afl->state_mode & STATE_MODE_PROBE) {

    afl->probe_union = ck_alloc(map_size);
    afl->probe_isect = ck_alloc(map_size);

  }

  if (afl->state_mode & (STATE_MODE_RARE | STATE_MODE_SIG)) {

    afl->edge_corpus_cnt = ck_alloc(map_size * sizeof(u32));

  }

  if (afl->state_mode & STATE_MODE_GATE) {

    afl->gate_ghost = ck_alloc(map_size);

  }

  if (afl->state_mode & STATE_MODE_HIWATER) {

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

  if (afl->state_mode & STATE_MODE_SIG) {

    afl->sig_seen = ck_alloc(SIG_MAP_BYTES);
    afl->sig_k = SIG_DEFAULT_K;
    afl->sig_max_freq = SIG_MAX_FREQ;
    afl->sig_min_corpus = SIG_MIN_CORPUS;

    if (getenv("AFL_SIG_MAX_FREQ")) {

      afl->sig_max_freq = atoi(getenv("AFL_SIG_MAX_FREQ"));

    }

    if (getenv("AFL_SIG_MIN_CORPUS")) {

      afl->sig_min_corpus = atoi(getenv("AFL_SIG_MIN_CORPUS"));

    }

    if (getenv("AFL_SIG_K")) {

      afl->sig_k = atoi(getenv("AFL_SIG_K"));
      if (afl->sig_k < 1) { afl->sig_k = 1; }
      if (afl->sig_k > SIG_MAX_K) { afl->sig_k = SIG_MAX_K; }

    }

  }

  if (afl->state_mode & STATE_MODE_DEEP) {

    afl->shelf = ck_alloc(STATE_SHELF_CELLS * STATE_SHELF_WITNESSES *
                          sizeof(struct queue_entry *));
    afl->shelf_avg_exec_us = ck_alloc(STATE_SHELF_CELLS * sizeof(double));
    afl->shelf_avg_len = ck_alloc(STATE_SHELF_CELLS * sizeof(double));
    afl->shelf_avg_info = ck_alloc(STATE_SHELF_CELLS * sizeof(double));
    afl->shelf_count = ck_alloc(STATE_SHELF_CELLS * sizeof(u32));

  }

}

void state_free(afl_state_t *afl) {

  if (afl->ballast_bits) { ck_free(afl->ballast_bits); }
  if (afl->cal_var_map) { ck_free(afl->cal_var_map); }
  if (afl->probe_union) { ck_free(afl->probe_union); }
  if (afl->probe_isect) { ck_free(afl->probe_isect); }
  if (afl->edge_corpus_cnt) { ck_free(afl->edge_corpus_cnt); }
  if (afl->shelf) { ck_free(afl->shelf); }
  if (afl->shelf_avg_exec_us) { ck_free(afl->shelf_avg_exec_us); }
  if (afl->shelf_avg_len) { ck_free(afl->shelf_avg_len); }
  if (afl->shelf_avg_info) { ck_free(afl->shelf_avg_info); }
  if (afl->shelf_count) { ck_free(afl->shelf_count); }
  if (afl->virgin_state) { ck_free(afl->virgin_state); }
  if (afl->state_seen) { ck_free(afl->state_seen); }
  if (afl->situation_seen) { ck_free(afl->situation_seen); }
  if (afl->situation_depth) { ck_free(afl->situation_depth); }
  if (afl->gate_ghost) { ck_free(afl->gate_ghost); }
  afl->gate_ghost = NULL;
  if (afl->hw_bits) { ck_free(afl->hw_bits); }
  if (afl->sig_seen) { ck_free(afl->sig_seen); }

  afl->hw_bits = NULL;
  afl->sig_seen = NULL;

  afl->virgin_state = NULL;
  afl->state_seen = NULL;
  afl->situation_seen = NULL;
  afl->situation_depth = NULL;
  afl->ballast_bits = NULL;
  afl->cal_var_map = NULL;
  afl->probe_union = NULL;
  afl->probe_isect = NULL;
  afl->edge_corpus_cnt = NULL;
  afl->shelf = NULL;
  afl->shelf_avg_exec_us = NULL;
  afl->shelf_avg_len = NULL;
  afl->shelf_avg_info = NULL;
  afl->shelf_count = NULL;

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

void state_ballast_fold(afl_state_t *afl) {

  if (likely(!afl->ballast_bits)) { return; }

  u8 *trace = afl->fsrv.trace_bits;
  u32 i, map_size = afl->fsrv.map_size;

  if (unlikely(!afl->ballast_valid)) {

    for (i = 0; i < map_size; ++i) {

      afl->ballast_bits[i] = trace[i] ? 1 : 0;

    }

    afl->ballast_valid = 1;

  } else {

    for (i = 0; i < map_size; ++i) {

      if (afl->ballast_bits[i] && !trace[i]) { afl->ballast_bits[i] = 0; }

    }

  }

  u32 reached = count_non_255_bytes(afl, afl->virgin_bits);

  afl->ballast_pct = 100.0 * (double)count_bytes(afl, afl->ballast_bits) /
                     (double)MAX(1U, reached);

}

u32 state_shelf_cell(afl_state_t *afl, struct queue_entry *q) {

  /* How much the input achieves. A mutator that speaks the input format
     reports the operation count, which is the quantity depth was always a
     proxy for; without one, fall back to the mutation generation. */

  u32 achieved = q->op_count ? q->op_count : q->len;
  u32 depth_b, cost_b;

  if (achieved > afl->shelf_achieved_max) {

    afl->shelf_achieved_max = achieved;

  }

  if (q->exec_us > afl->shelf_cost_max) { afl->shelf_cost_max = q->exec_us; }

  depth_b = MIN(7U, (u32)((u64)achieved * 8U / (afl->shelf_achieved_max + 1U)));
  cost_b = MIN(7U, (u32)((u64)q->exec_us * 8U / (afl->shelf_cost_max + 1U)));
  u32 state_b = (afl->state_signal_trusted || q->op_count || q->sig_only ||
                 (afl->sig_seen && q->state_id))
                    ? (q->state_id & 7)
                    : 0;

  return (depth_b * STATE_SHELF_COST_BUCKETS + cost_b) *
             STATE_SHELF_STATE_BUCKETS +
         state_b;

}

/* Clamp a byte range to the input and store it as the entry's hot region. */

static void state_hot_set(struct queue_entry *q, u32 off, u32 hot_len) {

  if (!hot_len || off >= q->len) {

    off = 0;
    hot_len = 0;

  } else if (off + hot_len > q->len) {

    hot_len = q->len - off;

  }

  q->hot_off = off;
  q->hot_len = hot_len;

}

/* The hot region the harness declared for this input, recorded at
   calibration time. Targets without the annotation are covered later by
   state_hot_from_taint(). */

static void state_hot_region(afl_state_t *afl, struct queue_entry *q) {

  if (afl->shm.state_map && afl->shm.state_map->hot_len) {

    state_hot_set(q, afl->shm.state_map->hot_off, afl->shm.state_map->hot_len);

  }

}

/* The fallback for harnesses without AFL_HOT_REGION: the largest byte range
   CmpLog colorization found to matter. Called while the taint list is still
   alive, since RedQueen frees it on the way out, and it never overrides a
   region the harness declared itself. */

void state_hot_from_taint(afl_state_t *afl, struct queue_entry *q,
                          struct tainted *t) {

  if (likely(!(afl->state_mode & STATE_MODE_HOT))) { return; }
  if (!q || q->hot_len || !q->len) { return; }

  u32 best_off = 0, best_len = 0;

  while (t) {

    if (t->len > best_len && t->pos < q->len) {

      best_off = t->pos;
      best_len = t->len;

    }

    t = t->next;

  }

  if (best_len && best_len < q->len) { state_hot_set(q, best_off, best_len); }

}

void state_calibration_stats(afl_state_t *afl, struct queue_entry *q) {

  u32 i, map_size = afl->fsrv.map_size;
  u8 *trace = afl->fsrv.trace_bits;

  if (likely(afl->cal_var_map != NULL)) {

    u32 edges = 0, hits = 0;

    for (i = 0; i < map_size; ++i) {

      if (likely(!afl->cal_var_map[i])) { continue; }

      if (afl->cal_var_map[i] == 2) {

        ++edges;

      } else {

        ++hits;

      }

    }

    q->var_edge_cnt = edges;
    q->var_hit_cnt = hits;

    double var = (double)(edges + hits) / (double)MAX(1U, q->bitmap_size);

    q->stability = 100.0 * (1.0 - var);
    if (q->stability < 0.0) { q->stability = 0.0; }
    if (q->stability > 100.0) { q->stability = 100.0; }

  }

  if (unlikely(afl->edge_corpus_cnt != NULL)) {

    double score = 0.0;

    ++afl->corpus_trace_cnt;

    for (i = 0; i < map_size; ++i) {

      if (likely(!trace[i])) { continue; }

      if (likely(afl->edge_corpus_cnt[i] < 0xffffffff)) {

        ++afl->edge_corpus_cnt[i];

      }

      score += log2((double)afl->corpus_trace_cnt /
                    (double)MAX(1U, afl->edge_corpus_cnt[i]));

    }

    q->info_score = score;

  }

  if (afl->cal_var_map || afl->edge_corpus_cnt) {

    double stab_sum = 0.0, stab_min = 100.0, info_sum = 0.0;
    u32    cnt = 0, scnt = 0;

    for (i = 0; i < afl->queued_items; ++i) {

      struct queue_entry *e = afl->queue_buf[i];

      if (unlikely(!e) || e->disabled || !e->bitmap_size) { continue; }

      info_sum += e->info_score;
      ++cnt;

      /* q->stability is only set when an entry is calibrated with the var map,
         and it is not persisted, so after a resume the queue is full of
         entries that carry no measurement at all. Averaging those in as 0%
         dragged input_stab_avg to a small number and pinned input_stab_min at
         0.00%, which inverts the advice to trust these fields rather than the
         corpus-cumulative stability. A genuinely 0%-stable entry always has a
         non-zero var count, so the two cases are distinguishable. */
      if (e->stability == 0.0 && !e->var_edge_cnt && !e->var_hit_cnt) {

        continue;

      }

      stab_sum += e->stability;
      if (e->stability < stab_min) { stab_min = e->stability; }
      ++scnt;

    }

    if (likely(cnt)) {

      if (afl->cal_var_map && scnt) {

        afl->corpus_stability_avg = stab_sum / (double)scnt;
        afl->corpus_stability_min = stab_min;

      }

      if (afl->edge_corpus_cnt) {

        afl->info_score_avg = info_sum / (double)cnt;

      }

    }

  }

  if (unlikely(afl->ballast_bits) && likely(afl->ballast_valid)) {

    u32 info = 0;

    for (i = 0; i < map_size; ++i) {

      if (trace[i] && !afl->ballast_bits[i]) { ++info; }

    }

    q->info_bitmap = info;
    afl->total_info_bitmap += info;

  }

  state_map_record(afl, q);

  if (unlikely(afl->hw_bits)) { q->hw_max = afl->hw_max_last; }

  if (unlikely(afl->sig_seen)) {

    u32 sig = sig_compute(afl);

    if (sig) { q->state_id = sig; }

  }

  q->shelf_cell = state_shelf_cell(afl, q);
  state_hot_region(afl, q);

}

u8 state_admission_gate(afl_state_t *afl, void *mem, u32 len) {

  if (likely(!(afl->state_mode & STATE_MODE_GATE))) { return 1; }
  if (unlikely(afl->non_instrumented_mode)) { return 1; }
  if (unlikely(!afl->virgin_undo_valid)) { return 1; }

  u32 i, map_size = afl->fsrv.map_size;
  u32 claimed = 0, survived = 0, restored = 0, fresh = 0;

  for (i = 0; i < map_size; ++i) {

    if (likely(afl->virgin_undo[i] == afl->virgin_bits[i])) { continue; }

    ++claimed;

    if (likely(!afl->gate_ghost) || afl->gate_ghost[i] < GATE_GHOST_LEARN ||
        afl->gate_ghost[i] == GATE_GHOST_PROVEN) {

      ++fresh;

    }

  }

  if (unlikely(!claimed)) { return 1; }

  if (unlikely(!fresh)) {

    virgin_undo_rollback(afl, NULL);
    ++afl->gate_rejected;
    ++afl->gate_skipped;
    return 0;

  }

  void *gate_mem = mem;

  (void)write_to_testcase(afl, &gate_mem, len, 1);
  (void)fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
  afl->trace_foreign = 1;

  ++afl->gate_checked;
  ++afl->slow_path_execs;

  if (unlikely(afl->stop_soon)) { return 1; }

  classify_counts(&afl->fsrv);

  for (i = 0; i < map_size; ++i) {

    if (likely(afl->virgin_undo[i] == afl->virgin_bits[i])) { continue; }

    if (afl->fsrv.trace_bits[i]) {

      ++survived;
      if (afl->gate_ghost) { afl->gate_ghost[i] = GATE_GHOST_PROVEN; }

    } else if (afl->gate_ghost && afl->gate_ghost[i] < GATE_GHOST_LEARN) {

      if (++afl->gate_ghost[i] == GATE_GHOST_LEARN) { ++afl->gate_learned; }

    }

  }

  if (!survived) {

    virgin_undo_rollback(afl, NULL);
    ++afl->gate_rejected;
    return 0;

  }

  for (i = 0; i < map_size; ++i) {

    if (likely(afl->virgin_undo[i] == afl->virgin_bits[i])) { continue; }
    if (afl->fsrv.trace_bits[i]) { continue; }
    if (unlikely(afl->virgin_reclaim[i] >= CAL_RECLAIM_MAX)) { continue; }

    ++afl->virgin_reclaim[i];

    if (likely(!afl->var_bytes[i])) {

      afl->virgin_bits[i] = afl->virgin_undo[i];
      ++restored;

    }

  }

  if (restored) {

    ++afl->gate_partial;
    afl->bitmap_changed = 1;

  }

  return 1;

}

void state_repeat_probe(afl_state_t *afl, struct queue_entry *q, u32 runs) {

  if (unlikely(!afl->probe_union || !afl->probe_isect)) { return; }
  if (unlikely(!q || !q->len || afl->non_instrumented_mode)) { return; }

  if (!runs) {

    runs = afl->afl_env.afl_state_probe_runs > 0
               ? (u32)afl->afl_env.afl_state_probe_runs
               : STATE_PROBE_RUNS;

  }

  u8 *buf = queue_testcase_get(afl, q);
  u32 i, r, map_size = afl->fsrv.map_size, identical = 0;
  u64 first_hash = 0;

  for (r = 0; r < runs; ++r) {

    state_exec_once(afl, buf, q->len);

    if (unlikely(afl->stop_soon)) { return; }

    u64 cksum = hash64(afl->fsrv.trace_bits, map_size, HASH_CONST);

    if (!r) {

      first_hash = cksum;
      identical = 1;

      for (i = 0; i < map_size; ++i) {

        u8 present = afl->fsrv.trace_bits[i] ? 1 : 0;

        afl->probe_union[i] = present;
        afl->probe_isect[i] = present;

      }

    } else {

      if (cksum == first_hash) { ++identical; }

      for (i = 0; i < map_size; ++i) {

        if (afl->fsrv.trace_bits[i]) {

          afl->probe_union[i] = 1;

        } else {

          afl->probe_isect[i] = 0;

        }

      }

    }

  }

  u32 in_union = count_bytes(afl, afl->probe_union);
  u32 in_isect = count_bytes(afl, afl->probe_isect);

  afl->probe_edge_pct = 100.0 * (double)in_isect / (double)MAX(1U, in_union);
  afl->probe_pct = 100.0 * (double)identical / (double)MAX(1U, runs);
  afl->probe_last_ms = get_cur_time();

}

void state_maybe_probe(afl_state_t *afl) {

  if (likely(!(afl->state_mode & STATE_MODE_PROBE))) { return; }
  if (unlikely(!afl->probe_union)) { return; }

  if (likely(get_cur_time() - afl->probe_last_ms < STATE_PROBE_INTERVAL_MS)) {

    return;

  }

  u32 i, cand = 0;

  for (i = 0; i < afl->queued_items; ++i) {

    struct queue_entry *q = afl->queue_buf[i];

    if (q && !q->disabled && q->favored && q->len) { ++cand; }

  }

  if (unlikely(!cand)) {

    state_repeat_probe(afl, state_first_entry(afl), 0);
    return;

  }

  u32 pick = rand_below(afl, cand);

  cand = 0;

  for (i = 0; i < afl->queued_items; ++i) {

    struct queue_entry *q = afl->queue_buf[i];

    if (!q || q->disabled || !q->favored || !q->len) { continue; }

    if (cand++ == pick) {

      state_repeat_probe(afl, q, 0);
      return;

    }

  }

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

  if (afl->state_mode & STATE_MODE_PROBE) { state_repeat_probe(afl, q, 0); }

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

u32 sig_compute(afl_state_t *afl) {

  u8  *trace = afl->fsrv.trace_bits;
  u64 *tw = (u64 *)trace;
  u32 *freq = afl->edge_corpus_cnt;
  u32  map_size = afl->fsrv.map_size;
  u32  w, b, words = map_size >> 3;
  u32  k = afl->sig_k, n = 0;
  u32  best_idx[SIG_MAX_K];
  u32  best_frq[SIG_MAX_K];
  u32  h = 0x811c9dc5U, i, j;

  if (unlikely(!freq) || afl->corpus_trace_cnt < afl->sig_min_corpus) {

    return 0;

  }

  for (w = 0; w <= words; ++w) {

    u32 base = w << 3, top = MIN(base + 8, map_size);

    if (w < words && likely(!tw[w])) { continue; }

    for (b = base; b < top; ++b) {

      if (likely(!trace[b])) { continue; }

      u32 fq = freq[b];

      if (fq > afl->sig_max_freq) { continue; }
      if (n == k && fq >= best_frq[n - 1]) { continue; }

      for (i = 0; i < n && best_frq[i] <= fq; ++i) {}

      for (j = MIN(n, k - 1); j > i; --j) {

        best_frq[j] = best_frq[j - 1];
        best_idx[j] = best_idx[j - 1];

      }

      best_frq[i] = fq;
      best_idx[i] = b;
      if (n < k) { ++n; }

    }

  }

  if (!n) { return 0; }

  for (i = 0; i < n; ++i) {

    for (j = i + 1; j < n; ++j) {

      if (best_idx[j] < best_idx[i]) {

        u32 t = best_idx[i];
        best_idx[i] = best_idx[j];
        best_idx[j] = t;

      }

    }

  }

  for (i = 0; i < n; ++i) {

    h ^= best_idx[i];
    h *= 0x01000193U;

  }

  return h ? h : 1;

}

u8 sig_is_new(afl_state_t *afl, u32 sig) {

  u32 idx;

  if (!sig || !afl->sig_seen) { return 0; }

  idx = sig & ((1U << SIG_MAP_BITS) - 1U);

  if (afl->sig_seen[idx >> 3] & (1U << (idx & 7))) { return 0; }

  afl->sig_seen[idx >> 3] |= (u8)(1U << (idx & 7));
  ++afl->sig_found;

  return 1;

}

void sig_admit_bound(afl_state_t *afl) {

  u32 cap = (u32)afl->afl_env.afl_state_admit_pct;

  if (!cap || afl->sig_admit_off) { return; }
  if (afl->queued_items < STATE_ADMIT_MIN_ITEMS) { return; }
  if (afl->sig_only_admits * 100 < (u64)afl->queued_items * cap) { return; }

  if (afl->sig_only_admits >= STATE_YIELD_MIN_SAMPLE) {

    u32 yield = (u32)afl->afl_env.afl_state_yield_pct;

    if (yield && afl->sig_only_paid * 100 >= afl->sig_only_admits * yield) {

      return;

    }

  }

  afl->sig_admit_off = 1;

  WARNF(
      "rare-edge signature switched off for saving: it had created %u%% of the "
      "queue\n    and only %llu of its %llu entries went on to find anything.",
      cap, afl->sig_only_paid, afl->sig_only_admits);

}

u32 state_score_bits(afl_state_t *afl, struct queue_entry *q) {

  if (unlikely(afl->state_mode & STATE_MODE_BALLAST) && q->info_bitmap > 1) {

    return q->info_bitmap;

  }

  return q->bitmap_size;

}

