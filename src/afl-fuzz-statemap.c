/*
   american fuzzy lop++ - state transition map
   -------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   State fuzzing mode (-J s): the separate (previous state, current state,
   action) map fed by IJON_STATE annotations, and the test that decides
   whether that state signal is allowed to influence which inputs are saved.

   Until the test passes, the signal is recorded and reported and changes
   nothing. See docs/fuzzing_stateful_targets.md.

 */

#include "afl-fuzz.h"

/* Allocate the virgin state map and publish the shared segment to the target.
   Idempotent, and a no-op unless -J s asked for a state map. */

void state_map_setup(afl_state_t *afl) {

  if (!afl->shm.state_mode || !afl->shm.state_map) { return; }

  if (!afl->virgin_state) {

    afl->virgin_state = ck_alloc(STATE_MAP_SIZE);
    memset(afl->virgin_state, 255, STATE_MAP_SIZE);

  }

  if (!afl->state_seen) {

    afl->state_seen = ck_alloc(STATE_MAP_SIZE);
    memset(afl->state_seen, 255, STATE_MAP_SIZE);

  }

  afl_shm_state_env_set(&afl->shm);

}

/* Clear the state map before an execution, the way the coverage map is
   cleared. The target does the same at child start, so a target that never
   reaches a transition still leaves an empty map behind. */

void state_map_reset(afl_state_t *afl) {

  if (likely(!afl->shm.state_map)) { return; }

  memset(afl->shm.state_map->map, 0, STATE_MAP_SIZE);
  afl->shm.state_map->cur_state = 0;
  afl->shm.state_map->prev_state = 0;
  afl->shm.state_map->action = 0;
  afl->shm.state_map->transitions = 0;
  afl->shm.state_map->hot_off = 0;
  afl->shm.state_map->hot_len = 0;

}

/* Fold the state map of the last execution into a map of the same size.
   Returns non-zero when a (prev, cur, action) triple appeared that the map
   had not recorded before. Deliberately does not reuse has_new_bits(), which
   is hardwired to afl->fsrv.trace_bits and to the coverage map size. */

static u8 state_map_fold(afl_state_t *afl, u8 *map, u8 count) {

  u64 *current = (u64 *)afl->shm.state_map->map;
  u64 *virgin = (u64 *)map;
  u32  i = STATE_MAP_SIZE >> 3;
  u8   ret = 0;

  while (i--) {

    if (unlikely(*current & *virgin)) {

      u8 *cur = (u8 *)current;
      u8 *vir = (u8 *)virgin;
      u32 j;

      for (j = 0; j < 8; ++j) {

        if (cur[j] && vir[j] == 0xff) {

          if (count) { ++afl->state_transitions_found; }
          ret = 1;

        }

      }

      *virgin &= ~*current;

    }

    ++current;
    ++virgin;

  }

  return ret;

}

/* Record the transitions of the last execution for reporting. This runs for
   every execution, whether or not the state signal is trusted yet, and never
   touches the map that admission decisions are made against. */

void state_map_observe(afl_state_t *afl) {

  if (likely(!afl->shm.state_map || !afl->state_seen)) { return; }

  (void)state_map_fold(afl, afl->state_seen, 1);

}

/* Fold the state map of the last execution into afl->virgin_state, which is
   only ever consumed once the utility test trusts the state signal. Consuming
   it earlier would spend every transition found during the observational
   phase, and none of them could justify saving an input afterwards. */

u8 state_map_has_new(afl_state_t *afl) {

  if (likely(!afl->shm.state_map || !afl->virgin_state)) { return 0; }

  return state_map_fold(afl, afl->virgin_state, 0);

}

/* Remember which state this queue entry ends in, so item 16 can group
   entries and item 9 can bucket them. */

void state_map_record(afl_state_t *afl, struct queue_entry *q) {

  if (likely(!afl->shm.state_map) || !q) { return; }

  q->state_id = afl->shm.state_map->cur_state;

}

/* Share of the state map that has ever been hit, in hundredths of a percent.
   Whole percent is useless here: a real target reaching 169 of 65536 slots
   would report 0%. The caller divides by 100. */

u32 state_map_density(afl_state_t *afl) {

  if (!afl->state_seen) { return 0; }

  u32 hit = 0, i;

  for (i = 0; i < STATE_MAP_SIZE; ++i) {

    if (afl->state_seen[i] != 0xff) { ++hit; }

  }

  return (u32)(((u64)hit * 10000) / STATE_MAP_SIZE);

}

/* --- item 16: is this state useful? --- */

static int state_id_cmp(const void *a, const void *b) {

  const struct queue_entry *qa = *(struct queue_entry *const *)a;
  const struct queue_entry *qb = *(struct queue_entry *const *)b;

  if (qa->state_id < qb->state_id) { return -1; }
  if (qa->state_id > qb->state_id) { return 1; }
  return 0;

}

/* Read a queue entry and append the probe action to it. Returns the buffer,
   NULL when the entry could not be read. */

static u8 *state_probe_input(struct queue_entry *q, u8 *probe, u32 probe_len,
                             u32 *len_out) {

  u32 base = MIN(q->len, (u32)MAX_FILE);
  s32 fd = open((char *)q->fname, O_RDONLY);

  if (fd < 0) { return NULL; }

  u8 *buf = ck_alloc(base + probe_len);

  if (base && read(fd, buf, base) != (ssize_t)base) {

    close(fd);
    ck_free(buf);
    return NULL;

  }

  close(fd);
  memcpy(buf + base, probe, probe_len);
  *len_out = base + probe_len;

  return buf;

}

/* Run one probe input. Reports the state it ends in, how many transitions it
   walked, how it terminated, and whether it produced coverage that
   virgin_scratch had not seen. virgin_scratch is a throwaway copy of
   afl->virgin_bits, refreshed per run so both members of a pair are asked the
   same question about the same starting knowledge - otherwise the first run
   would consume the novelty and the second would always disagree.
   Returns 0 when the run could not be used. */

static u8 state_probe_run(afl_state_t *afl, u8 *buf, u32 len,
                          u8 *virgin_scratch, u32 *state_out, u8 *novel_out,
                          u32 *trans_out, u8 *fault_out) {

  void *use = buf;

  memcpy(virgin_scratch, afl->virgin_bits, afl->fsrv.map_size);
  state_map_reset(afl);

  if (unlikely(!write_to_testcase(afl, &use, len, 1))) { return 0; }

  fsrv_run_result_t fault =
      fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  ++afl->slow_path_execs;

  if (afl->stop_soon || fault == FSRV_RUN_ERROR) { return 0; }

  classify_counts(&afl->fsrv);

  *novel_out = has_new_bits(afl, virgin_scratch) ? 1 : 0;
  *state_out = afl->shm.state_map->cur_state;
  *trans_out = afl->shm.state_map->transitions;
  *fault_out = (u8)fault;

  return 1;

}

/* The hard gate of item 16: a state signal may only influence which inputs
   are saved once inputs that the state definition calls identical actually
   behave identically. Two entries from the same state get the same freshly
   drawn action appended; the pair only counts when the appended bytes made
   both targets walk further than they did without them, and it agrees when
   both end in the same state, terminate the same way, and give the same
   answer to "did new coverage appear". */

void state_utility_test(afl_state_t *afl) {

  if (likely(!(afl->state_mode & STATE_MODE_SMAP))) { return; }
  if (!afl->shm.state_map || !afl->virgin_state) { return; }
  if (!afl->fsrv.fsrv_pid || afl->stop_soon) { return; }

  if (afl->state_utility_cycle &&
      afl->queue_cycle - afl->state_utility_cycle < STATE_UTILITY_CYCLES) {

    return;

  }

  u32 i, cand_cnt = 0;

  for (i = 0; i < afl->queued_items; ++i) {

    struct queue_entry *q = afl->queue_buf[i];
    if (!q->disabled && q->state_id && q->len) { ++cand_cnt; }

  }

  if (cand_cnt < STATE_UTILITY_MIN_ENTRIES) { return; }

  struct queue_entry **cand = ck_alloc(cand_cnt * sizeof(struct queue_entry *));
  u32                  n = 0;

  for (i = 0; i < afl->queued_items && n < cand_cnt; ++i) {

    struct queue_entry *q = afl->queue_buf[i];
    if (!q->disabled && q->state_id && q->len) { cand[n++] = q; }

  }

  qsort(cand, n, sizeof(struct queue_entry *), state_id_cmp);

  /* Pair up entries within each state_id group, preferring members whose
     coverage traces differ - a pair of near-identical inputs proves nothing. */

  struct queue_entry **pair_a =
      ck_alloc(STATE_UTILITY_MAX_PAIRS * sizeof(struct queue_entry *));
  struct queue_entry **pair_b =
      ck_alloc(STATE_UTILITY_MAX_PAIRS * sizeof(struct queue_entry *));
  u8 *used = ck_alloc(n);
  u32 pairs = 0, g_start = 0;

  while (g_start < n && pairs < STATE_UTILITY_MAX_PAIRS) {

    u32 g_end = g_start;

    while (g_end < n && cand[g_end]->state_id == cand[g_start]->state_id) {

      ++g_end;

    }

    u32 a;

    for (a = g_start; a < g_end && pairs < STATE_UTILITY_MAX_PAIRS; ++a) {

      if (used[a]) { continue; }

      u32 fallback = g_end, pick = g_end, b;

      for (b = a + 1; b < g_end; ++b) {

        if (used[b]) { continue; }
        if (fallback == g_end) { fallback = b; }
        if (cand[b]->exec_cksum != cand[a]->exec_cksum) {

          pick = b;
          break;

        }

      }

      if (pick == g_end) { pick = fallback; }
      if (pick == g_end) { continue; }

      used[a] = 1;
      used[pick] = 1;
      pair_a[pairs] = cand[a];
      pair_b[pairs] = cand[pick];
      ++pairs;

    }

    g_start = g_end;

  }

  if (pairs < STATE_UTILITY_MIN_PAIRS) {

    ck_free(used);
    ck_free(pair_b);
    ck_free(pair_a);
    ck_free(cand);
    return;

  }

  /* One probe action, drawn once and appended unchanged to both members of
     every pair, so every pair is asked about the same next action. */

  u32 probe_len = 1 + rand_below(afl, 32);
  u8 *probe = ck_alloc(probe_len);

  for (i = 0; i < probe_len; ++i) {

    probe[i] = (u8)rand_below(afl, 256);

  }

  u8 *virgin_scratch = ck_alloc(afl->fsrv.map_size);
  u64 usable = 0, agree = 0, ignored = 0;

  for (i = 0; i < pairs && !afl->stop_soon; ++i) {

    u32 len_a = 0, len_b = 0;
    u8 *buf_a = state_probe_input(pair_a[i], probe, probe_len, &len_a);
    u8 *buf_b = NULL;

    if (buf_a) {

      buf_b = state_probe_input(pair_b[i], probe, probe_len, &len_b);

    }

    if (!buf_a || !buf_b) {

      if (buf_a) { ck_free(buf_a); }
      if (buf_b) { ck_free(buf_b); }
      continue;

    }

    u32 state_a = 0, state_b = 0, trans_a = 0, trans_b = 0;
    u32 base_a = 0, base_b = 0, base_state = 0;
    u8  novel_a = 0, novel_b = 0, fault_a = 0, fault_b = 0;
    u8  base_novel = 0, base_fault = 0;

    /* Each entry is run first without the probe. Only when the appended
       bytes walk the target further than its own bytes did has an action
       actually been performed - otherwise the pair proves nothing, because
       two inputs that both ignore their suffix trivially agree. */

    if (state_probe_run(afl, buf_a, len_a - probe_len, virgin_scratch,
                        &base_state, &base_novel, &base_a, &base_fault) &&
        state_probe_run(afl, buf_b, len_b - probe_len, virgin_scratch,
                        &base_state, &base_novel, &base_b, &base_fault) &&
        state_probe_run(afl, buf_a, len_a, virgin_scratch, &state_a, &novel_a,
                        &trans_a, &fault_a) &&
        state_probe_run(afl, buf_b, len_b, virgin_scratch, &state_b, &novel_b,
                        &trans_b, &fault_b)) {

      if (trans_a <= base_a || trans_b <= base_b) {

        ++ignored;

      } else {

        ++usable;

        if (state_a == state_b && novel_a == novel_b && fault_a == fault_b) {

          ++agree;

        }

      }

    }

    ck_free(buf_a);
    ck_free(buf_b);

  }

  ck_free(virgin_scratch);
  ck_free(probe);
  ck_free(used);
  ck_free(pair_b);
  ck_free(pair_a);
  ck_free(cand);

  if (unlikely(afl->stop_soon)) { return; }

  afl->state_utility_cycle = afl->queue_cycle;

  if (usable < STATE_UTILITY_MIN_PAIRS) {

    if (ignored) {

      WARNF(
          "state signal not testable: the probe action was ignored by %llu of "
          "%llu pairs.\n    Appending bytes does not make this target take "
          "another step, so\n    same-state inputs cannot be compared. State "
          "transitions stay a metadata\n    note and do not influence saving.",
          ignored, ignored + usable);

    }

    return;

  }

  afl->state_utility_pairs = usable;
  afl->state_utility_agree = agree;
  afl->state_utility_pct = (100.0 * (double)agree) / (double)usable;

  u32 threshold = afl->afl_env.afl_state_utility_threshold
                      ? (u32)afl->afl_env.afl_state_utility_threshold
                      : STATE_UTILITY_THRESHOLD;

  u8 was_trusted = afl->state_signal_trusted;

  if (afl->state_utility_pct >= (double)threshold) {

    afl->state_signal_trusted = 1;
    OKF("state signal validated: %llu/%llu same-state pairs behaved the same "
        "(%u%%).\n    New state transitions now count as a reason to save an "
        "input.",
        agree, usable, (u32)afl->state_utility_pct);

  } else {

    afl->state_signal_trusted = 0;
    WARNF(
        "state signal NOT validated: %llu/%llu same-state pairs behaved the "
        "same (%u%%).\n    Inputs the state definition calls identical keep "
        "behaving differently, so\n    the definition is merging real states "
        "and needs one more field.\n    State transitions stay a metadata "
        "note and do not influence saving.",
        agree, usable, (u32)afl->state_utility_pct);

  }

  /* The state bucket of a shelf cell is only used while the signal is
     trusted, so a change of that verdict re-keys every cached cell. Leaving
     the old ones in place would mix two partitions in one shelf. */

  if (was_trusted != afl->state_signal_trusted &&
      (afl->state_mode & STATE_MODE_DEEP)) {

    for (i = 0; i < afl->queued_items; ++i) {

      struct queue_entry *q = afl->queue_buf[i];

      if (likely(q != NULL)) { q->shelf_cell = state_shelf_cell(afl, q); }

    }

    afl->score_changed = 1;

  }

}

