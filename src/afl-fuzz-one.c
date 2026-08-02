/*
   american fuzzy lop++ - fuzze_one routines in different flavours
   ---------------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include "afl-ijon-min.h"
#include <string.h>
#include <limits.h>
#include "cmplog.h"
#include "afl-mutations.h"

// Ensure the new mopt will not be left behind if we change havoc
_Static_assert(MOPT_OP_MAX == MUT_MAX, "MOPT_OP_MAX must equal MUT_MAX");
_Static_assert(MOPT_LUT_SIZE == MUT_STRATEGY_ARRAY_SIZE,
               "MOPT_LUT_SIZE must equal MUT_STRATEGY_ARRAY_SIZE");

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) { return 1; }

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) {

    ++sh;
    xor_val >>= 1;

  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) { return 1; }

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) { return 0; }

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) {

    return 1;

  }

  return 0;

}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) { return 1; }

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; (u8)i < blen; ++i) {

    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX) { return 1; }

  }

  if (blen == 1) { return 0; }

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; (u8)i < blen / 2; ++i) {

    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) {

      return 1;

    }

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX) {

      return 1;

    }

  }

  return 0;

}

/* Finalize trim bookkeeping. Guarded VP owners may need one deferred retry
   after ownership drops so they can trim once without VP constraints. */
static inline void vp_finalize_trim_state(struct queue_entry *q,
                                          u8 was_guarded_trim) {

  if (was_guarded_trim) {

    q->vp_trim_deferred = 1;
    if (!q->vp_ref_cnt) {

      q->vp_trim_deferred = 0;
      q->trim_done = 0;

    } else {

      q->trim_done = 1;

    }

  } else {

    q->vp_trim_deferred = 0;
    q->trim_done = 1;

  }

}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) { return 1; }

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; ++i) {

    for (j = 0; j < sizeof(interesting_8); ++j) {

      u32 tval = (old_val & ~(0xffU << (i * 8))) |
                 ((u32)(u8)interesting_8[j] << (i * 8));

      if (new_val == tval) { return 1; }

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) { return 0; }

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; (u8)i < blen - 1; ++i) {

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      u32 tval = (old_val & ~(0xffffU << (i * 8))) |
                 ((u32)(u16)interesting_16[j] << (i * 8));

      if (new_val == tval) { return 1; }

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffffU << (i * 8))) |
               ((u32)SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) { return 1; }

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      if (new_val == (u32)interesting_32[j]) { return 1; }

    }

  }

  return 0;

}

#ifndef IGNORE_FINDS

/* Helper function to compare buffers; returns first and last differing offset.
   We use this to find reasonable locations for splicing two files. */

static void locate_diffs(u8 *ptr1, u8 *ptr2, u32 len, s32 *first, s32 *last) {

  s32 f_loc = -1;
  s32 l_loc = -1;
  u32 pos;

  for (pos = 0; pos < len; ++pos) {

    if (*(ptr1++) != *(ptr2++)) {

      if (f_loc == -1) { f_loc = pos; }
      l_loc = pos;

    }

  }

  *first = f_loc;
  *last = l_loc;

  return;

}

#endif                                                     /* !IGNORE_FINDS */

/* Take the current entry from the queue, fuzz it for a while. This
   function is a tad too long... returns 0 if fuzzed successfully, 1 if
   skipped or bailed out.
   This is entry point for the mutator. */
u8 fuzz_one(afl_state_t *afl) {

  u32 len, temp_len;
  u32 j;
  u32 i;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt = 0, prev_cksum, _prev_cksum;
  u32 splice_cycle = 0, perf_score = 100, orig_perf;

  u8  ret_val = 1, doing_det = 0;
  u8  was_doing_ijon = afl->is_doing_ijon;
  u8  saved_frameshift_disabled = afl->afl_env.afl_frameshift_disabled;
  u32 saved_cur_depth = afl->cur_depth;
#ifdef INTROSPECTION
  u8 input_is_ascii = afl->queue_cur->is_ascii;
#endif

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

  /* IJON: If we're doing IJON, skip deterministic stages and go directly to
   * mutation */
  if (unlikely(was_doing_ijon)) {

    /* Use IJON input data that was selected by the queue scheduler */
    len = afl->ijon_input_len;
    if (unlikely(!len || len > afl->max_length || !afl->ijon_input_data)) {

      afl->is_doing_ijon = 0;
      return 1;

    }

    in_buf = afl_realloc(AFL_BUF_PARAM(in), len);
    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!in_buf || !out_buf)) { PFATAL("alloc"); }
    orig_in = in_buf;
    memcpy(in_buf, afl->ijon_input_data, len);
    memcpy(out_buf, afl->ijon_input_data, len);
#ifdef INTROSPECTION
    input_is_ascii = check_if_text_buf(in_buf, len) == len;
#endif

    /* Setup variables for the mutation stages */
    temp_len = len;
    orig_hit_cnt = afl->queued_items + afl->saved_crashes;
    havoc_queued = afl->queued_items;
    perf_score = 100;
    orig_perf = perf_score;
    afl->cur_depth = 0;
    afl->subseq_tmouts = 0;
    afl->afl_env.afl_frameshift_disabled = 1;

    if (unlikely(common_fuzz_stuff(afl, out_buf, len))) { goto abandon_entry; }

    /* Jump directly to the mutation stages */
    goto custom_mutator_stage;

  }

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (afl->queue_cur->depth > 1) return 1;

#else

  if (unlikely(afl->custom_mutators_count)) {

    /* The custom mutator will decide to skip this test case or not. */

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_queue_get &&
          !el->afl_custom_queue_get(el->data, afl->queue_cur->fname)) {

        /* Abandon the entry and return that we skipped it.
           If we don't do this then when the entry is smallest_favored then
           we get caught in an infinite loop calling afl_custom_queue_get
           on smallest_favored */
        ret_val = 1;
        goto abandon_entry;

      }

    });

  }

  if (likely(afl->pending_favored)) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((afl->queue_cur->fuzz_level || !afl->queue_cur->favored) &&
        likely(rand_below(afl, 100) < SKIP_TO_NEW_PROB)) {

      return 1;

    }

  } else if (!afl->non_instrumented_mode && !afl->queue_cur->favored &&

             !afl->prefer_unfuzzed && afl->queued_items > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 && !afl->queue_cur->fuzz_level) {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_NEW_PROB)) { return 1; }

    } else {

      if (likely(rand_below(afl, 100) < SKIP_NFAV_OLD_PROB)) { return 1; }

    }

  }

#endif                                                     /* ^IGNORE_FINDS */

#ifdef _AFL_DOCUMENT_MUTATIONS

  u8 path_buf[PATH_MAX];
  if (afl->do_document == 0) {

    snprintf(path_buf, PATH_MAX, "%s/mutations", afl->out_dir);
    afl->do_document = mkdir(path_buf, 0700);  // if it exists we do not care
    afl->do_document = 1;

  } else {

    afl->do_document = 2;
    afl->stop_soon = 2;

  }

#endif

  if (likely(afl->not_on_tty)) {

    u8 time_tmp[64];

    u_simplestring_time_diff(time_tmp, afl->prev_run_time + get_cur_time(),
                             afl->start_time);

    u32 t_bytes = count_non_255_bytes(afl, afl->virgin_bits);

    if (likely(!afl->afl_env.afl_frameshift_disabled)) {

      u8 search_time[64];
      u_simplestring_time_diff(search_time, afl->fs_stats.total_time_ms + 1, 1);

      u64 average_search_time_ms =
          afl->fs_stats.searched > 0
              ? afl->fs_stats.total_time_ms / afl->fs_stats.searched
              : 0;

      u64 total_runtime_ms =
          afl->prev_run_time + get_cur_time() - afl->start_time;
      double overhead_pct =
          total_runtime_ms > 0
              ? (double)afl->fs_stats.total_time_ms / total_runtime_ms * 100.0
              : 0.0;

      ACTF(
          "Fuzzing test case #%u (%u total, %s%llu crashes saved%s, state: %s, "
          "mode=%s, "
          "perf_score=%0.0f, weight=%0.0f, favorite=%u, was_fuzzed=%u, "
          "exec_us=%llu, hits=%u, map=%u, ascii=%u, run_time=%s, cvg=%.02f%%) "
          "FS (t=%s "
          "(%.2f%%), "
          "st=%llu, avg=%llu ms, found=%u/%u)...",
          afl->current_entry, afl->queued_items,
          afl->saved_crashes != 0 ? cRED : "", afl->saved_crashes, cRST,
          get_fuzzing_state(afl), afl->fuzz_mode ? "exploit" : "explore",
          afl->queue_cur->perf_score, afl->queue_cur->weight,
          afl->queue_cur->favored, afl->queue_cur->was_fuzzed,
          afl->queue_cur->exec_us,
          likely(afl->n_fuzz) ? afl->n_fuzz[afl->queue_cur->n_fuzz_entry] : 0,
          afl->queue_cur->bitmap_size, afl->queue_cur->is_ascii, time_tmp,
          ((double)t_bytes * 100) / afl->fsrv.real_map_size, search_time,
          overhead_pct, afl->fs_stats.search_tests, average_search_time_ms,
          afl->fs_stats.found, afl->fs_stats.searched);
      fflush(stdout);

    } else {

      ACTF(
          "Fuzzing test case #%u (%u total, %s%llu crashes saved%s, state: %s, "
          "mode=%s, "
          "perf_score=%0.0f, weight=%0.0f, favorite=%u, was_fuzzed=%u, "
          "exec_us=%llu, hits=%u, map=%u, ascii=%u, run_time=%s, "
          "cvg=%.02f%%)...",
          afl->current_entry, afl->queued_items,
          afl->saved_crashes != 0 ? cRED : "", afl->saved_crashes, cRST,
          get_fuzzing_state(afl), afl->fuzz_mode ? "exploit" : "explore",
          afl->queue_cur->perf_score, afl->queue_cur->weight,
          afl->queue_cur->favored, afl->queue_cur->was_fuzzed,
          afl->queue_cur->exec_us,
          likely(afl->n_fuzz) ? afl->n_fuzz[afl->queue_cur->n_fuzz_entry] : 0,
          afl->queue_cur->bitmap_size, afl->queue_cur->is_ascii, time_tmp,
          ((double)t_bytes * 100) / afl->fsrv.real_map_size);
      fflush(stdout);

    }

  }

  orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);
  len = afl->queue_cur->len;

  out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
  if (unlikely(!out_buf)) { PFATAL("alloc"); }

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(afl->queue_cur->cal_failed)) {

    u8 res = FSRV_RUN_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      afl->queue_cur->exec_cksum = 0;

      virgin_undo_arm(afl);

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (unlikely(res == FSRV_RUN_ERROR)) {

        FATAL("Unable to execute target application");

      }

      if (unlikely(afl->queue_cur->cal_failed) && likely(!afl->stop_soon)) {

        virgin_undo_rollback(afl, afl->queue_cur);

      } else {

        virgin_undo_commit(afl);

      }

    }

    if (unlikely(afl->stop_soon) || res != afl->crash_mode) {

      ++afl->cur_skipped_items;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (unlikely(!afl->non_instrumented_mode && !afl->queue_cur->trim_done &&
               !afl->disable_trim)) {

    u32 old_len = afl->queue_cur->len;
    u8  was_guarded_trim =
        (u8)(afl->value_profile_active && afl->queue_cur->vp_ref_cnt);

    u8 res = trim_case(afl, afl->queue_cur, in_buf);
    orig_in = in_buf = queue_testcase_get(afl, afl->queue_cur);

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (unlikely(afl->stop_soon)) {

      ++afl->cur_skipped_items;
      goto abandon_entry;

    }

    vp_finalize_trim_state(afl->queue_cur, was_guarded_trim);

    len = afl->queue_cur->len;

    /* maybe current entry is not ready for splicing anymore */
    if (unlikely(len <= 4 && old_len > 4)) --afl->ready_for_splicing_count;

  }

  memcpy(out_buf, in_buf, len);

  /**************
   * FRAMESHIFT *
   **************/

  if (likely(!afl->afl_env.afl_frameshift_disabled)) {

    if (unlikely(afl->queue_cur->fs_status == 0)) {

      /* FrameShift has not run on this input; the stage gates admission on the
         cumulative overhead budget, then analyses the input with the full
         per-input time budget. */
      frameshift_stage(afl);

    }

    /* If we have structure information for this input, reload it to prepare for
     * fuzzing. */
    if (afl->queue_cur->fs_status != 0) { fs_clone_meta(afl); }

  }

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  if (likely(!afl->old_seed_selection))
    orig_perf = perf_score = afl->queue_cur->perf_score;
  else
    afl->queue_cur->perf_score = orig_perf = perf_score =
        calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score <= 0 && afl->active_items > 1)) {

    goto abandon_entry;

  }

  if (unlikely(afl->queue_cur->handicap)) {

    if (afl->queue_cur->handicap >= 4) {

      afl->queue_cur->handicap -= 4;

    } else {

      --afl->queue_cur->handicap;

    }

    if (unlikely(++afl->pending_reinit > (afl->active_items >> 3))) {

      afl->reinit_table = 1;

    }

  }

  if (unlikely(afl->shm.cmplog_mode &&
               afl->queue_cur->colorized < afl->cmplog_lvl &&
               (u32)len <= afl->cmplog_max_filesize)) {

    if (unlikely(len < 4)) {

      afl->queue_cur->colorized = CMPLOG_LVL_MAX;

    } else {

      if (afl->queue_cur->favored || afl->cmplog_lvl == 3 ||
          (afl->cmplog_lvl == 2 &&
           (afl->queue_cur->tc_ref ||
            afl->fsrv.total_execs % afl->queued_items <= 10)) ||
          (!afl->pending_favored &&
           afl->fsrv.total_execs - afl->last_edge_execs >= CMPLOG_I2S_EXECS)) {

        if (input_to_state_stage(afl, in_buf, out_buf, len)) {

          goto abandon_entry;

        }

      }

    }

  }

  u64 before_det_time = get_cur_time();
  afl->det_start_time = before_det_time;
  afl->det_start_execs = afl->fsrv.total_execs;
#ifdef INTROSPECTION

  u64 before_havoc_time;
  u32 before_det_findings = afl->queued_items,
      before_det_edges = count_non_255_bytes(afl, afl->virgin_bits),
      before_havoc_findings, before_havoc_edges;
  u8 is_logged = 0;

#endif
  u8 *skip_eff_map = afl->queue_cur->skipdet_e->skip_eff_map;
  /* Favored VP-only entries that still own unresolved comparison work are
     routed straight to havoc/custom stages. Other VP-only entries may still
     run deterministic stages. */
  u8 vp_skip_det_candidate =
      (u8)(afl->value_profile_active && afl->queue_cur->favored &&
           afl->queue_cur->vp_only &&
           vp_queue_has_unresolved_work(afl->queue_cur));

  if (!afl->skip_deterministic && !vp_skip_det_candidate) {

    if (!skip_deterministic_stage(afl, in_buf, out_buf, len)) {

      goto abandon_entry;

    }

    skip_eff_map = afl->queue_cur->skipdet_e->skip_eff_map;

  }

  /* Skip right away if -d is given, if it has not been chosen sufficiently
     often to warrant the expensive deterministic stage (fuzz_level), or
     if it has gone through deterministic testing in earlier, resumed runs
     (passed_det). */
  /* If skipdet skips this seed (or finds no effective bytes), skip the whole
     deterministic stage. */

  if (likely(afl->skip_deterministic) ||
      likely(!afl->queue_cur->skipdet_e->done_eff) ||
      likely(afl->queue_cur->passed_det) || likely(vp_skip_det_candidate) ||
      likely(!afl->queue_cur->skipdet_e->quick_eff_bytes) ||
      likely(perf_score <
             (afl->queue_cur->depth * 30 <= afl->havoc_max_mult * 100
                  ? afl->queue_cur->depth * 30
                  : afl->havoc_max_mult * 100))) {

    goto custom_mutator_stage;

  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this main instance. */

  if (unlikely(afl->main_node_max &&
               (afl->queue_cur->exec_cksum % afl->main_node_max) !=
                   afl->main_node_id - 1)) {

    goto custom_mutator_stage;

  }

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b)                     \
  do {                                        \
                                              \
    u8 *_arf = (u8 *)(_ar);                   \
    u32 _bf = (_b);                           \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf) & 7)); \
                                              \
  } while (0)

  /* Single walking bit. */

  afl->stage_short = "flip1";
  afl->stage_max = len << 3;
  afl->stage_name = "bitflip 1/1";

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  /* Get a clean cksum. */

  if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

  prev_cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
  _prev_cksum = prev_cksum;

  /* Now flip bits. */

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    if (!bitmap_read(skip_eff_map, afl->stage_cur_byte)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    FLIP_BIT(out_buf, afl->stage_cur);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT1-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);

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

    if (!afl->non_instrumented_mode && (afl->stage_cur & 7) == 7) {

      u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      if (afl->stage_cur == afl->stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA) {

          maybe_add_auto(afl, a_collect, a_len);

        }

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != _prev_cksum) {

        if (a_len < MAX_AUTO_EXTRA) {

          a_collect[a_len] = out_buf[afl->stage_cur >> 3];

        }

        ++a_len;

      }

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP1] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* Two walking bits. */

  afl->stage_name = "bitflip 2/1";
  afl->stage_short = "flip2";
  afl->stage_max = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    if (!bitmap_read(skip_eff_map, afl->stage_cur_byte)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT2-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP2] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* Four walking bits. */

  afl->stage_name = "bitflip 4/1";
  afl->stage_short = "flip4";
  afl->stage_max = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    if (!bitmap_read(skip_eff_map, afl->stage_cur_byte)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT4-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP4] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* Walking byte. */

  afl->stage_name = "bitflip 8/8";
  afl->stage_short = "flip8";
  afl->stage_max = len;

  orig_hit_cnt = new_hit_cnt;
  prev_cksum = _prev_cksum;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur;

    if (!bitmap_read(skip_eff_map, afl->stage_cur_byte)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    out_buf[afl->stage_cur] ^= 0xFF;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT8-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

    out_buf[afl->stage_cur] ^= 0xFF;

  }

  /* New effective bytes calculation. */

  for (i = 0; i < len; i++) {

    if (bitmap_read(skip_eff_map, i)) afl->blocks_eff_select += 1;

  }

  afl->blocks_eff_total += len;

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP8] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* Two walking bytes. */

  if (len < 2) { goto skip_bitflip; }

  afl->stage_name = "bitflip 16/8";
  afl->stage_short = "flip16";
  afl->stage_cur = 0;
  afl->stage_max = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    INSERT16(out_buf, i, EXTRACT16(out_buf, i) ^ 0xFFFF);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT16-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    INSERT16(out_buf, i, EXTRACT16(out_buf, i) ^ 0xFFFF);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP16] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  if (len < 4) { goto skip_bitflip; }

  /* Four walking bytes. */

  afl->stage_name = "bitflip 32/8";
  afl->stage_short = "flip32";
  afl->stage_cur = 0;
  afl->stage_max = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    INSERT32(out_buf, i, EXTRACT32(out_buf, i) ^ 0xFFFFFFFF);

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s FLIP_BIT32-%u",
             afl->queue_cur->fname, afl->stage_cur);
#endif

    if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
    ++afl->stage_cur;

    INSERT32(out_buf, i, EXTRACT32(out_buf, i) ^ 0xFFFFFFFF);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP32] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

skip_bitflip:

  if (afl->no_arith) { goto skip_arith; }

  /**********************
   * ARITHMETIC INC/DEC *
   **********************/

  /* 8-bit arithmetics. */

  afl->stage_name = "arith 8/8";
  afl->stage_short = "arith8";
  afl->stage_cur = 0;
  afl->stage_max = 2 * len * ARITH_MAX;

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = j;
        out_buf[i] = orig + j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH8+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = -j;
        out_buf[i] = orig - j;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH8--%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* 16-bit arithmetics, both endians. */

  if (len < 2) { goto skip_arith; }

  afl->stage_name = "arith 16/8";
  afl->stage_short = "arith16";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len - 1; ++i) {

    u16 orig = EXTRACT16(out_buf, i);

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u16 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP16(SWAP16(orig) + j),
          r4 = orig ^ SWAP16(SWAP16(orig) - j);

      /* Try little endian addition and subtraction first. Do it only
         if the operation would affect more than one byte (hence the
         & 0xff overflow checks) and if it couldn't be a product of
         a bitflip. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xff) + j > 0xff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        INSERT16(out_buf, i, orig + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        INSERT16(out_buf, i, orig - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16--%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian comes next. Same deal. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        INSERT16(out_buf, i, SWAP16(SWAP16(orig) + j));

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16+BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        INSERT16(out_buf, i, SWAP16(SWAP16(orig) - j));

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH16_BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      INSERT16(out_buf, i, orig);

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH16] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* 32-bit arithmetics, both endians. */

  if (len < 4) { goto skip_arith; }

  afl->stage_name = "arith 32/8";
  afl->stage_short = "arith32";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len - 3; ++i) {

    u32 orig = EXTRACT32(out_buf, i);

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u32 r1 = orig ^ (orig + j), r2 = orig ^ (orig - j),
          r3 = orig ^ SWAP32(SWAP32(orig) + j),
          r4 = orig ^ SWAP32(SWAP32(orig) - j);

      /* Little endian first. Same deal as with 16-bit: we only want to
         try if the operation would have effect on more than two bytes. */

      afl->stage_val_type = STAGE_VAL_LE;

      if ((orig & 0xffff) + j > 0xffff && !could_be_bitflip(r1)) {

        afl->stage_cur_val = j;
        INSERT32(out_buf, i, orig + j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32+-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((orig & 0xffff) < (u32)j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        INSERT32(out_buf, i, orig - j);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32_-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      /* Big endian next. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        INSERT32(out_buf, i, SWAP32(SWAP32(orig) + j));

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32+BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((SWAP32(orig) & 0xffff) < (u32)j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        INSERT32(out_buf, i, SWAP32(SWAP32(orig) - j));

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s ARITH32_BE-%u-%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      INSERT32(out_buf, i, orig);

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH32] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

skip_arith:

  /**********************
   * INTERESTING VALUES *
   **********************/

  afl->stage_name = "interest 8/8";
  afl->stage_short = "int8";
  afl->stage_cur = 0;
  afl->stage_max = len * sizeof(interesting_8);

  afl->stage_val_type = STAGE_VAL_LE;

  orig_hit_cnt = new_hit_cnt;

  /* Setting 8-bit integers. */

  for (i = 0; i < (u32)len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 0; j < (u32)sizeof(interesting_8); ++j) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {

        --afl->stage_max;
        continue;

      }

      afl->stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation), "%s INTERESTING8_%u_%u",
               afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      out_buf[i] = orig;
      ++afl->stage_cur;

    }

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST8] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* Setting 16-bit integers, both endians. */

  if (afl->no_arith || len < 2) { goto skip_interest; }

  afl->stage_name = "interest 16/8";
  afl->stage_short = "int16";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = EXTRACT16(out_buf, i);

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      afl->stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        INSERT16(out_buf, i, interesting_16[j]);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s INTERESTING16_%u_%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s INTERESTING16BE_%u_%u", afl->queue_cur->fname, i, j);
#endif

        INSERT16(out_buf, i, SWAP16(interesting_16[j]));
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    INSERT16(out_buf, i, orig);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST16] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  if (len < 4) { goto skip_interest; }

  /* Setting 32-bit integers, both endians. */

  afl->stage_name = "interest 32/8";
  afl->stage_short = "int32";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = EXTRACT32(out_buf, i);

    /* Let's consult the effector map... */

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      afl->stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        INSERT32(out_buf, i, interesting_32[j]);

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation), "%s INTERESTING32_%u_%u",
                 afl->queue_cur->fname, i, j);
#endif

        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

#ifdef INTROSPECTION
        snprintf(afl->mutation, sizeof(afl->mutation),
                 "%s INTERESTING32BE_%u_%u", afl->queue_cur->fname, i, j);
#endif

        INSERT32(out_buf, i, SWAP32(interesting_32[j]));
        if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }
        ++afl->stage_cur;

      } else {

        --afl->stage_max;

      }

    }

    INSERT32(out_buf, i, orig);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST32] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!afl->extras_cnt) { goto skip_user_extras; }

  /* Overwrite with user-supplied extras. */

  afl->stage_name = "user extras (over)";
  afl->stage_short = "ext_UO";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < afl->extras_cnt; ++j) {

      /* Skip extras probabilistically if afl->extras_cnt > AFL_MAX_DET_EXTRAS.
         Also skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((afl->extras_cnt > afl->max_det_extras &&
           rand_below(afl, afl->extras_cnt) >= afl->max_det_extras) ||
          afl->extras[j].len > len - i ||
          !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len)) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->extras[j].len;
      memcpy(out_buf + i, afl->extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRA_OVERWRITE] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRA_OVERWRITE] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* Insertion of user-supplied extras. */

  afl->stage_name = "user extras (insert)";
  afl->stage_short = "ext_UI";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), len + MAX_DICT_FILE);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }

  for (i = 0; i <= (u32)len; ++i) {

    if (!bitmap_read(skip_eff_map, i % len)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 0; j < afl->extras_cnt; ++j) {

      if (len + afl->extras[j].len > MAX_FILE) {

        --afl->stage_max;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, afl->extras[j].data, afl->extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + afl->extras[j].len, out_buf + i, len - i);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation), "%s EXTRAS_insert-%u-%u",
               afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_EXTRA_INSERT] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRA_INSERT] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

skip_user_extras:

  if (!afl->a_extras_cnt) { goto skip_extras; }

  afl->stage_name = "auto extras (over)";
  afl->stage_short = "ext_AO";
  afl->stage_cur = 0;
  afl->stage_max = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS) * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < (u32)len; ++i) {

    u32 last_len = 0;

    if (!bitmap_read(skip_eff_map, i)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    u32 min_extra_len = MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS);
    for (j = 0; j < min_extra_len; ++j) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (afl->a_extras[j].len > len - i ||
          !memcmp(afl->a_extras[j].data, out_buf + i, afl->a_extras[j].len)) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->a_extras[j].len;
      memcpy(out_buf + i, afl->a_extras[j].data, last_len);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s AUTO_EXTRAS_overwrite-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, out_buf, len)) { goto abandon_entry; }

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_AUTO_EXTRA_OVERWRITE] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_AUTO_EXTRA_OVERWRITE] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

  /* Insertion of auto extras. */

  afl->stage_name = "auto extras (insert)";
  afl->stage_short = "ext_AI";
  afl->stage_cur = 0;
  afl->stage_max = afl->a_extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = afl_realloc(AFL_BUF_PARAM(ex), len + MAX_DICT_FILE);
  if (unlikely(!ex_tmp)) { PFATAL("alloc"); }

  for (i = 0; i <= (u32)len; ++i) {

    if (!bitmap_read(skip_eff_map, i % len)) continue;

    if (is_det_timeout(afl, 0)) { goto custom_mutator_stage; }

    afl->stage_cur_byte = i;

    for (j = 0; j < afl->a_extras_cnt; ++j) {

      if (len + afl->a_extras[j].len > MAX_FILE) {

        --afl->stage_max;
        continue;

      }

      /* Insert token */
      memcpy(ex_tmp + i, afl->a_extras[j].data, afl->a_extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + afl->a_extras[j].len, out_buf + i, len - i);

#ifdef INTROSPECTION
      snprintf(afl->mutation, sizeof(afl->mutation),
               "%s AUTO_EXTRAS_insert-%u-%u", afl->queue_cur->fname, i, j);
#endif

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->a_extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_AUTO_EXTRA_INSERT] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_AUTO_EXTRA_INSERT] += afl->stage_max;
#ifdef INTROSPECTION
  afl->queue_cur->stats_mutated += afl->stage_max;
#endif

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!afl->queue_cur->passed_det) { mark_as_det_done(afl, afl->queue_cur); }

custom_mutator_stage:
  /*******************
   * CUSTOM MUTATORS *
   *******************/

  if (likely(!afl->custom_mutators_count)) { goto havoc_stage; }

  afl->stage_name = "custom mutator";
  afl->stage_short = "custom";
  afl->stage_cur = 0;
  afl->stage_val_type = STAGE_VAL_NONE;
  bool has_custom_fuzz = false;
  u32  shift = unlikely(afl->custom_only) ? 7 : 8;
  afl->stage_max = (HAVOC_CYCLES * perf_score / afl->havoc_div) >> shift;

  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  const u32 max_seed_size = MAX_FILE, saved_max = afl->stage_max;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

#ifdef INTROSPECTION
  afl->mutation[0] = 0;
#endif

  LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

    if (el->afl_custom_fuzz) {

      havoc_queued = afl->queued_items;

      afl->current_custom_fuzz = el;
      afl->stage_name = el->name_short;

      if (el->afl_custom_fuzz_count) {

        afl->stage_max = el->afl_custom_fuzz_count(el->data, out_buf, len);

      } else {

        afl->stage_max = saved_max;

      }

      has_custom_fuzz = true;

      afl->stage_short = el->name_short;

      if (afl->stage_max) {

        for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;
             ++afl->stage_cur) {

          struct queue_entry *target = NULL;
          u32                 tid;
          u8                 *new_buf = NULL;
          u32                 target_len = 0;

          /* check if splicing makes sense yet (enough entries) */
          if (likely(!afl->custom_splice_optout &&
                     afl->ready_for_splicing_count > 1)) {

            /* Pick a random other queue entry for passing to external API
               that has the necessary length */

            if (likely(afl->splice_buf_count > 1)) {

              u32 tidx = rand_below(afl, afl->splice_buf_count);
              tid = afl->splice_buf_ids[tidx];
              if (unlikely(tid == afl->current_entry)) {

                tidx = (tidx + 1) % afl->splice_buf_count;
                tid = afl->splice_buf_ids[tidx];

              }

            } else {

              do {

                tid = rand_below(afl, afl->queued_items);

              } while (unlikely(tid == afl->current_entry ||

                                afl->queue_buf[tid]->len < 4));

            }

            target = afl->queue_buf[tid];
            afl->splicing_with = tid;

            /* Read the additional testcase into a new buffer. */
            new_buf = queue_testcase_get(afl, target);
            target_len = target->len;

          }

          u8 *mutated_buf = NULL;

          size_t mutated_size =
              el->afl_custom_fuzz(el->data, out_buf, len, &mutated_buf, new_buf,
                                  target_len, max_seed_size);

          if (mutated_size > 0) {

            if (unlikely(!mutated_buf)) {

              // FATAL("Error in custom_fuzz. Size returned: %zu",
              // mutated_size);
              break;

            }

            if (common_fuzz_stuff(afl, mutated_buf, (u32)mutated_size)) {

              goto abandon_entry;

            }

            if (!el->afl_custom_fuzz_count) {

              /* If we're finding new stuff, let's run for a bit longer, limits
                permitting. */

              if (afl->queued_items != havoc_queued) {

                if (perf_score <= afl->havoc_max_mult * 100) {

                  afl->stage_max *= 2;
                  perf_score *= 2;

                }

                havoc_queued = afl->queued_items;

              }

            }

          }

          /* out_buf may have been changed by the call to custom_fuzz */
          memcpy(out_buf, in_buf, len);

        }

      }

    }

  });

  afl->current_custom_fuzz = NULL;

  if (!has_custom_fuzz) goto havoc_stage;

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_CUSTOM_MUTATOR] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_CUSTOM_MUTATOR] += afl->stage_cur;
#ifdef INTROSPECTION
  if (!was_doing_ijon) { afl->queue_cur->stats_mutated += afl->stage_max; }
#endif

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

#ifdef INTROSPECTION

  if (was_doing_ijon || !is_logged) {

    is_logged = 1;
    before_havoc_findings = afl->queued_items;
    before_havoc_edges = count_non_255_bytes(afl, afl->virgin_bits);
    before_havoc_time = get_cur_time();

  }

#endif

  if (unlikely(afl->custom_only)) {

    /* Force UI update */
    show_stats(afl);
    /* Skip other stages */
    ret_val = 0;
    goto abandon_entry;

  }

  afl->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    afl->stage_name = "havoc";
    afl->stage_short = "havoc";
    afl->stage_max = ((doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                      perf_score / afl->havoc_div) >>
                     8;

  } else {

    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "splice %u", splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = "splice";
    afl->stage_max = (SPLICE_HAVOC * perf_score / afl->havoc_div) >> 8;

  }

  /* IJON stage name override */
  if (unlikely(afl->is_doing_ijon)) {

    afl->stage_name = "ijon-max";
    afl->stage_short = "ijon-max";

  }

  if (unlikely(afl->stage_max < HAVOC_MIN)) { afl->stage_max = HAVOC_MIN; }

  temp_len = len;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  havoc_queued = afl->queued_items;

  if (afl->custom_mutators_count) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->stacked_custom && el->afl_custom_havoc_mutation_probability) {

        el->stacked_custom_prob =
            el->afl_custom_havoc_mutation_probability(el->data);
        if (el->stacked_custom_prob > 100) {

          FATAL(
              "The probability returned by "
              "afl_custom_havoc_mutation_propability "
              "has to be in the range 0-100.");

        }

      }

    });

  }

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  u32 *mutation_array;
  u32  stack_max, rand_max;  // stack_max_pow = afl->havoc_stack_pow2;

  if (unlikely(afl->starved)) { afl->input_mode = (rand_next(afl) % 3); }

  switch (afl->input_mode) {

    case 1: {  // TEXT

      if (likely(afl->fuzz_mode == 0)) {  // is exploration?
        mutation_array = (unsigned int *)&mutation_strategy_exploration_text;
        rand_max = MUT_STRATEGY_ARRAY_SIZE;
        // TODO: versus mutation_strategy_exploration_text?

      } else {  // exploitation mode

        mutation_array = (unsigned int *)&mutation_strategy_exploitation_text;
        rand_max = MUT_STRATEGY_ARRAY_SIZE;
        // TODO: maybe this should be mutation_strategy_exploitation_text?

      }

      break;

    }

    case 2: {  // BINARY

      if (likely(afl->fuzz_mode == 0)) {  // is exploration?
        mutation_array = (unsigned int *)&mutation_strategy_exploration_binary;
        rand_max = MUT_STRATEGY_ARRAY_SIZE;

      } else {  // exploitation mode

        mutation_array = (unsigned int *)&mutation_strategy_exploitation_binary;
        rand_max = MUT_STRATEGY_ARRAY_SIZE;
        // or this one? we do not have enough binary bug benchmarks :-(
        // mutation_array = (unsigned int *)&binary_array;
        // rand_max = MUT_BIN_ARRAY_SIZE;

      }

      break;

    }

    default: {  // DEFAULT/GENERIC

      if (likely(afl->fuzz_mode == 0)) {  // is exploration?
        mutation_array = (unsigned int *)&binary_array;
        rand_max = MUT_BIN_ARRAY_SIZE;

      } else {  // exploitation mode

        mutation_array = (unsigned int *)&text_array;
        rand_max = MUT_TXT_ARRAY_SIZE;

      }

      break;

    }

  }

  /*
  if (temp_len < 64) {

    --stack_max_pow;

  } else if (temp_len <= 8096) {

    ++stack_max_pow;

  } else {

    ++stack_max_pow;

  }

  */

  stack_max = 1 << (1 + rand_below(afl, afl->havoc_stack_pow2));

  // + (afl->extras_cnt ? 2 : 0) + (afl->a_extras_cnt ? 2 : 0);

  const u32 *mopt_static_arr = mutation_array;
  u32        mopt_static_len = rand_max;
  u32        mopt_ctx_idx = mopt_ctx_index(afl->input_mode, afl->fuzz_mode);
  afl->mopt_adaptive.cur_ctx = (u8)mopt_ctx_idx;

  if (afl->mopt_adaptive.enabled) {

    struct mopt_ctx *mc = &afl->mopt_adaptive.ctx[mopt_ctx_idx];
    if (afl->fsrv.total_execs - mc->last_rebuild_execs >= MOPT_REBUILD_EXECS) {

      mc->last_rebuild_execs = afl->fsrv.total_execs;
      mopt_rebuild_ctx(mc, mopt_static_arr, mopt_static_len);
      mopt_policy_update(mc);
#ifdef INTROSPECTION
      mopt_introspect_log(afl, mopt_ctx_idx);
#endif

    }

    u32        chosen_len;
    const u32 *chosen = mopt_choose_array(afl, mopt_ctx_idx, mopt_static_arr,
                                          mopt_static_len, &chosen_len);
    mutation_array = (u32 *)chosen;
    rand_max = chosen_len;

  }

  u64 mopt_stage_start_us = get_cur_time_us();
  u64 mopt_stage_start_finds = afl->queued_items + afl->saved_crashes;
  u64 mopt_stage_start_execs = afl->fsrv.total_execs;
  u64 havoc_finds = mopt_stage_start_finds;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 use_stacking = 1 + rand_below(afl, stack_max);

    afl->stage_cur_val = use_stacking;

#ifdef INTROSPECTION
    snprintf(afl->mutation, sizeof(afl->mutation), "%s HAVOC-%u-%u",
             was_doing_ijon ? "ijon-max" : (char *)afl->queue_cur->fname,
             input_is_ascii, use_stacking);
#endif

    // Frameshift: save the current input meta
    if (likely(!afl->afl_env.afl_frameshift_disabled)) {

      if (afl->queue_cur->fs_status != 0) { fs_save(afl->fs_curr_meta); }

    }

    for (i = 0; i < use_stacking; ++i) {

      if (afl->custom_mutators_count) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (unlikely(el->stacked_custom &&
                       rand_below(afl, 100) < el->stacked_custom_prob)) {

            u8    *custom_havoc_buf = NULL;
            size_t new_len = el->afl_custom_havoc_mutation(
                el->data, out_buf, temp_len, &custom_havoc_buf, MAX_FILE);
            if (unlikely(!custom_havoc_buf)) {

              FATAL("Error in custom_havoc (return %zu)", new_len);

            }

            if (likely(new_len > 0 && custom_havoc_buf)) {

              temp_len = new_len;
              if (out_buf != custom_havoc_buf) {

                out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len);
                if (unlikely(!afl->out_buf)) { PFATAL("alloc"); }
                memcpy(out_buf, custom_havoc_buf, temp_len);

              }

            }

          }

        });

      }

    retry_havoc_step: {

      u32 r = rand_below(afl, rand_max), item;
      u32 mopt_op = mutation_array[r];
      u8  mopt_changed = 0;

      switch (mopt_op) {

        case MUT_FLIPBIT: {

          /* Flip a single bit somewhere. Spooky! */
          u8  bit = rand_below(afl, 8);
          u32 off = rand_below(afl, temp_len);
          out_buf[off] ^= 1 << bit;
          mopt_changed = 1;

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP-BIT_%u", bit);
          strcat(afl->mutation, afl->m_tmp);
#endif
          break;

        }

        case MUT_INTERESTING8: {

          /* Set byte to interesting value. */

          item = rand_below(afl, sizeof(interesting_8));
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING8_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          u32 pos = rand_below(afl, temp_len);
          mopt_changed = out_buf[pos] != (u8)interesting_8[item];
          out_buf[pos] = interesting_8[item];
          break;

        }

        case MUT_INTERESTING16: {

          /* Set word to interesting value, little endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_16) >> 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif

          u32 pos = rand_below(afl, temp_len - 1);
          u16 val = interesting_16[item];
          mopt_changed = memcmp(out_buf + pos, &val, sizeof(val)) != 0;
          INSERT16(out_buf, pos, val);

          break;

        }

        case MUT_INTERESTING16BE: {

          /* Set word to interesting value, big endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_16) >> 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING16BE_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          u32 pos = rand_below(afl, temp_len - 1);
          u16 val = SWAP16(interesting_16[item]);
          mopt_changed = memcmp(out_buf + pos, &val, sizeof(val)) != 0;
          INSERT16(out_buf, pos, val);

          break;

        }

        case MUT_INTERESTING32: {

          /* Set dword to interesting value, little endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_32) >> 2);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif

          u32 pos = rand_below(afl, temp_len - 3);
          u32 val = interesting_32[item];
          mopt_changed = memcmp(out_buf + pos, &val, sizeof(val)) != 0;
          INSERT32(out_buf, pos, val);

          break;

        }

        case MUT_INTERESTING32BE: {

          /* Set dword to interesting value, big endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          item = rand_below(afl, sizeof(interesting_32) >> 2);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INTERESTING32BE_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          u32 pos = rand_below(afl, temp_len - 3);
          u32 val = SWAP32(interesting_32[item]);
          mopt_changed = memcmp(out_buf + pos, &val, sizeof(val)) != 0;
          INSERT32(out_buf, pos, val);

          break;

        }

        case MUT_ARITH8_: {

          /* Randomly subtract from byte. */

          item = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8-_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] -= item;
          mopt_changed = 1;
          break;

        }

        case MUT_ARITH8: {

          /* Randomly add to byte. */

          item = 1 + rand_below(afl, ARITH_MAX);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH8+_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] += item;
          mopt_changed = 1;
          break;

        }

        case MUT_ARITH16_: {

          /* Randomly subtract from word, little endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16-_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT16(out_buf, pos, EXTRACT16(out_buf, pos) - item);
          mopt_changed = 1;

          break;

        }

        case MUT_ARITH16BE_: {

          /* Randomly subtract from word, big endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE-_%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT16(out_buf, pos, SWAP16(SWAP16(EXTRACT16(out_buf, pos)) - num));
          mopt_changed = 1;

          break;

        }

        case MUT_ARITH16: {

          /* Randomly add to word, little endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16+_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT16(out_buf, pos, EXTRACT16(out_buf, pos) + item);
          mopt_changed = 1;

          break;

        }

        case MUT_ARITH16BE: {

          /* Randomly add to word, big endian. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 1);
          u16 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH16BE+__%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT16(out_buf, pos, SWAP16(SWAP16(EXTRACT16(out_buf, pos)) + num));
          mopt_changed = 1;

          break;

        }

        case MUT_ARITH32_: {

          /* Randomly subtract from dword, little endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32-_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT32(out_buf, pos, EXTRACT32(out_buf, pos) - item);
          mopt_changed = 1;

          break;

        }

        case MUT_ARITH32BE_: {

          /* Randomly subtract from dword, big endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE-_%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT32(out_buf, pos, SWAP32(SWAP32(EXTRACT32(out_buf, pos)) - num));
          mopt_changed = 1;

          break;

        }

        case MUT_ARITH32: {

          /* Randomly add to dword, little endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          item = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32+_%u", item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT32(out_buf, pos, EXTRACT32(out_buf, pos) + item);
          mopt_changed = 1;

          break;

        }

        case MUT_ARITH32BE: {

          /* Randomly add to dword, big endian. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 pos = rand_below(afl, temp_len - 3);
          u32 num = 1 + rand_below(afl, ARITH_MAX);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ARITH32BE+_%u", num);
          strcat(afl->mutation, afl->m_tmp);
#endif
          INSERT32(out_buf, pos, SWAP32(SWAP32(EXTRACT32(out_buf, pos)) + num));
          mopt_changed = 1;

          break;

        }

        case MUT_RAND8: {

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          u32 pos = rand_below(afl, temp_len);
          item = 1 + rand_below(afl, 255);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " RAND8_%u",
                   out_buf[pos] ^ item);
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[pos] ^= item;
          mopt_changed = 1;
          break;

        }

        case MUT_CLONE_COPY: {

          if (likely(temp_len + 1 < MAX_FILE)) {

            /* Clone bytes. */

            u32 clone_len = choose_block_len(afl, temp_len);
            u32 clone_cap = (u32)(MAX_FILE - 1 - temp_len);
            if (unlikely(clone_len > clone_cap)) { clone_len = clone_cap; }
            u32 clone_from = rand_below(afl, temp_len - clone_len + 1);
            u32 clone_to = rand_below(afl, temp_len);

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s_%u_%u_%u",
                     "COPY", clone_from, clone_to, clone_len);
            strcat(afl->mutation, afl->m_tmp);
#endif
            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;
            mopt_changed = 1;

            // Frameshift tracking
            if (likely(!afl->afl_env.afl_frameshift_disabled)) {

              if (afl->queue_cur->fs_status != 0) {

                fs_track_insert(afl->fs_curr_meta, clone_to, clone_len, 1);

              }

            }

          } else if (unlikely(temp_len < 8)) {

            break;

          } else {

            goto retry_havoc_step;

          }

          break;

        }

        case MUT_CLONE_FIXED: {

          if (likely(temp_len + 1 < MAX_FILE)) {

            /* Insert a block of constant bytes (25%). */

            u32 clone_len = choose_block_len(afl, HAVOC_BLK_XL);
            u32 clone_cap = (u32)(MAX_FILE - 1 - temp_len);
            if (unlikely(clone_len > clone_cap)) { clone_len = clone_cap; }
            u32 clone_to = rand_below(afl, temp_len);
            u32 strat = rand_below(afl, 2);
            u32 clone_from = clone_to ? clone_to - 1 : 0;
            item = strat ? rand_below(afl, 256) : out_buf[clone_from];

#ifdef INTROSPECTION
            snprintf(afl->m_tmp, sizeof(afl->m_tmp), " CLONE-%s_%u_%u_%u",
                     "FIXED", strat, clone_to, clone_len);
            strcat(afl->mutation, afl->m_tmp);
#endif
            u8 *new_buf =
                afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            memset(new_buf + clone_to, item, clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += clone_len;
            mopt_changed = 1;

            // Frameshift tracking
            if (likely(!afl->afl_env.afl_frameshift_disabled)) {

              if (afl->queue_cur->fs_status != 0) {

                fs_track_insert(afl->fs_curr_meta, clone_to, clone_len, 1);

              }

            }

          } else if (unlikely(temp_len < 8)) {

            break;

          } else {

            goto retry_havoc_step;

          }

          break;

        }

        case MUT_OVERWRITE_COPY: {

          /* Overwrite bytes with a randomly selected chunk bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 copy_from, copy_to,
              copy_len = choose_block_len(afl, temp_len - 1);

          do {

            copy_from = rand_below(afl, temp_len - copy_len + 1);
            copy_to = rand_below(afl, temp_len - copy_len + 1);

          } while (unlikely(copy_from == copy_to));

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " OVERWRITE-COPY_%u_%u_%u",
                   copy_from, copy_to, copy_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          mopt_changed =
              memcmp(out_buf + copy_to, out_buf + copy_from, copy_len) != 0;
          memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          break;

        }

        case MUT_OVERWRITE_FIXED: {

          /* Overwrite bytes with fixed bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 copy_len = choose_block_len(afl, temp_len - 1);
          u32 copy_to = rand_below(afl, temp_len - copy_len + 1);
          u32 strat = rand_below(afl, 2);
          u32 copy_from = copy_to ? copy_to - 1 : 0;
          item = strat ? rand_below(afl, 256) : out_buf[copy_from];

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                   " OVERWRITE-FIXED_%u_%u_%u-%u", strat, item, copy_to,
                   copy_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          for (u32 pos = 0; pos < copy_len && !mopt_changed; ++pos) {

            mopt_changed = out_buf[copy_to + pos] != (u8)item;

          }

          memset(out_buf + copy_to, item, copy_len);

          break;

        }

        case MUT_BYTEADD: {

          /* Increase byte by 1. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " BYTEADD_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)]++;
          mopt_changed = 1;
          break;

        }

        case MUT_BYTESUB: {

          /* Decrease byte by 1. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " BYTESUB_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)]--;
          mopt_changed = 1;
          break;

        }

        case MUT_FLIP8: {

          /* Flip byte with a XOR 0xff. This is the same as NEG. */

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " FLIP8_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          out_buf[rand_below(afl, temp_len)] ^= 0xff;
          mopt_changed = 1;
          break;

        }

        case MUT_SWITCH: {

          if (unlikely(temp_len < 4)) { break; }  // no retry

          /* Switch bytes. */

          u32 to_end, switch_to, switch_len, switch_from;
          switch_from = rand_below(afl, temp_len);
          do {

            switch_to = rand_below(afl, temp_len);

          } while (unlikely(switch_from == switch_to));

          if (switch_from < switch_to) {

            switch_len = switch_to - switch_from;
            to_end = temp_len - switch_to;

          } else {

            switch_len = switch_from - switch_to;
            to_end = temp_len - switch_from;

          }

          switch_len = choose_block_len(afl, MIN(switch_len, to_end));

          u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), switch_len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SWITCH-%s_%u_%u_%u",
                   "switch", switch_from, switch_to, switch_len);
          strcat(afl->mutation, afl->m_tmp);
#endif

          mopt_changed = memcmp(out_buf + switch_from, out_buf + switch_to,
                                switch_len) != 0;

          /* Backup */

          memcpy(new_buf, out_buf + switch_from, switch_len);

          /* Switch 1 */

          memcpy(out_buf + switch_from, out_buf + switch_to, switch_len);

          /* Switch 2 */

          memcpy(out_buf + switch_to, new_buf, switch_len);

          break;

        }

        case MUT_DEL: {

          /* Delete bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          /* Don't delete too much. */

          u32 del_len = choose_block_len(afl, temp_len - 1);
          u32 del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DEL_%u_%u", del_from,
                   del_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;
          mopt_changed = 1;

          // Frameshift tracking
          if (likely(!afl->afl_env.afl_frameshift_disabled)) {

            if (afl->queue_cur->fs_status != 0) {

              fs_track_delete(afl->fs_curr_meta, del_from, del_len);

            }

          }

          break;

        }

        case MUT_SHUFFLE: {

          /* Shuffle bytes. */

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 len = choose_block_len(afl, temp_len - 1);
          u32 off = rand_below(afl, temp_len - len + 1);
          u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch), len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }
          memcpy(new_buf, out_buf + off, len);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SHUFFLE_%u", len);
          strcat(afl->mutation, afl->m_tmp);
#endif

          for (u32 i = len - 1; i > 0; i--) {

            u32 j;
            do {

              j = rand_below(afl, i + 1);

            } while (unlikely(i == j));

            unsigned char temp = out_buf[off + i];
            out_buf[off + i] = out_buf[off + j];
            out_buf[off + j] = temp;

          }

          mopt_changed = memcmp(new_buf, out_buf + off, len) != 0;

          break;

        }

        case MUT_DELONE: {

          /* Delete bytes. */

          if (unlikely(temp_len < 2)) { break; }  // no retry

          /* Don't delete too much. */

          u32 del_len = 1;
          u32 del_from = rand_below(afl, temp_len - del_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " DELONE_%u", del_from);
          strcat(afl->mutation, afl->m_tmp);
#endif
          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;
          mopt_changed = 1;

          // Frameshift tracking
          if (likely(!afl->afl_env.afl_frameshift_disabled)) {

            if (afl->queue_cur->fs_status != 0) {

              fs_track_delete(afl->fs_curr_meta, del_from, del_len);

            }

          }

          break;

        }

        case MUT_INSERTONE: {

          if (unlikely(temp_len < 2)) { break; }  // no retry

          u32 clone_len = 1;
          u32 clone_to = rand_below(afl, temp_len);
          u32 strat = rand_below(afl, 2);
          u32 clone_from = clone_to ? clone_to - 1 : 0;
          item = strat ? rand_below(afl, 256) : out_buf[clone_from];

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INSERTONE_%u_%u", strat,
                   clone_to);
          strcat(afl->mutation, afl->m_tmp);
#endif
          u8 *new_buf =
              afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len);
          if (unlikely(!new_buf)) { PFATAL("alloc"); }

          /* Head */

          memcpy(new_buf, out_buf, clone_to);

          /* Inserted part */

          memset(new_buf + clone_to, item, clone_len);

          /* Tail */
          memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                 temp_len - clone_to);

          out_buf = new_buf;
          afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
          temp_len += clone_len;
          mopt_changed = 1;

          // Frameshift tracking
          if (likely(!afl->afl_env.afl_frameshift_disabled)) {

            if (afl->queue_cur->fs_status != 0) {

              fs_track_insert(afl->fs_curr_meta, clone_to, clone_len, 1);

            }

          }

          break;

        }

        case MUT_ASCIINUM: {

          if (unlikely(temp_len < 4)) { break; }  // no retry

          u32 off = rand_below(afl, temp_len), off2 = off, cnt = 0;

          while (off2 + cnt < temp_len && !isdigit(out_buf[off2 + cnt])) {

            ++cnt;

          }

          // none found, wrap
          if (off2 + cnt == temp_len) {

            off2 = 0;
            cnt = 0;

            while (cnt < off && !isdigit(out_buf[off2 + cnt])) {

              ++cnt;

            }

            if (cnt == off) {

              if (temp_len < 8) {

                break;

              } else {

                goto retry_havoc_step;

              }

            }

          }

          off = off2 + cnt;
          off2 = off + 1;

          while (off2 < temp_len && isdigit(out_buf[off2])) {

            ++off2;

          }

          s64 val = out_buf[off] - '0';
          for (u32 i = off + 1; i < off2; ++i) {

            u8  digit = out_buf[i] - '0';
            s64 valx10;

            if (val > INT64_MAX / 10 ||
                (valx10 = (val * 10)) > INT64_MAX - digit) {

              off2 = i;
              break;

            }

            val = valx10 + digit;

          }

          if (off && out_buf[off - 1] == '-') { val = -val; }

          u32 strat = rand_below(afl, 8);
          switch (strat) {

            case 0:
              if (val == INT64_MAX) {

                val /= 10;
                --off2;

              }

              val++;
              break;
            case 1:
              if (val == INT64_MIN) {

                val /= 10;
                --off2;

              }

              val--;
              break;
            case 2:
              if (val > INT64_MAX / 2 || val < INT64_MIN / 2) {

                val /= 10;
                --off2;

              }

              val *= 2;
              break;
            case 3:
              val /= 2;
              break;
            case 4:
              if (likely(val && (u64)val < 0x19999999)) {

                val = (u64)rand_next(afl) % (u64)((u64)val * 10);

              } else {

                val = rand_below(afl, 256);

              }

              break;
            case 5:
              if (val > INT64_MAX - 256) {

                val /= 10;
                --off2;

              }

              val += rand_below(afl, 256);
              break;
            case 6:
              if (val < INT64_MIN + 256) {

                val /= 10;
                --off2;

              }

              val -= rand_below(afl, 256);
              break;
            case 7:
              val = ~(val);
              break;

          }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " ASCIINUM_%u_%u_%u",
                   input_is_ascii, strat, off);
          strcat(afl->mutation, afl->m_tmp);
#endif
          // fprintf(stderr, "val: %u-%u = %ld\n", off, off2, val);

          char buf[32];
          snprintf(buf, sizeof(buf), "%" PRId64, val);

          // fprintf(stderr, "BEFORE: %s\n", out_buf);

          u32 old_len = off2 - off;
          u32 new_len = strlen(buf);

          if (old_len == new_len) {

            mopt_changed = memcmp(out_buf + off, buf, new_len) != 0;
            memcpy(out_buf + off, buf, new_len);

          } else {

            mopt_changed = 1;

            u8 *new_buf = afl_realloc(AFL_BUF_PARAM(out_scratch),
                                      temp_len + new_len - old_len);
            if (unlikely(!new_buf)) { PFATAL("alloc"); }

            /* Head */

            memcpy(new_buf, out_buf, off);

            /* Inserted part */

            memcpy(new_buf + off, buf, new_len);

            /* Tail */
            memcpy(new_buf + off + new_len, out_buf + off2, temp_len - off2);

            out_buf = new_buf;
            afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
            temp_len += (new_len - old_len);

            // Frameshift tracking
            if (likely(!afl->afl_env.afl_frameshift_disabled)) {

              if (afl->queue_cur->fs_status != 0) {

                fs_track_delete(afl->fs_curr_meta, off, old_len);
                fs_track_insert(afl->fs_curr_meta, off, new_len, 1);

              }

            }

          }

          // fprintf(stderr, "AFTER : %s\n", out_buf);
          break;

        }

        case MUT_INSERTASCIINUM: {

          u32 len = 1 + rand_below(afl, 8);
          u32 pos = rand_below(afl, temp_len);
          /* Insert ascii number. */
          if (unlikely(temp_len < pos + len)) {

            if (unlikely(temp_len < 8)) {

              break;

            } else {

              goto retry_havoc_step;

            }

          }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " INSERTASCIINUM_");
          strcat(afl->mutation, afl->m_tmp);
#endif
          u64  val = rand_next(afl);
          char buf[32];
          snprintf(buf, sizeof(buf), "%llu", val);
          u32 val_len = strlen(buf), digit_off;
          if (len > val_len) {

            len = val_len;
            digit_off = 0;

          } else {

            digit_off = val_len - len;

          }

          mopt_changed = memcmp(out_buf + pos, buf + digit_off, len) != 0;
          memcpy(out_buf + pos, buf + digit_off, len);

          break;

        }

        case MUT_EXTRA_OVERWRITE: {

          if (unlikely(!afl->extras_cnt)) { goto retry_havoc_step; }

          /* Use the dictionary. */

          u32 use_extra = rand_below(afl, afl->extras_cnt);
          u32 extra_len = afl->extras[use_extra].len;

          if (unlikely(extra_len > temp_len)) { goto retry_havoc_step; }

          u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA-OVERWRITE_%u_%u",
                   insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          mopt_changed = memcmp(out_buf + insert_at,
                                afl->extras[use_extra].data, extra_len) != 0;
          memcpy(out_buf + insert_at, afl->extras[use_extra].data, extra_len);

          break;

        }

        case MUT_EXTRA_INSERT: {

          if (unlikely(!afl->extras_cnt)) { goto retry_havoc_step; }

          u32 use_extra = rand_below(afl, afl->extras_cnt);
          u32 extra_len = afl->extras[use_extra].len;
          if (unlikely(temp_len + extra_len >= MAX_FILE)) {

            goto retry_havoc_step;

          }

          u8 *ptr = afl->extras[use_extra].data;
          u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " EXTRA-INSERT_%u_%u",
                   insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif

          out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
          if (unlikely(!out_buf)) { PFATAL("alloc"); }

          /* Tail */
          memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                  temp_len - insert_at);

          /* Inserted part */
          memcpy(out_buf + insert_at, ptr, extra_len);
          temp_len += extra_len;
          mopt_changed = extra_len != 0;

          // Frameshift tracking
          if (likely(!afl->afl_env.afl_frameshift_disabled)) {

            if (afl->queue_cur->fs_status != 0) {

              fs_track_insert(afl->fs_curr_meta, insert_at, extra_len, 1);

            }

          }

          break;

        }

        case MUT_AUTO_EXTRA_OVERWRITE: {

          if (unlikely(!afl->a_extras_cnt)) { goto retry_havoc_step; }

          /* Use the dictionary. */

          u32 use_extra = rand_below(afl, afl->a_extras_cnt);
          u32 extra_len = afl->a_extras[use_extra].len;

          if (unlikely(extra_len > temp_len)) { goto retry_havoc_step; }

          u32 insert_at = rand_below(afl, temp_len - extra_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                   " AUTO-EXTRA-OVERWRITE_%u_%u", insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif
          mopt_changed = memcmp(out_buf + insert_at,
                                afl->a_extras[use_extra].data, extra_len) != 0;
          memcpy(out_buf + insert_at, afl->a_extras[use_extra].data, extra_len);

          break;

        }

        case MUT_AUTO_EXTRA_INSERT: {

          if (unlikely(!afl->a_extras_cnt)) { goto retry_havoc_step; }

          u32 use_extra = rand_below(afl, afl->a_extras_cnt);
          u32 extra_len = afl->a_extras[use_extra].len;
          if (unlikely(temp_len + extra_len >= MAX_FILE)) {

            goto retry_havoc_step;

          }

          u8 *ptr = afl->a_extras[use_extra].data;
          u32 insert_at = rand_below(afl, temp_len + 1);
#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " AUTO-EXTRA-INSERT_%u_%u",
                   insert_at, extra_len);
          strcat(afl->mutation, afl->m_tmp);
#endif

          out_buf = afl_realloc(AFL_BUF_PARAM(out), temp_len + extra_len);
          if (unlikely(!out_buf)) { PFATAL("alloc"); }

          /* Tail */
          memmove(out_buf + insert_at + extra_len, out_buf + insert_at,
                  temp_len - insert_at);

          /* Inserted part */
          memcpy(out_buf + insert_at, ptr, extra_len);
          temp_len += extra_len;
          mopt_changed = extra_len != 0;

          // Frameshift tracking
          if (likely(!afl->afl_env.afl_frameshift_disabled)) {

            if (afl->queue_cur->fs_status != 0) {

              fs_track_insert(afl->fs_curr_meta, insert_at, extra_len, 1);

            }

          }

          break;

        }

        case MUT_SPLICE_OVERWRITE: {

          if (unlikely(afl->ready_for_splicing_count <= 1)) {

            goto retry_havoc_step;

          }

          /* Pick a random queue entry and seek to it. */

          u32 tid;
          if (likely(afl->splice_buf_count > 1)) {

            u32 tidx = rand_below(afl, afl->splice_buf_count);
            tid = afl->splice_buf_ids[tidx];
            if (unlikely(tid == afl->current_entry)) {

              tidx = (tidx + 1) % afl->splice_buf_count;
              tid = afl->splice_buf_ids[tidx];

            }

          } else {

            do {

              tid = rand_below(afl, afl->queued_items);

            } while (unlikely(tid == afl->current_entry ||

                              afl->queue_buf[tid]->len < 4));

          }

          /* Get the testcase for splicing. */
          struct queue_entry *target = afl->queue_buf[tid];
          u32                 new_len = target->len;
          u8                 *new_buf = queue_testcase_get(afl, target);

          /* overwrite mode */

          u32 copy_from, copy_to, copy_len;

          copy_len = choose_block_len(afl, new_len - 1);
          if (copy_len > temp_len) copy_len = temp_len;

          copy_from = rand_below(afl, new_len - copy_len + 1);
          copy_to = rand_below(afl, temp_len - copy_len + 1);

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp),
                   " SPLICE-OVERWRITE_%u_%u_%u_%s", copy_from, copy_to,
                   copy_len, target->fname);
          strcat(afl->mutation, afl->m_tmp);
#endif
          mopt_changed =
              memcmp(out_buf + copy_to, new_buf + copy_from, copy_len) != 0;
          memmove(out_buf + copy_to, new_buf + copy_from, copy_len);

          break;

        }

        case MUT_SPLICE_INSERT: {

          if (unlikely(afl->ready_for_splicing_count <= 1)) {

            goto retry_havoc_step;

          }

          if (unlikely(temp_len + 1 >= MAX_FILE)) { goto retry_havoc_step; }

          /* Pick a random queue entry and seek to it. */

          u32 tid;
          if (likely(afl->splice_buf_count > 1)) {

            u32 tidx = rand_below(afl, afl->splice_buf_count);
            tid = afl->splice_buf_ids[tidx];
            if (unlikely(tid == afl->current_entry)) {

              tidx = (tidx + 1) % afl->splice_buf_count;
              tid = afl->splice_buf_ids[tidx];

            }

          } else {

            do {

              tid = rand_below(afl, afl->queued_items);

            } while (unlikely(tid == afl->current_entry ||

                              afl->queue_buf[tid]->len < 4));

          }

          /* Get the testcase for splicing. */
          struct queue_entry *target = afl->queue_buf[tid];
          u32                 new_len = target->len;
          u8                 *new_buf = queue_testcase_get(afl, target);

          /* insert mode */

          u32 clone_from, clone_to, clone_len;

          clone_len = choose_block_len(afl, new_len);
          u32 clone_cap = (u32)(MAX_FILE - 1 - temp_len);
          if (unlikely(clone_len > clone_cap)) { clone_len = clone_cap; }
          clone_from = rand_below(afl, new_len - clone_len + 1);
          clone_to = rand_below(afl, temp_len + 1);

          u8 *temp_buf =
              afl_realloc(AFL_BUF_PARAM(out_scratch), temp_len + clone_len + 1);
          if (unlikely(!temp_buf)) { PFATAL("alloc"); }

#ifdef INTROSPECTION
          snprintf(afl->m_tmp, sizeof(afl->m_tmp), " SPLICE-INSERT_%u_%u_%u_%s",
                   clone_from, clone_to, clone_len, target->fname);
          strcat(afl->mutation, afl->m_tmp);
#endif
          /* Head */

          memcpy(temp_buf, out_buf, clone_to);

          /* Inserted part */

          memcpy(temp_buf + clone_to, new_buf + clone_from, clone_len);

          /* Tail */
          memcpy(temp_buf + clone_to + clone_len, out_buf + clone_to,
                 temp_len - clone_to);

          out_buf = temp_buf;
          afl_swap_bufs(AFL_BUF_PARAM(out), AFL_BUF_PARAM(out_scratch));
          temp_len += clone_len;
          mopt_changed = clone_len != 0;

          // Frameshift tracking
          if (likely(!afl->afl_env.afl_frameshift_disabled)) {

            if (afl->queue_cur->fs_status != 0) {

              fs_track_insert(afl->fs_curr_meta, clone_to, clone_len, 1);

            }

          }

          break;

        }

      }

      if (likely(mopt_changed)) { mopt_record_use(afl, mopt_op); }

    }

    }

    if (likely((temp_len != len) || memcmp(out_buf, in_buf, len))) {

      if (common_fuzz_stuff(afl, out_buf, temp_len)) { goto abandon_entry; }

      u64 cur_finds = afl->queued_items + afl->saved_crashes;
      mopt_commit_round(afl, (u8)(cur_finds != havoc_finds));
      havoc_finds = cur_finds;

    } else {

      mopt_round_reset(afl);

    }

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    // Frameshift: restore the original input meta
    if (likely(!afl->afl_env.afl_frameshift_disabled)) {

      if (afl->queue_cur->fs_status != 0) { fs_restore(afl->fs_curr_meta); }

    }

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (afl->queued_items != havoc_queued) {

      if (perf_score <= afl->havoc_max_mult * 100) {

        afl->stage_max *= 2;
        perf_score *= 2;

      }

      havoc_queued = afl->queued_items;

    }

  }

  mopt_stage_account(
      afl, mopt_ctx_idx,
      (afl->queued_items + afl->saved_crashes) - mopt_stage_start_finds,
      get_cur_time_us() - mopt_stage_start_us,
      afl->fsrv.total_execs - mopt_stage_start_execs);

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  if (!splice_cycle) {

    afl->stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_HAVOC] += afl->stage_max;
#ifdef INTROSPECTION
    if (!was_doing_ijon) { afl->queue_cur->stats_mutated += afl->stage_max; }
#endif

  } else {

    afl->stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_SPLICE] += afl->stage_max;
#ifdef INTROSPECTION
    if (!was_doing_ijon) { afl->queue_cur->stats_mutated += afl->stage_max; }
#endif

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

  if (!was_doing_ijon && afl->use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      afl->ready_for_splicing_count > 1 && afl->queue_cur->len >= 4) {

    struct queue_entry *target;
    u32                 tid, split_at;
    u8                 *new_buf;
    s32                 f_diff, l_diff;

    // Frameshift: reload the original input meta
    if (likely(!afl->afl_env.afl_frameshift_disabled) &&
        afl->queue_cur->fs_status != 0) {

      fs_clone_meta(afl);

    }

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {

      in_buf = orig_in;
      len = afl->queue_cur->len;

    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    if (likely(afl->splice_buf_count > 1)) {

      u32 tidx = rand_below(afl, afl->splice_buf_count);
      tid = afl->splice_buf_ids[tidx];
      if (unlikely(tid == afl->current_entry)) {

        tidx = (tidx + 1) % afl->splice_buf_count;
        tid = afl->splice_buf_ids[tidx];

      }

    } else {

      do {

        tid = rand_below(afl, afl->queued_items);

      } while (

          unlikely(tid == afl->current_entry || afl->queue_buf[tid]->len < 4));

    }

    /* Get the testcase */
    afl->splicing_with = tid;
    target = afl->queue_buf[tid];
    new_buf = queue_testcase_get(afl, target);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, (s64)target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) { goto retry_splicing; }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + rand_below(afl, l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    afl->in_scratch_buf = afl_realloc(AFL_BUF_PARAM(in_scratch), len);
    memcpy(afl->in_scratch_buf, in_buf, split_at);
    memcpy(afl->in_scratch_buf + split_at, new_buf + split_at, len - split_at);
    in_buf = afl->in_scratch_buf;
    afl_swap_bufs(AFL_BUF_PARAM(in), AFL_BUF_PARAM(in_scratch));

    out_buf = afl_realloc(AFL_BUF_PARAM(out), len);
    if (unlikely(!out_buf)) { PFATAL("alloc"); }
    memcpy(out_buf, in_buf, len);

    // Frameshift tracking
    if (likely(!afl->afl_env.afl_frameshift_disabled)) {

      if (afl->queue_cur->fs_status != 0) {

        fs_track_delete(afl->fs_curr_meta, split_at,
                        afl->queue_cur->len - split_at);
        fs_track_insert(afl->fs_curr_meta, split_at, target->len - split_at, 1);

      }

    }

    goto custom_mutator_stage;

  }

#endif                                                     /* !IGNORE_FINDS */

  ret_val = 0;

#ifdef INTROSPECTION

  if (!was_doing_ijon) {

    afl->havoc_prof->queued_det_stage =
        before_havoc_findings - before_det_findings;
    afl->havoc_prof->queued_havoc_stage =
        afl->queued_items - before_havoc_findings;
    afl->havoc_prof->total_queued_det += afl->havoc_prof->queued_det_stage;
    afl->havoc_prof->edge_det_stage = before_havoc_edges - before_det_edges;
    afl->havoc_prof->edge_havoc_stage =
        count_non_255_bytes(afl, afl->virgin_bits) - before_havoc_edges;
    afl->havoc_prof->total_det_edge += afl->havoc_prof->edge_det_stage;
    afl->havoc_prof->det_stage_time = before_havoc_time - before_det_time;
    afl->havoc_prof->havoc_stage_time = get_cur_time() - before_havoc_time;
    afl->havoc_prof->total_det_time += afl->havoc_prof->det_stage_time;

    plot_profile_data(afl, afl->queue_cur);

  }

#endif

/* we are through with this queue entry - for this iteration */
abandon_entry:

  afl->is_doing_ijon = 0;
  afl->afl_env.afl_frameshift_disabled = saved_frameshift_disabled;
  if (was_doing_ijon) { afl->cur_depth = saved_cur_depth; }

  mopt_round_reset(afl);

  afl->splicing_with = -1;

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (unlikely(!was_doing_ijon && !afl->stop_soon &&
               !afl->queue_cur->cal_failed && !afl->queue_cur->was_fuzzed &&
               !afl->queue_cur->disabled)) {

    if (likely(afl->pending_not_fuzzed)) { --afl->pending_not_fuzzed; }
    afl->queue_cur->was_fuzzed = 1;

    if (afl->queue_cur->favored) {

      if (likely(afl->pending_favored)) { --afl->pending_favored; }
      afl->smallest_favored = -1;
      afl->reinit_table = 1;

    } else {

      if (unlikely(++afl->pending_reinit > (afl->active_items >> 3))) {

        afl->reinit_table = 1;

      }

    }

  }

  if (unlikely(!was_doing_ijon)) { ++afl->queue_cur->fuzz_level; }
  orig_in = NULL;
  return ret_val;

#undef FLIP_BIT

}

