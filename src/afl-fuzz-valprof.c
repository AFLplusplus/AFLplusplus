/*
   american fuzzy lop++ - value profiling
   --------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Dominik Meier <mail@dmnk.co>,
                     Andrea Fioraldi <andreafioraldi@gmail.com>, and
                     Heiko Eissfeldt <heiko.eissfeldt@hexco.de>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Value profiling provides an additional gradient signal by tracking
   how close comparison operands are to matching. It considers inputs
   that bring operands closer as "interesting".

 */

#include "afl-fuzz.h"
#include "cmplog.h"
#include "bitops.h"
#include "value-profile.h"

/* CmpLog marks string-like routine compares as 0x80 + len.
   stop_at_zero is deliberately not reset between the two operand-length
   decodes. Once either operand is 0x80-tagged, the compare uses
   stop-at-NUL semantics for VP processing. */
static inline u32 decode_rtn_len(u8 raw_len, u8 *stop_at_zero) {

  if (raw_len >= 0x80) {

    *stop_at_zero = 1;
    return (u32)(raw_len - 0x80);

  }

  return (u32)raw_len;

}

/* Parse one RTN compare entry: decode operand lengths, then walk the
   two buffers to find how many leading bytes match (prefix_len) out of
   the shorter operand length (max_len).  Returns 1 if the compare is
   solved (full-length equality, or NUL-terminated equality for
   string-like compares). */
static inline u8 analyze_rtn_compare(const struct cmpfn_operands *rtn,
                                     u32 *max_len_out, u32 *prefix_len_out) {

  u8  stop_at_zero = 0;
  u32 len0 = decode_rtn_len(rtn->v0_len, &stop_at_zero);
  u32 len1 = decode_rtn_len(rtn->v1_len, &stop_at_zero);
  u32 max_len = MIN(len0, len1);
  if (!max_len || max_len > 32) max_len = 32;

  u32 prefix_len = 0;
  while (prefix_len < max_len && rtn->v0[prefix_len] == rtn->v1[prefix_len]) {

    if (stop_at_zero && rtn->v0[prefix_len] == 0) {

      *max_len_out = max_len;
      *prefix_len_out = prefix_len;
      return 1;

    }

    prefix_len++;

  }

  *max_len_out = max_len;
  *prefix_len_out = prefix_len;
  return (prefix_len == max_len);

}

/* True absolute distance bucket for 128-bit values represented as hi:lo words.
   Returns 0 for equal values, otherwise 1..128. */
static inline u32 compute_abs_dist_bucket_128(u64 v0_lo, u64 v0_hi, u64 v1_lo,
                                              u64 v1_hi) {

  if (v0_lo == v1_lo && v0_hi == v1_hi) return 0;

  u64 d_lo, d_hi;
  if (v0_hi > v1_hi || (v0_hi == v1_hi && v0_lo >= v1_lo)) {

    d_lo = v0_lo - v1_lo;
    d_hi = v0_hi - v1_hi - (v0_lo < v1_lo);

  } else {

    d_lo = v1_lo - v0_lo;
    d_hi = v1_hi - v0_hi - (v1_lo < v0_lo);

  }

  if (d_hi) return 64 + bit_length_u64(d_hi);
  return bit_length_u64(d_lo);

}

/* Load and mask instruction compare operands according to compare width.
   shape is in bytes (already decoded via SHAPE_BYTES). */
static inline void load_ins_operands(const struct cmp_operands *op, u32 shape,
                                     u64 *v0_lo, u64 *v0_hi, u64 *v1_lo,
                                     u64 *v1_hi) {

  if (shape > 16) shape = 16;   /* cmp_operands stores up to 128-bit values */

  *v0_lo = op->v0;
  *v1_lo = op->v1;
  *v0_hi = 0;
  *v1_hi = 0;

  if (shape < 8) {

    u64 mask = (1ULL << (shape * 8)) - 1;
    *v0_lo &= mask;
    *v1_lo &= mask;
    return;

  }

  if (shape > 8) {

    *v0_hi = op->v0_128;
    *v1_hi = op->v1_128;

    if (shape < 16) {

      u32 hi_bits = (shape - 8) * 8;
      u64 hi_mask = (1ULL << hi_bits) - 1;
      *v0_hi &= hi_mask;
      *v1_hi &= hi_mask;

    }

  }

}

/* Absolute distance bucket for scalar (<=8-byte) compares.
   Returns 0 for equal values, otherwise clzll(diff) + 1. */
static inline u32 compute_abs_dist_bucket(u64 v0, u64 v1, u32 shape) {

  if (v0 == v1) return 0;

  /* Only 4-byte compares need explicit width wrapping.
     For 1/2-byte compares, integer promotion before subtraction already gives
     the intended result once operands are width-masked.
     8-byte compares naturally use full-width subtraction.
     For 4-byte compares, force uint32_t wrap first so upper 32 bits do not
     pollute the clzll result. */
  if (shape == 4) {

    u32 diff32 = (u32)v0 - (u32)v1;
    return (u32)__builtin_clzll((u64)diff32) + 1;

  }

  return (u32)__builtin_clzll(v0 - v1) + 1;

}

typedef enum {

  VP_DIST_WRAPPED = 0,
  VP_DIST_EXACT = 1,

} vp_scalar_dist_mode_t;

/* True absolute distance bucket for scalar (<=8-byte) compares.
   Returns 0 for equal values, otherwise 1..64. */
static inline u32 compute_abs_dist_exact(u64 v0, u64 v1) {

  u64 diff = (v0 > v1) ? (v0 - v1) : (v1 - v0);
  return diff ? (64 - (u32)__builtin_clzll(diff)) : 0;

}

/* Compute INS compare metrics used by VP feature extraction and ranking.
   Returns 0 when operands are equal (solved compare), otherwise 1 and writes:
     - hamming_out: bit hamming distance
     - abs_dist_out: scalar absolute-distance metric selected by scalar_mode,
                     or full 128-bit absolute distance for wide compares. */
static inline u8 compute_ins_metrics(const struct cmp_operands *op, u32 shape,
                                     vp_scalar_dist_mode_t scalar_mode,
                                     u32 *hamming_out, u32 *abs_dist_out) {

  u64 v0_lo, v0_hi, v1_lo, v1_hi;
  load_ins_operands(op, shape, &v0_lo, &v0_hi, &v1_lo, &v1_hi);

  /* A single CMP site can be hit multiple times per execution with different
     operands (e.g. a loop comparing input[i] == key[i] — hit 0 may be solved
     while hit 3 is not).  Skip solved hits; other hits at the same site may
     still be unsolved and need VP tracking. */
  if (v0_lo == v1_lo && v0_hi == v1_hi) return 0;

  if (shape > 8) {

    /* Wide compares always use full 128-bit resolution. */
    *hamming_out = popcount_u64(v0_lo ^ v1_lo) + popcount_u64(v0_hi ^ v1_hi);
    *abs_dist_out = compute_abs_dist_bucket_128(v0_lo, v0_hi, v1_lo, v1_hi);

  } else {

    *hamming_out = popcount_u64(v0_lo ^ v1_lo);
    *abs_dist_out = (scalar_mode == VP_DIST_WRAPPED)
                        ? compute_abs_dist_bucket(v0_lo, v1_lo, shape)
                        : compute_abs_dist_exact(v0_lo, v1_lo);

  }

  return 1;

}

/* Re-execute the current input under the CmpLog binary so VP can inspect
   comparison operands. Returns 1 if cmp_map is ready for VP processing. */
u8 vp_run_cmplog(afl_state_t *afl, void *mem, u32 len) {

  if (unlikely(!afl->value_profile_active ||
               afl->value_profile_source != VP_SOURCE_CMPLOG_CHILD ||
               !afl->cmplog_binary || !afl->shm.cmp_map))
    return 0;

  void *vp_mem = mem;
  u32   vp_len = write_to_testcase(afl, &vp_mem, len, 0);

  if (!vp_len || vp_len < 4 || vp_len > afl->cmplog_max_filesize) return 0;

  memcpy(afl->map_tmp_buf, afl->fsrv.trace_bits, afl->fsrv.map_size);
  memset(afl->shm.cmp_map->headers, 0, sizeof(afl->shm.cmp_map->headers));
  afl->cmplog_fsrv.custom_input = afl->fsrv.custom_input;
  afl->cmplog_fsrv.custom_input_len = afl->fsrv.custom_input_len;

  u8 result = fuzz_run_target(afl, &afl->cmplog_fsrv, afl->fsrv.exec_tmout);

  memcpy(afl->fsrv.trace_bits, afl->map_tmp_buf, afl->fsrv.map_size);
  return result == FSRV_RUN_OK;

}

/* Prepare per-execution VP state before running the main target:
   - runtime source: bump/reset exec epoch and per-exec control list
   - inline CmpLog source: clear cmp headers for this execution. */
void vp_prepare_exec(afl_state_t *afl, afl_forkserver_t *fsrv) {

  if (!afl->value_profile_mode) return;
  if (fsrv != &afl->fsrv) return;

  if (afl->value_profile_source == VP_SOURCE_RUNTIME_SHM) {

    if (unlikely(!fsrv->use_value_profile)) {

      FATAL(
          "Value profile level 1 requires target support for value "
          "profile runtime SHM. Recompile the target with "
          "AFL_LLVM_VALUE_PROFILE=1 (or AFL_LLVM_VALUEPROFILE=1).");

    }

    if (unlikely(!afl->shm.vp_map)) {

      FATAL("Value profile runtime map missing although level 1 was selected.");

    }

    vp_map_t *vp = afl->shm.vp_map;
    vp->exec_id = afl->value_profile_active ? vp->exec_id + 1 : 0;
    vp->control_len = 0;
    return;

  }

  if (afl->value_profile_source == VP_SOURCE_CMPLOG_INLINE &&
      afl->value_profile_active && afl->shm.cmp_map) {

    /* Inline CmpLog source: start each main execution with a clean header set
       so VP reads only comparisons produced by this input. */
    memset(afl->shm.cmp_map->headers, 0, sizeof(afl->shm.cmp_map->headers));

  }

}

/* Ensure comparison data is available for the current input and selected
   source. Returns 1 when VP consumers can safely read compare data. */
u8 vp_ensure_cmp_data_ready(afl_state_t *afl, void *mem, u32 len) {

  if (unlikely(!afl->value_profile_active)) return 0;

  if (afl->value_profile_source == VP_SOURCE_RUNTIME_SHM) {

    return afl->shm.vp_map && afl->shm.vp_map->exec_id;

  }

  if (afl->value_profile_source == VP_SOURCE_CMPLOG_INLINE ||
      afl->value_profile_source == VP_SOURCE_CMPLOG_CHILD) {

    if (unlikely(!afl->shm.cmp_map)) return 0;

    if (afl->value_profile_source == VP_SOURCE_CMPLOG_INLINE) return 1;
    if (afl->value_profile_source == VP_SOURCE_CMPLOG_CHILD) {

      return vp_run_cmplog(afl, mem, len);

    }

    return 0;

  }

  return 0;

}

/* Build vp_trigger_bitmap for the current execution so later frontier scans
   can skip untouched compare sites. */
void vp_mark_triggered_sites(afl_state_t *afl) {

  if (afl->value_profile_source == VP_SOURCE_RUNTIME_SHM) {

    vp_map_t *vp = afl->shm.vp_map;
    if (unlikely(!vp)) return;
    u32 control_len = MIN(vp->control_len, (u32)VP_CONTROL_CAP);
    for (u32 i = 0; i < control_len; ++i) {

      u32 k = vp->control[i];
      if (k >= CMP_MAP_W) continue;
      afl->vp_trigger_bitmap[k >> 6] |= (1ULL << (k & 63));

    }

    return;

  }

  struct cmp_map *cmp = afl->shm.cmp_map;
  if (unlikely(!cmp)) return;

  for (u32 k = 0; k < CMP_MAP_W; ++k) {

    if (!cmp->headers[k].hits) continue;
    afl->vp_trigger_bitmap[k >> 6] |= (1ULL << (k & 63));

  }

}

/* Clear a single virgin bit.  Returns 1 if the bit was new. */
static inline u32 clear_virgin_bit(u8 *virgin, u32 idx) {

  u32 byte = idx >> 3;
  u8  bit = 1 << (idx & 7);
  if (virgin[byte] & bit) {

    virgin[byte] &= ~bit;
    return 1;

  }

  return 0;

}

/* Clamp recorded site hits to the log depth for this compare type. */
static inline u32 vp_site_hits(const struct cmp_header *hdr) {

  return MIN((u32)hdr->hits,
             (hdr->type == CMP_TYPE_INS) ? (u32)CMP_MAP_H : (u32)CMP_MAP_RTN_H);

}

/* VP feature index layout.

   Each CmpLog site k gets a stride of 256 slots in a flat feature space.
   The composite index k * 256 + local_offset is fed through hash_fmix32()
   before
   being taken modulo the bitmap size, so every feature is independently
   scattered across the bitmap.  Since hash_fmix32 is bijective, distinct
   composite inputs produce distinct hash outputs - collisions come only from
   the final modulo, not from the hash itself.

   INS compares (scalar instructions):
     hamming  feature:  k * 256 + (hamming - 1)          offsets [0, 127]
     abs_dist feature:  k * 256 + 128 + (abs_dist - 1)   offsets [128, 255]
     hamming ∈ [1,128], abs_dist ∈ [1,128] for wide compares (>64-bit).
     hamming ∈ [1,64],  abs_dist ∈ [1,64]  for ≤64-bit compares.

   RTN compares (memcmp/strcmp-like routines):
     feature:  k * 256 + prefix_len * 8 + (first_diff_hamming - 1)
     prefix_len ∈ [0,31], first_diff_hamming ∈ [1,8]     offsets [0, 255]

   Max composite value: 65535 * 256 + 255 = 16,777,215, fits in u32. */

/* Compute value profile features from the current cmp_map.
   Check each feature against virgin_val_prof bitmap.
   Returns the number of newly consumed value profile bits. */

u32 vp_check_cmpmap(afl_state_t *afl) {

  struct cmp_map *cmp = afl->shm.cmp_map;
  u8             *virgin = afl->virgin_val_prof;
  u32             new_bits = 0;

  if (unlikely(!cmp || !virgin)) return 0;

  for (u32 k = 0; k < CMP_MAP_W; k++) {

    if (!cmp->headers[k].hits) continue;

    u32 hits = vp_site_hits(&cmp->headers[k]);
    afl->vp_trigger_bitmap[k >> 6] |= (1ULL << (k & 63));

    if (cmp->headers[k].type == CMP_TYPE_INS) {

      u32 shape = SHAPE_BYTES(cmp->headers[k].shape);

      for (u32 j = 0; j < hits; j++) {

        u32 hamming, abs_dist;
        if (!compute_ins_metrics(&cmp->log[k][j], shape, VP_DIST_WRAPPED,
                                 &hamming, &abs_dist))
          continue;

        /* Two features per INS compare: hamming and absolute distance.
           Each hashed independently via hash_fmix32 for uniform scattering. */
        u32 idx_h =
            hash_fmix32(k * 256 + (hamming - 1)) % (VALUE_PROFILE_MAP_SIZE * 8);
        u32 idx_a = hash_fmix32(k * 256 + 128 + (abs_dist - 1)) %
                    (VALUE_PROFILE_MAP_SIZE * 8);

        new_bits += clear_virgin_bit(virgin, idx_h);
        new_bits += clear_virgin_bit(virgin, idx_a);

      }

    } else {                                                /* CMP_TYPE_RTN */

      struct cmpfn_operands *rtn = (struct cmpfn_operands *)cmp->log[k];

      for (u32 j = 0; j < hits; j++) {

        u32 max_len, prefix_len;
        if (analyze_rtn_compare(&rtn[j], &max_len, &prefix_len)) { continue; }

        u32 first_diff_hamming = 0;
        if (prefix_len < max_len) {

          first_diff_hamming =
              popcount_u8(rtn[j].v0[prefix_len] ^ rtn[j].v1[prefix_len]);

        }

        /* Single feature per RTN compare: per-position hamming at full
           resolution.  Each prefix advance opens 8 fresh feature slots.
           Hashed via hash_fmix32 for uniform scattering. */
        u32 idx =
            hash_fmix32(k * 256 + prefix_len * 8 + (first_diff_hamming - 1)) %
            (VALUE_PROFILE_MAP_SIZE * 8);

        new_bits += clear_virgin_bit(virgin, idx);

      }

    }

  }

  return new_bits;

}

/* Update per-comparison-site best entry tracking.
   For each triggered comparison site, compute the minimum distance
   and update top_rated_vp[] if this entry is closer (or same distance
   but smaller exec_us * len).
   Ranking uses VP_DIST_EXACT (true |v0-v1|) rather than the wrapped
   subtraction used for feature bucketing in vp_check_cmpmap(). */

/* Apply VP frontier updates for one queue entry using data prepared by
   vp_prepare_data()/vp_mark_triggered_sites() in the current execution. */
void vp_update_bitmap_score(afl_state_t *afl, struct queue_entry *q) {

  struct cmp_map *cmp = afl->shm.cmp_map;

  if (unlikely(!cmp)) return;

  u64 *words = afl->vp_trigger_bitmap;
  u64  fav_factor = q->exec_us * q->len;

  for (u32 w = 0; w < VP_TRIGGER_BITMAP_WORDS; w++) {

    u64 bits = words[w];
    while (bits) {

      u32 k = w * 64 + __builtin_ctzll(bits);
      bits &= bits - 1;

      if (!cmp->headers[k].hits) continue;

      u32 hits = vp_site_hits(&cmp->headers[k]);

      /* VP distance range is 1..256; VP_DIST_UNSOLVED marks no candidate. */
      u32 site_dist = VP_DIST_UNSOLVED;

      if (cmp->headers[k].type == CMP_TYPE_INS) {

        u32 shape = SHAPE_BYTES(cmp->headers[k].shape);

        for (u32 j = 0; j < hits; j++) {

          u32 hamming, abs_dist;
          if (!compute_ins_metrics(&cmp->log[k][j], shape, VP_DIST_EXACT,
                                   &hamming, &abs_dist))
            continue;

          u32 dist = MIN(hamming, abs_dist);
          if (dist < site_dist) { site_dist = dist; }

        }

      } else {                                              /* CMP_TYPE_RTN */

        struct cmpfn_operands *rtn = (struct cmpfn_operands *)cmp->log[k];

        for (u32 j = 0; j < hits; j++) {

          u32 max_len, prefix_len;
          if (analyze_rtn_compare(&rtn[j], &max_len, &prefix_len)) { continue; }

          /* Safe: analyze_rtn_compare() already skipped solved entries
             where prefix_len == max_len. */
          u32 rem = max_len - prefix_len;

          u32 first_diff_hamming =
              popcount_u8(rtn[j].v0[prefix_len] ^ rtn[j].v1[prefix_len]);
          u32 dist = (rem - 1) * 8 + first_diff_hamming;

          if (dist < site_dist) { site_dist = dist; }

        }

      }

      /* All observed pairs at this site are solved. Drop stale best entry so
         cull_queue() no longer keeps favoring it. */
      if (site_dist >= VP_DIST_UNSOLVED) {

        if (afl->top_rated_vp[k]) {

          afl->top_rated_vp[k] = NULL;
          afl->top_rated_vp_dist[k] = 0xffffffff;
          afl->score_changed = 1;

        }

        continue;

      }

      if (!afl->top_rated_vp[k] || afl->top_rated_vp[k]->disabled ||
          site_dist < afl->top_rated_vp_dist[k] ||
          (site_dist == afl->top_rated_vp_dist[k] &&
           fav_factor <
               afl->top_rated_vp[k]->exec_us * afl->top_rated_vp[k]->len)) {

        afl->top_rated_vp[k] = q;
        afl->top_rated_vp_dist[k] = site_dist;
        afl->score_changed = 1;

      }

    }

  }

}

/* Check stagnation and activate/deactivate value profiling. */

void vp_update_activation(afl_state_t *afl) {

  if (afl->value_profile_mode != 2) return;

  u64 cur = get_cur_time();
  /* Stagnation mode is edge-coverage based, not queue-growth based. */
  u64 no_find_ms = (afl->last_cov_find_time == 0)
                       ? (cur - afl->start_time)
                       : (cur - afl->last_cov_find_time);

  u8 should = (no_find_ms >= (u64)afl->value_profile_stagnation_secs * 1000);

  if (should && !afl->value_profile_active) {

    afl->value_profile_active = 1;
    afl->value_profile_enabled_cycle = afl->queue_cycle;
    afl->score_changed = 1;
    OKF("Stagnation (%llu s), enabling value profiling.",
        (unsigned long long)(no_find_ms / 1000));

  } else if (!should && afl->value_profile_active) {

    /* Keep VP on for one full queue cycle after activation to avoid
       immediate on/off flapping on transient coverage recoveries. */
    if (afl->queue_cycle <= afl->value_profile_enabled_cycle) return;

    afl->value_profile_active = 0;
    afl->value_profile_enabled_cycle = 0;
    afl->score_changed = 1;
    OKF("New edge coverage found, disabling value profiling.");

  }

}
