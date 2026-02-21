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
#include <assert.h>

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
   - runtime source: set enabled state, bump exec epoch, reset control list
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
    vp->enabled = afl->value_profile_active ? 1U : 0U;
    if (vp->enabled) {

      ++vp->exec_id;
      if (unlikely(!vp->exec_id)) { ++vp->exec_id; }

    }

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

    return afl->shm.vp_map && afl->shm.vp_map->enabled;

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

typedef struct {

  vp_map_t *vp;
  u32       control_len;
  u32       pos;

} vp_runtime_site_iter_t;

/* Iterate runtime VP sites listed in control[].
   Runtime SHM is producer-owned by target hooks, so debug builds assert
   index bounds while release builds keep the hot path branch-free. */
static inline void vp_runtime_site_iter_init(vp_runtime_site_iter_t *it,
                                             vp_map_t               *vp) {

  assert(vp);
  it->vp = vp;
  it->control_len = MIN(vp->control_len, (u32)VP_CONTROL_CAP);
  it->pos = 0;

}

static inline u8 vp_runtime_site_iter_next(vp_runtime_site_iter_t *it,
                                           u32 *site, vp_site_t **site_state) {

  if (it->pos >= it->control_len) return 0;

  u32 k = it->vp->control[it->pos++];
  assert(k < CMP_MAP_W);
  *site = k;
  if (site_state) *site_state = &it->vp->site[k];
  return 1;

}

/* Mask runtime slot updates to valid+touched+active for this site. */
static inline u16 vp_runtime_site_changed_mask(const vp_site_t *site,
                                               u16              active_mask) {

  return (u16)(site->touched_mask & site->valid_mask & active_mask);

}

typedef struct {

  const u64 *bitmap;
  u32        word_idx;
  u64        bits;

} vp_trigger_site_iter_t;

/* Iterate cmp_map site indices present in vp_trigger_bitmap. */
static inline void vp_trigger_site_iter_init(vp_trigger_site_iter_t *it,
                                             const u64              *bitmap) {

  it->bitmap = bitmap;
  it->word_idx = 0;
  it->bits = 0;

}

static inline u8 vp_trigger_site_iter_next(vp_trigger_site_iter_t *it,
                                           u32                    *site) {

  while (!it->bits) {

    if (it->word_idx >= VP_TRIGGER_BITMAP_WORDS) return 0;
    it->bits = it->bitmap[it->word_idx];
    if (!it->bits) {

      ++it->word_idx;
      continue;

    }

  }

  u32 bit = (u32)__builtin_ctzll(it->bits);
  it->bits &= it->bits - 1;
  *site = it->word_idx * 64U + bit;
  if (!it->bits) ++it->word_idx;
  return 1;

}

/* Clear per-exec trigger bitmap before populating it from compare data. */
static inline void vp_reset_trigger_bitmap(afl_state_t *afl) {

  memset(afl->vp_trigger_bitmap, 0, sizeof(afl->vp_trigger_bitmap));

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
  vp_reset_trigger_bitmap(afl);

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

/* First frontier slot index for a compare site. */
static inline size_t vp_site_base(afl_state_t *afl, u32 site) {

  return (size_t)site * afl->value_profile_slots;

}

/* Cost tie-breaker used for equal-distance frontier candidates. */
static inline u64 vp_entry_cost(const struct queue_entry *q) {

  return (u64)q->exec_us * (u64)q->len;

}

/* Frontier ordering: lower distance wins; for ties, lower cost wins. */
static inline u8 vp_is_better(u32 cand_dist, u64 cand_cost, u32 old_dist,
                              u64 old_cost) {

  if (old_dist >= VP_DIST_UNSOLVED) return 1;
  if (cand_dist < old_dist) return 1;
  if (cand_dist == old_dist && cand_cost < old_cost) return 1;
  return 0;

}

/* Disable stale VP-only entries once they are no longer referenced by any
   frontier slot and have survived at least one queue cycle. */
static inline void vp_maybe_disable_entry(afl_state_t        *afl,
                                          struct queue_entry *q) {

  if (!q || q->disabled || !q->vp_only || q->has_new_cov || q->vp_ref_cnt)
    return;
  if (!q->vp_last_ref_cycle || afl->queue_cycle <= q->vp_last_ref_cycle) return;

  q->disabled = 1;
  q->perf_score = 0;
  if (afl->active_items) { --afl->active_items; }
  if (!q->was_fuzzed && afl->pending_not_fuzzed) { --afl->pending_not_fuzzed; }
  q->was_fuzzed = 1;
  afl->score_changed = 1;
  afl->reinit_table = 1;

}

/* Drop one frontier reference from q and trigger delayed disable logic when
   refcount reaches zero. */
static inline void vp_dec_ref(afl_state_t *afl, struct queue_entry *q) {

  if (!q || !q->vp_ref_cnt) return;
  --q->vp_ref_cnt;
  if (!q->vp_ref_cnt) {

    q->vp_last_ref_cycle = afl->queue_cycle;
    vp_maybe_disable_entry(afl, q);

  }

}

/* Increment frontier reference count for q. */
static inline void vp_inc_ref(struct queue_entry *q) {

  if (!q) return;
  ++q->vp_ref_cnt;

}

/* Reset one frontier slot to the empty sentinel state. */
static inline void vp_clear_slot(afl_state_t *afl, size_t idx) {

  struct queue_entry *old = afl->vp_frontier[idx].owner;
  if (old) vp_dec_ref(afl, old);
  afl->vp_frontier[idx].owner = NULL;
  afl->vp_frontier[idx].dist = VP_DIST_UNSOLVED;
  afl->vp_frontier[idx].tag = 0;
  afl->vp_frontier[idx].cost = ~(u64)0;

}

/* Recompute top_rated_vp/site distance from all active slots of one site. */
static inline void vp_refresh_site_winner(afl_state_t *afl, u32 site) {

  size_t              base = vp_site_base(afl, site);
  struct queue_entry *best_q = NULL;
  u32                 best_dist = VP_DIST_UNSOLVED;
  u64                 best_cost = ~(u64)0;

  for (u32 i = 0; i < afl->value_profile_slots; ++i) {

    size_t              idx = base + i;
    struct queue_entry *owner = afl->vp_frontier[idx].owner;
    u32                 dist = afl->vp_frontier[idx].dist;
    if (!owner || owner->disabled || dist >= VP_DIST_UNSOLVED) {

      if (owner && owner->disabled) vp_clear_slot(afl, idx);
      continue;

    }

    u64 cost = afl->vp_frontier[idx].cost;
    if (!best_q || dist < best_dist ||
        (dist == best_dist && cost < best_cost)) {

      best_q = owner;
      best_dist = dist;
      best_cost = cost;

    }

  }

  if (!best_q) {

    if (afl->top_rated_vp[site] ||
        afl->top_rated_vp_dist[site] != VP_DIST_UNSOLVED) {

      afl->top_rated_vp[site] = NULL;
      afl->top_rated_vp_dist[site] = VP_DIST_UNSOLVED;
      afl->score_changed = 1;

    }

    return;

  }

  if (afl->top_rated_vp[site] != best_q ||
      afl->top_rated_vp_dist[site] != best_dist) {

    afl->top_rated_vp[site] = best_q;
    afl->top_rated_vp_dist[site] = best_dist;
    afl->score_changed = 1;

  }

}

/* Re-scan is only needed on content change, or when cached winner became
   stale due to delayed disable. */
static inline u8 vp_site_refresh_needed(afl_state_t *afl, u32 site,
                                        u8 site_changed) {

  return site_changed ||
         (afl->top_rated_vp[site] && afl->top_rated_vp[site]->disabled);

}

typedef struct {

  s32 tag_match_idx;            /* Slot index with matching tag, -1 if none */
  s32 first_empty_idx;         /* First empty slot index, -1 if none        */
  s32 worst_idx;               /* Worst resident slot index, -1 if none     */
  u32 worst_dist;              /* Distance value for worst_idx              */
  u64 worst_cost;              /* Cost tie-break value for worst_idx        */

} vp_slot_scan_t;

typedef struct {

  u16 tag;
  u32 dist;

} vp_site_candidate_t;

/* Reset scan accumulator before processing one compare site. */
static inline void vp_slot_scan_reset(vp_slot_scan_t *scan) {

  scan->tag_match_idx = -1;
  scan->first_empty_idx = -1;
  scan->worst_idx = -1;
  scan->worst_dist = 0;
  scan->worst_cost = 0;

}

/* Frontier slot validity check shared by scan paths. */
static inline u8 vp_frontier_slot_is_empty(const struct queue_entry *owner,
                                           u32                       dist) {

  return !owner || owner->disabled || dist >= VP_DIST_UNSOLVED;

}

/* Active runtime-slot mask for configured slot count (1..16). */
static inline u16 vp_active_slot_mask(u16 max_slot_count) {

  return (u16)((1U << max_slot_count) - 1U);

}

/* Collect runtime-slot (tag,dist) candidates for one site from changed bits. */
static inline u32 vp_collect_runtime_site_candidates(const vp_site_t *site,
                                                     u16 active_mask,
                                                     vp_site_candidate_t *out,
                                                     u32                  cap) {

  u32 n = 0;
  u16 changed = vp_runtime_site_changed_mask(site, active_mask);

  for (u16 bits = changed; bits && n < cap; bits = (u16)(bits & (bits - 1U))) {

    u16 i = (u16)__builtin_ctz((u32)bits);
    u16 dist = site->slots[i].best_dist;
    if (!dist) continue;

    out[n].tag = site->slots[i].slot_key;
    out[n].dist = dist;
    ++n;

  }

  return n;

}

/* Scan a site's slots and collect candidate indices for tag match, empty slot,
   and worst slot (for replacement decisions). */
static inline void vp_frontier_site_scan_slots(afl_state_t *afl, u32 site,
                                               u16 tag, u8 clear_stale,
                                               vp_slot_scan_t *scan) {

  vp_slot_scan_reset(scan);

  size_t base = vp_site_base(afl, site);
  for (u32 i = 0; i < afl->value_profile_slots; ++i) {

    size_t               idx = base + i;
    vp_frontier_entry_t *entry = &afl->vp_frontier[idx];
    struct queue_entry  *owner = entry->owner;
    u32                  slot_dist = entry->dist;

    if (clear_stale && owner && owner->disabled) {

      vp_clear_slot(afl, idx);
      owner = NULL;

    }

    u8 is_empty = vp_frontier_slot_is_empty(owner, slot_dist);

    if (!is_empty && entry->tag == tag) {

      scan->tag_match_idx = (s32)idx;
      break;

    }

    if (is_empty) {

      if (scan->first_empty_idx < 0) scan->first_empty_idx = (s32)idx;

    } else if (scan->worst_idx < 0 || slot_dist > scan->worst_dist ||

               (slot_dist == scan->worst_dist &&
                entry->cost > scan->worst_cost)) {

      scan->worst_idx = (s32)idx;
      scan->worst_dist = slot_dist;
      scan->worst_cost = entry->cost;

    }

  }

}

/* Probe-only decision used for admission:
   would (site,tag,dist) improve this site's frontier by distance only? */
static inline u8 vp_frontier_site_would_improve(afl_state_t *afl, u32 site,
                                                u16 tag, u32 dist) {

  if (!dist) return 0;

  vp_slot_scan_t scan;
  vp_frontier_site_scan_slots(afl, site, tag, 0, &scan);

  if (scan.tag_match_idx >= 0) {

    return dist < afl->vp_frontier[scan.tag_match_idx].dist;

  }

  if (scan.first_empty_idx >= 0) return 1;
  assert(scan.worst_idx >= 0);
  return dist < scan.worst_dist;

}

/* Mutating apply path for one site candidate; updates slot ownership and
   reference counts when replacement succeeds. */
static inline u8 vp_frontier_site_apply(afl_state_t *afl, struct queue_entry *q,
                                        u32 site, u16 tag, u32 dist, u64 cost) {

  if (!dist) return 0;

  vp_slot_scan_t scan;
  vp_frontier_site_scan_slots(afl, site, tag, 1, &scan);

  s32 idx = -1;
  if (scan.tag_match_idx >= 0) {

    if (!vp_is_better(dist, cost, afl->vp_frontier[scan.tag_match_idx].dist,
                      afl->vp_frontier[scan.tag_match_idx].cost))
      return 0;
    idx = scan.tag_match_idx;

  } else if (scan.first_empty_idx >= 0) {

    idx = scan.first_empty_idx;

  } else {

    assert(scan.worst_idx >= 0);
    if (!vp_is_better(dist, cost, scan.worst_dist, scan.worst_cost)) return 0;
    idx = scan.worst_idx;

  }

  struct queue_entry *old = afl->vp_frontier[idx].owner;
  if (old && old != q) vp_dec_ref(afl, old);
  if (old != q) { vp_inc_ref(q); }

  afl->vp_frontier[idx].owner = q;
  afl->vp_frontier[idx].tag = tag;
  afl->vp_frontier[idx].dist = dist;
  afl->vp_frontier[idx].cost = cost;
  return 1;

}

/* RTN distance metric for one compare hit: remaining suffix weight plus first
   differing-byte hamming distance. */
static inline u32 vp_rtn_compare_dist(const struct cmpfn_operands *rtn,
                                      u32 max_len, u32 prefix_len) {

  u32 rem = max_len - prefix_len;
  return (rem - 1U) * 8U +
         popcount_u8(rtn->v0[prefix_len] ^ rtn->v1[prefix_len]);

}

/* Build an RTN slot tag from length class and per-class ordinal. */
static inline u16 vp_rtn_compare_tag(u32 max_len, u8 ord_in_len_class[32]) {

  u32 len_class = MIN(MAX(max_len, 1U), 32U) - 1U;
  u32 ord = ord_in_len_class[len_class]++;
  return (u16)(0x8000U | ((len_class & 31U) << 5) | (ord & 31U));

}

/* Collect CmpLog-site (tag,dist) candidates for frontier probe/apply paths. */
static inline u32 vp_collect_cmplog_site_candidates(struct cmp_map *cmp, u32 k,
                                                    vp_site_candidate_t *out,
                                                    u32                  cap) {

  u32 hits = vp_site_hits(&cmp->headers[k]);
  u32 n = 0;

  if (cmp->headers[k].type == CMP_TYPE_INS) {

    u32 shape = SHAPE_BYTES(cmp->headers[k].shape);
    for (u32 j = 0; j < hits && n < cap; ++j) {

      u32 hamming, abs_dist;
      if (!compute_ins_metrics(&cmp->log[k][j], shape, VP_DIST_EXACT, &hamming,
                               &abs_dist))
        continue;

      out[n].tag = (u16)(j & 31U);
      out[n].dist = MIN(hamming, abs_dist);
      ++n;

    }

  } else {

    struct cmpfn_operands *rtn = (struct cmpfn_operands *)cmp->log[k];
    u8                     ord_in_len_class[32] = {0};
    for (u32 j = 0; j < hits && n < cap; ++j) {

      u32 max_len, prefix_len;
      if (analyze_rtn_compare(&rtn[j], &max_len, &prefix_len)) continue;

      out[n].tag = vp_rtn_compare_tag(max_len, ord_in_len_class);
      out[n].dist = vp_rtn_compare_dist(&rtn[j], max_len, prefix_len);
      ++n;

    }

  }

  return n;

}

/* Apply one site's candidate list to frontier slots and refresh the per-site
   winner if needed. Returns whether any slot changed. */
static inline u8 vp_apply_site_candidates(afl_state_t        *afl,
                                          struct queue_entry *q, u32 site,
                                          vp_site_candidate_t *candidates,
                                          u32 cand_count, u64 cost) {

  u8 site_changed = 0;
  for (u32 i = 0; i < cand_count; ++i) {

    if (vp_frontier_site_apply(afl, q, site, candidates[i].tag,
                               candidates[i].dist, cost))
      site_changed = 1;

  }

  if (vp_site_refresh_needed(afl, site, site_changed)) {

    vp_refresh_site_winner(afl, site);

  }

  return site_changed;

}

/* Fast VP-interest probe used before queue admission.
   Admission is based on distance-only progress; cost tie-breaks are applied
   later in vp_update_bitmap_score() after calibration provides real exec_us. */
u8 vp_frontier_would_improve(afl_state_t *afl) {

  if (unlikely(!afl->vp_frontier)) return 0;

  assert(afl->value_profile_source == VP_SOURCE_RUNTIME_SHM);

  vp_map_t *vp = afl->shm.vp_map;
  if (unlikely(!vp || !vp->enabled)) return 0;
  u16                    max_slot_count = (u16)afl->value_profile_slots;
  u16                    active_mask = vp_active_slot_mask(max_slot_count);
  vp_runtime_site_iter_t it;
  vp_runtime_site_iter_init(&it, vp);
  u32        k;
  vp_site_t *site;
  while (vp_runtime_site_iter_next(&it, &k, &site)) {

    vp_site_candidate_t candidates[VP_MAX_SLOTS];
    u32                 cand_count = vp_collect_runtime_site_candidates(
        site, active_mask, candidates, max_slot_count);

    for (u32 i = 0; i < cand_count; ++i) {

      if (vp_frontier_site_would_improve(afl, k, candidates[i].tag,
                                         candidates[i].dist))
        return 1;

    }

  }

  return 0;

}

/* Apply L1 runtime-SHM candidates to the VP frontier using caller-provided
   cost (used as tie-breaker at equal distance). */
static inline u8 vp_apply_runtime_frontier(afl_state_t        *afl,
                                           struct queue_entry *q, u64 cost) {

  vp_map_t *vp = afl->shm.vp_map;
  if (unlikely(!vp || !vp->enabled)) return 0;

  u8                     improved = 0;
  u16                    max_slot_count = (u16)afl->value_profile_slots;
  u16                    active_mask = vp_active_slot_mask(max_slot_count);
  vp_runtime_site_iter_t it;
  vp_runtime_site_iter_init(&it, vp);
  u32        k;
  vp_site_t *site;
  while (vp_runtime_site_iter_next(&it, &k, &site)) {

    vp_site_candidate_t candidates[VP_MAX_SLOTS];
    u32                 cand_count = vp_collect_runtime_site_candidates(
        site, active_mask, candidates, max_slot_count);

    if (vp_apply_site_candidates(afl, q, k, candidates, cand_count, cost)) {

      improved = 1;

    }

  }

  return improved;

}

/* Apply CmpLog-site candidates to the VP frontier and return whether any
   frontier slot changed. */
static inline u8 vp_apply_cmplog_frontier(afl_state_t        *afl,
                                          struct queue_entry *q, u64 cost) {

  struct cmp_map *cmp = afl->shm.cmp_map;
  if (unlikely(!cmp)) return 0;

  u8                     improved = 0;
  vp_trigger_site_iter_t it;
  vp_trigger_site_iter_init(&it, afl->vp_trigger_bitmap);
  u32 k;
  while (vp_trigger_site_iter_next(&it, &k)) {

    if (!cmp->headers[k].hits) continue;

    vp_site_candidate_t candidates[CMP_MAP_H];
    u32                 cand_count =
        vp_collect_cmplog_site_candidates(cmp, k, candidates, CMP_MAP_H);
    if (vp_apply_site_candidates(afl, q, k, candidates, cand_count, cost)) {

      improved = 1;

    }

  }

  return improved;

}

void vp_update_bitmap_score_with_cost(afl_state_t *afl, struct queue_entry *q,
                                      u64 cost) {

  if (unlikely(!q || !afl->vp_frontier)) return;

  u8 improved = 0;
  if (afl->value_profile_source == VP_SOURCE_RUNTIME_SHM) {

    improved = vp_apply_runtime_frontier(afl, q, cost);

  } else {

    improved = vp_apply_cmplog_frontier(afl, q, cost);

  }

  if (q->vp_only && !q->vp_ref_cnt && !q->vp_last_ref_cycle) {

    q->vp_last_ref_cycle = afl->queue_cycle;

  }

  if (improved) afl->score_changed = 1;
  vp_maybe_disable_entry(afl, q);

}

void vp_update_bitmap_score(afl_state_t *afl, struct queue_entry *q) {

  vp_update_bitmap_score_with_cost(afl, q, vp_entry_cost(q));

}

/* Apply deferred disable checks for VP-only queue entries at queue-cycle
   boundaries. */
void vp_apply_delayed_evictions(afl_state_t *afl) {

  if (!afl->value_profile_mode) return;
  u8 needs_retry = 0;

  for (u32 i = 0; i < afl->queued_items; ++i) {

    struct queue_entry *q = afl->queue_buf[i];
    if (!q) continue;

    if (!q->disabled && q->vp_only && !q->has_new_cov && !q->vp_ref_cnt &&
        q->vp_last_ref_cycle && afl->queue_cycle <= q->vp_last_ref_cycle) {

      needs_retry = 1;
      continue;

    }

    vp_maybe_disable_entry(afl, q);

  }

  if (needs_retry) { afl->score_changed = 1; }

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

