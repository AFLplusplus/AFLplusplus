/*
   american fuzzy lop++ - value profiling
   --------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                     Dominik Maier <mail@dmnk.co>,
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
#include "value-profile.h"
#include <assert.h>

static inline const char *vp_entry_basename(const struct queue_entry *q) {

  const char *fname = q ? (const char *)q->fname : NULL;
  const char *base = fname ? strrchr(fname, '/') : NULL;
  return base ? base + 1 : fname;

}

static inline void vp_state_create_marker(afl_state_t *afl,
                                          const char  *state_dir,
                                          const char  *case_name) {

  if (!afl || !afl->out_dir || !case_name || !*case_name) return;

  char fn[PATH_MAX];
  snprintf(fn, sizeof(fn), "%s/queue/.state/%s/%s", (const char *)afl->out_dir,
           state_dir, case_name);

  s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, afl->perm);
  if (fd < 0) {

    if (errno == EEXIST) return;
    PFATAL("Unable to create '%s'", fn);

  }

  if (afl->chown_needed) {

    if (fchown(fd, -1, afl->fsrv.gid) == -1) { PFATAL("fchown() failed"); }

  }

  close(fd);

}

static inline u8 vp_state_marker_exists(afl_state_t *afl, const char *state_dir,
                                        const char *case_name) {

  if (!afl || !afl->in_dir || !case_name || !*case_name) return 0;

  char fn[PATH_MAX];
  snprintf(fn, sizeof(fn), "%s/.state/%s/%s", (const char *)afl->in_dir,
           state_dir, case_name);
  return (u8)(access(fn, F_OK) == 0);

}

void vp_mark_entry_vp_only(afl_state_t *afl, struct queue_entry *q) {

  if (!q) return;

  if (!q->vp_only) { ++afl->vp_only_items; }
  q->vp_only = 1;
  vp_state_create_marker(afl, "vp_only", vp_entry_basename(q));

}

void vp_persist_disabled_marker(afl_state_t *afl, struct queue_entry *q) {

  if (!q) return;
  vp_state_create_marker(afl, "vp_disabled", vp_entry_basename(q));

}

void vp_restore_queue_entry_state(afl_state_t *afl, struct queue_entry *q,
                                  const char *case_name) {

  if (!afl || !q || !case_name || !*case_name) return;

  u8 was_vp_only = vp_state_marker_exists(afl, "vp_only", case_name);
  u8 was_disabled = vp_state_marker_exists(afl, "vp_disabled", case_name);

  if (was_vp_only || was_disabled) {

    /* On a fastresume the blob is authoritative for vp_only and the restore
       loop does the counting, exactly as for disabled entries below. */
    if (!q->vp_only && !afl->fast_resume) { ++afl->vp_only_items; }
    q->vp_only = 1;
    vp_state_create_marker(afl, "vp_only", case_name);

  }

  if (was_disabled) { vp_state_create_marker(afl, "vp_disabled", case_name); }
  if (unlikely(afl->fast_resume)) return;
  if (!was_disabled || q->disabled) return;

  ++afl->disabled_items;
  q->disabled = 1;
  q->perf_score = 0;
  if (afl->active_items) { --afl->active_items; }
  if (!q->was_fuzzed && afl->pending_not_fuzzed) { --afl->pending_not_fuzzed; }
  q->was_fuzzed = 1;

}

/* Prepare per-execution runtime VP state before running the main target. */
void vp_prepare_exec(afl_state_t *afl, afl_forkserver_t *fsrv) {

  if (likely(!afl->value_profile_mode)) return;
  if (fsrv != &afl->fsrv) return;

  if (unlikely(!fsrv->use_value_profile)) {

    FATAL(
        "Value profiling requires target support for value profile runtime "
        "SHM. Recompile the target with "
        "AFL_LLVM_VALUE_PROFILE=1.");

  }

  if (unlikely(!afl->shm.vp_map)) {

    FATAL(
        "Value profile runtime map missing although value profiling was "
        "selected.");

  }

  vp_map_t *vp = afl->shm.vp_map;
  vp->enabled =
      (afl->value_profile_active && !afl->value_profile_suppressed) ? 1U : 0U;
  if (!vp->enabled) return;

  if (unlikely(!afl->vp_focus_active && afl->vp_sites_assigned &&
               vp->control_len > VP_FOCUS_TARGET_SITES)) {

    afl->vp_focus_rebuild_pending = 1;

  }

  ++vp->exec_id;
  if (unlikely(!vp->exec_id)) { ++vp->exec_id; }
  vp->control_len = 0;

}

static inline u8 vp_bitmap_test(const u64 *bitmap, u32 site) {

  return (u8)((bitmap[site >> 6] >> (site & 63)) & 1ULL);

}

static inline void vp_bitmap_set(u64 *bitmap, u32 site) {

  bitmap[site >> 6] |= (1ULL << (site & 63));

}

#define VP_FOCUS_BITMAP_BYTES (sizeof(u64) * (VP_MAP_W / 64U))

void vp_focus_init(afl_state_t *afl) {

  if (!afl || afl->vp_focus_bitmap) return;

  afl->vp_focus_bitmap = ck_alloc(VP_FOCUS_BITMAP_BYTES);
  afl->vp_focus_prev = ck_alloc(VP_FOCUS_BITMAP_BYTES);
  afl->vp_focus_relevant = ck_alloc(VP_FOCUS_BITMAP_BYTES);
  afl->vp_site_idle = ck_alloc(sizeof(u16) * VP_MAP_W);
  afl->vp_site_owned = ck_alloc(sizeof(u8) * VP_MAP_W);

}

static void vp_focus_push(afl_state_t *afl) {

  vp_map_t *vp = afl ? afl->shm.vp_map : NULL;
  if (unlikely(!vp)) return;

  if (!afl->vp_focus_active || !afl->vp_focus_bitmap) {

    vp->filter_mode = VP_FILTER_OFF;
    memset(vp->filter_bitmap, 0, sizeof(vp->filter_bitmap));
    return;

  }

  memcpy(vp->filter_bitmap, afl->vp_focus_bitmap, sizeof(vp->filter_bitmap));
  vp->filter_mode = VP_FILTER_FOCUS;

}

void vp_runtime_set_site_filter(afl_state_t *afl, const u16 *site_ids,
                                u32 site_cnt) {

  vp_map_t *vp = afl ? afl->shm.vp_map : NULL;
  if (unlikely(!vp)) return;

  memset(vp->filter_bitmap, 0, sizeof(vp->filter_bitmap));
  for (u32 i = 0; i < site_cnt; ++i) {

    u16 site_id = site_ids[i];
    vp->filter_bitmap[site_id >> 6] |= (1ULL << (site_id & 63));

  }

  vp->filter_mode = site_cnt ? VP_FILTER_STRICT : VP_FILTER_OFF;

}

void vp_runtime_clear_site_filter(afl_state_t *afl) {

  vp_focus_push(afl);

}

u8 vp_runtime_observe_begin(afl_state_t *afl, const u16 *site_ids, u32 site_cnt,
                            vp_site_t *saved_sites) {

  vp_map_t *vp = afl ? afl->shm.vp_map : NULL;
  if (unlikely(!vp || !vp->enabled || !site_ids || !site_cnt || !saved_sites))
    return 0;

  for (u32 i = 0; i < site_cnt; ++i) {

    u16 site_id = site_ids[i];
    saved_sites[i] = vp->site[site_id];

    vp->site[site_id].hit_count = 0;
    vp->site[site_id].touched_mask = 0;
    vp->site[site_id].exec_seen = 0;
    vp->site[site_id].flags &= ~(u32)VP_SITE_RETIRED;

  }

  vp_runtime_set_site_filter(afl, site_ids, site_cnt);
  return 1;

}

void vp_runtime_observe_end(afl_state_t *afl, const u16 *site_ids, u32 site_cnt,
                            const vp_site_t *saved_sites) {

  vp_map_t *vp = afl ? afl->shm.vp_map : NULL;
  if (unlikely(!vp || !site_ids || !site_cnt || !saved_sites)) return;

  for (u32 i = 0; i < site_cnt; ++i) {

    vp->site[site_ids[i]] = saved_sites[i];

  }

  vp_runtime_clear_site_filter(afl);

}

typedef struct {

  vp_map_t *vp;
  u32       control_len;
  u32       pos;

} vp_runtime_site_iter_t;

/* Iterate runtime VP sites listed in control[]. control[] stores u16 site ids,
   matching the current 16-bit VP_MAP_W namespace. */
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
  *site = k;
  if (site_state) *site_state = &it->vp->site[k];
  return 1;

}

/* Mask runtime slot updates to valid fixed-width slots for this site. */
static inline u16 vp_runtime_site_changed_mask(const vp_site_t *site) {

  return (u16)(site->touched_mask & VP_SLOT_MASK);

}

static inline size_t vp_site_base(u32 site) {

  return (size_t)site * VP_SLOTS;

}

static inline size_t vp_runtime_slot_base(u32 site, u16 slot_rel) {

  return vp_site_base(site) + (size_t)slot_rel;

}

static inline u8 vp_frontier_dist_is_unresolved(u32 dist) {

  return (u8)(dist && dist < VP_DIST_UNSOLVED);

}

static inline u8 vp_frontier_entry_is_unresolved(
    const vp_frontier_entry_t *entry) {

  return (u8)(entry && entry->owner &&
              vp_frontier_dist_is_unresolved(entry->dist));

}

/* Cost tie-breaker used for equal-distance frontier candidates.
   exec_us * len intentionally prefers inputs that are both quick to run and
   small to mutate further. It is only a tie-breaker after distance equality,
   not a replacement for the VP gradient itself. */
static inline u64 vp_entry_cost(const struct queue_entry *q) {

  return (u64)q->exec_us * (u64)q->len;

}

/* Frontier ordering: lower distance wins; for ties, lower cost wins. */
static inline u8 vp_is_better(u32 cand_dist, u64 cand_cost,
                              const vp_frontier_entry_t *old_entry) {

  if (old_entry->dist >= VP_DIST_UNSOLVED) return 1;
  if (cand_dist < old_entry->dist) return 1;
  if (!old_entry->owner) return 0;
  if (cand_dist == old_entry->dist &&
      cand_cost < vp_entry_cost(old_entry->owner))
    return 1;
  return 0;

}

static inline void vp_disable_entry_now(afl_state_t        *afl,
                                        struct queue_entry *q) {

  if (!q || q->disabled) return;

  ++afl->disabled_items;
  q->disabled = 1;
  if (q->vp_only) { vp_persist_disabled_marker(afl, q); }
  q->perf_score = 0;
  if (afl->active_items) { --afl->active_items; }
  if (!q->was_fuzzed && afl->pending_not_fuzzed) { --afl->pending_not_fuzzed; }
  q->was_fuzzed = 1;
  afl->score_changed = 1;
  afl->reinit_table = 1;

}

static inline u8 vp_entry_can_retire(const struct queue_entry *q) {

  return q && !q->disabled && q->vp_only && !q->has_new_cov && !q->vp_ref_cnt &&
         !q->tc_ref;

}

static inline void vp_schedule_delayed_eviction(afl_state_t        *afl,
                                                struct queue_entry *q) {

  if (afl && afl->value_profile_mode && vp_entry_can_retire(q)) {

    afl->vp_delayed_evictions_pending = 1;

  }

}

/* Disable stale VP-only entries once they are no longer referenced by any
   VP or coverage slot and have survived at least one queue cycle. */
static inline void vp_maybe_disable_entry(afl_state_t        *afl,
                                          struct queue_entry *q) {

  if (!vp_entry_can_retire(q)) return;
  if (!q->vp_last_ref_cycle || afl->queue_cycle <= q->vp_last_ref_cycle) return;

  vp_disable_entry_now(afl, q);

}

void vp_disable_unowned_entry(afl_state_t *afl, struct queue_entry *q) {

  if (!afl || !vp_entry_can_retire(q)) return;

  vp_disable_entry_now(afl, q);

}

void vp_coverage_owner_released(afl_state_t *afl, struct queue_entry *q) {

  if (!afl || !afl->value_profile_mode || !vp_entry_can_retire(q)) return;
  if (!q->vp_last_ref_cycle) { q->vp_last_ref_cycle = afl->queue_cycle; }
  vp_schedule_delayed_eviction(afl, q);

}

/* Keep coverage-identical inputs that own active VP frontier slots. */
u8 vp_try_disable_coverage_duplicate(afl_state_t *afl, struct queue_entry *q) {

  if (!afl || !q || q->disabled) return 0;
  if (afl->value_profile_active && q->vp_ref_cnt) return 0;

  if (!q->was_fuzzed) {

    q->was_fuzzed = 1;
    --afl->pending_not_fuzzed;
    --afl->active_items;

  }

  afl->reinit_table = 1;
  ++afl->disabled_items;
  q->disabled = 1;
  q->perf_score = 0;
  return 1;

}

/* Drop one frontier reference from q and trigger delayed disable logic when
   refcount reaches zero. */
static inline void vp_dec_ref(afl_state_t *afl, struct queue_entry *q) {

  if (!q || !q->vp_ref_cnt) return;
  --q->vp_ref_cnt;
  if (!q->vp_ref_cnt) {

    q->vp_unresolved_ref_cnt = 0;
    if (q->vp_trim_deferred) {

      q->trim_done = 0;
      q->vp_trim_deferred = 0;

    }

    q->vp_last_ref_cycle = afl->queue_cycle;
    vp_schedule_delayed_eviction(afl, q);
    vp_maybe_disable_entry(afl, q);

  }

}

/* Increment frontier reference count for q. */
static inline void vp_inc_ref(struct queue_entry *q) {

  if (!q) return;
  ++q->vp_ref_cnt;

}

static inline void vp_dec_unresolved_ref(struct queue_entry *q) {

  if (!q || !q->vp_unresolved_ref_cnt) return;
  --q->vp_unresolved_ref_cnt;

}

static inline void vp_inc_unresolved_ref(struct queue_entry *q) {

  if (!q) return;
  ++q->vp_unresolved_ref_cnt;

}

/* Reset one frontier slot to the empty sentinel state. */
static inline void vp_clear_slot(afl_state_t *afl, size_t idx) {

  vp_frontier_entry_t *entry = &afl->vp_frontier[idx];
  struct queue_entry  *old = entry->owner;
  u8                   old_unresolved = vp_frontier_entry_is_unresolved(entry);
  if (old) {

    if (old_unresolved) { vp_dec_unresolved_ref(old); }
    vp_dec_ref(afl, old);

  }

  entry->owner = NULL;
  entry->dist = VP_DIST_UNSOLVED;

}

typedef struct {

  const vp_site_t *site;
  u16              remaining_mask;

} vp_runtime_candidate_iter_t;

/* Frontier slot validity check shared by scan paths. A solved slot stays
   closed without an owner. */
static inline u8 vp_frontier_slot_is_empty(const struct queue_entry *owner,
                                           u32                       dist) {

  if (dist >= VP_DIST_UNSOLVED) return 1;
  if (!dist) return 0;
  return !owner || owner->disabled;

}

static inline void vp_release_solved_slot(afl_state_t *afl, size_t idx) {

  vp_frontier_entry_t *entry = &afl->vp_frontier[idx];
  if (entry->dist || !entry->owner) return;

  vp_dec_ref(afl, entry->owner);
  entry->owner = NULL;

}

/* Yield valid physical-site candidates one at a time so consumers can stop
   without first materializing every changed slot. */
static inline void vp_runtime_candidate_iter_init(
    vp_runtime_candidate_iter_t *it, const vp_site_t *site) {

  it->site = site;
  it->remaining_mask = vp_runtime_site_changed_mask(site);

}

static inline u8 vp_runtime_candidate_iter_next(vp_runtime_candidate_iter_t *it,
                                                u16 *slot_rel, u32 *dist) {

  while (it->remaining_mask) {

    u16 slot = (u16)__builtin_ctz((u32)it->remaining_mask);
    it->remaining_mask = (u16)(it->remaining_mask & (it->remaining_mask - 1U));
    u16 candidate_dist = it->site->slots[slot].best_dist;
    if (candidate_dist >= VP_DIST_UNSOLVED) continue;

    *slot_rel = slot;
    *dist = candidate_dist;
    return 1;

  }

  return 0;

}

void vp_mark_favored_queue_entry(afl_state_t *afl, struct queue_entry *q) {

  if (!afl || !afl->vp_frontier || !afl->value_profile_active || !q ||
      q->disabled || !q->vp_unresolved_ref_cnt || q->favored)
    return;

  q->favored = 1;
  ++afl->queued_favored;

  if (!q->was_fuzzed) {

    ++afl->pending_favored;
    if (unlikely(afl->smallest_favored < 0 ||
                 afl->smallest_favored > (s64)q->id)) {

      afl->smallest_favored = (s64)q->id;

    }

  }

}

/* Queue admission for VP-only inputs is intentionally strict-distance-only.
   Equal-distance cost improvements are not admitted on VP alone; they only
   matter once a seed is already being applied to the frontier. A solved
   distance (0) on a slot no queue entry owns yet also does not admit: the
   constraint is already satisfied and there is no gradient left to follow,
   so admitting on that signal alone would teach the frontier nothing an
   existing owner cannot already represent. */
static inline u8 vp_frontier_runtime_slot_would_improve(afl_state_t *afl,
                                                        u32 site, u16 slot_rel,
                                                        u32 dist) {

  if (dist >= VP_DIST_UNSOLVED) return 0;

  size_t               idx = vp_runtime_slot_base(site, slot_rel);
  vp_frontier_entry_t *entry = &afl->vp_frontier[idx];
  if (vp_frontier_slot_is_empty(entry->owner, entry->dist)) return dist != 0;

  return dist < entry->dist;

}

static inline u8 vp_frontier_runtime_slot_apply(afl_state_t        *afl,
                                                struct queue_entry *q, u32 site,
                                                u16 slot_rel, u32 dist,
                                                u64 cost) {

  if (dist >= VP_DIST_UNSOLVED) return 0;

  size_t               idx = vp_runtime_slot_base(site, slot_rel);
  vp_frontier_entry_t *entry = &afl->vp_frontier[idx];
  struct queue_entry  *old = entry->owner;
  u8                   old_unresolved = vp_frontier_entry_is_unresolved(entry);
  u8                   new_unresolved = vp_frontier_dist_is_unresolved(dist);
  if (!vp_frontier_slot_is_empty(old, entry->dist) &&
      !vp_is_better(dist, cost, entry))
    return 0;

  if (old && old != q) {

    if (old_unresolved) { vp_dec_unresolved_ref(old); }
    vp_dec_ref(afl, old);

  }

  if (old != q) {

    vp_inc_ref(q);
    if (new_unresolved) { vp_inc_unresolved_ref(q); }

  } else if (old_unresolved != new_unresolved) {

    if (old_unresolved) {

      vp_dec_unresolved_ref(q);

    } else {

      vp_inc_unresolved_ref(q);

    }

  }

  entry->owner = q;
  entry->dist = dist;

  return 1;

}

static inline void vp_frontier_site_clear_stale(afl_state_t *afl, u32 site) {

  size_t base = vp_site_base(site);
  for (size_t rel = 0; rel < VP_SLOTS; ++rel) {

    size_t              idx = base + rel;
    struct queue_entry *owner = afl->vp_frontier[idx].owner;
    if (!owner || !owner->disabled) continue;
    if (!afl->vp_frontier[idx].dist) {

      vp_release_solved_slot(afl, idx);

    } else {

      vp_clear_slot(afl, idx);

    }

  }

}

static inline u8 vp_apply_runtime_site(afl_state_t *afl, struct queue_entry *q,
                                       u32 site, const vp_site_t *site_state,
                                       u64 cost) {

  vp_runtime_candidate_iter_t it;
  vp_runtime_candidate_iter_init(&it, site_state);
  u16 slot_rel;
  u32 dist;
  if (!vp_runtime_candidate_iter_next(&it, &slot_rel, &dist)) return 0;

  vp_frontier_site_clear_stale(afl, site);
  u8 site_changed = 0;
  do {

    if (vp_frontier_runtime_slot_apply(afl, q, site, slot_rel, dist, cost))
      site_changed = 1;

  } while (vp_runtime_candidate_iter_next(&it, &slot_rel, &dist));

  if (site_changed && afl->vp_site_idle) { afl->vp_site_idle[site] = 0; }

  return site_changed;

}

static inline void vp_site_frontier_state(afl_state_t *afl, u32 site,
                                          u8 *owned_cnt, u8 *has_unresolved) {

  size_t base = vp_site_base(site);
  u8     owned = 0;

  *has_unresolved = 0;

  for (size_t rel = 0; rel < VP_SLOTS; ++rel) {

    const vp_frontier_entry_t *entry = &afl->vp_frontier[base + rel];
    if (vp_frontier_slot_is_empty(entry->owner, entry->dist)) continue;

    ++owned;
    if (entry->dist) { *has_unresolved = 1; }

  }

  *owned_cnt = owned;

}

static u32 vp_focus_fill(afl_state_t *afl, vp_map_t *vp, const u64 *tier,
                         u8 want_member, u32 cursor, u32 limit, u32 *live) {

  u32 taken = 0;
  u32 scanned = 0;
  u32 pos = cursor < VP_MAP_W ? cursor : 0;
  u32 next = pos;

  while (scanned < VP_MAP_W && taken < limit) {

    u32 s = pos;
    ++scanned;
    pos = s + 1 < VP_MAP_W ? s + 1 : 0;

    if (!vp->site_ids[s]) continue;
    if (vp->site[s].flags & VP_SITE_RETIRED) continue;
    if (vp_bitmap_test(tier, s) != want_member) continue;
    if (vp_bitmap_test(afl->vp_focus_bitmap, s)) continue;

    vp_bitmap_set(afl->vp_focus_bitmap, s);
    ++taken;
    next = pos;

  }

  *live += taken;
  return next;

}

void vp_focus_rotate(afl_state_t *afl) {

  if (!afl || !afl->value_profile_active || !afl->vp_frontier) return;

  vp_map_t *vp = afl->shm.vp_map;
  if (unlikely(!vp || !afl->vp_focus_bitmap || !afl->vp_site_idle ||
               !afl->vp_site_owned))
    return;

  afl->vp_focus_rebuild_pending = 0;

  u64 *focus = afl->vp_focus_bitmap;
  u64 *prev = afl->vp_focus_prev;
  u64 *relevant = afl->vp_focus_relevant;

  memcpy(prev, focus, VP_FOCUS_BITMAP_BYTES);
  memset(focus, 0, VP_FOCUS_BITMAP_BYTES);
  memset(relevant, 0, VP_FOCUS_BITMAP_BYTES);

  u32 assigned = 0, retired = 0;

  for (u32 s = 0; s < VP_MAP_W; ++s) {

    if (!vp->site_ids[s]) continue;
    ++assigned;

    vp_site_t *site = &vp->site[s];
    u32        flags = site->flags;
    u8         was_retired = (u8)((flags & VP_SITE_RETIRED) != 0);
    u8         was_recording = (u8)(!was_retired &&
                            (!afl->vp_focus_active || vp_bitmap_test(prev, s)));

    for (size_t rel = 0; rel < VP_SLOTS; ++rel) {

      vp_release_solved_slot(afl, vp_site_base(s) + rel);

    }

    u8 owned_cnt, has_unresolved;
    vp_site_frontier_state(afl, s, &owned_cnt, &has_unresolved);

    if (owned_cnt != afl->vp_site_owned[s]) {

      afl->vp_site_owned[s] = owned_cnt;
      afl->vp_site_idle[s] = 0;

    } else if (was_recording && afl->vp_site_idle[s] < 0xFFFFU) {

      ++afl->vp_site_idle[s];

    }

    u8 retire = (u8)((owned_cnt == VP_SLOTS && !has_unresolved) ||
                     (!has_unresolved &&
                      afl->vp_site_idle[s] >= VP_IDLE_RETIRE_CYCLES));

    site->flags =
        retire ? (flags | VP_SITE_RETIRED) : (flags & ~(u32)VP_SITE_RETIRED);

    if (retire) {

      ++retired;
      continue;

    }

    if (has_unresolved) { vp_bitmap_set(relevant, s); }

  }

  afl->vp_sites_assigned = assigned;
  afl->vp_sites_retired = retired;

  if (assigned <= VP_FOCUS_TARGET_SITES) {

    afl->vp_focus_active = 0;
    afl->vp_focus_live = assigned - retired;
    vp_focus_push(afl);
    return;

  }

  u32 live = 0;
  u32 owner_cap = VP_FOCUS_TARGET_SITES - (VP_FOCUS_TARGET_SITES / 4U);

  afl->vp_focus_cursor = vp_focus_fill(afl, vp, relevant, 1,
                                       afl->vp_focus_cursor, owner_cap, &live);

  afl->vp_focus_sample_cursor =
      vp_focus_fill(afl, vp, relevant, 0, afl->vp_focus_sample_cursor,
                    VP_FOCUS_TARGET_SITES - live, &live);

  if (live < VP_FOCUS_TARGET_SITES) {

    afl->vp_focus_cursor =
        vp_focus_fill(afl, vp, relevant, 1, afl->vp_focus_cursor,
                      VP_FOCUS_TARGET_SITES - live, &live);

  }

  afl->vp_focus_live = live;
  afl->vp_focus_active = 1;
  vp_focus_push(afl);

}

typedef struct {

  u32 site;
  u32 max_dist;
  u16 slot_rel;
  u16 need;
  u16 seen;

} vp_trim_req_t;

struct vp_trim_guard {

  afl_state_t        *afl;
  struct queue_entry *q;
  u8                  active;
  u8                  runtime_sandboxed;
  vp_trim_req_t      *req;
  u32                 req_cnt;
  u32                 req_cap;
  u16                *site_ids;
  u32                 site_cnt;
  u32                 site_cap;
  vp_site_t          *site_backup;

};

static inline void vp_trim_guard_destroy_req(vp_trim_guard_t *guard) {

  if (!guard) return;
  if (guard->req) { ck_free(guard->req); }
  if (guard->site_ids) { ck_free(guard->site_ids); }
  if (guard->site_backup) { ck_free(guard->site_backup); }
  ck_free(guard);

}

static inline void vp_trim_guard_add_site(vp_trim_guard_t *guard, u32 site) {

  if (guard->site_cnt == guard->site_cap) {

    u32 new_cap = guard->site_cap ? guard->site_cap << 1 : 8;
    guard->site_ids = ck_realloc(guard->site_ids, new_cap * sizeof(u16));
    guard->site_cap = new_cap;

  }

  guard->site_ids[guard->site_cnt++] = (u16)site;

}

static inline void vp_trim_guard_add_req(vp_trim_guard_t *guard, u32 site,
                                         u16 slot_rel, u32 max_dist) {

  /* The caller visits each (site, rel) pair at most once, so every request
     added here is independent; need is always 1. */
  if (guard->req_cnt == guard->req_cap) {

    u32 new_cap = guard->req_cap ? guard->req_cap << 1 : 8;
    guard->req = ck_realloc(guard->req, new_cap * sizeof(vp_trim_req_t));
    guard->req_cap = new_cap;

  }

  vp_trim_req_t *r = &guard->req[guard->req_cnt++];
  r->site = site;
  r->slot_rel = slot_rel;
  r->max_dist = max_dist;
  r->need = 1;
  r->seen = 0;

}

static inline void vp_trim_guard_reset_seen(vp_trim_guard_t *guard) {

  for (u32 i = 0; i < guard->req_cnt; ++i) {

    guard->req[i].seen = 0;

  }

}

static inline u8 vp_trim_guard_all_seen(const vp_trim_guard_t *guard) {

  for (u32 i = 0; i < guard->req_cnt; ++i) {

    if (guard->req[i].seen < guard->req[i].need) return 0;

  }

  return 1;

}

/* Assign one observed (site,slot,dist) candidate to the strictest
   unsatisfied guarded requirement that it can satisfy. */
static inline void vp_trim_guard_assign_candidate(vp_trim_guard_t *guard,
                                                  u32 site, u16 slot_rel,
                                                  u32 dist) {

  s32 best = -1;
  u32 best_max_dist = ~(u32)0;

  for (u32 i = 0; i < guard->req_cnt; ++i) {

    vp_trim_req_t *r = &guard->req[i];
    if (r->site != site || r->slot_rel != slot_rel || r->seen >= r->need ||
        dist > r->max_dist)
      continue;

    if (best < 0 || r->max_dist < best_max_dist) {

      best = (s32)i;
      best_max_dist = r->max_dist;

    }

  }

  if (best >= 0) { ++guard->req[best].seen; }

}

static inline u8 vp_trim_guard_eval_runtime(vp_trim_guard_t *guard) {

  afl_state_t *afl = guard->afl;
  vp_map_t    *vp = afl->shm.vp_map;
  if (unlikely(!vp || !vp->enabled)) return 0;

  for (u32 i = 0; i < guard->site_cnt; ++i) {

    u32                         site_id = guard->site_ids[i];
    vp_runtime_candidate_iter_t it;
    vp_runtime_candidate_iter_init(&it, &vp->site[site_id]);
    u16 slot_rel;
    u32 dist;

    while (vp_runtime_candidate_iter_next(&it, &slot_rel, &dist)) {

      vp_trim_guard_assign_candidate(guard, site_id, slot_rel, dist);

    }

  }

  return vp_trim_guard_all_seen(guard);

}

vp_trim_guard_t *vp_trim_guard_init(afl_state_t *afl, struct queue_entry *q) {

  if (unlikely(!afl || !q || !afl->vp_frontier || !afl->value_profile_active ||
               !q->vp_ref_cnt))
    return NULL;

  vp_trim_guard_t *guard = ck_alloc(sizeof(vp_trim_guard_t));
  guard->afl = afl;
  guard->q = q;

  /* Trimming is cold; scan the frontier here instead of maintaining a
     per-entry site index on every hot frontier ownership update. */
  u32 refs_left = q->vp_ref_cnt;
  for (u32 site = 0; site < VP_MAP_W && refs_left; ++site) {

    size_t base = vp_site_base(site);
    u8     site_added = 0;
    for (u16 rel = 0; rel < VP_SLOTS && refs_left; ++rel) {

      vp_frontier_entry_t *entry = &afl->vp_frontier[base + rel];
      if (entry->owner != q || entry->dist >= VP_DIST_UNSOLVED) continue;

      if (!site_added) {

        vp_trim_guard_add_site(guard, site);
        site_added = 1;

      }

      vp_trim_guard_add_req(guard, site, rel, entry->dist);
      --refs_left;

    }

  }

  if (!guard->req_cnt) {

    vp_trim_guard_destroy_req(guard);
    return NULL;

  }

  if (guard->site_cnt) {

    guard->site_backup = ck_alloc(guard->site_cnt * sizeof(vp_site_t));

  }

  guard->active = 1;
  return guard;

}

void vp_trim_guard_before_exec(vp_trim_guard_t *guard) {

  if (unlikely(!guard || !guard->active)) return;

  /* This intentionally runs before fuzz_run_target() calls vp_prepare_exec().
     The sandboxed sites are restored/reset here, then vp_prepare_exec() bumps
     exec_id and clears control_len so runtime collection lazily rebuilds only
     the filtered sites observed by this trim execution. */
  guard->runtime_sandboxed = vp_runtime_observe_begin(
      guard->afl, guard->site_ids, guard->site_cnt, guard->site_backup);

}

u8 vp_trim_guard_preserved(vp_trim_guard_t *guard) {

  if (unlikely(!guard || !guard->active || !guard->req_cnt)) return 1;
  vp_trim_guard_reset_seen(guard);

  return vp_trim_guard_eval_runtime(guard);

}

void vp_trim_guard_after_exec(vp_trim_guard_t *guard) {

  if (unlikely(!guard || !guard->active)) return;
  if (!guard->runtime_sandboxed) return;

  vp_runtime_observe_end(guard->afl, guard->site_ids, guard->site_cnt,
                         guard->site_backup);
  guard->runtime_sandboxed = 0;

}

void vp_trim_guard_destroy(vp_trim_guard_t *guard) {

  if (!guard) return;
  vp_trim_guard_after_exec(guard);
  vp_trim_guard_destroy_req(guard);

}

/* Fast VP-interest probe used before queue admission.
   VP-only inputs are admitted only for strict distance improvements (or empty
   frontier slots). Equal-distance cheaper candidates are intentionally ignored
   here to avoid calibrating and queueing non-coverage inputs just to learn
   their cost; cost tie-breaks still apply later when a seed is already being
   applied to the frontier. */
u8 vp_frontier_would_improve(afl_state_t *afl) {

  if (unlikely(!afl->vp_frontier)) return 0;

  vp_map_t *vp = afl->shm.vp_map;
  if (unlikely(!vp || !vp->enabled)) return 0;

  vp_runtime_site_iter_t it;
  vp_runtime_site_iter_init(&it, vp);
  u32        k;
  vp_site_t *site;
  while (vp_runtime_site_iter_next(&it, &k, &site)) {

    vp_runtime_candidate_iter_t candidate_it;
    vp_runtime_candidate_iter_init(&candidate_it, site);
    u16 slot_rel;
    u32 dist;

    while (vp_runtime_candidate_iter_next(&candidate_it, &slot_rel, &dist)) {

      if (vp_frontier_runtime_slot_would_improve(afl, k, slot_rel, dist)) {

        return 1;

      }

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
  vp_runtime_site_iter_t it;
  vp_runtime_site_iter_init(&it, vp);
  u32        k;
  vp_site_t *site;
  while (vp_runtime_site_iter_next(&it, &k, &site)) {

    if (vp_apply_runtime_site(afl, q, k, site, cost)) { improved = 1; }

  }

  return improved;

}

void vp_frontier_apply(afl_state_t *afl, struct queue_entry *q) {

  if (unlikely(!q || !afl->vp_frontier)) return;

  u64 cost = vp_entry_cost(q);
  u8  improved = vp_apply_runtime_frontier(afl, q, cost);

  if (vp_entry_can_retire(q)) {

    vp_disable_entry_now(afl, q);

  } else if (q->vp_only && !q->vp_last_ref_cycle) {

    q->vp_last_ref_cycle = afl->queue_cycle;

  }

  if (improved) afl->score_changed = 1;
  vp_maybe_disable_entry(afl, q);

}

/* Apply deferred disable checks for VP-only queue entries at queue-cycle
   boundaries. */
void vp_apply_delayed_evictions(afl_state_t *afl) {

  if (!afl->value_profile_mode || !afl->vp_delayed_evictions_pending) return;
  u8 needs_retry = 0;

  for (u32 i = 0; i < afl->queued_items; ++i) {

    struct queue_entry *q = afl->queue_buf[i];
    if (!q) continue;

    if (vp_entry_can_retire(q) && q->vp_last_ref_cycle &&
        afl->queue_cycle <= q->vp_last_ref_cycle) {

      needs_retry = 1;
      continue;

    }

    vp_maybe_disable_entry(afl, q);

  }

  afl->vp_delayed_evictions_pending = needs_retry;

}

/* Collect runtime VP signal for one concrete input. */
u8 vp_collect_signal_for_input(afl_state_t *afl, u8 *mem, u32 len) {

  if (unlikely(!afl->value_profile_active)) return 0;

  void *exec_mem = mem;
  u32   exec_len = write_to_testcase(afl, &exec_mem, len, 0);
  if (!exec_len) return 0;

  u8 fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);
  if (unlikely(fault == FSRV_RUN_ERROR)) {

    FATAL("Unable to execute target application");

  }

  if (fault != afl->crash_mode && fault != FSRV_RUN_NOBITS) return 0;

  return afl->shm.vp_map && afl->shm.vp_map->enabled;

}

static void vp_clear_transient_state(afl_state_t *afl) {

  if (!afl) return;

  for (u32 i = 0; afl->queue_buf && i < afl->queued_items; ++i) {

    struct queue_entry *q = afl->queue_buf[i];
    if (!q) continue;

    q->vp_ref_cnt = 0;
    q->vp_unresolved_ref_cnt = 0;
    q->vp_last_ref_cycle = 0;

    if (q->vp_trim_deferred) { q->trim_done = 0; }
    q->vp_trim_deferred = 0;

  }

  if (afl->vp_frontier) {

    size_t slots = (size_t)VP_MAP_W * VP_SLOTS;
    for (size_t i = 0; i < slots; ++i) {

      afl->vp_frontier[i].owner = NULL;
      afl->vp_frontier[i].dist = VP_DIST_UNSOLVED;

    }

  }

  afl->vp_delayed_evictions_pending = 0;

  if (afl->vp_focus_bitmap) {

    memset(afl->vp_focus_bitmap, 0, VP_FOCUS_BITMAP_BYTES);
    memset(afl->vp_focus_prev, 0, VP_FOCUS_BITMAP_BYTES);
    memset(afl->vp_focus_relevant, 0, VP_FOCUS_BITMAP_BYTES);

  }

  if (afl->vp_site_idle) {

    memset(afl->vp_site_idle, 0, sizeof(u16) * VP_MAP_W);
    memset(afl->vp_site_owned, 0, sizeof(u8) * VP_MAP_W);

  }

  afl->vp_focus_rebuild_pending = 0;
  afl->vp_focus_cursor = 0;
  afl->vp_focus_sample_cursor = 0;
  afl->vp_focus_live = 0;
  afl->vp_sites_assigned = 0;
  afl->vp_sites_retired = 0;
  afl->vp_focus_active = 0;

  vp_map_t *vp = afl->shm.vp_map;
  if (vp) {

    for (u32 s = 0; s < VP_MAP_W; ++s) {

      vp->site[s].flags &= ~(u32)VP_SITE_RETIRED;

    }

    vp->filter_mode = VP_FILTER_OFF;
    memset(vp->filter_bitmap, 0, sizeof(vp->filter_bitmap));

  }

}

/* Replay queue entries once VP activates in stagnation mode so the frontier
   is immediately based on existing inputs too. This is intentionally
   synchronous for now: activation is one-shot per fuzzing session, the replay
   cursor is retained for stop_soon interruption, and batching can be added if
   benchmark data shows the activation pause is material. */
static void vp_replay_queue(afl_state_t *afl) {

  u32 start = afl->value_profile_replay_idx;
  u32 end = afl->queued_items;
  if (start > end) start = end;
  if (start == end) {

    afl->value_profile_replay_idx = end;
    return;

  }

  u32 i = start;
  u32 replayed = 0;
  for (; i < end; ++i) {

    if (afl->stop_soon) break;

    struct queue_entry *q = afl->queue_buf[i];
    if (unlikely(!q || q->disabled || !q->len)) continue;

    u8 *mem = queue_testcase_get(afl, q);
    if (!vp_collect_signal_for_input(afl, mem, q->len)) continue;
    vp_frontier_apply(afl, q);
    ++replayed;

  }

  ACTF("Value profile replayed %u queued entries.", replayed);
  afl->value_profile_replay_idx = i;

}

/* Check stagnation and activate value profiling once. */

void vp_note_activation(afl_state_t *afl, u64 now) {

  if (!afl || !afl->value_profile_mode || afl->vp_start_time) return;
  afl->vp_start_time = now ? now : get_cur_time();

}

void vp_restore_resume_state(afl_state_t *afl) {

  if (!afl) return;

  vp_clear_transient_state(afl);

  if (!afl->value_profile_mode) return;

  if (afl->value_profile_mode > 1 && !afl->value_profile_active) {

    if (!afl->vp_start_time) return;
    afl->value_profile_active = 1;

  }

  if (!afl->value_profile_active) return;

  afl->value_profile_replay_idx = 0;
  vp_replay_queue(afl);
  vp_focus_rotate(afl);
  afl->score_changed = 1;

}

void vp_update_activation(afl_state_t *afl) {

  if (unlikely(afl->value_profile_mode != 2)) return;

  u64 cur = get_cur_time();
  /* Stagnation mode is edge-coverage based, not queue-growth based. */
  u64 last_progress_ms =
      afl->last_edge_time ? afl->last_edge_time : afl->start_time;
  u64 no_find_ms = cur > last_progress_ms ? (cur - last_progress_ms) : 0;

  u8 should = (no_find_ms >= (u64)afl->value_profile_stagnation_secs * 1000);

  if (should && !afl->value_profile_active) {

    if (afl->afl_env.afl_no_ui) {

      OKF("Stagnation (%llu s), enabling value profiling.",
          (unsigned long long)(no_find_ms / 1000));

    }

    afl->value_profile_active = 1;
    vp_note_activation(afl, cur);
    vp_clear_transient_state(afl);
    afl->value_profile_replay_idx = 0;
    vp_replay_queue(afl);
    vp_focus_rotate(afl);
    afl->score_changed = 1;

  }

}

void vp_force_activation(afl_state_t *afl) {

  if (unlikely(!afl || !afl->value_profile_mode)) return;

  if (likely(!afl->value_profile_active)) {

    if (afl->afl_env.afl_no_ui) {

      OKF("Starvation, enabling value profiling.");

    }

    afl->value_profile_active = 1;
    vp_note_activation(afl, get_cur_time());
    vp_clear_transient_state(afl);
    afl->value_profile_replay_idx = 0;
    vp_replay_queue(afl);
    vp_focus_rotate(afl);
    afl->score_changed = 1;

  }

}

