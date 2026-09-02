/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may obtain a copy at https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include "afl-fuzz.h"

#define FRAMESHIFT_DEBUG 0

#define FRAMESHIFT_INITIAL_CAPACITY 128

#define FRAMESHIFT_MAX_ITERS 10
#define FRAMESHIFT_LOSS_PCT 5      // 5% loss
#define FRAMESHIFT_RECOVER_PCT 20  // 20% recovery

// Hard time budget for frameshift analysis per input (milliseconds)
#define FRAMESHIFT_TIME_BUDGET_MS 2000

#define FRAMESHIFT_MIN_SLICE_MS 200

// Maximum number of inflection-point anchors probed per candidate field.
#define FRAMESHIFT_MAX_INFLECTION_PROBES 64

enum {

  FRAMESHIFT_RUN_SKIPPED,
  FRAMESHIFT_RUN_OK,
  FRAMESHIFT_RUN_DEADLINE

};

// Update the relation based on the given insertion.
//
// Returns 0 on success, 1 on error.
int rel_on_insert(fs_relation_t *rel, u64 idx, u64 size) {

  // Error if insert is inside the field.
  if (idx > rel->pos && idx < rel->pos + rel->size) { return 1; }

  // Check if we should update the value of the field.
  if (idx >= rel->anchor && idx <= rel->insert) {

    u64 max = rel->size < 8 ? (1ULL << (rel->size * 8)) - 1 : UINT64_MAX;

    // Check before adding: masking first misses increments that wrap by a
    // complete field width, such as adding 256 to an 8-bit length.
    if (size > max - rel->val) { return 1; }
    rel->val += size;

  }

  // Move the field.
  if (idx <= rel->pos) { rel->pos += size; }

  // Move the anchor point.
  // Anchor point of 0 is locked.
  if (idx < rel->anchor) { rel->anchor += size; }

  // Move the insert point.
  if (idx <= rel->insert) { rel->insert += size; }

  return 0;

}

// Update the relation based on the given removal.
//
// Returns 0 on success, 1 on error.
int rel_on_remove(fs_relation_t *rel, u64 idx, u64 size) {

  // Error if remove overlaps the field.
  if (idx < rel->pos + rel->size && idx + size > rel->pos) { return 1; }

  // P=pos, A=anchor, I=insert, R=removal, E=removal+size
  //
  // ....P.....A---------I.........
  // ..............R---------E.....
  // ....P.....A---I........

  // Compute how much of the removal happens before the field.
  u64 pre_pos = (idx < rel->pos) ? MIN(rel->pos - idx, size) : 0;
  u64 pre_anchor = (idx < rel->anchor) ? MIN(rel->anchor - idx, size) : 0;
  u64 pre_insert = (idx < rel->insert) ? MIN(rel->insert - idx, size) : 0;

  // Compute overlap between [idx, idx+size) and [anchor, insert)
  u64 overlap = 0;
  u64 a = MAX(idx, rel->anchor);
  u64 b = MIN(idx + size, rel->insert);
  if (b > a) { overlap = b - a; }

  // Adjust the field value.
  if (overlap > rel->val) {

    return 1;

  } else {

    rel->val -= overlap;

  }

  // Adjust the field position.
  rel->pos -= pre_pos;
  rel->anchor -= pre_anchor;
  rel->insert -= pre_insert;

  return 0;

}

// Apply the relation to the given buffer.
void rel_apply(u8 *buf, fs_relation_t *rel) {

  u32 i;
  u64 val = rel->val;
  u8  size = rel->size;

  if (rel->le) {

    for (i = 0; i < size; i++) {

      buf[rel->pos + i] = (u8)(val >> (i * 8));

    }

  } else {

    for (i = 0; i < size; i++) {

      buf[rel->pos + size - 1 - i] = (u8)(val >> (i * 8));

    }

  }

}

void rel_save(fs_relation_t *rel) {

  rel->_old_pos = rel->pos;
  rel->_old_val = rel->val;
  rel->_old_anchor = rel->anchor;
  rel->_old_insert = rel->insert;

}

void rel_restore(fs_relation_t *rel) {

  rel->pos = rel->_old_pos;
  rel->val = rel->_old_val;
  rel->anchor = rel->_old_anchor;
  rel->insert = rel->_old_insert;

  // Re-enable all
  rel->enabled = 1;

}

void fs_add_relation(fs_meta_t *meta, fs_relation_t *rel) {

  if (meta->rel_count == meta->rel_capacity) {

    meta->rel_capacity *= 2;
    fs_relation_t *tmp =
        realloc(meta->relations, sizeof(fs_relation_t) * meta->rel_capacity);
    if (!tmp) { PFATAL("alloc for frameshift relations failed."); }
    meta->relations = tmp;

  }

  memcpy(&meta->relations[meta->rel_count], rel, sizeof(fs_relation_t));
  meta->rel_count++;

  // Update blocked points map.
  for (u32 i = 0; i < rel->size; i++) {

    meta->blocked_points_map[rel->pos + i] = 1;

  }

}

void fs_save(fs_meta_t *meta) {

  // printf("Saving metadata\n");
  for (u32 i = 0; i < meta->rel_count; i++) {

    fs_relation_t *rel = &meta->relations[i];
    rel_save(rel);

  }

}

void fs_restore(fs_meta_t *meta) {

  // printf("Restoring metadata\n");
  for (u32 i = 0; i < meta->rel_count; i++) {

    fs_relation_t *rel = &meta->relations[i];
    rel_restore(rel);

  }

}

// Insert data into the buffer at the given index.
// Update any relations that are affected by the insertion.
// If ignore_invalid is set, invalid insertions are ignored.
// Returns 0 on success, 1 on error.
int fs_track_insert(fs_meta_t *meta, u64 idx, u64 data_size,
                    u8 ignore_invalid) {

  // printf("Inserting %llu at %llu\n", data_size, idx);
  for (u32 i = 0; i < meta->rel_count; i++) {

    if (meta->relations[i].enabled) {

      u8 res = rel_on_insert(&meta->relations[i], idx, data_size);
      if (res) {

        if (ignore_invalid) {

          // Invalid insertion, disable relation and keep going.
          meta->relations[i].enabled = 0;

        } else {

          // Invalid insertion, return error.
          return 1;

        }

      }

    }

  }

  return 0;

}

void fs_track_delete(fs_meta_t *meta, u64 idx, u64 data_size) {

  // printf("Deleting %llu at %llu\n", data_size, idx);
  for (u32 i = 0; i < meta->rel_count; i++) {

    if (meta->relations[i].enabled) {

      u8 res = rel_on_remove(&meta->relations[i], idx, data_size);
      if (res) {

        // Invalid deletion, disable relation and keep going.
        meta->relations[i].enabled = 0;

      }

    }

  }

}

void fs_sanitize(fs_meta_t *meta, u8 *buf, u32 len) {

  // Apply the relations in reverse order.
  for (u32 i = meta->rel_count - 1; i != (u32)-1; i--) {

    if (!meta->relations[i].enabled) { continue; }

    if (unlikely(meta->relations[i].pos + meta->relations[i].size > len)) {

      continue;

    }

    rel_apply(buf, &meta->relations[i]);

  }

}

void fs_clone_meta(afl_state_t *afl) {

  // printf("Cloning metadata\n");
  fs_meta_t *meta = afl->queue_cur->fs_meta;
  fs_meta_t *fs_curr_meta = afl->fs_curr_meta;
  if (unlikely(!fs_curr_meta)) {

    // Initial allocation.
    fs_curr_meta = malloc(sizeof(fs_meta_t));
    if (!fs_curr_meta) { PFATAL("alloc for frameshift metadata failed."); }
    fs_curr_meta->rel_count = 0;
    fs_curr_meta->rel_capacity = FRAMESHIFT_INITIAL_CAPACITY;
    fs_curr_meta->relations =
        malloc(sizeof(fs_relation_t) * fs_curr_meta->rel_capacity);
    if (!fs_curr_meta->relations) {

      PFATAL("alloc for frameshift relations failed.");

    }

    afl->fs_curr_meta = fs_curr_meta;

  }

  // Copy relation data over.
  if (fs_curr_meta->rel_capacity < meta->rel_count) {

    // Increase capacity if needed.
    fs_relation_t *tmp = realloc(fs_curr_meta->relations,
                                 sizeof(fs_relation_t) * meta->rel_count);
    if (!tmp) { PFATAL("alloc for frameshift relations failed."); }
    fs_curr_meta->relations = tmp;
    fs_curr_meta->rel_capacity = meta->rel_count;

  }

  memcpy(fs_curr_meta->relations, meta->relations,
         sizeof(fs_relation_t) * meta->rel_count);
  fs_curr_meta->rel_count = meta->rel_count;

  // Blocked points will be read only after this, so we can shallow copy.
  fs_curr_meta->blocked_points_map = meta->blocked_points_map;

}

fs_meta_t *fs_new_meta(u32 size) {

  fs_meta_t *meta = malloc(sizeof(fs_meta_t));
  if (!meta) { PFATAL("alloc for frameshift metadata failed."); }
  meta->rel_count = 0;
  meta->rel_capacity = FRAMESHIFT_INITIAL_CAPACITY;
  meta->relations = malloc(sizeof(fs_relation_t) * meta->rel_capacity);
  if (!meta->relations) { PFATAL("alloc for frameshift relations failed."); }

  meta->blocked_points_map = malloc(size);
  if (!meta->blocked_points_map) {

    PFATAL("alloc for frameshift blocked points map failed.");

  }

  memset(meta->blocked_points_map, 0, size);

  return meta;

}

u8 lightweight_run(afl_state_t *afl, u8 *out_buf, u32 len) {

  u64 now = get_cur_time();
  if (unlikely(now >= afl->frameshift_deadline)) {

    return FRAMESHIFT_RUN_DEADLINE;

  }

  u32 written = write_to_testcase(afl, (void **)&out_buf, len, 0);
  if (unlikely(written == 0)) { return FRAMESHIFT_RUN_SKIPPED; }

  now = get_cur_time();
  if (unlikely(now >= afl->frameshift_deadline)) {

    return FRAMESHIFT_RUN_DEADLINE;

  }

  /* The stage deadline bounds how long frameshift may keep going, not how
     long the target is allowed to take. Cutting an execution short at the
     remaining budget makes a target that runs in milliseconds return
     FSRV_RUN_TMOUT, and save_if_interesting() then files the input as a hang.
     Run with the timeout the user asked for and let the deadline checks above
     and below end the stage - the overrun is one execution, as in every other
     stage. */

  afl->fs_stats.search_tests++;

  fsrv_run_result_t fault =
      fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  afl->queued_discovered += save_if_interesting(afl, out_buf, written, fault);

  if (unlikely(get_cur_time() >= afl->frameshift_deadline)) {

    return FRAMESHIFT_RUN_DEADLINE;

  }

  if (unlikely(fault != afl->crash_mode)) { return FRAMESHIFT_RUN_SKIPPED; }

  return FRAMESHIFT_RUN_OK;

}

void print_buffer(u8 *buf, u32 len) {

  for (u32 i = 0; i < len; i++) {

    printf("%02x ", buf[i]);

  }

  printf("\n");

}

typedef struct field_tmpl {

  u8 size;
  u8 le;

} field_tmpl_t;

const field_tmpl_t FRAMESHIFT_SEARCH_ORDER[] = {

    {8, 1},  // u64 - little
    {8, 0},  // u64 - big
    {4, 1},  // u32 - little
    {4, 0},  // u32 - big
    {2, 1},  // u16 - little
    {2, 0},  // u16 - big
    {1, 1},  // u8 - little

};

u64 decode_value(u8 *buf, u8 size, u8 le) {

  u64 val = 0;
  if (le) {

    for (u8 i = 0; i < size; i++) {

      val |= ((u64)buf[i]) << (i * 8);

    }

  } else {

    for (u8 i = 0; i < size; i++) {

      val |= ((u64)buf[size - 1 - i]) << (i * 8);

    }

  }

  return val;

}

// Pick a shift amount that tests the given field size without overflowing
// the field itself.
u64 frameshift_shift_amount(u8 size, u64 curr_size) {

  u64 field_max = size < 8 ? (1ULL << (size * 8)) - 1 : UINT64_MAX;
  if (curr_size >= field_max) { return 0; }

  return MIN(size == 1 ? (u64)0x20 : (u64)0xff, field_max - curr_size);

}

int is_blocked(fs_meta_t *meta, u32 pos, u8 size) {

  for (u32 i = 0; i < size; i++) {

    if (meta->blocked_points_map[pos + i]) { return 1; }

  }

  return 0;

}

u8 check_anchor(afl_state_t *afl, u32 anchor, u32 len, u32 curr_size, u8 *buf,
                fs_meta_t *meta, u8 *trace_bits, u32 *loss_buffer,
                u32 loss_count, u8 *scratch, u8 *repeat_buffer,
                u32 shift_amount, fs_relation_t *potential_rel,
                double *curr_recover) {

  // Respect the absolute time budget on every probe.
  if (unlikely(get_cur_time() >= afl->frameshift_deadline)) { return 1; }

  // Check if the anchor is valid.
  if (anchor > len) { return 0; }

  u32 insertion = anchor + curr_size;
  if (insertion > len) { return 0; }

  // Construct testcase with valid insertion.
  memcpy(scratch, buf, insertion);
  memset(scratch + insertion, 0x41, shift_amount);
  memcpy(scratch + insertion + shift_amount, buf + insertion, len - insertion);

  // Handle on_insert for the prospective relation manually. Match the
  // idx <= pos semantics used by rel_on_insert.
  u64 saved_pos = potential_rel->pos;
  if (insertion <= potential_rel->pos) {

    // Temporarily shift the relation to apply on the scratch buffer.
    potential_rel->pos += shift_amount;

  }

  rel_apply(scratch, potential_rel);
  potential_rel->pos = saved_pos;

  fs_save(meta);
  u8 res = fs_track_insert(meta, insertion, shift_amount, 0);
  fs_sanitize(meta, scratch, len + shift_amount);
  fs_restore(meta);
  if (res) {

    // Invalid insertion, return.
    return 0;

  }

  // Measure recovery. Abort the probe if the run was skipped so we do not
  // read a stale trace.
  u8 ran = lightweight_run(afl, scratch, len + shift_amount);
  if (unlikely(ran == FRAMESHIFT_RUN_DEADLINE)) { return 1; }
  if (unlikely(ran != FRAMESHIFT_RUN_OK)) { return 0; }

  u64 recover_count = 0;
  if (afl->queue_cur->var_behavior) {

    for (u32 j = 0; j < loss_count; ++j) {

      repeat_buffer[j] = trace_bits[loss_buffer[j]] > 0;

    }

    ran = lightweight_run(afl, scratch, len + shift_amount);
    if (unlikely(ran == FRAMESHIFT_RUN_DEADLINE)) { return 1; }
    if (unlikely(ran != FRAMESHIFT_RUN_OK)) { return 0; }

    for (u32 j = 0; j < loss_count; ++j) {

      if (repeat_buffer[j] && trace_bits[loss_buffer[j]] > 0) {

        ++recover_count;

      }

    }

  } else {

    for (u32 j = 0; j < loss_count; j++) {

      u32 idx = loss_buffer[j];
      if (trace_bits[idx] > 0) { recover_count++; }

    }

  }

  double recover_pct = (double)recover_count / loss_count;

  // printf("   -> Anchor: %u, Insertion: %u, Recovery: %.2f%%\n", anchor,
  // insertion, recover_pct * 100);

  // Update the best relation if we have a better recovery.
  if (recover_pct > *curr_recover) {

    potential_rel->anchor = anchor;
    potential_rel->insert = insertion;
    *curr_recover = recover_pct;

  }

  return 0;

}

u64 frameshift_slice_budget(u64 spent_ms, u64 allowed_ms) {

  if (spent_ms >= allowed_ms) { return 0; }

  u64 remaining = allowed_ms - spent_ms;
  if (remaining < FRAMESHIFT_MIN_SLICE_MS) { return 0; }

  if (remaining > FRAMESHIFT_TIME_BUDGET_MS) {

    return FRAMESHIFT_TIME_BUDGET_MS;

  }

  return remaining;

}

void frameshift_stage(afl_state_t *afl) {

#if FRAMESHIFT_DEBUG
  printf("Frameshift stage\n");
#endif

  u64 time_start = get_cur_time();
  u64 total_runtime_ms = afl->prev_run_time + time_start - afl->start_time;
  u64 allowed_ms = (u64)((double)total_runtime_ms *
                         afl->afl_env.afl_frameshift_max_overhead);
  u64 budget_ms =
      frameshift_slice_budget(afl->fs_stats.total_time_ms, allowed_ms);
  if (!budget_ms) { return; }

  afl->frameshift_deadline = time_start + budget_ms;
  u32 *inflection_points = NULL;
  u32 *loss_buffer = NULL;
  u8  *repeat_buffer = NULL;

  if (unlikely(!afl->frameshift_index_buffer)) {

    // Allocate the frameshift index buffer.
    afl->frameshift_index_buffer = malloc(afl->fsrv.map_size * sizeof(u32));
    if (!afl->frameshift_index_buffer) {

      PFATAL("alloc for frameshift index buffer failed.");

    }

  }

  u32 *index_buf = afl->frameshift_index_buffer;
  u32  index_count = 0;

  u8 *buf = queue_testcase_get(afl, afl->queue_cur);
  u32 len = afl->queue_cur->len;

  u8 *scratch = malloc(len + 0x100);  // We will at most shift by 0xff
  if (!scratch) { PFATAL("alloc for frameshift scratch buffer failed."); }

  // Print out
#if FRAMESHIFT_DEBUG
  printf("[FS] Input buffer: ");
  u32 to_print = len > 256 ? 256 : len;
  print_buffer(buf, to_print);
  if (len > to_print) { printf("... (%u bytes total)\n", len); }
#endif

  // Update queue state
  afl->queue_cur->fs_status = 1;

  // Initialize relation metadata
  fs_meta_t *meta = fs_new_meta(len);
  afl->queue_cur->fs_meta = meta;

  if (len < 2) { goto cleanup; }

  // Compute base coverage for this testcase.
  u8 *trace_bits = afl->fsrv.trace_bits;
  u32 map_size = afl->fsrv.map_size;

  // Compute coverage of this testcase.
  u8 ran = lightweight_run(afl, buf, len);
  if (unlikely(ran != FRAMESHIFT_RUN_OK)) { goto cleanup; }
  for (u32 i = 0; i < map_size; i++) {

    if (trace_bits[i] > 0 && (!afl->var_bytes || !afl->var_bytes[i])) {

      index_buf[index_count++] = i;

    }

  }

  if (afl->queue_cur->var_behavior) {

    ran = lightweight_run(afl, buf, len);
    if (unlikely(ran != FRAMESHIFT_RUN_OK)) { goto cleanup; }

    u32 write_idx = 0;
    for (u32 i = 0; i < index_count; ++i) {

      u32 idx = index_buf[i];
      if (trace_bits[idx] > 0) { index_buf[write_idx++] = idx; }

    }

    index_count = write_idx;

  }

  // Compute base coverage for an invalid testcase.
  // Keep only indices that are found in the current testcase and not the base.
  ran = lightweight_run(afl, "a", 1);
  if (unlikely(ran != FRAMESHIFT_RUN_OK)) { goto cleanup; }
  u32 write_idx = 0;
  for (u32 i = 0; i < index_count; i++) {

    u32 idx = index_buf[i];
    if (trace_bits[idx] == 0) { index_buf[write_idx++] = idx; }

  }

  index_count = write_idx;

  if (afl->queue_cur->var_behavior) {

    ran = lightweight_run(afl, "a", 1);
    if (unlikely(ran != FRAMESHIFT_RUN_OK)) { goto cleanup; }

    write_idx = 0;
    for (u32 i = 0; i < index_count; ++i) {

      u32 idx = index_buf[i];
      if (trace_bits[idx] == 0) { index_buf[write_idx++] = idx; }

    }

    index_count = write_idx;

  }

  if (!index_count) { goto cleanup; }

  if (index_count) {

    loss_buffer = malloc(index_count * sizeof(u32));
    if (loss_buffer == NULL) { goto cleanup; }
    memset(loss_buffer, 0, index_count * sizeof(u32));

    if (afl->queue_cur->var_behavior) {

      repeat_buffer = malloc(index_count);
      if (!repeat_buffer) { goto cleanup; }

    }

  }

  u32 loss_count = 0;

  u32 loss_threshold = ((index_count * FRAMESHIFT_LOSS_PCT) / 100) + 1;

  // printf("[FS] Index count: %u\n", index_count);
  u32 inflection_points_count = 0;
  u32 inflection_points_capacity = 128;
  inflection_points = calloc(inflection_points_capacity, sizeof(u32));

  if (!inflection_points) { PFATAL("alloc for inflection_points failed."); }

  // Outer loop, run at most max_iterations times.
  for (u32 i = 0; i < FRAMESHIFT_MAX_ITERS; i++) {

    u8 found = 0;

    // Iterate over field position.
    for (u32 field_pos = 0; field_pos < len - 1; field_pos++) {

      // Iterate over field type.
      for (u8 k = 0; k < sizeof(FRAMESHIFT_SEARCH_ORDER) / sizeof(field_tmpl_t);
           k++) {

        field_tmpl_t *tmpl = (field_tmpl_t *)&FRAMESHIFT_SEARCH_ORDER[k];
        u8            size = tmpl->size;
        u8            le = tmpl->le;

        if (field_pos + size > len) { continue; }

        // Respect global stop/skip and time budget
        if (unlikely(afl->stop_soon)) { goto cleanup; }
        if (unlikely(afl->skip_requested)) {

          afl->skip_requested = 0;
          goto cleanup;

        }

        if (unlikely(get_cur_time() >= afl->frameshift_deadline)) {

          goto cleanup;

        }

        u64 curr_size = decode_value(buf + field_pos, size, le);

        // Does this look like a size/offset field?
        if (curr_size == 0 || curr_size > len) { continue; }

        u64 shift_amount = frameshift_shift_amount(size, curr_size);
        if (!shift_amount) { continue; }

        // Check if the field is blocked.
        if (is_blocked(meta, field_pos, size)) {

          // printf("[FS] Field is blocked\n");
          continue;

        }

        fs_relation_t potential_rel = {.pos = field_pos,
                                       .val = curr_size,
                                       .anchor = -1,  // unset
                                       .insert = -1,  // unset
                                       .size = size,
                                       .le = le,
                                       .enabled = 1};

        // Corrupt the field and measure lost features.
        potential_rel.val += shift_amount;
        rel_apply(buf, &potential_rel);

        loss_count = 0;

        ran = lightweight_run(afl, buf, len);
        if (likely(ran == FRAMESHIFT_RUN_OK)) {

          for (u32 j = 0; j < index_count; j++) {

            u32 idx = index_buf[j];
            if (trace_bits[idx] == 0) { loss_buffer[loss_count++] = idx; }

          }

        }

        if (unlikely(ran != FRAMESHIFT_RUN_OK)) {

          potential_rel.val -= shift_amount;
          rel_apply(buf, &potential_rel);
          potential_rel.val += shift_amount;
          if (ran == FRAMESHIFT_RUN_DEADLINE) { goto cleanup; }
          continue;

        }

        if (afl->queue_cur->var_behavior) {

          ran = lightweight_run(afl, buf, len);

          potential_rel.val -= shift_amount;
          rel_apply(buf, &potential_rel);
          potential_rel.val += shift_amount;

          if (unlikely(ran == FRAMESHIFT_RUN_DEADLINE)) { goto cleanup; }
          if (unlikely(ran != FRAMESHIFT_RUN_OK)) { continue; }

          write_idx = 0;
          for (u32 j = 0; j < loss_count; ++j) {

            u32 idx = loss_buffer[j];
            if (trace_bits[idx] == 0) { loss_buffer[write_idx++] = idx; }

          }

          loss_count = write_idx;

        } else {

          // Undo the change to the buffer.
          potential_rel.val -= shift_amount;
          rel_apply(buf, &potential_rel);
          potential_rel.val += shift_amount;

        }

        if (loss_count < loss_threshold) { continue; }

        // printf("[FS] Testing relation: pos=%u size=%u le=%u shift=%u value=%u
        // (loss: %d)\n", field_pos, size, le, shift_amount, curr_size,
        // loss_count);

        // Next, we iterate over inflection points to find the best anchor.
        double curr_recover = FRAMESHIFT_RECOVER_PCT / 100.0;

#define CHECK_FRAMESHIFT_ANCHOR(_anchor)                                    \
  do {                                                                      \
                                                                            \
    if (check_anchor(afl, (_anchor), len, curr_size, buf, meta, trace_bits, \
                     loss_buffer, loss_count, scratch, repeat_buffer,       \
                     shift_amount, &potential_rel, &curr_recover)) {        \
                                                                            \
      goto cleanup;                                                         \
                                                                            \
    }                                                                       \
                                                                            \
  } while (0)

        if (size == 1) {

          CHECK_FRAMESHIFT_ANCHOR(field_pos + size);

        } else if (size == 2) {

          CHECK_FRAMESHIFT_ANCHOR(0);
          CHECK_FRAMESHIFT_ANCHOR(field_pos);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size);

        } else {

          CHECK_FRAMESHIFT_ANCHOR(field_pos + size + 7);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size + 6);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size + 5);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size + 4);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size + 3);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size + 2);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size + 1);
          CHECK_FRAMESHIFT_ANCHOR(0);
          CHECK_FRAMESHIFT_ANCHOR(field_pos);
          CHECK_FRAMESHIFT_ANCHOR(field_pos + size);

          if (potential_rel.anchor == (u64)-1) {

            // Check other inflection points, bounded by a probe cap.
            u32 probe_cap = inflection_points_count;
            if (probe_cap > FRAMESHIFT_MAX_INFLECTION_PROBES) {

              probe_cap = FRAMESHIFT_MAX_INFLECTION_PROBES;

            }

            for (u32 j = 0; j < probe_cap; j++) {

              u32 anchor = inflection_points[j];
              CHECK_FRAMESHIFT_ANCHOR(anchor);

            }

          }

        }

#undef CHECK_FRAMESHIFT_ANCHOR

        // Check if we have a valid relation.
        if (potential_rel.anchor == (u64)-1) {

          // No valid relation found, continue.
          continue;

        }

#if FRAMESHIFT_DEBUG
        printf(
            "[FS] Found relation: pos=%u size=%u le=%u shift=%llu value=%llu "
            "anchor=%llu insert=%llu (loss: %u recover: %.2f%%)\n",
            field_pos, size, le, (unsigned long long)shift_amount,
            (unsigned long long)curr_size,
            (unsigned long long)potential_rel.anchor,
            (unsigned long long)potential_rel.insert, loss_count,
            curr_recover * 100.0);
#endif

        potential_rel.val = curr_size;
        fs_add_relation(meta, &potential_rel);

        // Update the inflection points.
        // Only size 4 and 8 are used for inflection points.
        if (potential_rel.size == 4 || potential_rel.size == 8) {

          // Need space for 3 more points.
          if (inflection_points_count + 3 >= inflection_points_capacity) {

            inflection_points_capacity *= 2;
            u32 *tmp = realloc(inflection_points,
                               inflection_points_capacity * sizeof(u32));
            if (!tmp) { PFATAL("alloc for inflection_points failed."); }
            inflection_points = tmp;

          }

          inflection_points[inflection_points_count++] = potential_rel.pos;
          inflection_points[inflection_points_count++] = potential_rel.anchor;
          inflection_points[inflection_points_count++] = potential_rel.insert;

        }

        found = 1;

      }

    }

    if (!found) {

      // Didn't find relations this iteration, stop searching.
      break;

    }

  }

cleanup:
  if (repeat_buffer) free(repeat_buffer);
  if (loss_buffer) free(loss_buffer);
  if (scratch) free(scratch);
  if (inflection_points) free(inflection_points);

  u64 time_end = get_cur_time();

  afl->fs_stats.total_time_ms += time_end - time_start;

  afl->fs_stats.searched += 1;
  if (meta->rel_count > 0) { afl->fs_stats.found += 1; }

}

