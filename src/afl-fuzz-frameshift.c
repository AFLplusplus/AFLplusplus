
#include "afl-fuzz.h"

#define FRAMESHIFT_DEBUG 0

#define FRAMESHIFT_INITIAL_CAPACITY 128

#define FRAMESHIFT_MAX_ITERS 10
#define FRAMESHIFT_LOSS_PCT 5      // 5% loss
#define FRAMESHIFT_RECOVER_PCT 20  // 20% recovery

// Hard time budget for frameshift analysis per input (milliseconds)
#define FRAMESHIFT_TIME_BUDGET_MS 2000

// Update the relation based on the given insertion.
//
// Returns 0 on success, 1 on error.
int rel_on_insert(fs_relation_t *rel, u64 idx, u64 size) {

  // Error if insert is inside the field.
  if (idx > rel->pos && idx < rel->pos + rel->size) { return 1; }

  // Check if we should update the value of the field.
  if (idx >= rel->anchor && idx <= rel->insert) {

    u64 pre = rel->val;
    rel->val += size;

    if (rel->size < 8) { rel->val &= (1ULL << (rel->size * 8)) - 1; }

    // Check if we overflowed the field.
    if (rel->val < pre) { return 1; }

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
    meta->relations =
        realloc(meta->relations, sizeof(fs_relation_t) * meta->rel_capacity);

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

void fs_sanitize(fs_meta_t *meta, u8 *buf) {

  // Apply the relations in reverse order.
  for (u32 i = meta->rel_count - 1; i != (u32)-1; i--) {

    if (!meta->relations[i].enabled) { continue; }

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
    fs_curr_meta->rel_count = 0;
    fs_curr_meta->rel_capacity = FRAMESHIFT_INITIAL_CAPACITY;
    fs_curr_meta->relations =
        malloc(sizeof(fs_relation_t) * fs_curr_meta->rel_capacity);
    afl->fs_curr_meta = fs_curr_meta;

  }

  // Copy relation data over.
  if (fs_curr_meta->rel_capacity < meta->rel_count) {

    // Increase capacity if needed.
    fs_curr_meta->relations = realloc(fs_curr_meta->relations,
                                      sizeof(fs_relation_t) * meta->rel_count);
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
  meta->rel_count = 0;
  meta->rel_capacity = FRAMESHIFT_INITIAL_CAPACITY;
  meta->relations = malloc(sizeof(fs_relation_t) * meta->rel_capacity);

  meta->blocked_points_map = malloc(size);
  memset(meta->blocked_points_map, 0, size);

  return meta;

}

void lightweight_run(afl_state_t *afl, u8 *out_buf, u32 len) {

  afl->fs_stats.search_tests++;

  u32 written = write_to_testcase(afl, (void **)&out_buf, len, 0);
  if (unlikely(written == 0)) { return; }

  u8 fault = fuzz_run_target(afl, &afl->fsrv, afl->fsrv.exec_tmout);

  afl->queued_discovered += save_if_interesting(afl, out_buf, written, fault);

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

int is_blocked(fs_meta_t *meta, u32 pos, u8 size) {

  for (u32 i = 0; i < size; i++) {

    if (meta->blocked_points_map[pos + i]) { return 1; }

  }

  return 0;

}

void check_anchor(afl_state_t *afl, u32 anchor, u32 len, u32 curr_size,
                  u32 field_pos, u8 *buf, fs_meta_t *meta, u8 *trace_bits,
                  u32 *loss_buffer, u32 loss_count, u8 *scratch,
                  u32 shift_amount, fs_relation_t *potential_rel,
                  double *curr_recover) {

  // Check if the anchor is valid.
  if (anchor > len) { return; }

  u32 insertion = anchor + curr_size;
  if (insertion > len) { return; }

  // Construct testcase with valid insertion.
  memcpy(scratch, buf, insertion);
  memset(scratch + insertion, 0x41, shift_amount);
  memcpy(scratch + insertion + shift_amount, buf + insertion, len - insertion);

  // Handle on_insert for the prospective relation manually.
  if (insertion < potential_rel->pos) {

    // Temporarily shift the relation to apply on the scratch buffer.
    potential_rel->pos += shift_amount;

  }

  rel_apply(scratch, potential_rel);
  potential_rel->pos = field_pos;

  fs_save(meta);
  u8 res = fs_track_insert(meta, insertion, shift_amount, 0);
  fs_sanitize(meta, scratch);
  fs_restore(meta);
  if (res) {

    // Invalid insertion, return.
    return;

  }

  // Measure recovery.
  lightweight_run(afl, scratch, len + shift_amount);

  u64 recover_count = 0;
  for (u32 j = 0; j < loss_count; j++) {

    u32 idx = loss_buffer[j];
    if (trace_bits[idx] > 0) { recover_count++; }

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

}

void frameshift_stage(afl_state_t *afl) {

#if FRAMESHIFT_DEBUG
  printf("Frameshift stage\n");
#endif

  u64  time_start = get_cur_time();
  u32 *inflection_points = NULL;

  if (unlikely(!afl->frameshift_index_buffer)) {

    // Allocate the frameshift index buffer.
    afl->frameshift_index_buffer = malloc(afl->fsrv.map_size * sizeof(u32));

  }

  u32 *index_buf = afl->frameshift_index_buffer;
  u32  index_count = 0;

  u8 *buf = queue_testcase_get(afl, afl->queue_cur);
  u32 len = afl->queue_cur->len;

  u8 *scratch = malloc(len + 0x100);  // We will at most shift by 0xff

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

  // Compute base coverage for this testcase.
  u8 *trace_bits = afl->fsrv.trace_bits;
  u32 map_size = afl->fsrv.map_size;

  // Compute coverage of this testcase.
  lightweight_run(afl, buf, len);
  for (u32 i = 0; i < map_size; i++) {

    if (trace_bits[i] > 0) { index_buf[index_count++] = i; }

  }

  // Compute base coverage for an invalid testcase.
  // Keep only indices that are found in the current testcase and not the base.
  lightweight_run(afl, "a", 1);
  u32 write_idx = 0;
  for (u32 i = 0; i < index_count; i++) {

    u32 idx = index_buf[i];
    if (trace_bits[idx] == 0) { index_buf[write_idx++] = idx; }

  }

  index_count = write_idx;

  u32 *loss_buffer = NULL;
  if (index_count) {

    loss_buffer = malloc(index_count * sizeof(u32));
    if (loss_buffer == NULL) { goto cleanup; }
    memset(loss_buffer, 0, index_count * sizeof(u32));

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

        if (unlikely(get_cur_time() - time_start >=
                     FRAMESHIFT_TIME_BUDGET_MS)) {

          goto cleanup;

        }

        u64 curr_size = decode_value(buf + field_pos, size, le);

        // Does this look like a size/offset field?
        if (curr_size == 0 || curr_size > len) { continue; }

        // Pick a shift amount that will test this field size.
        u64 shift_amount = 0xff;  // overflow the field boundary
        if (size == 1) {

          u64 max_shift = 0xff - curr_size;
          if (max_shift == 0) { continue; }
          shift_amount = MIN((u64)0x20, max_shift);

        }

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

        lightweight_run(afl, buf, len);
        for (u32 j = 0; j < index_count; j++) {

          u32 idx = index_buf[j];
          if (trace_bits[idx] == 0) { loss_buffer[loss_count++] = idx; }

        }

        // Undo the change to the buffer.
        potential_rel.val -= shift_amount;
        rel_apply(buf, &potential_rel);
        potential_rel.val += shift_amount;

        if (loss_count < loss_threshold) { continue; }

        // printf("[FS] Testing relation: pos=%u size=%u le=%u shift=%u value=%u
        // (loss: %d)\n", field_pos, size, le, shift_amount, curr_size,
        // loss_count);

        // Next, we iterate over inflection points to find the best anchor.
        double curr_recover = FRAMESHIFT_RECOVER_PCT / 100.0;

        if (size == 1) {

          check_anchor(afl, field_pos + size, len, curr_size, field_pos, buf,
                       meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);

        } else if (size == 2) {

          check_anchor(afl, 0, len, curr_size, field_pos, buf, meta, trace_bits,
                       loss_buffer, loss_count, scratch, shift_amount,
                       &potential_rel, &curr_recover);
          check_anchor(afl, field_pos, len, curr_size, field_pos, buf, meta,
                       trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size, len, curr_size, field_pos, buf,
                       meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);

        } else {

          check_anchor(afl, field_pos + size + 7, len, curr_size, field_pos,
                       buf, meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size + 6, len, curr_size, field_pos,
                       buf, meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size + 5, len, curr_size, field_pos,
                       buf, meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size + 4, len, curr_size, field_pos,
                       buf, meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size + 3, len, curr_size, field_pos,
                       buf, meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size + 2, len, curr_size, field_pos,
                       buf, meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size + 1, len, curr_size, field_pos,
                       buf, meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, 0, len, curr_size, field_pos, buf, meta, trace_bits,
                       loss_buffer, loss_count, scratch, shift_amount,
                       &potential_rel, &curr_recover);
          check_anchor(afl, field_pos, len, curr_size, field_pos, buf, meta,
                       trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);
          check_anchor(afl, field_pos + size, len, curr_size, field_pos, buf,
                       meta, trace_bits, loss_buffer, loss_count, scratch,
                       shift_amount, &potential_rel, &curr_recover);

          if (potential_rel.anchor == (u64)-1) {

            // Check other inflection points.
            for (u32 j = 0; j < inflection_points_count; j++) {

              u32 anchor = inflection_points[j];
              check_anchor(afl, anchor, len, curr_size, field_pos, buf, meta,
                           trace_bits, loss_buffer, loss_count, scratch,
                           shift_amount, &potential_rel, &curr_recover);

            }

          }

        }

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
            inflection_points = realloc(
                inflection_points, inflection_points_capacity * sizeof(u32));

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
  if (loss_buffer) free(loss_buffer);
  if (scratch) free(scratch);
  if (inflection_points) free(inflection_points);

  u64 time_end = get_cur_time();

  afl->fs_stats.total_time_ms += time_end - time_start;

  afl->fs_stats.searched += 1;
  if (meta->rel_count > 0) { afl->fs_stats.found += 1; }

}

