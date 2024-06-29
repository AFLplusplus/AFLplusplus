

#include "afl-fuzz.h"

void flip_range(u8 *input, u32 pos, u32 size) {

  for (u32 i = 0; i < size; i++)
    input[pos + i] ^= 0xFF;

  return;

}

#define MAX_EFF_TIMEOUT (10 * 60 * 1000)
#define MAX_DET_TIMEOUT (15 * 60 * 1000)
u8 is_det_timeout(u64 cur_ms, u8 is_flip) {

  if (is_flip) {

    if (unlikely(get_cur_time() - cur_ms > MAX_EFF_TIMEOUT)) return 1;

  } else {

    if (unlikely(get_cur_time() - cur_ms > MAX_DET_TIMEOUT)) return 1;

  }

  return 0;

}

/* decide if the seed should be deterministically fuzzed */

u8 should_det_fuzz(afl_state_t *afl, struct queue_entry *q) {

  if (unlikely(!afl->skipdet_g->virgin_det_bits)) {

    afl->skipdet_g->virgin_det_bits =
        (u8 *)ck_alloc(sizeof(u8) * afl->fsrv.map_size);

  }

  if (likely(!q->favored || q->passed_det)) return 0;
  if (unlikely(!q->trace_mini)) return 0;

  if (!afl->skipdet_g->last_cov_undet)
    afl->skipdet_g->last_cov_undet = get_cur_time();

  if (get_cur_time() - afl->skipdet_g->last_cov_undet >= THRESHOLD_DEC_TIME) {

    if (afl->skipdet_g->undet_bits_threshold >= 2) {

      afl->skipdet_g->undet_bits_threshold *= 0.75;
      afl->skipdet_g->last_cov_undet = get_cur_time();

    }

  }

  u32 new_det_bits = 0;

  for (u32 i = 0; i < afl->fsrv.map_size; i++) {

    if (unlikely(q->trace_mini[i >> 3] & (1 << (i & 7)))) {

      if (!afl->skipdet_g->virgin_det_bits[i]) { new_det_bits++; }

    }

  }

  if (!afl->skipdet_g->undet_bits_threshold)
    afl->skipdet_g->undet_bits_threshold = new_det_bits * 0.05;

  if (new_det_bits >= afl->skipdet_g->undet_bits_threshold) {

    afl->skipdet_g->last_cov_undet = get_cur_time();
    q->skipdet_e->undet_bits = new_det_bits;

    for (u32 i = 0; i < afl->fsrv.map_size; i++) {

      if (unlikely(q->trace_mini[i >> 3] & (1 << (i & 7)))) {

        if (!afl->skipdet_g->virgin_det_bits[i])
          afl->skipdet_g->virgin_det_bits[i] = 1;

      }

    }

    return 1;

  }

  return 0;

}

/*
  consists of two stages that
  return 0 if exec failed.
*/

u8 skip_deterministic_stage(afl_state_t *afl, u8 *orig_buf, u8 *out_buf,
                            u32 len, u64 before_det_time) {

  u64 orig_hit_cnt, new_hit_cnt;

  if (afl->queue_cur->skipdet_e->done_eff) return 1;

  if (!should_det_fuzz(afl, afl->queue_cur)) return 1;

  /* Add check to make sure that for seeds without too much undet bits,
     we ignore them */

  /******************
   * SKIP INFERENCE *
   ******************/

  afl->stage_short = "inf";
  afl->stage_name = "inference";
  afl->stage_cur = 0;
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  static u8 *inf_eff_map;
  inf_eff_map = (u8 *)ck_realloc(inf_eff_map, sizeof(u8) * len);
  memset(inf_eff_map, 1, sizeof(u8) * len);

  if (common_fuzz_stuff(afl, orig_buf, len)) { return 0; }

  u64 prev_cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
  u64 _prev_cksum = prev_cksum;

  if (MINIMAL_BLOCK_SIZE * 8 < len) {

    // u64 size_skiped = 0, quick_skip_exec = total_execs, quick_skip_time =
    // get_cur_time();
    u64 pre_inf_exec = afl->fsrv.total_execs, pre_inf_time = get_cur_time();

    /* if determine stage time / input size is too small, just go ahead */

    u32 pos = 0, cur_block_size = MINIMAL_BLOCK_SIZE, max_block_size = len / 8;

    while (pos < len - 1) {

      cur_block_size = MINIMAL_BLOCK_SIZE;

      while (cur_block_size < max_block_size) {

        u32 flip_block_size =
            (cur_block_size + pos < len) ? cur_block_size : len - 1 - pos;

        afl->stage_cur += 1;

        flip_range(out_buf, pos, flip_block_size);

        if (common_fuzz_stuff(afl, out_buf, len)) return 0;

        flip_range(out_buf, pos, flip_block_size);

        u64 cksum =
            hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

        // printf("Now trying range %d with %d, %s.\n", pos, cur_block_size,
        //     (cksum == prev_cksum) ? (u8*)"Yes" : (u8*) "Not");

        /* continue until we fail or exceed length */
        if (cksum == _prev_cksum) {

          cur_block_size *= 2;

          if (cur_block_size >= len - 1 - pos) break;

        } else {

          break;

        }

      }

      if (cur_block_size == MINIMAL_BLOCK_SIZE) {

        /* we failed early on*/

        pos += cur_block_size;

      } else {

        u32 cur_skip_len = (cur_block_size / 2 + pos < len)
                               ? (cur_block_size / 2)
                               : (len - pos - 1);

        memset(inf_eff_map + pos, 0, cur_skip_len);

        afl->skipdet_g->inf_prof->inf_skipped_bytes += cur_skip_len;

        pos += cur_skip_len;

      }

    }

    afl->skipdet_g->inf_prof->inf_execs_cost +=
        (afl->fsrv.total_execs - pre_inf_exec);
    afl->skipdet_g->inf_prof->inf_time_cost += (get_cur_time() - pre_inf_time);
    // PFATAL("Done, now have %d bytes skipped, with exec %lld, time %lld.\n",
    // afl->inf_skipped_bytes, afl->inf_execs_cost, afl->inf_time_cost);

  } else

    memset(inf_eff_map, 1, len);

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INF] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INF] += afl->stage_cur;

  /****************************
   * Quick Skip Effective Map *
   ****************************/

  /* Quick Effective Map Calculation */

  afl->stage_short = "quick";
  afl->stage_name = "quick eff";
  afl->stage_cur = 0;
  afl->stage_max = 32 * 1024;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  u32 before_skip_inf = afl->queued_items;

  /* clean all the eff bytes, since previous eff bytes are already fuzzed */
  u8 *skip_eff_map = afl->queue_cur->skipdet_e->skip_eff_map,
     *done_inf_map = afl->queue_cur->skipdet_e->done_inf_map;

  if (!skip_eff_map) {

    skip_eff_map = (u8 *)ck_alloc(sizeof(u8) * len);
    afl->queue_cur->skipdet_e->skip_eff_map = skip_eff_map;

  } else {

    memset(skip_eff_map, 0, sizeof(u8) * len);

  }

  /* restore the starting point */
  if (!done_inf_map) {

    done_inf_map = (u8 *)ck_alloc(sizeof(u8) * len);
    afl->queue_cur->skipdet_e->done_inf_map = done_inf_map;

  } else {

    for (afl->stage_cur = 0; afl->stage_cur < len; afl->stage_cur++) {

      if (done_inf_map[afl->stage_cur] == 0) break;

    }

  }

  /* depending on the seed's performance, we could search eff bytes
     for multiple rounds */

  u8 eff_round_continue = 1, eff_round_done = 0, done_eff = 0, repeat_eff = 0,
     fuzz_nearby = 0, *non_eff_bytes = 0;

  u64 before_eff_execs = afl->fsrv.total_execs;

  if (getenv("REPEAT_EFF")) repeat_eff = 1;
  if (getenv("FUZZ_NEARBY")) fuzz_nearby = 1;

  if (fuzz_nearby) {

    non_eff_bytes = (u8 *)ck_alloc(sizeof(u8) * len);

    // clean exec cksum
    if (common_fuzz_stuff(afl, out_buf, len)) { return 0; }
    prev_cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

  }

  do {

    eff_round_continue = 0;
    afl->stage_max = 32 * 1024;

    for (; afl->stage_cur < afl->stage_max && afl->stage_cur < len;
         ++afl->stage_cur) {

      afl->stage_cur_byte = afl->stage_cur;

      if (!inf_eff_map[afl->stage_cur_byte] ||
          skip_eff_map[afl->stage_cur_byte])
        continue;

      if (is_det_timeout(before_det_time, 1)) { goto cleanup_skipdet; }

      u8 orig = out_buf[afl->stage_cur_byte], replace = rand_below(afl, 256);

      while (replace == orig) {

        replace = rand_below(afl, 256);

      }

      out_buf[afl->stage_cur_byte] = replace;

      before_skip_inf = afl->queued_items;

      if (common_fuzz_stuff(afl, out_buf, len)) { return 0; }

      out_buf[afl->stage_cur_byte] = orig;

      if (fuzz_nearby) {

        if (prev_cksum ==
            hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST)) {

          non_eff_bytes[afl->stage_cur_byte] = 1;

        }

      }

      if (afl->queued_items != before_skip_inf) {

        skip_eff_map[afl->stage_cur_byte] = 1;
        afl->queue_cur->skipdet_e->quick_eff_bytes += 1;

        if (afl->stage_max < MAXIMUM_QUICK_EFF_EXECS) { afl->stage_max *= 2; }

        if (afl->stage_max == MAXIMUM_QUICK_EFF_EXECS && repeat_eff)
          eff_round_continue = 1;

      }

      done_inf_map[afl->stage_cur_byte] = 1;

    }

    afl->stage_cur = 0;
    done_eff = 1;

    if (++eff_round_done >= 8) break;

  } while (eff_round_continue);

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_QUICK] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_QUICK] += (afl->fsrv.total_execs - before_eff_execs);

cleanup_skipdet:

  if (fuzz_nearby) {

    u8 *nearby_bytes = (u8 *)ck_alloc(sizeof(u8) * len);

    u32 i = 3;
    while (i < len) {

      // assume DWORD size, from i - 3 -> i + 3
      if (skip_eff_map[i]) {

        u32 fill_length = (i + 3 < len) ? 7 : len - i + 2;
        memset(nearby_bytes + i - 3, 1, fill_length);
        i += 3;

      } else

        i += 1;

    }

    for (i = 0; i < len; i++) {

      if (nearby_bytes[i] && !non_eff_bytes[i]) skip_eff_map[i] = 1;

    }

    ck_free(nearby_bytes);
    ck_free(non_eff_bytes);

  }

  if (done_eff) {

    afl->queue_cur->skipdet_e->continue_inf = 0;
    afl->queue_cur->skipdet_e->done_eff = 1;

  } else {

    afl->queue_cur->skipdet_e->continue_inf = 1;

  }

  return 1;

}

