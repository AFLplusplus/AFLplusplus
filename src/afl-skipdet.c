

#include "afl-fuzz.h"



void flip_range(u8 *input, u32 pos, u32 size) {

  for (u32 i = 0; i < size; i ++)  input[pos + i] ^= 0xFF;

  return ;

}


static u64 estimate_det_time(afl_state_t *afl) {

  struct queue_entry *q = afl->queue_cur;

  u64 det_power = 0;

  det_power += (q->len << 3);
  det_power += ((q->len << 3)- 1);
  det_power += ((q->len << 3)- 3);
  det_power += (q->len * 3 - 4);
  det_power += 2 * q->len * ARITH_MAX;
  det_power += 4 * (q->len - 1) * ARITH_MAX;
  det_power += 4 * (q->len - 3) * ARITH_MAX;
  det_power += q->len * sizeof(interesting_8);
  det_power += 2 * (q->len - 1) * (sizeof(interesting_16) >> 1);
  det_power += 2 * (q->len - 3) * (sizeof(interesting_32) >> 2);
  det_power += 2 * afl->extras_cnt * q->len;
  det_power += MIN(afl->a_extras_cnt, (u32)USE_AUTO_EXTRAS) * q->len;

  return det_power * q->exec_us;

}

/*
  consists of two stages that 
  return 0 if exec failed.
*/

u8 skip_deterministic_stage(afl_state_t *afl, u8* orig_buf, u8* out_buf, u32 len) {

  u64 orig_hit_cnt, new_hit_cnt;
    
  /******************
   * SKIP INFERENCE *
   ******************/

  afl->stage_short = "inf";
  afl->stage_name  = "inference";
  afl->stage_cur   = 0;
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  u8 *inf_eff_map = (u8*) ck_alloc(sizeof(u8) * len);
  memset(inf_eff_map, 1, sizeof(u8) * len);

  if (common_fuzz_stuff(afl, orig_buf, len)) { return 0; }

  u64 prev_cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
  u64 _prev_cksum = prev_cksum;

  if (MINIMAL_BLOCK_SIZE * 8 < len)  {

    // u64 size_skiped = 0, quick_skip_exec = total_execs, quick_skip_time = get_cur_time();
    u64 pre_inf_exec = afl->fsrv.total_execs, pre_inf_time = get_cur_time();

    /* if determine stage time / input size is too small, just go ahead */

    u32 pos = 0, cur_block_size = MINIMAL_BLOCK_SIZE, max_block_size = len / 8;

    while (pos < len - 1) {

      cur_block_size = MINIMAL_BLOCK_SIZE;

      while (cur_block_size < max_block_size) {

        u32 flip_block_size = (cur_block_size + pos < len) ? cur_block_size : len - 1 - pos;

        afl->stage_cur += 1;

        flip_range(out_buf, pos, flip_block_size);

        if (common_fuzz_stuff(afl, out_buf, len)) return 0;

        flip_range(out_buf, pos, flip_block_size);

        u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

        // printf("Now trying range %d with %d, %s.\n", pos, cur_block_size,
        //     (cksum == prev_cksum) ? (u8*)"Yes" : (u8*) "Not");

        /* continue until we fail or exceed length */
        if (cksum == _prev_cksum) {

          cur_block_size *= 2;

          if (cur_block_size >= len - 1 - pos) break;

        } else { break; }

      }

      if (cur_block_size == MINIMAL_BLOCK_SIZE) {

        /* we failed early on*/

        pos += cur_block_size;

      } else {

        u32 cur_skip_len = (cur_block_size / 2 + pos < len) ? (cur_block_size / 2) : (len - pos - 1);

        memset(inf_eff_map + pos, 0, cur_skip_len);

        afl->skipdet_g->inf_prof->inf_skipped_bytes += cur_skip_len;

        pos += cur_skip_len;

      }

    }

    afl->skipdet_g->inf_prof->inf_execs_cost += (afl->fsrv.total_execs - pre_inf_exec);
    afl->skipdet_g->inf_prof->inf_time_cost += (get_cur_time() - pre_inf_time);
    // PFATAL("Done, now have %d bytes skipped, with exec %lld, time %lld.\n", afl->inf_skipped_bytes, afl->inf_execs_cost, afl->inf_time_cost);

  } else memset(inf_eff_map, 1, len);

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_finds[STAGE_INF] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INF] += afl->stage_cur;

  return 1;

}