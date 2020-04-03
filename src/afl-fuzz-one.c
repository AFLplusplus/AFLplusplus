/*
   american fuzzy lop++ - fuzze_one routines in different flavours
   ---------------------------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

/* MOpt */

int select_algorithm(afl_state_t *afl) {

  int i_puppet, j_puppet;

  double sele = ((double)(rand_below(afl, 10000)) * 0.0001);
  j_puppet = 0;
  for (i_puppet = 0; i_puppet < operator_num; ++i_puppet) {

    if (unlikely(i_puppet == 0)) {

      if (sele < afl->probability_now[afl->swarm_now][i_puppet]) break;

    } else {

      if (sele < afl->probability_now[afl->swarm_now][i_puppet]) {

        j_puppet = 1;
        break;

      }

    }

  }

  if (j_puppet == 1 &&
      sele < afl->probability_now[afl->swarm_now][i_puppet - 1])
    FATAL("error select_algorithm");
  return i_puppet;

}

/* Helper to choose random block len for block operations in fuzz_one().
   Doesn't return zero, provided that max_len is > 0. */

static u32 choose_block_len(afl_state_t *afl, u32 limit) {

  u32 min_value, max_value;
  u32 rlim = MIN(afl->queue_cycle, 3);

  if (unlikely(!afl->run_over10m)) rlim = 1;

  switch (rand_below(afl, rlim)) {

    case 0:
      min_value = 1;
      max_value = HAVOC_BLK_SMALL;
      break;

    case 1:
      min_value = HAVOC_BLK_SMALL;
      max_value = HAVOC_BLK_MEDIUM;
      break;

    default:

      if (rand_below(afl, 10)) {

        min_value = HAVOC_BLK_MEDIUM;
        max_value = HAVOC_BLK_LARGE;

      } else {

        min_value = HAVOC_BLK_LARGE;
        max_value = HAVOC_BLK_XL;

      }

  }

  if (min_value >= limit) min_value = 1;

  return min_value + rand_below(afl, MIN(max_value, limit) - min_value + 1);

}

/* Helper function to see if a particular change (xor_val = old ^ new) could
   be a product of deterministic bit flips with the lengths and stepovers
   attempted by afl-fuzz. This is used to avoid dupes in some of the
   deterministic fuzzing operations that follow bit flips. We also
   return 1 if xor_val is zero, which implies that the old and attempted new
   values are identical and the exec would be a waste of time. */

static u8 could_be_bitflip(u32 xor_val) {

  u32 sh = 0;

  if (!xor_val) return 1;

  /* Shift left until first bit set. */

  while (!(xor_val & 1)) {

    ++sh;
    xor_val >>= 1;

  }

  /* 1-, 2-, and 4-bit patterns are OK anywhere. */

  if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

  /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
     divisible by 8, since that's the stepover for these ops. */

  if (sh & 7) return 0;

  if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff) return 1;

  return 0;

}

/* Helper function to see if a particular value is reachable through
   arithmetic operations. Used for similar purposes. */

static u8 could_be_arith(u32 old_val, u32 new_val, u8 blen) {

  u32 i, ov = 0, nv = 0, diffs = 0;

  if (old_val == new_val) return 1;

  /* See if one-byte adjustments to any byte could produce this result. */

  for (i = 0; i < blen; ++i) {

    u8 a = old_val >> (8 * i), b = new_val >> (8 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one byte differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u8)(ov - nv) <= ARITH_MAX || (u8)(nv - ov) <= ARITH_MAX) return 1;

  }

  if (blen == 1) return 0;

  /* See if two-byte adjustments to any byte would produce this result. */

  diffs = 0;

  for (i = 0; i < blen / 2; ++i) {

    u16 a = old_val >> (16 * i), b = new_val >> (16 * i);

    if (a != b) {

      ++diffs;
      ov = a;
      nv = b;

    }

  }

  /* If only one word differs and the values are within range, return 1. */

  if (diffs == 1) {

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) return 1;

    ov = SWAP16(ov);
    nv = SWAP16(nv);

    if ((u16)(ov - nv) <= ARITH_MAX || (u16)(nv - ov) <= ARITH_MAX) return 1;

  }

  /* Finally, let's do the same thing for dwords. */

  if (blen == 4) {

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;

    new_val = SWAP32(new_val);
    old_val = SWAP32(old_val);

    if ((u32)(old_val - new_val) <= ARITH_MAX ||
        (u32)(new_val - old_val) <= ARITH_MAX)
      return 1;

  }

  return 0;

}

/* Last but not least, a similar helper to see if insertion of an
   interesting integer is redundant given the insertions done for
   shorter blen. The last param (check_le) is set if the caller
   already executed LE insertion for current blen and wants to see
   if BE variant passed in new_val is unique. */

static u8 could_be_interest(u32 old_val, u32 new_val, u8 blen, u8 check_le) {

  u32 i, j;

  if (old_val == new_val) return 1;

  /* See if one-byte insertions from interesting_8 over old_val could
     produce new_val. */

  for (i = 0; i < blen; ++i) {

    for (j = 0; j < sizeof(interesting_8); ++j) {

      u32 tval =
          (old_val & ~(0xff << (i * 8))) | (((u8)interesting_8[j]) << (i * 8));

      if (new_val == tval) return 1;

    }

  }

  /* Bail out unless we're also asked to examine two-byte LE insertions
     as a preparation for BE attempts. */

  if (blen == 2 && !check_le) return 0;

  /* See if two-byte insertions over old_val could give us new_val. */

  for (i = 0; i < blen - 1; ++i) {

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      u32 tval = (old_val & ~(0xffff << (i * 8))) |
                 (((u16)interesting_16[j]) << (i * 8));

      if (new_val == tval) return 1;

      /* Continue here only if blen > 2. */

      if (blen > 2) {

        tval = (old_val & ~(0xffff << (i * 8))) |
               (SWAP16(interesting_16[j]) << (i * 8));

        if (new_val == tval) return 1;

      }

    }

  }

  if (blen == 4 && check_le) {

    /* See if four-byte insertions could produce the same result
       (LE only). */

    for (j = 0; j < sizeof(interesting_32) / 4; ++j)
      if (new_val == (u32)interesting_32[j]) return 1;

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

      if (f_loc == -1) f_loc = pos;
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
   skipped or bailed out. */

u8 fuzz_one_original(afl_state_t *afl) {

  s32 len, fd, temp_len, i, j;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued = 0, orig_hit_cnt, new_hit_cnt;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8 ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

/* Not pretty, but saves a lot of writing */
#define BUF_PARAMS(name) (void **)&afl->name##_buf, &afl->name##_size

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (afl->queue_cur->depth > 1) return 1;

#else

  if (unlikely(afl->mutator) && unlikely(afl->mutator->afl_custom_queue_get)) {

    /* The custom mutator will decide to skip this test case or not. */

    if (!afl->mutator->afl_custom_queue_get(afl->mutator->data,
                                            afl->queue_cur->fname))
      return 1;

  }

  if (likely(afl->pending_favored)) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if (((afl->queue_cur->was_fuzzed > 0 || afl->queue_cur->fuzz_level > 0) ||
         !afl->queue_cur->favored) &&
        rand_below(afl, 100) < SKIP_TO_NEW_PROB)
      return 1;

  } else if (!afl->dumb_mode && !afl->queue_cur->favored &&

             afl->queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 &&
        (afl->queue_cur->fuzz_level == 0 || afl->queue_cur->was_fuzzed)) {

      if (rand_below(afl, 100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (rand_below(afl, 100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

#endif                                                     /* ^IGNORE_FINDS */

  if (unlikely(afl->not_on_tty)) {

    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         afl->current_entry, afl->queued_paths, afl->unique_crashes);
    fflush(stdout);

  }

  /* Map the test case into memory. */

  fd = open(afl->queue_cur->fname, O_RDONLY);

  if (unlikely(fd < 0)) PFATAL("Unable to open '%s'", afl->queue_cur->fname);

  len = afl->queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (unlikely(orig_in == MAP_FAILED))
    PFATAL("Unable to mmap '%s' with len %d", afl->queue_cur->fname, len);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_maybe_grow(BUF_PARAMS(out), len);

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (unlikely(afl->queue_cur->cal_failed)) {

    u8 res = FAULT_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (unlikely(res == FAULT_ERROR))
        FATAL("Unable to execute target application");

    }

    if (unlikely(afl->stop_soon) || res != afl->crash_mode) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (!afl->dumb_mode && !afl->queue_cur->trim_done && !afl->disable_trim) {

    u8 res = trim_case(afl, afl->queue_cur, in_buf);

    if (unlikely(res == FAULT_ERROR))
      FATAL("Unable to execute target application");

    if (unlikely(afl->stop_soon)) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    afl->queue_cur->trim_done = 1;

    len = afl->queue_cur->len;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(afl, afl->queue_cur);

  if (unlikely(perf_score == 0)) goto abandon_entry;

  if (unlikely(afl->use_radamsa > 1)) goto radamsa_stage;

  if (afl->shm.cmplog_mode) {

    if (input_to_state_stage(afl, in_buf, out_buf, len,
                             afl->queue_cur->exec_cksum))
      goto abandon_entry;

  }

  /* Skip right away if -d is given, if it has not been chosen sufficiently
     often to warrant the expensive deterministic stage (fuzz_level), or
     if it has gone through deterministic testing in earlier, resumed runs
     (passed_det). */

  if (afl->skip_deterministic ||
      ((!afl->queue_cur->passed_det) &&
       perf_score < (afl->queue_cur->depth * 30 <= afl->havoc_max_mult * 100
                         ? afl->queue_cur->depth * 30
                         : afl->havoc_max_mult * 100)) ||
      afl->queue_cur->passed_det) {

    goto custom_mutator_stage;

  }

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (afl->master_max &&
      (afl->queue_cur->exec_cksum % afl->master_max) != afl->master_id - 1) {

    goto custom_mutator_stage;

  }

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

  /* Single walking bit. */

  afl->stage_short = "flip1";
  afl->stage_max = len << 3;
  afl->stage_name = "bitflip 1/1";

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  prev_cksum = afl->queue_cur->exec_cksum;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

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

    if (!afl->dumb_mode && (afl->stage_cur & 7) == 7) {

      u32 cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);

      if (afl->stage_cur == afl->stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[afl->stage_cur >> 3];
        ++a_len;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(afl, a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(afl, a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != afl->queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[afl->stage_cur >> 3];
        ++a_len;

      }

    }

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP1] += afl->stage_max;

  /* Two walking bits. */

  afl->stage_name = "bitflip 2/1";
  afl->stage_short = "flip2";
  afl->stage_max = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP2] += afl->stage_max;

  /* Four walking bits. */

  afl->stage_name = "bitflip 4/1";
  afl->stage_short = "flip4";
  afl->stage_max = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP4] += afl->stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
     flag first and last byte as doing something. */

  eff_map = ck_maybe_grow(BUF_PARAMS(eff), EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {

    eff_map[EFF_APOS(len - 1)] = 1;
    ++eff_cnt;

  }

  /* Walking byte. */

  afl->stage_name = "bitflip 8/8";
  afl->stage_short = "flip8";
  afl->stage_max = len;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur;

    out_buf[afl->stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(afl->stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!afl->dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~afl->queue_cur->exec_cksum;

      if (cksum != afl->queue_cur->exec_cksum) {

        eff_map[EFF_APOS(afl->stage_cur)] = 1;
        ++eff_cnt;

      }

    }

    out_buf[afl->stage_cur] ^= 0xFF;

  }

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    afl->blocks_eff_select += EFF_ALEN(len);

  } else {

    afl->blocks_eff_select += eff_cnt;

  }

  afl->blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP8] += afl->stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  afl->stage_name = "bitflip 16/8";
  afl->stage_short = "flip16";
  afl->stage_cur = 0;
  afl->stage_max = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
    ++afl->stage_cur;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP16] += afl->stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  afl->stage_name = "bitflip 32/8";
  afl->stage_short = "flip32";
  afl->stage_cur = 0;
  afl->stage_max = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
    ++afl->stage_cur;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP32] += afl->stage_max;

skip_bitflip:

  if (afl->no_arith) goto skip_arith;

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

  for (i = 0; i < len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= 2 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      out_buf[i] = orig;

    }

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  afl->stage_name = "arith 16/8";
  afl->stage_short = "arith16";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

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
        *(u16 *)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      /* Big endian comes next. Same deal. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      *(u16 *)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH16] += afl->stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  afl->stage_name = "arith 32/8";
  afl->stage_short = "arith32";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

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
        *(u32 *)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      /* Big endian next. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      *(u32 *)(out_buf + i) = orig;

    }

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH32] += afl->stage_max;

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

  for (i = 0; i < len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= sizeof(interesting_8);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); ++j) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {

        --afl->stage_max;
        continue;

      }

      afl->stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      ++afl->stage_cur;

    }

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST8] += afl->stage_max;

  /* Setting 16-bit integers, both endians. */

  if (afl->no_arith || len < 2) goto skip_interest;

  afl->stage_name = "interest 16/8";
  afl->stage_short = "int16";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= sizeof(interesting_16);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      afl->stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u16 *)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

    }

    *(u16 *)(out_buf + i) = orig;

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST16] += afl->stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  afl->stage_name = "interest 32/8";
  afl->stage_short = "int32";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; i++) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= sizeof(interesting_32) >> 1;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      afl->stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u32 *)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

    }

    *(u32 *)(out_buf + i) = orig;

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST32] += afl->stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!afl->extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  afl->stage_name = "user extras (over)";
  afl->stage_short = "ext_UO";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < afl->extras_cnt; ++j) {

      /* Skip extras probabilistically if afl->extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((afl->extras_cnt > MAX_DET_EXTRAS &&
           rand_below(afl, afl->extras_cnt) >= MAX_DET_EXTRAS) ||
          afl->extras[j].len > len - i ||
          !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->extras[j].len;
      memcpy(out_buf + i, afl->extras[j].data, last_len);

      if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UO] += afl->stage_max;

  /* Insertion of user-supplied extras. */

  afl->stage_name = "user extras (insert)";
  afl->stage_short = "ext_UI";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_maybe_grow(BUF_PARAMS(ex), len + MAX_DICT_FILE);

  for (i = 0; i <= len; ++i) {

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

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UI] += afl->stage_max;

skip_user_extras:

  if (!afl->a_extras_cnt) goto skip_extras;

  afl->stage_name = "auto extras (over)";
  afl->stage_short = "ext_AO";
  afl->stage_cur = 0;
  afl->stage_max = MIN(afl->a_extras_cnt, USE_AUTO_EXTRAS) * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    for (j = 0; j < MIN(afl->a_extras_cnt, USE_AUTO_EXTRAS); ++j) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (afl->a_extras[j].len > len - i ||
          !memcmp(afl->a_extras[j].data, out_buf + i, afl->a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->a_extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->a_extras[j].len;
      memcpy(out_buf + i, afl->a_extras[j].data, last_len);

      if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_AO] += afl->stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!afl->queue_cur->passed_det) mark_as_det_done(afl, afl->queue_cur);

custom_mutator_stage:
  /*******************
   * CUSTOM MUTATORS *
   *******************/

  if (likely(!afl->mutator)) goto havoc_stage;
  if (likely(!afl->mutator->afl_custom_fuzz)) goto havoc_stage;

  afl->stage_name = "custom mutator";
  afl->stage_short = "custom";
  afl->stage_max = HAVOC_CYCLES * perf_score / afl->havoc_div / 100;
  afl->stage_val_type = STAGE_VAL_NONE;

  if (afl->stage_max < HAVOC_MIN) afl->stage_max = HAVOC_MIN;

  const u32 max_seed_size = MAX_FILE;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    struct queue_entry *target;
    u32                 tid;
    u8 *                new_buf;

  retry_external_pick:
    /* Pick a random other queue entry for passing to external API */
    do {

      tid = rand_below(afl, afl->queued_paths);

    } while (tid == afl->current_entry && afl->queued_paths > 1);

    target = afl->queue;

    while (tid >= 100) {

      target = target->next_100;
      tid -= 100;

    }

    while (tid--)
      target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == afl->queue_cur) &&
           afl->queued_paths > 1) {

      target = target->next;
      ++afl->splicing_with;

    }

    if (!target) goto retry_external_pick;

    /* Read the additional testcase into a new buffer. */
    fd = open(target->fname, O_RDONLY);
    if (unlikely(fd < 0)) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_maybe_grow(BUF_PARAMS(out_scratch), target->len);
    ck_read(fd, new_buf, target->len, target->fname);
    close(fd);

    u8 *mutated_buf = NULL;

    size_t mutated_size = afl->mutator->afl_custom_fuzz(
        afl->mutator->data, out_buf, len, &mutated_buf, new_buf, target->len,
        max_seed_size);

    if (unlikely(!mutated_buf))
      FATAL("Error in custom_fuzz. Size returned: %zd", mutated_size);

    if (mutated_size > 0) {

      if (common_fuzz_stuff(afl, mutated_buf, (u32)mutated_size)) {

        goto abandon_entry;

      }

      /* If we're finding new stuff, let's run for a bit longer, limits
         permitting. */

      if (afl->queued_paths != havoc_queued) {

        if (perf_score <= afl->havoc_max_mult * 100) {

          afl->stage_max *= 2;
          perf_score *= 2;

        }

        havoc_queued = afl->queued_paths;

      }

    }

    /* `(afl->)out_buf` may have been changed by the call to custom_fuzz */
    /* TODO: Only do this when `mutated_buf` == `out_buf`? Branch vs Memcpy. */
    memcpy(out_buf, in_buf, len);

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_CUSTOM_MUTATOR] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_CUSTOM_MUTATOR] += afl->stage_max;

  if (likely(afl->custom_only)) {

    /* Skip other stages */
    ret_val = 0;
    goto abandon_entry;

  }

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:

  afl->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    afl->stage_name = "havoc";
    afl->stage_short = "havoc";
    afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                     perf_score / afl->havoc_div / 100;

  } else {

    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE, "splice %u", splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = "splice";
    afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

  }

  if (afl->stage_max < HAVOC_MIN) afl->stage_max = HAVOC_MIN;

  temp_len = len;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  havoc_queued = afl->queued_paths;

  u8 stacked_custom = (afl->mutator && afl->mutator->afl_custom_havoc_mutation);
  u8 stacked_custom_prob = 6;  // like one of the default mutations in havoc

  if (stacked_custom && afl->mutator->afl_custom_havoc_mutation_probability) {

    stacked_custom_prob =
        afl->mutator->afl_custom_havoc_mutation_probability(afl->mutator->data);
    if (stacked_custom_prob > 100)
      FATAL(
          "The probability returned by afl_custom_havoc_mutation_propability "
          "has to be in the range 0-100.");

  }

  /* We essentially just do several thousand runs (depending on perf_score)
     where we take the input file and make random stacked tweaks. */

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 use_stacking = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2));

    afl->stage_cur_val = use_stacking;

    for (i = 0; i < use_stacking; ++i) {

      if (stacked_custom && rand_below(afl, 100) < stacked_custom_prob) {

        u8 *   custom_havoc_buf = NULL;
        size_t new_len = afl->mutator->afl_custom_havoc_mutation(
            afl->mutator->data, out_buf, temp_len, &custom_havoc_buf, MAX_FILE);
        if (unlikely(!custom_havoc_buf))
          FATAL("Error in custom_havoc (return %zd)", new_len);
        if (likely(new_len > 0 && custom_havoc_buf)) {

          temp_len = new_len;
          if (out_buf != custom_havoc_buf) {

            ck_maybe_grow(BUF_PARAMS(out), temp_len);
            memcpy(out_buf, custom_havoc_buf, temp_len);

          }

        }

      }

      switch (rand_below(
          afl, 15 + ((afl->extras_cnt + afl->a_extras_cnt) ? 2 : 0))) {

        case 0:

          /* Flip a single bit somewhere. Spooky! */

          FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
          break;

        case 1:

          /* Set byte to interesting value. */

          out_buf[rand_below(afl, temp_len)] =
              interesting_8[rand_below(afl, sizeof(interesting_8))];
          break;

        case 2:

          /* Set word to interesting value, randomly choosing endian. */

          if (temp_len < 2) break;

          if (rand_below(afl, 2)) {

            *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)];

          } else {

            *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) = SWAP16(
                interesting_16[rand_below(afl, sizeof(interesting_16) >> 1)]);

          }

          break;

        case 3:

          /* Set dword to interesting value, randomly choosing endian. */

          if (temp_len < 4) break;

          if (rand_below(afl, 2)) {

            *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)];

          } else {

            *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) = SWAP32(
                interesting_32[rand_below(afl, sizeof(interesting_32) >> 2)]);

          }

          break;

        case 4:

          /* Randomly subtract from byte. */

          out_buf[rand_below(afl, temp_len)] -= 1 + rand_below(afl, ARITH_MAX);
          break;

        case 5:

          /* Randomly add to byte. */

          out_buf[rand_below(afl, temp_len)] += 1 + rand_below(afl, ARITH_MAX);
          break;

        case 6:

          /* Randomly subtract from word, random endian. */

          if (temp_len < 2) break;

          if (rand_below(afl, 2)) {

            u32 pos = rand_below(afl, temp_len - 1);

            *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          } else {

            u32 pos = rand_below(afl, temp_len - 1);
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf + pos) =
                SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

          }

          break;

        case 7:

          /* Randomly add to word, random endian. */

          if (temp_len < 2) break;

          if (rand_below(afl, 2)) {

            u32 pos = rand_below(afl, temp_len - 1);

            *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          } else {

            u32 pos = rand_below(afl, temp_len - 1);
            u16 num = 1 + rand_below(afl, ARITH_MAX);

            *(u16 *)(out_buf + pos) =
                SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

          }

          break;

        case 8:

          /* Randomly subtract from dword, random endian. */

          if (temp_len < 4) break;

          if (rand_below(afl, 2)) {

            u32 pos = rand_below(afl, temp_len - 3);

            *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

          } else {

            u32 pos = rand_below(afl, temp_len - 3);
            u32 num = 1 + rand_below(afl, ARITH_MAX);

            *(u32 *)(out_buf + pos) =
                SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

          }

          break;

        case 9:

          /* Randomly add to dword, random endian. */

          if (temp_len < 4) break;

          if (rand_below(afl, 2)) {

            u32 pos = rand_below(afl, temp_len - 3);

            *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

          } else {

            u32 pos = rand_below(afl, temp_len - 3);
            u32 num = 1 + rand_below(afl, ARITH_MAX);

            *(u32 *)(out_buf + pos) =
                SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

          }

          break;

        case 10:

          /* Just set a random byte to a random value. Because,
             why not. We use XOR with 1-255 to eliminate the
             possibility of a no-op. */

          out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
          break;

        case 11 ... 12: {

          /* Delete bytes. We're making this a bit more likely
             than insertion (the next option) in hopes of keeping
             files reasonably small. */

          u32 del_from, del_len;

          if (temp_len < 2) break;

          /* Don't delete too much. */

          del_len = choose_block_len(afl, temp_len - 1);

          del_from = rand_below(afl, temp_len - del_len + 1);

          memmove(out_buf + del_from, out_buf + del_from + del_len,
                  temp_len - del_from - del_len);

          temp_len -= del_len;

          break;

        }

        case 13:

          if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

            /* Clone bytes (75%) or insert a block of constant bytes (25%). */

            u8  actually_clone = rand_below(afl, 4);
            u32 clone_from, clone_to, clone_len;
            u8 *new_buf;

            if (actually_clone) {

              clone_len = choose_block_len(afl, temp_len);
              clone_from = rand_below(afl, temp_len - clone_len + 1);

            } else {

              clone_len = choose_block_len(afl, HAVOC_BLK_XL);
              clone_from = 0;

            }

            clone_to = rand_below(afl, temp_len);

            new_buf =
                ck_maybe_grow(BUF_PARAMS(out_scratch), temp_len + clone_len);

            /* Head */

            memcpy(new_buf, out_buf, clone_to);

            /* Inserted part */

            if (actually_clone)
              memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
            else
              memset(new_buf + clone_to,
                     rand_below(afl, 2) ? rand_below(afl, 256)
                                        : out_buf[rand_below(afl, temp_len)],
                     clone_len);

            /* Tail */
            memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                   temp_len - clone_to);

            swap_bufs(BUF_PARAMS(out), BUF_PARAMS(out_scratch));
            out_buf = new_buf;
            new_buf = NULL;
            temp_len += clone_len;

          }

          break;

        case 14: {

          /* Overwrite bytes with a randomly selected chunk (75%) or fixed
             bytes (25%). */

          u32 copy_from, copy_to, copy_len;

          if (temp_len < 2) break;

          copy_len = choose_block_len(afl, temp_len - 1);

          copy_from = rand_below(afl, temp_len - copy_len + 1);
          copy_to = rand_below(afl, temp_len - copy_len + 1);

          if (rand_below(afl, 4)) {

            if (copy_from != copy_to)
              memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

          } else

            memset(out_buf + copy_to,
                   rand_below(afl, 2) ? rand_below(afl, 256)
                                      : out_buf[rand_below(afl, temp_len)],
                   copy_len);

          break;

        }

          /* Values 15 and 16 can be selected only if there are any extras
             present in the dictionaries. */

        case 15: {

          /* Overwrite bytes with an extra. */

          if (!afl->extras_cnt || (afl->a_extras_cnt && rand_below(afl, 2))) {

            /* No user-specified extras or odds in our favor. Let's use an
               auto-detected one. */

            u32 use_extra = rand_below(afl, afl->a_extras_cnt);
            u32 extra_len = afl->a_extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = rand_below(afl, temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, afl->a_extras[use_extra].data,
                   extra_len);

          } else {

            /* No auto extras or odds in our favor. Use the dictionary. */

            u32 use_extra = rand_below(afl, afl->extras_cnt);
            u32 extra_len = afl->extras[use_extra].len;
            u32 insert_at;

            if (extra_len > temp_len) break;

            insert_at = rand_below(afl, temp_len - extra_len + 1);
            memcpy(out_buf + insert_at, afl->extras[use_extra].data, extra_len);

          }

          break;

        }

        case 16: {

          u32 use_extra, extra_len, insert_at = rand_below(afl, temp_len + 1);
          u8 *new_buf;

          /* Insert an extra. Do the same dice-rolling stuff as for the
             previous case. */

          if (!afl->extras_cnt || (afl->a_extras_cnt && rand_below(afl, 2))) {

            use_extra = rand_below(afl, afl->a_extras_cnt);
            extra_len = afl->a_extras[use_extra].len;

            if (temp_len + extra_len >= MAX_FILE) break;

            new_buf =
                ck_maybe_grow(BUF_PARAMS(out_scratch), temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, afl->a_extras[use_extra].data,
                   extra_len);

          } else {

            use_extra = rand_below(afl, afl->extras_cnt);
            extra_len = afl->extras[use_extra].len;

            if (temp_len + extra_len >= MAX_FILE) break;

            new_buf =
                ck_maybe_grow(BUF_PARAMS(out_scratch), temp_len + extra_len);

            /* Head */
            memcpy(new_buf, out_buf, insert_at);

            /* Inserted part */
            memcpy(new_buf + insert_at, afl->extras[use_extra].data, extra_len);

          }

          /* Tail */
          memcpy(new_buf + insert_at + extra_len, out_buf + insert_at,
                 temp_len - insert_at);

          swap_bufs(BUF_PARAMS(out), BUF_PARAMS(out_scratch));
          out_buf = new_buf;
          new_buf = NULL;
          temp_len += extra_len;

          break;

        }

      }

    }

    if (common_fuzz_stuff(afl, out_buf, temp_len)) goto abandon_entry;

    /* out_buf might have been mangled a bit, so let's restore it to its
       original size and shape. */

    out_buf = ck_maybe_grow(BUF_PARAMS(out), len);
    temp_len = len;
    memcpy(out_buf, in_buf, len);

    /* If we're finding new stuff, let's run for a bit longer, limits
       permitting. */

    if (afl->queued_paths != havoc_queued) {

      if (perf_score <= afl->havoc_max_mult * 100) {

        afl->stage_max *= 2;
        perf_score *= 2;

      }

      havoc_queued = afl->queued_paths;

    }

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  if (!splice_cycle) {

    afl->stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_HAVOC] += afl->stage_max;

  } else {

    afl->stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
    afl->stage_cycles[STAGE_SPLICE] += afl->stage_max;

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

  if (afl->use_splicing && splice_cycle++ < SPLICE_CYCLES &&
      afl->queued_paths > 1 && afl->queue_cur->len > 1) {

    struct queue_entry *target;
    u32                 tid, split_at;
    u8 *                new_buf;
    s32                 f_diff, l_diff;

    /* First of all, if we've modified in_buf for havoc, let's clean that
       up... */

    if (in_buf != orig_in) {

      in_buf = orig_in;
      len = afl->queue_cur->len;

    }

    /* Pick a random queue entry and seek to it. Don't splice with yourself. */

    do {

      tid = rand_below(afl, afl->queued_paths);

    } while (tid == afl->current_entry);

    afl->splicing_with = tid;
    target = afl->queue;

    while (tid >= 100) {

      target = target->next_100;
      tid -= 100;

    }

    while (tid--)
      target = target->next;

    /* Make sure that the target has a reasonable length. */

    while (target && (target->len < 2 || target == afl->queue_cur)) {

      target = target->next;
      ++afl->splicing_with;

    }

    if (!target) goto retry_splicing;

    /* Read the testcase into a new buffer. */

    fd = open(target->fname, O_RDONLY);

    if (unlikely(fd < 0)) PFATAL("Unable to open '%s'", target->fname);

    new_buf = ck_maybe_grow(BUF_PARAMS(in_scratch), target->len);

    ck_read(fd, new_buf, target->len, target->fname);

    close(fd);

    /* Find a suitable splicing location, somewhere between the first and
       the last differing byte. Bail out if the difference is just a single
       byte or so. */

    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) { goto retry_splicing; }

    /* Split somewhere between the first and last differing byte. */

    split_at = f_diff + rand_below(afl, l_diff - f_diff);

    /* Do the thing. */

    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    swap_bufs(BUF_PARAMS(in), BUF_PARAMS(in_scratch));
    in_buf = new_buf;

    out_buf = ck_maybe_grow(BUF_PARAMS(out), len);
    memcpy(out_buf, in_buf, len);

    goto custom_mutator_stage;
    /* ???: While integrating Python module, the author decided to jump to
       python stage, but the reason behind this is not clear.*/
    // goto havoc_stage;

  }

#endif                                                     /* !IGNORE_FINDS */

  ret_val = 0;
  goto radamsa_stage;

radamsa_stage:

  if (likely(!afl->use_radamsa || !afl->radamsa_mutate_ptr)) goto abandon_entry;

  afl->stage_name = "radamsa";
  afl->stage_short = "radamsa";
  afl->stage_max = (HAVOC_CYCLES * perf_score / afl->havoc_div / 100)
                   << afl->use_radamsa;

  if (afl->stage_max < HAVOC_MIN) afl->stage_max = HAVOC_MIN;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  /* Read the additional testcase.
  We'll reuse in_scratch, as it is free at this point.
  */
  u8 *save_buf = ck_maybe_grow(BUF_PARAMS(in_scratch), len);
  memcpy(save_buf, out_buf, len);

  u32 max_len = len + choose_block_len(afl, HAVOC_BLK_XL);
  u8 *new_buf = ck_maybe_grow(BUF_PARAMS(out_scratch), max_len);
  u8 *tmp_buf;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 new_len = afl->radamsa_mutate_ptr(save_buf, len, new_buf, max_len,
                                          get_rand_seed(afl));

    if (new_len) {

      temp_len = new_len;
      tmp_buf = new_buf;

    } else {

      tmp_buf = save_buf;  // nope but I dont care
      temp_len = len;

    }

    if (common_fuzz_stuff(afl, tmp_buf, temp_len)) { goto abandon_entry; }

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_RADAMSA] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_RADAMSA] += afl->stage_max;

  ret_val = 0;
  goto abandon_entry;

/* we are through with this queue entry - for this iteration */
abandon_entry:

  afl->splicing_with = -1;

  /* Update afl->pending_not_fuzzed count if we made it through the calibration
     cycle and have not seen this entry before. */

  if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      (afl->queue_cur->was_fuzzed == 0 || afl->queue_cur->fuzz_level == 0)) {

    --afl->pending_not_fuzzed;
    afl->queue_cur->was_fuzzed = 1;
    if (afl->queue_cur->favored) --afl->pending_favored;

  }

  ++afl->queue_cur->fuzz_level;

  munmap(orig_in, afl->queue_cur->len);

  return ret_val;

#undef FLIP_BIT

}

/* MOpt mode */
u8 mopt_common_fuzzing(afl_state_t *afl, MOpt_globals_t MOpt_globals) {

  if (!MOpt_globals.is_pilot_mode) {

    if (swarm_num == 1) {

      afl->key_module = 2;
      return 0;

    }

  }

  s32 len, fd, temp_len, i, j;
  u8 *in_buf, *out_buf, *orig_in, *ex_tmp, *eff_map = 0;
  u64 havoc_queued, orig_hit_cnt, new_hit_cnt, cur_ms_lv;
  u32 splice_cycle = 0, perf_score = 100, orig_perf, prev_cksum, eff_cnt = 1;

  u8 ret_val = 1, doing_det = 0;

  u8  a_collect[MAX_AUTO_EXTRA];
  u32 a_len = 0;

#ifdef IGNORE_FINDS

  /* In IGNORE_FINDS mode, skip any entries that weren't in the
     initial data set. */

  if (afl->queue_cur->depth > 1) return 1;

#else

  if (afl->pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */

    if ((afl->queue_cur->was_fuzzed || !afl->queue_cur->favored) &&
        rand_below(afl, 100) < SKIP_TO_NEW_PROB)
      return 1;

  } else if (!afl->dumb_mode && !afl->queue_cur->favored &&

             afl->queued_paths > 10) {

    /* Otherwise, still possibly skip non-favored cases, albeit less often.
       The odds of skipping stuff are higher for already-fuzzed inputs and
       lower for never-fuzzed entries. */

    if (afl->queue_cycle > 1 && !afl->queue_cur->was_fuzzed) {

      if (rand_below(afl, 100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (rand_below(afl, 100) < SKIP_NFAV_OLD_PROB) return 1;

    }

  }

#endif                                                     /* ^IGNORE_FINDS */

  if (afl->not_on_tty) {

    ACTF("Fuzzing test case #%u (%u total, %llu uniq crashes found)...",
         afl->current_entry, afl->queued_paths, afl->unique_crashes);
    fflush(stdout);

  }

  /* Map the test case into memory. */

  fd = open(afl->queue_cur->fname, O_RDONLY);

  if (fd < 0) PFATAL("Unable to open '%s'", afl->queue_cur->fname);

  len = afl->queue_cur->len;

  orig_in = in_buf = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

  if (orig_in == MAP_FAILED)
    PFATAL("Unable to mmap '%s'", afl->queue_cur->fname);

  close(fd);

  /* We could mmap() out_buf as MAP_PRIVATE, but we end up clobbering every
     single byte anyway, so it wouldn't give us any performance or memory usage
     benefits. */

  out_buf = ck_maybe_grow(BUF_PARAMS(out), len);

  afl->subseq_tmouts = 0;

  afl->cur_depth = afl->queue_cur->depth;

  /*******************************************
   * CALIBRATION (only if failed earlier on) *
   *******************************************/

  if (afl->queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (afl->queue_cur->cal_failed < CAL_CHANCES) {

      res =
          calibrate_case(afl, afl->queue_cur, in_buf, afl->queue_cycle - 1, 0);

      if (res == FAULT_ERROR) FATAL("Unable to execute target application");

    }

    if (afl->stop_soon || res != afl->crash_mode) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

  }

  /************
   * TRIMMING *
   ************/

  if (!afl->dumb_mode && !afl->queue_cur->trim_done) {

    u8 res = trim_case(afl, afl->queue_cur, in_buf);

    if (res == FAULT_ERROR) FATAL("Unable to execute target application");

    if (afl->stop_soon) {

      ++afl->cur_skipped_paths;
      goto abandon_entry;

    }

    /* Don't retry trimming, even if it failed. */

    afl->queue_cur->trim_done = 1;

    len = afl->queue_cur->len;

  }

  memcpy(out_buf, in_buf, len);

  /*********************
   * PERFORMANCE SCORE *
   *********************/

  orig_perf = perf_score = calculate_score(afl, afl->queue_cur);

  /* Skip right away if -d is given, if we have done deterministic fuzzing on
     this entry ourselves (was_fuzzed), or if it has gone through deterministic
     testing in earlier, resumed runs (passed_det). */

  if (afl->skip_deterministic || afl->queue_cur->was_fuzzed ||
      afl->queue_cur->passed_det)
    goto havoc_stage;

  /* Skip deterministic fuzzing if exec path checksum puts this out of scope
     for this master instance. */

  if (afl->master_max &&
      (afl->queue_cur->exec_cksum % afl->master_max) != afl->master_id - 1)
    goto havoc_stage;

  cur_ms_lv = get_cur_time();
  if (!(afl->key_puppet == 0 &&
        ((cur_ms_lv - afl->last_path_time < afl->limit_time_puppet) ||
         (afl->last_crash_time != 0 &&
          cur_ms_lv - afl->last_crash_time < afl->limit_time_puppet) ||
         afl->last_path_time == 0))) {

    afl->key_puppet = 1;
    goto pacemaker_fuzzing;

  }

  doing_det = 1;

  /*********************************************
   * SIMPLE BITFLIP (+dictionary construction) *
   *********************************************/

#define FLIP_BIT(_ar, _b)                   \
  do {                                      \
                                            \
    u8 *_arf = (u8 *)(_ar);                 \
    u32 _bf = (_b);                         \
    _arf[(_bf) >> 3] ^= (128 >> ((_bf)&7)); \
                                            \
  } while (0)

  /* Single walking bit. */

  afl->stage_short = "flip1";
  afl->stage_max = len << 3;
  afl->stage_name = "bitflip 1/1";

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  prev_cksum = afl->queue_cur->exec_cksum;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

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

    if (!afl->dumb_mode && (afl->stage_cur & 7) == 7) {

      u32 cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);

      if (afl->stage_cur == afl->stage_max - 1 && cksum == prev_cksum) {

        /* If at end of file and we are still collecting a string, grab the
           final character and force output. */

        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[afl->stage_cur >> 3];
        ++a_len;

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(afl, a_collect, a_len);

      } else if (cksum != prev_cksum) {

        /* Otherwise, if the checksum has changed, see if we have something
           worthwhile queued up, and collect that if the answer is yes. */

        if (a_len >= MIN_AUTO_EXTRA && a_len <= MAX_AUTO_EXTRA)
          maybe_add_auto(afl, a_collect, a_len);

        a_len = 0;
        prev_cksum = cksum;

      }

      /* Continue collecting string, but only if the bit flip actually made
         any difference - we don't want no-op tokens. */

      if (cksum != afl->queue_cur->exec_cksum) {

        if (a_len < MAX_AUTO_EXTRA)
          a_collect[a_len] = out_buf[afl->stage_cur >> 3];
        ++a_len;

      }

    }                                       /* if (afl->stage_cur & 7) == 7 */

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP1] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP1] += afl->stage_max;

  /* Two walking bits. */

  afl->stage_name = "bitflip 2/1";
  afl->stage_short = "flip2";
  afl->stage_max = (len << 3) - 1;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP2] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP2] += afl->stage_max;

  /* Four walking bits. */

  afl->stage_name = "bitflip 4/1";
  afl->stage_short = "flip4";
  afl->stage_max = (len << 3) - 3;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur >> 3;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

    FLIP_BIT(out_buf, afl->stage_cur);
    FLIP_BIT(out_buf, afl->stage_cur + 1);
    FLIP_BIT(out_buf, afl->stage_cur + 2);
    FLIP_BIT(out_buf, afl->stage_cur + 3);

  }                                                   /* for afl->stage_cur */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP4] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP4] += afl->stage_max;

  /* Effector map setup. These macros calculate:

     EFF_APOS      - position of a particular file offset in the map.
     EFF_ALEN      - length of a map with a particular number of bytes.
     EFF_SPAN_ALEN - map span for a sequence of bytes.

   */

#define EFF_APOS(_p) ((_p) >> EFF_MAP_SCALE2)
#define EFF_REM(_x) ((_x) & ((1 << EFF_MAP_SCALE2) - 1))
#define EFF_ALEN(_l) (EFF_APOS(_l) + !!EFF_REM(_l))
#define EFF_SPAN_ALEN(_p, _l) (EFF_APOS((_p) + (_l)-1) - EFF_APOS(_p) + 1)

  /* Initialize effector map for the next step (see comments below). Always
         flag first and last byte as doing something. */

  eff_map = ck_maybe_grow(BUF_PARAMS(eff), EFF_ALEN(len));
  eff_map[0] = 1;

  if (EFF_APOS(len - 1) != 0) {

    eff_map[EFF_APOS(len - 1)] = 1;
    ++eff_cnt;

  }

  /* Walking byte. */

  afl->stage_name = "bitflip 8/8";
  afl->stage_short = "flip8";
  afl->stage_max = len;

  orig_hit_cnt = new_hit_cnt;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    afl->stage_cur_byte = afl->stage_cur;

    out_buf[afl->stage_cur] ^= 0xFF;

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

    /* We also use this stage to pull off a simple trick: we identify
       bytes that seem to have no effect on the current execution path
       even when fully flipped - and we skip them during more expensive
       deterministic stages, such as arithmetics or known ints. */

    if (!eff_map[EFF_APOS(afl->stage_cur)]) {

      u32 cksum;

      /* If in dumb mode or if the file is very short, just flag everything
         without wasting time on checksums. */

      if (!afl->dumb_mode && len >= EFF_MIN_LEN)
        cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);
      else
        cksum = ~afl->queue_cur->exec_cksum;

      if (cksum != afl->queue_cur->exec_cksum) {

        eff_map[EFF_APOS(afl->stage_cur)] = 1;
        ++eff_cnt;

      }

    }

    out_buf[afl->stage_cur] ^= 0xFF;

  }                                                   /* for afl->stage_cur */

  /* If the effector map is more than EFF_MAX_PERC dense, just flag the
     whole thing as worth fuzzing, since we wouldn't be saving much time
     anyway. */

  if (eff_cnt != EFF_ALEN(len) &&
      eff_cnt * 100 / EFF_ALEN(len) > EFF_MAX_PERC) {

    memset(eff_map, 1, EFF_ALEN(len));

    afl->blocks_eff_select += EFF_ALEN(len);

  } else {

    afl->blocks_eff_select += eff_cnt;

  }

  afl->blocks_eff_total += EFF_ALEN(len);

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP8] += afl->stage_max;

  /* Two walking bytes. */

  if (len < 2) goto skip_bitflip;

  afl->stage_name = "bitflip 16/8";
  afl->stage_short = "flip16";
  afl->stage_cur = 0;
  afl->stage_max = len - 1;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
    ++afl->stage_cur;

    *(u16 *)(out_buf + i) ^= 0xFFFF;

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP16] += afl->stage_max;

  if (len < 4) goto skip_bitflip;

  /* Four walking bytes. */

  afl->stage_name = "bitflip 32/8";
  afl->stage_short = "flip32";
  afl->stage_cur = 0;
  afl->stage_max = len - 3;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    /* Let's consult the effector map... */
    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      --afl->stage_max;
      continue;

    }

    afl->stage_cur_byte = i;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

    if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
    ++afl->stage_cur;

    *(u32 *)(out_buf + i) ^= 0xFFFFFFFF;

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_FLIP32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_FLIP32] += afl->stage_max;

skip_bitflip:

  if (afl->no_arith) goto skip_arith;

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

  for (i = 0; i < len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= 2 * ARITH_MAX;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 1; j <= ARITH_MAX; ++j) {

      u8 r = orig ^ (orig + j);

      /* Do arithmetic operations only if the result couldn't be a product
         of a bitflip. */

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = j;
        out_buf[i] = orig + j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      r = orig ^ (orig - j);

      if (!could_be_bitflip(r)) {

        afl->stage_cur_val = -j;
        out_buf[i] = orig - j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      out_buf[i] = orig;

    }

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH8] += afl->stage_max;

  /* 16-bit arithmetics, both endians. */

  if (len < 2) goto skip_arith;

  afl->stage_name = "arith 16/8";
  afl->stage_short = "arith16";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 1) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

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
        *(u16 *)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((orig & 0xff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      /* Big endian comes next. Same deal. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((orig >> 8) + j > 0xff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) + j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((orig >> 8) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u16 *)(out_buf + i) = SWAP16(SWAP16(orig) - j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      *(u16 *)(out_buf + i) = orig;

    }

  }                                               /* for i = 0; i < len - 1 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH16] += afl->stage_max;

  /* 32-bit arithmetics, both endians. */

  if (len < 4) goto skip_arith;

  afl->stage_name = "arith 32/8";
  afl->stage_short = "arith32";
  afl->stage_cur = 0;
  afl->stage_max = 4 * (len - 3) * ARITH_MAX;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= 4 * ARITH_MAX;
      continue;

    }

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
        *(u32 *)(out_buf + i) = orig + j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((orig & 0xffff) < j && !could_be_bitflip(r2)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = orig - j;

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      /* Big endian next. */

      afl->stage_val_type = STAGE_VAL_BE;

      if ((SWAP32(orig) & 0xffff) + j > 0xffff && !could_be_bitflip(r3)) {

        afl->stage_cur_val = j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) + j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((SWAP32(orig) & 0xffff) < j && !could_be_bitflip(r4)) {

        afl->stage_cur_val = -j;
        *(u32 *)(out_buf + i) = SWAP32(SWAP32(orig) - j);

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      *(u32 *)(out_buf + i) = orig;

    }

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_ARITH32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ARITH32] += afl->stage_max;

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

  for (i = 0; i < len; ++i) {

    u8 orig = out_buf[i];

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)]) {

      afl->stage_max -= sizeof(interesting_8);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_8); ++j) {

      /* Skip if the value could be a product of bitflips or arithmetics. */

      if (could_be_bitflip(orig ^ (u8)interesting_8[j]) ||
          could_be_arith(orig, (u8)interesting_8[j], 1)) {

        --afl->stage_max;
        continue;

      }

      afl->stage_cur_val = interesting_8[j];
      out_buf[i] = interesting_8[j];

      if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

      out_buf[i] = orig;
      ++afl->stage_cur;

    }

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST8] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST8] += afl->stage_max;

  /* Setting 16-bit integers, both endians. */

  if (afl->no_arith || len < 2) goto skip_interest;

  afl->stage_name = "interest 16/8";
  afl->stage_short = "int16";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 1) * (sizeof(interesting_16) >> 1);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 1; ++i) {

    u16 orig = *(u16 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)]) {

      afl->stage_max -= sizeof(interesting_16);
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_16) / 2; ++j) {

      afl->stage_cur_val = interesting_16[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or single-byte interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u16)interesting_16[j]) &&
          !could_be_arith(orig, (u16)interesting_16[j], 2) &&
          !could_be_interest(orig, (u16)interesting_16[j], 2, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u16 *)(out_buf + i) = interesting_16[j];

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((u16)interesting_16[j] != SWAP16(interesting_16[j]) &&
          !could_be_bitflip(orig ^ SWAP16(interesting_16[j])) &&
          !could_be_arith(orig, SWAP16(interesting_16[j]), 2) &&
          !could_be_interest(orig, SWAP16(interesting_16[j]), 2, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

        *(u16 *)(out_buf + i) = SWAP16(interesting_16[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

    }

    *(u16 *)(out_buf + i) = orig;

  }                                               /* for i = 0; i < len - 1 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST16] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST16] += afl->stage_max;

  if (len < 4) goto skip_interest;

  /* Setting 32-bit integers, both endians. */

  afl->stage_name = "interest 32/8";
  afl->stage_short = "int32";
  afl->stage_cur = 0;
  afl->stage_max = 2 * (len - 3) * (sizeof(interesting_32) >> 2);

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len - 3; ++i) {

    u32 orig = *(u32 *)(out_buf + i);

    /* Let's consult the effector map... */

    if (!eff_map[EFF_APOS(i)] && !eff_map[EFF_APOS(i + 1)] &&
        !eff_map[EFF_APOS(i + 2)] && !eff_map[EFF_APOS(i + 3)]) {

      afl->stage_max -= sizeof(interesting_32) >> 1;
      continue;

    }

    afl->stage_cur_byte = i;

    for (j = 0; j < sizeof(interesting_32) / 4; ++j) {

      afl->stage_cur_val = interesting_32[j];

      /* Skip if this could be a product of a bitflip, arithmetics,
         or word interesting value insertion. */

      if (!could_be_bitflip(orig ^ (u32)interesting_32[j]) &&
          !could_be_arith(orig, interesting_32[j], 4) &&
          !could_be_interest(orig, interesting_32[j], 4, 0)) {

        afl->stage_val_type = STAGE_VAL_LE;

        *(u32 *)(out_buf + i) = interesting_32[j];

        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

      if ((u32)interesting_32[j] != SWAP32(interesting_32[j]) &&
          !could_be_bitflip(orig ^ SWAP32(interesting_32[j])) &&
          !could_be_arith(orig, SWAP32(interesting_32[j]), 4) &&
          !could_be_interest(orig, SWAP32(interesting_32[j]), 4, 1)) {

        afl->stage_val_type = STAGE_VAL_BE;

        *(u32 *)(out_buf + i) = SWAP32(interesting_32[j]);
        if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;
        ++afl->stage_cur;

      } else

        --afl->stage_max;

    }

    *(u32 *)(out_buf + i) = orig;

  }                                               /* for i = 0; i < len - 3 */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_INTEREST32] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_INTEREST32] += afl->stage_max;

skip_interest:

  /********************
   * DICTIONARY STUFF *
   ********************/

  if (!afl->extras_cnt) goto skip_user_extras;

  /* Overwrite with user-supplied extras. */

  afl->stage_name = "user extras (over)";
  afl->stage_short = "ext_UO";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    /* Extras are sorted by size, from smallest to largest. This means
       that we don't have to worry about restoring the buffer in
       between writes at a particular offset determined by the outer
       loop. */

    for (j = 0; j < afl->extras_cnt; ++j) {

      /* Skip extras probabilistically if afl->extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      if ((afl->extras_cnt > MAX_DET_EXTRAS &&
           rand_below(afl, afl->extras_cnt) >= MAX_DET_EXTRAS) ||
          afl->extras[j].len > len - i ||
          !memcmp(afl->extras[j].data, out_buf + i, afl->extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->extras[j].len;
      memcpy(out_buf + i, afl->extras[j].data, last_len);

      if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_UO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UO] += afl->stage_max;

  /* Insertion of user-supplied extras. */

  afl->stage_name = "user extras (insert)";
  afl->stage_short = "ext_UI";
  afl->stage_cur = 0;
  afl->stage_max = afl->extras_cnt * (len + 1);

  orig_hit_cnt = new_hit_cnt;

  ex_tmp = ck_maybe_grow(BUF_PARAMS(ex), len + MAX_DICT_FILE);

  for (i = 0; i <= len; ++i) {

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

      if (common_fuzz_stuff(afl, ex_tmp, len + afl->extras[j].len)) {

        goto abandon_entry;

      }

      ++afl->stage_cur;

    }

    /* Copy head */
    ex_tmp[i] = out_buf[i];

  }                                                  /* for i = 0; i <= len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_UI] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_UI] += afl->stage_max;

skip_user_extras:

  if (!afl->a_extras_cnt) goto skip_extras;

  afl->stage_name = "auto extras (over)";
  afl->stage_short = "ext_AO";
  afl->stage_cur = 0;
  afl->stage_max = MIN(afl->a_extras_cnt, USE_AUTO_EXTRAS) * len;

  afl->stage_val_type = STAGE_VAL_NONE;

  orig_hit_cnt = new_hit_cnt;

  for (i = 0; i < len; ++i) {

    u32 last_len = 0;

    afl->stage_cur_byte = i;

    for (j = 0; j < MIN(afl->a_extras_cnt, USE_AUTO_EXTRAS); ++j) {

      /* See the comment in the earlier code; extras are sorted by size. */

      if (afl->a_extras[j].len > len - i ||
          !memcmp(afl->a_extras[j].data, out_buf + i, afl->a_extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1,
                  EFF_SPAN_ALEN(i, afl->a_extras[j].len))) {

        --afl->stage_max;
        continue;

      }

      last_len = afl->a_extras[j].len;
      memcpy(out_buf + i, afl->a_extras[j].data, last_len);

      if (common_fuzz_stuff(afl, out_buf, len)) goto abandon_entry;

      ++afl->stage_cur;

    }

    /* Restore all the clobbered memory. */
    memcpy(out_buf + i, in_buf + i, last_len);

  }                                                   /* for i = 0; i < len */

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_finds[STAGE_EXTRAS_AO] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_EXTRAS_AO] += afl->stage_max;

skip_extras:

  /* If we made this to here without jumping to havoc_stage or abandon_entry,
     we're properly done with deterministic steps and can mark it as such
     in the .state/ directory. */

  if (!afl->queue_cur->passed_det) mark_as_det_done(afl, afl->queue_cur);

  /****************
   * RANDOM HAVOC *
   ****************/

havoc_stage:
pacemaker_fuzzing:

  afl->stage_cur_byte = -1;

  /* The havoc stage mutation code is also invoked when splicing files; if the
     splice_cycle variable is set, generate different descriptions and such. */

  if (!splice_cycle) {

    afl->stage_name = MOpt_globals.havoc_stagename;
    afl->stage_short = MOpt_globals.havoc_stagenameshort;
    afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                     perf_score / afl->havoc_div / 100;

  } else {

    perf_score = orig_perf;

    snprintf(afl->stage_name_buf, STAGE_BUF_SIZE,
             MOpt_globals.splice_stageformat, splice_cycle);
    afl->stage_name = afl->stage_name_buf;
    afl->stage_short = MOpt_globals.splice_stagenameshort;
    afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

  }

  s32 temp_len_puppet;
  cur_ms_lv = get_cur_time();

  // for (; afl->swarm_now < swarm_num; ++afl->swarm_now)
  {

    if (afl->key_puppet == 1) {

      if (unlikely(afl->orig_hit_cnt_puppet == 0)) {

        afl->orig_hit_cnt_puppet = afl->queued_paths + afl->unique_crashes;
        afl->last_limit_time_start = get_cur_time();
        afl->SPLICE_CYCLES_puppet =
            (rand_below(
                 afl, SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) +
             SPLICE_CYCLES_puppet_low);

      }

    }                                            /* if afl->key_puppet == 1 */

    {

#ifndef IGNORE_FINDS
    havoc_stage_puppet:
#endif

      afl->stage_cur_byte = -1;

      /* The havoc stage mutation code is also invoked when splicing files; if
         the splice_cycle variable is set, generate different descriptions and
         such. */

      if (!splice_cycle) {

        afl->stage_name = MOpt_globals.havoc_stagename;
        afl->stage_short = MOpt_globals.havoc_stagenameshort;
        afl->stage_max = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                         perf_score / afl->havoc_div / 100;

      } else {

        perf_score = orig_perf;
        snprintf(afl->stage_name_buf, STAGE_BUF_SIZE,
                 MOpt_globals.splice_stageformat, splice_cycle);
        afl->stage_name = afl->stage_name_buf;
        afl->stage_short = MOpt_globals.splice_stagenameshort;
        afl->stage_max = SPLICE_HAVOC * perf_score / afl->havoc_div / 100;

      }

      if (afl->stage_max < HAVOC_MIN) afl->stage_max = HAVOC_MIN;

      temp_len = len;

      orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

      havoc_queued = afl->queued_paths;

      for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;
           ++afl->stage_cur) {

        u32 use_stacking = 1 << (1 + rand_below(afl, HAVOC_STACK_POW2));

        afl->stage_cur_val = use_stacking;

        for (i = 0; i < operator_num; ++i) {

          MOpt_globals.cycles_v3[i] = MOpt_globals.cycles_v2[i];

        }

        for (i = 0; i < use_stacking; ++i) {

          switch (select_algorithm(afl)) {

            case 0:
              /* Flip a single bit somewhere. Spooky! */
              FLIP_BIT(out_buf, rand_below(afl, temp_len << 3));
              MOpt_globals.cycles_v2[STAGE_FLIP1] += 1;
              break;

            case 1:
              if (temp_len < 2) break;
              temp_len_puppet = rand_below(afl, (temp_len << 3) - 1);
              FLIP_BIT(out_buf, temp_len_puppet);
              FLIP_BIT(out_buf, temp_len_puppet + 1);
              MOpt_globals.cycles_v2[STAGE_FLIP2] += 1;
              break;

            case 2:
              if (temp_len < 2) break;
              temp_len_puppet = rand_below(afl, (temp_len << 3) - 3);
              FLIP_BIT(out_buf, temp_len_puppet);
              FLIP_BIT(out_buf, temp_len_puppet + 1);
              FLIP_BIT(out_buf, temp_len_puppet + 2);
              FLIP_BIT(out_buf, temp_len_puppet + 3);
              MOpt_globals.cycles_v2[STAGE_FLIP4] += 1;
              break;

            case 3:
              if (temp_len < 4) break;
              out_buf[rand_below(afl, temp_len)] ^= 0xFF;
              MOpt_globals.cycles_v2[STAGE_FLIP8] += 1;
              break;

            case 4:
              if (temp_len < 8) break;
              *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) ^= 0xFFFF;
              MOpt_globals.cycles_v2[STAGE_FLIP16] += 1;
              break;

            case 5:
              if (temp_len < 8) break;
              *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) ^= 0xFFFFFFFF;
              MOpt_globals.cycles_v2[STAGE_FLIP32] += 1;
              break;

            case 6:
              out_buf[rand_below(afl, temp_len)] -=
                  1 + rand_below(afl, ARITH_MAX);
              out_buf[rand_below(afl, temp_len)] +=
                  1 + rand_below(afl, ARITH_MAX);
              MOpt_globals.cycles_v2[STAGE_ARITH8] += 1;
              break;

            case 7:
              /* Randomly subtract from word, random endian. */
              if (temp_len < 8) break;
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);
                *(u16 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) - num);

              }

              /* Randomly add to word, random endian. */
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 1);
                *(u16 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 1);
                u16 num = 1 + rand_below(afl, ARITH_MAX);
                *(u16 *)(out_buf + pos) =
                    SWAP16(SWAP16(*(u16 *)(out_buf + pos)) + num);

              }

              MOpt_globals.cycles_v2[STAGE_ARITH16] += 1;
              break;

            case 8:
              /* Randomly subtract from dword, random endian. */
              if (temp_len < 8) break;
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);
                *(u32 *)(out_buf + pos) -= 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) - num);

              }

              /* Randomly add to dword, random endian. */
              // if (temp_len < 4) break;
              if (rand_below(afl, 2)) {

                u32 pos = rand_below(afl, temp_len - 3);
                *(u32 *)(out_buf + pos) += 1 + rand_below(afl, ARITH_MAX);

              } else {

                u32 pos = rand_below(afl, temp_len - 3);
                u32 num = 1 + rand_below(afl, ARITH_MAX);
                *(u32 *)(out_buf + pos) =
                    SWAP32(SWAP32(*(u32 *)(out_buf + pos)) + num);

              }

              MOpt_globals.cycles_v2[STAGE_ARITH32] += 1;
              break;

            case 9:
              /* Set byte to interesting value. */
              if (temp_len < 4) break;
              out_buf[rand_below(afl, temp_len)] =
                  interesting_8[rand_below(afl, sizeof(interesting_8))];
              MOpt_globals.cycles_v2[STAGE_INTEREST8] += 1;
              break;

            case 10:
              /* Set word to interesting value, randomly choosing endian. */
              if (temp_len < 8) break;
              if (rand_below(afl, 2)) {

                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                    interesting_16[rand_below(afl,
                                              sizeof(interesting_16) >> 1)];

              } else {

                *(u16 *)(out_buf + rand_below(afl, temp_len - 1)) =
                    SWAP16(interesting_16[rand_below(
                        afl, sizeof(interesting_16) >> 1)]);

              }

              MOpt_globals.cycles_v2[STAGE_INTEREST16] += 1;
              break;

            case 11:
              /* Set dword to interesting value, randomly choosing endian. */

              if (temp_len < 8) break;

              if (rand_below(afl, 2)) {

                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                    interesting_32[rand_below(afl,
                                              sizeof(interesting_32) >> 2)];

              } else {

                *(u32 *)(out_buf + rand_below(afl, temp_len - 3)) =
                    SWAP32(interesting_32[rand_below(
                        afl, sizeof(interesting_32) >> 2)]);

              }

              MOpt_globals.cycles_v2[STAGE_INTEREST32] += 1;
              break;

            case 12:

              /* Just set a random byte to a random value. Because,
                 why not. We use XOR with 1-255 to eliminate the
                 possibility of a no-op. */

              out_buf[rand_below(afl, temp_len)] ^= 1 + rand_below(afl, 255);
              MOpt_globals.cycles_v2[STAGE_RANDOMBYTE] += 1;
              break;

            case 13: {

              /* Delete bytes. We're making this a bit more likely
                 than insertion (the next option) in hopes of keeping
                 files reasonably small. */

              u32 del_from, del_len;

              if (temp_len < 2) break;

              /* Don't delete too much. */

              del_len = choose_block_len(afl, temp_len - 1);

              del_from = rand_below(afl, temp_len - del_len + 1);

              memmove(out_buf + del_from, out_buf + del_from + del_len,
                      temp_len - del_from - del_len);

              temp_len -= del_len;
              MOpt_globals.cycles_v2[STAGE_DELETEBYTE] += 1;
              break;

            }

            case 14:

              if (temp_len + HAVOC_BLK_XL < MAX_FILE) {

                /* Clone bytes (75%) or insert a block of constant bytes (25%).
                 */

                u8  actually_clone = rand_below(afl, 4);
                u32 clone_from, clone_to, clone_len;
                u8 *new_buf;

                if (actually_clone) {

                  clone_len = choose_block_len(afl, temp_len);
                  clone_from = rand_below(afl, temp_len - clone_len + 1);

                } else {

                  clone_len = choose_block_len(afl, HAVOC_BLK_XL);
                  clone_from = 0;

                }

                clone_to = rand_below(afl, temp_len);

                new_buf = ck_maybe_grow(BUF_PARAMS(out_scratch),
                                        temp_len + clone_len);

                /* Head */

                memcpy(new_buf, out_buf, clone_to);

                /* Inserted part */

                if (actually_clone)
                  memcpy(new_buf + clone_to, out_buf + clone_from, clone_len);
                else
                  memset(new_buf + clone_to,
                         rand_below(afl, 2)
                             ? rand_below(afl, 256)
                             : out_buf[rand_below(afl, temp_len)],
                         clone_len);

                /* Tail */
                memcpy(new_buf + clone_to + clone_len, out_buf + clone_to,
                       temp_len - clone_to);

                swap_bufs(BUF_PARAMS(out), BUF_PARAMS(out_scratch));
                out_buf = new_buf;
                temp_len += clone_len;
                MOpt_globals.cycles_v2[STAGE_Clone75] += 1;

              }

              break;

            case 15: {

              /* Overwrite bytes with a randomly selected chunk (75%) or fixed
                 bytes (25%). */

              u32 copy_from, copy_to, copy_len;

              if (temp_len < 2) break;

              copy_len = choose_block_len(afl, temp_len - 1);

              copy_from = rand_below(afl, temp_len - copy_len + 1);
              copy_to = rand_below(afl, temp_len - copy_len + 1);

              if (rand_below(afl, 4)) {

                if (copy_from != copy_to)
                  memmove(out_buf + copy_to, out_buf + copy_from, copy_len);

              } else

                memset(out_buf + copy_to,
                       rand_below(afl, 2) ? rand_below(afl, 256)
                                          : out_buf[rand_below(afl, temp_len)],
                       copy_len);
              MOpt_globals.cycles_v2[STAGE_OverWrite75] += 1;
              break;

            }                                                    /* case 15 */

          }                                    /* switch select_algorithm() */

        }                                      /* for i=0; i < use_stacking */

        *MOpt_globals.pTime += 1;

        u64 temp_total_found = afl->queued_paths + afl->unique_crashes;

        if (common_fuzz_stuff(afl, out_buf, temp_len))
          goto abandon_entry_puppet;

        /* out_buf might have been mangled a bit, so let's restore it to its
           original size and shape. */

        out_buf = ck_maybe_grow(BUF_PARAMS(out), len);
        temp_len = len;
        memcpy(out_buf, in_buf, len);

        /* If we're finding new stuff, let's run for a bit longer, limits
           permitting. */

        if (afl->queued_paths != havoc_queued) {

          if (perf_score <= afl->havoc_max_mult * 100) {

            afl->stage_max *= 2;
            perf_score *= 2;

          }

          havoc_queued = afl->queued_paths;

        }

        if (unlikely(afl->queued_paths + afl->unique_crashes >
                     temp_total_found)) {

          u64 temp_temp_puppet =
              afl->queued_paths + afl->unique_crashes - temp_total_found;
          afl->total_puppet_find = afl->total_puppet_find + temp_temp_puppet;
          for (i = 0; i < operator_num; ++i) {

            if (MOpt_globals.cycles_v2[i] > MOpt_globals.cycles_v3[i])
              MOpt_globals.finds_v2[i] += temp_temp_puppet;

          }

        }                                                             /* if */

      } /* for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max;

           ++afl->stage_cur) { */

      new_hit_cnt = afl->queued_paths + afl->unique_crashes;

      if (MOpt_globals.is_pilot_mode) {

        if (!splice_cycle) {

          afl->stage_finds[STAGE_HAVOC] += new_hit_cnt - orig_hit_cnt;
          afl->stage_cycles[STAGE_HAVOC] += afl->stage_max;

        } else {

          afl->stage_finds[STAGE_SPLICE] += new_hit_cnt - orig_hit_cnt;
          afl->stage_cycles[STAGE_SPLICE] += afl->stage_max;

        }

      }

#ifndef IGNORE_FINDS

      /************
       * SPLICING *
       ************/

    retry_splicing_puppet:

      if (afl->use_splicing && splice_cycle++ < afl->SPLICE_CYCLES_puppet &&
          afl->queued_paths > 1 && afl->queue_cur->len > 1) {

        struct queue_entry *target;
        u32                 tid, split_at;
        u8 *                new_buf;
        s32                 f_diff, l_diff;

        /* First of all, if we've modified in_buf for havoc, let's clean that
           up... */

        if (in_buf != orig_in) {

          in_buf = orig_in;
          len = afl->queue_cur->len;

        }

        /* Pick a random queue entry and seek to it. Don't splice with yourself.
         */

        do {

          tid = rand_below(afl, afl->queued_paths);

        } while (tid == afl->current_entry);

        afl->splicing_with = tid;
        target = afl->queue;

        while (tid >= 100) {

          target = target->next_100;
          tid -= 100;

        }

        while (tid--)
          target = target->next;

        /* Make sure that the target has a reasonable length. */

        while (target && (target->len < 2 || target == afl->queue_cur)) {

          target = target->next;
          ++afl->splicing_with;

        }

        if (!target) goto retry_splicing_puppet;

        /* Read the testcase into a new buffer. */

        fd = open(target->fname, O_RDONLY);

        if (fd < 0) PFATAL("Unable to open '%s'", target->fname);

        new_buf = ck_maybe_grow(BUF_PARAMS(in_scratch), target->len);

        ck_read(fd, new_buf, target->len, target->fname);

        close(fd);

        /* Find a suitable splicin g location, somewhere between the first and
           the last differing byte. Bail out if the difference is just a single
           byte or so. */

        locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

        if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {

          goto retry_splicing_puppet;

        }

        /* Split somewhere between the first and last differing byte. */

        split_at = f_diff + rand_below(afl, l_diff - f_diff);

        /* Do the thing. */

        len = target->len;
        memcpy(new_buf, in_buf, split_at);
        swap_bufs(BUF_PARAMS(in), BUF_PARAMS(in_scratch));
        in_buf = new_buf;
        out_buf = ck_maybe_grow(BUF_PARAMS(out), len);
        memcpy(out_buf, in_buf, len);

        goto havoc_stage_puppet;

      }                                                  /* if splice_cycle */

#endif                                                     /* !IGNORE_FINDS */

      ret_val = 0;

    abandon_entry:
    abandon_entry_puppet:

      if (splice_cycle >= afl->SPLICE_CYCLES_puppet)
        afl->SPLICE_CYCLES_puppet =
            (rand_below(
                 afl, SPLICE_CYCLES_puppet_up - SPLICE_CYCLES_puppet_low + 1) +
             SPLICE_CYCLES_puppet_low);

      afl->splicing_with = -1;

      /* Update afl->pending_not_fuzzed count if we made it through the
         calibration cycle and have not seen this entry before. */

      // if (!afl->stop_soon && !afl->queue_cur->cal_failed &&
      // !afl->queue_cur->was_fuzzed) {

      //   afl->queue_cur->was_fuzzed = 1;
      //   --afl->pending_not_fuzzed;
      //   if (afl->queue_cur->favored) --afl->pending_favored;
      // }

      munmap(orig_in, afl->queue_cur->len);

      if (afl->key_puppet == 1) {

        if (unlikely(
                afl->queued_paths + afl->unique_crashes >
                ((afl->queued_paths + afl->unique_crashes) * limit_time_bound +
                 afl->orig_hit_cnt_puppet))) {

          afl->key_puppet = 0;
          cur_ms_lv = get_cur_time();
          new_hit_cnt = afl->queued_paths + afl->unique_crashes;
          afl->orig_hit_cnt_puppet = 0;
          afl->last_limit_time_start = 0;

        }

      }

      if (unlikely(*MOpt_globals.pTime > MOpt_globals.period)) {

        afl->total_pacemaker_time += *MOpt_globals.pTime;
        *MOpt_globals.pTime = 0;
        afl->temp_puppet_find = afl->total_puppet_find;
        new_hit_cnt = afl->queued_paths + afl->unique_crashes;

        if (MOpt_globals.is_pilot_mode) {

          afl->swarm_fitness[afl->swarm_now] =
              (double)(afl->total_puppet_find - afl->temp_puppet_find) /
              ((double)(afl->tmp_pilot_time) / afl->period_pilot_tmp);

        }

        u64 temp_stage_finds_puppet = 0;
        for (i = 0; i < operator_num; ++i) {

          if (MOpt_globals.is_pilot_mode) {

            double temp_eff = 0.0;

            if (MOpt_globals.cycles_v2[i] > MOpt_globals.cycles[i])
              temp_eff =
                  (double)(MOpt_globals.finds_v2[i] - MOpt_globals.finds[i]) /
                  (double)(MOpt_globals.cycles_v2[i] - MOpt_globals.cycles[i]);

            if (afl->eff_best[afl->swarm_now][i] < temp_eff) {

              afl->eff_best[afl->swarm_now][i] = temp_eff;
              afl->L_best[afl->swarm_now][i] = afl->x_now[afl->swarm_now][i];

            }

          }

          MOpt_globals.finds[i] = MOpt_globals.finds_v2[i];
          MOpt_globals.cycles[i] = MOpt_globals.cycles_v2[i];
          temp_stage_finds_puppet += MOpt_globals.finds[i];

        }                                    /* for i = 0; i < operator_num */

        if (MOpt_globals.is_pilot_mode) {

          afl->swarm_now = afl->swarm_now + 1;
          if (afl->swarm_now == swarm_num) {

            afl->key_module = 1;
            for (i = 0; i < operator_num; ++i) {

              afl->core_operator_cycles_puppet_v2[i] =
                  afl->core_operator_cycles_puppet[i];
              afl->core_operator_cycles_puppet_v3[i] =
                  afl->core_operator_cycles_puppet[i];
              afl->core_operator_finds_puppet_v2[i] =
                  afl->core_operator_finds_puppet[i];

            }

            double swarm_eff = 0.0;
            afl->swarm_now = 0;
            for (i = 0; i < swarm_num; ++i) {

              if (afl->swarm_fitness[i] > swarm_eff) {

                swarm_eff = afl->swarm_fitness[i];
                afl->swarm_now = i;

              }

            }

            if (afl->swarm_now < 0 || afl->swarm_now > swarm_num - 1)
              PFATAL("swarm_now error number  %d", afl->swarm_now);

          }                               /* if afl->swarm_now == swarm_num */

          /* adjust pointers dependent on 'afl->swarm_now' */
          afl->mopt_globals_pilot.finds =
              afl->stage_finds_puppet[afl->swarm_now];
          afl->mopt_globals_pilot.finds_v2 =
              afl->stage_finds_puppet_v2[afl->swarm_now];
          afl->mopt_globals_pilot.cycles =
              afl->stage_cycles_puppet[afl->swarm_now];
          afl->mopt_globals_pilot.cycles_v2 =
              afl->stage_cycles_puppet_v2[afl->swarm_now];
          afl->mopt_globals_pilot.cycles_v3 =
              afl->stage_cycles_puppet_v3[afl->swarm_now];

        } else {

          afl->key_module = 2;

          afl->old_hit_count = new_hit_cnt;

        }                                                  /* if pilot_mode */

      }         /* if (unlikely(*MOpt_globals.pTime > MOpt_globals.period)) */

    }                                                              /* block */

  }                                                                /* block */

  return ret_val;

}

#undef FLIP_BIT

u8 core_fuzzing(afl_state_t *afl) {

  return mopt_common_fuzzing(afl, afl->mopt_globals_core);

}

u8 pilot_fuzzing(afl_state_t *afl) {

  return mopt_common_fuzzing(afl, afl->mopt_globals_pilot);

}

void pso_updating(afl_state_t *afl) {

  afl->g_now += 1;
  if (afl->g_now > afl->g_max) afl->g_now = 0;
  afl->w_now =
      (afl->w_init - afl->w_end) * (afl->g_max - afl->g_now) / (afl->g_max) +
      afl->w_end;
  int tmp_swarm, i, j;
  u64 temp_operator_finds_puppet = 0;
  for (i = 0; i < operator_num; ++i) {

    afl->operator_finds_puppet[i] = afl->core_operator_finds_puppet[i];

    for (j = 0; j < swarm_num; ++j) {

      afl->operator_finds_puppet[i] =
          afl->operator_finds_puppet[i] + afl->stage_finds_puppet[j][i];

    }

    temp_operator_finds_puppet =
        temp_operator_finds_puppet + afl->operator_finds_puppet[i];

  }

  for (i = 0; i < operator_num; ++i) {

    if (afl->operator_finds_puppet[i])
      afl->G_best[i] = (double)((double)(afl->operator_finds_puppet[i]) /
                                (double)(temp_operator_finds_puppet));

  }

  for (tmp_swarm = 0; tmp_swarm < swarm_num; ++tmp_swarm) {

    double x_temp = 0.0;
    for (i = 0; i < operator_num; ++i) {

      afl->probability_now[tmp_swarm][i] = 0.0;
      afl->v_now[tmp_swarm][i] =
          afl->w_now * afl->v_now[tmp_swarm][i] +
          RAND_C * (afl->L_best[tmp_swarm][i] - afl->x_now[tmp_swarm][i]) +
          RAND_C * (afl->G_best[i] - afl->x_now[tmp_swarm][i]);
      afl->x_now[tmp_swarm][i] += afl->v_now[tmp_swarm][i];
      if (afl->x_now[tmp_swarm][i] > v_max)
        afl->x_now[tmp_swarm][i] = v_max;
      else if (afl->x_now[tmp_swarm][i] < v_min)
        afl->x_now[tmp_swarm][i] = v_min;
      x_temp += afl->x_now[tmp_swarm][i];

    }

    for (i = 0; i < operator_num; ++i) {

      afl->x_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i] / x_temp;
      if (likely(i != 0))
        afl->probability_now[tmp_swarm][i] =
            afl->probability_now[tmp_swarm][i - 1] + afl->x_now[tmp_swarm][i];
      else
        afl->probability_now[tmp_swarm][i] = afl->x_now[tmp_swarm][i];

    }

    if (afl->probability_now[tmp_swarm][operator_num - 1] < 0.99 ||
        afl->probability_now[tmp_swarm][operator_num - 1] > 1.01)
      FATAL("ERROR probability");

  }

  afl->swarm_now = 0;
  afl->key_module = 0;

}

/* larger change for MOpt implementation: the original fuzz_one was renamed
   to fuzz_one_original. All documentation references to fuzz_one therefore
   mean fuzz_one_original */

u8 fuzz_one(afl_state_t *afl) {

  int key_val_lv = 0;

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

  if (afl->limit_time_sig == 0) {

    key_val_lv = fuzz_one_original(afl);

  } else {

    if (afl->key_module == 0)
      key_val_lv = pilot_fuzzing(afl);
    else if (afl->key_module == 1)
      key_val_lv = core_fuzzing(afl);
    else if (afl->key_module == 2)
      pso_updating(afl);

  }

  return key_val_lv;

#undef BUF_PARAMS

}

