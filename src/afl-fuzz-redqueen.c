/*
   american fuzzy lop++ - redqueen implementation on top of cmplog
   ---------------------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#include "afl-fuzz.h"
#include "cmplog.h"

///// Colorization

struct range {

  u32           start;
  u32           end;
  struct range *next;

};

struct range *add_range(struct range *ranges, u32 start, u32 end) {

  struct range *r = ck_alloc_nozero(sizeof(struct range));
  r->start = start;
  r->end = end;
  r->next = ranges;
  return r;

}

struct range *pop_biggest_range(struct range **ranges) {

  struct range *r = *ranges;
  struct range *prev = NULL;
  struct range *rmax = NULL;
  struct range *prev_rmax = NULL;
  u32           max_size = 0;

  while (r) {

    u32 s = r->end - r->start;
    if (s >= max_size) {

      max_size = s;
      prev_rmax = prev;
      rmax = r;

    }

    prev = r;
    r = r->next;

  }

  if (rmax) {

    if (prev_rmax)
      prev_rmax->next = rmax->next;
    else
      *ranges = rmax->next;

  }

  return rmax;

}

static u8 get_exec_checksum(afl_state_t *afl, u8 *buf, u32 len, u32 *cksum) {

  if (unlikely(common_fuzz_stuff(afl, buf, len))) return 1;

  *cksum = hash32(afl->fsrv.trace_bits, MAP_SIZE, HASH_CONST);
  return 0;

}

static void rand_replace(afl_state_t *afl, u8 *buf, u32 len) {

  u32 i;
  for (i = 0; i < len; ++i)
    buf[i] = rand_below(afl, 256);

}

static u8 colorization(afl_state_t *afl, u8 *buf, u32 len, u32 exec_cksum) {

  struct range *ranges = add_range(NULL, 0, len);
  u8 *          backup = ck_alloc_nozero(len);

  u8 needs_write = 0;

  u64 orig_hit_cnt, new_hit_cnt;
  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "colorization";
  afl->stage_short = "colorization";
  afl->stage_max = 1000;

  struct range *rng;
  afl->stage_cur = 0;
  while ((rng = pop_biggest_range(&ranges)) != NULL &&
         afl->stage_cur < afl->stage_max) {

    u32 s = rng->end - rng->start;
    if (s == 0) goto empty_range;

    memcpy(backup, buf + rng->start, s);
    rand_replace(afl, buf + rng->start, s);

    u32 cksum;
    if (unlikely(get_exec_checksum(afl, buf, len, &cksum))) goto checksum_fail;

    if (cksum != exec_cksum) {

      ranges = add_range(ranges, rng->start, rng->start + s / 2);
      ranges = add_range(ranges, rng->start + s / 2 + 1, rng->end);
      memcpy(buf + rng->start, backup, s);

    } else

      needs_write = 1;

  empty_range:
    ck_free(rng);
    ++afl->stage_cur;

  }

  if (afl->stage_cur < afl->stage_max) afl->queue_cur->fully_colorized = 1;

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;
  afl->stage_finds[STAGE_COLORIZATION] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_COLORIZATION] += afl->stage_cur;
  ck_free(backup);

  while (ranges) {

    rng = ranges;
    ranges = ranges->next;
    ck_free(rng);

  }

  // save the input with the high entropy

  if (needs_write) {

    s32 fd;

    if (afl->no_unlink) {

      fd = open(afl->queue_cur->fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    } else {

      unlink(afl->queue_cur->fname);                       /* ignore errors */
      fd = open(afl->queue_cur->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    }

    if (fd < 0) PFATAL("Unable to create '%s'", afl->queue_cur->fname);

    ck_write(fd, buf, len, afl->queue_cur->fname);
    afl->queue_cur->len = len;  // no-op, just to be 100% safe

    close(fd);

  }

  return 0;

checksum_fail:
  ck_free(backup);

  while (ranges) {

    rng = ranges;
    ranges = ranges->next;
    ck_free(rng);

  }

  return 1;

}

///// Input to State replacement

static u8 its_fuzz(afl_state_t *afl, u8 *buf, u32 len, u8 *status) {

  u64 orig_hit_cnt, new_hit_cnt;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  if (unlikely(common_fuzz_stuff(afl, buf, len))) return 1;

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt))
    *status = 1;
  else
    *status = 2;

  return 0;

}

static u8 cmp_extend_encoding(afl_state_t *afl, struct cmp_header *h,
                              u64 pattern, u64 repl, u32 idx, u8 *orig_buf,
                              u8 *buf, u32 len, u8 do_reverse, u8 *status) {

  u64 *buf_64 = (u64 *)&buf[idx];
  u32 *buf_32 = (u32 *)&buf[idx];
  u16 *buf_16 = (u16 *)&buf[idx];
  // u8*  buf_8  = &buf[idx];
  // u64* o_buf_64 = (u64*)&orig_buf[idx];
  // u32* o_buf_32 = (u32*)&orig_buf[idx];
  // u16* o_buf_16 = (u16*)&orig_buf[idx];
  // u8*  o_buf_8  = &orig_buf[idx];

  u32 its_len = len - idx;
  *status = 0;

  if (SHAPE_BYTES(h->shape) == 8) {

    if (its_len >= 8 && *buf_64 == pattern) {  // && *o_buf_64 == pattern) {

      *buf_64 = repl;
      if (unlikely(its_fuzz(afl, buf, len, status))) return 1;
      *buf_64 = pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(afl, h, SWAP64(pattern), SWAP64(repl),
                                       idx, orig_buf, buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) == 4 || *status == 2) {

    if (its_len >= 4 &&
        *buf_32 == (u32)pattern) {  // && *o_buf_32 == (u32)pattern) {

      *buf_32 = (u32)repl;
      if (unlikely(its_fuzz(afl, buf, len, status))) return 1;
      *buf_32 = pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(afl, h, SWAP32(pattern), SWAP32(repl),
                                       idx, orig_buf, buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) == 2 || *status == 2) {

    if (its_len >= 2 &&
        *buf_16 == (u16)pattern) {  // && *o_buf_16 == (u16)pattern) {

      *buf_16 = (u16)repl;
      if (unlikely(its_fuzz(afl, buf, len, status))) return 1;
      *buf_16 = (u16)pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(afl, h, SWAP16(pattern), SWAP16(repl),
                                       idx, orig_buf, buf, len, 0, status)))
        return 1;

  }

  /*if (SHAPE_BYTES(h->shape) == 1 || *status == 2) {

    if (its_len >= 2 && *buf_8 == (u8)pattern) {// && *o_buf_8 == (u8)pattern) {

      *buf_8 = (u8)repl;
      if (unlikely(its_fuzz(afl, buf, len, status)))
        return 1;
      *buf_16 = (u16)pattern;

    }

  }*/

  return 0;

}

static void try_to_add_to_dict(afl_state_t *afl, u64 v, u8 shape) {

  u8 *b = (u8 *)&v;

  u32 k;
  u8  cons_ff = 0, cons_0 = 0;
  for (k = 0; k < shape; ++k) {

    if (b[k] == 0)
      ++cons_0;
    else if (b[k] == 0xff)
      ++cons_0;
    else
      cons_0 = cons_ff = 0;

    if (cons_0 > 1 || cons_ff > 1) return;

  }

  maybe_add_auto(afl, (u8 *)&v, shape);

  u64 rev;
  switch (shape) {

    case 1: break;
    case 2:
      rev = SWAP16((u16)v);
      maybe_add_auto(afl, (u8 *)&rev, shape);
      break;
    case 4:
      rev = SWAP32((u32)v);
      maybe_add_auto(afl, (u8 *)&rev, shape);
      break;
    case 8:
      rev = SWAP64(v);
      maybe_add_auto(afl, (u8 *)&rev, shape);
      break;

  }

}

static u8 cmp_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u32 len) {

  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  u32                i, j, idx;

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_H) loggeds = CMP_MAP_H;

  u8 status;
  // opt not in the paper
  u32 fails = 0;

  for (i = 0; i < loggeds; ++i) {

    struct cmp_operands *o = &afl->shm.cmp_map->log[key][i];

    // opt not in the paper
    for (j = 0; j < i; ++j)
      if (afl->shm.cmp_map->log[key][j].v0 == o->v0 &&
          afl->shm.cmp_map->log[key][i].v1 == o->v1)
        goto cmp_fuzz_next_iter;

    for (idx = 0; idx < len && fails < 8; ++idx) {

      if (unlikely(cmp_extend_encoding(afl, h, o->v0, o->v1, idx, orig_buf, buf,
                                       len, 1, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

      if (unlikely(cmp_extend_encoding(afl, h, o->v1, o->v0, idx, orig_buf, buf,
                                       len, 1, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

    }

    // If failed, add to dictionary
    if (fails == 8) {

      try_to_add_to_dict(afl, o->v0, SHAPE_BYTES(h->shape));
      try_to_add_to_dict(afl, o->v1, SHAPE_BYTES(h->shape));

    }

  cmp_fuzz_next_iter:
    afl->stage_cur++;

  }

  return 0;

}

static u8 rtn_extend_encoding(afl_state_t *afl, struct cmp_header *h,
                              u8 *pattern, u8 *repl, u32 idx, u8 *orig_buf,
                              u8 *buf, u32 len, u8 *status) {

  u32 i;
  u32 its_len = MIN(32, len - idx);

  u8 save[32];
  memcpy(save, &buf[idx], its_len);

  *status = 0;

  for (i = 0; i < its_len; ++i) {

    if (pattern[idx + i] != buf[idx + i] || *status == 1) break;

    buf[idx + i] = repl[idx + i];
    if (unlikely(its_fuzz(afl, buf, len, status))) return 1;

  }

  memcpy(&buf[idx], save, i);
  return 0;

}

static u8 rtn_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u32 len) {

  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  u32                i, j, idx;

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_RTN_H) loggeds = CMP_MAP_RTN_H;

  u8 status;
  // opt not in the paper
  u32 fails = 0;

  for (i = 0; i < loggeds; ++i) {

    struct cmpfn_operands *o =
        &((struct cmpfn_operands *)afl->shm.cmp_map->log[key])[i];

    // opt not in the paper
    for (j = 0; j < i; ++j)
      if (!memcmp(&((struct cmpfn_operands *)afl->shm.cmp_map->log[key])[j], o,
                  sizeof(struct cmpfn_operands)))
        goto rtn_fuzz_next_iter;

    for (idx = 0; idx < len && fails < 8; ++idx) {

      if (unlikely(rtn_extend_encoding(afl, h, o->v0, o->v1, idx, orig_buf, buf,
                                       len, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

      if (unlikely(rtn_extend_encoding(afl, h, o->v1, o->v0, idx, orig_buf, buf,
                                       len, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

    }

    // If failed, add to dictionary
    if (fails == 8) {

      maybe_add_auto(afl, o->v0, SHAPE_BYTES(h->shape));
      maybe_add_auto(afl, o->v1, SHAPE_BYTES(h->shape));

    }

  rtn_fuzz_next_iter:
    afl->stage_cur++;

  }

  return 0;

}

///// Input to State stage

// afl->queue_cur->exec_cksum
u8 input_to_state_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len,
                        u32 exec_cksum) {

  u8 r = 1;

  if (unlikely(colorization(afl, buf, len, exec_cksum))) return 1;

  // do it manually, forkserver clear only afl->fsrv.trace_bits
  memset(afl->shm.cmp_map->headers, 0, sizeof(afl->shm.cmp_map->headers));

  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) return 1;

  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs = afl->total_execs;
  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "input-to-state";
  afl->stage_short = "its";
  afl->stage_max = 0;
  afl->stage_cur = 0;

  u32 k;
  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!afl->shm.cmp_map->headers[k].hits) continue;
    if (afl->shm.cmp_map->headers[k].type == CMP_TYPE_INS)
      afl->stage_max += MIN((u32)afl->shm.cmp_map->headers[k].hits, CMP_MAP_H);
    else
      afl->stage_max +=
          MIN((u32)afl->shm.cmp_map->headers[k].hits, CMP_MAP_RTN_H);

  }

  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!afl->shm.cmp_map->headers[k].hits) continue;

    if (afl->shm.cmp_map->headers[k].type == CMP_TYPE_INS) {

      if (unlikely(cmp_fuzz(afl, k, orig_buf, buf, len))) goto exit_its;

    } else {

      if (unlikely(rtn_fuzz(afl, k, orig_buf, buf, len))) goto exit_its;

    }

  }

  r = 0;

exit_its:
  memcpy(orig_buf, buf, len);

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;
  afl->stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ITS] += afl->total_execs - orig_execs;

  return r;

}

