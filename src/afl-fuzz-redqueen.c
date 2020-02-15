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

static char** its_argv;

///// Colorization

struct range {

  u32           start;
  u32           end;
  struct range* next;

};

struct range* add_range(struct range* ranges, u32 start, u32 end) {

  struct range* r = ck_alloc_nozero(sizeof(struct range));
  r->start = start;
  r->end = end;
  r->next = ranges;
  return r;

}

struct range* pop_biggest_range(struct range** ranges) {

  struct range* r = *ranges;
  struct range* prev = NULL;
  struct range* rmax = NULL;
  struct range* prev_rmax = NULL;
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

u8 get_exec_checksum(u8* buf, u32 len, u32* cksum) {

  if (unlikely(common_fuzz_stuff(its_argv, buf, len))) return 1;

  *cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);
  return 0;

}

static void rand_replace(u8* buf, u32 len) {

  u32 i;
  for (i = 0; i < len; ++i)
    buf[i] = UR(256);

}

u8 colorization(u8* buf, u32 len, u32 exec_cksum) {

  struct range* ranges = add_range(NULL, 0, len);
  u8*           backup = ck_alloc_nozero(len);

  u8 needs_write = 0;

  u64 orig_hit_cnt, new_hit_cnt;
  orig_hit_cnt = queued_paths + unique_crashes;

  stage_name = "colorization";
  stage_short = "colorization";
  stage_max = 1000;

  struct range* rng;
  stage_cur = stage_max;
  while ((rng = pop_biggest_range(&ranges)) != NULL && stage_cur) {

    u32 s = rng->end - rng->start;
    if (s == 0) goto empty_range;

    memcpy(backup, buf + rng->start, s);
    rand_replace(buf + rng->start, s);

    u32 cksum;
    if (unlikely(get_exec_checksum(buf, len, &cksum))) goto checksum_fail;

    if (cksum != exec_cksum) {

      ranges = add_range(ranges, rng->start, rng->start + s / 2);
      ranges = add_range(ranges, rng->start + s / 2 + 1, rng->end);
      memcpy(buf + rng->start, backup, s);

    } else

      needs_write = 1;

  empty_range:
    ck_free(rng);
    --stage_cur;

  }

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_COLORIZATION] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_COLORIZATION] += stage_max - stage_cur;
  ck_free(backup);

  while (ranges) {

    rng = ranges;
    ranges = ranges->next;
    ck_free(rng);

  }

  // save the input with the high entropy

  if (needs_write) {

    s32 fd;

    if (no_unlink) {

      fd = open(queue_cur->fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    } else {

      unlink(queue_cur->fname);                            /* ignore errors */
      fd = open(queue_cur->fname, O_WRONLY | O_CREAT | O_EXCL, 0600);

    }

    if (fd < 0) PFATAL("Unable to create '%s'", queue_cur->fname);

    ck_write(fd, buf, len, queue_cur->fname);
    queue_cur->len = len;  // no-op, just to be 100% safe

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

u8 its_fuzz(u32 idx, u32 size, u8* buf, u32 len, u8* status) {

  u64 orig_hit_cnt, new_hit_cnt;

  orig_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(common_fuzz_stuff(its_argv, buf, len))) return 1;

  new_hit_cnt = queued_paths + unique_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt)) {

    *status = 1;

  } else {

    if (size >= MIN_AUTO_EXTRA && size <= MAX_AUTO_EXTRA)
      maybe_add_auto(&buf[idx], size);
    *status = 2;

  }

  return 0;

}

u8 cmp_extend_encoding(struct cmp_header* h, u64 pattern, u64 repl, u32 idx,
                       u8* orig_buf, u8* buf, u32 len, u8 do_reverse,
                       u8* status) {

  u64* buf_64 = (u64*)&buf[idx];
  u32* buf_32 = (u32*)&buf[idx];
  u16* buf_16 = (u16*)&buf[idx];
  // u8*  buf_8  = &buf[idx];
  u64* o_buf_64 = (u64*)&orig_buf[idx];
  u32* o_buf_32 = (u32*)&orig_buf[idx];
  u16* o_buf_16 = (u16*)&orig_buf[idx];
  // u8*  o_buf_8  = &orig_buf[idx];

  u32 its_len = len - idx;
  *status = 0;

  if (SHAPE_BYTES(h->shape) == 8) {

    if (its_len >= 8 && *buf_64 == pattern && *o_buf_64 == pattern) {

      *buf_64 = repl;
      if (unlikely(its_fuzz(idx, 8, buf, len, status))) return 1;
      *buf_64 = pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(h, SWAP64(pattern), SWAP64(repl), idx,
                                       orig_buf, buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) == 4 || *status == 2) {

    if (its_len >= 4 && *buf_32 == (u32)pattern && *o_buf_32 == (u32)pattern) {

      *buf_32 = (u32)repl;
      if (unlikely(its_fuzz(idx, 4, buf, len, status))) return 1;
      *buf_32 = pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(h, SWAP32(pattern), SWAP32(repl), idx,
                                       orig_buf, buf, len, 0, status)))
        return 1;

  }

  if (SHAPE_BYTES(h->shape) == 2 || *status == 2) {

    if (its_len >= 2 && *buf_16 == (u16)pattern && *o_buf_16 == (u16)pattern) {

      *buf_16 = (u16)repl;
      if (unlikely(its_fuzz(idx, 2, buf, len, status))) return 1;
      *buf_16 = (u16)pattern;

    }

    // reverse encoding
    if (do_reverse)
      if (unlikely(cmp_extend_encoding(h, SWAP16(pattern), SWAP16(repl), idx,
                                       orig_buf, buf, len, 0, status)))
        return 1;

  }

  /*if (SHAPE_BYTES(h->shape) == 1 || *status == 2) {

    if (its_len >= 2 && *buf_8 == (u8)pattern && *o_buf_8 == (u8)pattern) {

      *buf_8 = (u8)repl;
      if (unlikely(its_fuzz(idx, 1, buf, len, status)))
        return 1;
      *buf_16 = (u16)pattern;

    }

  }*/

  return 0;

}

void try_to_add_to_dict(u64 v, u8 shape) {

  u8* b = (u8*)&v;

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

  maybe_add_auto((u8*)&v, shape);

  u64 rev;
  switch (shape) {

    case 1: break;
    case 2:
      rev = SWAP16((u16)v);
      maybe_add_auto((u8*)&rev, shape);
      break;
    case 4:
      rev = SWAP32((u32)v);
      maybe_add_auto((u8*)&rev, shape);
      break;
    case 8:
      rev = SWAP64(v);
      maybe_add_auto((u8*)&rev, shape);
      break;

  }

}

u8 cmp_fuzz(u32 key, u8* orig_buf, u8* buf, u32 len) {

  struct cmp_header* h = &cmp_map->headers[key];
  u32                i, j, idx;

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_H) loggeds = CMP_MAP_H;

  u8 status;
  // opt not in the paper
  u32 fails = 0;

  for (i = 0; i < loggeds; ++i) {

    struct cmp_operands* o = &cmp_map->log[key][i];

    // opt not in the paper
    for (j = 0; j < i; ++j)
      if (cmp_map->log[key][j].v0 == o->v0 && cmp_map->log[key][i].v1 == o->v1)
        goto cmp_fuzz_next_iter;

    for (idx = 0; idx < len && fails < 8; ++idx) {

      if (unlikely(cmp_extend_encoding(h, o->v0, o->v1, idx, orig_buf, buf, len,
                                       1, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

      if (unlikely(cmp_extend_encoding(h, o->v1, o->v0, idx, orig_buf, buf, len,
                                       1, &status)))
        return 1;
      if (status == 2)
        ++fails;
      else if (status == 1)
        break;

    }

    // If failed, add to dictionary
    if (fails == 8) {

      try_to_add_to_dict(o->v0, SHAPE_BYTES(h->shape));
      try_to_add_to_dict(o->v1, SHAPE_BYTES(h->shape));

    }

  cmp_fuzz_next_iter:
    stage_cur++;

  }

  return 0;

}

///// Input to State stage

// queue_cur->exec_cksum
u8 input_to_state_stage(char** argv, u8* orig_buf, u8* buf, u32 len,
                        u32 exec_cksum) {

  its_argv = argv;

  if (unlikely(colorization(buf, len, exec_cksum))) return 1;

  // do it manually, forkserver clear only trace_bits
  memset(cmp_map->headers, 0, sizeof(cmp_map->headers));

  if (unlikely(common_fuzz_cmplog_stuff(argv, buf, len))) return 1;

  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs = total_execs;
  orig_hit_cnt = queued_paths + unique_crashes;

  stage_name = "input-to-state";
  stage_short = "its";
  stage_max = 0;
  stage_cur = 0;

  u32 k;
  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!cmp_map->headers[k].hits) continue;
    if (cmp_map->headers[k].hits > CMP_MAP_H)
      stage_max += CMP_MAP_H;
    else
      stage_max += cmp_map->headers[k].hits;

  }

  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!cmp_map->headers[k].hits) continue;
    cmp_fuzz(k, orig_buf, buf, len);

  }

  memcpy(orig_buf, buf, len);

  new_hit_cnt = queued_paths + unique_crashes;
  stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  stage_cycles[STAGE_ITS] += total_execs - orig_execs;

  return 0;

}

