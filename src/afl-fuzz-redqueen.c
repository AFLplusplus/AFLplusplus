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

#include <limits.h>
#include "afl-fuzz.h"
#include "cmplog.h"

//#define _DEBUG

///// Colorization

struct range {

  u32           start;
  u32           end;
  struct range *next;
  struct range *prev;
  u8            ok;

};

static struct range *add_range(struct range *ranges, u32 start, u32 end) {

  struct range *r = ck_alloc_nozero(sizeof(struct range));
  r->start = start;
  r->end = end;
  r->next = ranges;
  r->ok = 0;
  if (likely(ranges)) ranges->prev = r;
  return r;

}

static struct range *pop_biggest_range(struct range **ranges) {

  struct range *r = *ranges;
  struct range *rmax = NULL;
  u32           max_size = 0;

  while (r) {

    if (!r->ok) {

      u32 s = 1 + r->end - r->start;

      if (s >= max_size) {

        max_size = s;
        rmax = r;

      }

    }

    r = r->next;

  }

  return rmax;

}

#ifdef _DEBUG
// static int  logging = 0;
static void dump(char *txt, u8 *buf, u32 len) {

  u32 i;
  fprintf(stderr, "DUMP %s %llx ", txt, hash64(buf, len, 0));
  for (i = 0; i < len; i++)
    fprintf(stderr, "%02x", buf[i]);
  fprintf(stderr, "\n");

}

static void dump_file(char *path, char *name, u32 counter, u8 *buf, u32 len) {

  char fn[4096];
  if (!path) path = ".";
  snprintf(fn, sizeof(fn), "%s/%s%d", path, name, counter);
  int fd = open(fn, O_RDWR | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {

    write(fd, buf, len);
    close(fd);

  }

}

#endif

static u8 get_exec_checksum(afl_state_t *afl, u8 *buf, u32 len, u64 *cksum) {

  if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }

  *cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
  return 0;

}

/* replace everything with different values but stay in the same type */
static void type_replace(afl_state_t *afl, u8 *buf, u32 len) {

  u32 i;
  u8  c;
  for (i = 0; i < len; ++i) {

    // wont help for UTF or non-latin charsets
    do {

      switch (buf[i]) {

        case 'A' ... 'F':
          c = 'A' + rand_below(afl, 1 + 'F' - 'A');
          break;
        case 'a' ... 'f':
          c = 'a' + rand_below(afl, 1 + 'f' - 'a');
          break;
        case '0':
          c = '1';
          break;
        case '1':
          c = '0';
          break;
        case '2' ... '9':
          c = '2' + rand_below(afl, 1 + '9' - '2');
          break;
        case 'G' ... 'Z':
          c = 'G' + rand_below(afl, 1 + 'Z' - 'G');
          break;
        case 'g' ... 'z':
          c = 'g' + rand_below(afl, 1 + 'z' - 'g');
          break;
        case '!' ... '*':
          c = '!' + rand_below(afl, 1 + '*' - '!');
          break;
        case ',' ... '.':
          c = ',' + rand_below(afl, 1 + '.' - ',');
          break;
        case ':' ... '@':
          c = ':' + rand_below(afl, 1 + '@' - ':');
          break;
        case '[' ... '`':
          c = '[' + rand_below(afl, 1 + '`' - '[');
          break;
        case '{' ... '~':
          c = '{' + rand_below(afl, 1 + '~' - '{');
          break;
        case '+':
          c = '/';
          break;
        case '/':
          c = '+';
          break;
        case ' ':
          c = '\t';
          break;
        case '\t':
          c = ' ';
          break;
          /*
                case '\r':
                case '\n':
                  // nothing ...
                  break;
          */
        default:
          c = (buf[i] ^ 0xff);

      }

    } while (c == buf[i]);

    buf[i] = c;

  }

}

static u8 colorization(afl_state_t *afl, u8 *buf, u32 len, u64 exec_cksum,
                       struct tainted **taints) {

  struct range *  ranges = add_range(NULL, 0, len - 1), *rng;
  struct tainted *taint = NULL;
  u8 *            backup = ck_alloc_nozero(len);
  u8 *            changed = ck_alloc_nozero(len);

  u64 orig_hit_cnt, new_hit_cnt;
  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "colorization";
  afl->stage_short = "colorization";
  afl->stage_max = (len << 1);

  afl->stage_cur = 0;
  memcpy(backup, buf, len);
  memcpy(changed, buf, len);
  type_replace(afl, changed, len);

  while ((rng = pop_biggest_range(&ranges)) != NULL &&
         afl->stage_cur < afl->stage_max) {

    u32 s = 1 + rng->end - rng->start;

    memcpy(buf + rng->start, changed + rng->start, s);

    u64 cksum;
    u64 start_us = get_cur_time_us();
    if (unlikely(get_exec_checksum(afl, buf, len, &cksum))) {

      goto checksum_fail;

    }

    u64 stop_us = get_cur_time_us();

    /* Discard if the mutations change the path or if it is too decremental
      in speed - how could the same path have a much different speed
      though ...*/
    if (cksum != exec_cksum ||
        (unlikely(stop_us - start_us > 3 * afl->queue_cur->exec_us) &&
         likely(!afl->fixed_seed))) {

      memcpy(buf + rng->start, backup + rng->start, s);

      if (s > 1) {  // to not add 0 size ranges

        ranges = add_range(ranges, rng->start, rng->start - 1 + s / 2);
        ranges = add_range(ranges, rng->start + s / 2, rng->end);

      }

      if (ranges == rng) {

        ranges = rng->next;
        if (ranges) { ranges->prev = NULL; }

      } else if (rng->next) {

        rng->prev->next = rng->next;
        rng->next->prev = rng->prev;

      } else {

        if (rng->prev) { rng->prev->next = NULL; }

      }

      free(rng);

    } else {

      rng->ok = 1;

    }

    ++afl->stage_cur;

  }

  rng = ranges;
  while (rng) {

    rng = rng->next;

  }

  u32 i = 1;
  u32 positions = 0;
  while (i) {

  restart:
    i = 0;
    struct range *r = NULL;
    u32           pos = (u32)-1;
    rng = ranges;

    while (rng) {

      if (rng->ok == 1 && rng->start < pos) {

        if (taint && taint->pos + taint->len == rng->start) {

          taint->len += (1 + rng->end - rng->start);
          positions += (1 + rng->end - rng->start);
          rng->ok = 2;
          goto restart;

        } else {

          r = rng;
          pos = rng->start;

        }

      }

      rng = rng->next;

    }

    if (r) {

      struct tainted *t = ck_alloc_nozero(sizeof(struct tainted));
      t->pos = r->start;
      t->len = 1 + r->end - r->start;
      positions += (1 + r->end - r->start);
      if (likely(taint)) { taint->prev = t; }
      t->next = taint;
      t->prev = NULL;
      taint = t;
      r->ok = 2;
      i = 1;

    }

  }

  *taints = taint;

  /* temporary: clean ranges */
  while (ranges) {

    rng = ranges;
    ranges = rng->next;
    ck_free(rng);

  }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

#ifdef _DEBUG
  /*
    char fn[4096];
    snprintf(fn, sizeof(fn), "%s/introspection_color.txt", afl->out_dir);
    FILE *f = fopen(fn, "a");
    if (f) {

  */
  FILE *f = stderr;
  fprintf(f,
          "Colorization: fname=%s len=%u result=%u execs=%u found=%llu "
          "taint=%u\n",
          afl->queue_cur->fname, len, afl->queue_cur->colorized, afl->stage_cur,
          new_hit_cnt - orig_hit_cnt, positions);
/*
    fclose(f);

  }

*/
#endif

  afl->stage_finds[STAGE_COLORIZATION] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_COLORIZATION] += afl->stage_cur;
  ck_free(backup);
  ck_free(changed);

  return 0;

checksum_fail:
  ck_free(backup);
  ck_free(changed);

  return 1;

}

///// Input to State replacement

static u8 its_fuzz(afl_state_t *afl, u8 *buf, u32 len, u8 *status) {

  u64 orig_hit_cnt, new_hit_cnt;

  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

#ifdef _DEBUG
  dump("DATA", buf, len);
#endif

  if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;

  if (unlikely(new_hit_cnt != orig_hit_cnt)) {

#ifdef _DEBUG
    fprintf(stderr, "NEW FIND\n");
#endif
    *status = 1;

  } else {

    *status = 2;

  }

  return 0;

}

static int strntoll(const char *str, size_t sz, char **end, int base,
                    long long *out) {

  char        buf[64];
  long long   ret;
  const char *beg = str;

  for (; beg && sz && *beg == ' '; beg++, sz--) {};

  if (!sz) return 1;
  if (sz >= sizeof(buf)) sz = sizeof(buf) - 1;

  memcpy(buf, beg, sz);
  buf[sz] = '\0';
  ret = strtoll(buf, end, base);
  if ((ret == LLONG_MIN || ret == LLONG_MAX) && errno == ERANGE) return 1;
  if (end) *end = (char *)beg + (*end - buf);
  *out = ret;

  return 0;

}

static int strntoull(const char *str, size_t sz, char **end, int base,
                     unsigned long long *out) {

  char               buf[64];
  unsigned long long ret;
  const char *       beg = str;

  for (; beg && sz && *beg == ' '; beg++, sz--)
    ;

  if (!sz) return 1;
  if (sz >= sizeof(buf)) sz = sizeof(buf) - 1;

  memcpy(buf, beg, sz);
  buf[sz] = '\0';
  ret = strtoull(buf, end, base);
  if (ret == ULLONG_MAX && errno == ERANGE) return 1;
  if (end) *end = (char *)beg + (*end - buf);
  *out = ret;

  return 0;

}

static u8 cmp_extend_encoding(afl_state_t *afl, struct cmp_header *h,
                              u64 pattern, u64 repl, u64 o_pattern,
                              u64 changed_val, u8 attr, u32 idx, u32 taint_len,
                              u8 *orig_buf, u8 *buf, u8 *cbuf, u32 len,
                              u8 do_reverse, u8 lvl, u8 *status) {

  //  (void)(changed_val); // TODO
  //  we can use the information in changed_val to see if there is a
  //  computable i2s transformation.
  //  if (pattern != o_pattern && repl != changed_val) {

  //    u64 in_diff = pattern - o_pattern, out_diff = repl - changed_val;
  //    if (in_diff != out_diff) {

  //      switch(in_diff) {

  //        detect uppercase <-> lowercase, base64, hex encoding, etc.:
  //        repl = reverse_transform(TYPE, pattern);
  //      }
  //    }
  //  }
  //  not 100% but would have a chance to be detected

  // fprintf(stderr,
  //         "Encode: %llx->%llx into %llx(<-%llx) at pos=%u "
  //         "taint_len=%u shape=%u attr=%u\n",
  //         o_pattern, pattern, repl, changed_val, idx, taint_len,
  //         h->shape + 1, attr);

  u64 *buf_64 = (u64 *)&buf[idx];
  u32 *buf_32 = (u32 *)&buf[idx];
  u16 *buf_16 = (u16 *)&buf[idx];
  u8 * buf_8 = &buf[idx];
  u64 *o_buf_64 = (u64 *)&orig_buf[idx];
  u32 *o_buf_32 = (u32 *)&orig_buf[idx];
  u16 *o_buf_16 = (u16 *)&orig_buf[idx];
  u8 * o_buf_8 = &orig_buf[idx];

  u32 its_len = MIN(len - idx, taint_len);

  u8 *               endptr;
  u8                 use_num = 0, use_unum = 0;
  unsigned long long unum;
  long long          num;

  // reverse atoi()/strnu?toll() is expensive, so we only to it in lvl == 3
  if (lvl & 4) {

    if (afl->queue_cur->is_ascii) {

      endptr = buf_8;
      if (strntoll(buf_8, len - idx, (char **)&endptr, 0, &num)) {

        if (!strntoull(buf_8, len - idx, (char **)&endptr, 0, &unum))
          use_unum = 1;

      } else

        use_num = 1;

    }

#ifdef _DEBUG
    if (idx == 0)
      fprintf(stderr, "ASCII is=%u use_num=%u use_unum=%u idx=%u %llx==%llx\n",
              afl->queue_cur->is_ascii, use_num, use_unum, idx, num, pattern);
#endif

    // num is likely not pattern as atoi("AAA") will be zero...
    if (use_num && ((u64)num == pattern || !num)) {

      u8     tmp_buf[32];
      size_t num_len = snprintf(tmp_buf, sizeof(tmp_buf), "%lld", repl);
      size_t old_len = endptr - buf_8;

      u8 *new_buf = afl_realloc((void **)&afl->out_scratch_buf, len + num_len);
      if (unlikely(!new_buf)) { PFATAL("alloc"); }

      memcpy(new_buf, buf, idx);
      memcpy(new_buf + idx, tmp_buf, num_len);
      memcpy(new_buf + idx + num_len, buf_8 + old_len, len - idx - old_len);

      if (new_buf[idx + num_len] >= '0' && new_buf[idx + num_len] <= '9') {

        new_buf[idx + num_len] = ' ';

      }

      if (unlikely(its_fuzz(afl, new_buf, len, status))) { return 1; }

    } else if (use_unum && (unum == pattern || !unum)) {

      u8     tmp_buf[32];
      size_t num_len = snprintf(tmp_buf, sizeof(tmp_buf), "%llu", repl);
      size_t old_len = endptr - buf_8;

      u8 *new_buf = afl_realloc((void **)&afl->out_scratch_buf, len + num_len);
      if (unlikely(!new_buf)) { PFATAL("alloc"); }

      memcpy(new_buf, buf, idx);
      memcpy(new_buf + idx, tmp_buf, num_len);
      memcpy(new_buf + idx + num_len, buf_8 + old_len, len - idx - old_len);

      if (new_buf[idx + num_len] >= '0' && new_buf[idx + num_len] <= '9') {

        new_buf[idx + num_len] = ' ';

      }

      if (unlikely(its_fuzz(afl, new_buf, len, status))) { return 1; }

    }

  }

  // we only allow this for ascii2integer (above)
  if (unlikely(pattern == o_pattern)) { return 0; }

  if ((lvl & 1) || ((lvl & 2) && (attr >= 8 && attr <= 15)) || attr >= 16) {

    if (SHAPE_BYTES(h->shape) >= 8 && *status != 1) {

      // if (its_len >= 8 && (attr == 0 || attr >= 8))
      // fprintf(stderr,
      //         "TestU64: %u>=4 %x==%llx"
      //         " %x==%llx (idx=%u attr=%u) <= %llx<-%llx\n",
      //         its_len, *buf_32, pattern, *o_buf_32, o_pattern, idx, attr,
      //         repl, changed_val);

      // if this is an fcmp (attr & 8 == 8) then do not compare the patterns -
      // due to a bug in llvm dynamic float bitcasts do not work :(
      // the value 16 means this is a +- 1.0 test case
      if (its_len >= 8 &&
          ((*buf_64 == pattern && *o_buf_64 == o_pattern) || attr >= 16)) {

        u64 tmp_64 = *buf_64;
        *buf_64 = repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        if (*status == 1) { memcpy(cbuf + idx, buf_64, 8); }
        *buf_64 = tmp_64;

        // fprintf(stderr, "Status=%u\n", *status);

      }

      // reverse encoding
      if (do_reverse && *status != 1) {

        if (unlikely(cmp_extend_encoding(afl, h, SWAP64(pattern), SWAP64(repl),
                                         SWAP64(o_pattern), SWAP64(changed_val),
                                         attr, idx, taint_len, orig_buf, buf,
                                         cbuf, len, 0, lvl, status))) {

          return 1;

        }

      }

    }

    if (SHAPE_BYTES(h->shape) >= 4 && *status != 1) {

      // if (its_len >= 4 && (attr <= 1 || attr >= 8))
      // fprintf(stderr,
      //         "TestU32: %u>=4 %x==%llx"
      //         " %x==%llx (idx=%u attr=%u) <= %llx<-%llx\n",
      //         its_len, *buf_32, pattern, *o_buf_32, o_pattern, idx, attr,
      //         repl, changed_val);

      if (its_len >= 4 &&
          ((*buf_32 == (u32)pattern && *o_buf_32 == (u32)o_pattern) ||
           attr >= 16)) {

        u32 tmp_32 = *buf_32;
        *buf_32 = (u32)repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        if (*status == 1) { memcpy(cbuf + idx, buf_32, 4); }
        *buf_32 = tmp_32;

        // fprintf(stderr, "Status=%u\n", *status);

      }

      // reverse encoding
      if (do_reverse && *status != 1) {

        if (unlikely(cmp_extend_encoding(afl, h, SWAP32(pattern), SWAP32(repl),
                                         SWAP32(o_pattern), SWAP32(changed_val),
                                         attr, idx, taint_len, orig_buf, buf,
                                         cbuf, len, 0, lvl, status))) {

          return 1;

        }

      }

    }

    if (SHAPE_BYTES(h->shape) >= 2 && *status != 1) {

      if (its_len >= 2 &&
          ((*buf_16 == (u16)pattern && *o_buf_16 == (u16)o_pattern) ||
           attr >= 16)) {

        u16 tmp_16 = *buf_16;
        *buf_16 = (u16)repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        if (*status == 1) { memcpy(cbuf + idx, buf_16, 2); }
        *buf_16 = tmp_16;

      }

      // reverse encoding
      if (do_reverse && *status != 1) {

        if (unlikely(cmp_extend_encoding(afl, h, SWAP16(pattern), SWAP16(repl),
                                         SWAP16(o_pattern), SWAP16(changed_val),
                                         attr, idx, taint_len, orig_buf, buf,
                                         cbuf, len, 0, lvl, status))) {

          return 1;

        }

      }

    }

    if (*status != 1) {  // u8

      // if (its_len >= 1 && (attr <= 1 || attr >= 8))
      // fprintf(stderr,
      //         "TestU8: %u>=1 %x==%x %x==%x (idx=%u attr=%u) <= %x<-%x\n",
      //         its_len, *buf_8, pattern, *o_buf_8, o_pattern, idx, attr,
      //         repl, changed_val);

      if (its_len >= 1 &&
          ((*buf_8 == (u8)pattern && *o_buf_8 == (u8)o_pattern) ||
           attr >= 16)) {

        u8 tmp_8 = *buf_8;
        *buf_8 = (u8)repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        if (*status == 1) { cbuf[idx] = *buf_8; }
        *buf_8 = tmp_8;

      }

    }

  }

  // here we add and subract 1 from the value, but only if it is not an
  // == or != comparison
  // Bits: 1 = Equal, 2 = Greater, 3 = Lesser, 4 = Float

  if (lvl < 4) { return 0; }

  if (attr >= 8 && attr < 16) {  // lesser/greater integer comparison

    u64 repl_new;
    if (SHAPE_BYTES(h->shape) == 4 && its_len >= 4) {

      float *f = (float *)&repl;
      float  g = *f;
      g += 1.0;
      u32 *r = (u32 *)&g;
      repl_new = (u32)*r;

    } else if (SHAPE_BYTES(h->shape) == 8 && its_len >= 8) {

      double *f = (double *)&repl;
      double  g = *f;
      g += 1.0;

      u64 *r = (u64 *)&g;
      repl_new = *r;

    } else {

      return 0;

    }

    changed_val = repl_new;

    if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                     changed_val, 16, idx, taint_len, orig_buf,
                                     buf, cbuf, len, 1, lvl, status))) {

      return 1;

    }

    if (SHAPE_BYTES(h->shape) == 4) {

      float *f = (float *)&repl;
      float  g = *f;
      g -= 1.0;
      u32 *r = (u32 *)&g;
      repl_new = (u32)*r;

    } else if (SHAPE_BYTES(h->shape) == 8) {

      double *f = (double *)&repl;
      double  g = *f;
      g -= 1.0;
      u64 *r = (u64 *)&g;
      repl_new = *r;

    } else {

      return 0;

    }

    changed_val = repl_new;

    if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                     changed_val, 16, idx, taint_len, orig_buf,
                                     buf, cbuf, len, 1, lvl, status))) {

      return 1;

    }

    // transform double to float, llvm likes to do that internally ...
    if (SHAPE_BYTES(h->shape) == 8 && its_len >= 4) {

      double *f = (double *)&repl;
      float   g = (float)*f;
      repl_new = 0;
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
      memcpy((char *)&repl_new, (char *)&g, 4);
#else
      memcpy(((char *)&repl_new) + 4, (char *)&g, 4);
#endif
      changed_val = repl_new;
      h->shape = 3;  // modify shape

      // fprintf(stderr, "DOUBLE2FLOAT %llx\n", repl_new);

      if (unlikely(cmp_extend_encoding(
              afl, h, pattern, repl_new, o_pattern, changed_val, 16, idx,
              taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

        h->shape = 7;
        return 1;

      }

      h->shape = 7;  // recover shape

    }

  } else if (attr > 1 && attr < 8) {  // lesser/greater integer comparison

    u64 repl_new;

    repl_new = repl + 1;
    changed_val = repl_new;
    if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                     changed_val, 32, idx, taint_len, orig_buf,
                                     buf, cbuf, len, 1, lvl, status))) {

      return 1;

    }

    repl_new = repl - 1;
    changed_val = repl_new;
    if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                     changed_val, 32, idx, taint_len, orig_buf,
                                     buf, cbuf, len, 1, lvl, status))) {

      return 1;

    }

  }

  return 0;

}

static u8 cmp_extend_encoding128(afl_state_t *afl, struct cmp_header *h,
                                 u128 pattern, u128 repl, u128 o_pattern,
                                 u128 changed_val, u8 attr, u32 idx,
                                 u32 taint_len, u8 *orig_buf, u8 *buf, u8 *cbuf,
                                 u32 len, u8 do_reverse, u8 lvl, u8 *status) {

  u128 *buf_128 = (u128 *)&buf[idx];
  u64 * buf0 = (u64 *)&buf[idx];
  u64 * buf1 = (u64 *)(buf + idx + 8);
  u128 *o_buf_128 = (u128 *)&orig_buf[idx];
  u32   its_len = MIN(len - idx, taint_len);
  u64   v10 = (u64)repl;
  u64   v11 = (u64)(repl >> 64);

  // if this is an fcmp (attr & 8 == 8) then do not compare the patterns -
  // due to a bug in llvm dynamic float bitcasts do not work :(
  // the value 16 means this is a +- 1.0 test case
  if (its_len >= 16) {

#ifdef _DEBUG
    fprintf(stderr, "TestU128: %u>=16 (idx=%u attr=%u) (%u)\n", its_len, idx,
            attr, do_reverse);
    u64 v00 = (u64)pattern;
    u64 v01 = pattern >> 64;
    u64 ov00 = (u64)o_pattern;
    u64 ov01 = o_pattern >> 64;
    u64 ov10 = (u64)changed_val;
    u64 ov11 = changed_val >> 64;
    u64 b00 = (u64)*buf_128;
    u64 b01 = *buf_128 >> 64;
    u64 ob00 = (u64)*o_buf_128;
    u64 ob01 = *o_buf_128 >> 64;
    fprintf(stderr,
            "TestU128: %llx:%llx==%llx:%llx"
            " %llx:%llx==%llx:%llx <= %llx:%llx<-%llx:%llx\n",
            b01, b00, v01, v00, ob01, ob00, ov01, ov00, v11, v10, ov11, ov10);
#endif

    if (*buf_128 == pattern && *o_buf_128 == o_pattern) {

      u128 tmp_128 = *buf_128;
      // *buf_128 = repl; <- this crashes
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
      *buf0 = v10;
      *buf1 = v11;
#else
      *buf1 = v10;
      *buf0 = v11;
#endif
      if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
      if (*status == 1) { memcpy(cbuf + idx, buf_128, 16); }
      *buf_128 = tmp_128;

#ifdef _DEBUG
      fprintf(stderr, "Status=%u\n", *status);
#endif

    }

    // reverse encoding
    if (do_reverse && *status != 1) {

      if (unlikely(cmp_extend_encoding128(
              afl, h, SWAPN(pattern, 128), SWAPN(repl, 128),
              SWAPN(o_pattern, 128), SWAPN(changed_val, 128), attr, idx,
              taint_len, orig_buf, buf, cbuf, len, 0, lvl, status))) {

        return 1;

      }

    }

  }

  return 0;

}

// uh a pointer read from (long double*) reads 12 bytes, not 10 ...
// so lets make this complicated.
static u8 cmp_extend_encoding_ld(afl_state_t *afl, struct cmp_header *h,
                                 u8 *pattern, u8 *repl, u8 *o_pattern,
                                 u8 *changed_val, u8 attr, u32 idx,
                                 u32 taint_len, u8 *orig_buf, u8 *buf, u8 *cbuf,
                                 u32 len, u8 do_reverse, u8 lvl, u8 *status) {

  u8 *buf_ld = &buf[idx], *o_buf_ld = &orig_buf[idx], backup[10];
  u32 its_len = MIN(len - idx, taint_len);

  if (its_len >= 10) {

#ifdef _DEBUG
    fprintf(stderr, "TestUld: %u>=10 (len=%u idx=%u attr=%u) (%u)\n", its_len,
            len, idx, attr, do_reverse);
    fprintf(stderr, "TestUld: ");
    u32 i;
    for (i = 0; i < 10; i++)
      fprintf(stderr, "%02x", pattern[i]);
    fprintf(stderr, "==");
    for (i = 0; i < 10; i++)
      fprintf(stderr, "%02x", buf_ld[i]);
    fprintf(stderr, " ");
    for (i = 0; i < 10; i++)
      fprintf(stderr, "%02x", o_pattern[i]);
    fprintf(stderr, "==");
    for (i = 0; i < 10; i++)
      fprintf(stderr, "%02x", o_buf_ld[i]);
    fprintf(stderr, " <= ");
    for (i = 0; i < 10; i++)
      fprintf(stderr, "%02x", repl[i]);
    fprintf(stderr, "==");
    for (i = 0; i < 10; i++)
      fprintf(stderr, "%02x", changed_val[i]);
    fprintf(stderr, "\n");
#endif

    if (!memcmp(pattern, buf_ld, 10) && !memcmp(o_pattern, o_buf_ld, 10)) {

      // if this is an fcmp (attr & 8 == 8) then do not compare the patterns -
      // due to a bug in llvm dynamic float bitcasts do not work :(
      // the value 16 means this is a +- 1.0 test case

      memcpy(backup, buf_ld, 10);
      memcpy(buf_ld, repl, 10);
      if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
      if (*status == 1) { memcpy(cbuf + idx, repl, 10); }
      memcpy(buf_ld, backup, 10);

#ifdef _DEBUG
      fprintf(stderr, "Status=%u\n", *status);
#endif

    }

  }

  // reverse encoding
  if (do_reverse && *status != 1) {

    u8 sp[10], sr[10], osp[10], osr[10];
    SWAPNN(sp, pattern, 10);
    SWAPNN(sr, repl, 10);
    SWAPNN(osp, o_pattern, 10);
    SWAPNN(osr, changed_val, 10);

    if (unlikely(cmp_extend_encoding_ld(afl, h, sp, sr, osp, osr, attr, idx,
                                        taint_len, orig_buf, buf, cbuf, len, 0,
                                        lvl, status))) {

      return 1;

    }

  }

  return 0;

}

static void try_to_add_to_dict(afl_state_t *afl, u64 v, u8 shape) {

  u8 *b = (u8 *)&v;

  u32 k;
  u8  cons_ff = 0, cons_0 = 0;
  for (k = 0; k < shape; ++k) {

    if (b[k] == 0) {

      ++cons_0;

    } else if (b[k] == 0xff) {

      ++cons_0;

    } else {

      cons_0 = cons_ff = 0;

    }

    if (cons_0 > 1 || cons_ff > 1) { return; }

  }

  maybe_add_auto(afl, (u8 *)&v, shape);

  u64 rev;
  switch (shape) {

    case 1:
      break;
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

static void try_to_add_to_dict128(afl_state_t *afl, u128 v) {

  u8 *b = (u8 *)&v;

  u32 k;
  u8  cons_ff = 0, cons_0 = 0;
  for (k = 0; k < 16; ++k) {

    if (b[k] == 0) {

      ++cons_0;

    } else if (b[k] == 0xff) {

      ++cons_0;

    } else {

      cons_0 = cons_ff = 0;

    }

    // too many uninteresting values? try adding 2 64-bit values
    if (cons_0 > 6 || cons_ff > 6) {

      u64 v64 = (u64)v;
      try_to_add_to_dict(afl, v64, 8);
      v64 = (u64)(v >> 64);
      try_to_add_to_dict(afl, v64, 8);

      return;

    }

  }

  maybe_add_auto(afl, (u8 *)&v, 16);
  u128 rev = SWAPN(v, 128);
  maybe_add_auto(afl, (u8 *)&rev, 16);

}

static void try_to_add_to_dictN(afl_state_t *afl, u128 v, u8 size) {

  u8 *b = (u8 *)&v;

  u32 k;
  u8  cons_ff = 0, cons_0 = 0;
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  for (k = 0; k < size; ++k) {

#else
  for (k = 16 - size; k < 16; ++k) {

#endif
    if (b[k] == 0) {

      ++cons_0;

    } else if (b[k] == 0xff) {

      ++cons_0;

    } else {

      cons_0 = cons_ff = 0;

    }

  }

  maybe_add_auto(afl, (u8 *)&v, size);
  u128 rev = SWAPN(v, size);
  maybe_add_auto(afl, (u8 *)&rev, size);

}

static u8 cmp_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u8 *cbuf,
                   u32 len, u32 lvl, struct tainted *taint) {

  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  struct tainted *   t;
  u32                i, j, idx, taint_len;
  u32                have_taint = 1, is_128 = 0, is_n = 0, is_ld = 0;
  u32                loggeds = h->hits;
  if (h->hits > CMP_MAP_H) { loggeds = CMP_MAP_H; }

  u8 status = 0;
  u8 found_one = 0;

  /* loop cmps are useless, detect and ignore them */
  u128        s128_v0 = 0, s128_v1 = 0, orig_s128_v0 = 0, orig_s128_v1 = 0;
  long double ld0, ld1, o_ld0, o_ld1;
  u64         s_v0, s_v1;
  u8          s_v0_fixed = 1, s_v1_fixed = 1;
  u8          s_v0_inc = 1, s_v1_inc = 1;
  u8          s_v0_dec = 1, s_v1_dec = 1;

  switch (SHAPE_BYTES(h->shape)) {

    case 1:
    case 2:
    case 4:
    case 8:
      break;
    case 16:
      is_128 = 1;
      break;
    case 10:
      if (h->attribute & 8) { is_ld = 1; }
      // fall through
    default:
      is_n = 1;

  }

  // FCmp not in if level 1 only
  if ((h->attribute & 8) && lvl < 2) return 0;

  for (i = 0; i < loggeds; ++i) {

    struct cmp_operands *o = &afl->shm.cmp_map->log[key][i];

    // loop detection code
    if (i == 0) {

      s_v0 = o->v0;
      s_v1 = o->v1;

    } else {

      if (s_v0 != o->v0) { s_v0_fixed = 0; }
      if (s_v1 != o->v1) { s_v1_fixed = 0; }
      if (s_v0 + 1 != o->v0) { s_v0_inc = 0; }
      if (s_v1 + 1 != o->v1) { s_v1_inc = 0; }
      if (s_v0 - 1 != o->v0) { s_v0_dec = 0; }
      if (s_v1 - 1 != o->v1) { s_v1_dec = 0; }
      s_v0 = o->v0;
      s_v1 = o->v1;

    }

    struct cmp_operands *orig_o = &afl->orig_cmp_map->log[key][i];

    // opt not in the paper
    for (j = 0; j < i; ++j) {

      if (afl->shm.cmp_map->log[key][j].v0 == o->v0 &&
          afl->shm.cmp_map->log[key][i].v1 == o->v1) {

        goto cmp_fuzz_next_iter;

      }

    }

#ifdef _DEBUG
    fprintf(stderr, "Handling: %llx->%llx vs %llx->%llx attr=%u shape=%u\n",
            orig_o->v0, o->v0, orig_o->v1, o->v1, h->attribute,
            SHAPE_BYTES(h->shape));
#endif

    if (taint) {

      t = taint;

      while (t->next) {

        t = t->next;

      }

    } else {

      have_taint = 0;
      t = NULL;

    }

    if (unlikely(is_128 || is_n)) {

      s128_v0 = ((u128)o->v0) + (((u128)o->v0_128) << 64);
      s128_v1 = ((u128)o->v1) + (((u128)o->v1_128) << 64);
      orig_s128_v0 = ((u128)orig_o->v0) + (((u128)orig_o->v0_128) << 64);
      orig_s128_v1 = ((u128)orig_o->v1) + (((u128)orig_o->v1_128) << 64);

      if (is_ld) {

#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
        memcpy((char *)&ld0, (char *)&s128_v0, sizeof(long double));
        memcpy((char *)&ld1, (char *)&s128_v1, sizeof(long double));
        memcpy((char *)&o_ld0, (char *)&orig_s128_v0, sizeof(long double));
        memcpy((char *)&o_ld1, (char *)&orig_s128_v1, sizeof(long double));
#else
        memcpy((char *)&ld0, (char *)(&s128_v0) + 6, sizeof(long double));
        memcpy((char *)&ld1, (char *)(&s128_v1) + 6, sizeof(long double));
        memcpy((char *)&o_ld0, (char *)(&orig_s128_v0) + 6,
               sizeof(long double));
        memcpy((char *)&o_ld1, (char *)(&orig_s128_v1) + 6,
               sizeof(long double));
#endif

      }

    }

    for (idx = 0; idx < len; ++idx) {

      if (have_taint) {

        if (!t || idx < t->pos) {

          continue;

        } else {

          taint_len = t->pos + t->len - idx;

          if (idx == t->pos + t->len - 1) { t = t->prev; }

        }

      } else {

        taint_len = len - idx;

      }

      status = 0;

      if (is_ld) {  // long double special case

        if (ld0 != o_ld0 && o_ld1 != o_ld0) {

          if (unlikely(cmp_extend_encoding_ld(
                  afl, h, (u8 *)&ld0, (u8 *)&ld1, (u8 *)&o_ld0, (u8 *)&o_ld1,
                  h->attribute, idx, taint_len, orig_buf, buf, cbuf, len, 1,
                  lvl, &status))) {

            return 1;

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }

        if (ld1 != o_ld1 && o_ld0 != o_ld1) {

          if (unlikely(cmp_extend_encoding_ld(
                  afl, h, (u8 *)&ld1, (u8 *)&ld0, (u8 *)&o_ld1, (u8 *)&o_ld0,
                  h->attribute, idx, taint_len, orig_buf, buf, cbuf, len, 1,
                  lvl, &status))) {

            return 1;

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }

      }

      if (is_128) {  // u128 special case

        if (s128_v0 != orig_s128_v0 && orig_s128_v0 != orig_s128_v1) {

          if (unlikely(cmp_extend_encoding128(
                  afl, h, s128_v0, s128_v1, orig_s128_v0, orig_s128_v1,
                  h->attribute, idx, taint_len, orig_buf, buf, cbuf, len, 1,
                  lvl, &status))) {

            return 1;

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }

        if (s128_v1 != orig_s128_v1 && orig_s128_v1 != orig_s128_v0) {

          if (unlikely(cmp_extend_encoding128(
                  afl, h, s128_v1, s128_v0, orig_s128_v1, orig_s128_v0,
                  h->attribute, idx, taint_len, orig_buf, buf, cbuf, len, 1,
                  lvl, &status))) {

            return 1;

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }

      }

      // even for u128 and long double do cmp_extend_encoding() because
      // if we got here their own special trials failed and it might just be
      // a cast from e.g. u64 to u128 from the input data.

      if ((o->v0 != orig_o->v0 || lvl >= 4) && orig_o->v0 != orig_o->v1) {

        if (unlikely(cmp_extend_encoding(
                afl, h, o->v0, o->v1, orig_o->v0, orig_o->v1, h->attribute, idx,
                taint_len, orig_buf, buf, cbuf, len, 1, lvl, &status))) {

          return 1;

        }

      }

      if (status == 1) {

        found_one = 1;
        break;

      }

      status = 0;
      if ((o->v1 != orig_o->v1 || lvl >= 4) && orig_o->v0 != orig_o->v1) {

        if (unlikely(cmp_extend_encoding(
                afl, h, o->v1, o->v0, orig_o->v1, orig_o->v0, h->attribute, idx,
                taint_len, orig_buf, buf, cbuf, len, 1, lvl, &status))) {

          return 1;

        }

      }

      if (status == 1) {

        found_one = 1;
        break;

      }

    }

#ifdef _DEBUG
    fprintf(stderr,
            "END: %llx->%llx vs %llx->%llx attr=%u i=%u found=%u is128=%u "
            "isN=%u size=%u\n",
            orig_o->v0, o->v0, orig_o->v1, o->v1, h->attribute, i, found_one,
            is_128, is_n, SHAPE_BYTES(h->shape));
#endif

    // If failed, add to dictionary
    if (!found_one) {

      if (afl->pass_stats[key].total == 0) {

        if (unlikely(is_128)) {

          try_to_add_to_dict128(afl, s128_v0);
          try_to_add_to_dict128(afl, s128_v1);

        } else if (unlikely(is_n)) {

          try_to_add_to_dictN(afl, s128_v0, SHAPE_BYTES(h->shape));
          try_to_add_to_dictN(afl, s128_v1, SHAPE_BYTES(h->shape));

        } else {

          try_to_add_to_dict(afl, o->v0, SHAPE_BYTES(h->shape));
          try_to_add_to_dict(afl, o->v1, SHAPE_BYTES(h->shape));

        }

      }

    }

  cmp_fuzz_next_iter:
    afl->stage_cur++;

  }

  if (loggeds > 3 && ((s_v0_fixed && s_v1_inc) || (s_v1_fixed && s_v0_inc) ||
                      (s_v0_fixed && s_v1_dec) || (s_v1_fixed && s_v0_dec))) {

    afl->pass_stats[key].total = afl->pass_stats[key].faileds = 0xff;

  }

  if (!found_one && afl->pass_stats[key].faileds < 0xff) {

    afl->pass_stats[key].faileds++;

  }

  if (afl->pass_stats[key].total < 0xff) { afl->pass_stats[key].total++; }

  return 0;

}

static u8 rtn_extend_encoding(afl_state_t *afl, u8 *pattern, u8 *repl,
                              u8 *o_pattern, u32 idx, u32 taint_len,
                              u8 *orig_buf, u8 *buf, u8 *cbuf, u32 len,
                              u8 *status) {

  u32 i;
  u32 its_len = MIN((u32)32, len - idx);
  its_len = MIN(its_len, taint_len);
  u8 save[32];
  memcpy(save, &buf[idx], its_len);

  for (i = 0; i < its_len; ++i) {

    if ((pattern[i] != buf[idx + i] && o_pattern[i] != orig_buf[idx + i]) ||
        *status == 1) {

      break;

    }

    buf[idx + i] = repl[i];

    if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }

    if (*status == 1) { memcpy(cbuf + idx, &buf[idx], i); }

  }

  memcpy(&buf[idx], save, i);
  return 0;

}

static u8 rtn_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u8 *cbuf,
                   u32 len, struct tainted *taint) {

  struct tainted *   t;
  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  u32                i, j, idx, have_taint = 1, taint_len;

  u32 loggeds = h->hits;
  if (h->hits > CMP_MAP_RTN_H) { loggeds = CMP_MAP_RTN_H; }

  u8 status = 0;
  u8 found_one = 0;

  for (i = 0; i < loggeds; ++i) {

    struct cmpfn_operands *o =
        &((struct cmpfn_operands *)afl->shm.cmp_map->log[key])[i];

    struct cmpfn_operands *orig_o =
        &((struct cmpfn_operands *)afl->orig_cmp_map->log[key])[i];

    // opt not in the paper
    for (j = 0; j < i; ++j) {

      if (!memcmp(&((struct cmpfn_operands *)afl->shm.cmp_map->log[key])[j], o,
                  sizeof(struct cmpfn_operands))) {

        goto rtn_fuzz_next_iter;

      }

    }

    if (taint) {

      t = taint;
      while (t->next) {

        t = t->next;

      }

    } else {

      have_taint = 0;
      t = NULL;

    }

    for (idx = 0; idx < len; ++idx) {

      if (have_taint) {

        if (!t || idx < t->pos) {

          continue;

        } else {

          taint_len = t->pos + t->len - idx;

          if (idx == t->pos + t->len - 1) { t = t->prev; }

        }

      } else {

        taint_len = len - idx;

      }

      status = 0;

      if (unlikely(rtn_extend_encoding(afl, o->v0, o->v1, orig_o->v0, idx,
                                       taint_len, orig_buf, buf, cbuf, len,
                                       &status))) {

        return 1;

      }

      if (status == 1) {

        found_one = 1;
        break;

      }

      status = 0;

      if (unlikely(rtn_extend_encoding(afl, o->v1, o->v0, orig_o->v1, idx,
                                       taint_len, orig_buf, buf, cbuf, len,
                                       &status))) {

        return 1;

      }

      if (status == 1) {

        found_one = 1;
        break;

      }

    }

    // If failed, add to dictionary
    if (!found_one) {

      if (unlikely(!afl->pass_stats[key].total)) {

        maybe_add_auto(afl, o->v0, SHAPE_BYTES(h->shape));
        maybe_add_auto(afl, o->v1, SHAPE_BYTES(h->shape));

      }

    }

  rtn_fuzz_next_iter:
    afl->stage_cur++;

  }

  if (!found_one && afl->pass_stats[key].faileds < 0xff) {

    afl->pass_stats[key].faileds++;

  }

  if (afl->pass_stats[key].total < 0xff) { afl->pass_stats[key].total++; }

  return 0;

}

///// Input to State stage

// afl->queue_cur->exec_cksum
u8 input_to_state_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len,
                        u64 exec_cksum) {

  u8 r = 1;
  if (unlikely(!afl->orig_cmp_map)) {

    afl->orig_cmp_map = ck_alloc_nozero(sizeof(struct cmp_map));

  }

  if (unlikely(!afl->pass_stats)) {

    afl->pass_stats = ck_alloc(sizeof(struct afl_pass_stat) * CMP_MAP_W);

  }

  // do it manually, forkserver clear only afl->fsrv.trace_bits
  memset(afl->shm.cmp_map->headers, 0, sizeof(afl->shm.cmp_map->headers));

  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) { return 1; }

  memcpy(afl->orig_cmp_map, afl->shm.cmp_map, sizeof(struct cmp_map));

  struct tainted *taint = NULL;

  if (!afl->queue_cur->taint || !afl->queue_cur->cmplog_colorinput) {

    if (unlikely(colorization(afl, buf, len, exec_cksum, &taint))) { return 1; }

    // no taint? still try, create a dummy to prevent again colorization
    if (!taint) {

      taint = ck_alloc(sizeof(struct tainted));
      taint->len = len;

    }

  } else {

    buf = afl->queue_cur->cmplog_colorinput;
    taint = afl->queue_cur->taint;
    // reget the cmplog information
    if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) { return 1; }

  }

#ifdef _DEBUG
  dump("ORIG", orig_buf, len);
  dump("NEW ", buf, len);
#endif

  struct tainted *t = taint;

  while (t) {

#ifdef _DEBUG
    fprintf(stderr, "T: pos=%u len=%u\n", t->pos, t->len);
#endif
    t = t->next;

  }

  // do it manually, forkserver clear only afl->fsrv.trace_bits
  memset(afl->shm.cmp_map->headers, 0, sizeof(afl->shm.cmp_map->headers));

  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) { return 1; }

  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs = afl->fsrv.total_execs;
  orig_hit_cnt = afl->queued_paths + afl->unique_crashes;

  afl->stage_name = "input-to-state";
  afl->stage_short = "its";
  afl->stage_max = 0;
  afl->stage_cur = 0;

  u32 lvl;
  u32 cmplog_done = afl->queue_cur->colorized;
  u32 cmplog_lvl = afl->cmplog_lvl;
  if (!cmplog_done) {

    lvl = 1;

  } else {

    lvl = 0;

  }

  if (cmplog_lvl >= 2 && cmplog_done < 2) { lvl += 2; }
  if (cmplog_lvl >= 3 && cmplog_done < 3) { lvl += 4; }

  u8 *cbuf = afl_realloc((void **)&afl->in_scratch_buf, len + 128);
  memcpy(cbuf, orig_buf, len);
  u8 *virgin_backup = afl_realloc((void **)&afl->ex_buf, afl->shm.map_size);
  memcpy(virgin_backup, afl->virgin_bits, afl->shm.map_size);

  u32 k;
  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!afl->shm.cmp_map->headers[k].hits) { continue; }

    if (afl->pass_stats[k].faileds == 0xff ||
        afl->pass_stats[k].total == 0xff) {

#ifdef _DEBUG
      fprintf(stderr, "DISABLED %u\n", k);
#endif

      afl->shm.cmp_map->headers[k].hits = 0;  // ignore this cmp

    }

    if (afl->shm.cmp_map->headers[k].type == CMP_TYPE_INS) {

      afl->stage_max +=
          MIN((u32)(afl->shm.cmp_map->headers[k].hits), (u32)CMP_MAP_H);

    } else {

      afl->stage_max +=
          MIN((u32)(afl->shm.cmp_map->headers[k].hits), (u32)CMP_MAP_RTN_H);

    }

  }

  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!afl->shm.cmp_map->headers[k].hits) { continue; }

    if (afl->shm.cmp_map->headers[k].type == CMP_TYPE_INS) {

      if (unlikely(cmp_fuzz(afl, k, orig_buf, buf, cbuf, len, lvl, taint))) {

        goto exit_its;

      }

    } else {

      if (unlikely(rtn_fuzz(afl, k, orig_buf, buf, cbuf, len, taint))) {

        goto exit_its;

      }

    }

  }

  r = 0;

exit_its:

  afl->queue_cur->colorized = afl->cmplog_lvl;
  if (afl->cmplog_lvl == CMPLOG_LVL_MAX) {

    ck_free(afl->queue_cur->cmplog_colorinput);
    t = taint;
    while (taint) {

      t = taint->next;
      ck_free(taint);
      taint = t;

    }

    afl->queue_cur->taint = NULL;

  } else {

    if (!afl->queue_cur->taint) { afl->queue_cur->taint = taint; }

    if (!afl->queue_cur->cmplog_colorinput) {

      afl->queue_cur->cmplog_colorinput = ck_alloc_nozero(len);
      memcpy(afl->queue_cur->cmplog_colorinput, buf, len);
      memcpy(buf, orig_buf, len);

    }

  }

  // copy the current virgin bits so we can recover the information
  u8 *virgin_save = afl_realloc((void **)&afl->eff_buf, afl->shm.map_size);
  memcpy(virgin_save, afl->virgin_bits, afl->shm.map_size);
  // reset virgin bits to the backup previous to redqueen
  memcpy(afl->virgin_bits, virgin_backup, afl->shm.map_size);

  u8 status = 0;
  its_fuzz(afl, cbuf, len, &status);

  // now combine with the saved virgin bits
#ifdef WORD_SIZE_64
  u64 *v = (u64 *)afl->virgin_bits;
  u64 *s = (u64 *)virgin_save;
  u32  i;
  for (i = 0; i < (afl->shm.map_size >> 3); i++) {

    v[i] &= s[i];

  }

#else
  u32 *v = (u64 *)afl->virgin_bits;
  u32 *s = (u64 *)virgin_save;
  u32 i;
  for (i = 0; i < (afl->shm.map_size >> 2); i++) {

    v[i] &= s[i];

  }

#endif

#ifdef _DEBUG
  dump("COMB", cbuf, len);
  if (status == 1) {

    fprintf(stderr, "NEW COMBINED\n");

  } else {

    fprintf(stderr, "NO new combined\n");

  }

#endif

  new_hit_cnt = afl->queued_paths + afl->unique_crashes;
  afl->stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ITS] += afl->fsrv.total_execs - orig_execs;

  return r;

}

