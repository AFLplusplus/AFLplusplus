/*
   american fuzzy lop++ - redqueen implementation on top of cmplog
   ---------------------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#include <limits.h>
#include "afl-fuzz.h"
#include "cmplog.h"

//#define _DEBUG
//#define CMPLOG_INTROSPECTION

// CMP attribute enum
enum {

  IS_EQUAL = 1,    // arithemtic equal comparison
  IS_GREATER = 2,  // arithmetic greater comparison
  IS_LESSER = 4,   // arithmetic lesser comparison
  IS_FP = 8,       // is a floating point, not an integer
  /* --- below are internal settings, not from target cmplog */
  IS_FP_MOD = 16,    // arithemtic changed floating point
  IS_INT_MOD = 32,   // arithmetic changed interger
  IS_TRANSFORM = 64  // transformed integer

};

// add to dictionary enum
// DEFAULT = 1, notTXT = 2, FOUND = 4, notSAME = 8
enum {

  DICT_ADD_NEVER = 0,
  DICT_ADD_NOTFOUND_SAME_TXT = 1,
  DICT_ADD_NOTFOUND_SAME = 3,
  DICT_ADD_FOUND_SAME_TXT = 5,
  DICT_ADD_FOUND_SAME = 7,
  DICT_ADD_NOTFOUND_TXT = 9,
  DICT_ADD_NOTFOUND = 11,
  DICT_ADD_FOUND_TXT = 13,
  DICT_ADD_FOUND = 15,
  DICT_ADD_ANY = DICT_ADD_FOUND

};

// CMPLOG LVL
enum {

  LVL1 = 1,  // Integer solving
  LVL2 = 2,  // unused except for setting the queue entry
  LVL3 = 4   // expensive tranformations

};

#define DICT_ADD_STRATEGY DICT_ADD_FOUND_SAME

struct range {

  u32           start;
  u32           end;
  struct range *next;
  struct range *prev;
  u8            ok;

};

static u32 hshape;
static u64 screen_update;
static u64 last_update;

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
  fprintf(stderr, "DUMP %s %016llx ", txt, hash64(buf, len, HASH_CONST));
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
        case '\r':
          c = '\n';
          break;
        case '\n':
          c = '\r';
          break;
        case 0:
          c = 1;
          break;
        case 1:
          c = 0;
          break;
        case 0xff:
          c = 0;
          break;
        default:
          if (buf[i] < 32) {

            c = (buf[i] ^ 0x1f);

          } else {

            c = (buf[i] ^ 0x7f);  // we keep the highest bit

          }

      }

    } while (c == buf[i]);

    buf[i] = c;

  }

}

static u8 colorization(afl_state_t *afl, u8 *buf, u32 len,
                       struct tainted **taints) {

  struct range   *ranges = add_range(NULL, 0, len - 1), *rng;
  struct tainted *taint = NULL;
  u8             *backup = ck_alloc_nozero(len);
  u8             *changed = ck_alloc_nozero(len);

#if defined(_DEBUG) || defined(CMPLOG_INTROSPECTION)
  u64 start_time = get_cur_time();
#endif

  u64 orig_hit_cnt, new_hit_cnt, exec_cksum;
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_name = "colorization";
  afl->stage_short = "colorization";
  afl->stage_max = (len << 1);
  afl->stage_cur = 0;

  // in colorization we do not classify counts, hence we have to calculate
  // the original checksum.
  if (unlikely(get_exec_checksum(afl, buf, len, &exec_cksum))) {

    goto checksum_fail;

  }

  memcpy(backup, buf, len);
  memcpy(changed, buf, len);
  type_replace(afl, changed, len);

  while ((rng = pop_biggest_range(&ranges)) != NULL &&
         afl->stage_cur < afl->stage_max) {

    u32 s = 1 + rng->end - rng->start;

    memcpy(buf + rng->start, changed + rng->start, s);

    u64 cksum = 0;
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

    if (++afl->stage_cur % screen_update == 0) { show_stats(afl); };

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

  /* temporary: clean ranges */
  while (ranges) {

    rng = ranges;
    ranges = rng->next;
    ck_free(rng);
    rng = NULL;

  }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

#if defined(_DEBUG) || defined(CMPLOG_INTROSPECTION)
  FILE *f = stderr;
  #ifndef _DEBUG
  if (afl->not_on_tty) {

    char fn[4096];
    snprintf(fn, sizeof(fn), "%s/introspection_cmplog.txt", afl->out_dir);
    f = fopen(fn, "a");

  }

  #endif

  if (f) {

    fprintf(
        f,
        "Colorization: fname=%s len=%u ms=%llu result=%u execs=%u found=%llu "
        "taint=%u ascii=%u auto_extra_before=%u\n",
        afl->queue_cur->fname, len, get_cur_time() - start_time,
        afl->queue_cur->colorized, afl->stage_cur, new_hit_cnt - orig_hit_cnt,
        positions, afl->queue_cur->is_ascii ? 1 : 0, afl->a_extras_cnt);

  #ifndef _DEBUG
    if (afl->not_on_tty) { fclose(f); }
  #endif

  }

#endif

  if (taint) {

    if (afl->colorize_success && afl->cmplog_lvl < 3 &&
        (positions > CMPLOG_POSITIONS_MAX && len / positions == 1 &&
         afl->active_items / afl->colorize_success > CMPLOG_CORPUS_PERCENT)) {

#ifdef _DEBUG
      fprintf(stderr, "Colorization unsatisfactory\n");
#endif

      *taints = NULL;

      struct tainted *t;
      while (taint) {

        t = taint->next;
        ck_free(taint);
        taint = t;

      }

    } else {

      *taints = taint;
      ++afl->colorize_success;

    }

  }

  afl->stage_finds[STAGE_COLORIZATION] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_COLORIZATION] += afl->stage_cur;
  ck_free(backup);
  ck_free(changed);

  return 0;

checksum_fail:
  while (ranges) {

    rng = ranges;
    ranges = rng->next;
    ck_free(rng);
    rng = NULL;

  }

  ck_free(backup);
  ck_free(changed);

  return 1;

}

///// Input to State replacement

static u8 its_fuzz(afl_state_t *afl, u8 *buf, u32 len, u8 *status) {

  u64 orig_hit_cnt, new_hit_cnt;

  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

#ifdef _DEBUG
  dump("DATA", buf, len);
#endif

  if (unlikely(common_fuzz_stuff(afl, buf, len))) { return 1; }

  new_hit_cnt = afl->queued_items + afl->saved_crashes;

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

//#ifdef CMPLOG_SOLVE_TRANSFORM
static int strntoll(const char *str, size_t sz, char **end, int base,
                    long long *out) {

  char        buf[64];
  long long   ret;
  const char *beg = str;

  if (!str || !sz) { return 1; }

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
  const char        *beg = str;

  if (!str || !sz) { return 1; }

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

static u8 hex_table_up[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                              '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
static u8 hex_table_low[16] = {'0', '1', '2', '3', '4', '5', '6', '7',
                               '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
static u8 hex_table[] = {0, 1, 2, 3,  4,  5,  6,  7,  8,  9,  0,  0,  0, 0,
                         0, 0, 0, 10, 11, 12, 13, 14, 15, 0,  0,  0,  0, 0,
                         0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 0,
                         0, 0, 0, 0,  0,  0,  0,  10, 11, 12, 13, 14, 15};

// tests 2 bytes at location
static int is_hex(const char *str) {

  u32 i;

  for (i = 0; i < 2; i++) {

    switch (str[i]) {

      case '0' ... '9':
      case 'A' ... 'F':
      case 'a' ... 'f':
        break;
      default:
        return 0;

    }

  }

  return 1;

}

#ifdef CMPLOG_SOLVE_TRANSFORM_BASE64
// tests 4 bytes at location
static int is_base64(const char *str) {

  u32 i;

  for (i = 0; i < 4; i++) {

    switch (str[i]) {

      case '0' ... '9':
      case 'A' ... 'Z':
      case 'a' ... 'z':
      case '+':
      case '/':
      case '=':
        break;
      default:
        return 0;

    }

  }

  return 1;

}

static u8 base64_encode_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static u8 base64_decode_table[] = {

    62, 0,  0,  0,  63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0,
    0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
    10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    0,  0,  0,  0,  0,  0,  26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
    36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51};

static u32 from_base64(u8 *src, u8 *dst, u32 dst_len) {

  u32 i, j, v;
  u32 len = ((dst_len / 3) << 2);
  u32 ret = 0;

  for (i = 0, j = 0; i < len; i += 4, j += 3) {

    v = base64_decode_table[src[i] - 43];
    v = (v << 6) | base64_decode_table[src[i + 1] - 43];
    v = src[i + 2] == '=' ? v << 6
                          : (v << 6) | base64_decode_table[src[i + 2] - 43];
    v = src[i + 3] == '=' ? v << 6
                          : (v << 6) | base64_decode_table[src[i + 3] - 43];

    dst[j] = (v >> 16) & 0xFF;
    ++ret;

    if (src[i + 2] != '=') {

      dst[j + 1] = (v >> 8) & 0xFF;
      ++ret;

    }

    if (src[i + 3] != '=') {

      dst[j + 2] = v & 0xFF;
      ++ret;

    }

  }

  return ret;

}

static void to_base64(u8 *src, u8 *dst, u32 dst_len) {

  u32 i, j, v;
  u32 len = (dst_len >> 2) * 3;

  for (i = 0, j = 0; i < len; i += 3, j += 4) {

    v = src[i];
    v = i + 1 < len ? v << 8 | src[i + 1] : v << 8;
    v = i + 2 < len ? v << 8 | src[i + 2] : v << 8;

    dst[j] = base64_encode_table[(v >> 18) & 0x3F];
    dst[j + 1] = base64_encode_table[(v >> 12) & 0x3F];
    if (i + 1 < len) {

      dst[j + 2] = base64_encode_table[(v >> 6) & 0x3F];

    } else {

      dst[j + 2] = '=';

    }

    if (i + 2 < len) {

      dst[j + 3] = base64_encode_table[v & 0x3F];

    } else {

      dst[j + 3] = '=';

    }

  }

}

#endif

//#endif

static u8 cmp_extend_encoding(afl_state_t *afl, struct cmp_header *h,
                              u64 pattern, u64 repl, u64 o_pattern,
                              u64 changed_val, u8 attr, u32 idx, u32 taint_len,
                              u8 *orig_buf, u8 *buf, u8 *cbuf, u32 len,
                              u8 do_reverse, u8 lvl, u8 *status) {

  u64 *buf_64 = (u64 *)&buf[idx];
  u32 *buf_32 = (u32 *)&buf[idx];
  u16 *buf_16 = (u16 *)&buf[idx];
  u8  *buf_8 = &buf[idx];
  u64 *o_buf_64 = (u64 *)&orig_buf[idx];
  u32 *o_buf_32 = (u32 *)&orig_buf[idx];
  u16 *o_buf_16 = (u16 *)&orig_buf[idx];
  u8  *o_buf_8 = &orig_buf[idx];

  u32 its_len = MIN(len - idx, taint_len);

  if (afl->fsrv.total_execs - last_update > screen_update) {

    show_stats(afl);
    last_update = afl->fsrv.total_execs;

  }

  // fprintf(stderr,
  //         "Encode: %llx->%llx into %llx(<-%llx) at idx=%u "
  //         "taint_len=%u shape=%u attr=%u\n",
  //         o_pattern, pattern, repl, changed_val, idx, taint_len,
  //         hshape, attr);

  //#ifdef CMPLOG_SOLVE_TRANSFORM
  // reverse atoi()/strnu?toll() is expensive, so we only to it in lvl 3
  if (afl->cmplog_enable_transform && (lvl & LVL3)) {

    u8                *endptr;
    u8                 use_num = 0, use_unum = 0;
    unsigned long long unum;
    long long          num;

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

    // Try to identify transform magic
    if (pattern != o_pattern && repl == changed_val && attr <= IS_EQUAL) {

      u64 b_val, o_b_val, mask;
      u8  bytes;

      switch (hshape) {

        case 0:
        case 1:
          bytes = 1;
          break;
        case 2:
          bytes = 2;
          break;
        case 3:
        case 4:
          bytes = 4;
          break;
        default:
          bytes = 8;

      }

      // necessary for preventing heap access overflow
      bytes = MIN(bytes, len - idx);

      switch (bytes) {

        case 0:                        // cannot happen
          b_val = o_b_val = mask = 0;  // keep the linters happy
          break;
        case 1: {

          u8 *ptr = (u8 *)&buf[idx];
          u8 *o_ptr = (u8 *)&orig_buf[idx];
          b_val = (u64)(*ptr);
          o_b_val = (u64)(*o_ptr % 0x100);
          mask = 0xff;
          break;

        }

        case 2:
        case 3: {

          u16 *ptr = (u16 *)&buf[idx];
          u16 *o_ptr = (u16 *)&orig_buf[idx];
          b_val = (u64)(*ptr);
          o_b_val = (u64)(*o_ptr);
          mask = 0xffff;
          break;

        }

        case 4:
        case 5:
        case 6:
        case 7: {

          u32 *ptr = (u32 *)&buf[idx];
          u32 *o_ptr = (u32 *)&orig_buf[idx];
          b_val = (u64)(*ptr);
          o_b_val = (u64)(*o_ptr);
          mask = 0xffffffff;
          break;

        }

        default: {

          u64 *ptr = (u64 *)&buf[idx];
          u64 *o_ptr = (u64 *)&orig_buf[idx];
          b_val = (u64)(*ptr);
          o_b_val = (u64)(*o_ptr);
          mask = 0xffffffffffffffff;

        }

      }

      // test for arithmetic, eg. "if ((user_val - 0x1111) == 0x1234) ..."
      s64 diff = pattern - b_val;
      s64 o_diff = o_pattern - o_b_val;
      /* fprintf(stderr, "DIFF1 idx=%03u shape=%02u %llx-%llx=%lx\n", idx,
                 hshape, o_pattern, o_b_val, o_diff);
         fprintf(stderr, "DIFF1 %016llx %llx-%llx=%lx\n", repl, pattern,
                 b_val, diff); */
      if (diff == o_diff && diff) {

        // this could be an arithmetic transformation

        u64 new_repl = (u64)((s64)repl - diff);
        // fprintf(stderr, "SAME DIFF %llx->%llx\n", repl, new_repl);

        if (unlikely(cmp_extend_encoding(
                afl, h, pattern, new_repl, o_pattern, repl, IS_TRANSFORM, idx,
                taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

          return 1;

        }

        // if (*status == 1) { fprintf(stderr, "FOUND!\n"); }

      }

      // test for XOR, eg. "if ((user_val ^ 0xabcd) == 0x1234) ..."
      if (*status != 1) {

        diff = pattern ^ b_val;
        s64 o_diff = o_pattern ^ o_b_val;

        /* fprintf(stderr, "DIFF2 idx=%03u shape=%02u %llx-%llx=%lx\n",
                   idx, hshape, o_pattern, o_b_val, o_diff);
           fprintf(stderr,
                   "DIFF2 %016llx %llx-%llx=%lx\n", repl, pattern, b_val, diff);
        */
        if (diff == o_diff && diff) {

          // this could be a XOR transformation

          u64 new_repl = (u64)((s64)repl ^ diff);
          // fprintf(stderr, "SAME DIFF %llx->%llx\n", repl, new_repl);

          if (unlikely(cmp_extend_encoding(
                  afl, h, pattern, new_repl, o_pattern, repl, IS_TRANSFORM, idx,
                  taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

            return 1;

          }

          // if (*status == 1) { fprintf(stderr, "FOUND!\n"); }

        }

      }

      // test for to lowercase, eg. "new_val = (user_val | 0x2020) ..."
      if (*status != 1) {

        if ((b_val | (0x2020202020202020 & mask)) == (pattern & mask)) {

          diff = 1;

        } else {

          diff = 0;

        }

        if ((o_b_val | (0x2020202020202020 & mask)) == (o_pattern & mask)) {

          o_diff = 1;

        } else {

          diff = 0;

        }

        /* fprintf(stderr, "DIFF3 idx=%03u shape=%02u %llx-%llx=%lx\n",
                   idx, hshape, o_pattern, o_b_val, o_diff);
           fprintf(stderr,
                   "DIFF3 %016llx %llx-%llx=%lx\n", repl, pattern, b_val, diff);
        */
        if (o_diff && diff) {

          // this could be a lower to upper

          u64 new_repl = (repl & (0x5f5f5f5f5f5f5f5f & mask));
          // fprintf(stderr, "SAME DIFF %llx->%llx\n", repl, new_repl);

          if (unlikely(cmp_extend_encoding(
                  afl, h, pattern, new_repl, o_pattern, repl, IS_TRANSFORM, idx,
                  taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

            return 1;

          }

          // if (*status == 1) { fprintf(stderr, "FOUND!\n"); }

        }

      }

      // test for to uppercase, eg. "new_val = (user_val | 0x5f5f) ..."
      if (*status != 1) {

        if ((b_val & (0x5f5f5f5f5f5f5f5f & mask)) == (pattern & mask)) {

          diff = 1;

        } else {

          diff = 0;

        }

        if ((o_b_val & (0x5f5f5f5f5f5f5f5f & mask)) == (o_pattern & mask)) {

          o_diff = 1;

        } else {

          o_diff = 0;

        }

        /* fprintf(stderr, "DIFF4 idx=%03u shape=%02u %llx-%llx=%lx\n",
                   idx, hshape, o_pattern, o_b_val, o_diff);
           fprintf(stderr,
                   "DIFF4 %016llx %llx-%llx=%lx\n", repl, pattern, b_val, diff);
        */
        if (o_diff && diff) {

          // this could be a lower to upper

          u64 new_repl = (repl | (0x2020202020202020 & mask));
          // fprintf(stderr, "SAME DIFF %llx->%llx\n", repl, new_repl);

          if (unlikely(cmp_extend_encoding(
                  afl, h, pattern, new_repl, o_pattern, repl, IS_TRANSFORM, idx,
                  taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

            return 1;

          }

          // if (*status == 1) { fprintf(stderr, "FOUND!\n"); }

        }

      }

      *status = 0;

    }

  }

  //#endif

  // we only allow this for ascii2integer (above) so leave if this is the case
  if (unlikely(pattern == o_pattern)) { return 0; }

  if ((lvl & LVL1) || attr >= IS_FP_MOD) {

    if (hshape >= 8 && *status != 1) {

      // if (its_len >= 8)
      //   fprintf(stderr,
      //           "TestU64: %u>=8 (idx=%u attr=%u) %llx==%llx"
      //           " %llx==%llx <= %llx<-%llx\n",
      //           its_len, idx, attr, *buf_64, pattern, *o_buf_64, o_pattern,
      //           repl, changed_val);

      // if this is an fcmp (attr & 8 == 8) then do not compare the patterns -
      // due to a bug in llvm dynamic float bitcasts do not work :(
      // the value 16 means this is a +- 1.0 test case
      if (its_len >= 8 && ((*buf_64 == pattern && *o_buf_64 == o_pattern) ||
                           attr >= IS_FP_MOD)) {

        u64 tmp_64 = *buf_64;
        *buf_64 = repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, buf_64, 8); }
#endif
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

    if (hshape >= 4 && *status != 1) {

      // if (its_len >= 4 && (attr <= 1 || attr >= 8))
      //   fprintf(stderr,
      //           "TestU32: %u>=4 (idx=%u attr=%u) %x==%x"
      //           " %x==%x <= %x<-%x\n",
      //           its_len, idx, attr, *buf_32, (u32)pattern, *o_buf_32,
      //           (u32)o_pattern, (u32)repl, (u32)changed_val);

      if (its_len >= 4 &&
          ((*buf_32 == (u32)pattern && *o_buf_32 == (u32)o_pattern) ||
           attr >= IS_FP_MOD)) {

        u32 tmp_32 = *buf_32;
        *buf_32 = (u32)repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, buf_32, 4); }
#endif
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

    if (hshape >= 2 && *status != 1) {

      if (its_len >= 2 &&
          ((*buf_16 == (u16)pattern && *o_buf_16 == (u16)o_pattern) ||
           attr >= IS_FP_MOD)) {

        u16 tmp_16 = *buf_16;
        *buf_16 = (u16)repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, buf_16, 2); }
#endif
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

      // if (its_len >= 1)
      //   fprintf(stderr,
      //           "TestU8: %u>=1 (idx=%u attr=%u) %x==%x %x==%x <= %x<-%x\n",
      //           its_len, idx, attr, *buf_8, (u8)pattern, *o_buf_8,
      //           (u8)o_pattern, (u8)repl, (u8)changed_val);

      if (its_len >= 1 &&
          ((*buf_8 == (u8)pattern && *o_buf_8 == (u8)o_pattern) ||
           attr >= IS_FP_MOD)) {

        u8 tmp_8 = *buf_8;
        *buf_8 = (u8)repl;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { cbuf[idx] = *buf_8; }
#endif
        *buf_8 = tmp_8;

      }

    }

  }

  // here we add and subract 1 from the value, but only if it is not an
  // == or != comparison
  // Bits: 1 = Equal, 2 = Greater, 4 = Lesser, 8 = Float
  //       16 = modified float, 32 = modified integer (modified = wont match
  //                                                   in original buffer)

  //#ifdef CMPLOG_SOLVE_ARITHMETIC
  if (!afl->cmplog_enable_arith || lvl < LVL3 || attr == IS_TRANSFORM) {

    return 0;

  }

  if (!(attr & (IS_GREATER | IS_LESSER)) || hshape < 4) { return 0; }

  // transform >= to < and <= to >
  if ((attr & IS_EQUAL) && (attr & (IS_GREATER | IS_LESSER))) {

    if (attr & 2) {

      attr += 2;

    } else {

      attr -= 2;

    }

  }

  // lesser/greater FP comparison
  if (attr >= IS_FP && attr < IS_FP_MOD) {

    u64 repl_new;

    if (attr & IS_GREATER) {

      if (hshape == 4 && its_len >= 4) {

        float *f = (float *)&repl;
        float  g = *f;
        g += 1.0;
        u32 *r = (u32 *)&g;
        repl_new = (u32)*r;

      } else if (hshape == 8 && its_len >= 8) {

        double *f = (double *)&repl;
        double  g = *f;
        g += 1.0;

        u64 *r = (u64 *)&g;
        repl_new = *r;

      } else {

        return 0;

      }

      changed_val = repl_new;

      if (unlikely(cmp_extend_encoding(
              afl, h, pattern, repl_new, o_pattern, changed_val, 16, idx,
              taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

        return 1;

      }

    } else {

      if (hshape == 4) {

        float *f = (float *)&repl;
        float  g = *f;
        g -= 1.0;
        u32 *r = (u32 *)&g;
        repl_new = (u32)*r;

      } else if (hshape == 8) {

        double *f = (double *)&repl;
        double  g = *f;
        g -= 1.0;
        u64 *r = (u64 *)&g;
        repl_new = *r;

      } else {

        return 0;

      }

      changed_val = repl_new;

      if (unlikely(cmp_extend_encoding(
              afl, h, pattern, repl_new, o_pattern, changed_val, 16, idx,
              taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

        return 1;

      }

    }

    // transform double to float, llvm likes to do that internally ...
    if (hshape == 8 && its_len >= 4) {

      double *f = (double *)&repl;
      float   g = (float)*f;
      repl_new = 0;
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
      memcpy((char *)&repl_new, (char *)&g, 4);
#else
      memcpy(((char *)&repl_new) + 4, (char *)&g, 4);
#endif
      changed_val = repl_new;
      hshape = 4;  // modify shape

      // fprintf(stderr, "DOUBLE2FLOAT %llx\n", repl_new);

      if (unlikely(cmp_extend_encoding(
              afl, h, pattern, repl_new, o_pattern, changed_val, 16, idx,
              taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

        hshape = 8;  // recover shape
        return 1;

      }

      hshape = 8;  // recover shape

    }

  }

  else if (attr < IS_FP) {

    // lesser/greater integer comparison

    u64 repl_new;

    if (attr & IS_GREATER) {

      repl_new = repl + 1;
      changed_val = repl_new;
      if (unlikely(cmp_extend_encoding(
              afl, h, pattern, repl_new, o_pattern, changed_val, 32, idx,
              taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

        return 1;

      }

    } else {

      repl_new = repl - 1;
      changed_val = repl_new;
      if (unlikely(cmp_extend_encoding(
              afl, h, pattern, repl_new, o_pattern, changed_val, 32, idx,
              taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

        return 1;

      }

    }

  }

  //#endif                                           /*
  // CMPLOG_SOLVE_ARITHMETIC

  return 0;

}

#ifdef WORD_SIZE_64

static u8 cmp_extend_encodingN(afl_state_t *afl, struct cmp_header *h,
                               u128 pattern, u128 repl, u128 o_pattern,
                               u128 changed_val, u8 attr, u32 idx,
                               u32 taint_len, u8 *orig_buf, u8 *buf, u8 *cbuf,
                               u32 len, u8 do_reverse, u8 lvl, u8 *status) {

  if (afl->fsrv.total_execs - last_update > screen_update) {

    show_stats(afl);
    last_update = afl->fsrv.total_execs;

  }

  u8 *ptr = (u8 *)&buf[idx];
  u8 *o_ptr = (u8 *)&orig_buf[idx];
  u8 *p = (u8 *)&pattern;
  u8 *o_p = (u8 *)&o_pattern;
  u8 *r = (u8 *)&repl;
  u8  backup[16];
  u32 its_len = MIN(len - idx, taint_len);
  #if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  size_t off = 0;
  #else
  size_t off = 16 - hshape;
  #endif

  if (its_len >= hshape) {

  #ifdef _DEBUG
    fprintf(stderr, "TestUN: %u>=%u (len=%u idx=%u attr=%u off=%lu) (%u) ",
            its_len, hshape, len, idx, attr, off, do_reverse);
    u32 i;
    u8 *o_r = (u8 *)&changed_val;
    for (i = 0; i < hshape; i++)
      fprintf(stderr, "%02x", ptr[i]);
    fprintf(stderr, "==");
    for (i = 0; i < hshape; i++)
      fprintf(stderr, "%02x", p[off + i]);
    fprintf(stderr, " ");
    for (i = 0; i < hshape; i++)
      fprintf(stderr, "%02x", o_ptr[i]);
    fprintf(stderr, "==");
    for (i = 0; i < hshape; i++)
      fprintf(stderr, "%02x", o_p[off + i]);
    fprintf(stderr, " <= ");
    for (i = 0; i < hshape; i++)
      fprintf(stderr, "%02x", r[off + i]);
    fprintf(stderr, "<-");
    for (i = 0; i < hshape; i++)
      fprintf(stderr, "%02x", o_r[off + i]);
    fprintf(stderr, "\n");
  #endif

    if (!memcmp(ptr, p + off, hshape) && !memcmp(o_ptr, o_p + off, hshape)) {

      memcpy(backup, ptr, hshape);
      memcpy(ptr, r + off, hshape);

      if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }

  #ifdef CMPLOG_COMBINE
      if (*status == 1) { memcpy(cbuf + idx, r, hshape); }
  #endif

      memcpy(ptr, backup, hshape);

  #ifdef _DEBUG
      fprintf(stderr, "Status=%u\n", *status);
  #endif

    }

    // reverse encoding
    if (do_reverse && *status != 1) {

      if (unlikely(cmp_extend_encodingN(
              afl, h, SWAPN(pattern, (hshape << 3)), SWAPN(repl, (hshape << 3)),
              SWAPN(o_pattern, (hshape << 3)),
              SWAPN(changed_val, (hshape << 3)), attr, idx, taint_len, orig_buf,
              buf, cbuf, len, 0, lvl, status))) {

        return 1;

      }

    }

  }

  return 0;

}

#endif

static void try_to_add_to_dict(afl_state_t *afl, u64 v, u8 shape) {

  u8 *b = (u8 *)&v;

  u32 k;
  u8  cons_ff = 0, cons_0 = 0;
  for (k = 0; k < shape; ++k) {

    if (b[k] == 0) {

      ++cons_0;

    } else if (b[k] == 0xff) {

      ++cons_ff;

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

#ifdef WORD_SIZE_64
static void try_to_add_to_dictN(afl_state_t *afl, u128 v, u8 size) {

  u8 *b = (u8 *)&v;

  u32 k;
  u8  cons_ff = 0, cons_0 = 0;
  #if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
  u32 off = 0;
  for (k = 0; k < size; ++k) {

  #else
  u32    off = 16 - size;
  for (k = 16 - size; k < 16; ++k) {

  #endif
    if (b[k] == 0) {

      ++cons_0;

    } else if (b[k] == 0xff) {

      ++cons_ff;

    } else {

      cons_0 = cons_ff = 0;

    }

  }

  maybe_add_auto(afl, (u8 *)&v + off, size);
  u128 rev = SWAPN(v, size);
  maybe_add_auto(afl, (u8 *)&rev + off, size);

}

#endif

#define SWAPA(_x) ((_x & 0xf8) + ((_x & 7) ^ 0x07))

static u8 cmp_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u8 *cbuf,
                   u32 len, u32 lvl, struct tainted *taint) {

  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  struct tainted    *t;
  u32                i, j, idx, taint_len, loggeds;
  u32                have_taint = 1;
  u8                 status = 0, found_one = 0;

  /* loop cmps are useless, detect and ignore them */
#ifdef WORD_SIZE_64
  u32  is_n = 0;
  u128 s128_v0 = 0, s128_v1 = 0, orig_s128_v0 = 0, orig_s128_v1 = 0;
#endif
  u64 s_v0, s_v1;
  u8  s_v0_fixed = 1, s_v1_fixed = 1;
  u8  s_v0_inc = 1, s_v1_inc = 1;
  u8  s_v0_dec = 1, s_v1_dec = 1;

  hshape = SHAPE_BYTES(h->shape);

  if (h->hits > CMP_MAP_H) {

    loggeds = CMP_MAP_H;

  } else {

    loggeds = h->hits;

  }

#ifdef WORD_SIZE_64
  switch (hshape) {

    case 1:
    case 2:
    case 4:
    case 8:
      break;
    default:
      is_n = 1;

  }

#endif

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
          afl->shm.cmp_map->log[key][j].v1 == o->v1) {

        goto cmp_fuzz_next_iter;

      }

    }

#ifdef _DEBUG
    fprintf(stderr, "Handling: %llx->%llx vs %llx->%llx attr=%u shape=%u\n",
            orig_o->v0, o->v0, orig_o->v1, o->v1, h->attribute, hshape);
#endif

    t = taint;
    while (t->next) {

      t = t->next;

    }

#ifdef WORD_SIZE_64
    if (unlikely(is_n)) {

      s128_v0 = ((u128)o->v0) + (((u128)o->v0_128) << 64);
      s128_v1 = ((u128)o->v1) + (((u128)o->v1_128) << 64);
      orig_s128_v0 = ((u128)orig_o->v0) + (((u128)orig_o->v0_128) << 64);
      orig_s128_v1 = ((u128)orig_o->v1) + (((u128)orig_o->v1_128) << 64);

    }

#endif

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

#ifdef WORD_SIZE_64
      if (is_n) {  // _ExtInt special case including u128

        if (s128_v0 != orig_s128_v0 && orig_s128_v0 != orig_s128_v1) {

          if (unlikely(cmp_extend_encodingN(
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

          if (unlikely(cmp_extend_encodingN(
                  afl, h, s128_v1, s128_v0, orig_s128_v1, orig_s128_v0,
                  SWAPA(h->attribute), idx, taint_len, orig_buf, buf, cbuf, len,
                  1, lvl, &status))) {

            return 1;

          }

        }

        if (status == 1) {

          found_one = 1;
          break;

        }

      }

#endif

#ifdef _DEBUG
      if (o->v0 != orig_o->v0 || o->v1 != orig_o->v1)
        fprintf(stderr, "key=%u idx=%u o0=%llu v0=%llu o1=%llu v1=%llu\n", key,
                idx, orig_o->v0, o->v0, orig_o->v1, o->v1);
#endif

      // even for u128 and _ExtInt we do cmp_extend_encoding() because
      // if we got here their own special trials failed and it might just be
      // a cast from e.g. u64 to u128 from the input data.

      if ((o->v0 != orig_o->v0 || lvl >= LVL3) && orig_o->v0 != orig_o->v1) {

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
      if ((o->v1 != orig_o->v1 || lvl >= LVL3) && orig_o->v0 != orig_o->v1) {

        if (unlikely(cmp_extend_encoding(afl, h, o->v1, o->v0, orig_o->v1,
                                         orig_o->v0, SWAPA(h->attribute), idx,
                                         taint_len, orig_buf, buf, cbuf, len, 1,
                                         lvl, &status))) {

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
            "END: %llx->%llx vs %llx->%llx attr=%u i=%u found=%u "
            "isN=%u size=%u\n",
            orig_o->v0, o->v0, orig_o->v1, o->v1, h->attribute, i, found_one,
            is_n, hshape);
#endif

    // we only learn 16 bit +
    if (hshape > 1) {

      if (!found_one || afl->queue_cur->is_ascii) {

#ifdef WORD_SIZE_64
        if (unlikely(is_n)) {

          if (!found_one ||
              check_if_text_buf((u8 *)&s128_v0, SHAPE_BYTES(h->shape)) ==
                  SHAPE_BYTES(h->shape))
            try_to_add_to_dictN(afl, s128_v0, SHAPE_BYTES(h->shape));
          if (!found_one ||
              check_if_text_buf((u8 *)&s128_v1, SHAPE_BYTES(h->shape)) ==
                  SHAPE_BYTES(h->shape))
            try_to_add_to_dictN(afl, s128_v1, SHAPE_BYTES(h->shape));

        } else

#endif
        {

          if (!memcmp((u8 *)&o->v0, (u8 *)&orig_o->v0, SHAPE_BYTES(h->shape)) &&
              (!found_one ||
               check_if_text_buf((u8 *)&o->v0, SHAPE_BYTES(h->shape)) ==
                   SHAPE_BYTES(h->shape)))
            try_to_add_to_dict(afl, o->v0, SHAPE_BYTES(h->shape));
          if (!memcmp((u8 *)&o->v1, (u8 *)&orig_o->v1, SHAPE_BYTES(h->shape)) &&
              (!found_one ||
               check_if_text_buf((u8 *)&o->v1, SHAPE_BYTES(h->shape)) ==
                   SHAPE_BYTES(h->shape)))
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

static u8 rtn_extend_encoding(afl_state_t *afl, u8 entry,
                              struct cmpfn_operands *o,
                              struct cmpfn_operands *orig_o, u32 idx,
                              u32 taint_len, u8 *orig_buf, u8 *buf, u8 *cbuf,
                              u32 len, u8 lvl, u8 *status) {

#ifndef CMPLOG_COMBINE
  (void)(cbuf);
#endif
  //#ifndef CMPLOG_SOLVE_TRANSFORM
  //  (void)(changed_val);
  //#endif

  if (afl->fsrv.total_execs - last_update > screen_update) {

    show_stats(afl);
    last_update = afl->fsrv.total_execs;

  }

  u8 *pattern, *repl, *o_pattern, *changed_val;
  u8  l0, l1, ol0, ol1;

  if (entry == 0) {

    pattern = o->v0;
    repl = o->v1;
    o_pattern = orig_o->v0;
    changed_val = orig_o->v1;
    l0 = o->v0_len;
    ol0 = orig_o->v0_len;
    l1 = o->v1_len;
    ol1 = orig_o->v1_len;

  } else {

    pattern = o->v1;
    repl = o->v0;
    o_pattern = orig_o->v1;
    changed_val = orig_o->v0;
    l0 = o->v1_len;
    ol0 = orig_o->v1_len;
    l1 = o->v0_len;
    ol1 = orig_o->v0_len;

  }

  if (l0 >= 0x80 || ol0 >= 0x80) {

    l0 -= 0x80;
    l1 -= 0x80;
    ol0 -= 0x80;
    ol1 -= 0x80;

  }

  if (l0 == 0 || l1 == 0 || ol0 == 0 || ol1 == 0 || l0 > 31 || l1 > 31 ||
      ol0 > 31 || ol1 > 31) {

    l0 = ol0 = hshape;

  }

  u8  lmax = MAX(l0, ol0);
  u8  save[40];
  u32 saved_idx = idx, pre, from = 0, to = 0, i, j;
  u32 its_len = MIN(MIN(lmax, hshape), len - idx);
  its_len = MIN(its_len, taint_len);
  u32 saved_its_len = its_len;

  if (lvl & LVL3) {

    u32 max_to = MIN(4U, idx);
    if (!(lvl & LVL1) && max_to) { from = 1; }
    to = max_to;

  }

  memcpy(save, &buf[saved_idx - to], its_len + to);
  (void)(j);

#ifdef _DEBUG
  fprintf(stderr, "RTN T idx=%u lvl=%02x is_txt=%u shape=%u/%u ", idx, lvl,
          o->v0_len >= 0x80 ? 1 : 0, hshape, l0);
  for (j = 0; j < 8; j++)
    fprintf(stderr, "%02x", orig_buf[idx + j]);
  fprintf(stderr, " -> ");
  for (j = 0; j < 8; j++)
    fprintf(stderr, "%02x", o_pattern[j]);
  fprintf(stderr, " <= ");
  for (j = 0; j < 8; j++)
    fprintf(stderr, "%02x", repl[j]);
  fprintf(stderr, "\n");
  fprintf(stderr, "                ");
  for (j = 0; j < 8; j++)
    fprintf(stderr, "%02x", buf[idx + j]);
  fprintf(stderr, " -> ");
  for (j = 0; j < 8; j++)
    fprintf(stderr, "%02x", pattern[j]);
  fprintf(stderr, " <= ");
  for (j = 0; j < 8; j++)
    fprintf(stderr, "%02x", changed_val[j]);
  fprintf(stderr, "\n");
#endif

  // Try to match the replace value up to 4 bytes before the current idx.
  // This allows matching of eg.:
  //   if (memcmp(user_val, "TEST") == 0)
  //     if (memcmp(user_val, "TEST-VALUE") == 0) ...
  // We only do this in lvl 3, otherwise we only do direct matching

  for (pre = from; pre <= to; pre++) {

    if (*status != 1 && (!pre || !memcmp(buf + saved_idx - pre, repl, pre))) {

      idx = saved_idx - pre;
      its_len = saved_its_len + pre;

      for (i = 0; i < its_len; ++i) {

        if ((pattern[i] != buf[idx + i] && o_pattern[i] != orig_buf[idx + i]) ||
            *status == 1) {

          break;

        }

        buf[idx + i] = repl[i];

        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }

#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, &buf[idx], i); }
#endif

      }

      memcpy(&buf[idx], save + to - pre, i);

    }

  }

  if (*status == 1) return 0;

  // transform solving

  if (afl->cmplog_enable_transform && (lvl & LVL3)) {

    u32 toupper = 0, tolower = 0, xor = 0, arith = 0, tohex = 0, fromhex = 0;
#ifdef CMPLOG_SOLVE_TRANSFORM_BASE64
    u32 tob64 = 0, fromb64 = 0;
#endif
    u32 from_0 = 0, from_x = 0, from_X = 0, from_slash = 0, from_up = 0;
    u32 to_0 = 0, to_x = 0, to_slash = 0, to_up = 0;
    u8  xor_val[32], arith_val[32], tmp[48];

    idx = saved_idx;
    its_len = saved_its_len;

    memcpy(save, &buf[idx], its_len);

    for (i = 0; i < its_len; ++i) {

      xor_val[i] = pattern[i] ^ buf[idx + i];
      arith_val[i] = pattern[i] - buf[idx + i];

      if (i == 0) {

        if (orig_buf[idx] == '0') {

          from_0 = 1;

        } else if (orig_buf[idx] == '\\') {

          from_slash = 1;

        }

        if (repl[0] == '0') {

          to_0 = 1;

        } else if (repl[0] == '\\') {

          to_slash = 1;

        }

      } else if (i == 1) {

        if (orig_buf[idx + 1] == 'x') {

          from_x = 1;

        } else if (orig_buf[idx + 1] == 'X') {

          from_X = from_x = 1;

        }

        if (repl[1] == 'x' || repl[1] == 'X') { to_x = 1; }

      }

      if (i < 16 && is_hex(repl + (i << 1))) {

        ++tohex;

        if (!to_up) {

          if (repl[i << 1] >= 'A' && repl[i << 1] <= 'F')
            to_up = 1;
          else if (repl[i << 1] >= 'a' && repl[i << 1] <= 'f')
            to_up = 2;
          if (repl[(i << 1) + 1] >= 'A' && repl[(i << 1) + 1] <= 'F')
            to_up = 1;
          else if (repl[(i << 1) + 1] >= 'a' && repl[(i << 1) + 1] <= 'f')
            to_up = 2;

        }

      }

      if ((i % 2)) {

        if (len > idx + i + 1 && is_hex(orig_buf + idx + i)) {

          fromhex += 2;

          if (!from_up) {

            if (orig_buf[idx + i] >= 'A' && orig_buf[idx + i] <= 'F')
              from_up = 1;
            else if (orig_buf[idx + i] >= 'a' && orig_buf[idx + i] <= 'f')
              from_up = 2;
            if (orig_buf[idx + i - 1] >= 'A' && orig_buf[idx + i - 1] <= 'F')
              from_up = 1;
            else if (orig_buf[idx + i - 1] >= 'a' &&
                     orig_buf[idx + i - 1] <= 'f')
              from_up = 2;

          }

        }

      }

#ifdef CMPLOG_SOLVE_TRANSFORM_BASE64
      if (i % 3 == 2 && i < 24) {

        if (is_base64(repl + ((i / 3) << 2))) tob64 += 3;

      }

      if (i % 4 == 3 && i < 24) {

        if (is_base64(orig_buf + idx + i - 3)) fromb64 += 4;

      }

#endif

      if ((o_pattern[i] ^ orig_buf[idx + i]) == xor_val[i] && xor_val[i]) {

        ++xor;

      }

      if ((o_pattern[i] - orig_buf[idx + i]) == arith_val[i] && arith_val[i]) {

        ++arith;

      }

      if ((buf[idx + i] | 0x20) == pattern[i] &&
          (orig_buf[idx + i] | 0x20) == o_pattern[i]) {

        ++tolower;

      }

      if ((buf[idx + i] & 0x5a) == pattern[i] &&
          (orig_buf[idx + i] & 0x5a) == o_pattern[i]) {

        ++toupper;

      }

#ifdef _DEBUG
      fprintf(stderr,
              "RTN idx=%u loop=%u xor=%u arith=%u tolower=%u toupper=%u "
              "tohex=%u fromhex=%u to_0=%u to_slash=%u to_x=%u "
              "from_0=%u from_slash=%u from_x=%u\n",
              idx, i, xor, arith, tolower, toupper, tohex, fromhex, to_0,
              to_slash, to_x, from_0, from_slash, from_x);
  #ifdef CMPLOG_SOLVE_TRANSFORM_BASE64
      fprintf(stderr, "RTN idx=%u loop=%u tob64=%u from64=%u\n", tob64,
              fromb64);
  #endif
#endif

#ifdef CMPLOG_SOLVE_TRANSFORM_BASE64
      // input is base64 and converted to binary? convert repl to base64!
      if ((i % 4) == 3 && i < 24 && fromb64 > i) {

        to_base64(repl, tmp, i + 1);
        memcpy(buf + idx, tmp, i + 1);
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT fromb64 %u result %u\n", fromb64,
        // *status);

      }

      // input is converted to base64? decode repl with base64!
      if ((i % 3) == 2 && i < 24 && tob64 > i) {

        u32 olen = from_base64(repl, tmp, i + 1);
        memcpy(buf + idx, tmp, olen);
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT tob64 %u idx=%u result %u\n", tob64,
        // idx, *status);

      }

#endif

      // input is converted to hex? convert repl to binary!
      if (i < 16 && tohex > i) {

        u32 off;
        if (to_slash + to_x + to_0 == 2) {

          off = 2;

        } else {

          off = 0;

        }

        for (j = 0; j <= i; j++)
          tmp[j] = (hex_table[repl[off + (j << 1)] - '0'] << 4) +
                   hex_table[repl[off + (j << 1) + 1] - '0'];

        memcpy(buf + idx, tmp, i + 1);
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT tohex %u result %u\n", tohex,
        // *status);

      }

      // input is hex and converted to binary? convert repl to hex!
      if (i && (i % 2) && i < 16 && fromhex &&
          fromhex + from_slash + from_x + from_0 > i) {

        u8 off = 0;
        if (from_slash && from_x) {

          tmp[0] = '\\';
          if (from_X) {

            tmp[1] = 'X';

          } else {

            tmp[1] = 'x';

          }

          off = 2;

        } else if (from_0 && from_x) {

          tmp[0] = '0';
          if (from_X) {

            tmp[1] = 'X';

          } else {

            tmp[1] = 'x';

          }

          off = 2;

        }

        if (to_up == 1) {

          for (j = 0; j <= (i >> 1); j++) {

            tmp[off + (j << 1)] = hex_table_up[repl[j] >> 4];
            tmp[off + (j << 1) + 1] = hex_table_up[repl[j] % 16];

          }

        } else {

          for (j = 0; j <= (i >> 1); j++) {

            tmp[off + (j << 1)] = hex_table_low[repl[j] >> 4];
            tmp[off + (j << 1) + 1] = hex_table_low[repl[j] % 16];

          }

        }

        memcpy(buf + idx, tmp, i + 1 + off);
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT fromhex %u result %u\n", fromhex,
        // *status);
        memcpy(buf + idx, save, i + 1 + off);

      }

      if (xor > i) {

        for (j = 0; j <= i; j++)
          buf[idx + j] = repl[j] ^ xor_val[j];
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT xor %u result %u\n", xor, *status);

      }

      if (arith > i && *status != 1) {

        for (j = 0; j <= i; j++)
          buf[idx + j] = repl[j] - arith_val[j];
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT arith %u result %u\n", arith,
        // *status);

      }

      if (toupper > i && *status != 1) {

        for (j = 0; j <= i; j++)
          buf[idx + j] = repl[j] | 0x20;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT toupper %u result %u\n", toupper,
        // *status);

      }

      if (tolower > i && *status != 1) {

        for (j = 0; j <= i; j++)
          buf[idx + j] = repl[j] & 0x5f;
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
        // fprintf(stderr, "RTN ATTEMPT tolower %u result %u\n", tolower,
        // *status);

      }

#ifdef CMPLOG_COMBINE
      if (*status == 1) { memcpy(cbuf + idx, &buf[idx], i + 1); }
#endif

      if ((i >= 7 &&
           (i >= xor&&i >= arith &&i >= tolower &&i >= toupper &&i > tohex &&i >
                (fromhex + from_0 + from_x + from_slash + 1)
#ifdef CMPLOG_SOLVE_TRANSFORM_BASE64
            && i > tob64 + 3 && i > fromb64 + 4
#endif
            )) ||
          repl[i] != changed_val[i] || *status == 1) {

        break;

      }

    }

    memcpy(&buf[idx], save, i);

  }

  //#endif

  return 0;

}

static u8 rtn_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u8 *cbuf,
                   u32 len, u8 lvl, struct tainted *taint) {

  struct tainted    *t;
  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  u32                i, j, idx, have_taint = 1, taint_len, loggeds;
  u8                 status = 0, found_one = 0;

  hshape = SHAPE_BYTES(h->shape);

  if (h->hits > CMP_MAP_RTN_H) {

    loggeds = CMP_MAP_RTN_H;

  } else {

    loggeds = h->hits;

  }

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

    /*
    struct cmp_header *hh = &afl->orig_cmp_map->headers[key];
    fprintf(stderr, "RTN N hits=%u id=%u shape=%u attr=%u v0=", h->hits, h->id,
            hshape, h->attribute);
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", o->v0[j]);
    fprintf(stderr, " v1=");
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", o->v1[j]);
    fprintf(stderr, "\nRTN O hits=%u id=%u shape=%u attr=%u o0=", hh->hits,
            hh->id, hshape, hh->attribute);
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", orig_o->v0[j]);
    fprintf(stderr, " o1=");
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", orig_o->v1[j]);
    fprintf(stderr, "\n");
    */

    t = taint;
    while (t->next) {

      t = t->next;

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

#ifdef _DEBUG
      int w;
      fprintf(stderr, "key=%u idx=%u len=%u o0=", key, idx, hshape);
      for (w = 0; w < hshape; ++w)
        fprintf(stderr, "%02x", orig_o->v0[w]);
      fprintf(stderr, " v0=");
      for (w = 0; w < hshape; ++w)
        fprintf(stderr, "%02x", o->v0[w]);
      fprintf(stderr, " o1=");
      for (w = 0; w < hshape; ++w)
        fprintf(stderr, "%02x", orig_o->v1[w]);
      fprintf(stderr, " v1=");
      for (w = 0; w < hshape; ++w)
        fprintf(stderr, "%02x", o->v1[w]);
      fprintf(stderr, "\n");
#endif

      if (unlikely(rtn_extend_encoding(afl, 0, o, orig_o, idx, taint_len,
                                       orig_buf, buf, cbuf, len, lvl,
                                       &status))) {

        return 1;

      }

      if (status == 1) {

        found_one = 1;
        break;

      }

      status = 0;

      if (unlikely(rtn_extend_encoding(afl, 1, o, orig_o, idx, taint_len,
                                       orig_buf, buf, cbuf, len, lvl,
                                       &status))) {

        return 1;

      }

      if (status == 1) {

        found_one = 1;
        break;

      }

    }

    //  if (unlikely(!afl->pass_stats[key].total)) {

    if ((!found_one && (lvl & LVL1)) || afl->queue_cur->is_ascii) {

      // if (unlikely(!afl->pass_stats[key].total)) {

      u32 shape_len = SHAPE_BYTES(h->shape);
      u32 v0_len = shape_len, v1_len = shape_len;
      if (afl->queue_cur->is_ascii ||
          check_if_text_buf((u8 *)&o->v0, shape_len) == shape_len) {

        if (strlen(o->v0)) v0_len = strlen(o->v0);

      }

      if (afl->queue_cur->is_ascii ||
          check_if_text_buf((u8 *)&o->v1, shape_len) == shape_len) {

        if (strlen(o->v1)) v1_len = strlen(o->v1);

      }

      // fprintf(stderr, "SHOULD: found:%u ascii:%u text?%u:%u %u:%s %u:%s \n",
      // found_one, afl->queue_cur->is_ascii, check_if_text_buf((u8 *)&o->v0,
      // shape_len), check_if_text_buf((u8 *)&o->v1, shape_len), v0_len,
      // o->v0, v1_len, o->v1);

      if (!memcmp(o->v0, orig_o->v0, v0_len) ||
          (!found_one || check_if_text_buf((u8 *)&o->v0, v0_len) == v0_len))
        maybe_add_auto(afl, o->v0, v0_len);
      if (!memcmp(o->v1, orig_o->v1, v1_len) ||
          (!found_one || check_if_text_buf((u8 *)&o->v1, v1_len) == v1_len))
        maybe_add_auto(afl, o->v1, v1_len);

      //}

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
u8 input_to_state_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len) {

  u8 r = 1;
  if (unlikely(!afl->pass_stats)) {

    afl->pass_stats = ck_alloc(sizeof(struct afl_pass_stat) * CMP_MAP_W);

  }

  struct tainted *taint = NULL;
  if (likely(afl->queue_cur->exec_us)) {

    if (likely((100000 / 2) >= afl->queue_cur->exec_us)) {

      screen_update = 100000 / afl->queue_cur->exec_us;

    } else {

      screen_update = 1;

    }

  } else {

    screen_update = 100000;

  }

  if (!afl->queue_cur->taint || !afl->queue_cur->cmplog_colorinput) {

    if (unlikely(colorization(afl, buf, len, &taint))) { return 1; }

    // no taint? still try, create a dummy to prevent again colorization
    if (!taint) {

#ifdef _DEBUG
      fprintf(stderr, "TAINT FAILED\n");
#endif
      afl->queue_cur->colorized = CMPLOG_LVL_MAX;
      return 0;

    }

#ifdef _DEBUG
    else if (taint->pos == 0 && taint->len == len) {

      fprintf(stderr, "TAINT FULL\n");

    }

#endif

  } else {

    buf = afl->queue_cur->cmplog_colorinput;
    taint = afl->queue_cur->taint;

  }

  struct tainted *t = taint;

  while (t) {

#ifdef _DEBUG
    fprintf(stderr, "T: idx=%u len=%u\n", t->pos, t->len);
#endif
    t = t->next;

  }

#if defined(_DEBUG) || defined(CMPLOG_INTROSPECTION)
  u64 start_time = get_cur_time();
  u32 cmp_locations = 0;
#endif

  // Generate the cmplog data

  // manually clear the full cmp_map
  memset(afl->shm.cmp_map, 0, sizeof(struct cmp_map));
  if (unlikely(common_fuzz_cmplog_stuff(afl, orig_buf, len))) {

    afl->queue_cur->colorized = CMPLOG_LVL_MAX;
    while (taint) {

      t = taint->next;
      ck_free(taint);
      taint = t;

    }

    return 1;

  }

  if (unlikely(!afl->orig_cmp_map)) {

    afl->orig_cmp_map = ck_alloc_nozero(sizeof(struct cmp_map));

  }

  memcpy(afl->orig_cmp_map, afl->shm.cmp_map, sizeof(struct cmp_map));
  memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);
  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) {

    afl->queue_cur->colorized = CMPLOG_LVL_MAX;
    while (taint) {

      t = taint->next;
      ck_free(taint);
      taint = t;

    }

    return 1;

  }

#ifdef _DEBUG
  dump("ORIG", orig_buf, len);
  dump("NEW ", buf, len);
#endif

  // Start insertion loop

  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs = afl->fsrv.total_execs;
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_name = "input-to-state";
  afl->stage_short = "its";
  afl->stage_max = 0;
  afl->stage_cur = 0;

  u32 lvl = (afl->queue_cur->colorized ? 0 : LVL1) +
            (afl->cmplog_lvl == CMPLOG_LVL_MAX ? LVL3 : 0);

#ifdef CMPLOG_COMBINE
  u8 *cbuf = afl_realloc((void **)&afl->in_scratch_buf, len + 128);
  memcpy(cbuf, orig_buf, len);
  u8 *virgin_backup = afl_realloc((void **)&afl->ex_buf, afl->shm.map_size);
  memcpy(virgin_backup, afl->virgin_bits, afl->shm.map_size);
#else
  u8 *cbuf = NULL;
#endif

  u32 k;
  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!afl->shm.cmp_map->headers[k].hits) { continue; }

    if (afl->pass_stats[k].faileds >= CMPLOG_FAIL_MAX ||
        afl->pass_stats[k].total >= CMPLOG_FAIL_MAX) {

#ifdef _DEBUG
      fprintf(stderr, "DISABLED %u\n", k);
#endif

      afl->shm.cmp_map->headers[k].hits = 0;  // ignore this cmp

    }

    if (afl->shm.cmp_map->headers[k].type == CMP_TYPE_INS) {

      // fprintf(stderr, "INS %u\n", k);
      afl->stage_max +=
          MIN((u32)(afl->shm.cmp_map->headers[k].hits), (u32)CMP_MAP_H);

    } else {

      // fprintf(stderr, "RTN %u\n", k);
      afl->stage_max +=
          MIN((u32)(afl->shm.cmp_map->headers[k].hits), (u32)CMP_MAP_RTN_H);

    }

  }

  for (k = 0; k < CMP_MAP_W; ++k) {

    if (!afl->shm.cmp_map->headers[k].hits) { continue; }

#if defined(_DEBUG) || defined(CMPLOG_INTROSPECTION)
    ++cmp_locations;
#endif

    if (afl->shm.cmp_map->headers[k].type == CMP_TYPE_INS) {

      if (unlikely(cmp_fuzz(afl, k, orig_buf, buf, cbuf, len, lvl, taint))) {

        goto exit_its;

      }

    } else if ((lvl & LVL1)

               //#ifdef CMPLOG_SOLVE_TRANSFORM
               || ((lvl & LVL3) && afl->cmplog_enable_transform)
               //#endif
    ) {

      if (unlikely(rtn_fuzz(afl, k, orig_buf, buf, cbuf, len, lvl, taint))) {

        goto exit_its;

      }

    }

  }

  r = 0;

exit_its:

  if (afl->cmplog_lvl == CMPLOG_LVL_MAX) {

    afl->queue_cur->colorized = CMPLOG_LVL_MAX;

    if (afl->queue_cur->cmplog_colorinput) {

      ck_free(afl->queue_cur->cmplog_colorinput);

    }

    while (taint) {

      t = taint->next;
      ck_free(taint);
      taint = t;

    }

    afl->queue_cur->taint = NULL;

  } else {

    afl->queue_cur->colorized = LVL2;

    if (!afl->queue_cur->taint) { afl->queue_cur->taint = taint; }

    if (!afl->queue_cur->cmplog_colorinput) {

      afl->queue_cur->cmplog_colorinput = ck_alloc_nozero(len);
      memcpy(afl->queue_cur->cmplog_colorinput, buf, len);
      memcpy(buf, orig_buf, len);

    }

  }

#ifdef CMPLOG_COMBINE
  if (afl->queued_items + afl->saved_crashes > orig_hit_cnt + 1) {

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
    u32 *v = (u32 *)afl->virgin_bits;
    u32 *s = (u32 *)virgin_save;
    u32  i;
    for (i = 0; i < (afl->shm.map_size >> 2); i++) {

      v[i] &= s[i];

    }

  #endif

  #ifdef _DEBUG
    dump("COMB", cbuf, len);
    if (status == 1) {

      fprintf(stderr, "NEW CMPLOG_COMBINED\n");

    } else {

      fprintf(stderr, "NO new combined\n");

    }

  #endif

  }

#endif

  new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_ITS] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_ITS] += afl->fsrv.total_execs - orig_execs;

#if defined(_DEBUG) || defined(CMPLOG_INTROSPECTION)
  FILE *f = stderr;
  #ifndef _DEBUG
  if (afl->not_on_tty) {

    char fn[4096];
    snprintf(fn, sizeof(fn), "%s/introspection_cmplog.txt", afl->out_dir);
    f = fopen(fn, "a");

  }

  #endif

  if (f) {

    fprintf(f,
            "Cmplog: fname=%s len=%u ms=%llu result=%u finds=%llu entries=%u "
            "auto_extra_after=%u\n",
            afl->queue_cur->fname, len, get_cur_time() - start_time, r,
            new_hit_cnt - orig_hit_cnt, cmp_locations, afl->a_extras_cnt);

  #ifndef _DEBUG
    if (afl->not_on_tty) { fclose(f); }
  #endif

  }

#endif

  return r;

}

