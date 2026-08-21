/*
   american fuzzy lop++ - redqueen implementation on top of cmplog
   ---------------------------------------------------------------

   Originally written by Michal Zalewski

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eissfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2023 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

   Shared code to handle the shared memory. This is used by the fuzzer
   as well the other components like afl-tmin, afl-showmap, etc...

 */

#include <limits.h>
#include <math.h>
#include "afl-fuzz.h"
#include "cmplog.h"

// #define _DEBUG
// #define USE_HASHMAP
// #define CMPLOG_INTROSPECTION

static inline u8 cmp_attr_is_fp(u8 attr) {

  return attr <= CMP_ATTR_FCMP_TRUE;

}

static inline u8 cmp_attr_is_integer(u8 attr) {

  return attr >= CMP_ATTR_ICMP_EQ && attr <= CMP_ATTR_ICMP_SLE;

}

static inline u8 cmp_attr_is_internal(u8 attr) {

  return attr >= CMP_ATTR_MOD_FLOAT && attr <= CMP_ATTR_TRANSFORM;

}

static inline u8 cmp_attr_is_equality(u8 attr) {

  return attr == CMP_ATTR_ICMP_EQ || attr == CMP_ATTR_ICMP_NE ||
         attr == CMP_ATTR_FCMP_OEQ || attr == CMP_ATTR_FCMP_ONE ||
         attr == CMP_ATTR_FCMP_UEQ || attr == CMP_ATTR_FCMP_UNE;

}

static inline u8 cmp_attr_is_greater(u8 attr) {

  return attr == CMP_ATTR_ICMP_UGT || attr == CMP_ATTR_ICMP_UGE ||
         attr == CMP_ATTR_ICMP_SGT || attr == CMP_ATTR_ICMP_SGE ||
         attr == CMP_ATTR_FCMP_OGT || attr == CMP_ATTR_FCMP_OGE ||
         attr == CMP_ATTR_FCMP_UGT || attr == CMP_ATTR_FCMP_UGE;

}

static inline u8 cmp_attr_is_lesser(u8 attr) {

  return attr == CMP_ATTR_ICMP_ULT || attr == CMP_ATTR_ICMP_ULE ||
         attr == CMP_ATTR_ICMP_SLT || attr == CMP_ATTR_ICMP_SLE ||
         attr == CMP_ATTR_FCMP_OLT || attr == CMP_ATTR_FCMP_OLE ||
         attr == CMP_ATTR_FCMP_ULT || attr == CMP_ATTR_FCMP_ULE;

}

static inline u8 cmp_attr_is_signed(u8 attr) {

  return attr >= CMP_ATTR_ICMP_SGT && attr <= CMP_ATTR_ICMP_SLE;

}

static inline u8 cmp_attr_swap(u8 attr) {

  switch (attr) {

    case CMP_ATTR_ICMP_UGT:
      return CMP_ATTR_ICMP_ULT;
    case CMP_ATTR_ICMP_UGE:
      return CMP_ATTR_ICMP_ULE;
    case CMP_ATTR_ICMP_ULT:
      return CMP_ATTR_ICMP_UGT;
    case CMP_ATTR_ICMP_ULE:
      return CMP_ATTR_ICMP_UGE;
    case CMP_ATTR_ICMP_SGT:
      return CMP_ATTR_ICMP_SLT;
    case CMP_ATTR_ICMP_SGE:
      return CMP_ATTR_ICMP_SLE;
    case CMP_ATTR_ICMP_SLT:
      return CMP_ATTR_ICMP_SGT;
    case CMP_ATTR_ICMP_SLE:
      return CMP_ATTR_ICMP_SGE;
    case CMP_ATTR_FCMP_OGT:
      return CMP_ATTR_FCMP_OLT;
    case CMP_ATTR_FCMP_OGE:
      return CMP_ATTR_FCMP_OLE;
    case CMP_ATTR_FCMP_OLT:
      return CMP_ATTR_FCMP_OGT;
    case CMP_ATTR_FCMP_OLE:
      return CMP_ATTR_FCMP_OGE;
    case CMP_ATTR_FCMP_UGT:
      return CMP_ATTR_FCMP_ULT;
    case CMP_ATTR_FCMP_UGE:
      return CMP_ATTR_FCMP_ULE;
    case CMP_ATTR_FCMP_ULT:
      return CMP_ATTR_FCMP_UGT;
    case CMP_ATTR_FCMP_ULE:
      return CMP_ATTR_FCMP_UGE;
    default:
      return attr;

  }

}

static inline u16 cmp_load16(const void *ptr) {

  u16 value;
  memcpy(&value, ptr, sizeof(value));
  return value;

}

static inline u32 cmp_load32(const void *ptr) {

  u32 value;
  memcpy(&value, ptr, sizeof(value));
  return value;

}

static inline u64 cmp_load64(const void *ptr) {

  u64 value;
  memcpy(&value, ptr, sizeof(value));
  return value;

}

static inline void cmp_store16(void *ptr, u16 value) {

  memcpy(ptr, &value, sizeof(value));

}

static inline void cmp_store32(void *ptr, u32 value) {

  memcpy(ptr, &value, sizeof(value));

}

static inline void cmp_store64(void *ptr, u64 value) {

  memcpy(ptr, &value, sizeof(value));

}

static inline u64 cmp_integer_slack(u64 a, u64 b, u32 bytes, u8 is_signed) {

  u32 bits = bytes * 8;
  u64 mask = bits == 64 ? UINT64_MAX : (1ULL << bits) - 1;
  a &= mask;
  b &= mask;
  if (is_signed) {

    u64 sign = 1ULL << (bits - 1);
    a ^= sign;
    b ^= sign;

  }

  return a >= b ? a - b : b - a;

}

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
  LVL3 = 4   // expensive transformations

};

#define DICT_ADD_STRATEGY DICT_ADD_FOUND_SAME

struct range {

  u32 start;
  u32 end;

};

struct range_heap {

  struct range *items;
  u32           count;
  u32           capacity;

};

static u32 hshape;
static u64 screen_update;
static u64 last_update;

#ifdef USE_HASHMAP
// hashmap functions
void hashmap_reset();
bool hashmap_search_and_add(uint8_t type, uint64_t key);
bool hashmap_search_and_add_ptr(uint8_t type, u8 *key);
#endif

static inline u32 range_size(const struct range *range) {

  return range->end - range->start + 1;

}

static inline u8 range_larger(const struct range *a, const struct range *b) {

  u32 a_size = range_size(a);
  u32 b_size = range_size(b);
  return a_size > b_size || (a_size == b_size && a->start < b->start);

}

static void range_heap_push(struct range_heap *heap, struct range range) {

  if (heap->count == heap->capacity) {

    heap->capacity = heap->capacity ? heap->capacity << 1 : 16;
    heap->items =
        ck_realloc(heap->items, heap->capacity * sizeof(*heap->items));

  }

  u32 idx = heap->count++;
  while (idx) {

    u32 parent = (idx - 1) >> 1;
    if (!range_larger(&range, &heap->items[parent])) { break; }
    heap->items[idx] = heap->items[parent];
    idx = parent;

  }

  heap->items[idx] = range;

}

static u8 range_heap_pop(struct range_heap *heap, struct range *range) {

  if (!heap->count) { return 0; }

  *range = heap->items[0];
  struct range last = heap->items[--heap->count];
  if (!heap->count) { return 1; }

  u32 idx = 0;
  while (1) {

    u32 child = (idx << 1) + 1;
    if (child >= heap->count) { break; }
    if (child + 1 < heap->count &&
        range_larger(&heap->items[child + 1], &heap->items[child])) {

      ++child;

    }

    if (!range_larger(&heap->items[child], &last)) { break; }
    heap->items[idx] = heap->items[child];
    idx = child;

  }

  heap->items[idx] = last;
  return 1;

}

static int range_start_compare(const void *a, const void *b) {

  const struct range *range_a = a;
  const struct range *range_b = b;
  if (range_a->start < range_b->start) { return -1; }
  if (range_a->start > range_b->start) { return 1; }
  return 0;

}

static u8 trace_matches(const u8 *trace, const u8 *baseline, const u8 *unstable,
                        u32 map_size) {

  if (!unstable) { return !memcmp(trace, baseline, map_size); }

  u32 i = 0;
  for (; i + sizeof(u64) <= map_size; i += sizeof(u64)) {

    u64 trace_word;
    u64 baseline_word;
    u64 unstable_word;
    memcpy(&trace_word, trace + i, sizeof(trace_word));
    memcpy(&baseline_word, baseline + i, sizeof(baseline_word));
    memcpy(&unstable_word, unstable + i, sizeof(unstable_word));
    if ((trace_word ^ baseline_word) & ~unstable_word) { return 0; }

  }

  for (; i < map_size; ++i) {

    if (unstable[i] != 0xff && trace[i] != baseline[i]) { return 0; }

  }

  return 1;

}

#ifdef _DEBUG
static void dump(char *txt, u8 *buf, u32 len) {

  u32 i;
  fprintf(stderr, "DUMP %s %016llx ", txt, hash64(buf, len, HASH_CONST));
  for (i = 0; i < len; i++)
    fprintf(stderr, "%02x", buf[i]);
  fprintf(stderr, "\n");

}

/*
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

*/

#endif

/* replace everything with different values */
static void random_replace(afl_state_t *afl, u8 *buf, u32 len) {

  for (u32 i = 0; i < len; i++) {

    u8 c;

    do {

      c = rand_below(afl, 256);

    } while (c == buf[i]);

    buf[i] = c;

  }

}

/* replace everything with different values but stay in the same type */
static void type_replace(afl_state_t *afl, u8 *buf, u32 len) {

  u32 i;
  u8  c;
  for (i = 0; i < len; ++i) {

    // won't help for UTF or non-latin charsets
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

  if (unlikely(!len)) {

    *taints = NULL;
    return 0;

  }

  struct range_heap ranges = {0};
  struct range     *accepted = NULL;
  struct tainted   *taint = NULL;
  u8               *backup = ck_alloc_nozero(len);
  u8               *changed = ck_alloc_nozero(len);
  u8               *baseline = ck_alloc_nozero(afl->fsrv.map_size);
  u8               *unstable = NULL;
  u32               accepted_count = 0;
  u32               accepted_capacity = 0;

  range_heap_push(&ranges, (struct range){.start = 0, .end = len - 1});

#if defined(_DEBUG) || defined(CMPLOG_INTROSPECTION)
  u64 start_time = get_cur_time();
#endif

  u64 orig_hit_cnt, new_hit_cnt;
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  afl->stage_name = "colorization";
  afl->stage_short = "colorization";
  afl->stage_max = (len << 1);
  afl->stage_cur = 0;

  // in colorization we do not classify counts, hence we preserve the original
  // trace and ignore bytes known to be unstable.
  if (unlikely(common_fuzz_stuff(afl, buf, len))) { goto colorization_fail; }

  memcpy(baseline, afl->fsrv.trace_bits, afl->fsrv.map_size);
  if (unlikely(afl->var_byte_count)) {

    unstable = ck_alloc_nozero(afl->fsrv.map_size);
    for (u32 i = 0; i < afl->fsrv.map_size; ++i)
      unstable[i] = afl->var_bytes[i] ? 0xff : 0;
    if (unlikely(common_fuzz_stuff(afl, buf, len))) { goto colorization_fail; }

    for (u32 i = 0; i < afl->fsrv.map_size; ++i) {

      if (afl->fsrv.trace_bits[i] != baseline[i]) { unstable[i] = 0xff; }

    }

  }

  memcpy(backup, buf, len);
  memcpy(changed, buf, len);
  if (likely(afl->cmplog_random_colorization)) {

    random_replace(afl, changed, len);

  } else {

    type_replace(afl, changed, len);

  }

  struct range rng;
  while (range_heap_pop(&ranges, &rng) && afl->stage_cur < afl->stage_max) {

    u32 s = range_size(&rng);

    memcpy(buf + rng.start, changed + rng.start, s);

    u64 start_us = get_cur_time_us();
    if (unlikely(common_fuzz_stuff(afl, buf, len))) { goto colorization_fail; }

    u64 stop_us = get_cur_time_us();

    /* Discard if the mutations change the path or if it is too decremental
      in speed - how could the same path have a much different speed
      though ...*/
    if (!trace_matches(afl->fsrv.trace_bits, baseline, unstable,
                       afl->fsrv.map_size) ||
        unlikely(stop_us - start_us > 3 * afl->queue_cur->exec_us)) {

      memcpy(buf + rng.start, backup + rng.start, s);

      if (s > 1) {  // to not add 0 size ranges

        range_heap_push(&ranges, (struct range){.start = rng.start,
                                                .end = rng.start - 1 + s / 2});
        range_heap_push(&ranges, (struct range){.start = rng.start + s / 2,
                                                .end = rng.end});

      }

    } else {

      if (accepted_count == accepted_capacity) {

        accepted_capacity = accepted_capacity ? accepted_capacity << 1 : 16;
        accepted = ck_realloc(accepted, accepted_capacity * sizeof(*accepted));

      }

      accepted[accepted_count++] = rng;

    }

    if (unlikely(++afl->stage_cur % screen_update == 0)) { show_stats(afl); };

  }

  u32 positions = 0;
  if (accepted_count > 1) {

    qsort(accepted, accepted_count, sizeof(*accepted), range_start_compare);

  }

  for (u32 i = 0; i < accepted_count; ++i) {

    u32 accepted_size = range_size(&accepted[i]);
    positions += accepted_size;
    if (taint && taint->pos + taint->len == accepted[i].start) {

      taint->len += accepted_size;

    } else {

      struct tainted *t = ck_alloc_nozero(sizeof(struct tainted));
      t->pos = accepted[i].start;
      t->len = accepted_size;
      if (likely(taint)) { taint->prev = t; }
      t->next = taint;
      t->prev = NULL;
      taint = t;

    }

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
  ck_free(ranges.items);
  ck_free(accepted);
  ck_free(backup);
  ck_free(changed);
  ck_free(baseline);
  ck_free(unstable);

  return 0;

colorization_fail:
  ck_free(ranges.items);
  ck_free(accepted);
  ck_free(backup);
  ck_free(changed);
  ck_free(baseline);
  ck_free(unstable);

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

static u32 to_base64(u8 *src, u8 *dst, u32 src_len) {

  u32 i, j, v;
  u32 len = (src_len / 3) * 4;
  if (src_len % 3) len += 4;

  for (i = 0, j = 0; j < len; i += 3, j += 4) {

    v = src[i];
    v = i + 1 < src_len ? v << 8 | src[i + 1] : v << 8;
    v = i + 2 < src_len ? v << 8 | src[i + 2] : v << 8;

    dst[j] = base64_encode_table[(v >> 18) & 0x3F];
    dst[j + 1] = base64_encode_table[(v >> 12) & 0x3F];

    if (i + 1 < src_len) {

      dst[j + 2] = base64_encode_table[(v >> 6) & 0x3F];

    } else {

      dst[j + 2] = '=';

    }

    if (i + 2 < src_len) {

      dst[j + 3] = base64_encode_table[v & 0x3F];

    } else {

      dst[j + 3] = '=';

    }

  }

  dst[len] = 0;
  return len;

}

#ifdef WORD_SIZE_64
static u8 cmp_extend_encodingN(afl_state_t *afl, struct cmp_header *h,
                               u128 pattern, u128 repl, u128 o_pattern,
                               u128 changed_val, u8 attr, u32 idx,
                               u32 taint_len, u8 *orig_buf, u8 *buf, u8 *cbuf,
                               u32 len, u8 do_reverse, u8 lvl, u8 *status);
#endif
static u8 cmp_extend_encoding(afl_state_t *afl, struct cmp_header *h,
                              u64 pattern, u64 repl, u64 o_pattern,
                              u64 changed_val, u8 attr, u32 idx, u32 taint_len,
                              u8 *orig_buf, u8 *buf, u8 *cbuf, u32 len,
                              u8 do_reverse, u8 lvl, u8 *status) {

  u8 *buf_8 = &buf[idx];
  // u8  *o_buf_8 = &orig_buf[idx];

  u32 its_len = MIN(len - idx, taint_len);

  if (unlikely(afl->fsrv.total_execs - last_update > screen_update)) {

    show_stats(afl);
    last_update = afl->fsrv.total_execs;

  }

  /*
  fprintf(stderr,
          "Encode: %llx->%llx into %llx(<-%llx) at idx=%u "
          "taint_len=%u shape=%u attr=%u\n",
          o_pattern, pattern, repl, changed_val, idx, taint_len,
          hshape, attr);
  */

  u8 bytes;

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
  if (unlikely(!bytes)) { return 0; }

  //  reverse atoi()/strnu?toll() is expensive, so we only to it in lvl 3
  if (afl->cmplog_enable_transform && (lvl & LVL3)) {

    u8                *endptr;
    u8                 use_num = 0, use_unum = 0;
    unsigned long long unum = 0;
    long long          num = 0;

    // if (afl->queue_cur->is_ascii) {

    // we first check if our input are ascii numbers that are transformed to
    // an integer and used for comparison:

    endptr = buf_8;
    if (strntoll(buf_8, len - idx, (char **)&endptr, 0, &num)) {

      if (!strntoull(buf_8, len - idx, (char **)&endptr, 0, &unum)) {

        use_unum = 1;

      }

    } else {

      use_num = 1;

    }

    //}

#ifdef _DEBUG
    if (idx == 0)
      fprintf(stderr,
              "ASCII is=%u use_num=%u>%lld use_unum=%u>%llu idx=%u "
              "pattern=0x%llx\n",
              afl->queue_cur->is_ascii, use_num, num, use_unum, unum, idx,
              pattern);
#endif

    // atoi("AAA") == 0 so !num means we have to investigate
    if (use_num && ((u64)num == pattern || !num)) {

      u8     tmp_buf[32];
      size_t num_len =
          snprintf(tmp_buf, sizeof(tmp_buf), "%lld", (long long)(s64)repl);
      size_t old_len = endptr - buf_8;
      size_t base_len = len - old_len;

      if (likely(num_len < sizeof(tmp_buf) && base_len <= afl->max_length &&
                 num_len <= afl->max_length - base_len)) {

        u32 new_len = base_len + num_len;
        u8 *new_buf = afl_realloc((void **)&afl->out_scratch_buf, new_len);
        if (unlikely(!new_buf)) { PFATAL("alloc"); }

        memcpy(new_buf, buf, idx);
        memcpy(new_buf + idx, tmp_buf, num_len);
        memcpy(new_buf + idx + num_len, buf_8 + old_len, len - idx - old_len);

        if (idx + num_len < new_len && new_buf[idx + num_len] >= '0' &&
            new_buf[idx + num_len] <= '9') {

          new_buf[idx + num_len] = ' ';

        }

        if (unlikely(its_fuzz(afl, new_buf, new_len, status))) { return 1; }

      }

    } else if (use_unum && (unum == pattern || !unum)) {

      u8     tmp_buf[32];
      size_t num_len =
          snprintf(tmp_buf, sizeof(tmp_buf), "%llu", (unsigned long long)repl);
      size_t old_len = endptr - buf_8;
      size_t base_len = len - old_len;

      if (likely(num_len < sizeof(tmp_buf) && base_len <= afl->max_length &&
                 num_len <= afl->max_length - base_len)) {

        u32 new_len = base_len + num_len;
        u8 *new_buf = afl_realloc((void **)&afl->out_scratch_buf, new_len);
        if (unlikely(!new_buf)) { PFATAL("alloc"); }

        memcpy(new_buf, buf, idx);
        memcpy(new_buf + idx, tmp_buf, num_len);
        memcpy(new_buf + idx + num_len, buf_8 + old_len, len - idx - old_len);

        if (idx + num_len < new_len && new_buf[idx + num_len] >= '0' &&
            new_buf[idx + num_len] <= '9') {

          new_buf[idx + num_len] = ' ';

        }

        if (unlikely(its_fuzz(afl, new_buf, new_len, status))) { return 1; }

      }

    }

    // Try to identify transform magic
    if (pattern != o_pattern && repl == changed_val &&
        (cmp_attr_is_equality(attr) || attr == CMP_ATTR_NONE)) {

      u64 b_val, o_b_val, mask;
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

          b_val = cmp_load16(&buf[idx]);
          o_b_val = cmp_load16(&orig_buf[idx]);
          mask = 0xffff;
          break;

        }

        case 4:
        case 5:
        case 6:
        case 7: {

          b_val = cmp_load32(&buf[idx]);
          o_b_val = cmp_load32(&orig_buf[idx]);
          mask = 0xffffffff;
          break;

        }

        default: {

          b_val = cmp_load64(&buf[idx]);
          o_b_val = cmp_load64(&orig_buf[idx]);
          mask = 0xffffffffffffffff;

        }

      }

      // test for arithmetic, eg. "if ((user_val - 0x1111) == 0x1234) ..."
      s64 diff = pattern - b_val;
      s64 o_diff = o_pattern - o_b_val;
      /*
             fprintf(stderr, "DIFF1 idx=%03u shape=%02u %llx-%llx=%lx\n", idx,
                       hshape, o_pattern, o_b_val, o_diff);
               fprintf(stderr, "DIFF1 %016llx %llx-%llx=%lx\n", repl, pattern,
                       b_val, diff);
      */
      if (diff == o_diff && diff) {

        // this could be an arithmetic transformation

        u64 new_repl = (u64)((s64)repl - diff);
        // fprintf(stderr, "SAME DIFF %llx->%llx\n", repl, new_repl);

        if (unlikely(cmp_extend_encoding(
                afl, h, pattern, new_repl, o_pattern, repl, CMP_ATTR_TRANSFORM,
                idx, taint_len, orig_buf, buf, cbuf, len, 1, lvl, status))) {

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

          if (unlikely(cmp_extend_encoding(afl, h, pattern, new_repl, o_pattern,
                                           repl, CMP_ATTR_TRANSFORM, idx,
                                           taint_len, orig_buf, buf, cbuf, len,
                                           1, lvl, status))) {

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

          o_diff = 0;

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

          if (unlikely(cmp_extend_encoding(afl, h, pattern, new_repl, o_pattern,
                                           repl, CMP_ATTR_TRANSFORM, idx,
                                           taint_len, orig_buf, buf, cbuf, len,
                                           1, lvl, status))) {

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

          if (unlikely(cmp_extend_encoding(afl, h, pattern, new_repl, o_pattern,
                                           repl, CMP_ATTR_TRANSFORM, idx,
                                           taint_len, orig_buf, buf, cbuf, len,
                                           1, lvl, status))) {

            return 1;

          }

          // if (*status == 1) { fprintf(stderr, "FOUND!\n"); }

        }

      }

      *status = 0;

    }

  }

  // #endif

  // we only allow this for ascii2integer (above) so leave if this is the case
  if (unlikely(pattern == o_pattern)) { return 0; }

  if ((lvl & LVL1) || cmp_attr_is_internal(attr)) {

    if (hshape >= 8 && *status != 1) {

      // if (its_len >= 8)
      //   fprintf(stderr,
      //           "TestU64: %u>=8 (idx=%u attr=%u) %llx==%llx"
      //           " %llx==%llx <= %llx<-%llx\n",
      //           its_len, idx, attr, *buf_64, pattern, *o_buf_64, o_pattern,
      //           repl, changed_val);

      u64 buf_value = its_len >= 8 ? cmp_load64(buf + idx) : 0;
      u64 orig_value = its_len >= 8 ? cmp_load64(orig_buf + idx) : 0;
      if (its_len >= 8 && ((buf_value == pattern && orig_value == o_pattern) ||
                           cmp_attr_is_internal(attr))) {

        u64 tmp_64 = buf_value;
        cmp_store64(buf + idx, repl);
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, buf + idx, 8); }
#endif
        cmp_store64(buf + idx, tmp_64);

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

      u32 buf_value = its_len >= 4 ? cmp_load32(buf + idx) : 0;
      u32 orig_value = its_len >= 4 ? cmp_load32(orig_buf + idx) : 0;
      if (its_len >= 4 &&
          ((buf_value == (u32)pattern && orig_value == (u32)o_pattern) ||
           cmp_attr_is_internal(attr))) {

        u32 tmp_32 = buf_value;
        cmp_store32(buf + idx, (u32)repl);
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, buf + idx, 4); }
#endif
        cmp_store32(buf + idx, tmp_32);

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

      u16 buf_value = its_len >= 2 ? cmp_load16(buf + idx) : 0;
      u16 orig_value = its_len >= 2 ? cmp_load16(orig_buf + idx) : 0;
      if (its_len >= 2 &&
          ((buf_value == (u16)pattern && orig_value == (u16)o_pattern) ||
           cmp_attr_is_internal(attr))) {

        u16 tmp_16 = buf_value;
        cmp_store16(buf + idx, (u16)repl);
        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, buf + idx, 2); }
#endif
        cmp_store16(buf + idx, tmp_16);

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
          ((*buf_8 == (u8)pattern && orig_buf[idx] == (u8)o_pattern) ||
           cmp_attr_is_internal(attr))) {

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

  // If 'S' is set for cmplog mode then we try a scale encoding of the value.
  // Currently we can only handle bytes up to 1 << 55 on 32 bit and 1 << 119
  // on 64 bit systems.
  // Caveat: This implementation here works only on little endian systems.

  if (cmp_attr_is_integer(attr) && (afl->cmplog_enable_scale || lvl >= LVL3) &&
      repl == changed_val) {

    u8  do_call = 1;
    u64 new_val = repl << 2;
    u32 ilen = 0;

    if (changed_val <= 255) {

      ilen = 1;

    } else if (new_val <= 65535) {

      new_val += 1;  // two byte mode
      ilen = 2;

    } else if (new_val <= 4294967295) {

      new_val += 2;  // four byte mode
      ilen = 4;

    } else {

#ifndef WORD_SIZE_64
      if (repl <= 0x00ffffffffffffff) {

        new_val = repl << 8;
        u8  scale_len = 0;
        u64 tmp_val = repl;
        while (tmp_val) {

          tmp_val >>= 8;
          ++scale_len;

        }  // scale_len will be >= 4;

        if (scale_len >= 4) {

          scale_len -= 4;

        } else {

          scale_len = 0;

        };

        new_val += (scale_len << 2) + 3;
        ilen = scale_len + 5;

      } else {

        do_call = 0;

      }

#else
      {

        u128 new_vall = ((u128)repl) << 8;
        u8   scale_len = 0;
        u128 tmp_val = (u128)repl;

        while (tmp_val) {

          tmp_val >>= 8;
          ++scale_len;

        }  // scale_len will be >= 4;

        if (scale_len >= 4) {

          scale_len -= 4;

        } else {

          scale_len = 0;

        };

        new_vall += (scale_len << 2) + 3;
        ilen = scale_len + 5;

        if (ilen <= its_len && ilen > 1) {

          u8 tmpbuf[32];
          memcpy(tmpbuf, buf + idx, ilen);
          memcpy(buf + idx, (char *)&new_vall, ilen);

          if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
  #ifdef CMPLOG_COMBINE
          if (*status == 1) { memcpy(cbuf + idx, (char *)&new_vall, ilen); }
  #endif
          memcpy(buf + idx, tmpbuf, ilen);

        };

        do_call = 0;

      }

#endif

    }

    if (do_call) {

      if (ilen <= its_len && ilen > 1) {

        u8 tmpbuf[32];
        memcpy(tmpbuf, buf + idx, ilen);
        memcpy(buf + idx, (char *)&new_val, ilen);

        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
#ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, (char *)&new_val, ilen); }
#endif
        memcpy(buf + idx, tmpbuf, ilen);

      };

    }

  }

  // move relational replacements across the nearest representable boundary
  if (!afl->cmplog_enable_arith || lvl < LVL3 || attr == CMP_ATTR_TRANSFORM) {

    return 0;

  }

  int direction = 0;
  switch (attr) {

    case CMP_ATTR_ICMP_UGT:
    case CMP_ATTR_ICMP_SGT:
    case CMP_ATTR_ICMP_ULE:
    case CMP_ATTR_ICMP_SLE:
    case CMP_ATTR_FCMP_OGT:
    case CMP_ATTR_FCMP_UGT:
    case CMP_ATTR_FCMP_OLE:
    case CMP_ATTR_FCMP_ULE:
      direction = 1;
      break;
    case CMP_ATTR_ICMP_ULT:
    case CMP_ATTR_ICMP_SLT:
    case CMP_ATTR_ICMP_UGE:
    case CMP_ATTR_ICMP_SGE:
    case CMP_ATTR_FCMP_OLT:
    case CMP_ATTR_FCMP_ULT:
    case CMP_ATTR_FCMP_OGE:
    case CMP_ATTR_FCMP_UGE:
      direction = -1;
      break;
    default:
      return 0;

  }

  u64 repl_new = 0;
  if (cmp_attr_is_fp(attr)) {

    if (hshape == 4 && its_len >= 4) {

      u32   bits = (u32)repl;
      float value;
      memcpy(&value, &bits, sizeof(value));
      if (isnan(value)) { return 0; }
      float next = nextafterf(value, direction > 0 ? INFINITY : -INFINITY);
      u32   next_bits;
      memcpy(&next_bits, &next, sizeof(next_bits));
      if (next_bits == bits) { return 0; }
      repl_new = next_bits;

      changed_val = repl_new;
      if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                       changed_val, CMP_ATTR_MOD_FLOAT, idx,
                                       taint_len, orig_buf, buf, cbuf, len, 1,
                                       lvl, status))) {

        return 1;

      }

    } else if (hshape == 8 && its_len >= 8) {

      double value;
      memcpy(&value, &repl, sizeof(value));
      if (!isnan(value)) {

        double next = nextafter(value, direction > 0 ? INFINITY : -INFINITY);
        memcpy(&repl_new, &next, sizeof(next));
        if (repl_new != repl) {

          changed_val = repl_new;
          if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                           changed_val, CMP_ATTR_MOD_FLOAT, idx,
                                           taint_len, orig_buf, buf, cbuf, len,
                                           1, lvl, status))) {

            return 1;

          }

        }

      }

    } else {

      return 0;

    }

    if (hshape == 8 && its_len >= 4) {

      double value;
      float  narrowed;
      memcpy(&value, &repl, sizeof(value));
      narrowed = (float)value;
      repl_new = 0;
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
      memcpy(&repl_new, &narrowed, sizeof(narrowed));
#else
      memcpy((u8 *)&repl_new + 4, &narrowed, sizeof(narrowed));
#endif
      changed_val = repl_new;
      hshape = 4;
      if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                       changed_val, CMP_ATTR_MOD_FLOAT, idx,
                                       taint_len, orig_buf, buf, cbuf, len, 1,
                                       lvl, status))) {

        hshape = 8;
        return 1;

      }

      hshape = 8;

    }

  } else if (cmp_attr_is_integer(attr)) {

    u32 value_bytes;
    switch (hshape) {

      case 1:
        value_bytes = 1;
        break;
      case 2:
        value_bytes = 2;
        break;
      case 3:
      case 4:
        value_bytes = 4;
        break;
      default:
        value_bytes = 8;

    }

    if (its_len < value_bytes) { return 0; }
    u32 bits = value_bytes * 8;
    u64 mask = bits == 64 ? UINT64_MAX : (1ULL << bits) - 1;
    u64 raw = repl & mask;
    if (cmp_attr_is_signed(attr)) {

      u64 minimum = 1ULL << (bits - 1);
      u64 maximum = minimum - 1;
      if ((direction > 0 && raw == maximum) ||
          (direction < 0 && raw == minimum)) {

        return 0;

      }

    } else if ((direction > 0 && raw == mask) || (direction < 0 && !raw)) {

      return 0;

    }

    repl_new = direction > 0 ? raw + 1 : raw - 1;
    repl_new &= mask;
    changed_val = repl_new;
    if (unlikely(cmp_extend_encoding(afl, h, pattern, repl_new, o_pattern,
                                     changed_val, CMP_ATTR_MOD_INTEGER, idx,
                                     taint_len, orig_buf, buf, cbuf, len, 1,
                                     lvl, status))) {

      return 1;

    }

  }

  return 0;

}

#ifdef WORD_SIZE_64

static u8 cmp_extend_encodingN(afl_state_t *afl, struct cmp_header *h,
                               u128 pattern, u128 repl, u128 o_pattern,
                               u128 changed_val, u8 attr, u32 idx,
                               u32 taint_len, u8 *orig_buf, u8 *buf, u8 *cbuf,
                               u32 len, u8 do_reverse, u8 lvl, u8 *status) {

  if (unlikely(afl->fsrv.total_execs - last_update > screen_update)) {

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

    // Scale encoding only works on little endian systems

    if (cmp_attr_is_integer(attr) &&
        (afl->cmplog_enable_scale || lvl >= LVL3)) {

      u128 new_val = repl << 2;
      u128 max_scale = (u128)1 << 120;
      u32  ilen = 0;
      u8   do_call = 1;

      if (new_val <= 255) {

        ilen = 1;

      } else if (new_val <= 65535) {

        new_val += 1;  // two byte mode
        ilen = 2;

      } else if (new_val <= 4294967295) {

        new_val += 2;  // four byte mode
        ilen = 4;

      } else if (repl < max_scale) {

        new_val = (u128)repl << 8;
        u8   scale_len = 0;
        u128 tmp_val = (u128)repl;
        while (tmp_val) {

          tmp_val >>= 8;
          ++scale_len;

        }  // scale_len will be >= 4;

        if (scale_len >= 4) {

          scale_len -= 4;

        } else {

          scale_len = 0;

        };

        new_val += (scale_len << 2) + 3;
        ilen = scale_len + 5;

      } else {

        do_call = 0;

      }

      if (do_call && ilen <= its_len) {

        u8 tmpbuf[32];
        memcpy(tmpbuf, buf + idx, ilen);
        memcpy(buf + idx, (char *)&new_val, ilen);

        if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
  #ifdef CMPLOG_COMBINE
        if (*status == 1) { memcpy(cbuf + idx, (char *)&new_val, ilen); }
  #endif
        memcpy(buf + idx, tmpbuf, ilen);

      };

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
  u32 off = 16 - size;
  for (k = 16 - size; k < 16; ++k) {

  #endif
    if (b[k] == 0) {

      ++cons_0;

    } else if (b[k] == 0xff) {

      ++cons_ff;

    } else {

      cons_0 = cons_ff = 0;

    }

    if (cons_0 > 1 || cons_ff > 1) { return; }

  }

  maybe_add_auto(afl, (u8 *)&v + off, size);
  u128 rev = SWAPN(v, size);
  maybe_add_auto(afl, (u8 *)&rev + off, size);

}

#endif

static u8 cmp_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u8 *cbuf,
                   u32 len, u32 lvl, struct tainted *taint) {

  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  struct cmp_header *orig_h = &afl->orig_cmp_map->headers[key];
  struct tainted    *t;
  u32                i, j, idx, taint_len, loggeds, orig_loggeds;
  u32                have_taint = 1;
  u8                 status = 0, found_one = 0;
  u8                 attr = cmp_map_attribute(afl->shm.cmp_map, key);
  u8 orig_attr = cmp_map_snapshot_attribute(afl->orig_cmp_map, key);

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

  if (!orig_h->hits ||
      afl->orig_cmp_map->site_ids[key] != afl->shm.cmp_map->site_ids[key] ||
      orig_h->type != h->type || orig_h->shape != h->shape ||
      orig_attr != attr) {

    return 0;

  }

  loggeds = MIN((u32)h->hits, (u32)CMP_MAP_H);
  orig_loggeds = MIN((u32)orig_h->hits, (u32)CMP_MAP_H);
  loggeds = MIN(loggeds, orig_loggeds);
  struct cmp_operands *orig_log = cmp_map_snapshot_log(afl->orig_cmp_map, key);

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

    // add agressively to dictionary in starved mode
    if (unlikely(afl->starved)) {

      u32 asz = hshape > 8 ? 8 : hshape;
      maybe_add_auto(afl, (u8 *)&o->v1, asz);
      maybe_add_auto(afl, (u8 *)&o->v0, asz);

    }

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

    struct cmp_operands *orig_o = NULL;
    if (!afl->shm.cmp_map->site_ids[key]) {

      orig_o = &orig_log[i];

    } else {

      for (u32 orig_i = 0; orig_i < orig_loggeds; ++orig_i) {

        if (orig_log[orig_i].occurrence == o->occurrence) {

          orig_o = &orig_log[orig_i];
          break;

        }

      }

    }

    if (!orig_o) { goto cmp_fuzz_next_iter; }

    // opt not in the paper
    for (j = 0; j < i; ++j) {

      if (afl->shm.cmp_map->log[key][j].v0 == o->v0 &&
          afl->shm.cmp_map->log[key][j].v1 == o->v1) {

        goto cmp_fuzz_next_iter;

      }

    }

#ifdef USE_HASHMAP
    // TODO: add attribute? not sure
    if (hshape <= 8 && hashmap_search_and_add(hshape - 1, o->v0) &&
        hashmap_search_and_add(hshape - 1, orig_o->v0) &&
        hashmap_search_and_add(hshape - 1, o->v1) &&
        hashmap_search_and_add(hshape - 1, orig_o->v1)) {

      continue;

    }

#endif

#ifdef _DEBUG
    fprintf(stderr, "Handling: %llx->%llx vs %llx->%llx attr=%u shape=%u\n",
            orig_o->v0, o->v0, orig_o->v1, o->v1, attr, hshape);
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
                  afl, h, s128_v0, s128_v1, orig_s128_v0, orig_s128_v1, attr,
                  idx, taint_len, orig_buf, buf, cbuf, len, 1, lvl, &status))) {

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
                  cmp_attr_swap(attr), idx, taint_len, orig_buf, buf, cbuf, len,
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
                afl, h, o->v0, o->v1, orig_o->v0, orig_o->v1, attr, idx,
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
                                         orig_o->v0, cmp_attr_swap(attr), idx,
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
            orig_o->v0, o->v0, orig_o->v1, o->v1, attr, i, found_one, is_n,
            hshape);
#endif

    // we only learn 16 bit +
    if (hshape > 1) {

      if (!found_one || afl->queue_cur->is_ascii) {

#ifdef WORD_SIZE_64
        if (unlikely(is_n)) {

          if (!found_one ||
              check_if_text_buf((u8 *)&s128_v0, SHAPE_BYTES(h->shape)) ==
                  (u32)SHAPE_BYTES(h->shape))
            try_to_add_to_dictN(afl, s128_v0, SHAPE_BYTES(h->shape));
          if (!found_one ||
              check_if_text_buf((u8 *)&s128_v1, SHAPE_BYTES(h->shape)) ==
                  (u32)SHAPE_BYTES(h->shape))
            try_to_add_to_dictN(afl, s128_v1, SHAPE_BYTES(h->shape));

        } else

#endif
        {

          if (!memcmp((u8 *)&o->v0, (u8 *)&orig_o->v0, SHAPE_BYTES(h->shape)) &&
              (!found_one ||
               check_if_text_buf((u8 *)&o->v0, SHAPE_BYTES(h->shape)) ==
                   (u32)SHAPE_BYTES(h->shape)))
            try_to_add_to_dict(afl, o->v0, SHAPE_BYTES(h->shape));
          if (!memcmp((u8 *)&o->v1, (u8 *)&orig_o->v1, SHAPE_BYTES(h->shape)) &&
              (!found_one ||
               check_if_text_buf((u8 *)&o->v1, SHAPE_BYTES(h->shape)) ==
                   (u32)SHAPE_BYTES(h->shape)))
            try_to_add_to_dict(afl, o->v1, SHAPE_BYTES(h->shape));

        }

      }

    }

  cmp_fuzz_next_iter:
    afl->stage_cur++;

  }

  u8 loop =
      loggeds > 3 && ((s_v0_fixed && s_v1_inc) || (s_v1_fixed && s_v0_inc) ||
                      (s_v0_fixed && s_v1_dec) || (s_v1_fixed && s_v0_dec));
  cmp_pass_record(&afl->pass_stats[key], found_one, loop);

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
  // #ifndef CMPLOG_SOLVE_TRANSFORM
  //   (void)(changed_val);
  // #endif

  if (unlikely(afl->fsrv.total_execs - last_update > screen_update)) {

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

  l0 &= 0x7f;
  l1 &= 0x7f;
  ol0 &= 0x7f;
  ol1 &= 0x7f;

  if (l0 == 0 || l1 == 0 || ol0 == 0 || ol1 == 0 || l0 > 32 || l1 > 32 ||
      ol0 > 32 || ol1 > 32) {

    return 0;

  }

  u8  lmax = MIN(MIN(l0, l1), MIN(ol0, ol1));
  u8  save[80];
  u32 saved_idx = idx, pre, from = 0, to = 0, i, j;
  u32 its_len = MIN(MIN(lmax, hshape), len - idx);
  its_len = MIN(its_len, taint_len);
  if (o->unused) { its_len = MIN(its_len, (u32)o->unused); }
  if (orig_o->unused) { its_len = MIN(its_len, (u32)orig_o->unused); }
  u32 saved_its_len = its_len;

  // fprintf(stderr, "its_len=%u repl=%s\n", its_len, repl);

  if (!its_len) { return 0; }

  if (lvl & LVL3) {

    if (memcmp(changed_val, repl, its_len) != 0) { return 0; }

    u32 max_to = MIN(MIN(4U, idx), lmax - saved_its_len);
    if (!(lvl & LVL1) && max_to) { from = 1; }
    to = max_to;

  }

  memcpy(save, &buf[saved_idx - to], its_len + to);
  (void)(j);

#ifdef _DEBUG
  if (idx == 0) {

    u32 debug_len = MIN(MIN(8U, (u32)lmax), len - idx);
    fprintf(stderr, "RTN T idx=%u lvl=%02x is_txt=%u shape=%u/%u ", idx, lvl,
            o->v0_len >= 0x80 ? 1 : 0, hshape, l0);
    for (j = 0; j < debug_len; j++)
      fprintf(stderr, "%02x", orig_buf[idx + j]);
    fprintf(stderr, " -> ");
    for (j = 0; j < debug_len; j++)
      fprintf(stderr, "%02x", o_pattern[j]);
    fprintf(stderr, " <= ");
    for (j = 0; j < debug_len; j++)
      fprintf(stderr, "%02x", repl[j]);
    fprintf(stderr, "\n");
    fprintf(stderr, "                ");
    for (j = 0; j < debug_len; j++)
      fprintf(stderr, "%02x", buf[idx + j]);
    fprintf(stderr, " -> ");
    for (j = 0; j < debug_len; j++)
      fprintf(stderr, "%02x", pattern[j]);
    fprintf(stderr, " <= ");
    for (j = 0; j < debug_len; j++)
      fprintf(stderr, "%02x", changed_val[j]);
    fprintf(stderr, "\n");

  }

#endif

  // Try to match the replace value up to 4 bytes before the current idx.
  // This allows matching of eg.:
  //   if (memcmp(user_val, "TEST") == 0)
  //     if (memcmp(user_val, "TEST-VALUE") == 0) ...
  // We only do this in lvl 3, otherwise we only do direct matching

  // fprintf(stderr, "XXXX FROMB64 saved_idx=%u its_len=%u from=%u to=%u FROMHEX
  // repl=%s\n", saved_idx, saved_its_len, from, to, repl);

  for (pre = from; pre <= to; pre++) {

    if (*status != 1 && (!pre || !memcmp(buf + saved_idx - pre, repl, pre))) {

      idx = saved_idx - pre;
      its_len = saved_its_len + pre;

      for (i = 0; i < its_len; ++i) {

        if ((pattern[i] != buf[idx + i] || o_pattern[i] != orig_buf[idx + i]) ||
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
    u32 tob64 = 0, fromb64 = 0;
    u32 from_0 = 0, from_x = 0, from_X = 0, from_slash = 0, from_up = 0;
    u32 to_0 = 0, to_x = 0, to_slash = 0, to_up = 0;
    u8  xor_val[64], arith_val[64], tmp[64];

    idx = saved_idx;
    its_len = saved_its_len;

    u32 save_len = MIN((u32)sizeof(save), len - idx);
    memcpy(save, &buf[idx], save_len);

    for (i = 0; i < its_len; ++i) {

      memcpy(&buf[idx], save, save_len);

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

      if (afl->cmplog_enable_xtreme_transform && i < 16 && (i << 1) + 2 <= l1 &&
          is_hex(repl + (i << 1))) {

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

      if (afl->cmplog_enable_xtreme_transform && (i % 2) == 1) {

        if (len > idx + i + 1 && is_hex(orig_buf + idx + i - 1)) {

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

      if (afl->cmplog_enable_xtreme_transform) {

        if (i % 3 == 2 && i < 24 && ((i / 3) << 2) + 4 <= l1) {

          if (is_base64(repl + ((i / 3) << 2))) tob64 += 3;

        }

        // fprintf(stderr, "X FROMB64 idx=%u i=%u repl=%s\n", saved_idx, i,
        // repl);
        if (i % 4 == 3 && i < 24) {

          if (is_base64(orig_buf + idx + i - 3)) fromb64 += 4;

        }

      }

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
      if (idx == 0) {

        fprintf(stderr, "RTN Z %s %s %s %s repl=%s\n", buf, pattern, orig_buf,
                o_pattern, repl);
        fprintf(
            stderr,
            "RTN Z idx=%u len=%u loop=%u xor=%u arith=%u tolower=%u toupper=%u "
            "tohex=%u fromhex=%u to_0=%u to_slash=%u to_x=%u "
            "from_0=%u from_slash=%u from_x=%u\n",
            idx, its_len, i, xor, arith, tolower, toupper, tohex, fromhex, to_0,
            to_slash, to_x, from_0, from_slash, from_x);
        if (afl->cmplog_enable_xtreme_transform) {

          fprintf(stderr, "RTN Z idx=%u loop=%u tob64=%u from64=%u\n", idx, i,
                  tob64, fromb64);

        }

      }

#endif

      if (afl->cmplog_enable_xtreme_transform) {

        // input is base64 and converted to binary? convert repl to base64!
        // fprintf(stderr, "FROMB64 idx=%u i=%u %% 4 == 3 && i < 24 &&
        // fromb64=%u > i, repl=%s\n", saved_idx, i, fromb64, repl);
        if ((i % 4) == 3 && i < 24 && fromb64 > i) {

          for (u32 hlen = i; hlen + saved_idx < len && hlen <= its_len;
               ++hlen) {

            u32 res = to_base64(repl, tmp, hlen);
            // fprintf(stderr, "FROMB64 GOGO! idx=%u repl=%s tmp[%u]=%s
            // hlen=%u\n", saved_idx, repl, res, tmp, hlen);
            if (res + saved_idx < len) {

              memcpy(buf + idx, tmp, res);
              if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
              // fprintf(stderr, "RTN ATTEMPT FROMB64 idx=%u fromb64 %u %s %s
              // result %u\n",       saved_idx,      fromb64,      tmp, repl,
              // *status);

            }

          }

        }

        // input is converted to base64? decode repl with base64!
        if ((i % 3) == 2 && i < 24 && tob64 > i) {

          u32 olen = from_base64(repl, tmp, i + 1);
          memcpy(buf + idx, tmp, olen);
          if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
          // fprintf(stderr, "RTN ATTEMPT tob64 %u idx=%u result %u\n", tob64,
          // idx, *status);

        }

      }

      // input is converted to hex? convert repl to binary!
      if (afl->cmplog_enable_xtreme_transform && i < 16 && tohex > i) {

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
      if (afl->cmplog_enable_xtreme_transform && (i % 2) == 1 && i < 16 &&
          fromhex && fromhex + from_slash + from_x + from_0 > i) {

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

        for (u32 hlen = i; hlen <= (i << 1) && hlen + idx < len; hlen += i) {

          if (to_up == 1) {

            for (j = 0; j <= (hlen >> 1); j++) {

              tmp[off + (j << 1)] = hex_table_up[repl[j] >> 4];
              tmp[off + (j << 1) + 1] = hex_table_up[repl[j] % 16];

            }

          } else {

            for (j = 0; j <= (hlen >> 1); j++) {

              tmp[off + (j << 1)] = hex_table_low[repl[j] >> 4];
              tmp[off + (j << 1) + 1] = hex_table_low[repl[j] % 16];

            }

          }

          u32 tmp_l = 2 * ((hlen >> 1) + 1) + off;
          if (tmp_l > len - idx || tmp_l >= sizeof(tmp)) { continue; }
          memcpy(buf + idx, tmp, tmp_l);
          if (unlikely(its_fuzz(afl, buf, len, status))) { return 1; }
          tmp[tmp_l] = 0;
          // fprintf(stderr, "RTN ATTEMPT idx=%u len=%u fromhex %u %s %s result
          // %u\n", idx, len, fromhex, tmp, repl, *status);
          memcpy(buf + idx, save, tmp_l);

        }

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
                (fromhex + from_0 + from_x + from_slash + 1) &&
            (afl->cmplog_enable_xtreme_transform && i > tob64 + 3 &&
             i > fromb64 + 4))) ||
          repl[i] != changed_val[i] || *status == 1) {

        break;

      }

    }

    memcpy(&buf[idx], save, save_len);

  }

  return 0;

}

static u8 rtn_fuzz(afl_state_t *afl, u32 key, u8 *orig_buf, u8 *buf, u8 *cbuf,
                   u32 len, u8 lvl, struct tainted *taint) {

  struct tainted    *t;
  struct cmp_header *h = &afl->shm.cmp_map->headers[key];
  struct cmp_header *orig_h = &afl->orig_cmp_map->headers[key];
  u32                i, idx, have_taint = 1, taint_len, loggeds, orig_loggeds;
  u8                 status = 0, found_one = 0;
  u8                 attr = cmp_map_attribute(afl->shm.cmp_map, key);
  u8 orig_attr = cmp_map_snapshot_attribute(afl->orig_cmp_map, key);

  hshape = SHAPE_BYTES(h->shape);

  if (!orig_h->hits ||
      afl->orig_cmp_map->site_ids[key] != afl->shm.cmp_map->site_ids[key] ||
      orig_h->type != h->type || orig_attr != attr) {

    return 0;

  }

  loggeds = MIN((u32)h->hits, (u32)CMP_MAP_RTN_H);
  orig_loggeds = MIN((u32)orig_h->hits, (u32)CMP_MAP_RTN_H);
  loggeds = MIN(loggeds, orig_loggeds);
  struct cmpfn_operands *orig_log =
      (struct cmpfn_operands *)cmp_map_snapshot_log(afl->orig_cmp_map, key);

  for (i = 0; i < loggeds; ++i) {

    struct cmpfn_operands *o =
        &((struct cmpfn_operands *)afl->shm.cmp_map->log[key])[i];

    // agressively add dictionary entries if starved
    if (unlikely(afl->starved)) {

      if (o->v1_len && o->v1_len <= 32) {

        maybe_add_auto(afl, o->v1, o->v1_len);

      }

      if (o->v0_len && o->v0_len <= 32) {

        maybe_add_auto(afl, o->v0, o->v0_len);

      }

    }

    struct cmpfn_operands *orig_o = NULL;
    if (!afl->shm.cmp_map->site_ids[key]) {

      orig_o = &orig_log[i];

    } else {

      for (u32 orig_i = 0; orig_i < orig_loggeds; ++orig_i) {

        if (orig_log[orig_i].occurrence == o->occurrence) {

          orig_o = &orig_log[orig_i];
          break;

        }

      }

    }

    if (!orig_o) { goto rtn_fuzz_next_iter; }

    u32 v0_len = o->v0_len & 0x7f;
    u32 v1_len = o->v1_len & 0x7f;
    u32 orig_v0_len = orig_o->v0_len & 0x7f;
    u32 orig_v1_len = orig_o->v1_len & 0x7f;
    if (!v0_len || !v1_len || !orig_v0_len || !orig_v1_len || v0_len > 32 ||
        v1_len > 32 || orig_v0_len > 32 || orig_v1_len > 32) {

      goto rtn_fuzz_next_iter;

    }

    /*
        // opt not in the paper
        for (j = 0; j < i; ++j) {

          if (!memcmp(&((struct cmpfn_operands *)afl->shm.cmp_map->log[key])[j],
       o, sizeof(struct cmpfn_operands))) {

            goto rtn_fuzz_next_iter;

          }

        }

    */

#ifdef _DEBUG
    u32                j;
    struct cmp_header *hh = &afl->orig_cmp_map->headers[key];
    fprintf(stderr, "RTN N hits=%u shape=%u attr=%u v0=", h->hits, hshape,
            attr);
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", o->v0[j]);
    fprintf(stderr, " v1=");
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", o->v1[j]);
    fprintf(stderr, "\nRTN O hits=%u shape=%u attr=%u o0=", hh->hits, hshape,
            orig_attr);
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", orig_o->v0[j]);
    fprintf(stderr, " o1=");
    for (j = 0; j < 8; j++)
      fprintf(stderr, "%02x", orig_o->v1[j]);
    fprintf(stderr, "\n");
#endif

#ifdef USE_HASHMAP
    if (hshape <= 8 && hashmap_search_and_add_ptr(hshape - 1, o->v0) &&
        hashmap_search_and_add_ptr(hshape - 1, orig_o->v0) &&
        hashmap_search_and_add_ptr(hshape - 1, o->v1) &&
        hashmap_search_and_add_ptr(hshape - 1, orig_o->v1)) {

      continue;

    }

#endif

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
      u32 w;
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

      u8 v0_same = v0_len == orig_v0_len && !memcmp(o->v0, orig_o->v0, v0_len);
      u8 v1_same = v1_len == orig_v1_len && !memcmp(o->v1, orig_o->v1, v1_len);

      // fprintf(stderr, "SHOULD: found:%u ascii:%u text?%u:%u %u:%s %u:%s \n",
      // found_one, afl->queue_cur->is_ascii, check_if_text_buf((u8 *)&o->v0,
      // shape_len), check_if_text_buf((u8 *)&o->v1, shape_len), v0_len,
      // o->v0, v1_len, o->v1);

      if (v0_same && ADDR_ATTR_V0(o->addr_attr) != ADDR_ATTR_NOTFOUND &&
          ADDR_ATTR_V0(orig_o->addr_attr) != ADDR_ATTR_NOTFOUND) {

        maybe_add_auto(afl, o->v0, v0_len);

      } else if (v1_same &&

                 ADDR_ATTR_V1(o->addr_attr) != ADDR_ATTR_NOTFOUND &&
                 ADDR_ATTR_V1(orig_o->addr_attr) != ADDR_ATTR_NOTFOUND) {

        maybe_add_auto(afl, o->v1, v1_len);

      } else {

        // Note that this check differs from the line 1901, for RTN we are more
        // opportunistic for adding to the dictionary than cmps
        if (v0_same &&
            (!found_one || check_if_text_buf((u8 *)&o->v0, v0_len) == v0_len) &&
            v0_len != 32)
          maybe_add_auto(afl, o->v0, v0_len);
        if (v1_same &&
            (!found_one || check_if_text_buf((u8 *)&o->v1, v1_len) == v1_len) &&
            v1_len != 32)
          maybe_add_auto(afl, o->v1, v1_len);

      }

      //}

    }

  rtn_fuzz_next_iter:
    afl->stage_cur++;

  }

  cmp_pass_record(&afl->pass_stats[key], found_one, 0);

  return 0;

}

/* If -l -M is active, scan cmp_map for inequality cmps, derive typed slack
   from v0/v1, and track per-site global minima in afl->min_slack. Marks the
   current queue entry as tightness_novel (and favoured) iff a new
   per-site min was achieved. Allocates the slack state lazily on first call. */
static void collect_tightness_minima(afl_state_t *afl) {

  if (likely(!afl->cmplog_tightness)) return;

  if (unlikely(!afl->min_slack)) {

    afl->min_slack = ck_alloc(sizeof(u64) * CMP_MAP_W);
    afl->min_slack_ids = ck_alloc(sizeof(u32) * CMP_MAP_W);
    for (u32 i = 0; i < CMP_MAP_W; ++i)
      afl->min_slack[i] = (u64)-1;

  }

  u8 found_new_min = 0;
  for (u32 k = 0; k < CMP_MAP_W; ++k) {

    struct cmp_header *h = &afl->shm.cmp_map->headers[k];
    if (!h->hits || h->type != CMP_TYPE_INS) continue;
    u8 attr = cmp_map_attribute(afl->shm.cmp_map, k);
    if (!cmp_attr_is_integer(attr) ||
        (!cmp_attr_is_greater(attr) && !cmp_attr_is_lesser(attr))) {

      continue;

    }

    u32 bytes = SHAPE_BYTES(h->shape);
    if (!bytes || bytes > 8) { continue; }
    u32 site_id = afl->shm.cmp_map->site_ids[k];
    if (afl->min_slack_ids[k] != site_id) {

      afl->min_slack_ids[k] = site_id;
      afl->min_slack[k] = UINT64_MAX;

    }

    u64 hits = h->hits > CMP_MAP_H ? CMP_MAP_H : h->hits;
    u64 best = (u64)-1;
    for (u64 i = 0; i < hits; ++i) {

      struct cmp_operands *o = &afl->shm.cmp_map->log[k][i];
      u64                  slack =
          cmp_integer_slack(o->v0, o->v1, bytes, cmp_attr_is_signed(attr));
      if (slack < best) best = slack;

    }

    if (best < afl->min_slack[k]) {

      afl->min_slack[k] = best;
      found_new_min = 1;

    }

  }

  if (found_new_min && afl->queue_cur) {

    afl->cmplog_tightness_new++;
    afl->queue_cur->tightness_novel = 1;
    /* Stamp the cycle so cull_queue can decay this flag later. */
    afl->queue_cur->tightness_novel_cycle = afl->queue_cycle;
    afl->queue_cur->favored = 1;
    afl->score_changed = 1;

  }

}

///// Input to State stage

// afl->queue_cur->exec_cksum
u8 input_to_state_stage(afl_state_t *afl, u8 *orig_buf, u8 *buf, u32 len) {

  u64 cmplog_start_us = get_cur_time_us();
  u8  r = 1;
  if (unlikely(!afl->pass_stats)) {

    afl->pass_stats = ck_alloc(sizeof(struct cmp_pass_stat) * CMP_MAP_W);

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

    if (unlikely(colorization(afl, buf, len, &taint))) {

      update_cmplog_time(afl, &cmplog_start_us);
      return 1;

    }

    // no taint? still try, create a dummy to prevent again colorization
    if (!taint) {

#ifdef _DEBUG
      fprintf(stderr, "TAINT FAILED\n");
#endif
      afl->queue_cur->colorized = CMPLOG_LVL_MAX;
      update_cmplog_time(afl, &cmplog_start_us);
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

  update_cmplog_time(afl, &cmplog_start_us);

  struct tainted *t = taint;

#ifdef _DEBUG
  while (t) {

    fprintf(stderr, "T: idx=%u len=%u\n", t->pos, t->len);
    t = t->next;

  }

#endif

#if defined(_DEBUG) || defined(CMPLOG_INTROSPECTION)
  u64 start_time = get_cur_time();
  u32 cmp_locations = 0;
#endif

  // Generate the cmplog data

  // manually clear the cmp_map metadata
  memset(afl->shm.cmp_map->headers, 0, sizeof(afl->shm.cmp_map->headers));
  memset(afl->shm.cmp_map->site_ids, 0, sizeof(afl->shm.cmp_map->site_ids));
  memset(afl->shm.cmp_map->attributes, 0, sizeof(afl->shm.cmp_map->attributes));
  if (unlikely(common_fuzz_cmplog_stuff(afl, orig_buf, len))) {

    afl->queue_cur->colorized = CMPLOG_LVL_MAX;
    while (taint) {

      t = taint->next;
      ck_free(taint);
      taint = t;

    }

    update_cmplog_time(afl, &cmplog_start_us);
    return 1;

  }

  if (unlikely(!afl->orig_cmp_map)) {

    afl->orig_cmp_map = ck_alloc(sizeof(struct cmp_map_snapshot));

  }

  u32 snapshot_size =
      cmp_map_snapshot_collect(afl->orig_cmp_map, afl->shm.cmp_map);
  if (snapshot_size > afl->orig_cmp_map->capacity) {

    afl->orig_cmp_map->log =
        afl_realloc((void **)&afl->orig_cmp_map->log,
                    snapshot_size * sizeof(*afl->orig_cmp_map->log));
    afl->orig_cmp_map->capacity = snapshot_size;

  }

  cmp_map_snapshot_copy(afl->orig_cmp_map, afl->shm.cmp_map);
  for (u32 i = 0; i < afl->orig_cmp_map->count; ++i) {

    afl->shm.cmp_map->headers[afl->orig_cmp_map->keys[i]].hits = 0;

  }

  if (unlikely(common_fuzz_cmplog_stuff(afl, buf, len))) {

    afl->queue_cur->colorized = CMPLOG_LVL_MAX;
    while (taint) {

      t = taint->next;
      ck_free(taint);
      taint = t;

    }

    update_cmplog_time(afl, &cmplog_start_us);
    return 1;

  }

#ifdef _DEBUG
  dump("ORIG", orig_buf, len);
  dump("NEW ", buf, len);
#endif

  collect_tightness_minima(afl);

  // Start insertion loop

#ifdef USE_HASHMAP
  hashmap_reset();
#endif

  u64 orig_hit_cnt, new_hit_cnt;
  u64 orig_execs = afl->fsrv.total_execs;
  orig_hit_cnt = afl->queued_items + afl->saved_crashes;
  update_cmplog_time(afl, &cmplog_start_us);

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

    if (cmp_pass_should_skip(&afl->pass_stats[k],
                             afl->shm.cmp_map->site_ids[k])) {

#ifdef _DEBUG
      fprintf(stderr, "SKIPPED %u\n", k);
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

    } else if ((lvl & LVL1) || ((lvl & LVL3) && afl->cmplog_enable_transform)) {

      if (unlikely(rtn_fuzz(afl, k, orig_buf, buf, cbuf, len, lvl, taint))) {

        goto exit_its;

      }

    }

    update_cmplog_time(afl, &cmplog_start_us);

  }

  r = 0;

exit_its:

  // if (afl->cmplog_lvl == CMPLOG_LVL_MAX) {

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

  /*} else {

    afl->queue_cur->colorized = LVL2;

    if (!afl->queue_cur->taint) { afl->queue_cur->taint = taint; }

    if (!afl->queue_cur->cmplog_colorinput) {

      afl->queue_cur->cmplog_colorinput = ck_alloc_nozero(len);
      memcpy(afl->queue_cur->cmplog_colorinput, buf, len);
      memcpy(buf, orig_buf, len);

    }

  }*/

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

  update_cmplog_time(afl, &cmplog_start_us);
  return r;

}

