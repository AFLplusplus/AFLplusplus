/*
   american fuzzy lop++ - extras relates routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"

/* helper function for auto_extras qsort */
static int compare_auto_extras_len(const void *ae1, const void *ae2) {

  return ((struct auto_extra_data *)ae1)->len -
         ((struct auto_extra_data *)ae2)->len;

}

/* descending order */

static int compare_auto_extras_use_d(const void *ae1, const void *ae2) {

  return ((struct auto_extra_data *)ae2)->hit_cnt -
         ((struct auto_extra_data *)ae1)->hit_cnt;

}

/* Helper function for load_extras. */

static int compare_extras_len(const void *e1, const void *e2) {

  return ((struct extra_data *)e1)->len - ((struct extra_data *)e2)->len;

}

/* Read extras from a file, sort by size. */

void load_extras_file(afl_state_t *afl, u8 *fname, u32 *min_len, u32 *max_len,
                      u32 dict_level) {

  FILE *f;
  u8    buf[MAX_LINE];
  u8   *lptr;
  u32   cur_line = 0;

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  f = fopen(fname, "r");

  if (!f) { PFATAL("Unable to open '%s'", fname); }

  while ((lptr = fgets(buf, MAX_LINE, f))) {

    u8 *rptr, *wptr;
    u32 klen = 0;

    ++cur_line;

    /* Trim on left and right. */

    while (isspace(*lptr)) {

      ++lptr;

    }

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr)) {

      --rptr;

    }

    ++rptr;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#') { continue; }

    /* All other lines must end with '"', which we can consume. */

    --rptr;

    if (rptr < lptr || *rptr != '"') {

      WARNF("Malformed name=\"value\" pair in line %u.", cur_line);
      continue;

    }

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_') {

      ++lptr;

    }

    /* If @number follows, parse that. */

    if (*lptr == '@') {

      ++lptr;
      if (atoi(lptr) > (s32)dict_level) { continue; }
      while (isdigit(*lptr)) {

        ++lptr;

      }

    }

    /* Skip [number] */

    if (*lptr == '[') {

      do {

        ++lptr;

      } while (*lptr >= '0' && *lptr <= '9');

      if (*lptr == ']') { ++lptr; }

    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=') {

      ++lptr;

    }

    /* Consume opening '"'. */

    if (*lptr != '"') {

      WARNF("Malformed name=\"keyword\" pair in line %u.", cur_line);
      continue;

    }

    ++lptr;

    if (!*lptr) {

      WARNF("Empty keyword in line %u.", cur_line);
      continue;

    }

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    afl->extras =
        afl_realloc((void **)&afl->extras,
                    (afl->extras_cnt + 1) * sizeof(struct extra_data));
    if (unlikely(!afl->extras)) { PFATAL("alloc"); }

    wptr = afl->extras[afl->extras_cnt].data = ck_alloc(rptr - lptr);

    if (!wptr) { PFATAL("no mem for data"); }

    while (*lptr) {

      char *hexdigits = "0123456789abcdef";

      switch (*lptr) {

        case 1 ... 31:
        case 128 ... 255:
          WARNF("Non-printable characters in line %u.", cur_line);
          continue;
          break;

        case '\\':

          ++lptr;

          if (*lptr == '\\' || *lptr == '"') {

            *(wptr++) = *(lptr++);
            klen++;
            break;

          }

          if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2])) {

            WARNF("Invalid escaping (not \\xNN) in line %u.", cur_line);
            continue;

          }

          *(wptr++) = ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
                      (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

          lptr += 3;
          ++klen;

          break;

        default:
          *(wptr++) = *(lptr++);
          ++klen;

      }

    }

    afl->extras[afl->extras_cnt].len = klen;

    if (afl->extras[afl->extras_cnt].len > MAX_DICT_FILE) {

      WARNF(
          "Keyword too big in line %u (%s, limit is %s)", cur_line,
          stringify_mem_size(val_bufs[0], sizeof(val_bufs[0]), klen),
          stringify_mem_size(val_bufs[1], sizeof(val_bufs[1]), MAX_DICT_FILE));
      continue;

    }

    if (*min_len > klen) { *min_len = klen; }
    if (*max_len < klen) { *max_len = klen; }

    ++afl->extras_cnt;

  }

  fclose(f);

}

static void extras_check_and_sort(afl_state_t *afl, u32 min_len, u32 max_len,
                                  u8 *dir) {

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  if (!afl->extras_cnt) {

    WARNF("No usable data in '%s'", dir);
    return;

  }

  qsort(afl->extras, afl->extras_cnt, sizeof(struct extra_data),
        compare_extras_len);

  ACTF("Loaded %u extra tokens, size range %s to %s.", afl->extras_cnt,
       stringify_mem_size(val_bufs[0], sizeof(val_bufs[0]), min_len),
       stringify_mem_size(val_bufs[1], sizeof(val_bufs[1]), max_len));

  if (max_len > 32) {

    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          stringify_mem_size(val_bufs[0], sizeof(val_bufs[0]), max_len));

  }

  if (afl->extras_cnt > afl->max_det_extras) {

    WARNF("More than %u tokens - will use them probabilistically.",
          afl->max_det_extras);

  }

}

/* Read extras from the extras directory and sort them by size. */

void load_extras(afl_state_t *afl, u8 *dir) {

  DIR           *d;
  struct dirent *de;
  u32            min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8            *x;

  u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr(dir, '@'))) {

    *x = 0;
    dict_level = atoi(x + 1);

  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);

  if (!d) {

    if (errno == ENOTDIR) {

      load_extras_file(afl, dir, &min_len, &max_len, dict_level);
      extras_check_and_sort(afl, min_len, max_len, dir);
      return;

    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (x) { FATAL("Dictionary levels not supported for directories."); }

  while ((de = readdir(d))) {

    struct stat st;
    u8         *fn = alloc_printf("%s/%s", dir, de->d_name);
    s32         fd;

    if (lstat(fn, &st) || access(fn, R_OK)) {

      PFATAL("Unable to access '%s'", fn);

    }

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_DICT_FILE) {

      WARNF(
          "Extra '%s' is too big (%s, limit is %s)", fn,
          stringify_mem_size(val_bufs[0], sizeof(val_bufs[0]), st.st_size),
          stringify_mem_size(val_bufs[1], sizeof(val_bufs[1]), MAX_DICT_FILE));
      continue;

    }

    if (min_len > st.st_size) { min_len = st.st_size; }
    if (max_len < st.st_size) { max_len = st.st_size; }

    afl->extras =
        afl_realloc((void **)&afl->extras,
                    (afl->extras_cnt + 1) * sizeof(struct extra_data));
    if (unlikely(!afl->extras)) { PFATAL("alloc"); }

    afl->extras[afl->extras_cnt].data = ck_alloc(st.st_size);
    afl->extras[afl->extras_cnt].len = st.st_size;

    fd = open(fn, O_RDONLY);

    if (fd < 0) { PFATAL("Unable to open '%s'", fn); }

    ck_read(fd, afl->extras[afl->extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    ++afl->extras_cnt;

  }

  closedir(d);

  extras_check_and_sort(afl, min_len, max_len, dir);

}

/* Helper function for maybe_add_auto(afl, ) */

static inline u8 memcmp_nocase(u8 *m1, u8 *m2, u32 len) {

  while (len--) {

    if (tolower(*(m1++)) ^ tolower(*(m2++))) { return 1; }

  }

  return 0;

}

/* add an extra/dict/token - no checks performed, no sorting */

static void add_extra_nocheck(afl_state_t *afl, u8 *mem, u32 len) {

  afl->extras = afl_realloc((void **)&afl->extras,
                            (afl->extras_cnt + 1) * sizeof(struct extra_data));

  if (unlikely(!afl->extras)) { PFATAL("alloc"); }

  afl->extras[afl->extras_cnt].data = ck_alloc(len);
  afl->extras[afl->extras_cnt].len = len;
  memcpy(afl->extras[afl->extras_cnt].data, mem, len);
  afl->extras_cnt++;

  /* We only want to print this once */

  if (afl->extras_cnt == afl->max_det_extras + 1) {

    WARNF("More than %u tokens - will use them probabilistically.",
          afl->max_det_extras);

  }

}

/* Sometimes strings in input is transformed to unicode internally, so for
   fuzzing we should attempt to de-unicode if it looks like simple unicode */

void deunicode_extras(afl_state_t *afl) {

  if (!afl->extras_cnt) return;

  u32 i, j, orig_cnt = afl->extras_cnt;
  u8  buf[64];

  for (i = 0; i < orig_cnt; ++i) {

    if (afl->extras[i].len < 6 || afl->extras[i].len > 64 ||
        afl->extras[i].len % 2) {

      continue;

    }

    u32 k = 0, z1 = 0, z2 = 0, z3 = 0, z4 = 0, half = afl->extras[i].len >> 1;
    u32 quarter = half >> 1;

    for (j = 0; j < afl->extras[i].len; ++j) {

      switch (j % 4) {

        case 2:
          if (!afl->extras[i].data[j]) { ++z3; }
          // fall through
        case 0:
          if (!afl->extras[i].data[j]) { ++z1; }
          break;
        case 3:
          if (!afl->extras[i].data[j]) { ++z4; }
          // fall through
        case 1:
          if (!afl->extras[i].data[j]) { ++z2; }
          break;

      }

    }

    if ((z1 < half && z2 < half) || z1 + z2 == afl->extras[i].len) { continue; }

    // also maybe 32 bit unicode?
    if (afl->extras[i].len % 4 == 0 && afl->extras[i].len >= 12 &&
        (z3 == quarter || z4 == quarter) && z1 + z2 == quarter * 3) {

      for (j = 0; j < afl->extras[i].len; ++j) {

        if (z4 < quarter) {

          if (j % 4 == 3) { buf[k++] = afl->extras[i].data[j]; }

        } else if (z3 < quarter) {

          if (j % 4 == 2) { buf[k++] = afl->extras[i].data[j]; }

        } else if (z2 < half) {

          if (j % 4 == 1) { buf[k++] = afl->extras[i].data[j]; }

        } else {

          if (j % 4 == 0) { buf[k++] = afl->extras[i].data[j]; }

        }

      }

      add_extra_nocheck(afl, buf, k);
      k = 0;

    }

    for (j = 0; j < afl->extras[i].len; ++j) {

      if (z1 < half) {

        if (j % 2 == 0) { buf[k++] = afl->extras[i].data[j]; }

      } else {

        if (j % 2 == 1) { buf[k++] = afl->extras[i].data[j]; }

      }

    }

    add_extra_nocheck(afl, buf, k);

  }

  qsort(afl->extras, afl->extras_cnt, sizeof(struct extra_data),
        compare_extras_len);

}

/* Removes duplicates from the loaded extras. This can happen if multiple files
   are loaded */

void dedup_extras(afl_state_t *afl) {

  if (afl->extras_cnt < 2) return;

  u32 i, j, orig_cnt = afl->extras_cnt;

  for (i = 0; i < afl->extras_cnt - 1; ++i) {

    for (j = i + 1; j < afl->extras_cnt; ++j) {

    restart_dedup:

      // if the goto was used we could be at the end of the list
      if (j >= afl->extras_cnt || afl->extras[i].len != afl->extras[j].len)
        break;

      if (memcmp(afl->extras[i].data, afl->extras[j].data,
                 afl->extras[i].len) == 0) {

        ck_free(afl->extras[j].data);
        if (j + 1 < afl->extras_cnt)  // not at the end of the list?
          memmove((char *)&afl->extras[j], (char *)&afl->extras[j + 1],
                  (afl->extras_cnt - j - 1) * sizeof(struct extra_data));
        --afl->extras_cnt;
        goto restart_dedup;  // restart if several duplicates are in a row

      }

    }

  }

  if (afl->extras_cnt != orig_cnt)
    afl->extras = afl_realloc_exact(
        (void **)&afl->extras, afl->extras_cnt * sizeof(struct extra_data));

}

/* Adds a new extra / dict entry. */
void add_extra(afl_state_t *afl, u8 *mem, u32 len) {

  u32 i, found = 0;

  for (i = 0; i < afl->extras_cnt; i++) {

    if (afl->extras[i].len == len) {

      if (memcmp(afl->extras[i].data, mem, len) == 0) return;
      found = 1;

    } else {

      if (found) break;

    }

  }

  if (len > MAX_DICT_FILE) {

    u8 val_bufs[2][STRINGIFY_VAL_SIZE_MAX];
    WARNF("Extra '%.*s' is too big (%s, limit is %s), skipping file!", (int)len,
          mem, stringify_mem_size(val_bufs[0], sizeof(val_bufs[0]), len),
          stringify_mem_size(val_bufs[1], sizeof(val_bufs[1]), MAX_DICT_FILE));
    return;

  } else if (len > 32) {

    WARNF("Extra '%.*s' is pretty large, consider trimming.", (int)len, mem);

  }

  add_extra_nocheck(afl, mem, len);

  qsort(afl->extras, afl->extras_cnt, sizeof(struct extra_data),
        compare_extras_len);

}

/* Maybe add automatic extra. */

void maybe_add_auto(afl_state_t *afl, u8 *mem, u32 len) {

  u32 i;

  /* Allow users to specify that they don't want auto dictionaries. */

  if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS) { return; }

  /* Skip runs of identical bytes. */

  for (i = 1; i < len; ++i) {

    if (mem[0] ^ mem[i]) { break; }

  }

  if (i == len || unlikely(len > MAX_AUTO_EXTRA)) { return; }

  /* Reject builtin interesting values. */

  if (len == 2) {

    i = sizeof(interesting_16) >> 1;

    while (i--) {

      if (*((u16 *)mem) == interesting_16[i] ||
          *((u16 *)mem) == SWAP16(interesting_16[i])) {

        return;

      }

    }

  }

  if (len == 4) {

    i = sizeof(interesting_32) >> 2;

    while (i--) {

      if (*((u32 *)mem) == (u32)interesting_32[i] ||
          *((u32 *)mem) == SWAP32(interesting_32[i])) {

        return;

      }

    }

  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. */

  for (i = 0; i < afl->extras_cnt; ++i) {

    if (afl->extras[i].len >= len) { break; }

  }

  for (; i < afl->extras_cnt && afl->extras[i].len == len; ++i) {

    if (!memcmp_nocase(afl->extras[i].data, mem, len)) { return; }

  }

  /* Last but not least, check afl->a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  afl->auto_changed = 1;

  for (i = 0; i < afl->a_extras_cnt; ++i) {

    if (afl->a_extras[i].len == len &&
        !memcmp_nocase(afl->a_extras[i].data, mem, len)) {

      afl->a_extras[i].hit_cnt++;
      goto sort_a_extras;

    }

  }

  /* At this point, looks like we're dealing with a new entry. So, let's
     append it if we have room. Otherwise, let's randomly evict some other
     entry from the bottom half of the list. */

  if (afl->a_extras_cnt < MAX_AUTO_EXTRAS) {

    memcpy(afl->a_extras[afl->a_extras_cnt].data, mem, len);
    afl->a_extras[afl->a_extras_cnt].len = len;
    ++afl->a_extras_cnt;

  } else {

    i = MAX_AUTO_EXTRAS / 2 + rand_below(afl, (MAX_AUTO_EXTRAS + 1) / 2);

    memcpy(afl->a_extras[i].data, mem, len);
    afl->a_extras[i].len = len;
    afl->a_extras[i].hit_cnt = 0;

  }

sort_a_extras:

  /* First, sort all auto extras by use count, descending order. */

  qsort(afl->a_extras, afl->a_extras_cnt, sizeof(struct auto_extra_data),
        compare_auto_extras_use_d);

  /* Then, sort the top USE_AUTO_EXTRAS entries by size. */

  qsort(afl->a_extras, MIN((u32)USE_AUTO_EXTRAS, afl->a_extras_cnt),
        sizeof(struct auto_extra_data), compare_auto_extras_len);

}

/* Save automatically generated extras. */

void save_auto(afl_state_t *afl) {

  u32 i;

  if (!afl->auto_changed) { return; }
  afl->auto_changed = 0;

  for (i = 0; i < MIN((u32)USE_AUTO_EXTRAS, afl->a_extras_cnt); ++i) {

    u8 *fn =
        alloc_printf("%s/queue/.state/auto_extras/auto_%06u", afl->out_dir, i);
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

    if (fd < 0) { PFATAL("Unable to create '%s'", fn); }

    ck_write(fd, afl->a_extras[i].data, afl->a_extras[i].len, fn);

    close(fd);
    ck_free(fn);

  }

}

/* Load automatically generated extras. */

void load_auto(afl_state_t *afl) {

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; ++i) {

    u8  tmp[MAX_AUTO_EXTRA + 1];
    u8 *fn = alloc_printf("%s/.state/auto_extras/auto_%06u", afl->in_dir, i);
    s32 fd, len;

    fd = open(fn, O_RDONLY);

    if (fd < 0) {

      if (errno != ENOENT) { PFATAL("Unable to open '%s'", fn); }
      ck_free(fn);
      break;

    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

    if (len < 0) { PFATAL("Unable to read from '%s'", fn); }

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA) {

      maybe_add_auto(afl, tmp, len);

    }

    close(fd);
    ck_free(fn);

  }

  if (i) {

    OKF("Loaded %u auto-discovered dictionary tokens.", i);

  } else {

    ACTF("No auto-generated dictionary tokens to reuse.");

  }

}

/* Destroy extras. */

void destroy_extras(afl_state_t *afl) {

  u32 i;

  for (i = 0; i < afl->extras_cnt; ++i) {

    ck_free(afl->extras[i].data);

  }

  afl_free(afl->extras);

}

