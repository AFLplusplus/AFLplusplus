/*
   american fuzzy lop++ - extras relates routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by by Marc Heuse <mh@mh-sec.de>,
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

/* Helper function for load_extras. */

static int compare_extras_len(const void* p1, const void* p2) {

  struct extra_data *e1 = (struct extra_data*)p1, *e2 = (struct extra_data*)p2;

  return e1->len - e2->len;

}

static int compare_extras_use_d(const void* p1, const void* p2) {

  struct extra_data *e1 = (struct extra_data*)p1, *e2 = (struct extra_data*)p2;

  return e2->hit_cnt - e1->hit_cnt;

}

/* Read extras from a file, sort by size. */

void load_extras_file(u8* fname, u32* min_len, u32* max_len, u32 dict_level) {

  FILE* f;
  u8    buf[MAX_LINE];
  u8*   lptr;
  u32   cur_line = 0;

  f = fopen(fname, "r");

  if (!f) PFATAL("Unable to open '%s'", fname);

  while ((lptr = fgets(buf, MAX_LINE, f))) {

    u8 *rptr, *wptr;
    u32 klen = 0;

    ++cur_line;

    /* Trim on left and right. */

    while (isspace(*lptr))
      ++lptr;

    rptr = lptr + strlen(lptr) - 1;
    while (rptr >= lptr && isspace(*rptr))
      --rptr;
    ++rptr;
    *rptr = 0;

    /* Skip empty lines and comments. */

    if (!*lptr || *lptr == '#') continue;

    /* All other lines must end with '"', which we can consume. */

    --rptr;

    if (rptr < lptr || *rptr != '"')
      FATAL("Malformed name=\"value\" pair in line %u.", cur_line);

    *rptr = 0;

    /* Skip alphanumerics and dashes (label). */

    while (isalnum(*lptr) || *lptr == '_')
      ++lptr;

    /* If @number follows, parse that. */

    if (*lptr == '@') {

      ++lptr;
      if (atoi(lptr) > dict_level) continue;
      while (isdigit(*lptr))
        ++lptr;

    }

    /* Skip whitespace and = signs. */

    while (isspace(*lptr) || *lptr == '=')
      ++lptr;

    /* Consume opening '"'. */

    if (*lptr != '"')
      FATAL("Malformed name=\"keyword\" pair in line %u.", cur_line);

    ++lptr;

    if (!*lptr) FATAL("Empty keyword in line %u.", cur_line);

    /* Okay, let's allocate memory and copy data between "...", handling
       \xNN escaping, \\, and \". */

    extras =
        ck_realloc_block(extras, (extras_cnt + 1) * sizeof(struct extra_data));

    wptr = extras[extras_cnt].data = ck_alloc(rptr - lptr);

    while (*lptr) {

      char* hexdigits = "0123456789abcdef";

      switch (*lptr) {

        case 1 ... 31:
        case 128 ... 255:
          FATAL("Non-printable characters in line %u.", cur_line);

        case '\\':

          ++lptr;

          if (*lptr == '\\' || *lptr == '"') {

            *(wptr++) = *(lptr++);
            klen++;
            break;

          }

          if (*lptr != 'x' || !isxdigit(lptr[1]) || !isxdigit(lptr[2]))
            FATAL("Invalid escaping (not \\xNN) in line %u.", cur_line);

          *(wptr++) = ((strchr(hexdigits, tolower(lptr[1])) - hexdigits) << 4) |
                      (strchr(hexdigits, tolower(lptr[2])) - hexdigits);

          lptr += 3;
          ++klen;

          break;

        default: *(wptr++) = *(lptr++); ++klen;

      }

    }

    extras[extras_cnt].len = klen;

    if (extras[extras_cnt].len > MAX_DICT_FILE)
      FATAL("Keyword too big in line %u (%s, limit is %s)", cur_line, DMS(klen),
            DMS(MAX_DICT_FILE));

    if (*min_len > klen) *min_len = klen;
    if (*max_len < klen) *max_len = klen;

    ++extras_cnt;

  }

  fclose(f);

}

/* Read extras from the extras directory and sort them by size. */

void load_extras(u8* dir) {

  DIR*           d;
  struct dirent* de;
  u32            min_len = MAX_DICT_FILE, max_len = 0, dict_level = 0;
  u8*            x;

  /* If the name ends with @, extract level and continue. */

  if ((x = strchr(dir, '@'))) {

    *x = 0;
    dict_level = atoi(x + 1);

  }

  ACTF("Loading extra dictionary from '%s' (level %u)...", dir, dict_level);

  d = opendir(dir);

  if (!d) {

    if (errno == ENOTDIR) {

      load_extras_file(dir, &min_len, &max_len, dict_level);
      goto check_and_sort;

    }

    PFATAL("Unable to open '%s'", dir);

  }

  if (x) FATAL("Dictionary levels not supported for directories.");

  while ((de = readdir(d))) {

    struct stat st;
    u8*         fn = alloc_printf("%s/%s", dir, de->d_name);
    s32         fd;

    if (lstat(fn, &st) || access(fn, R_OK)) PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */
    if (!S_ISREG(st.st_mode) || !st.st_size) {

      ck_free(fn);
      continue;

    }

    if (st.st_size > MAX_DICT_FILE)
      FATAL("Extra '%s' is too big (%s, limit is %s)", fn, DMS(st.st_size),
            DMS(MAX_DICT_FILE));

    if (min_len > st.st_size) min_len = st.st_size;
    if (max_len < st.st_size) max_len = st.st_size;

    extras =
        ck_realloc_block(extras, (extras_cnt + 1) * sizeof(struct extra_data));

    extras[extras_cnt].data = ck_alloc(st.st_size);
    extras[extras_cnt].len = st.st_size;

    fd = open(fn, O_RDONLY);

    if (fd < 0) PFATAL("Unable to open '%s'", fn);

    ck_read(fd, extras[extras_cnt].data, st.st_size, fn);

    close(fd);
    ck_free(fn);

    ++extras_cnt;

  }

  closedir(d);

check_and_sort:

  if (!extras_cnt) FATAL("No usable files in '%s'", dir);

  qsort(extras, extras_cnt, sizeof(struct extra_data), compare_extras_len);

  OKF("Loaded %u extra tokens, size range %s to %s.", extras_cnt, DMS(min_len),
      DMS(max_len));

  if (max_len > 32)
    WARNF("Some tokens are relatively large (%s) - consider trimming.",
          DMS(max_len));

  if (extras_cnt > MAX_DET_EXTRAS)
    WARNF("More than %d tokens - will use them probabilistically.",
          MAX_DET_EXTRAS);

}

/* Helper function for maybe_add_auto() */

static inline u8 memcmp_nocase(u8* m1, u8* m2, u32 len) {

  while (len--)
    if (tolower(*(m1++)) ^ tolower(*(m2++))) return 1;
  return 0;

}

/* Maybe add automatic extra. */

void maybe_add_auto(u8* mem, u32 len) {

  u32 i;

  /* Allow users to specify that they don't want auto dictionaries. */

  if (!MAX_AUTO_EXTRAS || !USE_AUTO_EXTRAS) return;

  /* Skip runs of identical bytes. */

  for (i = 1; i < len; ++i)
    if (mem[0] ^ mem[i]) break;

  if (i == len) return;

  /* Reject builtin interesting values. */

  if (len == 2) {

    i = sizeof(interesting_16) >> 1;

    while (i--)
      if (*((u16*)mem) == interesting_16[i] ||
          *((u16*)mem) == SWAP16(interesting_16[i]))
        return;

  }

  if (len == 4) {

    i = sizeof(interesting_32) >> 2;

    while (i--)
      if (*((u32*)mem) == interesting_32[i] ||
          *((u32*)mem) == SWAP32(interesting_32[i]))
        return;

  }

  /* Reject anything that matches existing extras. Do a case-insensitive
     match. We optimize by exploiting the fact that extras[] are sorted
     by size. */

  for (i = 0; i < extras_cnt; ++i)
    if (extras[i].len >= len) break;

  for (; i < extras_cnt && extras[i].len == len; ++i)
    if (!memcmp_nocase(extras[i].data, mem, len)) return;

  /* Last but not least, check a_extras[] for matches. There are no
     guarantees of a particular sort order. */

  auto_changed = 1;

  for (i = 0; i < a_extras_cnt; ++i) {

    if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len)) {

      a_extras[i].hit_cnt++;
      goto sort_a_extras;

    }

  }

  /* At this point, looks like we're dealing with a new entry. So, let's
     append it if we have room. Otherwise, let's randomly evict some other
     entry from the bottom half of the list. */

  if (a_extras_cnt < MAX_AUTO_EXTRAS) {

    a_extras = ck_realloc_block(a_extras,
                                (a_extras_cnt + 1) * sizeof(struct extra_data));

    a_extras[a_extras_cnt].data = ck_memdup(mem, len);
    a_extras[a_extras_cnt].len = len;
    ++a_extras_cnt;

  } else {

    i = MAX_AUTO_EXTRAS / 2 + UR((MAX_AUTO_EXTRAS + 1) / 2);

    ck_free(a_extras[i].data);

    a_extras[i].data = ck_memdup(mem, len);
    a_extras[i].len = len;
    a_extras[i].hit_cnt = 0;

  }

sort_a_extras:

  /* First, sort all auto extras by use count, descending order. */

  qsort(a_extras, a_extras_cnt, sizeof(struct extra_data),
        compare_extras_use_d);

  /* Then, sort the top USE_AUTO_EXTRAS entries by size. */

  qsort(a_extras, MIN(USE_AUTO_EXTRAS, a_extras_cnt), sizeof(struct extra_data),
        compare_extras_len);

}

/* Save automatically generated extras. */

void save_auto(void) {

  u32 i;

  if (!auto_changed) return;
  auto_changed = 0;

  for (i = 0; i < MIN(USE_AUTO_EXTRAS, a_extras_cnt); ++i) {

    u8* fn = alloc_printf("%s/queue/.state/auto_extras/auto_%06u", out_dir, i);
    s32 fd;

    fd = open(fn, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) PFATAL("Unable to create '%s'", fn);

    ck_write(fd, a_extras[i].data, a_extras[i].len, fn);

    close(fd);
    ck_free(fn);

  }

}

/* Load automatically generated extras. */

void load_auto(void) {

  u32 i;

  for (i = 0; i < USE_AUTO_EXTRAS; ++i) {

    u8  tmp[MAX_AUTO_EXTRA + 1];
    u8* fn = alloc_printf("%s/.state/auto_extras/auto_%06u", in_dir, i);
    s32 fd, len;

    fd = open(fn, O_RDONLY, 0600);

    if (fd < 0) {

      if (errno != ENOENT) PFATAL("Unable to open '%s'", fn);
      ck_free(fn);
      break;

    }

    /* We read one byte more to cheaply detect tokens that are too
       long (and skip them). */

    len = read(fd, tmp, MAX_AUTO_EXTRA + 1);

    if (len < 0) PFATAL("Unable to read from '%s'", fn);

    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
      maybe_add_auto(tmp, len);

    close(fd);
    ck_free(fn);

  }

  if (i)
    OKF("Loaded %u auto-discovered dictionary tokens.", i);
  else
    OKF("No auto-generated dictionary tokens to reuse.");

}

/* Destroy extras. */

void destroy_extras(void) {

  u32 i;

  for (i = 0; i < extras_cnt; ++i)
    ck_free(extras[i].data);

  ck_free(extras);

  for (i = 0; i < a_extras_cnt; ++i)
    ck_free(a_extras[i].data);

  ck_free(a_extras);

}

