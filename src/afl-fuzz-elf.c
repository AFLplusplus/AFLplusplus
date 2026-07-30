/*
   american fuzzy lop++ - ELF dictionary mining
   -------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version. See https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

   Mines string and numeric constants out of the target binary's data sections
   and feeds them to the fuzzing dictionary. Opt-in via AFL_ELF_DICT.
   See docs/env_variables.md.

 */

#include "afl-fuzz.h"
#include "afl-elf.h"
#include "afl-elf-dict.h"

#include <sys/mman.h>

/* Reads w bytes (w <= 8) as an unsigned value. be != 0 selects big-endian. */

u64 elf_dict_val(u8 *b, u32 w, u8 be) {

  u64 v = 0;
  u32 i;

  for (i = 0; i < w; ++i) {

    v = (v << 8) | (u64)b[be ? i : (w - 1 - i)];

  }

  return v;

}

/* F1: every byte identical - 0x00000000, 0xffffffff, 0x11111111, ... */

u8 elf_dict_is_uniform(u8 *b, u32 w) {

  u32 i;

  for (i = 1; i < w; ++i) {

    if (b[i] != b[0]) { return 0; }

  }

  return 1;

}

/* F2: a zero- or sign-extension of a single low byte, in either byte order.
   AFL's arithmetic and interest-value mutations already cover that range. */

u8 elf_dict_is_small(u8 *b, u32 w) {

  u32 i;
  u8  hi_zero = 1, hi_ff = 1, lo_zero = 1, lo_ff = 1;

  for (i = 1; i < w; ++i) {                           /* little-endian high */

    if (b[i] != 0x00) { hi_zero = 0; }
    if (b[i] != 0xff) { hi_ff = 0; }

  }

  for (i = 0; i + 1 < w; ++i) {                          /* big-endian high */

    if (b[i] != 0x00) { lo_zero = 0; }
    if (b[i] != 0xff) { lo_ff = 0; }

  }

  return (hi_zero || hi_ff || lo_zero || lo_ff) ? 1 : 0;

}

/* F3: every byte printable ASCII or NUL - string extraction already covers
   these, including the NUL-padded tail of one. */

u8 elf_dict_is_textual(u8 *b, u32 w) {

  u32 i;

  for (i = 0; i < w; ++i) {

    if (b[i] && (b[i] < 0x20 || b[i] > 0x7e)) { return 0; }

  }

  return 1;

}

/* Reads like an identifier or a chunk tag: every byte alphanumeric, underscore
   or space, and at least one of them a letter. "WEBP", "VP8L" and "RIFF" pass;
   the punctuation ramps that numeric lookup tables produce, " !\"#" or "'()*",
   do not. Used to decide whether a printable word that no string covers is
   worth keeping. */

u8 elf_dict_is_tagish(u8 *b, u32 w) {

  u32 i, letters = 0;

  /* a tag may be NUL-padded to its field width, as in "VP8\0" */

  while (w && !b[w - 1]) {

    --w;

  }

  for (i = 0; i < w; ++i) {

    u8 c = b[i];

    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {

      ++letters;

    } else if (!((c >= '0' && c <= '9') || c == '_' || c == ' ')) {

      return 0;

    }

  }

  return letters ? 1 : 0;

}

/* F4: looks like a pointer. Only applied at the target's pointer width.

   For 64 bit, one rule covers non-PIE code (0x0000000000400000), PIE images
   (0x0000555555......), heap (0x0000556.........) and shared libraries and
   stack (0x00007f........): a canonical userspace address has its top 16 bits
   clear. A second rule covers kernel pointers. This assumes the usual 48-bit
   virtual address layout; widening it to 56 bits would reject every genuine
   constant below 2^56, which costs far more than it gains.

   For 32 bit the binary's own PT_LOAD ranges are used. A blanket
   0x08000000-0xc0000000 window would match the usual i386 layout but would
   also reject legitimate magics such as 0x0a0b0c0d. */

u8 elf_dict_is_pointer(elf_dict_ctx_t *ctx, u8 *b, u32 w) {

  u32 k;

  if (w != ctx->ptr_width) { return 0; }

  for (k = 0; k < 2; ++k) {

    u64 v = elf_dict_val(b, w, (u8)k);

    if (w == 8) {

      if (!(v >> 48) && v >= 0x10000) { return 1; }
      if (v >= 0xffff800000000000ULL) { return 1; }

    } else {

      u32 j;

      if (v < 0x1000) { continue; }

      for (j = 0; j < ctx->load_cnt; ++j) {

        if (v >= ctx->load_lo[j] && v < ctx->load_hi[j]) { return 1; }

      }

    }

  }

  return 0;

}

/* F5: a value AFL already tries on its own. */

u8 elf_dict_is_builtin(u8 *b, u32 w) {

  u32 k, i;

  if (w != 4 && w != 8) { return 0; }

  for (k = 0; k < 2; ++k) {

    u64 v = elf_dict_val(b, w, (u8)k);

    if (w == 4) {

      for (i = 0; i < sizeof(interesting_32) / sizeof(interesting_32[0]); ++i) {

        if ((u32)v == (u32)interesting_32[i]) { return 1; }

      }

      for (i = 0; i < sizeof(interesting_16) / sizeof(interesting_16[0]); ++i) {

        if ((u32)v == (u32)(u16)interesting_16[i]) { return 1; }

      }

    } else {

      for (i = 0; i < sizeof(interesting_32) / sizeof(interesting_32[0]); ++i) {

        if (v == (u64)(s64)interesting_32[i]) { return 1; }

      }

    }

  }

  return 0;

}

/* Entirely letters and digits, optionally with one trailing NUL: "ABCD" and
   "GET\0" qualify, "AB\0\0" and "a-b1" do not. */

u8 elf_dict_is_alnum_word(u8 *b, u32 w) {

  u32 i, n = w;

  if (!w) { return 0; }

  if (!b[w - 1]) { n = w - 1; }                /* one optional trailing NUL */

  if (!n) { return 0; }

  for (i = 0; i < n; ++i) {

    u8 c = b[i];

    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
          (c >= '0' && c <= '9'))) {

      return 0;

    }

  }

  return 1;

}

/* Cheap byte-pattern tests first, the loops over the interest arrays last.
   Rejections are attributed to the filter that fired so AFL_DEBUG can report
   what each one is worth on a real binary. */

u8 elf_dict_keep_numeric(elf_dict_ctx_t *ctx, u8 *b, u32 w) {

  /* "-a text" says the target consumes text, so a raw byte constant is of no
     use to it. Keep only those that are themselves alphanumeric, which is what
     a textual protocol actually compares against. */

  if (ctx->text_mode && !elf_dict_is_alnum_word(b, w)) {

    ++ctx->rej[ELF_DICT_FILTER_TEXTMODE];
    return 0;

  }

  if (elf_dict_is_uniform(b, w)) {

    ++ctx->rej[ELF_DICT_FILTER_UNIFORM];
    return 0;

  }

  if (elf_dict_is_small(b, w)) {

    ++ctx->rej[ELF_DICT_FILTER_SMALL];
    return 0;

  }

  /* Printable words need care. Rejecting all of them as "already covered by
     the string pass" loses unterminated chunk tags, which no string run can
     see: libwebp stores "WEBP" and "VP8L" in a tag table exactly that way, and
     they are the tokens a WebP fuzzer wants most. Keeping all of them instead
     admits hundreds of ascending byte ramps out of numeric lookup tables that
     merely happen to land in 0x20-0x7e, such as " !\"#" or "'()*".

     So keep a printable word only when no string covers it and it reads like
     an identifier or tag. */

  if (elf_dict_is_textual(b, w)) {

    if (elf_dict_str_covered(ctx, b, w) || !elf_dict_is_tagish(b, w)) {

      ++ctx->rej[ELF_DICT_FILTER_TEXTUAL];
      return 0;

    }

  }

  if (elf_dict_is_pointer(ctx, b, w)) {

    ++ctx->rej[ELF_DICT_FILTER_POINTER];
    return 0;

  }

  if (elf_dict_is_builtin(b, w)) {

    ++ctx->rej[ELF_DICT_FILTER_BUILTIN];
    return 0;

  }

  return 1;

}

void elf_dict_push(elf_dict_ctx_t *ctx, u32 class, u8 *data, u32 len) {

  elf_dict_token_t *t;

  ++ctx->seen[class];

  if (ctx->tok_cnt[class] >= ELF_DICT_MAX_CANDIDATES) { return; }

  ctx->tok[class] =
      afl_realloc((void **)&ctx->tok[class],
                  (ctx->tok_cnt[class] + 1) * sizeof(elf_dict_token_t));

  if (unlikely(!ctx->tok[class])) { PFATAL("alloc"); }

  t = &ctx->tok[class][ctx->tok_cnt[class]];

  memset(t->data, 0, sizeof(t->data));
  memcpy(t->data, data, len);
  t->len = len;
  t->hits = 1;

  ++ctx->tok_cnt[class];

}

static u8 elf_dict_printable(u8 c) {

  return (c >= 0x20 && c <= 0x7e) ? 1 : 0;

}

/* \t, \n and \r belong to a string but may not open one: leading whitespace is
   noise, while a trailing "\r\n" is exactly what makes a protocol line useful
   as a token. */

static u8 elf_dict_str_byte(u8 c) {

  return (elf_dict_printable(c) || c == '\t' || c == '\n' || c == '\r') ? 1 : 0;

}

u8 elf_dict_str_covered(elf_dict_ctx_t *ctx, u8 *b, u32 w) {

  u32 off, i;

  if (!ctx->strcov || !ctx->region) { return 0; }

  off = (u32)(b - ctx->region);

  for (i = 0; i < w; ++i) {

    u32 o = off + i;

    if (o >= ctx->region_len) { return 0; }
    if (!(ctx->strcov[o >> 3] & (1u << (o & 7)))) { return 0; }

  }

  return 1;

}

static void elf_dict_mark_covered(elf_dict_ctx_t *ctx, u32 from, u32 to) {

  u32 o;

  if (!ctx->strcov) { return; }

  for (o = from; o < to && o < ctx->region_len; ++o) {

    ctx->strcov[o >> 3] |= (u8)(1u << (o & 7));

  }

}

static void elf_dict_scan_strings(elf_dict_ctx_t *ctx, u8 *base, u32 len) {

  u32 i = 0;

  while (i < len) {

    u32 start;

    if (!elf_dict_printable(base[i])) {

      ++i;
      continue;

    }

    start = i;

    while (i < len && elf_dict_str_byte(base[i])) {

      ++i;

    }

    if (i < len && !base[i]) {

      u32 slen = i - start;

      /* Mark every NUL-terminated run, terminator included, whether or not it
         became a token: a run too short or too long to be a token is still a
         real string whose interior windows are noise, not magic values. */

      elf_dict_mark_covered(ctx, start, i + 1);

      if (slen >= ELF_DICT_MIN_STRING && slen <= ELF_DICT_MAX_STRING) {

        elf_dict_push(ctx, ELF_DICT_CLASS_STRING, base + start, slen);

      }

    }

    ++i;

  }

}

static void elf_dict_scan_numeric(elf_dict_ctx_t *ctx, u8 *base, u32 len,
                                  u64 file_off) {

  static const u32 widths[3] = {4, 8, 16};
  static const u32 classes[3] = {ELF_DICT_CLASS_32, ELF_DICT_CLASS_64,
                                 ELF_DICT_CLASS_128};
  u32              k;

  for (k = 0; k < 3; ++k) {

    u32 w = widths[k];
    u32 off = (u32)((w - (file_off % w)) % w);

    for (; off + w <= len; off += w) {

      u8 *b = base + off;
      u8  rev[16];
      u32 i;

      if (!elf_dict_keep_numeric(ctx, b, w)) { continue; }

      elf_dict_push(ctx, classes[k], b, w);

      if (w == 16) { continue; }

      for (i = 0; i < w; ++i) {

        rev[i] = b[w - 1 - i];

      }

      if (memcmp(rev, b, w)) { elf_dict_push(ctx, classes[k], rev, w); }

    }

  }

}

void elf_dict_scan_region(elf_dict_ctx_t *ctx, u8 *base, u32 len,
                          u64 file_off) {

  u32 bitmap_len;

  if (!base || len < ELF_DICT_MIN_STRING) { return; }

  /* One bit per region byte, so the textual filter can tell text inside a real
     string from a printable word that no string covers. */

  bitmap_len = (len + 7) / 8;
  ctx->strcov = afl_realloc((void **)&ctx->strcov, bitmap_len);

  if (unlikely(!ctx->strcov)) { PFATAL("alloc"); }

  memset(ctx->strcov, 0, bitmap_len);
  ctx->region = base;
  ctx->region_len = len;

  elf_dict_scan_strings(ctx, base, len);
  elf_dict_scan_numeric(ctx, base, len, file_off);

  ctx->region = NULL;
  ctx->region_len = 0;

}

static int elf_dict_cmp_tok(const void *a, const void *b) {

  const elf_dict_token_t *x = (const elf_dict_token_t *)a;
  const elf_dict_token_t *y = (const elf_dict_token_t *)b;

  if (x->len != y->len) { return (int)x->len - (int)y->len; }

  return memcmp(x->data, y->data, x->len);

}

/* Collapses duplicates, accumulating each survivor's occurrence count into
   its hits field. */

u32 elf_dict_dedup(elf_dict_token_t *tok, u32 cnt) {

  u32 i, w;

  if (cnt < 2) { return cnt; }

  qsort(tok, cnt, sizeof(elf_dict_token_t), elf_dict_cmp_tok);

  for (i = 1, w = 1; i < cnt; ++i) {

    if (elf_dict_cmp_tok(&tok[w - 1], &tok[i])) {

      if (w != i) { tok[w] = tok[i]; }
      ++w;

    } else {

      tok[w - 1].hits += tok[i].hits;

    }

  }

  return w;

}

/* Descending occurrence count, then by (len, bytes) so the order is total and
   reproducible. */

static int elf_dict_cmp_hits(const void *a, const void *b) {

  const elf_dict_token_t *x = (const elf_dict_token_t *)a;
  const elf_dict_token_t *y = (const elf_dict_token_t *)b;

  if (x->hits != y->hits) { return x->hits < y->hits ? 1 : -1; }

  return elf_dict_cmp_tok(a, b);

}

/* Quotas are applied in class order and unused space rolls over, so a binary
   with no strings still spends the full budget on constants.

   When a class holds more survivors than its allowance, the ones that occur
   most often in the binary are kept. Positional stride selection was tried
   first and measured badly: at the default 2048-token cap it threw away
   libwebp's "WEBP" and "VP8L" and libxml2's "UTF-8", because a content-blind
   rule gives the few tokens that matter no better odds than table filler. A
   value referenced from many places is far more likely to be a real magic than
   a one-off table entry - "VP8L" appears 95 times in libwebp's .rodata - so
   occurrence count is the ranking signal. */

u32 elf_dict_select(elf_dict_ctx_t *ctx, u32 cap) {

  static const u32 quota[ELF_DICT_CLASS_CNT] = {

      ELF_DICT_QUOTA_STRING, ELF_DICT_QUOTA_32, ELF_DICT_QUOTA_64,
      ELF_DICT_QUOTA_128, ELF_DICT_QUOTA_TEXT};

  u32 cnt[ELF_DICT_CLASS_CNT], take[ELF_DICT_CLASS_CNT];
  u32 c, leftover = 0, total = 0, progress;

  ctx->sel_cnt = 0;

  if (!cap) { return 0; }

  ctx->sel = afl_realloc((void **)&ctx->sel, cap * sizeof(elf_dict_token_t));
  if (unlikely(!ctx->sel)) { PFATAL("alloc"); }

  for (c = 0; c < ELF_DICT_CLASS_CNT; ++c) {

    u32 allow;

    cnt[c] = elf_dict_dedup(ctx->tok[c], ctx->tok_cnt[c]);
    ctx->tok_cnt[c] = cnt[c];

    allow = (u32)(((u64)cap * quota[c]) / ELF_DICT_MAX_TOKENS) + leftover;
    if (allow > cap - total) { allow = cap - total; }

    take[c] = cnt[c] < allow ? cnt[c] : allow;

    leftover = allow - take[c];
    total += take[c];

  }

  /* Rollover above only flows forward, so an empty last class leaves budget
     on the table. Hand whatever is left to the classes that still have spare
     candidates, one at a time so the surplus is shared rather than dumped
     entirely on strings. The cap is a ceiling, not a target to undershoot. */

  progress = 1;

  while (total < cap && progress) {

    progress = 0;

    for (c = 0; c < ELF_DICT_CLASS_CNT && total < cap; ++c) {

      if (cnt[c] > take[c]) {

        ++take[c];
        ++total;
        progress = 1;

      }

    }

  }

  total = 0;

  for (c = 0; c < ELF_DICT_CLASS_CNT; ++c) {

    u32 i;

    if (!take[c]) { continue; }

    if (take[c] < cnt[c]) {

      qsort(ctx->tok[c], cnt[c], sizeof(elf_dict_token_t), elf_dict_cmp_hits);

    }

    for (i = 0; i < take[c]; ++i) {

      ctx->sel[total + i] = ctx->tok[c][i];

    }

    total += take[c];

  }

  ctx->sel_cnt = total;

  return total;

}

/* Executable sections need their own pass. A compiler materialises a small
   magic as an instruction immediate - "cmpl $0x50424557, 0x8(%rbx)" for
   libwebp's "WEBP" - so the value sits at whatever offset the instruction
   stream put it at, never at a natural alignment. Sweeping every byte offset
   is therefore mandatory here, and it means almost nothing gets filtered:
   measured on libwebp, 93.6% of unaligned 4-byte windows in .text survive the
   ordinary numeric filters, because instruction bytes are close to random.

   Requiring the word to read like a tag is what makes this usable at all: on
   libwebp it cuts 363306 survivors to 484 unique values while keeping every
   FourCC the format actually uses. The tag test runs first because it is both
   the cheapest and by far the most selective. */

void elf_dict_scan_text_region(elf_dict_ctx_t *ctx, u8 *base, u32 len) {

  static const u32 widths[2] = {4, 8};
  u32              k;

  if (!base || len < 4) { return; }

  for (k = 0; k < 2; ++k) {

    u32 w = widths[k];
    u32 off;

    if (len < w) { continue; }

    for (off = 0; off + w <= len; ++off) {

      u8 *b = base + off;

      if (!elf_dict_is_tagish(b, w)) {

        ++ctx->rej[ELF_DICT_FILTER_NOTTAG];
        continue;

      }

      if (!elf_dict_keep_numeric(ctx, b, w)) { continue; }

      elf_dict_push(ctx, ELF_DICT_CLASS_TEXT, b, w);

    }

  }

}

void elf_dict_free(elf_dict_ctx_t *ctx) {

  u32 c;

  for (c = 0; c < ELF_DICT_CLASS_CNT; ++c) {

    if (ctx->tok[c]) {

      afl_free(ctx->tok[c]);
      ctx->tok[c] = NULL;

    }

    ctx->tok_cnt[c] = 0;

  }

  if (ctx->sel) {

    afl_free(ctx->sel);
    ctx->sel = NULL;

  }

  if (ctx->strcov) {

    afl_free(ctx->strcov);
    ctx->strcov = NULL;

  }

  ctx->sel_cnt = 0;
  ctx->region = NULL;
  ctx->region_len = 0;

}

/* Byte-order aware field reads. The target's endianness is independent of
   ours, so a big-endian MIPS binary parses correctly on x86-64. */

static u8 elf_swap;

static u16 elf_dict_r16(u16 v) {

  return elf_swap ? SWAP16(v) : v;

}

static u32 elf_dict_r32(u32 v) {

  return elf_swap ? SWAP32(v) : v;

}

static u64 elf_dict_r64(u64 v) {

  return elf_swap ? SWAP64(v) : v;

}

static u8 elf_dict_host_is_be(void) {

  u16 probe = 1;

  return (*(u8 *)&probe) ? 0 : 1;

}

/* 1 when [off, off+size) lies inside the mapping. */

static u8 elf_dict_in_bounds(u64 off, u64 size, u64 map_len) {

  if (off > map_len) { return 0; }
  if (size > map_len - off) { return 0; }

  return 1;

}

static u8 elf_dict_name_wanted(const char *name) {

  static const char *prefixes[] = {".rodata", ".data.rel.ro", ".data", NULL};
  u32                i;

  for (i = 0; prefixes[i]; ++i) {

    u32 plen = (u32)strlen(prefixes[i]);

    if (!strncmp(name, prefixes[i], plen) &&
        (name[plen] == 0 || name[plen] == '.')) {

      return 1;

    }

  }

  return 0;

}

/* Records the PT_LOAD vaddr ranges, which the 32-bit pointer filter needs. */

static void elf_dict_collect_load(elf_dict_ctx_t *ctx, u8 *map, u64 map_len,
                                  u8 is64, u64 phoff, u16 phnum,
                                  u16 phentsize) {

  u64 pesz = is64 ? sizeof(afl_elf64_phdr) : sizeof(afl_elf32_phdr);
  u32 i;

  if (!phoff || phentsize < pesz) { return; }
  if (!elf_dict_in_bounds(phoff, (u64)phnum * phentsize, map_len)) { return; }

  for (i = 0; i < phnum; ++i) {

    u8 *p = map + phoff + (u64)i * phentsize;
    u64 p_type, p_vaddr, p_memsz;

    if (is64) {

      afl_elf64_phdr ph;
      memcpy(&ph, p, sizeof(ph));
      p_type = elf_dict_r32(ph.p_type);
      p_vaddr = elf_dict_r64(ph.p_vaddr);
      p_memsz = elf_dict_r64(ph.p_memsz);

    } else {

      afl_elf32_phdr ph;
      memcpy(&ph, p, sizeof(ph));
      p_type = elf_dict_r32(ph.p_type);
      p_vaddr = elf_dict_r32(ph.p_vaddr);
      p_memsz = elf_dict_r32(ph.p_memsz);

    }

    if (p_type != AFL_PT_LOAD) { continue; }
    if (ctx->load_cnt >= ELF_DICT_MAX_LOAD) { break; }

    ctx->load_lo[ctx->load_cnt] = p_vaddr;
    ctx->load_hi[ctx->load_cnt] = p_vaddr + p_memsz;
    ++ctx->load_cnt;

  }

}

/* Scans the data sections named in elf_dict_name_wanted(). Returns the number
   of regions scanned, 0 if the section table is missing or unusable. */

static u32 elf_dict_scan_sections(elf_dict_ctx_t *ctx, u8 *map, u64 map_len,
                                  u8 is64, u64 shoff, u16 shnum, u16 shentsize,
                                  u16 shstrndx) {

  u64 sesz = is64 ? sizeof(afl_elf64_shdr) : sizeof(afl_elf32_shdr);
  u8 *shstr;
  u64 shstr_off, shstr_len;
  u32 i, scanned = 0;

  if (!shoff || !shnum || shentsize < sesz || shstrndx >= shnum) { return 0; }
  if (!elf_dict_in_bounds(shoff, (u64)shnum * shentsize, map_len)) { return 0; }

  /* the section header string table, needed to match section names */

  {

    u8 *p = map + shoff + (u64)shstrndx * shentsize;

    if (is64) {

      afl_elf64_shdr sh;
      memcpy(&sh, p, sizeof(sh));
      shstr_off = elf_dict_r64(sh.sh_offset);
      shstr_len = elf_dict_r64(sh.sh_size);

    } else {

      afl_elf32_shdr sh;
      memcpy(&sh, p, sizeof(sh));
      shstr_off = elf_dict_r32(sh.sh_offset);
      shstr_len = elf_dict_r32(sh.sh_size);

    }

    if (!shstr_len || !elf_dict_in_bounds(shstr_off, shstr_len, map_len)) {

      return 0;

    }

    shstr = map + shstr_off;

  }

  for (i = 0; i < shnum; ++i) {

    u8  *p = map + shoff + (u64)i * shentsize;
    u64  sh_off, sh_size, sh_flags;
    u32  sh_name, sh_type;
    char name[64];
    u64  avail, n;

    if (is64) {

      afl_elf64_shdr sh;
      memcpy(&sh, p, sizeof(sh));
      sh_name = elf_dict_r32(sh.sh_name);
      sh_type = elf_dict_r32(sh.sh_type);
      sh_flags = elf_dict_r64(sh.sh_flags);
      sh_off = elf_dict_r64(sh.sh_offset);
      sh_size = elf_dict_r64(sh.sh_size);

    } else {

      afl_elf32_shdr sh;
      memcpy(&sh, p, sizeof(sh));
      sh_name = elf_dict_r32(sh.sh_name);
      sh_type = elf_dict_r32(sh.sh_type);
      sh_flags = elf_dict_r32(sh.sh_flags);
      sh_off = elf_dict_r32(sh.sh_offset);
      sh_size = elf_dict_r32(sh.sh_size);

    }

    if (sh_type == AFL_SHT_NULL || sh_type == AFL_SHT_NOBITS) { continue; }
    if (!(sh_flags & AFL_SHF_ALLOC)) { continue; }
    if (!sh_size || sh_size > 0xffffffffULL) { continue; }
    if (sh_name >= shstr_len) { continue; }
    if (!elf_dict_in_bounds(sh_off, sh_size, map_len)) { continue; }

    if (sh_flags & AFL_SHF_EXECINSTR) {

      /* Code is only mined under AFL_ELF_DICT=2. */

      if (!ctx->scan_text) { continue; }

      elf_dict_scan_text_region(ctx, map + sh_off, (u32)sh_size);
      ++scanned;
      continue;

    }

    /* the string table should be NUL-terminated, but do not trust it: bound
       the name by the table it lives in */

    avail = shstr_len - sh_name;
    n = avail < sizeof(name) - 1 ? avail : sizeof(name) - 1;
    memcpy(name, shstr + sh_name, n);
    name[n] = 0;

    if (!elf_dict_name_wanted(name)) { continue; }

    elf_dict_scan_region(ctx, map + sh_off, (u32)sh_size, sh_off);
    ++scanned;

  }

  return scanned;

}

/* Fallback for a binary stripped of section headers: every non-executable
   PT_LOAD segment. */

static u32 elf_dict_scan_segments(elf_dict_ctx_t *ctx, u8 *map, u64 map_len,
                                  u8 is64, u64 phoff, u16 phnum,
                                  u16 phentsize) {

  u64 pesz = is64 ? sizeof(afl_elf64_phdr) : sizeof(afl_elf32_phdr);
  u32 i, scanned = 0;

  if (!phoff || phentsize < pesz) { return 0; }
  if (!elf_dict_in_bounds(phoff, (u64)phnum * phentsize, map_len)) { return 0; }

  for (i = 0; i < phnum; ++i) {

    u8 *p = map + phoff + (u64)i * phentsize;
    u64 p_type, p_off, p_filesz, p_flags;

    if (is64) {

      afl_elf64_phdr ph;
      memcpy(&ph, p, sizeof(ph));
      p_type = elf_dict_r32(ph.p_type);
      p_flags = elf_dict_r32(ph.p_flags);
      p_off = elf_dict_r64(ph.p_offset);
      p_filesz = elf_dict_r64(ph.p_filesz);

    } else {

      afl_elf32_phdr ph;
      memcpy(&ph, p, sizeof(ph));
      p_type = elf_dict_r32(ph.p_type);
      p_flags = elf_dict_r32(ph.p_flags);
      p_off = elf_dict_r32(ph.p_offset);
      p_filesz = elf_dict_r32(ph.p_filesz);

    }

    if (p_type != AFL_PT_LOAD) { continue; }
    if (p_flags & AFL_PF_X) { continue; }
    if (!p_filesz || p_filesz > 0xffffffffULL) { continue; }
    if (!elf_dict_in_bounds(p_off, p_filesz, map_len)) { continue; }

    elf_dict_scan_region(ctx, map + p_off, (u32)p_filesz, p_off);
    ++scanned;

  }

  return scanned;

}

u8 elf_dict_parse(elf_dict_ctx_t *ctx, u8 *map, u64 map_len) {

  u8  is64;
  u64 shoff, phoff;
  u16 shnum, shentsize, shstrndx, phnum, phentsize;
  u32 scanned;

  if (map_len < 20) { return 0; }

  if (map[AFL_EI_MAG0] != 0x7f || map[AFL_EI_MAG1] != 'E' ||
      map[AFL_EI_MAG2] != 'L' || map[AFL_EI_MAG3] != 'F') {

    return 0;

  }

  if (map[AFL_EI_CLASS] == AFL_ELFCLASS64) {

    is64 = 1;

  } else if (map[AFL_EI_CLASS] == AFL_ELFCLASS32) {

    is64 = 0;

  } else {

    return 0;

  }

  if (map[AFL_EI_DATA] == AFL_ELFDATA2LSB) {

    elf_swap = elf_dict_host_is_be() ? 1 : 0;

  } else if (map[AFL_EI_DATA] == AFL_ELFDATA2MSB) {

    elf_swap = elf_dict_host_is_be() ? 0 : 1;

  } else {

    return 0;

  }

  ctx->ptr_width = is64 ? 8 : 4;

  if (is64) {

    afl_elf64_ehdr eh;

    if (map_len < sizeof(eh)) { return 0; }
    memcpy(&eh, map, sizeof(eh));
    shoff = elf_dict_r64(eh.e_shoff);
    phoff = elf_dict_r64(eh.e_phoff);
    shnum = elf_dict_r16(eh.e_shnum);
    shentsize = elf_dict_r16(eh.e_shentsize);
    shstrndx = elf_dict_r16(eh.e_shstrndx);
    phnum = elf_dict_r16(eh.e_phnum);
    phentsize = elf_dict_r16(eh.e_phentsize);

  } else {

    afl_elf32_ehdr eh;

    if (map_len < sizeof(eh)) { return 0; }
    memcpy(&eh, map, sizeof(eh));
    shoff = elf_dict_r32(eh.e_shoff);
    phoff = elf_dict_r32(eh.e_phoff);
    shnum = elf_dict_r16(eh.e_shnum);
    shentsize = elf_dict_r16(eh.e_shentsize);
    shstrndx = elf_dict_r16(eh.e_shstrndx);
    phnum = elf_dict_r16(eh.e_phnum);
    phentsize = elf_dict_r16(eh.e_phentsize);

  }

  elf_dict_collect_load(ctx, map, map_len, is64, phoff, phnum, phentsize);

  scanned = elf_dict_scan_sections(ctx, map, map_len, is64, shoff, shnum,
                                   shentsize, shstrndx);

  if (!scanned) {

    scanned = elf_dict_scan_segments(ctx, map, map_len, is64, phoff, phnum,
                                     phentsize);

  }

  return scanned ? 1 : 0;

}

/* 1 when the token is already an extra. Lets user dictionaries, which are
   always loaded first, win over anything mined from the binary. */

u8 elf_dict_in_extras(struct extra_data *extras, u32 extras_cnt, u8 *data,
                      u32 len) {

  u32 i;

  if (!extras || !extras_cnt) { return 0; }

  for (i = 0; i < extras_cnt; ++i) {

    if (extras[i].len != len) { continue; }
    if (!memcmp(extras[i].data, data, len)) { return 1; }

  }

  return 0;

}

/* Writes the selection to <out_dir>/afl-elf.dict in AFL dictionary format so
   the result is inspectable and reusable with -x. */

static void elf_dict_write_file(afl_state_t *afl, elf_dict_ctx_t *ctx) {

  u8   *fn = alloc_printf("%s/afl-elf.dict", afl->out_dir);
  FILE *f = fopen((char *)fn, "w");
  u32   i, j;

  if (!f) {

    WARNF("Unable to write '%s'", fn);
    ck_free(fn);
    return;

  }

  for (i = 0; i < ctx->sel_cnt; ++i) {

    fprintf(f, "elf_%u=\"", i);

    for (j = 0; j < ctx->sel[i].len; ++j) {

      u8 c = ctx->sel[i].data[j];

      if (c == '"' || c == '\\') {

        fprintf(f, "\\%c", c);

      } else if (c >= 0x20 && c <= 0x7e) {

        fputc(c, f);

      } else {

        fprintf(f, "\\x%02x", c);

      }

    }

    fprintf(f, "\"\n");

  }

  fclose(f);
  ck_free(fn);

}

/* Mines fname for dictionary tokens. Never fatal: a target that cannot be
   mined is not a target that cannot be fuzzed. */

void load_extras_from_elf(afl_state_t *afl, u8 *fname) {

  elf_dict_ctx_t ctx;
  struct stat    st;
  s32            fd;
  u8            *map;
  u32            cap = ELF_DICT_MAX_TOKENS, i, added = 0;
  u64            map_len;

  if (!fname) { return; }

  memset(&ctx, 0, sizeof(ctx));

  /* AFL_ELF_DICT accepts:
       1        data sections only
       2        data sections plus executable code
       N > 2    data sections only, token budget N
       L:N      level L (1 or 2) with token budget N

     The bare-N form keeps the budget reachable without a second variable, and
     the L:N form exists because "2" and a large budget are exactly what a
     FourCC-heavy target wants at the same time. */

  if (afl->afl_env.afl_elf_dict) {

    char *s = (char *)afl->afl_env.afl_elf_dict;
    char *colon = strchr(s, ':');
    s32   v = atoi(s);

    if (colon) {

      s32 n = atoi(colon + 1);

      if (v == 2) { ctx.scan_text = 1; }
      if (n > 0) { cap = (u32)n; }

    } else if (v == 2) {

      ctx.scan_text = 1;

    } else if (v > 2) {

      cap = (u32)v;

    }

  }

  /* -a text: input_mode 1 means the target wants textual input. */
  ctx.text_mode = (afl->input_mode == 1) ? 1 : 0;

  fd = open((char *)fname, O_RDONLY);

  if (fd < 0) {

    WARNF("AFL_ELF_DICT: unable to open '%s'", fname);
    return;

  }

  if (fstat(fd, &st) || st.st_size < 20) {

    close(fd);
    return;

  }

  map_len = (u64)st.st_size;
  map = mmap(0, map_len, PROT_READ, MAP_PRIVATE, fd, 0);
  close(fd);

  if (map == MAP_FAILED) {

    WARNF("AFL_ELF_DICT: unable to mmap '%s'", fname);
    return;

  }

  if (!elf_dict_parse(&ctx, map, map_len)) {

    if (afl->debug) {

      WARNF("AFL_ELF_DICT: '%s' has no minable data sections", fname);

    }

    munmap(map, map_len);
    elf_dict_free(&ctx);
    return;

  }

  elf_dict_select(&ctx, cap);

  if (afl->debug) {

    SAYF(
        "[AFL_ELF_DICT] strings %llu/%u 32bit %llu/%u 64bit %llu/%u "
        "128bit %llu/%u text %llu/%u -> %u selected\n",
        ctx.seen[ELF_DICT_CLASS_STRING], ctx.tok_cnt[ELF_DICT_CLASS_STRING],
        ctx.seen[ELF_DICT_CLASS_32], ctx.tok_cnt[ELF_DICT_CLASS_32],
        ctx.seen[ELF_DICT_CLASS_64], ctx.tok_cnt[ELF_DICT_CLASS_64],
        ctx.seen[ELF_DICT_CLASS_128], ctx.tok_cnt[ELF_DICT_CLASS_128],
        ctx.seen[ELF_DICT_CLASS_TEXT], ctx.tok_cnt[ELF_DICT_CLASS_TEXT],
        ctx.sel_cnt);
    SAYF(
        "[AFL_ELF_DICT] rejected: uniform %llu small %llu textual %llu "
        "pointer %llu builtin %llu textmode %llu nottag %llu\n",
        ctx.rej[ELF_DICT_FILTER_UNIFORM], ctx.rej[ELF_DICT_FILTER_SMALL],
        ctx.rej[ELF_DICT_FILTER_TEXTUAL], ctx.rej[ELF_DICT_FILTER_POINTER],
        ctx.rej[ELF_DICT_FILTER_BUILTIN], ctx.rej[ELF_DICT_FILTER_TEXTMODE],
        ctx.rej[ELF_DICT_FILTER_NOTTAG]);

  }

  /* User dictionaries were loaded before this point and keep priority: a mined
     token that already exists as an extra is skipped, so the -x entry is the
     one that survives and mining stays purely additive. */

  for (i = 0; i < ctx.sel_cnt; ++i) {

    if (elf_dict_in_extras(afl->extras, afl->extras_cnt, ctx.sel[i].data,
                           ctx.sel[i].len)) {

      continue;

    }

    add_extra_nocheck(afl, ctx.sel[i].data, ctx.sel[i].len);
    ++added;

  }

  sort_extras(afl);

  if (ctx.sel_cnt) {

    elf_dict_write_file(afl, &ctx);
    OKF("Mined %u dictionary tokens from '%s' (%u added).", ctx.sel_cnt, fname,
        added);

  }

  munmap(map, map_len);
  elf_dict_free(&ctx);

}

