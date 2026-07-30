/*
   american fuzzy lop++ - ELF dictionary mining, internal interface
   ---------------------------------------------------------------

   Written by Marc Heuse <mh@mh-sec.de>

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version. See https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

   Types and internal entry points of src/afl-fuzz-elf.c. Split out from
   afl-elf.h so that the format definitions stay free of mining policy, and
   exposed as a header so test/unittests/unit_elf_dict.c can drive the scan
   and selection logic directly.

 */

#ifndef _HAVE_AFL_ELF_DICT_H
#define _HAVE_AFL_ELF_DICT_H

#include "types.h"
#include "config.h"

enum {

  ELF_DICT_CLASS_STRING = 0,
  ELF_DICT_CLASS_32,
  ELF_DICT_CLASS_64,
  ELF_DICT_CLASS_128,
  ELF_DICT_CLASS_TEXT,                 /* immediates out of executable code */
  ELF_DICT_CLASS_CNT

};

/* Which filter rejected a word. Counted per filter so AFL_DEBUG can show what
   each one actually contributes on a real binary. */

enum {

  ELF_DICT_FILTER_UNIFORM = 0,
  ELF_DICT_FILTER_SMALL,
  ELF_DICT_FILTER_TEXTUAL,
  ELF_DICT_FILTER_POINTER,
  ELF_DICT_FILTER_BUILTIN,
  ELF_DICT_FILTER_TEXTMODE,
  ELF_DICT_FILTER_NOTTAG,              /* code immediate that is not a tag  */
  ELF_DICT_FILTER_CNT

};

typedef struct elf_dict_token {

  u8  data[ELF_DICT_MAX_STRING];
  u32 len;
  u32 hits;                       /* occurrences, summed during dedup       */

} elf_dict_token_t;

typedef struct elf_dict_ctx {

  elf_dict_token_t *tok[ELF_DICT_CLASS_CNT];  /* candidates, per class      */
  u32               tok_cnt[ELF_DICT_CLASS_CNT];
  u64               seen[ELF_DICT_CLASS_CNT]; /* incl. those over the cap   */

  elf_dict_token_t *sel;                      /* selection, all classes     */
  u32               sel_cnt;

  u64 rej[ELF_DICT_FILTER_CNT];               /* rejections, per filter     */

  /* Bitmap over the region currently being scanned: a set bit means the byte
     belongs to a NUL-terminated string, so the string pass already covers it.
     Lets the textual filter reject text inside real strings while keeping a
     printable word that no string covers, such as a FourCC chunk tag sitting
     in an unterminated lookup table. */
  u8 *strcov;
  u8 *region;
  u32 region_len;

  /* Set for "-a text": the target wants textual input, so a numeric constant
     is only worth a token when it is itself printable alphanumeric. */
  u8 text_mode;

  /* Set for AFL_ELF_DICT=2: also scan executable sections. */
  u8 scan_text;

  u8  ptr_width;                              /* 4 or 8                     */
  u32 load_cnt;
  u64 load_lo[ELF_DICT_MAX_LOAD];             /* PT_LOAD vaddr ranges       */
  u64 load_hi[ELF_DICT_MAX_LOAD];

} elf_dict_ctx_t;

/* Numeric filters. Each returns 1 when the word should be rejected. */
u8 elf_dict_is_uniform(u8 *b, u32 w);
u8 elf_dict_is_small(u8 *b, u32 w);
u8 elf_dict_is_textual(u8 *b, u32 w);

/* 1 when every byte of the word belongs to a NUL-terminated string in the
   region currently being scanned. */
u8 elf_dict_str_covered(elf_dict_ctx_t *ctx, u8 *b, u32 w);

/* 1 when the word reads like an identifier or chunk tag rather than a ramp of
   byte values that happens to be printable. */
u8 elf_dict_is_tagish(u8 *b, u32 w);

/* 1 when the word is entirely letters and digits, optionally with a single
   trailing NUL. The only numeric constants kept under "-a text". */
u8 elf_dict_is_alnum_word(u8 *b, u32 w);

u8 elf_dict_is_pointer(elf_dict_ctx_t *ctx, u8 *b, u32 w);
u8 elf_dict_is_builtin(u8 *b, u32 w);

/* Reads w bytes as an unsigned value; be != 0 selects big-endian. w <= 8. */
u64 elf_dict_val(u8 *b, u32 w, u8 be);

/* 1 when the word survives every filter. */
u8 elf_dict_keep_numeric(elf_dict_ctx_t *ctx, u8 *b, u32 w);

void elf_dict_push(elf_dict_ctx_t *ctx, u32 class, u8 *data, u32 len);

/* Scans one region. file_off is the region's offset in the file, used to align
   numeric candidates the way the linker aligned them. */
void elf_dict_scan_region(elf_dict_ctx_t *ctx, u8 *base, u32 len, u64 file_off);

/* Scans one executable region for tag-like immediates. Unaligned, because a
   compiler embeds an immediate wherever the instruction stream puts it. */
void elf_dict_scan_text_region(elf_dict_ctx_t *ctx, u8 *base, u32 len);

/* Sorts by (len, bytes) and removes duplicates in place, accumulating each
   survivor's occurrence count into its hits field; returns the new count. */
u32 elf_dict_dedup(elf_dict_token_t *tok, u32 cnt);

/* Dedups every class, applies quotas with rollover, and where a class is over
   its allowance keeps the most frequently occurring tokens. Fills ctx->sel /
   ctx->sel_cnt and returns ctx->sel_cnt. */
u32 elf_dict_select(elf_dict_ctx_t *ctx, u32 cap);

/* Walks the ELF headers of a mapped image and scans its data regions.
   Returns 1 when the buffer was a usable ELF and at least one region was
   scanned. Never reads outside [map, map + map_len). */
u8 elf_dict_parse(elf_dict_ctx_t *ctx, u8 *map, u64 map_len);

void elf_dict_free(elf_dict_ctx_t *ctx);

#endif                                              /* _HAVE_AFL_ELF_DICT_H */

