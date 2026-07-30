/*
   american fuzzy lop++ - unit tests for ELF dictionary mining
   ----------------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version. See https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

   Exercises src/afl-fuzz-elf.c: the numeric filters, string and numeric region
   scanning, dedup and selection, and ELF header walking including malformed
   inputs.

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "afl-fuzz.h"
#include "afl-elf.h"
#include "afl-elf-dict.h"

/* afl-fuzz-elf.c references these; they live in afl-fuzz-one.c, which we do
   not link here, so define them locally. */
s8  interesting_8[INTERESTING_8_LEN] = {INTERESTING_8};
s16 interesting_16[INTERESTING_8_LEN + INTERESTING_16_LEN] = {INTERESTING_8,
                                                              INTERESTING_16};
s32 interesting_32[INTERESTING_8_LEN + INTERESTING_16_LEN +
                   INTERESTING_32_LEN] = {INTERESTING_8, INTERESTING_16,
                                          INTERESTING_32};

/* Stubs for the extras API that load_extras_from_elf() calls. */
void add_extra_nocheck(afl_state_t *afl, u8 *mem, u32 len) {

  (void)afl;
  (void)mem;
  (void)len;

}

void sort_extras(afl_state_t *afl) {

  (void)afl;

}

u8 elf_dict_in_extras(struct extra_data *extras, u32 extras_cnt, u8 *data,
                      u32 len);

static void test_elf_struct_sizes(void **state) {

  (void)state;
  assert_int_equal(sizeof(afl_elf32_ehdr), 52);
  assert_int_equal(sizeof(afl_elf64_ehdr), 64);
  assert_int_equal(sizeof(afl_elf32_shdr), 40);
  assert_int_equal(sizeof(afl_elf64_shdr), 64);
  assert_int_equal(sizeof(afl_elf32_phdr), 32);
  assert_int_equal(sizeof(afl_elf64_phdr), 56);

}

static void test_quotas_sum_to_cap(void **state) {

  (void)state;
  assert_int_equal(ELF_DICT_QUOTA_STRING + ELF_DICT_QUOTA_32 +
                       ELF_DICT_QUOTA_64 + ELF_DICT_QUOTA_128 +
                       ELF_DICT_QUOTA_TEXT,
                   ELF_DICT_MAX_TOKENS);

}

static void test_filter_uniform(void **state) {

  (void)state;
  u8 zero[4] = {0x00, 0x00, 0x00, 0x00};
  u8 ones[4] = {0x11, 0x11, 0x11, 0x11};
  u8 near[4] = {0x11, 0x11, 0x11, 0x12};

  assert_int_equal(elf_dict_is_uniform(zero, 4), 1);
  assert_int_equal(elf_dict_is_uniform(ones, 4), 1);
  assert_int_equal(elf_dict_is_uniform(near, 4), 0);

}

static void test_filter_small(void **state) {

  (void)state;
  u8 le_pos[4] = {0x2a, 0x00, 0x00, 0x00};             /* 42 little-endian */
  u8 be_pos[4] = {0x00, 0x00, 0x00, 0x2a};             /* 42 big-endian    */
  u8 le_neg[4] = {0xfe, 0xff, 0xff, 0xff};             /* -2 little-endian */
  u8 be_neg[4] = {0xff, 0xff, 0xff, 0xfe};             /* -2 big-endian    */
  u8 magic[4] = {0x89, 0x50, 0x4e, 0x47};              /* PNG, not small   */

  assert_int_equal(elf_dict_is_small(le_pos, 4), 1);
  assert_int_equal(elf_dict_is_small(be_pos, 4), 1);
  assert_int_equal(elf_dict_is_small(le_neg, 4), 1);
  assert_int_equal(elf_dict_is_small(be_neg, 4), 1);
  assert_int_equal(elf_dict_is_small(magic, 4), 0);

}

static void test_filter_textual(void **state) {

  (void)state;
  u8 text[4] = {'H', 'T', 'T', 'P'};
  u8 tail[4] = {'G', 'E', 'T', 0x00};
  u8 magic[4] = {0x89, 0x50, 0x4e, 0x47};

  assert_int_equal(elf_dict_is_textual(text, 4), 1);
  assert_int_equal(elf_dict_is_textual(tail, 4), 1);
  assert_int_equal(elf_dict_is_textual(magic, 4), 0);

}

static void test_filter_pointer_64(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* little-endian encodings of representative addresses */
  u8 nonpie[8] = {0x10, 0x4f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00};
  u8 pie[8] = {0x00, 0x10, 0x55, 0x55, 0x55, 0x55, 0x00, 0x00};
  u8 heap[8] = {0x40, 0xa2, 0x1b, 0x9c, 0x56, 0x00, 0x00, 0x00};
  u8 stack[8] = {0x18, 0xe4, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00};
  u8 kern[8] = {0x78, 0x56, 0x34, 0x12, 0x80, 0x88, 0xff, 0xff};
  u8 magic[8] = {0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca};

  assert_int_equal(elf_dict_is_pointer(&ctx, nonpie, 8), 1);
  assert_int_equal(elf_dict_is_pointer(&ctx, pie, 8), 1);
  assert_int_equal(elf_dict_is_pointer(&ctx, heap, 8), 1);
  assert_int_equal(elf_dict_is_pointer(&ctx, stack, 8), 1);
  assert_int_equal(elf_dict_is_pointer(&ctx, kern, 8), 1);
  assert_int_equal(elf_dict_is_pointer(&ctx, magic, 8), 0);

  /* 4-byte words are not pointer width in a 64-bit target */
  u8 four[4] = {0x10, 0x4f, 0x40, 0x00};
  assert_int_equal(elf_dict_is_pointer(&ctx, four, 4), 0);

}

static void test_filter_pointer_32(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 4;
  ctx.load_cnt = 1;
  ctx.load_lo[0] = 0x08048000;
  ctx.load_hi[0] = 0x08060000;

  u8 inside[4] = {0x10, 0x9f, 0x04, 0x08};              /* 0x08049f10 LE   */
  u8 outside[4] = {0x0d, 0x0c, 0x0b, 0x0a};             /* 0x0a0b0c0d LE   */

  assert_int_equal(elf_dict_is_pointer(&ctx, inside, 4), 1);
  assert_int_equal(elf_dict_is_pointer(&ctx, outside, 4), 0);

}

static void test_filter_builtin(void **state) {

  (void)state;
  u8 intmax[4] = {0xff, 0xff, 0xff, 0x7f};              /* 0x7fffffff LE   */
  u8 intmax_be[4] = {0x7f, 0xff, 0xff, 0xff};
  u8 magic[4] = {0x89, 0x50, 0x4e, 0x47};

  assert_int_equal(elf_dict_is_builtin(intmax, 4), 1);
  assert_int_equal(elf_dict_is_builtin(intmax_be, 4), 1);
  assert_int_equal(elf_dict_is_builtin(magic, 4), 0);

}

static void test_keep_numeric(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  u8 png[4] = {0x89, 0x50, 0x4e, 0x47};
  u8 zero[4] = {0x00, 0x00, 0x00, 0x00};

  assert_int_equal(elf_dict_keep_numeric(&ctx, png, 4), 1);
  assert_int_equal(elf_dict_keep_numeric(&ctx, zero, 4), 0);

  /* rejections are attributed to the filter that fired */
  assert_int_equal(ctx.rej[ELF_DICT_FILTER_UNIFORM], 1);
  assert_int_equal(ctx.rej[ELF_DICT_FILTER_SMALL], 0);

}

static void test_elf_dict_val(void **state) {

  (void)state;
  u8 b[4] = {0x89, 0x50, 0x4e, 0x47};

  assert_int_equal(elf_dict_val(b, 4, 0), 0x474e5089ULL);
  assert_int_equal(elf_dict_val(b, 4, 1), 0x89504e47ULL);

}

static void test_scan_strings(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* "Content-Length" is kept. "ab" is too short. "unterminated" has no NUL
     because the buffer ends. " lead" keeps its leading space: a space is
     ordinary printable ASCII and genuinely part of the string literal.
     "\tTabbed" does not, because \t may not open a run. "GET / HTTP/1.1\r\n"
     keeps its trailing CRLF, which is the whole point of allowing \r\n
     after the first byte. */
  u8 buf[] =
      "Content-Length\0"
      "ab\0"
      " lead\0"
      "\tTabbed\0"
      "GET / HTTP/1.1\r\n\0"
      "unterminated";

  elf_dict_scan_region(&ctx, buf, sizeof(buf) - 1, 0);

  u32 i, found_cl = 0, found_lead = 0, found_tab = 0, found_get = 0,
         found_ab = 0, found_unterm = 0;

  for (i = 0; i < ctx.tok_cnt[ELF_DICT_CLASS_STRING]; ++i) {

    elf_dict_token_t *t = &ctx.tok[ELF_DICT_CLASS_STRING][i];

    if (t->len == 14 && !memcmp(t->data, "Content-Length", 14)) {

      found_cl = 1;

    }

    if (t->len == 5 && !memcmp(t->data, " lead", 5)) { found_lead = 1; }
    if (t->len == 6 && !memcmp(t->data, "Tabbed", 6)) { found_tab = 1; }
    if (t->len == 16 && !memcmp(t->data, "GET / HTTP/1.1\r\n", 16)) {

      found_get = 1;

    }

    if (t->len == 2) { found_ab = 1; }
    if (t->len == 12 && !memcmp(t->data, "unterminated", 12)) {

      found_unterm = 1;

    }

  }

  assert_int_equal(found_cl, 1);
  assert_int_equal(found_lead, 1);
  assert_int_equal(found_tab, 1);
  assert_int_equal(found_get, 1);
  assert_int_equal(found_ab, 0);
  assert_int_equal(found_unterm, 0);

  elf_dict_free(&ctx);

}

/* Regression: libwebp stores "WEBP", "VP8X" and "ALPH" in .rodata without NUL
   terminators, so the string pass cannot see them. Rejecting every printable
   word as "already covered by strings" silently dropped exactly the tokens a
   WebP fuzzer needs most. A printable word must only be rejected when it
   really lies inside a NUL-terminated string. */
static void test_unterminated_fourcc_survives(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u32            i, found_webp = 0, found_text = 0;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* Offsets 0-3 hold an unterminated FourCC: the 0x01 that follows is neither
     printable nor a NUL, so no string run covers it. Offsets 8-11 hold "long",
     terminated by the NUL at 12, so a string run does cover that one. The
     0x01 filler at 4-7 is uniform and drops out on its own. */
  u8 buf[16] = {'W',  'E',  'B',  'P', 0x01, 0x01, 0x01, 0x01,
                'l',  'o',  'n',  'g', 0x00, 0x00, 0x00, 0x00};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 0);

  for (i = 0; i < ctx.tok_cnt[ELF_DICT_CLASS_32]; ++i) {

    elf_dict_token_t *t = &ctx.tok[ELF_DICT_CLASS_32][i];

    if (t->len == 4 && !memcmp(t->data, "WEBP", 4)) { found_webp = 1; }
    if (t->len == 4 && !memcmp(t->data, "long", 4)) { found_text = 1; }

  }

  /* the unterminated tag is kept */
  assert_int_equal(found_webp, 1);

  /* and so is its byte-reversed form */
  for (i = 0; i < ctx.tok_cnt[ELF_DICT_CLASS_32]; ++i) {

    elf_dict_token_t *t = &ctx.tok[ELF_DICT_CLASS_32][i];

    if (t->len == 4 && !memcmp(t->data, "PBEW", 4)) { found_webp = 2; }

  }

  assert_int_equal(found_webp, 2);

  /* a word inside the NUL-terminated string stays rejected */
  assert_int_equal(found_text, 0);

  /* the terminated string is still picked up by the string pass */
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_STRING], 1);
  assert_memory_equal(ctx.tok[ELF_DICT_CLASS_STRING][0].data, "long", 4);

  elf_dict_free(&ctx);

}

static void test_is_tagish(void **state) {

  (void)state;

  /* chunk tags and identifiers */
  assert_int_equal(elf_dict_is_tagish((u8 *)"WEBP", 4), 1);
  assert_int_equal(elf_dict_is_tagish((u8 *)"RIFF", 4), 1);
  assert_int_equal(elf_dict_is_tagish((u8 *)"VP8L", 4), 1);
  assert_int_equal(elf_dict_is_tagish((u8 *)"VP8 ", 4), 1);
  assert_int_equal(elf_dict_is_tagish((u8 *)"a_b1", 4), 1);

  /* ramps of byte values out of a numeric table that happen to be printable */
  assert_int_equal(elf_dict_is_tagish((u8 *)" !\"#", 4), 0);
  assert_int_equal(elf_dict_is_tagish((u8 *)"'()*", 4), 0);
  assert_int_equal(elf_dict_is_tagish((u8 *)",-./", 4), 0);

  /* digits alone carry no letter, so they read as a table not a tag */
  assert_int_equal(elf_dict_is_tagish((u8 *)"0123", 4), 0);

}

/* Regression: without the tag test, keeping every printable word that no
   string covers admitted ~960 junk tokens from libwebp alone. */
static void test_printable_ramp_still_rejected(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u32            i, found_ramp = 0;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* an ascending, unterminated, entirely printable byte table */
  u8 buf[8] = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 0);

  for (i = 0; i < ctx.tok_cnt[ELF_DICT_CLASS_32]; ++i) {

    if (ctx.tok[ELF_DICT_CLASS_32][i].len == 4) { found_ramp = 1; }

  }

  assert_int_equal(found_ramp, 0);
  assert_int_equal(ctx.rej[ELF_DICT_FILTER_TEXTUAL] > 0, 1);

  elf_dict_free(&ctx);

}

static void test_is_alnum_word(void **state) {

  (void)state;

  /* letters and digits, with an optional single trailing NUL */
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"ABCD", 4), 1);
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"VP8L", 4), 1);
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"1234", 4), 1);
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"GET\0", 4), 1);

  /* two trailing NULs is not "an optional null byte ending" */
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"AB\0\0", 4), 0);

  /* is_tagish tolerates NUL padding, so the two notions agree on "GET\0" */
  assert_int_equal(elf_dict_is_tagish((u8 *)"GET\0", 4), 1);

  /* punctuation, spaces and raw bytes are all out */
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"a-b1", 4), 0);
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"VP8 ", 4), 0);
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"\x89PNG", 4), 0);
  assert_int_equal(elf_dict_is_alnum_word((u8 *)"\0\0\0\0", 4), 0);

}

static void test_text_mode_keeps_only_alnum_constants(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;

  u8 png[4] = {0x89, 0x50, 0x4e, 0x47};
  u8 tag[4] = {'V', 'P', '8', 'L'};
  u8 tagnul[4] = {'G', 'E', 'T', 0x00};

  /* binary mode: the raw magic is a perfectly good token */
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;
  assert_int_equal(elf_dict_keep_numeric(&ctx, png, 4), 1);

  /* -a text: it is not, and the rejection is attributed to the text filter */
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;
  ctx.text_mode = 1;
  assert_int_equal(elf_dict_keep_numeric(&ctx, png, 4), 0);
  assert_int_equal(ctx.rej[ELF_DICT_FILTER_TEXTMODE], 1);

  /* but an alphanumeric constant still is, with or without a trailing NUL */
  assert_int_equal(elf_dict_keep_numeric(&ctx, tag, 4), 1);
  assert_int_equal(elf_dict_keep_numeric(&ctx, tagnul, 4), 1);

}

static void test_text_mode_keeps_strings(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;
  ctx.text_mode = 1;

  u8 buf[24] = {'C', 'o', 'n', 't', 'e', 'n', 't', '-',
                'T', 'y', 'p', 'e', 0x00, 0x89, 0x50, 0x4e,
                0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 0);

  /* strings are unaffected by text mode */
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_STRING], 1);
  assert_memory_equal(ctx.tok[ELF_DICT_CLASS_STRING][0].data, "Content-Type",
                      12);

  /* the embedded PNG magic is not alphanumeric, so no numeric token survives */
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_32], 0);
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_64], 0);

  elf_dict_free(&ctx);

}

/* A compiler puts a magic into an instruction immediate at whatever offset the
   instruction stream lands on, so the code pass must sweep every byte offset,
   not just aligned ones. */
static void test_scan_text_finds_unaligned_immediate(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u32            i, found = 0;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* "cmpl $0x50424557, 0x8(%rbx)" - the tag starts at offset 3 */
  u8 buf[12] = {0x81, 0x7b, 0x08, 'W', 'E', 'B',
                'P',  0x0f, 0x85, 0x83, 0x01, 0x00};

  elf_dict_scan_text_region(&ctx, buf, sizeof(buf));

  for (i = 0; i < ctx.tok_cnt[ELF_DICT_CLASS_TEXT]; ++i) {

    elf_dict_token_t *t = &ctx.tok[ELF_DICT_CLASS_TEXT][i];

    if (t->len == 4 && !memcmp(t->data, "WEBP", 4)) { found = 1; }

  }

  assert_int_equal(found, 1);

  /* the surrounding opcode bytes are not tags and must not become tokens */
  assert_true(ctx.rej[ELF_DICT_FILTER_NOTTAG] > 0);

  elf_dict_free(&ctx);

}

/* Without the tag requirement, 93.6% of unaligned windows in a real .text
   survive the numeric filters, because instruction bytes are near-random. */
static void test_scan_text_rejects_opcode_noise(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* a stretch of ordinary x86-64 with no embedded tag */
  u8 buf[16] = {0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x64,
                0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00};

  elf_dict_scan_text_region(&ctx, buf, sizeof(buf));

  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_TEXT], 0);

  elf_dict_free(&ctx);

}

static void test_str_covered(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;

  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* with no region set up, nothing is considered covered */
  u8 word[4] = {'a', 'b', 'c', 'd'};
  assert_int_equal(elf_dict_str_covered(&ctx, word, 4), 0);

  u8 buf[16] = {'W', 'E', 'B', 'P', 'l', 'o', 'n', 'g',
                'i', 's', 'h', 0,   0,   0,   0,   0};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 0);

  /* region pointers are cleared once the scan is done */
  assert_int_equal(elf_dict_str_covered(&ctx, buf, 4), 0);

  elf_dict_free(&ctx);

}

static void test_scan_numeric_both_orders(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* one 4-byte PNG magic, 4-byte aligned, nothing else that survives */
  u8 buf[8] = {0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x00, 0x00};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 0);

  /* as found plus byte-reversed */
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_32], 2);
  assert_memory_equal(ctx.tok[ELF_DICT_CLASS_32][0].data, "\x89\x50\x4e\x47",
                      4);
  assert_memory_equal(ctx.tok[ELF_DICT_CLASS_32][1].data, "\x47\x4e\x50\x89",
                      4);

  elf_dict_free(&ctx);

}

static void test_scan_numeric_palindrome_once(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  u8 buf[4] = {0x91, 0xa3, 0xa3, 0x91};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 0);

  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_32], 1);

  elf_dict_free(&ctx);

}

static void test_scan_numeric_128_not_reversed(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  u8 buf[16] = {0x91, 0x33, 0xc5, 0xa7, 0x18, 0x2b, 0xd4, 0x6e,
                0xf1, 0x0c, 0x9a, 0x57, 0x23, 0xbe, 0x8d, 0x41};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 0);

  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_128], 1);
  assert_memory_equal(ctx.tok[ELF_DICT_CLASS_128][0].data, buf, 16);

  elf_dict_free(&ctx);

}

static void test_scan_alignment_uses_file_offset(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.ptr_width = 8;

  /* Region sits at file offset 2, so the first 4-byte aligned word starts at
     buf[2] (file offset 4), not at buf[0]. */
  u8 buf[8] = {0xaa, 0xbb, 0x89, 0x50, 0x4e, 0x47, 0xcc, 0xdd};

  elf_dict_scan_region(&ctx, buf, sizeof(buf), 2);

  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_32], 2);
  assert_memory_equal(ctx.tok[ELF_DICT_CLASS_32][0].data, "\x89\x50\x4e\x47",
                      4);

  elf_dict_free(&ctx);

}

static void test_dedup(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  memset(&ctx, 0, sizeof(ctx));

  elf_dict_push(&ctx, ELF_DICT_CLASS_32, (u8 *)"\x01\x02\x03\x04", 4);
  elf_dict_push(&ctx, ELF_DICT_CLASS_32, (u8 *)"\x01\x02\x03\x04", 4);
  elf_dict_push(&ctx, ELF_DICT_CLASS_32, (u8 *)"\x05\x06\x07\x08", 4);

  u32 cnt = elf_dict_dedup(ctx.tok[ELF_DICT_CLASS_32],
                           ctx.tok_cnt[ELF_DICT_CLASS_32]);

  assert_int_equal(cnt, 2);

  elf_dict_free(&ctx);

}

static void test_select_under_quota_keeps_all(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u32            i;
  memset(&ctx, 0, sizeof(ctx));

  for (i = 0; i < 10; ++i) {

    u8 b[4] = {0x91, 0xa3, (u8)(i >> 8), (u8)i};
    elf_dict_push(&ctx, ELF_DICT_CLASS_32, b, 4);

  }

  assert_int_equal(elf_dict_select(&ctx, ELF_DICT_MAX_TOKENS), 10);
  assert_int_equal(ctx.sel_cnt, 10);

  elf_dict_free(&ctx);

}

/* Selection under pressure keeps the most frequently occurring tokens.
   Positional stride selection was measured to throw away libwebp's "WEBP" and
   libxml2's "UTF-8" at the default cap, because it cannot tell a magic value
   from table filler. */
static void test_select_prefers_frequent_tokens(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u32            i;
  memset(&ctx, 0, sizeof(ctx));

  /* 1000 distinct tokens seen once each */
  for (i = 0; i < 1000; ++i) {

    u8 b[4] = {0x91, 0xa3, (u8)(i >> 8), (u8)i};
    elf_dict_push(&ctx, ELF_DICT_CLASS_32, b, 4);

  }

  /* plus one seen five times, which must outrank all of them */
  for (i = 0; i < 5; ++i) {

    elf_dict_push(&ctx, ELF_DICT_CLASS_32, (u8 *)"\x91\xa3\xff\xfe", 4);

  }

  assert_int_equal(elf_dict_select(&ctx, 4), 4);
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_32], 1001);

  /* the repeated token is ranked first and its hits were accumulated */
  assert_memory_equal(ctx.sel[0].data, "\x91\xa3\xff\xfe", 4);
  assert_int_equal(ctx.sel[0].hits, 5);

  /* the rest are singletons */
  for (i = 1; i < 4; ++i) {

    assert_int_equal(ctx.sel[i].hits, 1);

  }

  elf_dict_free(&ctx);

}

static void test_select_never_exceeds_cap(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u32            i;
  memset(&ctx, 0, sizeof(ctx));

  for (i = 0; i < 5000; ++i) {

    u8 s[8];
    snprintf((char *)s, sizeof(s), "s%05u", i);
    elf_dict_push(&ctx, ELF_DICT_CLASS_STRING, s, 6);

  }

  for (i = 0; i < 5000; ++i) {

    u8 b[4] = {0x91, (u8)(i >> 16), (u8)(i >> 8), (u8)i};
    elf_dict_push(&ctx, ELF_DICT_CLASS_32, b, 4);

  }

  assert_int_equal(elf_dict_select(&ctx, 100), 100);
  assert_int_equal(ctx.sel_cnt, 100);

  elf_dict_free(&ctx);

}

static void test_select_rollover_feeds_later_classes(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u32            i;
  memset(&ctx, 0, sizeof(ctx));

  /* No strings and no 64/128-bit constants at all: every other class's quota
     must reach the 32-bit class, which has candidates to spare, so the full
     budget gets spent rather than a 1536-token fraction of it. */
  for (i = 0; i < 3000; ++i) {

    u8 b[4] = {0x91, (u8)(i >> 16), (u8)(i >> 8), (u8)i};
    elf_dict_push(&ctx, ELF_DICT_CLASS_32, b, 4);

  }

  assert_int_equal(elf_dict_select(&ctx, ELF_DICT_MAX_TOKENS),
                   ELF_DICT_MAX_TOKENS);

  elf_dict_free(&ctx);

}

/* Builds a minimal ELF64 LSB object: ehdr, three section headers (null,
   .rodata, .shstrtab), the section header string table, and a .rodata
   payload. shoff_override / shnum_override inject malformed values. */
static u32 build_elf64(u8 *out, u32 out_len, u8 *payload, u32 payload_len,
                       u64 shoff_override, u16 shnum_override) {

  const char shstr[] = "\0.rodata\0.shstrtab";
  u32        shstr_len = sizeof(shstr);
  u32        ro_off = 0x200;
  u32        shstr_off = ro_off + payload_len;
  u32        sh_off = shstr_off + shstr_len;
  u32        total = sh_off + 3 * sizeof(afl_elf64_shdr);

  afl_elf64_ehdr eh;
  afl_elf64_shdr sh;

  assert_true(total <= out_len);
  memset(out, 0, total);

  memset(&eh, 0, sizeof(eh));
  eh.e_ident[AFL_EI_MAG0] = 0x7f;
  eh.e_ident[AFL_EI_MAG1] = 'E';
  eh.e_ident[AFL_EI_MAG2] = 'L';
  eh.e_ident[AFL_EI_MAG3] = 'F';
  eh.e_ident[AFL_EI_CLASS] = AFL_ELFCLASS64;
  eh.e_ident[AFL_EI_DATA] = AFL_ELFDATA2LSB;
  eh.e_type = AFL_ET_EXEC;
  eh.e_machine = AFL_EM_X86_64;
  eh.e_ehsize = (u16)sizeof(eh);
  eh.e_shoff = shoff_override ? shoff_override : sh_off;
  eh.e_shentsize = (u16)sizeof(afl_elf64_shdr);
  eh.e_shnum = shnum_override ? shnum_override : 3;
  eh.e_shstrndx = 2;
  memcpy(out, &eh, sizeof(eh));

  memcpy(out + ro_off, payload, payload_len);
  memcpy(out + shstr_off, shstr, shstr_len);

  /* index 0: SHT_NULL */
  memset(&sh, 0, sizeof(sh));
  memcpy(out + sh_off, &sh, sizeof(sh));

  /* index 1: .rodata */
  memset(&sh, 0, sizeof(sh));
  sh.sh_name = 1;
  sh.sh_type = AFL_SHT_PROGBITS;
  sh.sh_flags = AFL_SHF_ALLOC;
  sh.sh_addr = 0x400000 + ro_off;
  sh.sh_offset = ro_off;
  sh.sh_size = payload_len;
  memcpy(out + sh_off + sizeof(sh), &sh, sizeof(sh));

  /* index 2: .shstrtab */
  memset(&sh, 0, sizeof(sh));
  sh.sh_name = 9;
  sh.sh_type = AFL_SHT_STRTAB;
  sh.sh_offset = shstr_off;
  sh.sh_size = shstr_len;
  memcpy(out + sh_off + 2 * sizeof(sh), &sh, sizeof(sh));

  return total;

}

static void test_parse_finds_rodata(void **state) {

  (void)state;
  static u8      img[8192];
  elf_dict_ctx_t ctx;
  u8             payload[32];

  memset(&ctx, 0, sizeof(ctx));
  memset(payload, 0, sizeof(payload));
  memcpy(payload, "Content-Length", 15);
  payload[16] = 0x89;
  payload[17] = 0x50;
  payload[18] = 0x4e;
  payload[19] = 0x47;

  u32 len = build_elf64(img, sizeof(img), payload, sizeof(payload), 0, 0);

  assert_int_equal(elf_dict_parse(&ctx, img, len), 1);
  assert_int_equal(ctx.ptr_width, 8);
  assert_true(ctx.tok_cnt[ELF_DICT_CLASS_STRING] >= 1);
  assert_true(ctx.tok_cnt[ELF_DICT_CLASS_32] >= 2);

  elf_dict_free(&ctx);

}

static void test_parse_rejects_non_elf(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u8             buf[64];

  memset(&ctx, 0, sizeof(ctx));
  memset(buf, 'A', sizeof(buf));

  assert_int_equal(elf_dict_parse(&ctx, buf, sizeof(buf)), 0);

  elf_dict_free(&ctx);

}

static void test_parse_survives_bad_shoff(void **state) {

  (void)state;
  static u8      img[8192];
  elf_dict_ctx_t ctx;
  u8             payload[32];

  memset(&ctx, 0, sizeof(ctx));
  memset(payload, 0x41, sizeof(payload));

  /* e_shoff points far past the end of the buffer */
  u32 len =
      build_elf64(img, sizeof(img), payload, sizeof(payload), 0xdeadbeef, 0);

  /* no crash, no read past the buffer, nothing usable found */
  elf_dict_parse(&ctx, img, len);
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_STRING], 0);

  elf_dict_free(&ctx);

}

static void test_parse_survives_shnum_overflow(void **state) {

  (void)state;
  static u8      img[8192];
  elf_dict_ctx_t ctx;
  u8             payload[32];

  memset(&ctx, 0, sizeof(ctx));
  memset(payload, 0x41, sizeof(payload));

  /* claims 40000 section headers in a buffer that holds three */
  u32 len = build_elf64(img, sizeof(img), payload, sizeof(payload), 0, 40000);

  elf_dict_parse(&ctx, img, len);
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_STRING], 0);

  elf_dict_free(&ctx);

}

static void test_parse_survives_truncated_buffer(void **state) {

  (void)state;
  elf_dict_ctx_t ctx;
  u8             buf[8];

  memset(&ctx, 0, sizeof(ctx));
  buf[0] = 0x7f;
  buf[1] = 'E';
  buf[2] = 'L';
  buf[3] = 'F';
  buf[4] = AFL_ELFCLASS64;
  buf[5] = AFL_ELFDATA2LSB;
  buf[6] = 1;
  buf[7] = 0;

  assert_int_equal(elf_dict_parse(&ctx, buf, sizeof(buf)), 0);

  elf_dict_free(&ctx);

}

static void test_in_extras_gives_user_dict_priority(void **state) {

  (void)state;
  struct extra_data e[2];
  u8                a[4] = {0x89, 0x50, 0x4e, 0x47};
  u8                b[4] = {0x01, 0x02, 0x03, 0x04};

  e[0].data = a;
  e[0].len = 4;
  e[1].data = (u8 *)"GET";
  e[1].len = 3;

  assert_int_equal(elf_dict_in_extras(e, 2, a, 4), 1);
  assert_int_equal(elf_dict_in_extras(e, 2, (u8 *)"GET", 3), 1);
  assert_int_equal(elf_dict_in_extras(e, 2, b, 4), 0);
  assert_int_equal(elf_dict_in_extras(NULL, 0, a, 4), 0);

}

/* --- AFL_CMPLOG_BINARY_CONSTS: the constant set used to gate cmplog --- */

static void test_const_dedup_and_lookup32(void **state) {

  (void)state;
  u32 v[8] = {7, 3, 3, 0xdeadbeef, 1, 7, 0xdeadbeef, 42};
  u32 cnt = elf_const_dedup32(v, 8);

  /* 7, 3, 0xdeadbeef, 1, 42 -> five distinct, sorted ascending */
  assert_int_equal(cnt, 5);
  assert_int_equal(v[0], 1);
  assert_int_equal(v[1], 3);
  assert_int_equal(v[2], 7);
  assert_int_equal(v[3], 42);
  assert_int_equal(v[4], 0xdeadbeef);

  assert_int_equal(elf_const_lookup32(v, cnt, 0xdeadbeef), 1);
  assert_int_equal(elf_const_lookup32(v, cnt, 1), 1);
  assert_int_equal(elf_const_lookup32(v, cnt, 42), 1);
  assert_int_equal(elf_const_lookup32(v, cnt, 0xcafebabe), 0);
  assert_int_equal(elf_const_lookup32(v, cnt, 0), 0);

  /* an empty set must never claim membership */
  assert_int_equal(elf_const_lookup32(v, 0, 1), 0);
  assert_int_equal(elf_const_lookup32(NULL, 0, 1), 0);

}

static void test_const_dedup_and_lookup64(void **state) {

  (void)state;
  u64 v[6] = {0xdeadbeefcafebabeULL, 5, 5, 0xdeadbeefcafebabeULL, 1, 9};
  u32 cnt = elf_const_dedup64(v, 6);

  assert_int_equal(cnt, 4);
  assert_int_equal(v[0], 1);
  assert_int_equal(v[3], 0xdeadbeefcafebabeULL);

  assert_int_equal(elf_const_lookup64(v, cnt, 0xdeadbeefcafebabeULL), 1);
  assert_int_equal(elf_const_lookup64(v, cnt, 9), 1);
  assert_int_equal(elf_const_lookup64(v, cnt, 0xcafebabeULL), 0);
  assert_int_equal(elf_const_lookup64(NULL, 0, 5), 0);

}

/* The set must be swept unaligned, so a constant embedded at an odd offset -
   an instruction immediate, typically - is still found. */
static void test_const_collect_is_unaligned(void **state) {

  (void)state;
  static u8      img[8192];
  elf_dict_ctx_t ctx;
  u8             payload[32];

  memset(&ctx, 0, sizeof(ctx));
  ctx.collect_consts = 1;

  memset(payload, 0x41, sizeof(payload));
  /* 0xdeadbeef little-endian at offset 3, deliberately unaligned */
  payload[3] = 0xef;
  payload[4] = 0xbe;
  payload[5] = 0xad;
  payload[6] = 0xde;

  u32 len = build_elf64(img, sizeof(img), payload, sizeof(payload), 0, 0);

  assert_int_equal(elf_dict_parse(&ctx, img, len), 1);

  ctx.c32_cnt = elf_const_dedup32(ctx.c32, ctx.c32_cnt);

  assert_true(ctx.c32_cnt > 0);
  assert_int_equal(elf_const_lookup32(ctx.c32, ctx.c32_cnt, 0xdeadbeef), 1);

  /* the filler is there too, but an unrelated value is not */
  assert_int_equal(elf_const_lookup32(ctx.c32, ctx.c32_cnt, 0x41414141), 1);
  assert_int_equal(elf_const_lookup32(ctx.c32, ctx.c32_cnt, 0x12345678), 0);

  /* collecting constants must not produce dictionary tokens */
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_STRING], 0);
  assert_int_equal(ctx.tok_cnt[ELF_DICT_CLASS_32], 0);

  elf_dict_free(&ctx);

}

/* The gate must fail open: an absent or empty set means "do not gate", never
   "reject everything", or cmplog would silently lose every token. */
static void test_const_in_binary_fails_open(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  u32          set32[2] = {0x11223344, 0xdeadbeef};
  u64          set64[2] = {0x1122334455667788ULL, 0xdeadbeefcafebabeULL};

  assert_non_null(afl);

  /* no set at all -> everything passes */
  assert_int_equal(const_in_binary(afl, 0xdeadbeef, 4), 1);
  assert_int_equal(const_in_binary(afl, 0x99999999, 4), 1);
  assert_int_equal(const_in_binary(afl, 0xdeadbeefcafebabeULL, 8), 1);

  afl->ro_consts32 = set32;
  afl->ro_consts32_cnt = 2;
  afl->ro_consts64 = set64;
  afl->ro_consts64_cnt = 2;

  /* with a set, membership decides */
  assert_int_equal(const_in_binary(afl, 0xdeadbeef, 4), 1);
  assert_int_equal(const_in_binary(afl, 0x11223344, 4), 1);
  assert_int_equal(const_in_binary(afl, 0x99999999, 4), 0);
  assert_int_equal(const_in_binary(afl, 0xdeadbeefcafebabeULL, 8), 1);
  assert_int_equal(const_in_binary(afl, 0x1234567812345678ULL, 8), 0);

  /* widths where the answer carries no information are never gated */
  assert_int_equal(const_in_binary(afl, 0x99, 1), 1);
  assert_int_equal(const_in_binary(afl, 0x9999, 2), 1);
  assert_int_equal(const_in_binary(afl, 0x99999999, 16), 1);

  /* a 32-bit set present but the 64-bit one missing must not gate 64-bit */
  afl->ro_consts64 = NULL;
  afl->ro_consts64_cnt = 0;
  assert_int_equal(const_in_binary(afl, 0x1234567812345678ULL, 8), 1);

  afl->ro_consts32 = NULL;
  afl->ro_consts32_cnt = 0;
  free(afl);

}

/* The cmplog gate may only be enabled implicitly where a wide immediate is one
   contiguous field. Verified with clang: on aarch64 a 32-bit magic used in a
   comparison is assembled by "mov"+"movk" and appears nowhere in the object, so
   gating there would reject it. */
static void test_immediates_contiguous_by_arch(void **state) {

  (void)state;

  assert_int_equal(elf_dict_immediates_contiguous(AFL_EM_X86_64), 1);
  assert_int_equal(elf_dict_immediates_contiguous(AFL_EM_386), 1);

  assert_int_equal(elf_dict_immediates_contiguous(AFL_EM_AARCH64), 0);
  assert_int_equal(elf_dict_immediates_contiguous(AFL_EM_ARM), 0);
  assert_int_equal(elf_dict_immediates_contiguous(AFL_EM_RISCV), 0);
  assert_int_equal(elf_dict_immediates_contiguous(AFL_EM_MIPS), 0);
  assert_int_equal(elf_dict_immediates_contiguous(AFL_EM_PPC64), 0);

  /* an architecture we have not characterised must default to "not safe" */
  assert_int_equal(elf_dict_immediates_contiguous(0), 0);
  assert_int_equal(elf_dict_immediates_contiguous(9999), 0);

}

/* e_machine has to be picked up by the header walk, since the gate decision
   depends on it. */
static void test_parse_records_e_machine(void **state) {

  (void)state;
  static u8      img[8192];
  elf_dict_ctx_t ctx;
  u8             payload[32];

  memset(&ctx, 0, sizeof(ctx));
  memset(payload, 0x41, sizeof(payload));

  u32 len = build_elf64(img, sizeof(img), payload, sizeof(payload), 0, 0);

  assert_int_equal(elf_dict_parse(&ctx, img, len), 1);
  assert_int_equal(ctx.e_machine, AFL_EM_X86_64);

  elf_dict_free(&ctx);

}

/* The gate is on by default, so it has to notice when it is wrong about a
   target. Rejecting nearly every operand means the constants live somewhere the
   scan never looked - typically an instrumented shared library, whose values
   are in the .so and not in the executable. It must then stop gating rather
   than quietly starve cmplog of its dictionary. */
static void test_const_gate_disables_itself(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  u32          set32[2] = {0x11223344, 0xdeadbeef};
  u32          i;

  assert_non_null(afl);
  afl->ro_consts32 = set32;
  afl->ro_consts32_cnt = 2;

  /* feed it values that are all absent, as the shared-library case would */
  for (i = 0; i < ELF_CONST_GATE_SAMPLE - 1; ++i) {

    assert_int_equal(const_in_binary(afl, 0x90000000 + i, 4), 0);

  }

  assert_int_equal(afl->const_gate_off, 0);

  /* the decision is taken on the sample'th operand */
  assert_int_equal(const_in_binary(afl, 0x90000000 + i, 4), 1);
  assert_int_equal(afl->const_gate_off, 1);

  /* from then on nothing is gated, not even a value clearly absent */
  assert_int_equal(const_in_binary(afl, 0x12345678, 4), 1);
  assert_int_equal(const_in_binary(afl, 0x12345678, 8), 1);

  afl->ro_consts32 = NULL;
  afl->ro_consts32_cnt = 0;
  free(afl);

}

/* A healthy target accepts a decent fraction, so the gate must stay on. */
static void test_const_gate_survives_healthy_target(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  u32          set32[2] = {0x11223344, 0xdeadbeef};
  u32          i;

  assert_non_null(afl);
  afl->ro_consts32 = set32;
  afl->ro_consts32_cnt = 2;

  /* one in ten present, far above the 1-in-200 floor */
  for (i = 0; i < ELF_CONST_GATE_SAMPLE + 10; ++i) {

    if (i % 10 == 0) {

      assert_int_equal(const_in_binary(afl, 0xdeadbeef, 4), 1);

    } else {

      const_in_binary(afl, 0x90000000 + i, 4);

    }

  }

  assert_int_equal(afl->const_gate_off, 0);
  assert_int_equal(const_in_binary(afl, 0x12345678, 4), 0);

  afl->ro_consts32 = NULL;
  afl->ro_consts32_cnt = 0;
  free(afl);

}

int main(void) {

  const struct CMUnitTest tests[] = {

      cmocka_unit_test(test_elf_struct_sizes),
      cmocka_unit_test(test_quotas_sum_to_cap),
      cmocka_unit_test(test_filter_uniform),
      cmocka_unit_test(test_filter_small),
      cmocka_unit_test(test_filter_textual),
      cmocka_unit_test(test_filter_pointer_64),
      cmocka_unit_test(test_filter_pointer_32),
      cmocka_unit_test(test_filter_builtin),
      cmocka_unit_test(test_keep_numeric),
      cmocka_unit_test(test_elf_dict_val),
      cmocka_unit_test(test_scan_strings),
      cmocka_unit_test(test_unterminated_fourcc_survives),
      cmocka_unit_test(test_is_tagish),
      cmocka_unit_test(test_printable_ramp_still_rejected),
      cmocka_unit_test(test_is_alnum_word),
      cmocka_unit_test(test_text_mode_keeps_only_alnum_constants),
      cmocka_unit_test(test_text_mode_keeps_strings),
      cmocka_unit_test(test_scan_text_finds_unaligned_immediate),
      cmocka_unit_test(test_scan_text_rejects_opcode_noise),
      cmocka_unit_test(test_str_covered),
      cmocka_unit_test(test_scan_numeric_both_orders),
      cmocka_unit_test(test_scan_numeric_palindrome_once),
      cmocka_unit_test(test_scan_numeric_128_not_reversed),
      cmocka_unit_test(test_scan_alignment_uses_file_offset),
      cmocka_unit_test(test_dedup),
      cmocka_unit_test(test_select_under_quota_keeps_all),
      cmocka_unit_test(test_select_prefers_frequent_tokens),
      cmocka_unit_test(test_select_never_exceeds_cap),
      cmocka_unit_test(test_select_rollover_feeds_later_classes),
      cmocka_unit_test(test_parse_finds_rodata),
      cmocka_unit_test(test_parse_rejects_non_elf),
      cmocka_unit_test(test_parse_survives_bad_shoff),
      cmocka_unit_test(test_parse_survives_shnum_overflow),
      cmocka_unit_test(test_parse_survives_truncated_buffer),
      cmocka_unit_test(test_in_extras_gives_user_dict_priority),
      cmocka_unit_test(test_const_dedup_and_lookup32),
      cmocka_unit_test(test_const_dedup_and_lookup64),
      cmocka_unit_test(test_const_collect_is_unaligned),
      cmocka_unit_test(test_const_in_binary_fails_open),
      cmocka_unit_test(test_immediates_contiguous_by_arch),
      cmocka_unit_test(test_parse_records_e_machine),
      cmocka_unit_test(test_const_gate_disables_itself),
      cmocka_unit_test(test_const_gate_survives_healthy_target),

  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}

