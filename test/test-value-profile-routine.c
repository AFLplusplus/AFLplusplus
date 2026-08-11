#if defined(__linux__)
  #define _GNU_SOURCE
#endif

#include <stdint.h>
#include <string.h>

#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__) || \
    defined(__NetBSD__) || defined(__OpenBSD__)
  #include <sys/mman.h>
  #include <unistd.h>
  #ifndef MAP_ANONYMOUS
    #define MAP_ANONYMOUS MAP_ANON
  #endif
  #define VP_HAVE_GUARD_PAGE_TEST 1
#endif

#include "../include/value-profile.h"
#include "test-value-profile-common.h"

extern vp_map_t *__afl_vp_map;
void __valueprofile_rtn_hook_n(uint8_t *ptr1, uint8_t *ptr2, uint64_t len,
                               uint64_t site_token);
void __valueprofile_rtn_hook_strn(uint8_t *ptr1, uint8_t *ptr2, uint64_t len,
                                  uint64_t site_token);
void __valueprofile_rtn_hook_str(uint8_t *ptr1, uint8_t *ptr2,
                                 uint64_t site_token);
void __valueprofile_rtn_hook_str_ci(uint8_t *ptr1, uint8_t *ptr2,
                                    uint64_t site_token);
void __valueprofile_rtn_hook_strn_ci(uint8_t *ptr1, uint8_t *ptr2, uint64_t len,
                                     uint64_t site_token);
void __valueprofile_rtn_hook_sub(uint8_t *hay, uint8_t *needle,
                                 uint64_t site_token);
void __valueprofile_rtn_hook_sub_hn(uint8_t *hay, uint64_t hay_len,
                                    uint8_t *needle, uint64_t site_token);
void __sanitizer_weak_hook_strncasestr(void *pc, const void *s1, const void *s2,
                                       size_t n, char *result);

static const uint16_t site = 0x3456U;
static const uint64_t site_token = VP_TEST_TOKEN_FOR_SITE(0x3456U, 0x3456789aU);

static vp_map_t vp_local;

static void begin_exec(void) {

  vp_local.enabled = 1;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;

}

#ifdef VP_HAVE_GUARD_PAGE_TEST
static int test_guarded_operands(void) {

  long page_size = sysconf(_SC_PAGE_SIZE);
  if (page_size <= 0) return 10;

  uint8_t *mapping = mmap(NULL, (size_t)page_size * 2U, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (mapping == MAP_FAILED) return 11;

  memset(mapping, 'A', (size_t)page_size);
  if (mprotect(mapping + page_size, (size_t)page_size, PROT_NONE)) return 12;

  VP_TEST_OPERAND uint8_t valid[] = {'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B'};
  uint8_t                *invalid = mapping + page_size;
  uint8_t                *crossing = invalid - 4;

  begin_exec();
  __valueprofile_rtn_hook_n(valid, invalid, sizeof(valid), site_token);
  if (vp_local.control_len != 0) return 13;

  begin_exec();
  __valueprofile_rtn_hook_n(invalid, valid, sizeof(valid), site_token);
  if (vp_local.control_len != 0) return 14;

  begin_exec();
  __valueprofile_rtn_hook_n(crossing, valid, sizeof(valid), site_token);
  if (vp_local.control_len != 1) return 15;

  crossing[0] = 'a';
  crossing[1] = 'b';
  crossing[2] = 0;
  VP_TEST_OPERAND uint8_t valid_str[] = {'a', 'b', 0, 'Y', 0, 0, 0, 0};
  begin_exec();
  __valueprofile_rtn_hook_strn(crossing, valid_str, sizeof(valid_str),
                               site_token);
  if (vp_local.control_len != 1) return 16;

  if (munmap(mapping, (size_t)page_size * 2U)) return 17;
  return 0;

}

#endif

int main(void) {

  VP_TEST_OPERAND uint8_t lhs_memcmp[] = {'a', 'b', 'X', 'Y'};
  VP_TEST_OPERAND uint8_t rhs_memcmp[] = {'a', 'b', 'C', 'D'};
  VP_TEST_OPERAND uint8_t lhs_str[] = {'a', 'b', 0, 'Z', 0};
  VP_TEST_OPERAND uint8_t rhs_str[] = {'a', 'b', 0, 'Y', 0};

  memset(&vp_local, 0, sizeof(vp_local));
  if (vp_test_claim_site(&vp_local, site_token, site)) return 18;
  vp_local.filter_mode = VP_FILTER_STRICT;
  vp_local.filter_bitmap[site >> 6] = (1ULL << (site & 63));
  __afl_vp_map = &vp_local;

  begin_exec();
  __valueprofile_rtn_hook_n(lhs_memcmp, rhs_memcmp, 4, site_token);
  vp_site_t *site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 1;
  if (vp_local.control[0] != site) return 2;
  if (site_state->touched_mask != 0x3U) return 3;
  if (site_state->slots[0].best_dist != 12) return 4;
  if (site_state->slots[1].best_dist != 8) return 5;

  begin_exec();
  __valueprofile_rtn_hook_strn(lhs_str, rhs_str, 4, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 6;
  if (vp_local.control[0] != site) return 7;
  if (site_state->touched_mask != 0x3U) return 8;
  if (site_state->slots[0].best_dist != 0 ||
      site_state->slots[1].best_dist != 0)
    return 9;

#ifdef VP_HAVE_GUARD_PAGE_TEST
  int guarded_result = test_guarded_operands();
  if (guarded_result) return guarded_result;
#endif

  VP_TEST_OPERAND uint8_t lhs_ci[] = {'A', 'B', 'C', 0};
  VP_TEST_OPERAND uint8_t rhs_ci[] = {'a', 'b', 'c', 0};

  begin_exec();
  __valueprofile_rtn_hook_str_ci(lhs_ci, rhs_ci, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 20;
  if (site_state->slots[0].best_dist != 0) return 21;
  if (site_state->slots[1].best_dist != 0) return 22;

  VP_TEST_OPERAND uint8_t lhs_cin[] = {'A', 'B', 'X', 0};
  VP_TEST_OPERAND uint8_t rhs_cin[] = {'a', 'b', 'y', 0};

  begin_exec();
  __valueprofile_rtn_hook_strn_ci(lhs_cin, rhs_cin, 3, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 23;
  if (site_state->slots[0].best_dist == 0) return 24;

  VP_TEST_OPERAND uint8_t hay[] = {'x', 'x', 'n', 'e', 'e', 'd', 'l', 'e', 0};
  VP_TEST_OPERAND uint8_t needle[] = {'n', 'e', 'e', 'd', 'l', 'e', 0};

  begin_exec();
  __valueprofile_rtn_hook_sub(hay, needle, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 25;
  if (site_state->slots[0].best_dist != 0) return 26;
  if (site_state->slots[1].best_dist != 0) return 27;

  VP_TEST_OPERAND uint8_t hay_miss[] = {'x', 'x', 'n', 'e', 'e',
                                        'd', 'l', 'f', 0};

  begin_exec();
  __valueprofile_rtn_hook_sub(hay_miss, needle, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 28;
  if (site_state->slots[1].best_dist == 0) return 29;

  /* strnstr/g_strstr_len: negative length means nul-terminated, a bounded
     length is still cut short by an embedded nul. */
  begin_exec();
  __valueprofile_rtn_hook_sub_hn(hay, (uint64_t)-1, needle, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 30;
  if (site_state->slots[0].best_dist != 0) return 31;
  if (site_state->slots[1].best_dist != 0) return 32;

  begin_exec();
  __valueprofile_rtn_hook_sub_hn(hay, 8, needle, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 33;
  if (site_state->slots[0].best_dist != 0) return 34;

  begin_exec();
  __valueprofile_rtn_hook_sub_hn(hay, 5, needle, site_token);
  if (vp_local.control_len != 0) return 35;

  VP_TEST_OPERAND uint8_t hay_nul[] = {'z', 'z', 0,   'n', 'e',
                                       'e', 'd', 'l', 'e', 0};

  begin_exec();
  __valueprofile_rtn_hook_sub_hn(hay_nul, 9, needle, site_token);
  if (vp_local.control_len != 0) return 36;

  /* The weak strncasestr hook folds case, so a match differing only in case
     is solved. Its site comes from the caller pc, so drop the site filter and
     read the touched site back. */
  VP_TEST_OPERAND uint8_t hay_case[] = {'x', 'x', 'N', 'E', 'E',
                                        'D', 'L', 'E', 0};

  begin_exec();
  vp_local.filter_mode = VP_FILTER_OFF;
  __sanitizer_weak_hook_strncasestr((void *)0x1234, hay_case, needle, 8, NULL);
  vp_local.filter_mode = VP_FILTER_STRICT;
  if (vp_local.control_len != 1) return 37;
  site_state = &vp_local.site[vp_local.control[0]];
  if (site_state->slots[0].best_dist != 0) return 38;
  if (site_state->slots[1].best_dist != 0) return 39;

  /* A nul in only one operand is a mismatch like any other: the comparison
     ends only where both operands are nul, so neither metric may collapse
     towards zero for an input that shares just a one byte prefix. */
  VP_TEST_OPERAND uint8_t lhs_nul[] = {'A', 0, 0, 0, 0, 0, 0, 0};
  VP_TEST_OPERAND uint8_t rhs_nul[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'};

  begin_exec();
  vp_local.filter_mode = VP_FILTER_STRICT;
  __valueprofile_rtn_hook_strn(lhs_nul, rhs_nul, 8, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 40;
  if (site_state->slots[0].best_dist != 50) return 41;
  if (site_state->slots[1].best_dist != 19) return 42;

  /* Same, across the word-at-a-time part of the hamming sum. */
  VP_TEST_OPERAND uint8_t lhs_nul16[16] = {'A', 'A', 'A', 0};
  VP_TEST_OPERAND uint8_t rhs_nul16[16];
  memset(rhs_nul16, 'A', sizeof(rhs_nul16));

  begin_exec();
  __valueprofile_rtn_hook_strn(lhs_nul16, rhs_nul16, 16, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 43;
  if (site_state->slots[0].best_dist != 98) return 44;
  if (site_state->slots[1].best_dist != 26) return 45;

  /* strcmp sizes its window from the longer operand, so a short input is
     scored on the bytes it still has to grow. */
  VP_TEST_OPERAND uint8_t lhs_short[] = {'A', 0, 0, 0, 0, 0, 0, 0};
  VP_TEST_OPERAND uint8_t rhs_long[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 0};

  begin_exec();
  __valueprofile_rtn_hook_str(lhs_short, rhs_long, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 46;
  if (site_state->slots[0].best_dist != 50) return 47;
  if (site_state->slots[1].best_dist != 17) return 48;

  return 0;

}

