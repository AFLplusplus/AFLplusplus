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

  uint8_t  valid[] = {'B', 'B', 'B', 'B', 'B', 'B', 'B', 'B'};
  uint8_t *invalid = mapping + page_size;
  uint8_t *crossing = invalid - 4;

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
  uint8_t valid_str[] = {'a', 'b', 0, 'Y', 0, 0, 0, 0};
  begin_exec();
  __valueprofile_rtn_hook_strn(crossing, valid_str, sizeof(valid_str),
                               site_token);
  if (vp_local.control_len != 1) return 16;

  if (munmap(mapping, (size_t)page_size * 2U)) return 17;
  return 0;

}

#endif

int main(void) {

  uint8_t lhs_memcmp[] = {'a', 'b', 'X', 'Y'};
  uint8_t rhs_memcmp[] = {'a', 'b', 'C', 'D'};
  uint8_t lhs_str[] = {'a', 'b', 0, 'Z', 0};
  uint8_t rhs_str[] = {'a', 'b', 0, 'Y', 0};

  memset(&vp_local, 0, sizeof(vp_local));
  if (vp_test_claim_site(&vp_local, site_token, site)) return 18;
  vp_local.filter_enabled = 1;
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

  return 0;

}

