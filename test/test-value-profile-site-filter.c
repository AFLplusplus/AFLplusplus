#include <stdint.h>
#include <string.h>

#include "../include/value-profile.h"
#include "test-value-profile-common.h"

extern vp_map_t *__afl_vp_map;

void __valueprofile_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr,
                          uint64_t site_token);

static const uint16_t site_a = 0x1000U;
static const uint16_t site_b = 0x1001U;
static const uint64_t token_a = VP_TEST_TOKEN_FOR_SITE(0x1000U, 0xaaaa0001U);
static const uint64_t token_b = VP_TEST_TOKEN_FOR_SITE(0x1001U, 0xbbbb0002U);

static vp_map_t vp_local;

static void begin_exec(void) {

  vp_local.enabled = 1;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;

}

static int reset_map(void) {

  memset(&vp_local, 0, sizeof(vp_local));
  __afl_vp_map = &vp_local;
  return vp_test_claim_site(&vp_local, token_a, site_a);

}

static int test_focus_records_only_focus_members(void) {

  if (reset_map()) return 10;

  vp_local.filter_mode = VP_FILTER_FOCUS;
  vp_local.filter_bitmap[site_a >> 6] = (1ULL << (site_a & 63));

  begin_exec();
  __valueprofile_hook4(0xffU, 0, CMP_ATTR_NONE, token_a);
  if (vp_local.control_len != 1) return 11;
  if (vp_local.control[0] != site_a) return 12;

  __valueprofile_hook4(0xffU, 0, CMP_ATTR_NONE, token_b);
  if (vp_local.control_len != 1) return 13;
  if (vp_local.site[site_b].touched_mask != 0) return 14;
  if (vp_local.site_ids[site_b] == 0) return 15;

  return 0;

}

static int test_strict_filter_blocks_assignment(void) {

  if (reset_map()) return 20;

  vp_local.filter_mode = VP_FILTER_STRICT;
  vp_local.filter_bitmap[site_a >> 6] = (1ULL << (site_a & 63));

  begin_exec();
  __valueprofile_hook4(0xffU, 0, CMP_ATTR_NONE, token_b);
  if (vp_local.control_len != 0) return 21;
  if (vp_local.site_ids[site_b] != 0) return 22;

  __valueprofile_hook4(0xffU, 0, CMP_ATTR_NONE, token_a);
  if (vp_local.control_len != 1) return 23;

  return 0;

}

static int test_retired_site_records_nothing(void) {

  if (reset_map()) return 30;

  vp_local.filter_mode = VP_FILTER_OFF;
  vp_local.site[site_a].flags = VP_SITE_RETIRED;

  begin_exec();
  __valueprofile_hook4(0xffU, 0, CMP_ATTR_NONE, token_a);
  if (vp_local.control_len != 0) return 31;
  if (vp_local.site[site_a].touched_mask != 0) return 32;

  vp_local.site[site_a].flags = 0;
  begin_exec();
  __valueprofile_hook4(0xffU, 0, CMP_ATTR_NONE, token_a);
  if (vp_local.control_len != 1) return 33;
  if (vp_local.control[0] != site_a) return 34;
  if (vp_local.site[site_a].touched_mask != 0x3U) return 35;

  return 0;

}

int main(void) {

  int rc;

  rc = test_focus_records_only_focus_members();
  if (rc) return rc;

  rc = test_strict_filter_blocks_assignment();
  if (rc) return rc;

  rc = test_retired_site_records_nothing();
  if (rc) return rc;

  return 0;

}

