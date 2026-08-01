#include <stdint.h>
#include <string.h>

#include "../include/value-profile.h"
#include "test-value-profile-common.h"

extern vp_map_t *__afl_vp_map;
void __valueprofile_switch(uint64_t val, uint64_t *cases, uint64_t site_token);

static const uint16_t site = 0x2345U;
static const uint64_t site_token = VP_TEST_TOKEN_FOR_SITE(0x2345U, 0x23456789U);

static vp_map_t vp_local;

static void begin_exec(void) {

  vp_local.enabled = 1;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;

}

static int expect_slot_pair(vp_site_t *site_state, u16 slot0, u16 dist0,
                            u16 slot1, u16 dist1, int rc) {

  if (site_state->slots[slot0].best_dist != dist0 ||
      site_state->slots[slot1].best_dist != dist1)
    return rc;
  return 0;

}

int main(void) {

  static uint64_t cases[] = {2, 8, 10, 20};
  static uint64_t cases_unsorted[] = {2, 8, 20, 10};

  memset(&vp_local, 0, sizeof(vp_local));
  if (vp_test_claim_site(&vp_local, site_token, site)) return 23;
  vp_local.filter_mode = VP_FILTER_STRICT;
  vp_local.filter_bitmap[site >> 6] = (1ULL << (site & 63));
  __afl_vp_map = &vp_local;

  begin_exec();
  __valueprofile_switch(0, cases, site_token);
  vp_site_t *site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 1;
  if (vp_local.control[0] != site) return 2;
  if (site_state->touched_mask != 0x3U) return 3;
  if (expect_slot_pair(site_state, 0, 2, 1, 4, 4)) return 4;

  begin_exec();
  __valueprofile_switch(20, cases, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 5;
  if (vp_local.control[0] != site) return 6;
  if (site_state->touched_mask != 0x3U) return 7;
  if (expect_slot_pair(site_state, 0, 0, 1, 0, 8)) return 8;

  begin_exec();
  __valueprofile_switch(30, cases, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 9;
  if (vp_local.control[0] != site) return 10;
  if (site_state->touched_mask != 0x3U) return 11;
  if (expect_slot_pair(site_state, 0, 2, 1, 4, 12)) return 12;

  begin_exec();
  __valueprofile_switch(15, cases, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 13;
  if (vp_local.control[0] != site) return 14;
  if (site_state->touched_mask != 0xfU) return 15;
  if (expect_slot_pair(site_state, 0, 2, 1, 3, 16)) return 16;
  if (expect_slot_pair(site_state, 2, 4, 3, 3, 17)) return 17;

  begin_exec();
  __valueprofile_switch(15, cases_unsorted, site_token);
  site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 18;
  if (vp_local.control[0] != site) return 19;
  if (site_state->touched_mask != 0xfU) return 20;
  if (expect_slot_pair(site_state, 0, 2, 1, 3, 21)) return 21;
  if (expect_slot_pair(site_state, 2, 4, 3, 3, 22)) return 22;

  return 0;

}

