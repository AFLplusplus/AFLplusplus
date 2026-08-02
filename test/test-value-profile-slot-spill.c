#include <stdint.h>
#include <string.h>

#include "../include/value-profile.h"
#include "test-value-profile-common.h"

extern vp_map_t *__afl_vp_map;
void __valueprofile_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr,
                          uint64_t site_token);

static const uint16_t site = 0x1234U;
static const uint64_t site_token = VP_TEST_TOKEN_FOR_SITE(0x1234U, 0x12345678U);

static vp_map_t vp_local;

static void begin_exec(void) {

  vp_local.enabled = 1;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;

}

__attribute__((noinline)) static void run_once(uint32_t observed) {

  __valueprofile_hook4(observed, 0, CMP_ATTR_NONE, site_token);

}

int main(void) {

  memset(&vp_local, 0, sizeof(vp_local));
  if (vp_test_claim_site(&vp_local, site_token, site)) return 23;
  vp_local.filter_mode = VP_FILTER_STRICT;
  vp_local.filter_bitmap[site >> 6] = (1ULL << (site & 63));
  __afl_vp_map = &vp_local;

  /* First unsolved hit initializes only the first physical-site metric pair. */
  begin_exec();
  run_once(0x01010101U);
  if (vp_local.control_len != 1) return 1;
  if (vp_local.control[0] != site) return 2;
  vp_site_t *site_state = &vp_local.site[site];
  if (site_state->touched_mask != 0x3U) return 3;
  if (site_state->slots[0].best_dist != 4 ||
      site_state->slots[1].best_dist != 25)
    return 4;

  /* Repeating the same observation in a later exec must still stay on the same
     metric pair and must not touch unrelated slots. */
  begin_exec();
  run_once(0x01010101U);
  if (vp_local.control_len != 1) return 5;
  site_state = &vp_local.site[site];
  if (site_state->touched_mask != 0x3U) return 6;
  if (site_state->slots[0].best_dist != 4 ||
      site_state->slots[1].best_dist != 25)
    return 7;

  /* Improvement to solved must still update the same two slots. */
  begin_exec();
  run_once(0x00000000U);
  if (vp_local.control_len != 1) return 8;
  site_state = &vp_local.site[site];
  if (site_state->touched_mask != 0x3U) return 9;
  if (site_state->slots[0].best_dist != 0 ||
      site_state->slots[1].best_dist != 0)
    return 10;

  /* The first wrapped hit keeps the first pair's per-slot minima. */
  begin_exec();
  for (u32 i = 0; i < VP_PAIR_COUNT; ++i) {

    run_once(0xffffffffU);

  }

  run_once(1U);
  if (vp_local.control_len != 1) return 11;
  site_state = &vp_local.site[site];
  if (site_state->touched_mask != VP_SLOT_MASK) return 12;
  if (site_state->slots[0].best_dist != 1 ||
      site_state->slots[1].best_dist != 1)
    return 13;
  for (u32 i = 2; i < VP_SLOTS; ++i) {

    if (site_state->slots[i].best_dist != 32) return 14;

  }

  /* The u16 ordinal wraps without interrupting the pair rotation. */
  begin_exec();
  for (u32 i = 0; i < 0x10000U; ++i) {

    run_once(0xffffffffU);

  }

  if (site_state->hit_count != 0) return 15;
  if (site_state->touched_mask != VP_SLOT_MASK) return 16;
  run_once(1U);
  if (site_state->hit_count != 1U) return 17;
  if (site_state->slots[0].best_dist != 1 ||
      site_state->slots[1].best_dist != 1)
    return 18;
  for (u32 i = 2; i < VP_SLOTS; ++i) {

    if (site_state->slots[i].best_dist != 32) return 19;

  }

  /* A new execution still restarts the ordinal at pair 0. */
  begin_exec();
  run_once(0xffffffffU);
  if (site_state->hit_count != 1U) return 20;
  if (site_state->touched_mask != 0x3U) return 21;
  if (site_state->slots[0].best_dist != 32 ||
      site_state->slots[1].best_dist != 32)
    return 22;

  return 0;

}

