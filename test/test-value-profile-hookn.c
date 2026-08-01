#include <stdint.h>
#include <string.h>

#include "../include/value-profile.h"
#include "test-value-profile-common.h"

extern vp_map_t *__afl_vp_map;

#ifdef __SIZEOF_INT128__
void __valueprofile_hookN(__uint128_t arg1, __uint128_t arg2, uint8_t attr,
                          uint8_t bits_minus_1, uint64_t site_token);
#endif

static const uint16_t site = 0x6789U;
static const uint64_t site_token = VP_TEST_TOKEN_FOR_SITE(0x6789U, 0x6789abcdU);

static vp_map_t vp_local;

static void begin_exec(void) {

  vp_local.enabled = 1;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;

}

int main(void) {

#ifdef __SIZEOF_INT128__
  memset(&vp_local, 0, sizeof(vp_local));
  if (vp_test_claim_site(&vp_local, site_token, site)) return 6;
  vp_local.filter_mode = VP_FILTER_STRICT;
  vp_local.filter_bitmap[site >> 6] = (1ULL << (site & 63));
  __afl_vp_map = &vp_local;

  begin_exec();
  __valueprofile_hookN(0, ((__uint128_t)1) << 127, CMP_ATTR_NONE, 31,
                       site_token);

  vp_site_t *site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return 1;
  if (vp_local.control[0] != site) return 2;
  if (site_state->touched_mask != 0x3U) return 3;
  if (site_state->slots[0].best_dist != 1) return 4;
  if (site_state->slots[1].best_dist != 128) return 5;
#endif

  return 0;

}

