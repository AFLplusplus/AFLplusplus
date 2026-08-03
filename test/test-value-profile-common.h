#ifndef _AFL_TEST_VALUE_PROFILE_COMMON_H
#define _AFL_TEST_VALUE_PROFILE_COMMON_H

/* Construct a token whose primary preferred way is one known physical key.
   Keep the secondary set distinct so tests exercise the production layout. */
#define VP_TEST_TOKEN_FOR_SITE(site, tag)                                  \
  (((u64)(tag) << 32) | ((u64)((site) & (VP_MAP_A - 1U)) << 14) |         \
   ((u64)((((site) / VP_MAP_A) + 1U) & (VP_MAP_S - 1U)) << 16) |          \
   ((u64)(site) / VP_MAP_A))

static inline int vp_test_claim_site(vp_map_t *map, u64 token, u16 site) {

  return vp_map_select(map, token, 1) == site ? 0 : 1;

}

#endif

