#if defined(VP_ABI_TEST_STANDALONE_TYPES)
  #define _HAVE_TYPES_H
typedef __UINT8_TYPE__     u8;
typedef __UINT16_TYPE__    u16;
typedef __UINT32_TYPE__    u32;
typedef unsigned long long u64;
#endif

#include "../include/value-profile.h"

#define VP_ABI_OFFSETOF(type, member) __builtin_offsetof(type, member)

_Static_assert(sizeof(vp_slot_t) == 2U, "unexpected VP slot size");
_Static_assert(sizeof(vp_site_t) == 32U, "unexpected VP site size");
_Static_assert(VP_ABI_OFFSETOF(vp_site_t, exec_seen) == 0U,
               "unexpected VP site epoch offset");
_Static_assert(VP_ABI_OFFSETOF(vp_site_t, hit_count) == 8U,
               "unexpected VP site hit-count offset");
_Static_assert(VP_ABI_OFFSETOF(vp_site_t, touched_mask) == 10U,
               "unexpected VP site touched-mask offset");
_Static_assert(VP_ABI_OFFSETOF(vp_site_t, slots) == 12U,
               "unexpected VP site slot offset");
_Static_assert(VP_ABI_OFFSETOF(vp_site_t, flags) == 28U,
               "unexpected VP site padding offset");

_Static_assert(VP_ABI_OFFSETOF(vp_map_t, exec_id) == 0U,
               "unexpected VP map epoch offset");
_Static_assert(VP_ABI_OFFSETOF(vp_map_t, enabled) == 8U,
               "unexpected VP map enabled offset");
_Static_assert(VP_ABI_OFFSETOF(vp_map_t, filter_mode) == 9U,
               "unexpected VP map filter-enabled offset");
_Static_assert(VP_ABI_OFFSETOF(vp_map_t, control_len) == 12U,
               "unexpected VP map control-length offset");
_Static_assert(VP_ABI_OFFSETOF(vp_map_t, filter_bitmap) == 16U,
               "unexpected VP map filter offset");
_Static_assert(VP_ABI_OFFSETOF(vp_map_t, control) == 8208U,
               "unexpected VP map control offset");
_Static_assert(VP_ABI_OFFSETOF(vp_map_t, site) == 139280U,
               "unexpected VP map site-array offset");
_Static_assert(VP_ABI_OFFSETOF(vp_map_t, site_ids) == 2236432U,
               "unexpected VP map tag-array offset");
_Static_assert(sizeof(vp_map_t) == 2498576U, "unexpected VP map size");

#undef VP_ABI_OFFSETOF

int main(void) {

  return 0;

}

