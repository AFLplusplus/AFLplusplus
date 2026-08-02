#include <stdint.h>
#include <string.h>

#include "../include/bitops.h"
#include "../include/value-profile.h"
#include "test-value-profile-common.h"

extern vp_map_t *__afl_vp_map;

void __valueprofile_hook1(uint8_t arg1, uint8_t arg2, uint8_t attr,
                          uint64_t site_token);
void __valueprofile_hook4(uint32_t arg1, uint32_t arg2, uint8_t attr,
                          uint64_t site_token);
void __valueprofile_hook_float(float arg1, float arg2, uint8_t attr,
                               uint64_t site_token);
void __valueprofile_hook_double(double arg1, double arg2, uint8_t attr,
                                uint64_t site_token);
void __sanitizer_cov_trace_cmp1(uint8_t arg1, uint8_t arg2);
void __sanitizer_cov_trace_const_cmp1(uint8_t arg1, uint8_t arg2);
#ifdef __SIZEOF_INT128__
void __valueprofile_hookN(__uint128_t arg1, __uint128_t arg2, uint8_t attr,
                          uint8_t bits_minus_1, uint64_t site_token);
#endif

static const uint16_t site = 0x4567U;
static const uint64_t site_token = VP_TEST_TOKEN_FOR_SITE(0x4567U, 0x456789abU);

static vp_map_t vp_local;

static void begin_exec(void) {

  vp_local.enabled = 1;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;

}

static int expect_pair(u16 hamming, u16 abs_dist, int rc) {

  vp_site_t *site_state = &vp_local.site[site];
  if (vp_local.control_len != 1) return rc;
  if (vp_local.control[0] != site) return rc + 1;
  if (site_state->touched_mask != 0x3U) return rc + 2;
  if (site_state->slots[0].best_dist != hamming) return rc + 3;
  if (site_state->slots[1].best_dist != abs_dist) return rc + 4;
  return 0;

}

static float float_from_bits(u32 bits) {

  float f;
  memcpy((void *)&f, (const void *)&bits, sizeof(f));
  return f;

}

static double double_from_bits(u64 bits) {

  double d;
  memcpy((void *)&d, (const void *)&bits, sizeof(d));
  return d;

}

static u32 fp32_order_key(u32 raw) {

  return (raw & 0x80000000U) ? ~raw : (raw ^ 0x80000000U);

}

static u64 fp64_order_key(u64 raw) {

  return (raw & 0x8000000000000000ULL) ? ~raw : (raw ^ 0x8000000000000000ULL);

}

int main(void) {

  int rc;

  memset(&vp_local, 0, sizeof(vp_local));
  if (vp_test_claim_site(&vp_local, site_token, site)) return 110;
  vp_local.filter_mode = VP_FILTER_STRICT;
  vp_local.filter_bitmap[site >> 6] = (1ULL << (site & 63));
  __afl_vp_map = &vp_local;

  begin_exec();
  __valueprofile_hook4(0xffffffffU, 0, CMP_ATTR_ICMP_SGT, site_token);
  rc = expect_pair(32, 1, 1);
  if (rc) return rc;

  begin_exec();
  __valueprofile_hook4(0xffffffffU, 0, CMP_ATTR_ICMP_UGT, site_token);
  rc = expect_pair(32, 32, 10);
  if (rc) return rc;

  begin_exec();
  __valueprofile_hook4(0xfffffffeU, 1, CMP_ATTR_ICMP_SGT, site_token);
  rc = expect_pair(32, 2, 20);
  if (rc) return rc;

  begin_exec();
  __valueprofile_hook4(0x80000000U, 0x7fffffffU, CMP_ATTR_ICMP_SGT, site_token);
  rc = expect_pair(32, 32, 30);
  if (rc) return rc;

#ifdef __SIZEOF_INT128__
  begin_exec();
  __uint128_t neg1_72 = (((__uint128_t)1) << 72) - 1;
  __valueprofile_hookN(neg1_72, 0, CMP_ATTR_ICMP_SGT, 8, site_token);
  rc = expect_pair(72, 1, 40);
  if (rc) return rc;

  begin_exec();
  __valueprofile_hookN(neg1_72, 0, CMP_ATTR_ICMP_UGT, 8, site_token);
  rc = expect_pair(72, 72, 50);
  if (rc) return rc;
#endif

  begin_exec();
  u32 neg_tiny_bits = 0x80000005U;
  u32 pos_tiny_bits = 0x00000005U;
  u32 neg_tiny_key = fp32_order_key(neg_tiny_bits);
  u32 pos_tiny_key = fp32_order_key(pos_tiny_bits);
  u32 tiny_diff = pos_tiny_key - neg_tiny_key;
  __valueprofile_hook_float(float_from_bits(neg_tiny_bits),
                            float_from_bits(pos_tiny_bits), CMP_ATTR_FCMP_OLT,
                            site_token);
  rc = expect_pair(1, (u16)bit_length_u64((u64)tiny_diff), 60);
  if (rc) return rc;
  if (bit_length_u64((u64)tiny_diff) >= 32) return 69;

  begin_exec();
  u64 neg_double_bits = 0x8000000000000005ULL;
  u64 pos_double_bits = 0x0000000000000005ULL;
  u64 neg_double_key = fp64_order_key(neg_double_bits);
  u64 pos_double_key = fp64_order_key(pos_double_bits);
  u64 double_diff = pos_double_key - neg_double_key;
  __valueprofile_hook_double(double_from_bits(neg_double_bits),
                             double_from_bits(pos_double_bits),
                             CMP_ATTR_FCMP_OLT, site_token);
  rc = expect_pair(1, (u16)bit_length_u64(double_diff), 70);
  if (rc) return rc;
  if (bit_length_u64(double_diff) >= 64) return 79;

  begin_exec();
  __valueprofile_hook_float(float_from_bits(0x00000000U),
                            float_from_bits(0x80000000U), CMP_ATTR_FCMP_OEQ,
                            site_token);
  rc = expect_pair(0, 0, 80);
  if (rc) return rc;

  begin_exec();
  __valueprofile_hook_float(float_from_bits(0x7fc00000U),
                            float_from_bits(0x3f800000U), CMP_ATTR_FCMP_OEQ,
                            site_token);
  if (vp_local.control_len != 0) return 90;

  begin_exec();
  u32 one_bits = 0x3f800000U;
  u32 inf_bits = 0x7f800000U;
  u32 one_key = fp32_order_key(one_bits);
  u32 inf_key = fp32_order_key(inf_bits);
  u32 inf_diff = inf_key - one_key;
  __valueprofile_hook_float(float_from_bits(one_bits),
                            float_from_bits(inf_bits), CMP_ATTR_FCMP_OLT,
                            site_token);
  rc = expect_pair((u16)popcount_u32(one_bits ^ inf_bits),
                   (u16)bit_length_u64((u64)inf_diff), 100);
  if (rc) return rc;

  begin_exec();
  __valueprofile_hook1(0xffU, 0, CMP_ATTR_ICMP_SGT, site_token);
  rc = expect_pair(8, 1, 110);
  if (rc) return rc;

  begin_exec();
  __valueprofile_hook1(0xffU, 0, CMP_ATTR_ICMP_UGT, site_token);
  rc = expect_pair(8, 8, 120);
  if (rc) return rc;

  /* SanitizerCoverage provides a useful i8 fallback only for constant
     compares. Its return-address token is assigned dynamically. */
  vp_local.enabled = 0;
  vp_local.filter_mode = VP_FILTER_OFF;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;
  vp_local.enabled = 1;
  __sanitizer_cov_trace_const_cmp1(0xffU, 0);
  vp_local.enabled = 0;
  if (vp_local.control_len != 1) return 130;
  vp_site_t *fallback_site = &vp_local.site[vp_local.control[0]];
  if (fallback_site->touched_mask != 0x3U) return 131;
  if (fallback_site->slots[0].best_dist != 8 ||
      fallback_site->slots[1].best_dist != 8)
    return 132;

  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;
  vp_local.enabled = 1;
  __sanitizer_cov_trace_cmp1(0xffU, 0);
  vp_local.enabled = 0;
  if (vp_local.control_len != 0) return 133;

  return 0;

}

