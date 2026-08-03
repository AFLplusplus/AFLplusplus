/* Runtime check that half/bfloat compares route through the exact float VP
   hook (see cmplog-instructions-pass.cc). No site is pre-claimed: the
   physical site is read back from control[0] after each compare. Every
   value an assertion depends on is captured into a local in the statement
   immediately after the call that produces it - inserting any other
   statement in between breaks the measurement, because that statement's own
   comparison would be auto-instrumented too and claim a VP site before the
   capture runs. */

#include <stdint.h>
#include <string.h>

#include "../include/value-profile.h"

extern vp_map_t *__afl_vp_map;
extern uint8_t   __afl_vp_enabled_fallback;

static vp_map_t vp_local;

static void begin_exec(void) {

  vp_local.enabled = 1;
  ++vp_local.exec_id;
  if (!vp_local.exec_id) ++vp_local.exec_id;
  vp_local.control_len = 0;

}

__attribute__((noinline)) static int cmp_half(_Float16 a, _Float16 b) {

  return a == b;

}

__attribute__((noinline)) static int cmp_bfloat(__bf16 a, __bf16 b) {

  return a == b;

}

int main(void) {

  memset(&vp_local, 0, sizeof(vp_local));
  __afl_vp_map = &vp_local;
  __afl_vp_enabled_fallback = 1;

  volatile _Float16 hp = 0.0f16, hn = -0.0f16;
  begin_exec();
  int      r1 = cmp_half(hp, hn);
  uint16_t len1 = vp_local.control_len;
  uint16_t site_half = vp_local.control[0];
  uint16_t half_d0 = vp_local.site[site_half].slots[0].best_dist;
  uint16_t half_d1 = vp_local.site[site_half].slots[1].best_dist;
  if (!r1) return 1;
  if (len1 != 1) return 2;
  if (half_d0 != 0) return 3;
  if (half_d1 != 0) return 4;

  volatile _Float16 hnan = (_Float16)(0.0f / 0.0f), hone = 1.0f16;
  begin_exec();
  int      r2 = cmp_half(hnan, hone);
  uint16_t len2 = vp_local.control_len;
  if (r2) return 5;
  if (len2 != 0) return 6;

  volatile __bf16 bp = (__bf16)0.0f, bn = (__bf16)-0.0f;
  begin_exec();
  int      r3 = cmp_bfloat(bp, bn);
  uint16_t len3 = vp_local.control_len;
  uint16_t site_bfloat = vp_local.control[0];
  uint16_t bfloat_d0 = vp_local.site[site_bfloat].slots[0].best_dist;
  uint16_t bfloat_d1 = vp_local.site[site_bfloat].slots[1].best_dist;
  if (!r3) return 7;
  if (len3 != 1) return 8;
  if (bfloat_d0 != 0) return 9;
  if (bfloat_d1 != 0) return 10;

  return 0;

}

