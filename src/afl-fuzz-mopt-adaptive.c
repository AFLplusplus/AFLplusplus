/*
   american fuzzy lop++ - mopt-adaptive (part of AFL++)
   ----------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   This file is part of AFL++ and, unlike the original Apache-2.0 source files,
   is licensed under the GNU Affero General Public License as published by the
   Free Software Foundation, either version 3 of the License, or (at your
   option) any later version. See https://www.gnu.org/licenses/agpl-3.0.html

   A commercial license is available for organizations that cannot use the
   AGPL; see LICENSE.COMMERCIAL.

   SPDX-License-Identifier: AGPL-3.0-or-later

 */

#include "afl-fuzz.h"

/* Map (input_mode, fuzz_mode) -> 0..5.  input_mode: 0=generic,1=text,2=binary
   (clamped); fuzz_mode: 0=explore,1=exploit. */
u32 mopt_ctx_index(u8 input_mode, u8 fuzz_mode) {

  u32 im = input_mode > 2 ? 0 : input_mode;
  return im * 2u + (fuzz_mode ? 1u : 0u);

}

void mopt_adaptive_init(afl_state_t *afl) {

  /* default: off (standard havoc); the -L switch turns it on */
  memset(&afl->mopt_adaptive, 0, sizeof(afl->mopt_adaptive));

}

void mopt_round_reset(afl_state_t *afl) {

  afl->mopt_adaptive.round_cnt = 0;

}

void mopt_record_use(afl_state_t *afl, u32 op) {

  struct mopt_adaptive *m = &afl->mopt_adaptive;
  if (!afl->mopt_adaptive.enabled) return;
  if (unlikely(op >= MOPT_OP_MAX)) return;
  if (likely(m->round_cnt < sizeof(m->round_list)))
    m->round_list[m->round_cnt++] = (u8)op;

}

void mopt_commit_round(afl_state_t *afl, u8 found) {

  struct mopt_adaptive *m = &afl->mopt_adaptive;
  struct mopt_ctx      *c = &m->ctx[m->cur_ctx];

  u32 cnt[MOPT_OP_MAX];
  memset(cnt, 0, sizeof(cnt));

  for (u32 i = 0; i < m->round_cnt; ++i) {

    u8 op = m->round_list[i];
    c->op_uses[op]++;
    cnt[op]++;

  }

  if (found && m->round_cnt) {

    for (u32 op = 0; op < MOPT_OP_MAX; ++op)
      if (cnt[op]) {

        u64 share = (u64)MOPT_FIND_SCALE * cnt[op] / m->round_cnt;
        if (!share) { share = 1; }
        c->op_finds[op] += share;

      }

  }

  mopt_round_reset(afl);

}

static void quantize_into(const double *weight, u32 n, u32 *out, u32 out_len) {

  u32    counts[MOPT_OP_MAX];
  double frac[MOPT_OP_MAX];
  double sum = 0.0;
  for (u32 i = 0; i < n; ++i)
    sum += weight[i];
  if (sum <= 0.0) {

    for (u32 i = 0; i < out_len; ++i)
      out[i] = i % n;
    return;

  }

  u32 assigned = 0;
  for (u32 i = 0; i < n; ++i) {

    double exact = (weight[i] / sum) * (double)out_len;
    counts[i] = (u32)exact;
    frac[i] = exact - (double)counts[i];
    assigned += counts[i];

  }

  while (assigned < out_len) {

    u32    best = 0;
    double bf = -1.0;
    for (u32 i = 0; i < n; ++i)
      if (frac[i] > bf) {

        bf = frac[i];
        best = i;

      }

    counts[best]++;
    frac[best] = -1.0;
    assigned++;

  }

  /* Exploration floor: keep every operator at >= 1 slot so none is ever
     permanently starved (e.g. one absent from the prior with no learned
     credit). Revive a starved operator by stealing one slot from the current
     richest, but only when that richest has more than one to give. */
  for (u32 i = 0; i < n; ++i) {

    if (counts[i] == 0) {

      u32 rich = 0;
      for (u32 j = 1; j < n; ++j)
        if (counts[j] > counts[rich]) rich = j;
      if (counts[rich] > 1) {

        counts[rich]--;
        counts[i] = 1;

      }

    }

  }

  u32 pos = 0;
  for (u32 i = 0; i < n && pos < out_len; ++i)
    for (u32 k = 0; k < counts[i] && pos < out_len; ++k)
      out[pos++] = i;
  while (pos < out_len)
    out[pos++] = 0;

}

void mopt_rebuild_ctx(struct mopt_ctx *c, const u32 *prior, u32 prior_len) {

  for (u32 i = 0; i < MOPT_OP_MAX; ++i) {

    c->op_finds[i] = c->op_finds[i] * MOPT_DECAY_NUM / MOPT_DECAY_DEN;
    c->op_uses[i] = c->op_uses[i] * MOPT_DECAY_NUM / MOPT_DECAY_DEN;

  }

  double prior_w[MOPT_OP_MAX];
  double prior_sum = 0.0;
  for (u32 i = 0; i < MOPT_OP_MAX; ++i)
    prior_w[i] = 0.0;
  for (u32 i = 0; i < prior_len; ++i)
    if (prior[i] < MOPT_OP_MAX) {

      prior_w[prior[i]] += 1.0;
      prior_sum += 1.0;

    }

  if (prior_sum <= 0.0) prior_sum = 1.0;

  double eff[MOPT_OP_MAX];
  double eff_sum = 0.0;
  for (u32 i = 0; i < MOPT_OP_MAX; ++i) {

    eff[i] =
        c->op_uses[i] ? (double)c->op_finds[i] / (double)c->op_uses[i] : 0.0;
    eff_sum += eff[i];

  }

  /* Anneal prior trust from MOPT_PRIOR_NUM down to a MOPT_PRIOR_MIN_NUM floor
     over MOPT_PRIOR_ANNEAL rebuilds: trust the static prior at cold-start,
     then let learned efficiency dominate. The exploration floor in
     quantize_into keeps every operator alive as epsilon shrinks. */
  double eps_max = (double)MOPT_PRIOR_NUM / (double)MOPT_PRIOR_DEN;
  double eps_min = (double)MOPT_PRIOR_MIN_NUM / (double)MOPT_PRIOR_DEN;
  double t = (double)c->rebuild_count / (double)MOPT_PRIOR_ANNEAL;
  if (t > 1.0) t = 1.0;
  double eps = eps_max - (eps_max - eps_min) * t;

  double blended[MOPT_OP_MAX];
  for (u32 i = 0; i < MOPT_OP_MAX; ++i) {

    double e = eff_sum > 0.0 ? eff[i] / eff_sum : 0.0;
    double p = prior_w[i] / prior_sum;
    blended[i] = (1.0 - eps) * e + eps * p;

  }

  quantize_into(blended, MOPT_OP_MAX, c->learned_array, MOPT_LUT_SIZE);

  ++c->rebuild_count;

}

void mopt_policy_update(struct mopt_ctx *c) {

  double r_static = 0.0, r_learned = 0.0;
  if (c->arm_time_us[0])
    r_static = (double)c->arm_finds[0] * 1e6 / (double)c->arm_time_us[0];
  if (c->arm_time_us[1])
    r_learned = (double)c->arm_finds[1] * 1e6 / (double)c->arm_time_us[1];

  u8 learned_ready = c->arm_execs[1] >= MOPT_ARM_MIN_SAMPLES;
  u8 static_ready = c->arm_execs[0] >= MOPT_ARM_MIN_SAMPLES;

  if (!learned_ready) {

    c->active_arm = 1;

  } else if (!static_ready) {

    c->active_arm = 0;

  } else {

    c->active_arm = (r_learned > r_static) ? 1 : 0;

  }

  for (u32 a = 0; a < 2; ++a) {

    c->arm_finds[a] = c->arm_finds[a] * MOPT_ARM_DECAY_NUM / MOPT_ARM_DECAY_DEN;
    c->arm_time_us[a] =
        c->arm_time_us[a] * MOPT_ARM_DECAY_NUM / MOPT_ARM_DECAY_DEN;
    c->arm_execs[a] = c->arm_execs[a] * MOPT_ARM_DECAY_NUM / MOPT_ARM_DECAY_DEN;

  }

}

const u32 *mopt_choose_array(afl_state_t *afl, u32 ctx_idx,
                             const u32 *static_arr, u32 static_len,
                             u32 *out_len) {

  struct mopt_ctx *c = &afl->mopt_adaptive.ctx[ctx_idx];
  if (!afl->mopt_adaptive.enabled || c->active_arm == 0 ||
      c->last_rebuild_execs == 0) {

    *out_len = static_len;
    return static_arr;

  }

  *out_len = MOPT_LUT_SIZE;
  return c->learned_array;

}

void mopt_stage_account(afl_state_t *afl, u32 ctx_idx, u64 finds, u64 time_us,
                        u64 execs) {

  struct mopt_ctx *c = &afl->mopt_adaptive.ctx[ctx_idx];
  u8               arm = c->active_arm;
  c->arm_finds[arm] += finds;
  c->arm_time_us[arm] += time_us;
  c->arm_execs[arm] += execs;

}

#ifdef INTROSPECTION
void mopt_introspect_log(afl_state_t *afl, u32 ctx_idx) {

  struct mopt_ctx *c = &afl->mopt_adaptive.ctx[ctx_idx];
  u32              counts[MOPT_OP_MAX];
  memset(counts, 0, sizeof(counts));
  for (u32 i = 0; i < MOPT_LUT_SIZE; ++i)
    counts[c->learned_array[i]]++;

  u32 top[3] = {MOPT_OP_MAX, MOPT_OP_MAX, MOPT_OP_MAX};
  for (u32 i = 0; i < MOPT_OP_MAX; ++i) {

    u32 c0 = top[0] < MOPT_OP_MAX ? counts[top[0]] : 0;
    u32 c1 = top[1] < MOPT_OP_MAX ? counts[top[1]] : 0;
    u32 c2 = top[2] < MOPT_OP_MAX ? counts[top[2]] : 0;

    if (counts[i] > c0) {

      top[2] = top[1];
      top[1] = top[0];
      top[0] = i;

    } else if (counts[i] > c1) {

      top[2] = top[1];
      top[1] = i;

    } else if (counts[i] > c2) {

      top[2] = i;

    }

  }

  if (afl->introspection_file) {

    s32 id[3];
    u32 cnt[3];
    for (u32 k = 0; k < 3; ++k) {

      id[k] = top[k] < MOPT_OP_MAX ? (s32)top[k] : -1;
      cnt[k] = top[k] < MOPT_OP_MAX ? counts[top[k]] : 0;

    }

    fprintf(afl->introspection_file,
            "MOPT rebuild ctx=%u arm=%u top=[%d:%u,%d:%u,%d:%u]\n", ctx_idx,
            c->active_arm, id[0], cnt[0], id[1], cnt[1], id[2], cnt[2]);

  }

}

#endif

