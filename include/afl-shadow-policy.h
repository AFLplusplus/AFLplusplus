#ifndef AFL_SHADOW_POLICY_H
#define AFL_SHADOW_POLICY_H

#include "types.h"

static inline u32 afl_shadow_policy_stride(u64 completed, u32 ewma_q16) {

  if (completed < 8 || ewma_q16 >= 16384) { return 1; }
  if (ewma_q16 >= 6554) { return 2; }
  return 4;

}

static inline u32 afl_shadow_policy_update(u32 previous_q16, u32 sample_q16,
                                           u64 completed_before) {

  return completed_before ? (previous_q16 * 7U + sample_q16) / 8U
                          : sample_q16;

}

#endif
