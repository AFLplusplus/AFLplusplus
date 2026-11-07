#include <assert.h>

#include "afl-shadow-policy.h"

int main(void) {

  assert(afl_shadow_policy_stride(0, 0) == 1);
  assert(afl_shadow_policy_stride(7, 0) == 1);
  assert(afl_shadow_policy_stride(8, 0) == 4);
  assert(afl_shadow_policy_stride(8, 6553) == 4);
  assert(afl_shadow_policy_stride(8, 6554) == 2);
  assert(afl_shadow_policy_stride(8, 16383) == 2);
  assert(afl_shadow_policy_stride(8, 16384) == 1);
  assert(afl_shadow_policy_update(0, 65535, 0) == 65535);
  assert(afl_shadow_policy_update(65535, 0, 1) == 57343);
  return 0;

}
