#ifndef AFL_FUZZ_RL_H
#define AFL_FUZZ_RL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "types.h"

// Store Parameters for Reinforcement learning
typedef struct {
#ifdef RL_USE_PYTHON
  #pragma message "Using Python-based RL"
  int msqid_sender;
  int msqid_reciever;
#else
  #pragma message "Using C++-based RL"
#endif

  u32 *positive_reward;
  u32 *negative_reward;

  u8 *trace_bits;

  u32 map_size, current_entry;

  struct queue_entry * queue_cur;
  struct queue_entry **top_rated;
} rl_params_t;

rl_params_t *rl_init_params(u32);
void         rl_store_features(rl_params_t *);
void         rl_update_queue(rl_params_t *);
u32          rl_select_best_bit(const rl_params_t *, bool);

#ifdef __cplusplus
}
#endif

#endif  // AFL_FUZZ_RL_H
