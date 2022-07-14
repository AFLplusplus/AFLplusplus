#ifndef AFL_FUZZ_RL
#define AFL_FUZZ_RL

#include "types.h"

#define PYTHON_RL

// Store Parameters for Reinforcement learning
typedef struct {
#ifdef PYTHON_RL
  int msqid_sender;
  int msqid_reciever;
#endif

  u32 *positive_reward;
  u32 *negative_reward;

  u8 *trace_bits;

  u32 map_size, current_entry;

  struct queue_entry * queue_cur;
  struct queue_entry **top_rated;
} rl_params_t;

rl_params_t *init_rl_params(u32);
void         store_features(rl_params_t *);
void         update_queue(rl_params_t *);

#endif
