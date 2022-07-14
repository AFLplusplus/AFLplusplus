#ifndef RL_PY_H
#define RL_PY_H

#include "types.h"

// Message Queue Parameters and Structs
#define BUFF_SIZE 1024

// Message types
#define INITIALIZATION_FLAG 1
#define UPDATE_SCORE 2
#define BEST_SEED 3

typedef struct __attribute__((__packed__)) {
  u32 seed;    ///< Best seed ID
  u32 reward;  ///< Reward
} best_seed_t;

// Communicating with Python
typedef struct __attribute__((__packed__)) {
  long type;
  // Tagged union
  union {
    u32         map_size;  ///< The initialization message is just the map size
    u32         score[BUFF_SIZE];  ///< Update score message
    best_seed_t best_seed;
  };
} py_msg_t;

#endif
