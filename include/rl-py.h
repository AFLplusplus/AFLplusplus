#ifndef RL_PY_H
#define RL_PY_H

#include "types.h"

// Message Queue Parameters and Structs
#define BUFF_SIZE 1024

// Message types
#define INITIALIZATION_FLAG 1
#define UPDATE_SCORE 2
#define BEST_BIT 3

// Size of a SystemV message queue message
#define MSG_SZ (sizeof(py_msg_t) - sizeof(long))

typedef struct __attribute__((__packed__)) {
  u32 bit;    ///< Best bit ID
} best_bit_t;

// Communicating with Python
typedef struct __attribute__((__packed__)) {
  long type;
  // Tagged union
  union {
    u32         map_size;  ///< The initialization message is just the map size
    u32         score[BUFF_SIZE];  ///< Update score message
    best_bit_t  best_bit;
  };
} py_msg_t;

void rl_update_map_size(rl_params_t *);

#endif  // RL_PY_H
