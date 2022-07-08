#include "types.h"

#include <sys/ipc.h>
#include <sys/msg.h>

// Message Queue Parameters and Structs
#define  BUFF_SIZE_SENDER     1024
#define  BUFF_SIZE_RECEIVER   1024


typedef struct {
  long    data_type;
  double  data_buff[BUFF_SIZE_SENDER];
} t_send_double_data;

typedef struct {
  long    data_type;
  double  data_buff[BUFF_SIZE_RECEIVER];
} t_recieve_double_data;

typedef struct {
  long    data_type;
  u8      data_buff[BUFF_SIZE_SENDER];
} t_send_u8_data;

typedef struct {
  long    data_type;
  u8      data_buff[BUFF_SIZE_RECEIVER];
} t_recieve_u8_data;

typedef struct {
  long    data_type;
  u32     data_buff[BUFF_SIZE_SENDER];
} t_send_u32_data;

typedef struct {
  long    data_type;
  u32     data_buff[BUFF_SIZE_RECEIVER];
} t_recieve_u32_data;



// Store Parameters for Reinforcement learning

typedef struct rl_params{

    u64 *positive_reward;
    u64 *negative_reward;

    u8 *trace_bits;

    u32 mapsize,
        current_entry;

    struct queue_entry *queue_cur,
                       *top_rated;
} rl_params_t;

rl_params_t* new_hier_sched(u32);


void store_features(rl_params_t *);

void update_queue(rl_params_t *);