#include "types.h"

#include <sys/ipc.h>
#include <sys/msg.h>

// Message Queue Parameters and Structs
#define  BUFF_SIZE    1024


typedef struct {
  long    data_type;
  double  data_buff[BUFF_SIZE];
} t_double_data;


typedef struct {
  long    data_type;
  u8      data_buff[BUFF_SIZE];
} t_u8_data;

typedef struct {
  long    data_type;
  u64     data_buff[BUFF_SIZE];
} t_u64_data;



// Store Parameters for Reinforcement learning

typedef struct rl_params{

  int msqid_sender;
  int msqid_reciever;

  u64 *positive_reward;
  u64 *negative_reward;

  u8 *trace_bits;

  u32 map_size,
      current_entry;

  struct queue_entry *queue_cur;
  struct queue_entry **top_rated;
} rl_params_t;

rl_params_t* init_rl_params(u32);


void store_features(rl_params_t *);

void update_queue(rl_params_t *);