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

} rl_params_t;

rl_params_t* new_hier_sched(u32);

#include "afl-fuzz.h"

void store_features(afl_state_t *);

void update_queue(afl_state_t *);