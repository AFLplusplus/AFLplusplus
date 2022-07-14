#include <sys/ipc.h>
#include <sys/msg.h>

#include "afl-fuzz.h"
#include "afl-fuzz-rl.h"

#ifdef PYTHON_RL
  #include "rl-py.h"
#endif

rl_params_t *init_rl_params(u32 map_size) {
  rl_params_t *rl_params = (rl_params_t *)ck_alloc(sizeof(rl_params_t));

  rl_params->positive_reward = (u32 *)ck_alloc(map_size * sizeof(u32));
  rl_params->negative_reward = (u32 *)ck_alloc(map_size * sizeof(u32));

  // ck_alloc already zeroes out memory in non-debug mode
#ifdef DEBUG_BUILD
  memset(rl_params->positive_reward, 0, map_size * sizeof(u32));
  memset(rl->params->negative_reward, 0, map_size * sizeof(u32));
#endif
  rl_params->map_size = map_size;

#ifdef PYTHON_RL
  if (-1 == (rl_params->msqid_sender = msgget((key_t)1, IPC_CREAT | 0666))) {
    perror("msgget() failed");
    exit(1);
  }

  if (-1 == (rl_params->msqid_reciever = msgget((key_t)2, IPC_CREAT | 0666))) {
    perror("msgget() failed");
    exit(1);
  }

  // Send the initial message (with the map size)
  py_msg_t py_data;
  py_data.type = INITIALIZATION_FLAG;
  py_data.map_size = map_size;

  if (-1 == msgsnd(rl_params->msqid_sender, &py_data, sizeof(py_data), 0)) {
    perror("msgsnd() failed");
    exit(1);
  }
#endif

  return rl_params;
}

void store_features(rl_params_t *rl_params) {
  u8 *trace_bits = rl_params->trace_bits;

  for (u32 i = 0; i < rl_params->map_size; i++) {
    if (trace_bits[i]) {
      rl_params->positive_reward[i] += 1;
    } else {
      rl_params->negative_reward[i] += 1;
    }
  }
}

void update_queue(rl_params_t *rl_params) {
#ifdef PYTHON_RL
  py_msg_t py_data;

  // Send map size
  py_data.type = INITIALIZATION_FLAG;
  py_data.map_size = rl_params->map_size;

  if (-1 == msgsnd(rl_params->msqid_sender, &py_data, sizeof(py_data), 0)) {
    perror("msgsnd() failed");
    exit(1);
  }

  // Send positive reward
  u32 index = 0;
  while (index < rl_params->map_size) {
    py_data.type = UPDATE_SCORE;

    for (u32 i = 0; i < BUFF_SIZE; i++) {
      if (index + i < rl_params->map_size) {
        py_data.score[i] = rl_params->positive_reward[index + i];
      } else {
        py_data.score[i] = 0;
      }
    }

    if (-1 == msgsnd(rl_params->msqid_sender, &py_data, sizeof(py_data), 0)) {
      perror("msgsnd() failed");
      exit(1);
    }

    index += BUFF_SIZE;
  }

  // Send negative reward
  index = 0;
  while (index < rl_params->map_size) {
    py_data.type = UPDATE_SCORE;

    for (u32 i = 0; i < BUFF_SIZE; i++) {
      if (index + i < rl_params->map_size) {
        py_data.score[i] = rl_params->negative_reward[index + i];
      } else {
        py_data.score[i] = 0;
      }
    }

    if (-1 == msgsnd(rl_params->msqid_sender, &py_data, sizeof(py_data), 0)) {
      perror("msgsnd() failed");
      exit(1);
    }

    index += BUFF_SIZE;
  }

  // Receive best seed
  if (-1 == msgrcv(rl_params->msqid_reciever, &py_data, sizeof(py_data),
                   BEST_SEED, 0)) {
    perror("msgrcv() failed");
    exit(1);
  }

  rl_params->current_entry = py_data.best_seed.seed;
  // TODO: Do something with the reward?

  rl_params->queue_cur = rl_params->top_rated[(int)rl_params->current_entry];
  if (rl_params->queue_cur) {
    rl_params->current_entry = rl_params->queue_cur->id;
  }
#endif
}
