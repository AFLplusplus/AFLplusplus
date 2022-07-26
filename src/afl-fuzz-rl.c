#include <sys/ipc.h>
#include <sys/msg.h>

#include "afl-fuzz.h"
#include "afl-fuzz-rl.h"

#ifdef RL_USE_PYTHON
  #pragma message "Using Python-based RL"
#else
  #pragma message "Using C++-based RL"
#endif

static const char *rl_correction_factor_strs[] = {
    "none",
    "without_square_root",
    "with_square_root",
    "sample",
};

u32 __attribute__((weak)) rl_select_best_bit(const rl_params_t *params) {
  (void)params;
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
//
// For Python prototyping

#if RL_USE_PYTHON
  #include "rl-py.h"

static void rl_initialize_msg_queue(rl_params_t *rl_params) {
  if (-1 == (rl_params->msqid_sender = msgget((key_t)1, IPC_CREAT | 0666))) {
    perror("msgget() failed");
    exit(1);
  }

  if (-1 == (rl_params->msqid_reciever = msgget((key_t)2, IPC_CREAT | 0666))) {
    perror("msgget() failed");
    exit(1);
  }
}

void rl_py_update_map_size(rl_params_t *rl_params) {
  py_msg_t py_data;

  // Send map size
  py_data.type = INITIALIZATION_FLAG;
  py_data.map_size = rl_params->map_size;

  ACTF("Sending INITIALIZATION_FLAG msg: map_size=%u", py_data.map_size);
  if (-1 == msgsnd(rl_params->msqid_sender, &py_data, MSG_SZ, 0)) {
    perror("msgsnd() failed");
    exit(1);
  }
}
#endif

//
///////////////////////////////////////////////////////////////////////////////

rl_params_t *rl_init_params(u32 map_size) {
  rl_params_t *rl_params = (rl_params_t *)ck_alloc(sizeof(rl_params_t));

  if (getenv("AFL_RL_CORRECTION_FACTOR")) {
    s32 correction_factor = atoi(getenv("AFL_RL_CORRECTION_FACTOR"));
    if (correction_factor < NONE || correction_factor > NUM_VALUES) {
      FATAL("Bad value specified for AFL_RL_CORRECTION_FACTOR");
    }
    rl_params->correction_factor = correction_factor;
  } else {
    rl_params->correction_factor = NONE;
  }
  OKF("Correction factor = %s\n",
      rl_correction_factor_strs[rl_params->correction_factor]);

  rl_params->positive_reward = (u32 *)ck_alloc(map_size * sizeof(u32));
  rl_params->negative_reward = (u32 *)ck_alloc(map_size * sizeof(u32));

  // Initalize to 1 to save me from adding 1 later on
  memset(rl_params->positive_reward, 1, map_size * sizeof(u32));
  memset(rl_params->negative_reward, 1, map_size * sizeof(u32));

  rl_params->map_size = map_size;

#ifdef RL_USE_PYTHON
  // Initialize the SystemV message queue
  rl_initialize_msg_queue(rl_params);

  // Send the initial message (with the map size)
  rl_py_update_map_size(rl_params);
#endif

  return rl_params;
}

void rl_store_features(rl_params_t *rl_params) {
  u8 *trace_bits = rl_params->trace_bits;

  for (u32 i = 0; i < rl_params->map_size; i++) {
    if (trace_bits[i]) {
      rl_params->positive_reward[i] += 1;
    } else {
      rl_params->negative_reward[i] += 1;
    }
  }
}

void rl_update_queue(rl_params_t *rl_params) {
  u32 best_bit;

#ifdef RL_USE_PYTHON
  py_msg_t py_data;

  // Send positive reward
  py_data.type = UPDATE_SCORE;
  u32 index = 0;

  ACTF("Sending UPDATE_SCORE msg: positive reward");
  while (index < rl_params->map_size) {
    for (u32 i = 0; i < BUFF_SIZE; i++) {
      if (index + i < rl_params->map_size) {
        py_data.score[i] = rl_params->positive_reward[index + i];
      } else {
        py_data.score[i] = 0;
      }
    }

    if (-1 == msgsnd(rl_params->msqid_sender, &py_data, MSG_SZ, 0)) {
      perror("msgsnd() failed");
      exit(1);
    }

    index += BUFF_SIZE;
  }

  // Send negative reward
  py_data.type = UPDATE_SCORE;
  index = 0;

  ACTF("Sending UPDATE_SCORE msg: negative reward");
  while (index < rl_params->map_size) {
    for (u32 i = 0; i < BUFF_SIZE; i++) {
      if (index + i < rl_params->map_size) {
        py_data.score[i] = rl_params->negative_reward[index + i];
      } else {
        py_data.score[i] = 0;
      }
    }

    if (-1 == msgsnd(rl_params->msqid_sender, &py_data, MSG_SZ, 0)) {
      perror("msgsnd() failed");
      exit(1);
    }

    index += BUFF_SIZE;
  }

  // Receive best bit
  if (-1 == msgrcv(rl_params->msqid_reciever, &py_data, MSG_SZ, BEST_BIT, 0)) {
    perror("msgrcv() failed");
    exit(1);
  }

  ACTF("Recieved BEST_BIT msg: bit=%u", py_data.best_bit.bit);
  best_bit = py_data.best_bit.bit;
#else
  // XXX hardcode correction factor for now
  best_bit = rl_select_best_bit(rl_params);
  ACTF("Best bit=%u", best_bit);
#endif

  rl_params->current_entry = best_bit;
  rl_params->queue_cur = rl_params->top_rated[(int)rl_params->current_entry];
  if (likely(rl_params->queue_cur)) {
    rl_params->current_entry = rl_params->queue_cur->id;
  }
}
