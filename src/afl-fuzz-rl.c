#include "afl-fuzz.h"

rl_params_t* init_rl_params(u32 map_size){
  rl_params->map_size = map_size;
  
  rl_params_t* rl_params = (rl_params_t *)ck_alloc(sizeof(rl_params_t));
  rl_params->positive_reward = (u32 *)ck_alloc(map_size * sizeof(u32));
  rl_params->negative_reward = (u32 *)ck_alloc(map_size * sizeof(u32));

  for(u32 i = 0; i < map_size; i++) {
    rl_params->positive_reward[i] = 0;
    rl_params->negative_reward[i] = 0;
  }
  return rl_params;
}


void store_features(rl_params_t *rl_params) {
    u8 *trace_bits = rl_params->trace_bits;
    for(u32 i = 0; i < rl_params->map_size; i++) {
        if (trace_bits[i]) {
            rl_params->positive_reward[i] += 1;
        } else {
            rl_params->negative_reward[i] += 1;
        }
    }


    // int msqid_sender;
    // int msqid_reciever;

    // if (-1 == ( msqid_sender = msgget( (key_t)1, IPC_CREAT | 0666))) {
    //   perror("msgget() failed");
    //   exit(1);
    // }

    // if (-1 == ( msqid_reciever = msgget( (key_t)2, IPC_CREAT | 0666))) {
    //   perror("msgget() failed");
    //   exit(1);
    // }


    // /* Send Messages */
    // t_send_u32_data send_data;
    // send_data.data_type = 2;
    // u32 msg_array[BUFF_SIZE_SENDER];

    // u32 index = 0;
    // while (index < rl_params.map_size) {
    //   msg_array[0] = rl_params.map_size;
      
    //   for (u32 i = 0; i < (BUFF_SIZE_SENDER - 1); i++) {
    //     if (index+i < rl_params.map_size) {
    //       msg_array[i+1] = (u32) rl_params.trace_bits[index+i];
    //     } else {
    //        msg_array[i+1] = (u32) 0;
    //     }
    //   }
    //   memcpy(send_data.data_buff, msg_array, BUFF_SIZE_SENDER * sizeof(u32));
    //   if (-1 == msgsnd(msqid_sender, &send_data, sizeof(t_send_u32_data) - sizeof(long), 0)) {
    //     perror("msgsnd() failed");
    //     exit(1);
    //   }
    //   index += BUFF_SIZE_SENDER;
    // }


  // /* Receive Messages */
  //   t_recieve_u8_data recieve_data;
  //   u8 recieved_array[BUFF_SIZE_RECEIVER];
  //   if (-1 == msgrcv(msqid_reciever, &recieve_data, sizeof(t_recieve_u8_data) - sizeof(long), 0, 0)) {
  //     perror( "msgrcv() failed");
  //     exit(1);
  //   }

  //   memcpy(recieved_array, recieve_data.data_buff, BUFF_SIZE_RECEIVER * sizeof(double));
  //   printf("Interpreted as array: ");
  //   for(int i = 0; i<BUFF_SIZE_RECEIVER; i++) {
  //     printf("%d ", recieved_array[i]);
  //   }
  //   printf("\n");

}

void update_queue(rl_params_t *rl_params) {


  int msqid_sender;
  int msqid_reciever;
  if (-1 == ( msqid_sender = msgget( (key_t)1, IPC_CREAT | 0666))) {
    perror("msgget() failed");
    exit(1);
  }

  if (-1 == ( msqid_reciever = msgget( (key_t)2, IPC_CREAT | 0666))) {
    perror("msgget() failed");
    exit(1);
  }

  /* Send Messages */
  t_u32_data send_data;
  send_data.data_type = 1;
  u32 msg_array[BUFF_SIZE];
  msg_array[0] = rl_params->map_size;



  memcpy(send_data.data_buff, msg_array, BUFF_SIZE * sizeof(u32));
  if (-1 == msgsnd(msqid_sender, &send_data, sizeof(t_u32_data) - sizeof(long), 0)) {
    perror("msgsnd() failed");
    exit(1);
  }

  u32 index = 0;
  while (index < rl_params->map_size) {
    
    for (u32 i = 0; i < BUFF_SIZE; i++) {
      if (index+i < rl_params->map_size) {
        msg_array[i] = rl_params->positive_reward[index+i];
      } else {
         msg_array[i] = 0;
      }
    }
    memcpy(send_data.data_buff, msg_array, BUFF_SIZE * sizeof(u32));
    if (-1 == msgsnd(msqid_sender, &send_data, sizeof(t_u32_data) - sizeof(long), 0)) {
      perror("msgsnd() failed");
      exit(1);
    }
    index += BUFF_SIZE;
  }

  index = 0;
  while (index < rl_params->map_size) {
    
    for (u32 i = 0; i < BUFF_SIZE; i++) {
      if (index+i < rl_params->map_size) {
        msg_array[i] = rl_params->negative_reward[index+i];
      } else {
         msg_array[i] = 0;
      }
    }
    memcpy(send_data.data_buff, msg_array, BUFF_SIZE * sizeof(u32));
    if (-1 == msgsnd(msqid_sender, &send_data, sizeof(t_u32_data) - sizeof(long), 0)) {
      perror("msgsnd() failed");
      exit(1);
    }
    index += BUFF_SIZE;
  }



  // /* Receive Messages */
  // t_recieve_double_data recieve_data;
  // double recieved_array[BUFF_SIZE_RECEIVER];
  // double score_array[afl->fsrv.map_size];
  // u32 index = 0;
  // while (index < afl->fsrv.map_size) {
  //   if (-1 == msgrcv(msqid_reciever, &recieve_data, sizeof(t_recieve_double_data) - sizeof(long), 0, 0)) {
  //     perror( "msgrcv() failed");
  //     exit(1);
  //   }
  //   memcpy(recieved_array, recieve_data.data_buff, BUFF_SIZE_RECEIVER * sizeof(double));
  //   for(u32 i = 0; i < BUFF_SIZE_RECEIVER; i++) {
  //     if(index+i < afl->fsrv.map_size) {
  //       score_array[index+i] = recieved_array[i];
  //     }
  //   }
  //   index += BUFF_SIZE_RECEIVER;
  // }
  // (void)score_array; // Silence Error Remove Later


    /* Receive Messages */
    t_u32_data recieve_data;
    double recieved_array[BUFF_SIZE];
    if (-1 == msgrcv(msqid_reciever, &recieve_data, sizeof(t_u32_data) - sizeof(long), 0, 0)) {
      perror( "msgrcv() failed");
      exit(1);
    }

    memcpy(recieved_array, recieve_data.data_buff, BUFF_SIZE * sizeof(u32));

    rl_params->current_entry = (u32) recieved_array[0];

    OKF("Modifying queue with RL\n");
    rl_params->queue_cur = rl_params->top_rated[(int) rl_params->current_entry];
    if (rl_params->queue_cur) {
      OKF("Setting queue_cur to %d", rl_params->queue_cur->id);
      rl_params->current_entry = rl_params->queue_cur->id;
    }



}



