
hier_sched_t* new_hier_sched(u32 map_size){
  rl_params_t* rl_params = (rl_params_t *)ck_alloc(sizeof(rl_params_t));
  rl_params->positive_reward = (u64 *)ck_alloc(map_size * sizeof(u64));
  rl_params->negative_reward = (u64 *)ck_alloc(map_size * sizeof(u64));
  return rl_params
}


void store_features(afl_state_t *afl) {
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
    t_send_u32_data send_data;
    send_data.data_type = 2;
    u32 msg_array[BUFF_SIZE_SENDER];

    u32 index = 0;
    while (index < afl->fsrv.map_size) {
      msg_array[0] = afl->fsrv.map_size;
      
      for (u32 i = 0; i < (BUFF_SIZE_SENDER - 1); i++) {
        if (index+i < afl->fsrv.map_size) {
          msg_array[i+1] = (u32) afl->fsrv.trace_bits[index+i];
        } else {
           msg_array[i+1] = (u32) 0;
        }
      }
      memcpy(send_data.data_buff, msg_array, BUFF_SIZE_SENDER * sizeof(u32));
      if (-1 == msgsnd(msqid_sender, &send_data, sizeof(t_send_u32_data) - sizeof(long), 0)) {
        perror("msgsnd() failed");
        exit(1);
      }
      index += BUFF_SIZE_SENDER;
    }


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

void update_queue(afl_state_t *afl) {


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
  t_send_u32_data send_data;
  send_data.data_type = 1;
  u32 msg_array[BUFF_SIZE_SENDER];
  msg_array[0] = afl->fsrv.map_size;



  memcpy(send_data.data_buff, msg_array, BUFF_SIZE_SENDER * sizeof(u32));
  if (-1 == msgsnd(msqid_sender, &send_data, sizeof(t_send_u32_data) - sizeof(long), 0)) {
  perror("msgsnd() failed");
  exit(1);
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
  t_recieve_u32_data recieve_data;
  double recieved_array[BUFF_SIZE_RECEIVER];
  if (-1 == msgrcv(msqid_reciever, &recieve_data, sizeof(t_recieve_u32_data) - sizeof(long), 0, 0)) {
  perror( "msgrcv() failed");
  exit(1);
  }

  memcpy(recieved_array, recieve_data.data_buff, BUFF_SIZE_RECEIVER * sizeof(u32));

  afl->current_entry = (u32) recieved_array[0];

  OKF("Modifying queue with RL\n");
  afl->queue_cur = afl->top_rated[(int) afl->current_entry];
  if (afl->queue_cur) {
  OKF("Setting queue_cur to %d", afl->queue_cur->id);
  afl->current_entry = afl->queue_cur->id;
  }



}



