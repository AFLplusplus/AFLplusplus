#include "afl-mutations.h"
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <time.h>

#define BUFF_SIZE 16
int TYPE_REQUEST = 1;
int TYPE_REWARD = 2;
int TYPE_SEED = 3;
int TYPE_EMPTY_SEED = 4;

typedef struct {
  long data_type;
  char data_buff[BUFF_SIZE];
} My_message;

typedef struct my_mutator {
  afl_state_t *afl;
  u8          *buf;
  u32          buf_size;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  (void)seed;

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }
  // allocate MAX size buf
  if ((data->buf = malloc(MAX_FILE)) == NULL) {
    perror("afl_custom_init alloc");
    return NULL;
  } else {
    data->buf_size = MAX_FILE;
  }
  data->afl = afl;

  /* the mutation, send request to LLM, then receive mutate seed */
  //   u32 out_buf_len = afl_mutate(data->afl, data->buf, buf_size,
  //   havoc_steps,false, true, add_buf, add_buf_size, max_size);
  My_message my_msg;
  int        msg = 200;
  int        msqid;
  int        receive_flag = 1;

  // Create or open the message queue
  if ((msqid = msgget((key_t)1234, IPC_CREAT | 0666)) == -1) {
    perror("msgget() failed");
    exit(1);
  }

  // send the request message
  memcpy(my_msg.data_buff, &msg, sizeof(int));
  my_msg.data_type = TYPE_REQUEST
  if (msgsnd(msqid, &my_msg, sizeof(my_msg.data_buff), 0) == -1) {
    perror("msgsnd() failed");
    exit(1);
  }
  // receive seed info from llm
  clock_t start_time;
  start_time = clock();

  while (true) {
    // if run time exceed 0.1s then break and mutate default one
    if (difftime(clock(), start_time) >= 0.1) {
      receive_flag = 0;
      break;
    }
    
    if (-1 == msgrcv(msqid, &my_msg, sizeof(My_message) - sizeof(long), 0, 0)) {
      perror("msgrcv() failed");
      exit(1);
    } 
    else {
      if (my_msg.data_type == TYPE_SEED){
        receive_flag = 1;
        data.buf = my_msg.data_buff;
        data->buf_size = size(my_msg.data_buff) <= MAX_FILE ? size(my_msg.data_buff) : MAX_FILE;
      }
      else{
        // receive empty seed
        receive_flag = 0;
      }
      break;
    }
  }
  // did not receive new seed, mutate default seed
  if receive_flag==0:
  {
    
  }
  return data;
}

/* here we run the AFL++ mutator, which is the best! */

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {
  if (max_size > data->buf_size) {
    u8 *ptr = realloc(data->buf, max_size);

    if (ptr) {
      return 0;

    } else {
      data->buf = ptr;
      data->buf_size = max_size;
    }
  }

  u32 havoc_steps = 1 + rand_below(data->afl, 16);

  /* set everything up, costly ... :( */
  memcpy(data->buf, buf, buf_size);
  u32 out_buf_len = afl_mutate(data->afl, data->buf, buf_size, havoc_steps,
                               false, true, add_buf, add_buf_size, max_size);

  /* return size of mutated data */
  *out_buf = data->buf;
  return out_buf_len;
}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {
  free(data->buf);
  free(data);
}
