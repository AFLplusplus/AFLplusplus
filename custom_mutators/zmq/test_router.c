/*
   Simple ZMQ Router for testing the AFL++ ZMQ consumer mutator
   Compile: gcc -o test_router test_router.c -lzmq
*/

#include <zmq.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

static int keep_running = 1;

void signal_handler(int sig) {
  keep_running = 0;
  printf("\nShutting down...\n");
}

int main(int argc, char *argv[]) {
  void *context = zmq_ctx_new();
  void *router = zmq_socket(context, ZMQ_ROUTER);
  
  const char *bind_addr = argc > 1 ? argv[1] : "ipc:///tmp/haha";
  
  if (zmq_bind(router, bind_addr) != 0) {
    fprintf(stderr, "Failed to bind to %s: %s\n", bind_addr, zmq_strerror(zmq_errno()));
    zmq_close(router);
    zmq_ctx_destroy(context);
    return 1;
  }
  
  printf("Router listening on %s\n", bind_addr);
  printf("Waiting for dealers to connect...\n");
  
  signal(SIGINT, signal_handler);
  
  int msg_counter = 0;
  char dealer_id[256];
  char cmd[256];
  
  while (keep_running) {
    zmq_msg_t msg_id, msg_cmd, msg_data;
    
    // Initialize messages
    zmq_msg_init(&msg_id);
    zmq_msg_init(&msg_cmd);
    zmq_msg_init(&msg_data);
    
    // Receive dealer identity
    if (zmq_msg_recv(&msg_id, router, ZMQ_DONTWAIT) < 0) {
      if (zmq_errno() == EAGAIN) {
        usleep(100000); // 100ms
        continue;
      }
      break;
    }
    
    // Extract dealer ID
    size_t id_size = zmq_msg_size(&msg_id);
    if (id_size >= sizeof(dealer_id)) id_size = sizeof(dealer_id) - 1;
    memcpy(dealer_id, zmq_msg_data(&msg_id), id_size);
    dealer_id[id_size] = '\0';
    
    // Receive command
    if (zmq_msg_recv(&msg_cmd, router, 0) < 0) {
      zmq_msg_close(&msg_id);
      continue;
    }
    
    // Extract command
    size_t cmd_size = zmq_msg_size(&msg_cmd);
    if (cmd_size >= sizeof(cmd)) cmd_size = sizeof(cmd) - 1;
    memcpy(cmd, zmq_msg_data(&msg_cmd), cmd_size);
    cmd[cmd_size] = '\0';
    
    if (strcmp(cmd, "HEARTBEAT") == 0) {
      // Receive harness name
      if (zmq_msg_recv(&msg_data, router, 0) >= 0) {
        size_t data_size = zmq_msg_size(&msg_data);
        char harness[256];
        if (data_size >= sizeof(harness)) data_size = sizeof(harness) - 1;
        memcpy(harness, zmq_msg_data(&msg_data), data_size);
        harness[data_size] = '\0';
        
        printf("[%s] Heartbeat from %s\n", dealer_id, harness);
        
        // Send some seeds every 3rd heartbeat
        if (++msg_counter % 3 == 0) {
          printf("[%s] Sending seed bundle...\n", dealer_id);
          
          // Create a simple JSON bundle (simplified)
          char json_bundle[1024];
          snprintf(json_bundle, sizeof(json_bundle),
                   "{\"script_id\": %d, \"harness_name\": \"%s\", "
                   "\"shm_name\": \"shm_%d\", \"seed_ids\": [%d, %d, %d]}",
                   msg_counter, harness, msg_counter, 
                   msg_counter*10, msg_counter*10+1, msg_counter*10+2);
          
          char msg_id_str[64];
          snprintf(msg_id_str, sizeof(msg_id_str), "msg_%d", msg_counter);
          
          // Send SEED message
          zmq_send(router, dealer_id, id_size, ZMQ_SNDMORE);
          zmq_send(router, "SEED", 4, ZMQ_SNDMORE);
          zmq_send(router, msg_id_str, strlen(msg_id_str), ZMQ_SNDMORE);
          zmq_send(router, json_bundle, strlen(json_bundle), 0);
        }
      }
    } else if (strcmp(cmd, "ACK") == 0) {
      // Receive message ID
      zmq_msg_t msg_ack_id, msg_ack_data;
      zmq_msg_init(&msg_ack_id);
      zmq_msg_init(&msg_ack_data);
      
      if (zmq_msg_recv(&msg_ack_id, router, 0) >= 0 &&
          zmq_msg_recv(&msg_ack_data, router, 0) >= 0) {
        size_t ack_id_size = zmq_msg_size(&msg_ack_id);
        char ack_id[256];
        if (ack_id_size >= sizeof(ack_id)) ack_id_size = sizeof(ack_id) - 1;
        memcpy(ack_id, zmq_msg_data(&msg_ack_id), ack_id_size);
        ack_id[ack_id_size] = '\0';
        
        printf("[%s] ACK received for %s\n", dealer_id, ack_id);
      }
      
      zmq_msg_close(&msg_ack_id);
      zmq_msg_close(&msg_ack_data);
    } else {
      printf("[%s] Unknown command: %s\n", dealer_id, cmd);
    }
    
    zmq_msg_close(&msg_id);
    zmq_msg_close(&msg_cmd);
    zmq_msg_close(&msg_data);
  }
  
  printf("Cleaning up...\n");
  zmq_close(router);
  zmq_ctx_destroy(context);
  
  return 0;
} 