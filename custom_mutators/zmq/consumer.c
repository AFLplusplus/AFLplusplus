/*
   AFL++ ZMQ Consumer Mutator with Shared Memory Support
   -----------------------------------------------------
   
   This custom mutator receives seed IDs from a ZMQ router and reads the actual
   seed content from shared memory pools. Based on the dealer pattern.
   
   Features:
   - Connects to ZMQ router as a dealer
   - Receives JSON bundles with seed IDs and shared memory names
   - Reads actual seed content from /dev/shm/<shm_name>
   - Maintains a circular buffer of seeds for non-blocking fuzzing
   - Background thread handles all network and shared memory operations
   
   Compile with: make libzmqmutator.so
   Requires: libzmq, cJSON or json-c, shared memory support
*/

#include "afl-fuzz.h"
#include <zmq.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

// Configuration
#define MAX_SEED_SIZE 1048576    // 1MB max per seed
#define BUFFER_SIZE 104857600    // 100MB buffer for seeds
#define HEARTBEAT_INTERVAL 5     // seconds
#define RECV_TIMEOUT 100         // milliseconds
#define MAX_SHM_POOLS 10         // Maximum number of concurrent shared memory pools

// Shared memory pool header constants
#define SHM_HEADER_SIZE 8
#define SHM_LEN_FIELD_SIZE 4

// JSON parsing helpers (simplified - use cJSON in production)
#define JSON_MAX_SIZE 4096

// Logging helper
static void zmq_printf(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stdout, fmt, ap);
  va_end(ap);
  fflush(stdout);
}

// Shared memory pool consumer structure
typedef struct shm_consumer {
  char name[256];              // Shared memory name
  int fd;                      // File descriptor
  void *mapped_memory;         // Mapped memory pointer
  size_t file_size;           // Total file size
  u32 item_size;              // Size of each item
  u32 item_num;               // Number of items
  struct shm_consumer *next;   // Linked list
} shm_consumer_t;

// ZMQ mutator structure
typedef struct zmq_mutator {
  afl_state_t *afl;
  
  // ZMQ context and socket
  void *zmq_context;
  void *zmq_socket;
  char dealer_id[64];
  char *router_addr;
  char *harness_name;
  
  // Shared memory consumers
  shm_consumer_t *shm_consumers;
  pthread_mutex_t shm_mutex;
  
  // Large circular buffer for seeds
  u8 *seed_buffer;
  size_t buffer_size;
  size_t write_pos;
  size_t read_pos;
  size_t data_available;
  pthread_mutex_t buffer_mutex;
  pthread_cond_t buffer_cond;
  
  // Background thread
  pthread_t network_thread;
  volatile u8 should_stop;
  
  // Working buffer for mutations
  u8 *fuzz_buf;
  size_t fuzz_buf_size;
  
  // Statistics
  u64 total_mutations;
  u64 zmq_seeds_received;
  u64 seeds_used;
  u64 bytes_received;
  u32 seed_count;
  u32 last_printed_count;
  
} zmq_mutator_t;

// Forward declarations
static void *network_thread_func(void *arg);
static void send_heartbeat(zmq_mutator_t *data);
static void process_zmq_messages(zmq_mutator_t *data);
static void process_seed_bundle(zmq_mutator_t *data, const char *msg_id, const char *bundle_json);
static shm_consumer_t *get_or_create_consumer(zmq_mutator_t *data, const char *shm_name);
static int read_seed_from_shm(shm_consumer_t *consumer, int seed_id, u8 **out_data, size_t *out_size);
static int add_seed_to_buffer(zmq_mutator_t *data, u8 *seed_data, size_t len);
static size_t get_seed_from_buffer(zmq_mutator_t *data, u8 *out_buf, size_t max_size);
static void cleanup_shm_consumers(zmq_mutator_t *data);

// Initialize the custom mutator
zmq_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {
  
  zmq_printf("[ZMQ] Initializing ZMQ consumer mutator with shared memory support\n");
  
  zmq_mutator_t *data = calloc(1, sizeof(zmq_mutator_t));
  if (!data) {
    perror("afl_custom_init alloc");
    return NULL;
  }
  
  data->afl = afl;
  data->should_stop = 0;
  
  // Initialize mutexes
  if (pthread_mutex_init(&data->buffer_mutex, NULL) != 0 ||
      pthread_mutex_init(&data->shm_mutex, NULL) != 0) {
    free(data);
    return NULL;
  }
  
  if (pthread_cond_init(&data->buffer_cond, NULL) != 0) {
    pthread_mutex_destroy(&data->buffer_mutex);
    pthread_mutex_destroy(&data->shm_mutex);
    free(data);
    return NULL;
  }
  
  // Get configuration from environment or use defaults
  data->router_addr = getenv("AFL_ZMQ_ROUTER");
  if (!data->router_addr) data->router_addr = "ipc:///tmp/ipc/haha";
  
  // Try to get harness name from argv[0], then environment, then use default
  data->harness_name = NULL;
  if (afl->argv && afl->argv[0]) {
    // Extract just the binary name from the full path
    char *binary_name = strrchr(afl->argv[0], '/');
    if (binary_name) {
      data->harness_name = binary_name + 1;  // Skip the '/'
    } else {
      data->harness_name = afl->argv[0];
    }
  }
  
  // Fallback to environment variable if still not available
  if (!data->harness_name) {
    data->harness_name = getenv("FUZZER");
  }
  
  // Final fallback to default
  if (!data->harness_name) data->harness_name = "AFL";
  
  zmq_printf("[ZMQ] Using harness name: %s\n", data->harness_name);
  
  // Allocate large circular buffer
  data->buffer_size = BUFFER_SIZE;
  data->seed_buffer = malloc(data->buffer_size);
  if (!data->seed_buffer) {
    pthread_cond_destroy(&data->buffer_cond);
    pthread_mutex_destroy(&data->buffer_mutex);
    pthread_mutex_destroy(&data->shm_mutex);
    free(data);
    return NULL;
  }
  
  // Initialize buffer positions
  data->write_pos = 0;
  data->read_pos = 0;
  data->data_available = 0;
  
  // Generate unique dealer ID
  snprintf(data->dealer_id, sizeof(data->dealer_id), "AFL-%u-%u", 
           getpid(), seed);
  
  // Initialize ZMQ
  data->zmq_context = zmq_ctx_new();
  if (!data->zmq_context) {
    fprintf(stderr, "[ZMQ] Failed to create ZMQ context\n");
    free(data->seed_buffer);
    pthread_cond_destroy(&data->buffer_cond);
    pthread_mutex_destroy(&data->buffer_mutex);
    pthread_mutex_destroy(&data->shm_mutex);
    free(data);
    return NULL;
  }
  
  data->zmq_socket = zmq_socket(data->zmq_context, ZMQ_DEALER);
  if (!data->zmq_socket) {
    fprintf(stderr, "[ZMQ] Failed to create ZMQ socket\n");
    zmq_ctx_destroy(data->zmq_context);
    free(data->seed_buffer);
    pthread_cond_destroy(&data->buffer_cond);
    pthread_mutex_destroy(&data->buffer_mutex);
    pthread_mutex_destroy(&data->shm_mutex);
    free(data);
    return NULL;
  }
  
  // Set socket identity
  zmq_setsockopt(data->zmq_socket, ZMQ_IDENTITY, 
                 data->dealer_id, strlen(data->dealer_id));
  
  // Set receive timeout
  int timeout = RECV_TIMEOUT;
  zmq_setsockopt(data->zmq_socket, ZMQ_RCVTIMEO, &timeout, sizeof(timeout));
  
  // Connect to router
  if (zmq_connect(data->zmq_socket, data->router_addr) != 0) {
    fprintf(stderr, "[ZMQ] Failed to connect to %s: %s\n", 
            data->router_addr, zmq_strerror(errno));
    zmq_close(data->zmq_socket);
    zmq_ctx_destroy(data->zmq_context);
    free(data->seed_buffer);
    pthread_cond_destroy(&data->buffer_cond);
    pthread_mutex_destroy(&data->buffer_mutex);
    pthread_mutex_destroy(&data->shm_mutex);
    free(data);
    return NULL;
  }
  
  zmq_printf("[ZMQ] Connected to router at %s with ID %s\n", 
             data->router_addr, data->dealer_id);
  
  // Allocate working fuzz buffer
  data->fuzz_buf_size = MAX_SEED_SIZE;
  data->fuzz_buf = malloc(data->fuzz_buf_size);
  if (!data->fuzz_buf) {
    zmq_close(data->zmq_socket);
    zmq_ctx_destroy(data->zmq_context);
    free(data->seed_buffer);
    pthread_cond_destroy(&data->buffer_cond);
    pthread_mutex_destroy(&data->buffer_mutex);
    pthread_mutex_destroy(&data->shm_mutex);
    free(data);
    return NULL;
  }
  
  // Start network thread
  if (pthread_create(&data->network_thread, NULL, 
                     network_thread_func, data) != 0) {
    fprintf(stderr, "[ZMQ] Failed to create network thread\n");
    free(data->fuzz_buf);
    zmq_close(data->zmq_socket);
    zmq_ctx_destroy(data->zmq_context);
    free(data->seed_buffer);
    pthread_cond_destroy(&data->buffer_cond);
    pthread_mutex_destroy(&data->buffer_mutex);
    pthread_mutex_destroy(&data->shm_mutex);
    free(data);
    return NULL;
  }
  
  return data;
}

// Main fuzzing function - completely non-blocking
size_t afl_custom_fuzz(zmq_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {
  
  // Try to get a seed from the buffer
  size_t seed_size = get_seed_from_buffer(data, data->fuzz_buf, 
                                           max_size < data->fuzz_buf_size ? max_size : data->fuzz_buf_size);
  
  if (seed_size > 0) {
    // We got a seed from the buffer
    *out_buf = data->fuzz_buf;
    data->total_mutations++;
    data->seeds_used++;
    return seed_size;
  }
  
  // No seeds available, return nothing
  return 0;
}

// Network thread - handles all ZMQ communication and shared memory reading
static void *network_thread_func(void *arg) {
  zmq_mutator_t *data = (zmq_mutator_t *)arg;
  time_t last_heartbeat = 0;
  int heartbeat_count = 0;
  
  zmq_printf("[ZMQ] Network thread started\n");
  
  while (!data->should_stop) {
    // Send heartbeat if needed
    time_t now = time(NULL);
    if (now - last_heartbeat >= HEARTBEAT_INTERVAL) {
      send_heartbeat(data);
      last_heartbeat = now;
      heartbeat_count++;
      
      if (heartbeat_count % 10 == 0) {
        pthread_mutex_lock(&data->buffer_mutex);
        zmq_printf("[ZMQ] Status: %d heartbeats, %u seeds, buffer: %zu/%zu bytes\n",
                   heartbeat_count, data->seed_count,
                   data->data_available, data->buffer_size);
        pthread_mutex_unlock(&data->buffer_mutex);
      }
    }
    
    // Process incoming messages
    process_zmq_messages(data);
    
    // Small sleep to prevent busy waiting
    usleep(10000); // 10ms
  }
  
  zmq_printf("[ZMQ] Network thread exiting\n");
  return NULL;
}

// Send heartbeat
static void send_heartbeat(zmq_mutator_t *data) {
  zmq_printf("[ZMQ] Sending HEARTBEAT\n");
  zmq_send(data->zmq_socket, "HEARTBEAT", 9, ZMQ_SNDMORE);
  zmq_send(data->zmq_socket, data->harness_name, 
           strlen(data->harness_name), 0);
}

// Process incoming ZMQ messages
static void process_zmq_messages(zmq_mutator_t *data) {
  zmq_msg_t msg_cmd, msg_id, msg_data;
  char cmd[32], msg_id_str[256];
  
  // Initialize messages
  zmq_msg_init(&msg_cmd);
  zmq_msg_init(&msg_id);
  zmq_msg_init(&msg_data);
  
  // Try to receive command (non-blocking due to timeout)
  if (zmq_msg_recv(&msg_cmd, data->zmq_socket, 0) < 0) {
    goto cleanup;
  }
  
  // Extract command
  size_t cmd_size = zmq_msg_size(&msg_cmd);
  if (cmd_size >= sizeof(cmd)) cmd_size = sizeof(cmd) - 1;
  memcpy(cmd, zmq_msg_data(&msg_cmd), cmd_size);
  cmd[cmd_size] = '\0';
  
  zmq_printf("[ZMQ] Received command: %s\n", cmd);
  
  if (strcmp(cmd, "SEED") == 0) {
    // Receive message ID
    if (zmq_msg_recv(&msg_id, data->zmq_socket, 0) < 0) {
      goto cleanup;
    }
    
    size_t id_size = zmq_msg_size(&msg_id);
    if (id_size >= sizeof(msg_id_str)) id_size = sizeof(msg_id_str) - 1;
    memcpy(msg_id_str, zmq_msg_data(&msg_id), id_size);
    msg_id_str[id_size] = '\0';
    
    // Receive bundle data
    if (zmq_msg_recv(&msg_data, data->zmq_socket, 0) < 0) {
      goto cleanup;
    }
    
    // Extract JSON bundle
    size_t data_size = zmq_msg_size(&msg_data);
    char *json_data = malloc(data_size + 1);
    if (json_data) {
      memcpy(json_data, zmq_msg_data(&msg_data), data_size);
      json_data[data_size] = '\0';
      
      // Process the bundle
      process_seed_bundle(data, msg_id_str, json_data);
      
      // Send ACK
      zmq_printf("[ZMQ] Sending ACK for %s\n", msg_id_str);
      zmq_send(data->zmq_socket, "ACK", 3, ZMQ_SNDMORE);
      zmq_send(data->zmq_socket, msg_id_str, strlen(msg_id_str), ZMQ_SNDMORE);
      zmq_send(data->zmq_socket, json_data, strlen(json_data), 0);
      zmq_printf("[ZMQ] ACK sent for %s\n", msg_id_str);
      
      free(json_data);
    }
  } else {
    zmq_printf("[ZMQ] Unknown command: %s\n", cmd);
  }
  
cleanup:
  zmq_msg_close(&msg_cmd);
  zmq_msg_close(&msg_id);
  zmq_msg_close(&msg_data);
}

// Process seed bundle - parse JSON and read seeds from shared memory
static void process_seed_bundle(zmq_mutator_t *data, const char *msg_id, const char *bundle_json) {
  zmq_printf("[ZMQ] Processing SEED bundle: %s\n", msg_id);
  
  // Simple JSON parsing - extract shm_name and seed_ids
  // In production, use cJSON or json-c
  char shm_name[256] = {0};
  int seed_ids[1000];
  int seed_count = 0;
  
  // Extract shm_name (looking for "shm_name": "value")
  const char *shm_ptr = strstr(bundle_json, "\"shm_name\"");
  if (shm_ptr) {
    shm_ptr = strchr(shm_ptr, ':');
    if (shm_ptr) {
      shm_ptr = strchr(shm_ptr, '"');
      if (shm_ptr) {
        shm_ptr++;
        const char *end = strchr(shm_ptr, '"');
        if (end) {
          size_t len = end - shm_ptr;
          if (len < sizeof(shm_name)) {
            strncpy(shm_name, shm_ptr, len);
            shm_name[len] = '\0';
          }
        }
      }
    }
  }
  
  // Extract seed_ids (looking for "seed_ids": [1, 2, 3])
  const char *ids_ptr = strstr(bundle_json, "\"seed_ids\"");
  if (ids_ptr) {
    ids_ptr = strchr(ids_ptr, '[');
    if (ids_ptr) {
      ids_ptr++;
      while (*ids_ptr && seed_count < 1000) {
        while (*ids_ptr == ' ' || *ids_ptr == ',') ids_ptr++;
        if (*ids_ptr == ']') break;
        
        char *endptr;
        int seed_id = strtol(ids_ptr, &endptr, 10);
        if (endptr != ids_ptr) {
          seed_ids[seed_count++] = seed_id;
          ids_ptr = endptr;
        } else {
          break;
        }
      }
    }
  }
  
  if (strlen(shm_name) == 0 || seed_count == 0) {
    zmq_printf("[ZMQ] Invalid bundle: missing shm_name or seed_ids\n");
    return;
  }
  
  zmq_printf("[ZMQ] Bundle has shm_name=%s, %d seeds\n", shm_name, seed_count);
  
  // Get or create shared memory consumer
  shm_consumer_t *consumer = get_or_create_consumer(data, shm_name);
  if (!consumer) {
    zmq_printf("[ZMQ] Failed to get consumer for %s\n", shm_name);
    return;
  }
  
  // Process each seed ID
  for (int i = 0; i < seed_count; i++) {
    u8 *seed_data = NULL;
    size_t seed_size = 0;
    
    if (read_seed_from_shm(consumer, seed_ids[i], &seed_data, &seed_size)) {
      if (seed_size > 0) {
        // Add to circular buffer
        if (add_seed_to_buffer(data, seed_data, seed_size)) {
          data->seed_count++;
          data->zmq_seeds_received++;
        }
        free(seed_data);
      }
    }
  }
  
  // Print progress
  if (data->seed_count - data->last_printed_count >= 1000) {
    zmq_printf("[ZMQ] Processed %u seeds so far\n", data->seed_count);
    data->last_printed_count = data->seed_count;
  }
}

// Get or create a shared memory consumer
static shm_consumer_t *get_or_create_consumer(zmq_mutator_t *data, const char *shm_name) {
  pthread_mutex_lock(&data->shm_mutex);
  
  // Check if we already have this consumer
  shm_consumer_t *consumer = data->shm_consumers;
  while (consumer) {
    if (strcmp(consumer->name, shm_name) == 0) {
      pthread_mutex_unlock(&data->shm_mutex);
      return consumer;
    }
    consumer = consumer->next;
  }
  
  // Create new consumer
  zmq_printf("[ZMQ] Creating new consumer for shared memory: %s\n", shm_name);
  
  consumer = calloc(1, sizeof(shm_consumer_t));
  if (!consumer) {
    pthread_mutex_unlock(&data->shm_mutex);
    return NULL;
  }
  
  strncpy(consumer->name, shm_name, sizeof(consumer->name) - 1);
  consumer->fd = -1;
  consumer->mapped_memory = MAP_FAILED;
  
  // Open shared memory
  char shm_path[512];
  snprintf(shm_path, sizeof(shm_path), "/dev/shm/%s", shm_name);
  
  consumer->fd = open(shm_path, O_RDONLY);
  if (consumer->fd == -1) {
    zmq_printf("[ZMQ] Failed to open shared memory %s: %s\n", shm_path, strerror(errno));
    free(consumer);
    pthread_mutex_unlock(&data->shm_mutex);
    return NULL;
  }
  
  // Get file size
  struct stat sb;
  if (fstat(consumer->fd, &sb) == -1) {
    zmq_printf("[ZMQ] Failed to stat shared memory: %s\n", strerror(errno));
    close(consumer->fd);
    free(consumer);
    pthread_mutex_unlock(&data->shm_mutex);
    return NULL;
  }
  consumer->file_size = sb.st_size;
  
  // Map the shared memory
  consumer->mapped_memory = mmap(NULL, consumer->file_size, PROT_READ, MAP_SHARED, consumer->fd, 0);
  if (consumer->mapped_memory == MAP_FAILED) {
    zmq_printf("[ZMQ] Failed to map shared memory: %s\n", strerror(errno));
    close(consumer->fd);
    free(consumer);
    pthread_mutex_unlock(&data->shm_mutex);
    return NULL;
  }
  
  // Read header (item_size, item_num)
  memcpy(&consumer->item_size, consumer->mapped_memory, sizeof(u32));
  memcpy(&consumer->item_num, (u8 *)consumer->mapped_memory + sizeof(u32), sizeof(u32));
  
  // Verify size consistency
  size_t expected_size = SHM_HEADER_SIZE + (size_t)consumer->item_size * consumer->item_num;
  if (expected_size != consumer->file_size) {
    zmq_printf("[ZMQ] Shared memory size mismatch: expected=%zu, actual=%zu\n", 
               expected_size, consumer->file_size);
    munmap(consumer->mapped_memory, consumer->file_size);
    close(consumer->fd);
    free(consumer);
    pthread_mutex_unlock(&data->shm_mutex);
    return NULL;
  }
  
  zmq_printf("[ZMQ] Shared memory opened: items=%u, item_size=%u\n", 
             consumer->item_num, consumer->item_size);
  
  // Add to list
  consumer->next = data->shm_consumers;
  data->shm_consumers = consumer;
  
  pthread_mutex_unlock(&data->shm_mutex);
  return consumer;
}

// Read a seed from shared memory
static int read_seed_from_shm(shm_consumer_t *consumer, int seed_id, u8 **out_data, size_t *out_size) {
  if (seed_id < 0 || seed_id >= consumer->item_num) {
    return 0;
  }
  
  // Calculate offset
  size_t offset = SHM_HEADER_SIZE + seed_id * consumer->item_size;
  
  // Read data length
  u32 data_len;
  memcpy(&data_len, (u8 *)consumer->mapped_memory + offset, sizeof(u32));
  
  // Validate length
  if (data_len == 0 || data_len > consumer->item_size - SHM_LEN_FIELD_SIZE) {
    return 0;
  }
  
  // Allocate and copy seed data
  *out_data = malloc(data_len);
  if (!*out_data) {
    return 0;
  }
  
  memcpy(*out_data, (u8 *)consumer->mapped_memory + offset + SHM_LEN_FIELD_SIZE, data_len);
  *out_size = data_len;
  
  return 1;
}

// Add seed to circular buffer
static int add_seed_to_buffer(zmq_mutator_t *data, u8 *seed_data, size_t len) {
  if (len > MAX_SEED_SIZE) len = MAX_SEED_SIZE;
  
  pthread_mutex_lock(&data->buffer_mutex);
  
  // Check if we have enough space
  size_t free_space = data->buffer_size - data->data_available;
  if (len + sizeof(size_t) > free_space) {
    pthread_mutex_unlock(&data->buffer_mutex);
    return 0; // Buffer full
  }
  
  // Write seed length first
  size_t remaining = data->buffer_size - data->write_pos;
  if (remaining >= sizeof(size_t)) {
    memcpy(data->seed_buffer + data->write_pos, &len, sizeof(size_t));
    data->write_pos += sizeof(size_t);
  } else {
    // Wrap around
    memcpy(data->seed_buffer + data->write_pos, &len, remaining);
    memcpy(data->seed_buffer, ((u8*)&len) + remaining, sizeof(size_t) - remaining);
    data->write_pos = sizeof(size_t) - remaining;
  }
  
  // Write seed data
  remaining = data->buffer_size - data->write_pos;
  if (remaining >= len) {
    memcpy(data->seed_buffer + data->write_pos, seed_data, len);
    data->write_pos += len;
    if (data->write_pos >= data->buffer_size) data->write_pos = 0;
  } else {
    // Wrap around
    memcpy(data->seed_buffer + data->write_pos, seed_data, remaining);
    memcpy(data->seed_buffer, seed_data + remaining, len - remaining);
    data->write_pos = len - remaining;
  }
  
  data->data_available += sizeof(size_t) + len;
  data->bytes_received += len;
  
  // Signal any waiting threads
  pthread_cond_signal(&data->buffer_cond);
  pthread_mutex_unlock(&data->buffer_mutex);
  
  return 1;
}

// Get seed from circular buffer
static size_t get_seed_from_buffer(zmq_mutator_t *data, u8 *out_buf, size_t max_size) {
  pthread_mutex_lock(&data->buffer_mutex);
  
  if (data->data_available < sizeof(size_t)) {
    pthread_mutex_unlock(&data->buffer_mutex);
    return 0; // No seeds available
  }
  
  // Read seed length
  size_t seed_len;
  size_t remaining = data->buffer_size - data->read_pos;
  if (remaining >= sizeof(size_t)) {
    memcpy(&seed_len, data->seed_buffer + data->read_pos, sizeof(size_t));
    data->read_pos += sizeof(size_t);
  } else {
    // Wrap around
    memcpy(&seed_len, data->seed_buffer + data->read_pos, remaining);
    memcpy(((u8*)&seed_len) + remaining, data->seed_buffer, sizeof(size_t) - remaining);
    data->read_pos = sizeof(size_t) - remaining;
  }
  
  // Sanity check
  if (seed_len > MAX_SEED_SIZE || seed_len > data->data_available - sizeof(size_t)) {
    // Corrupted buffer, reset
    data->read_pos = data->write_pos;
    data->data_available = 0;
    pthread_mutex_unlock(&data->buffer_mutex);
    return 0;
  }
  
  // Limit to max_size
  size_t copy_len = seed_len;
  if (copy_len > max_size) copy_len = max_size;
  
  // Read seed data
  remaining = data->buffer_size - data->read_pos;
  if (remaining >= seed_len) {
    memcpy(out_buf, data->seed_buffer + data->read_pos, copy_len);
    data->read_pos += seed_len;
    if (data->read_pos >= data->buffer_size) data->read_pos = 0;
  } else {
    // Wrap around
    if (copy_len <= remaining) {
      memcpy(out_buf, data->seed_buffer + data->read_pos, copy_len);
    } else {
      memcpy(out_buf, data->seed_buffer + data->read_pos, remaining);
      memcpy(out_buf + remaining, data->seed_buffer, copy_len - remaining);
    }
    data->read_pos = (data->read_pos + seed_len) % data->buffer_size;
  }
  
  data->data_available -= sizeof(size_t) + seed_len;
  
  pthread_mutex_unlock(&data->buffer_mutex);
  
  return copy_len;
}

// Clean up shared memory consumers
static void cleanup_shm_consumers(zmq_mutator_t *data) {
  pthread_mutex_lock(&data->shm_mutex);
  
  shm_consumer_t *consumer = data->shm_consumers;
  while (consumer) {
    shm_consumer_t *next = consumer->next;
    
    if (consumer->mapped_memory != MAP_FAILED) {
      munmap(consumer->mapped_memory, consumer->file_size);
    }
    if (consumer->fd != -1) {
      close(consumer->fd);
    }
    free(consumer);
    
    consumer = next;
  }
  
  data->shm_consumers = NULL;
  pthread_mutex_unlock(&data->shm_mutex);
}

// Deinitialize everything
void afl_custom_deinit(zmq_mutator_t *data) {
  if (!data) return;
  
  zmq_printf("[ZMQ] Shutting down ZMQ consumer mutator\n");
  zmq_printf("[ZMQ] Total mutations: %llu, Seeds: %u, Seeds used: %u, "
             "Bytes: %llu\n",
             data->total_mutations, data->seed_count, data->seeds_used,
             data->bytes_received);
  
  // Stop network thread
  data->should_stop = 1;
  pthread_join(data->network_thread, NULL);
  
  // Clean up shared memory consumers
  cleanup_shm_consumers(data);
  
  // Clean up ZMQ
  if (data->zmq_socket) {
    zmq_close(data->zmq_socket);
  }
  if (data->zmq_context) {
    zmq_ctx_destroy(data->zmq_context);
  }
  
  // Clean up buffers and synchronization
  if (data->seed_buffer) {
    free(data->seed_buffer);
  }
  if (data->fuzz_buf) {
    free(data->fuzz_buf);
  }
  pthread_cond_destroy(&data->buffer_cond);
  pthread_mutex_destroy(&data->buffer_mutex);
  pthread_mutex_destroy(&data->shm_mutex);
  
  free(data);
}

// Optional: Describe the mutator
const char *afl_custom_describe(zmq_mutator_t *data) {
  static char desc[256];
  pthread_mutex_lock(&data->buffer_mutex);
  size_t buffer_pct = (data->data_available * 100) / data->buffer_size;
  pthread_mutex_unlock(&data->buffer_mutex);
  
  snprintf(desc, sizeof(desc), 
           "ZMQ+SHM (buffer: %zu%%, seeds: %u, used: %llu)",
           buffer_pct, data->seed_count, data->seeds_used);
  return desc;
}

