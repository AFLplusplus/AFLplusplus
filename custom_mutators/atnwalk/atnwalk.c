#include "afl-fuzz.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define BUF_SIZE_INIT 4096
#define SOCKET_NAME "./atnwalk.socket"

// how many errors (e.g. timeouts) to tolerate until moving on to the next queue
// entry
#define ATNWALK_ERRORS_MAX 1

// how many execution timeouts to tolerate until moving on to the next queue
// entry
#define EXEC_TIMEOUT_MAX 2

// handshake constants
const uint8_t SERVER_ARE_YOU_ALIVE = 213;
const uint8_t SERVER_YES_I_AM_ALIVE = 42;

// control bits
const uint8_t SERVER_CROSSOVER_BIT = 0b00000001;
const uint8_t SERVER_MUTATE_BIT = 0b00000010;
const uint8_t SERVER_DECODE_BIT = 0b00000100;
const uint8_t SERVER_ENCODE_BIT = 0b00001000;

typedef struct atnwalk_mutator {

  afl_state_t *afl;
  uint8_t      atnwalk_error_count;
  uint64_t     prev_timeouts;
  uint32_t     prev_hits;
  uint32_t     stage_havoc_cur;
  uint32_t     stage_havoc_max;
  uint32_t     stage_splice_cur;
  uint32_t     stage_splice_max;
  uint8_t     *fuzz_buf;
  size_t       fuzz_size;
  uint8_t     *post_process_buf;
  size_t       post_process_size;

} atnwalk_mutator_t;

int read_all(int fd, uint8_t *buf, size_t buf_size) {

  int    n;
  size_t offset = 0;
  while (offset < buf_size) {

    n = read(fd, buf + offset, buf_size - offset);
    if (n == -1) { return 0; }
    offset += n;

  }

  return 1;

}

int write_all(int fd, uint8_t *buf, size_t buf_size) {

  int    n;
  size_t offset = 0;
  while (offset < buf_size) {

    n = write(fd, buf + offset, buf_size - offset);
    if (n == -1) { return 0; }
    offset += n;

  }

  return 1;

}

void put_uint32(uint8_t *buf, uint32_t val) {

  buf[0] = (uint8_t)(val >> 24);
  buf[1] = (uint8_t)((val & 0x00ff0000) >> 16);
  buf[2] = (uint8_t)((val & 0x0000ff00) >> 8);
  buf[3] = (uint8_t)(val & 0x000000ff);

}

uint32_t to_uint32(uint8_t *buf) {

  uint32_t val = 0;
  val |= (((uint32_t)buf[0]) << 24);
  val |= (((uint32_t)buf[1]) << 16);
  val |= (((uint32_t)buf[2]) << 8);
  val |= ((uint32_t)buf[3]);
  return val;

}

void put_uint64(uint8_t *buf, uint64_t val) {

  buf[0] = (uint8_t)(val >> 56);
  buf[1] = (uint8_t)((val & 0x00ff000000000000) >> 48);
  buf[2] = (uint8_t)((val & 0x0000ff0000000000) >> 40);
  buf[3] = (uint8_t)((val & 0x000000ff00000000) >> 32);
  buf[4] = (uint8_t)((val & 0x00000000ff000000) >> 24);
  buf[5] = (uint8_t)((val & 0x0000000000ff0000) >> 16);
  buf[6] = (uint8_t)((val & 0x000000000000ff00) >> 8);
  buf[7] = (uint8_t)(val & 0x00000000000000ff);

}

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Return NULL on error.
 */
atnwalk_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  srand(seed);
  atnwalk_mutator_t *data =
      (atnwalk_mutator_t *)malloc(sizeof(atnwalk_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  data->afl = afl;
  data->prev_hits = 0;
  data->fuzz_buf = (uint8_t *)malloc(BUF_SIZE_INIT);
  data->fuzz_size = BUF_SIZE_INIT;
  data->post_process_buf = (uint8_t *)malloc(BUF_SIZE_INIT);
  data->post_process_size = BUF_SIZE_INIT;
  return data;

}

unsigned int afl_custom_fuzz_count(atnwalk_mutator_t   *data,
                                   const unsigned char *buf, size_t buf_size) {

  // afl_custom_fuzz_count is called exactly once before entering the
  // 'stage-loop' for the current queue entry thus, we use it to reset the error
  // count and to initialize stage variables (somewhat not intended by the API,
  // but still better than rewriting the whole thing to have a custom mutator
  // stage)
  data->atnwalk_error_count = 0;
  data->prev_timeouts = data->afl->total_tmouts;

  // it might happen that on the last execution of the splice stage a new path
  // is found we need to fix that here and count it
  if (data->prev_hits) {

    data->afl->stage_finds[STAGE_SPLICE] +=
        data->afl->queued_items + data->afl->saved_crashes - data->prev_hits;

  }

  data->prev_hits = data->afl->queued_items + data->afl->saved_crashes;
  data->stage_havoc_cur = 0;
  data->stage_splice_cur = 0;

  // 50% havoc, 50% splice
  data->stage_havoc_max = data->afl->stage_max >> 1;
  if (data->stage_havoc_max < HAVOC_MIN) { data->stage_havoc_max = HAVOC_MIN; }
  data->stage_splice_max = data->stage_havoc_max;
  return data->stage_havoc_max + data->stage_splice_max;

}

size_t fail_fatal(int fd_socket, uint8_t **out_buf) {

  if (fd_socket != -1) { close(fd_socket); }
  *out_buf = NULL;
  fprintf(stderr, "atnwalk.socket not found in current directory!\n");
  exit(-1);

}

size_t fail_gracefully(int fd_socket, atnwalk_mutator_t *data, uint8_t *buf,
                       size_t buf_size, uint8_t **out_buf) {

  if (fd_socket != -1) { close(fd_socket); }
  data->atnwalk_error_count++;
  if (data->atnwalk_error_count > ATNWALK_ERRORS_MAX) {

    data->afl->stage_max = data->afl->stage_cur;

  }

  *out_buf = buf;
  return buf_size;

}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[out] out_buf the buffer we will work on. we can reuse *buf. NULL on
 * error.
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_fuzz(atnwalk_mutator_t *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  struct sockaddr_un addr;
  int                fd_socket;
  uint8_t            ctrl_buf[8];
  uint8_t            wanted;

  // let's display what's going on in a nice way
  if (data->stage_havoc_cur == 0) {

    data->afl->stage_name = (uint8_t *)"atnwalk - havoc";

  }

  if (data->stage_havoc_cur == data->stage_havoc_max) {

    data->afl->stage_name = (uint8_t *)"atnwalk - splice";

  }

  // increase the respective havoc or splice counters
  if (data->stage_havoc_cur < data->stage_havoc_max) {

    data->stage_havoc_cur++;
    data->afl->stage_cycles[STAGE_HAVOC]++;

  } else {

    // if there is nothing to splice, continue with havoc and skip splicing this
    // time
    if (data->afl->ready_for_splicing_count < 1) {

      data->stage_havoc_max = data->afl->stage_max;
      data->stage_havoc_cur++;
      data->afl->stage_cycles[STAGE_HAVOC]++;

    } else {

      data->stage_splice_cur++;
      data->afl->stage_cycles[STAGE_SPLICE]++;

    }

  }

  // keep track of found new corpus seeds per stage
  if (data->afl->queued_items + data->afl->saved_crashes > data->prev_hits) {

    if (data->stage_splice_cur <= 1) {

      data->afl->stage_finds[STAGE_HAVOC] +=
          data->afl->queued_items + data->afl->saved_crashes - data->prev_hits;

    } else {

      data->afl->stage_finds[STAGE_SPLICE] +=
          data->afl->queued_items + data->afl->saved_crashes - data->prev_hits;

    }

  }

  data->prev_hits = data->afl->queued_items + data->afl->saved_crashes;

  // check whether this input produces a lot of timeouts, if it does then
  // abandon this queue entry
  if (data->afl->total_tmouts - data->prev_timeouts >= EXEC_TIMEOUT_MAX) {

    data->afl->stage_max = data->afl->stage_cur;
    return fail_gracefully(-1, data, buf, buf_size, out_buf);

  }

  // initialize the socket
  fd_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd_socket == -1) { return fail_fatal(fd_socket, out_buf); }
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
  if (connect(fd_socket, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {

    return fail_fatal(fd_socket, out_buf);

  }

  // ask whether the server is alive
  ctrl_buf[0] = SERVER_ARE_YOU_ALIVE;
  if (!write_all(fd_socket, ctrl_buf, 1)) {

    return fail_fatal(fd_socket, out_buf);

  }

  // see whether the server replies as expected
  if (!read_all(fd_socket, ctrl_buf, 1) ||
      ctrl_buf[0] != SERVER_YES_I_AM_ALIVE) {

    return fail_fatal(fd_socket, out_buf);

  }

  // tell the server what we want to do
  wanted = SERVER_MUTATE_BIT | SERVER_ENCODE_BIT;

  // perform a crossover if we are splicing
  if (data->stage_splice_cur > 0) { wanted |= SERVER_CROSSOVER_BIT; }

  // tell the server what we want and how much data will be sent
  ctrl_buf[0] = wanted;
  put_uint32(ctrl_buf + 1, (uint32_t)buf_size);
  if (!write_all(fd_socket, ctrl_buf, 5)) {

    return fail_fatal(fd_socket, out_buf);

  }

  // send the data to mutate and encode
  if (!write_all(fd_socket, buf, buf_size)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  if (wanted & SERVER_CROSSOVER_BIT) {

    // since we requested crossover, we will first tell how much additional data
    // is to be expected
    put_uint32(ctrl_buf, (uint32_t)add_buf_size);
    if (!write_all(fd_socket, ctrl_buf, 4)) {

      return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

    }

    // send the additional data for crossover
    if (!write_all(fd_socket, add_buf, add_buf_size)) {

      return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

    }

    // lastly, a seed is required for crossover so send one
    put_uint64(ctrl_buf, (uint64_t)rand());
    if (!write_all(fd_socket, ctrl_buf, 8)) {

      return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

    }

  }

  // since we requested mutation, we need to provide a seed for that
  put_uint64(ctrl_buf, (uint64_t)rand());
  if (!write_all(fd_socket, ctrl_buf, 8)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  // obtain the required buffer size for the data that will be returned
  if (!read_all(fd_socket, ctrl_buf, 4)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  size_t new_size = (size_t)to_uint32(ctrl_buf);

  // if the data is too large then we ignore this round
  if (new_size > max_size) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  if (new_size > buf_size) {

    // buf is too small, need to use data->fuzz_buf, let's see whether we need
    // to reallocate
    if (new_size > data->fuzz_size) {

      data->fuzz_size = new_size << 1;
      data->fuzz_buf = (uint8_t *)realloc(data->fuzz_buf, data->fuzz_size);

    }

    *out_buf = data->fuzz_buf;

  } else {

    // new_size fits into buf, so re-use it
    *out_buf = buf;

  }

  // obtain the encoded data
  if (!read_all(fd_socket, *out_buf, new_size)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  close(fd_socket);
  return new_size;

}

/**
 * A post-processing function to use right before AFL writes the test case to
 * disk in order to execute the target.
 *
 * (Optional) If this functionality is not needed, simply don't define this
 * function.
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Buffer containing the test case to be executed
 * @param[in] buf_size Size of the test case
 * @param[out] out_buf Pointer to the buffer containing the test case after
 *     processing. External library should allocate memory for out_buf.
 *     The buf pointer may be reused (up to the given buf_size);
 * @return Size of the output buffer after processing or the needed amount.
 *     A return of 0 indicates an error.
 */
size_t afl_custom_post_process(atnwalk_mutator_t *data, uint8_t *buf,
                               size_t buf_size, uint8_t **out_buf) {

  struct sockaddr_un addr;
  int                fd_socket;
  uint8_t            ctrl_buf[8];

  // initialize the socket
  fd_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd_socket == -1) { return fail_fatal(fd_socket, out_buf); }
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, SOCKET_NAME, sizeof(addr.sun_path) - 1);
  if (connect(fd_socket, (const struct sockaddr *)&addr, sizeof(addr)) == -1) {

    return fail_fatal(fd_socket, out_buf);

  }

  // ask whether the server is alive
  ctrl_buf[0] = SERVER_ARE_YOU_ALIVE;
  if (!write_all(fd_socket, ctrl_buf, 1)) {

    return fail_fatal(fd_socket, out_buf);

  }

  // see whether the server replies as expected
  if (!read_all(fd_socket, ctrl_buf, 1) ||
      ctrl_buf[0] != SERVER_YES_I_AM_ALIVE) {

    return fail_fatal(fd_socket, out_buf);

  }

  // tell the server what we want and how much data will be sent
  ctrl_buf[0] = SERVER_DECODE_BIT;
  put_uint32(ctrl_buf + 1, (uint32_t)buf_size);
  if (!write_all(fd_socket, ctrl_buf, 5)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  // send the data to decode
  if (!write_all(fd_socket, buf, buf_size)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  // obtain the required buffer size for the data that will be returned
  if (!read_all(fd_socket, ctrl_buf, 4)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  size_t new_size = (size_t)to_uint32(ctrl_buf);

  // need to use data->post_process_buf, let's see whether we need to reallocate
  if (new_size > data->post_process_size) {

    data->post_process_size = new_size << 1;
    data->post_process_buf =
        (uint8_t *)realloc(data->post_process_buf, data->post_process_size);

  }

  *out_buf = data->post_process_buf;

  // obtain the decoded data
  if (!read_all(fd_socket, *out_buf, new_size)) {

    return fail_gracefully(fd_socket, data, buf, buf_size, out_buf);

  }

  close(fd_socket);
  return new_size;

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(atnwalk_mutator_t *data) {

  free(data->fuzz_buf);
  free(data->post_process_buf);
  free(data);

}

