/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
             Dominik Maier <mail@dmnk.co>
*/

// You need to use -I /path/to/AFLplusplus/include
#include "custom_mutator_helpers.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DATA_SIZE (100)
#define INITIAL_BUF_SIZE (16384)

static const char *commands[] = {

    "GET",
    "PUT",
    "DEL",

};

typedef struct my_mutator {

  afl_t *afl;
  // any additional data here!
  size_t pre_save_size;
  u8 *   pre_save_buf;

} my_mutator_t;

/**
 * Initialize this custom mutator
 *
 * @param[in] afl a pointer to the internal state object. Can be ignored for
 * now.
 * @param[in] seed A seed for this mutator - the same seed should always mutate
 * in the same way.
 * @return Pointer to the data object this custom mutator instance should use.
 *         There may be multiple instances of this mutator in one afl-fuzz run!
 *         Returns NULL on error.
 */
my_mutator_t *afl_custom_init(afl_t *afl, unsigned int seed) {

  srand(seed);  // needed also by surgical_havoc_mutate()

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  data->afl = afl;

  data->pre_save_buf = malloc(INITIAL_BUF_SIZE);
  if (!data->pre_save_buf) {

    free(data);
    return NULL;

  }

  data->pre_save_size = INITIAL_BUF_SIZE;

  return data;

}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_fuzz(my_mutator_t *data, uint8_t **buf, size_t buf_size,
                       uint8_t *add_buf,
                       size_t   add_buf_size,  // add_buf can be NULL
                       size_t   max_size) {

  // Make sure that the packet size does not exceed the maximum size expected by
  // the fuzzer
  size_t mutated_size = DATA_SIZE <= max_size ? DATA_SIZE : max_size;

  if (mutated_size > buf_size) *buf = realloc(*buf, mutated_size);

  uint8_t *mutated_out = *buf;

  // Randomly select a command string to add as a header to the packet
  memcpy(mutated_out, commands[rand() % 3], 3);

  // Mutate the payload of the packet
  int i;
  for (i = 0; i < 8; ++i) {

    // Randomly perform one of the (no len modification) havoc mutations
    surgical_havoc_mutate(mutated_out, 3, mutated_size);

  }

  return mutated_size;

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
 *     A return smaller 1 indicates an error.
 */
size_t afl_custom_pre_save(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                           uint8_t **out_buf) {

  if (data->pre_save_size < buf_size + 5) {

    data->pre_save_buf = realloc(data->pre_save_buf, buf_size + 5);
    if (!data->pre_save_buf) {

      perror("custom mutator realloc");
      free(data);
      return -1;

    }

    data->pre_save_size = buf_size + 5;

  }
  *out_buf = data->pre_save_buf;

  memcpy(*out_buf + 5, buf, buf_size);
  size_t out_buf_size = buf_size + 5;
  *out_buf[0] = 'A';
  *out_buf[1] = 'F';
  *out_buf[2] = 'L';
  *out_buf[3] = '+';
  *out_buf[4] = '+';

  return out_buf_size;

}

static uint8_t *trim_buf;
static size_t   trim_buf_size;
static int      trimmming_steps;
static int      cur_step;

/**
 * This method is called at the start of each trimming operation and receives
 * the initial buffer. It should return the amount of iteration steps possible
 * on this input (e.g. if your input has n elements and you want to remove
 * them one by one, return n, if you do a binary search, return log(n),
 * and so on...).
 *
 * If your trimming algorithm doesn't allow you to determine the amount of
 * (remaining) steps easily (esp. while running), then you can alternatively
 * return 1 here and always return 0 in post_trim until you are finished and
 * no steps remain. In that case, returning 1 in post_trim will end the
 * trimming routine. The whole current index/max iterations stuff is only used
 * to show progress.
 *
 * (Optional)
 *
 * @param data pointer returned in afl_custom_init for this fuzz case
 * @param buf Buffer containing the test case
 * @param buf_size Size of the test case
 * @return The amount of possible iteration steps to trim the input
 */
int afl_custom_init_trim(my_mutator_t *data, uint8_t *buf, size_t buf_size) {

  // We simply trim once
  trimmming_steps = 1;

  cur_step = 0;
  trim_buf = buf;
  trim_buf_size = buf_size;

  return trimmming_steps;

}

/**
 * This method is called for each trimming operation. It doesn't have any
 * arguments because we already have the initial buffer from init_trim and we
 * can memorize the current state in global variables. This can also save
 * reparsing steps for each iteration. It should return the trimmed input
 * buffer, where the returned data must not exceed the initial input data in
 * length. Returning anything that is larger than the original data (passed
 * to init_trim) will result in a fatal abort of AFLFuzz.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[out] out_buf Pointer to the buffer containing the trimmed test case.
 *     External library should allocate memory for out_buf. AFL++ will release
 *     the memory after saving the test case.
 * @param[out] out_buf_size Pointer to the size of the trimmed test case
 */
void afl_custom_trim(my_mutator_t *data, uint8_t **out_buf,
                     size_t *out_buf_size) {

  *out_buf_size = trim_buf_size - 1;

  // External mutator should allocate memory for `out_buf`
  *out_buf = malloc(*out_buf_size);
  // Remove the last byte of the trimming input
  memcpy(*out_buf, trim_buf, *out_buf_size);

}

/**
 * This method is called after each trim operation to inform you if your
 * trimming step was successful or not (in terms of coverage). If you receive
 * a failure here, you should reset your input to the last known good state.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param success Indicates if the last trim operation was successful.
 * @return The next trim iteration index (from 0 to the maximum amount of
 *     steps returned in init_trim)
 */
int afl_custom_post_trim(my_mutator_t *data, int success) {

  if (success) {

    ++cur_step;
    return cur_step;

  }

  return trimmming_steps;

}

/**
 * Perform a single custom mutation on a given input.
 * This mutation is stacked with the other muatations in havoc.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param[inout] buf Pointer to the input data to be mutated and the mutated
 *     output
 * @param[in] buf_size Size of input data
 * @param[in] max_size Maximum size of the mutated output. The mutation must
 *     not produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_havoc_mutation(my_mutator_t *data, uint8_t **buf,
                                 size_t buf_size, size_t max_size) {

  if (buf_size == 0) {

    *buf = realloc(*buf, 1);
    **buf = rand() % 256;
    buf_size = 1;

  }

  size_t victim = rand() % buf_size;
  (*buf)[victim] += rand() % 10;

  return buf_size;

}

/**
 * Return the probability (in percentage) that afl_custom_havoc_mutation
 * is called in havoc. By default it is 6 %.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @return The probability (0-100).
 */
uint8_t afl_custom_havoc_mutation_probability(my_mutator_t *data) {

  return 5;  // 5 %

}

/**
 * Determine whether the fuzzer should fuzz the queue entry or not.
 *
 * (Optional)
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param filename File name of the test case in the queue entry
 * @return Return True(1) if the fuzzer will fuzz the queue entry, and
 *     False(0) otherwise.
 */
uint8_t afl_custom_queue_get(my_mutator_t *data, const uint8_t *filename) {

  return 1;

}

/**
 * Allow for additional analysis (e.g. calling a different tool that does a
 * different kind of coverage and saves this for the custom mutator).
 *
 * (Optional)
 *
 * @param data pointer returned in afl_custom_init for this fuzz case
 * @param filename_new_queue File name of the new queue entry
 * @param filename_orig_queue File name of the original queue entry
 */
void afl_custom_queue_new_entry(my_mutator_t * data,
                                const uint8_t *filename_new_queue,
                                const uint8_t *filename_orig_queue) {

  /* Additional analysis on the original or new test case */

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->pre_save_buf);
  free(data);

}

