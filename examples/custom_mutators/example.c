/*
  New Custom Mutator for AFL++
  Written by Khaled Yakdan <yakdan@code-intelligence.de>
             Andrea Fioraldi <andreafioraldi@gmail.com>
             Shengtuo Hu <h1994st@gmail.com>
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *commands[] = {

    "GET",
    "PUT",
    "DEL",

};

static size_t data_size = 100;

void afl_custom_init(unsigned int seed) {

  srand(seed);

}

/**
 * Perform custom mutations on a given input
 *
 * (Optional for now. Required in the future)
 *
 * @param[in] buf Pointer to input data to be mutated
 * @param[in] buf_size Size of input data
 * @param[in] add_buf Buffer containing the additional test case
 * @param[in] add_buf_size Size of the additional test case
 * @param[in] max_size Maximum size of the mutated output. The mutation must not
 *     produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_fuzz(uint8_t **buf, size_t buf_size,
                       uint8_t *add_buf,size_t add_buf_size, // add_buf can be NULL
                       size_t max_size) {

  // Make sure that the packet size does not exceed the maximum size expected by
  // the fuzzer
  size_t mutated_size = data_size <= max_size ? data_size : max_size;

  if (mutated_size > buf_size)
    *buf = realloc(*buf, mutated_size);
  
  uint8_t* mutated_out = *buf;

  // Randomly select a command string to add as a header to the packet
  memcpy(mutated_out, commands[rand() % 3], 3);

  // Mutate the payload of the packet
  for (int i = 3; i < mutated_size; i++) {

    mutated_out[i] = (mutated_out[i] + rand() % 10) & 0xff;

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
 * @param[in] buf Buffer containing the test case to be executed
 * @param[in] buf_size Size of the test case
 * @param[out] out_buf Pointer to the buffer containing the test case after
 *     processing. External library should allocate memory for out_buf. AFL++
 *     will release the memory after saving the test case.
 * @return Size of the output buffer after processing
 */
size_t afl_custom_pre_save(uint8_t *buf, size_t buf_size, uint8_t **out_buf) {

  size_t out_buf_size;

  out_buf_size = buf_size;

  // External mutator should allocate memory for `out_buf`
  *out_buf = malloc(out_buf_size);
  memcpy(*out_buf, buf, out_buf_size);

  return out_buf_size;

}

static uint8_t *trim_buf;
static size_t trim_buf_size;
static int trimmming_steps;
static int cur_step;

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
 * @param buf Buffer containing the test case
 * @param buf_size Size of the test case
 * @return The amount of possible iteration steps to trim the input
 */
int afl_custom_init_trim(uint8_t *buf, size_t buf_size) {

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
 * @param[out] out_buf Pointer to the buffer containing the trimmed test case.
 *     External library should allocate memory for out_buf. AFL++ will release
 *     the memory after saving the test case.
 * @param[out] out_buf_size Pointer to the size of the trimmed test case
 */
void afl_custom_trim(uint8_t **out_buf, size_t* out_buf_size) {

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
 * @param success Indicates if the last trim operation was successful.
 * @return The next trim iteration index (from 0 to the maximum amount of
 *     steps returned in init_trim)
 */
int afl_custom_post_trim(int success) {

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
 * @param[inout] buf Pointer to the input data to be mutated and the mutated
 *     output
 * @param[in] buf_size Size of input data
 * @param[in] max_size Maximum size of the mutated output. The mutation must
 *     not produce data larger than max_size.
 * @return Size of the mutated output.
 */
size_t afl_custom_havoc_mutation(uint8_t** buf, size_t buf_size, size_t max_size) {

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
 * @return The probability (0-100).
 */
uint8_t afl_custom_havoc_mutation_probability(void) {

  return 5; // 5 %

}

/**
 * Determine whether the fuzzer should fuzz the queue entry or not.
 *
 * (Optional)
 *
 * @param filename File name of the test case in the queue entry
 * @return Return True(1) if the fuzzer will fuzz the queue entry, and
 *     False(0) otherwise.
 */
uint8_t afl_custom_queue_get(const uint8_t* filename) {

  return 1;

}

/**
 * Allow for additional analysis (e.g. calling a different tool that does a 
 * different kind of coverage and saves this for the custom mutator).
 *
 * (Optional)
 *
 * @param filename_new_queue File name of the new queue entry
 * @param filename_orig_queue File name of the original queue entry
 */
void afl_custom_queue_new_entry(const uint8_t* filename_new_queue,
                                const uint8_t* filename_orig_queue) {

  /* Additional analysis on the original or new test case */

}

