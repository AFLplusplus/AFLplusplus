#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "custom_mutator_helpers.h"
#include "mangle.h"

#define NUMBER_OF_MUTATIONS 5

uint8_t *         queue_input;
size_t            queue_input_size;
afl_state_t *     afl_struct;
run_t             run;
honggfuzz_t       global;
struct _dynfile_t dynfile;

typedef struct my_mutator {

  afl_state_t *afl;
  run_t *      run;
  u8 *         mutator_buf;
  unsigned int seed;
  unsigned int extras_cnt, a_extras_cnt;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutator_buf = malloc(MAX_FILE)) == NULL) {

    free(data);
    perror("mutator_buf alloc");
    return NULL;

  }

  run.dynfile = &dynfile;
  run.global = &global;
  data->afl = afl;
  data->seed = seed;
  data->run = &run;
  afl_struct = afl;

  run.global->mutate.maxInputSz = MAX_FILE;
  run.global->mutate.mutationsPerRun = NUMBER_OF_MUTATIONS;
  run.mutationsPerRun = NUMBER_OF_MUTATIONS;
  run.global->timing.lastCovUpdate = 6;

  // global->feedback.cmpFeedback
  // global->feedback.cmpFeedbackMap

  return data;

}

/* When a new queue entry is added we check if there are new dictionary
   entries to add to honggfuzz structure */

uint8_t afl_custom_queue_new_entry(my_mutator_t * data,
                                   const uint8_t *filename_new_queue,
                                   const uint8_t *filename_orig_queue) {

  if (run.global->mutate.dictionaryCnt >= 1024) return;

  while (data->extras_cnt < data->afl->extras_cnt &&
         run.global->mutate.dictionaryCnt < 1024) {

    memcpy(run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].val,
           data->afl->extras[data->extras_cnt].data,
           data->afl->extras[data->extras_cnt].len);
    run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].len =
        data->afl->extras[data->extras_cnt].len;
    run.global->mutate.dictionaryCnt++;
    data->extras_cnt++;

  }

  while (data->a_extras_cnt < data->afl->a_extras_cnt &&
         run.global->mutate.dictionaryCnt < 1024) {

    memcpy(run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].val,
           data->afl->a_extras[data->a_extras_cnt].data,
           data->afl->a_extras[data->a_extras_cnt].len);
    run.global->mutate.dictionary[run.global->mutate.dictionaryCnt].len =
        data->afl->a_extras[data->a_extras_cnt].len;
    run.global->mutate.dictionaryCnt++;
    data->a_extras_cnt++;

  }

  return 0;

}

/* we could set only_printable if is_ascii is set ... let's see
uint8_t afl_custom_queue_get(void *data, const uint8_t *filename) {

  //run.global->cfg.only_printable = ...

}

*/

/* here we run the honggfuzz mutator, which is really good */

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  /* set everything up, costly ... :( */
  memcpy(data->mutator_buf, buf, buf_size);
  queue_input = data->mutator_buf;
  run.dynfile->data = data->mutator_buf;
  queue_input_size = buf_size;
  run.dynfile->size = buf_size;
  *out_buf = data->mutator_buf;

  /* the mutation */
  mangle_mangleContent(&run, NUMBER_OF_MUTATIONS);

  /* return size of mutated data */
  return run.dynfile->size;

}

/**
 * Deinitialize everything
 *
 * @param data The data ptr from afl_custom_init
 */
void afl_custom_deinit(my_mutator_t *data) {

  free(data->mutator_buf);
  free(data);

}

