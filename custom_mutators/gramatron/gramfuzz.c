// This simple example just creates random buffer <= 100 filled with 'A'
// needs -I /path/to/AFLplusplus/include
//#include "custom_mutator_helpers.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "afl-fuzz.h"
#include "gramfuzz.h"

#define MUTATORS 4  // Specify the total number of mutators

typedef struct my_mutator {

  afl_state_t *afl;

  u8 *   mutator_buf;
  u8 *   unparsed_input;
  Array *mutated_walk;
  Array *orig_walk;

  IdxMap_new *statemap;  // Keeps track of the statemap
  UT_array ** recurIdx;
  // Get_Dupes_Ret* getdupesret; // Recursive feature map
  int recurlen;

  int mut_alloced;
  int orig_alloced;
  int mut_idx;  // Signals the current mutator being used, used to cycle through
                // each mutator

  unsigned int seed;

} my_mutator_t;

state *create_pda(u8 *automaton_file) {

  struct json_object *parsed_json;
  state *             pda;
  json_object *       source_obj, *attr;
  int                 arraylen, ii, ii2, trigger_len, error;

  printf("\n[GF] Automaton file passed:%s", automaton_file);
  // parsed_json =
  // json_object_from_file("./gramfuzz/php_gnf_processed_full.json");
  parsed_json = json_object_from_file(automaton_file);

  // Getting final state
  source_obj = json_object_object_get(parsed_json, "final_state");
  printf("\t\nFinal=%s\n", json_object_get_string(source_obj));
  final_state = atoi(json_object_get_string(source_obj));

  // Getting initial state
  source_obj = json_object_object_get(parsed_json, "init_state");
  init_state = atoi(json_object_get_string(source_obj));
  printf("\tInit=%s\n", json_object_get_string(source_obj));

  // Getting number of states
  source_obj = json_object_object_get(parsed_json, "numstates");
  numstates = atoi(json_object_get_string(source_obj)) + 1;
  printf("\tNumStates=%d\n", numstates);

  // Allocate state space for each pda state
  pda = (state *)calloc(atoi(json_object_get_string(source_obj)) + 1,
                        sizeof(state));

  // Getting PDA representation
  source_obj = json_object_object_get(parsed_json, "pda");
  enum json_type type;
  json_object_object_foreach(source_obj, key, val) {

    state *  state_ptr;
    trigger *trigger_ptr;
    int      offset;

    // Get the correct offset into the pda to store state information
    state_ptr = pda;
    offset = atoi(key);
    state_ptr += offset;
    // Store state string
    state_ptr->state_name = offset;

    // Create trigger array of structs
    trigger_len = json_object_array_length(val);
    state_ptr->trigger_len = trigger_len;
    trigger_ptr = (trigger *)calloc(trigger_len, sizeof(trigger));
    state_ptr->ptr = trigger_ptr;

    for (ii = 0; ii < trigger_len; ii++) {

      json_object *obj = json_object_array_get_idx(val, ii);
      // Get all the trigger trigger attributes
      attr = json_object_array_get_idx(obj, 0);
      (trigger_ptr)->id = strdup(json_object_get_string(attr));

      attr = json_object_array_get_idx(obj, 1);
      trigger_ptr->dest = atoi(json_object_get_string(attr));

      attr = json_object_array_get_idx(obj, 2);
      if (!strcmp("\\n", json_object_get_string(attr))) {

        trigger_ptr->term = strdup("\n");

      } else {

        trigger_ptr->term = strdup(json_object_get_string(attr));

      }

      trigger_ptr->term_len = strlen(trigger_ptr->term);
      trigger_ptr++;

    }

  }

  // Delete the JSON object
  json_object_put(parsed_json);

  return pda;

}

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if ((data->mutator_buf = malloc(MAX_FILE)) == NULL) {

    perror("mutator_buf alloc");
    return NULL;

  }

  data->afl = afl;
  global_afl = afl;  // dirty
  data->seed = seed;

  data->mut_alloced = 0;
  data->orig_alloced = 0;
  data->mut_idx = 0;
  data->recurlen = 0;

  // data->mutator_buf = NULL;
  // data->unparsed_input = NULL;
  // data->mutated_walk = NULL;
  // data->orig_walk = NULL;
  //
  // data->statemap = NULL;  // Keeps track of the statemap
  // data->recur_idx = NULL; // Will keep track of recursive feature indices
  // u32 recur_len = 0;       // The number of recursive features
  // data->mutator_buf = NULL;

  char *automaton_file = getenv("GRAMATRON_AUTOMATION");
  if (automaton_file) {

    pda = create_pda(automaton_file);

  } else {

    fprintf(stderr,
            "\nError: GrammaTron needs an automation json file set in "
            "GRAMATRON_AUTOMATION\n");
    exit(-1);

  }

  return data;

}

size_t afl_custom_fuzz(my_mutator_t *data, uint8_t *buf, size_t buf_size,
                       u8 **out_buf, uint8_t *add_buf, size_t add_buf_size,
                       size_t max_size) {

  u8 *unparsed_input;

  // Pick a mutator
  // int choice = rand() % MUTATORS;
  // data->mut_idx = 1;
  // GC old mutant
  if (data->mut_alloced) {

    free(data->mutated_walk->start);
    free(data->mutated_walk);
    data->mut_alloced = 0;

  };

  // printf("\nChoice:%d", choice);

  if (data->mut_idx == 0) {  // Perform random mutation
    data->mutated_walk = performRandomMutation(pda, data->orig_walk);
    data->mut_alloced = 1;

  } else if (data->mut_idx == 1 &&

             data->recurlen) {  // Perform recursive mutation
    data->mutated_walk =
        doMult(data->orig_walk, data->recurIdx, data->recurlen);
    data->mut_alloced = 1;

  } else if (data->mut_idx == 2) {  // Perform splice mutation

    // we cannot use the supplied splice data so choose a new random file
    u32                 tid = rand_below(global_afl, data->afl->queued_paths);
    struct queue_entry *q = data->afl->queue_buf[tid];

    // Read the input representation for the splice candidate
    u8 *   automaton_fn = alloc_printf("%s.aut", q->fname);
    Array *spliceCandidate = read_input(pda, automaton_fn);

    if (spliceCandidate) {

      data->mutated_walk =
          performSpliceOne(data->orig_walk, data->statemap, spliceCandidate);
      data->mut_alloced = 1;
      free(spliceCandidate->start);
      free(spliceCandidate);

    } else {

      data->mutated_walk = gen_input(pda, NULL);
      data->mut_alloced = 1;

    }

    ck_free(automaton_fn);

  } else {  // Generate an input from scratch

    data->mutated_walk = gen_input(pda, NULL);
    data->mut_alloced = 1;

  }

  // Cycle to the next mutator
  if (data->mut_idx == MUTATORS - 1)
    data->mut_idx =
        0;  // Wrap around if we have reached end of the mutator list
  else
    data->mut_idx += 1;

  // Unparse the mutated automaton walk
  if (data->unparsed_input) { free(data->unparsed_input); }
  data->unparsed_input = unparse_walk(data->mutated_walk);
  *out_buf = data->unparsed_input;

  return data->mutated_walk->inputlen;

}

/**
 * Create the automaton-based representation for the corresponding input
 *
 * @param data pointer returned in afl_custom_init for this fuzz case
 * @param filename_new_queue File name of the new queue entry
 * @param filename_orig_queue File name of the original queue entry
 */
u8 afl_custom_queue_new_entry(my_mutator_t * data,
                              const uint8_t *filename_new_queue,
                              const uint8_t *filename_orig_queue) {

  // get the filename
  u8 *   automaton_fn, *unparsed_input;
  Array *new_input;
  s32    fd;

  automaton_fn = alloc_printf("%s.aut", filename_new_queue);
  // Check if this method is being called during initialization

  // fprintf(stderr, "new: %s, old: %s, auto: %s\n",
  // filename_new_queue,filename_orig_queue,automaton_fn);

  if (filename_orig_queue) {

    write_input(data->mutated_walk, automaton_fn);

  } else {

    new_input = gen_input(pda, NULL);
    write_input(new_input, automaton_fn);

    // Update the placeholder file
    if (unlink(filename_new_queue)) {

      PFATAL("Unable to delete '%s'", filename_new_queue);

    }

    unparsed_input = unparse_walk(new_input);
    fd = open(filename_new_queue, O_WRONLY | O_CREAT | O_TRUNC,
              S_IRUSR | S_IWUSR);
    if (fd < 0) { PFATAL("Failed to update file '%s'", filename_new_queue); }
    int written = write(fd, unparsed_input, new_input->inputlen + 1);
    close(fd);

    free(new_input->start);
    free(new_input);
    free(unparsed_input);

  }

  ck_free(automaton_fn);

  return 1;

}

/**
 * Get the corresponding tree representation for the candidate that is to be
 * mutated
 *
 * @param[in] data pointer returned in afl_custom_init for this fuzz case
 * @param filename File name of the test case in the queue entry
 * @return Return True(1) if the fuzzer will fuzz the queue entry, and
 *     False(0) otherwise.
 */
uint8_t afl_custom_queue_get(my_mutator_t *data, const uint8_t *filename) {

  // get the filename
  u8 *        automaton_fn = alloc_printf("%s.aut", filename);
  IdxMap_new *statemap_ptr;
  terminal *  term_ptr;
  int         state;

  // TODO: I don't think we need to update pointers when reading back
  // Probably build two different versions of read_input one for flushing
  // inputs to disk and the other that
  if (data->orig_alloced) {

    free(data->orig_walk->start);
    free(data->orig_walk);
    data->orig_alloced = 0;

  }

  if (data->statemap) {

    for (int x = 0; x < numstates; x++) {

      utarray_free(data->statemap[x].nums);

    }

    free(data->statemap);

  }

  if (data->recurIdx) {

    data->recurlen = 0;
    free(data->recurIdx);

  }

  data->orig_walk = read_input(pda, automaton_fn);
  data->orig_alloced = 1;

  // Create statemap for the fuzz candidate
  IdxMap_new *statemap_start =
      (IdxMap_new *)malloc(sizeof(IdxMap_new) * numstates);
  for (int x = 0; x < numstates; x++) {

    statemap_ptr = &statemap_start[x];
    utarray_new(statemap_ptr->nums, &ut_int_icd);

  }

  int offset = 0;
  while (offset < data->orig_walk->used) {

    term_ptr = &data->orig_walk->start[offset];
    state = term_ptr->state;
    statemap_ptr = &statemap_start[state];
    utarray_push_back(statemap_ptr->nums, &offset);
    offset += 1;

  }

  data->statemap = statemap_start;

  // Create recursive feature map (if it exists)
  data->recurIdx = malloc(sizeof(UT_array *) * numstates);
  // Retrieve the duplicated states
  offset = 0;
  while (offset < numstates) {

    statemap_ptr = &data->statemap[offset];
    int length = utarray_len(statemap_ptr->nums);
    if (length >= 2) {

      data->recurIdx[data->recurlen] = statemap_ptr->nums;
      data->recurlen += 1;

    }

    offset += 1;

  }

  // data->getdupesret = get_dupes(data->orig_walk, &data->recurlen);

  ck_free(automaton_fn);
  return 1;

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

