#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "afl-fuzz.h"
#include "gramfuzz.h"

/*Slices from beginning till idx*/
Array *slice(Array *input, int idx) {

  // printf("\nSlice idx:%d", idx);
  terminal *origptr;
  terminal *term_ptr;
  Array *   sliced = (Array *)malloc(sizeof(Array));
  initArray(sliced, input->size);
  // Populate dynamic array members
  if (idx == 0) { return sliced; }
  for (int x = 0; x < idx; x++) {

    origptr = &input->start[x];
    insertArray(sliced, origptr->state, origptr->symbol, origptr->symbol_len,
                origptr->trigger_idx);

  }

  return sliced;

}

/* Slices from idx till end*/
Array *slice_inverse(Array *input, int idx) {

  // printf("\nSlice idx:%d", idx);
  terminal *origptr;
  terminal *term_ptr;
  Array *   sliced = (Array *)malloc(sizeof(Array));
  initArray(sliced, input->size);
  for (int x = idx; x < input->used; x++) {

    origptr = &input->start[x];
    insertArray(sliced, origptr->state, origptr->symbol, origptr->symbol_len,
                origptr->trigger_idx);

  }

  return sliced;

}

/*Carves with `start` included and `end` excluded*/
Array *carve(Array *input, int start, int end) {

  terminal *origptr;
  terminal *term_ptr;
  Array *   sliced = (Array *)malloc(sizeof(Array));
  initArray(sliced, input->size);
  for (int x = start; x < end; x++) {

    origptr = &input->start[x];
    insertArray(sliced, origptr->state, origptr->symbol, origptr->symbol_len,
                origptr->trigger_idx);

  }

  return sliced;

}

/*Concats prefix + feature *mult*/
void concatPrefixFeature(Array *prefix, Array *feature) {

  // XXX: Currently we have hardcoded the multiplication threshold for adding
  // the recursive feature. Might want to fix it to choose a random number upper
  // bounded by a static value instead.
  terminal *featureptr;
  int       len = rand_below(global_afl, RECUR_THRESHOLD);
  for (int x = 0; x < len; x++) {

    for (int y = 0; y < feature->used; y++) {

      featureptr = &feature->start[y];
      insertArray(prefix, featureptr->state, featureptr->symbol,
                  featureptr->symbol_len, featureptr->trigger_idx);

    }

  }

}

void concatPrefixFeatureBench(Array *prefix, Array *feature) {

  // XXX: Currently we have hardcoded the multiplication threshold for adding
  // the recursive feature. Might want to fix it to choose a random number upper
  // bounded by a static value instead.
  terminal *featureptr;
  int       len =
      5;  // 5 is the number of times we compare performing random recursion.
  for (int x = 0; x < len; x++) {

    for (int y = 0; y < feature->used; y++) {

      featureptr = &feature->start[y];
      insertArray(prefix, featureptr->state, featureptr->symbol,
                  featureptr->symbol_len, featureptr->trigger_idx);

    }

  }

}

Array *spliceGF(Array *orig, Array *toSplice, int idx) {

  terminal *toSplicePtr;
  terminal *tempPtr;
  // Iterate through the splice candidate from the `idx` till end
  for (int x = idx; x < toSplice->used; x++) {

    toSplicePtr = &toSplice->start[x];
    insertArray(orig, toSplicePtr->state, toSplicePtr->symbol,
                toSplicePtr->symbol_len, toSplicePtr->trigger_idx);

  }

  return orig;

}

Array *gen_input(state *pda, Array *input) {

  state *   state_ptr;
  trigger * trigger_ptr;
  terminal *term_ptr;
  int       offset = 0;
  int       randval, error;
  // Generating an input for the first time
  if (input == NULL) {

    input = (Array *)calloc(1, sizeof(Array));
    initArray(input, INIT_SIZE);
    curr_state = init_state;

  }

  while (curr_state != final_state) {

    // Retrieving the state from the pda
    state_ptr = pda + curr_state;

    // Get a random trigger
    randval = rand_below(global_afl, state_ptr->trigger_len);
    trigger_ptr = (state_ptr->ptr) + randval;

    // Insert into the dynamic array
    insertArray(input, curr_state, trigger_ptr->term, trigger_ptr->term_len,
                randval);
    curr_state = trigger_ptr->dest;
    offset += 1;

  }

  return input;

}

Array *gen_input_count(state *pda, Array *input, int *mut_count) {

  state *   state_ptr;
  trigger * trigger_ptr;
  terminal *term_ptr;
  int       offset = 0;
  int       randval, error;
  // Generating an input for the first time
  if (input == NULL) {

    input = (Array *)calloc(1, sizeof(Array));
    initArray(input, INIT_SIZE);
    curr_state = init_state;

  }

  while (curr_state != final_state) {

    *mut_count += 1;
    // Retrieving the state from the pda
    state_ptr = pda + curr_state;

    // Get a random trigger
    randval = rand_below(global_afl, state_ptr->trigger_len);
    trigger_ptr = (state_ptr->ptr) + randval;

    // Insert into the dynamic array
    insertArray(input, curr_state, trigger_ptr->term, trigger_ptr->term_len,
                randval);
    curr_state = trigger_ptr->dest;
    offset += 1;

  }

  return input;

}

/*Creates a candidate from walk with state hashmap and
 * recursion hashmap
 */

Candidate *gen_candidate(Array *input) {

  terminal *  term_ptr;
  IdxMap_new *idxmapPtr;
  // Declare the State Hash Table
  IdxMap_new *idxmapStart =
      (IdxMap_new *)malloc(sizeof(IdxMap_new) * numstates);
  for (int x = 0; x < numstates; x++) {

    idxmapPtr = &idxmapStart[x];
    utarray_new(idxmapPtr->nums, &ut_int_icd);

  }

  char *     trigger;
  int        state;
  char *     key;
  Candidate *candidate = (Candidate *)malloc(sizeof(Candidate));
  candidate->walk = input;
  int offset = 0, error;

  // Generate statemap for splicing
  while (offset < input->used) {

    term_ptr = &input->start[offset];
    state = term_ptr->state;
    // char *statenum = state + 1;
    // int num = atoi(statenum);
    idxmapPtr = &idxmapStart[state];
    utarray_push_back(idxmapPtr->nums, &offset);
    offset += 1;

  }

  candidate->statemap = idxmapStart;
  return candidate;

}

char *get_state(char *trigger) {

  // Get the state from transition
  int trigger_idx = 0;
  printf("\nTrigger:%s", trigger);
  char *state = (char *)malloc(sizeof(char) * 10);
  while (trigger[trigger_idx] != '_') {

    state[trigger_idx] = trigger[trigger_idx];
    trigger_idx += 1;

  }

  printf("\nTrigger Idx:%d", trigger_idx);
  state[trigger_idx] = '\0';
  return state;

}

void print_repr(Array *input, char *prefix) {

  size_t    offset = 0;
  terminal *term_ptr;
  char      geninput[input->used * 100];
  if (!input->used) {

    printf("\n=============");
    printf("\n%s:%s", prefix, "");
    printf("\n=============");
    return;

  }

  // This is done to create a null-terminated initial string
  term_ptr = &input->start[offset];
  strcpy(geninput, term_ptr->symbol);
  offset += 1;

  while (offset < input->used) {

    term_ptr = &input->start[offset];
    strcat(geninput, term_ptr->symbol);
    offset += 1;

  }

  printf("\n=============");
  printf("\n%s:%s", prefix, geninput);
  printf("\n=============");

}

// int main(int argc, char*argv[]) {

//     char *mode;
//     if (argc == 1) {

//         printf("\nUsage: ./gramfuzzer <mode>");
//         return -1;
//     }
//     if (argc >= 2) {

//         mode = argv[1];
//         printf("\nMode:%s", mode);
//     }
//     if (! strcmp(mode, "Generate")) {

//         GenInputBenchmark();
//     }
//     else if (! strcmp(mode, "RandomMutation")) {

//         RandomMutationBenchmark();
//     }
//     else if (! strcmp(mode, "Splice")) {

//         SpliceMutationBenchmark();
//     }
//     else if (! strcmp(mode, "Recursive")) {

//         RandomRecursiveBenchmark();
//     }
//     else {

//         printf("\nUnrecognized mode");
//         return -1;
//     }
//     return 0;
// }

