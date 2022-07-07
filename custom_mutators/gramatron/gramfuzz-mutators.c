#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "afl-fuzz.h"
#include "gramfuzz.h"

Array *performRandomMutation(state *pda, Array *input) {

  terminal *term_ptr;
  // terminal *prev_ptr;
  Array *mutated;
  Array *sliced;

  // Get offset at which to generate new input and slice it
  int idx = rand_below(global_afl, input->used);
  sliced = slice(input, idx);
  // print_repr(sliced, "Slice");

  // prev_ptr = & input->start[idx - 1];
  // printf("\nState:%s Symbol:%s", prev_ptr->state, prev_ptr->symbol);
  // Reset current state to that of the slice's last member
  term_ptr = &input->start[idx];
  curr_state = term_ptr->state;
  // printf("\nState:%s Symbol:%s", curr_state, term_ptr->symbol);

  // Set the next available cell to the one adjacent to this chosen point
  mutated = gen_input(pda, sliced);
  return mutated;

}

// Tries to perform splice operation between two automaton walks
UT_icd intpair_icd = {sizeof(intpair_t), NULL, NULL, NULL};

Array *performSpliceOne(Array *originput, IdxMap_new *statemap_orig,
                        Array *splicecand) {

  UT_array * stateptr, *pairs;
  intpair_t  ip;
  intpair_t *cand;

  terminal *term_ptr;
  Array *   prefix;
  int       state;

  // Initialize the dynamic holding the splice indice pairs
  utarray_new(pairs, &intpair_icd);
  // print_repr(originput, "Orig");
  // print_repr(splicecand, "SpliceCand");

  // Iterate through the splice candidate identifying potential splice points
  // and pushing pair (orig_idx, splice_idx) to a dynamic array
  for (int x = 0; x < splicecand->used; x++) {

    term_ptr = &splicecand->start[x];
    stateptr = statemap_orig[term_ptr->state].nums;
    int length = utarray_len(stateptr);
    if (length) {

      int *splice_idx = (int *)utarray_eltptr(stateptr, rand_below(global_afl, length));
      ip.orig_idx = *splice_idx;
      ip.splice_idx = x;
      utarray_push_back(pairs, &ip);

    }

  }

  // Pick a random pair
  int length = utarray_len(pairs);
  cand = (intpair_t *)utarray_eltptr(pairs, rand_below(global_afl, length));
  // printf("\n Orig_idx:%d Splice_idx:%d", cand->orig_idx, cand->splice_idx);

  // Perform the splicing
  prefix = slice(originput, cand->orig_idx);
  Array *spliced = spliceGF(prefix, splicecand, cand->splice_idx);
  // print_repr(spliced, "Spliced");
  //
  utarray_free(pairs);

  return spliced;

}

UT_array **get_dupes(Array *input, int *recur_len) {

  // Variables related to finding duplicates
  int         offset = 0;
  int         state;
  terminal *  term_ptr;
  IdxMap_new *idxMapPtr;
  UT_array ** recurIdx;

  // Declare the Recursive Map Table
  IdxMap_new *idxmapStart =
      (IdxMap_new *)malloc(sizeof(IdxMap_new) * numstates);
  //
  // UT_array *(recurIdx[numstates]);
  recurIdx = malloc(sizeof(UT_array *) * numstates);

  for (int x = 0; x < numstates; x++) {

    idxMapPtr = &idxmapStart[x];
    utarray_new(idxMapPtr->nums, &ut_int_icd);

  }

  // Obtain frequency distribution of states
  while (offset < input->used) {

    term_ptr = &input->start[offset];
    state = term_ptr->state;
    // int num = atoi(state + 1);
    idxMapPtr = &idxmapStart[state];
    utarray_push_back(idxMapPtr->nums, &offset);
    offset += 1;

  }

  // Retrieve the duplicated states
  offset = 0;
  while (offset < numstates) {

    idxMapPtr = &idxmapStart[offset];
    int length = utarray_len(idxMapPtr->nums);
    if (length >= 2) {

      recurIdx[*recur_len] = idxMapPtr->nums;
      *recur_len += 1;

    }

    // else {

    //     utarray_free(idxMapPtr->nums);
    // }
    offset += 1;

  }

  if (*recur_len) {

    // Declare the return struct
    // We use this struct so that we save the reference to IdxMap_new and free
    // it after we have used it in doMult
    // Get_Dupes_Ret* getdupesret =
    // (Get_Dupes_Ret*)malloc(sizeof(Get_Dupes_Ret));
    return recurIdx;
    // getdupesret->idxmap = idxmapStart;
    // getdupesret->recurIdx = recurIdx;
    // return getdupesret;

  } else {

    return NULL;

  }

}

Array *doMult(Array *input, UT_array **recur, int recurlen) {

  int       offset = 0;
  int       idx = rand_below(global_afl, recurlen);
  UT_array *recurMap = recur[idx];
  UT_array *recurPtr;
  Array *   prefix;
  Array *   postfix;
  Array *   feature;

  // Choose two indices to get the recursive feature
  int recurIndices = utarray_len(recurMap);
  int firstIdx = 0;
  int secondIdx = 0;
  getTwoIndices(recurMap, recurIndices, &firstIdx, &secondIdx);

  // Perform the recursive mut
  // print_repr(input, "Orig");
  prefix = slice(input, firstIdx);
  // print_repr(prefix, "Prefix");
  if (firstIdx < secondIdx) {

    feature = carve(input, firstIdx, secondIdx);

  } else {

    feature = carve(input, secondIdx, firstIdx);

  }

  // print_repr(feature, "Feature");
  concatPrefixFeature(prefix, feature);

  // GC allocated structures
  free(feature->start);
  free(feature);
  // for(int x = 0; x < recurlen; x++) {

  //     utarray_free(recur[x]);
  // }
  // free(recur);
  // print_repr(prefix, "Concat");
  return spliceGF(prefix, input, secondIdx);

}

void getTwoIndices(UT_array *recur, int recurlen, int *firstIdx,
                   int *secondIdx) {

  int ArrayRecurIndices[recurlen];
  int offset = 0, *p;
  // Unroll into an array
  for (p = (int *)utarray_front(recur); p != NULL;
       p = (int *)utarray_next(recur, p)) {

    ArrayRecurIndices[offset] = *p;
    offset += 1;

  }

  /*Source:
   * https://www.geeksforgeeks.org/shuffle-a-given-array-using-fisher-yates-shuffle-algorithm/
   */
  for (int i = offset - 1; i > 0; i--) {

    // Pick a random index from 0 to i
    int j = rand_below(global_afl, i + 1);

    // Swap arr[i] with the element at random index
    swap(&ArrayRecurIndices[i], &ArrayRecurIndices[j]);

  }

  *firstIdx = ArrayRecurIndices[0];
  *secondIdx = ArrayRecurIndices[1];

}

void swap(int *a, int *b) {

  int temp = *a;
  *a = *b;
  *b = temp;

}

