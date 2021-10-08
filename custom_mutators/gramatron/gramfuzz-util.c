#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "afl-fuzz.h"
#include "gramfuzz.h"
#ifdef _GNU_SOURCE
  #undef _GNU_SOURCE
#endif
#define _GNU_SOURCE
#include <sys/mman.h>

/* Dynamic Array for adding to the input repr
 * */
void initArray(Array *a, size_t initialSize) {

  a->start = (terminal *)calloc(1, sizeof(terminal) * initialSize);
  a->used = 0;
  a->size = initialSize;
  a->inputlen = 0;

}

void insertArray(Array *a, int state, char *symbol, size_t symbol_len,
                 int trigger_idx) {

  // a->used is the number of used entries, because a->array[a->used++] updates
  // a->used only *after* the array has been accessed. Therefore a->used can go
  // up to a->size
  terminal *term_ptr;
  if (a->used == a->size) {

    a->size = a->size * sizeof(terminal);
    a->start = (terminal *)realloc(a->start, a->size * sizeof(terminal));

  }

  // Add the element
  term_ptr = &a->start[a->used];
  term_ptr->state = state;
  term_ptr->symbol = symbol;
  term_ptr->symbol_len = symbol_len;
  term_ptr->trigger_idx = trigger_idx;

  // Increment the pointer
  a->used += 1;
  a->inputlen += symbol_len;

}

void freeArray(Array *a) {

  terminal *ptr;
  for (int x = 0; x < a->used; x++) {

    ptr = &a->start[x];
    free(ptr);

  }

  a->start = NULL;
  a->used = a->size = 0;

}

/* Dynamic array for adding indices of states/recursive features
 * Source:
 * https://stackoverflow.com/questions/3536153/c-dynamically-growing-array
 */
void initArrayIdx(IdxMap *a, size_t initialSize) {

  a->array = (int *)malloc(initialSize * sizeof(int));
  a->used = 0;
  a->size = initialSize;

}

void insertArrayIdx(IdxMap *a, int idx) {

  // a->used is the number of used entries, because a->array[a->used++] updates
  // a->used only *after* the array has been accessed. Therefore a->used can go
  // up to a->size
  if (a->used == a->size) {

    a->size *= 2;
    a->array = (int *)realloc(a->array, a->size * sizeof(int));

  }

  a->array[a->used++] = idx;

}

void freeArrayIdx(IdxMap *a) {

  free(a->array);
  a->array = NULL;
  a->used = a->size = 0;

}

/* Dynamic array for adding potential splice points
 */
void initArraySplice(SpliceCandArray *a, size_t initialSize) {

  a->start = (SpliceCand *)malloc(initialSize * sizeof(SpliceCand));
  a->used = 0;
  a->size = initialSize;

}

void insertArraySplice(SpliceCandArray *a, Candidate *candidate, int idx) {

  // a->used is the number of used entries, because a->array[a->used++] updates
  // a->used only *after* the array has been accessed. Therefore a->used can go
  // up to a->size
  SpliceCand *candptr;
  if (a->used == a->size) {

    a->size = a->size * sizeof(SpliceCand);
    a->start = (SpliceCand *)realloc(a->start, a->size * sizeof(SpliceCand));

  }

  // Add the element
  candptr = &a->start[a->used];
  candptr->splice_cand = candidate;
  candptr->idx = idx;
  a->used += 1;

}

void freeArraySplice(IdxMap *a) {

  free(a->array);
  a->array = NULL;
  a->used = a->size = 0;

}

int fact(int n) {

  int i, f = 1;
  for (i = 1; i <= n; i++) {

    f *= i;

  }

  return f;

}

/* Uses the walk to create the input in-memory */
u8 *unparse_walk(Array *input) {

  terminal *term_ptr;
  int       offset = 0;
  u8 *      unparsed = (u8 *)malloc(input->inputlen + 1);
  term_ptr = &input->start[offset];
  strcpy(unparsed, term_ptr->symbol);
  offset += 1;
  while (offset < input->used) {

    term_ptr = &input->start[offset];
    strcat(unparsed, term_ptr->symbol);
    offset += 1;

  }

  return unparsed;

}

/*Dump the input representation into a file*/
void write_input(Array *input, u8 *fn) {

  FILE *fp;
  // If file already exists, then skip creating the file
  if (access(fn, F_OK) != -1) { return; }

  fp = fopen(fn, "wbx+");
  // If the input has already been flushed, then skip silently
  if (fp == NULL) {

    fprintf(stderr, "\n File '%s' could not be open, exiting\n", fn);
    exit(1);

  }

  // Write the length parameters
  fwrite(&input->used, sizeof(size_t), 1, fp);
  fwrite(&input->size, sizeof(size_t), 1, fp);
  fwrite(&input->inputlen, sizeof(size_t), 1, fp);

  // Write the dynamic array to file
  fwrite(input->start, input->size * sizeof(terminal), 1, fp);
  // printf("\nUsed:%zu Size:%zu Inputlen:%zu", input->used, input->size,
  // input->inputlen);
  fclose(fp);

}

Array *parse_input(state *pda, FILE *fp) {

  terminal *term;
  state *   state_ptr;
  trigger * trigger;
  int       trigger_idx;
  Array *   input = (Array *)calloc(1, sizeof(Array));

  // Read the length parameters
  fread(&input->used, sizeof(size_t), 1, fp);
  fread(&input->size, sizeof(size_t), 1, fp);
  fread(&input->inputlen, sizeof(size_t), 1, fp);

  terminal *start_ptr = (terminal *)calloc(input->size, sizeof(terminal));
  if (!start_ptr) {

    fprintf(stderr, "alloc failed!\n");
    return NULL;

  }

  // Read the dynamic array to memory
  fread(start_ptr, input->size * sizeof(terminal), 1, fp);
  // Update the pointers to the terminals since they would have
  // changed
  int idx = 0;
  while (idx < input->used) {

    terminal *term = &start_ptr[idx];
    // Find the state
    state_ptr = pda + term->state;
    // Find the trigger and update the terminal address
    trigger_idx = term->trigger_idx;
    trigger = (state_ptr->ptr) + trigger_idx;
    term->symbol = trigger->term;
    idx += 1;

  }

  input->start = start_ptr;
  // printf("\nUsed:%zu Size:%zu Inputlen:%zu", input->used, input->size,
  // input->inputlen);

  return input;

}

// Read the input representation into memory
Array *read_input(state *pda, u8 *fn) {

  FILE *fp;
  fp = fopen(fn, "rb");
  if (fp == NULL) {

    fprintf(stderr, "\n File '%s' does not exist, exiting\n", fn);
    exit(1);

  }

  Array *res = parse_input(pda, fp);
  fclose(fp);
  return res;

}

