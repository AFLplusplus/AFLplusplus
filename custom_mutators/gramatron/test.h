#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <json-c/json.h>
#include <unistd.h>
#include "hashmap.h"
#include "uthash.h"
#include "utarray.h"

#define INIT_SIZE 100  // Initial size of the dynamic array holding the input

typedef struct terminal {

  int    state;
  int    trigger_idx;
  size_t symbol_len;
  char * symbol;

} terminal;

typedef struct trigger {

  char * id;
  int    dest;
  char * term;
  size_t term_len;

} trigger;

typedef struct state {

  int      state_name;   // Integer State name
  int      trigger_len;  // Number of triggers associated with this state
  trigger *ptr;          // Pointer to beginning of the list of triggers

} state;

typedef struct {

  size_t    used;
  size_t    size;
  size_t    inputlen;
  terminal *start;

} Array;

int init_state;
int curr_state;
int final_state;

state *create_pda(char *);
Array *gen_input(state *, Array *);
void   print_repr(Array *, char *);
void   initArray(Array *, size_t);
void   insertArray(Array *, int, char *, size_t, int);

