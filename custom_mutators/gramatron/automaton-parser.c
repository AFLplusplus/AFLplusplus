#include "afl-fuzz.h"
#include "automaton-parser.h"

int free_terminal_arr(any_t placeholder, any_t item) {
  struct terminal_arr* tmp = item;
  free(tmp->start);
  free(tmp);
  return MAP_OK;
}

int compare_two_symbols(const void * a, const void * b) {
    char* a_char = *(char **)a;
    char* b_char = *(char **)b;
    size_t fa = strlen(a_char);
    size_t fb = strlen(b_char);
    if (fa > fb) return -1;
    else if (fa == fb) return 0;
    else return 1;

}

// TODO: create a map
// key: first character of a symbol, value: a list of symbols that starts with key, the list is sorted in descending order of the symbol lengths
map_t create_first_char_to_symbols_hashmap(struct symbols_arr *symbols, struct symbols_arr *first_chars) {
  map_t char_to_symbols = hashmap_new();
  // TODO: free the allocated map
  // sort the symbol_dict in descending order of the symbol lengths
  qsort(symbols->symbols_arr, symbols->len, sizeof(char*), compare_two_symbols);
  #ifdef DEBUG
  printf("------ print after sort ------\n");
  print_symbols_arr(symbols);
  #endif
  size_t i;
  int r; // response from hashmap get and put
  for (i = 0; i < symbols->len; i++) {
    char* symbol_curr = symbols->symbols_arr[i];
    // get first character from symbol_curr
    char first_character[2];
    first_character[0] = symbol_curr[0];
    first_character[1] = '\0';
    #ifdef DEBUG
    printf("****** Current symbol is %s, its first character is %s ******\n", symbol_curr, first_character);
    #endif
    // key would be the first character of symbol_curr
    // the value would be an array of chars
    struct symbols_arr* associated_symbols;
    r = hashmap_get(char_to_symbols, first_character, (any_t*)&associated_symbols);
    if (!r) {
      // append current symbol to existing array
      #ifdef DEBUG
      printf("****** First character %s is already in hashmap ******\n", first_character);
      #endif
      if(!add_element_to_symbols_arr(associated_symbols, symbol_curr, strlen(symbol_curr) + 1)) {
        free_hashmap(char_to_symbols, &free_array_of_chars);
        return NULL;
      }
    }
    else {
      // start a new symbols_arr
      #ifdef DEBUG
      printf("****** First character %s is not in hashmap ******\n", first_character);
      #endif
      struct symbols_arr* new_associated_symbols = create_array_of_chars();
      strncpy(first_chars->symbols_arr[first_chars->len], first_character, 2); // 2 because one character plus the NULL byte
      add_element_to_symbols_arr(new_associated_symbols, symbol_curr, strlen(symbol_curr) + 1);
      r = hashmap_put(char_to_symbols, first_chars->symbols_arr[first_chars->len], new_associated_symbols);
      first_chars->len++;
      #ifdef DEBUG
      if (r) {
        printf("hashmap put failed\n");
      }
      else {
        printf("hashmap put succeeded\n");
      }
      #endif
    }
  }
  printf("****** Testing ******\n");
  struct symbols_arr* tmp_arr;
  char str[] = "i";
  int t = hashmap_get(char_to_symbols, str, (any_t *)&tmp_arr);
  if (!t)
    print_symbols_arr(tmp_arr);
  return char_to_symbols;
}

struct symbols_arr* create_array_of_chars() {
  struct symbols_arr* ret = (struct symbols_arr*)malloc(sizeof(struct symbols_arr));
  ret->len = 0; 
  ret->symbols_arr = (char **)malloc(MAX_TERMINAL_NUMS * sizeof(char*));
  size_t i;
  for (i = 0; i < MAX_TERMINAL_NUMS; i++) {
    ret->symbols_arr[i] = (char *)calloc(MAX_TERMINAL_LENGTH, sizeof(char));
  }
  return ret;
}

// map a symbol to a list of (state, trigger_idx)
map_t create_pda_hashmap(state* pda, struct symbols_arr* symbols_arr) {
  int state_idx, trigger_idx, r; // r is the return result for hashmap operation 
  map_t m = hashmap_new();
  // iterate over pda
  for (state_idx = 0; state_idx < numstates; state_idx++) {
    #ifdef DEBUG
    printf("------ The state idx is %d ------\n", state_idx);
    #endif
    if (state_idx == final_state) continue;
    state* state_curr = pda + state_idx;
    for (trigger_idx = 0; trigger_idx < state_curr->trigger_len; trigger_idx++) {
      #ifdef DEBUG
      printf("------ The trigger idx is %d ------\n", trigger_idx);
      #endif
      trigger* trigger_curr = state_curr->ptr + trigger_idx;
      char* symbol_curr = trigger_curr->term;
      size_t symbol_len = trigger_curr->term_len;
      struct terminal_arr* terminal_arr_curr;
      r = hashmap_get(m, symbol_curr, (any_t*)&terminal_arr_curr);
      if (r) {
        // the symbol is not in the map
        if (!add_element_to_symbols_arr(symbols_arr, symbol_curr, symbol_len+1)) {
          // the number of symbols exceed maximual number
          free_hashmap(m, &free_terminal_arr);
          return NULL;
        }
        #ifdef DEBUG
        printf("Symbol %s is not in map\n", symbol_curr);
        #endif
        struct terminal_arr* new_terminal_arr = (struct terminal_arr*)malloc(sizeof(struct terminal_arr));
        new_terminal_arr->start = (struct terminal_meta*)calloc(numstates, sizeof(struct terminal_meta));
        #ifdef DEBUG
        printf("allocate new memory address %p\n", new_terminal_arr->start);
        #endif
        new_terminal_arr->start->state_name = state_idx;
        new_terminal_arr->start->dest = trigger_curr->dest;
        new_terminal_arr->start->trigger_idx = trigger_idx;
        new_terminal_arr->len = 1;
        #ifdef DEBUG
        printf("Symbol %s is included in %zu edges\n", symbol_curr, new_terminal_arr->len);
        #endif
        r = hashmap_put(m, symbol_curr, new_terminal_arr);
        #ifdef DEBUG
        if (r) {
          printf("hashmap put failed\n");
        }
        else {
          printf("hashmap put succeeded\n");
        }
        #endif
        // if symbol not already in map, it's not in symbol_dict, simply add the symbol to the array
        // TODO: need to initialize symbol dict (calloc)
      }
      else {
        // the symbol is already in map
        // append to terminal array
        // no need to touch start
        #ifdef DEBUG
        printf("Symbol %s is in map\n", symbol_curr);
        #endif
        struct terminal_meta* modify = terminal_arr_curr->start + terminal_arr_curr->len;
        modify->state_name = state_idx;
        modify->trigger_idx = trigger_idx;
        modify->dest = trigger_curr->dest;
        terminal_arr_curr->len++;
        #ifdef DEBUG
        printf("Symbol %s is included in %zu edges\n", symbol_curr, terminal_arr_curr->len);
        #endif
        // if symbol already in map, it's already in symbol_dict as well, no work needs to be done
      }

    }
  }
  return m;
}

void print_symbols_arr(struct symbols_arr* arr) {
  size_t i;
  printf("(");
  for (i = 0; i < arr->len; i++) {
    printf("%s", arr->symbols_arr[i]);
    if (i != arr->len - 1) printf(",");
  }
  printf(")\n");
}

void free_hashmap(map_t m, int (*f)(any_t, any_t)) {
  if (!m) {
    printf("m map is empty\n");
    return;
  }
  int r = hashmap_iterate(m, f, NULL);
  #ifdef DEBUG
  if (!r) printf("free hashmap items successfully!\n");
  else printf("free hashmap items failed");
  #endif
  hashmap_free(m);
}

int free_array_of_chars(any_t placeholder, any_t item) {
  if (!item) {
    printf("item is empty\n");
    return MAP_MISSING;
  }
  struct symbols_arr* arr = item;
  size_t i;
  for (i = 0; i < MAX_TERMINAL_NUMS; i++) {
    free(arr->symbols_arr[i]);
  }
  free(arr->symbols_arr);
  free(arr);
  return MAP_OK;
}

void free_pda(state* pda) {
  if (!pda) {
    printf("pda is null\n");
    return;
  }
  size_t i, j;
  for (i = 0; i < numstates; i++) {
    state* state_curr = pda + i;
    for (j = 0; j < state_curr->trigger_len; j++) {
      trigger* trigger_curr = state_curr->ptr + j;
      free(trigger_curr->id);
      free(trigger_curr->term);
    }
    free(state_curr->ptr);
  }
  free(pda);
}

int dfs(struct terminal_arr** tmp, const char* program, const size_t program_length, struct terminal_arr** res, size_t idx, int curr_state) {
  if (*res) return 1; // 1 means successfully found a path
  if (idx == program_length) {
    // test if the last terminal points to the final state
    if (curr_state != final_state) return 0;
    *res = *tmp;
    return 1;
  }
  if ((*tmp)->len == MAX_PROGRAM_WALK_LENGTH) {
    printf("Reached maximum program walk length\n");
    return 0;
  }
  char first_char[2];
  first_char[0] = program[idx]; // first character of program
  first_char[1] = '\0';
  int r;
  struct symbols_arr* matching_symbols;
  r = hashmap_get(first_char_to_symbols_map, first_char, (any_t *)&matching_symbols);
  if (r) {
    printf("No symbols match the current character, abort!"); // hopefully won't reach this state
    return 0;
  }
  size_t i;
  bool matched = false;
  for (i = 0; i < matching_symbols->len; i++) {
    if (matched) break;
    char *matching_symbol = matching_symbols->symbols_arr[i];
    if (!strncmp(matching_symbol, program + idx, strlen(matching_symbol))) {
      // there is a match
      matched = true;
      // find the possible paths of that symbol
      struct terminal_arr* ta;
      int r2 = hashmap_get(pda_map, matching_symbol, (any_t *)&ta);
      if (!r2) {
        // the terminal is found in the dictionary
        size_t j;
        for (j = 0; j < ta->len; j++) {
          int state_name = (ta->start + j)->state_name;
          if (state_name != curr_state) continue;
          size_t trigger_idx = (ta->start + j)->trigger_idx;
          int dest = (ta->start + j)->dest;
          (*tmp)->start[(*tmp)->len].state_name = state_name;
          (*tmp)->start[(*tmp)->len].trigger_idx = trigger_idx;
          (*tmp)->start[(*tmp)->len].dest = dest;
          (*tmp)->len++;
          if (dfs(tmp, program, program_length, res, idx + strlen(matching_symbol), dest)) return 1;
          (*tmp)->len--;
        }
      }
      else {
        printf("No path goes out of this symbol, abort!"); // hopefully won't reach this state
        return 0;
      }
    }
  }
  return 0;
  /*
  1. First extract the first character of the current program
  2. Match the possible symbols of that program
  3. Find the possible paths of that symbol
  4. Add to temporary terminal array
  5. Recursion
  6. Pop the path from the terminal array
  7. - If idx reaches end of program, set tmp to res
     - If idx is not at the end and nothing matches, the current path is not working, simply return 0
  */
}

Array* constructArray(struct terminal_arr* terminal_arr, state* pda) {
  Array * res = (Array *)calloc(1, sizeof(Array));
  initArray(res, INIT_SIZE);
  size_t i;
  for (i = 0; i < terminal_arr->len; i ++) {
    struct terminal_meta* curr = terminal_arr->start + i;
    int state_name = curr->state_name;
    int trigger_idx = curr->trigger_idx;
    // get the symbol from pda
    state* state_curr = pda + state_name;
    trigger* trigger_curr = state_curr->ptr + trigger_idx;
    char *symbol_curr = trigger_curr->term;
    size_t symbol_curr_len = trigger_curr->term_len;
    insertArray(res, state_name, symbol_curr, symbol_curr_len, trigger_idx);
  }
  return res;
}

Array* automaton_parser(const uint8_t *seed_fn) {
    Array* parsed_res = NULL;
    FILE* ptr;
    ptr = fopen(seed_fn, "r");
    if (ptr == NULL) {
      printf("file can't be opened \n");
      fclose(ptr);
      return NULL;
    }
    char ch;
    char program[MAX_PROGRAM_LENGTH];
    int i = 0;
    bool program_too_long = false;
    do {
      if (i == MAX_PROGRAM_LENGTH) {
        // the maximum program length is reached
        printf("maximum program length is reached, give up the current seed\n");
        program_too_long = true;
        break;
      }
      ch = fgetc(ptr);
      program[i] = ch;
      i ++;
    } while (ch != EOF);
    program[i-1] = '\0';
    fclose(ptr);
    if ((i == 1 && program[0] == '\0') || program_too_long) return NULL;
    struct terminal_arr* arr_holder;
    struct terminal_arr* dfs_res = NULL;
    arr_holder = (struct terminal_arr*)calloc(1, sizeof(struct terminal_arr));
    arr_holder->start = (struct terminal_meta*)calloc(MAX_PROGRAM_WALK_LENGTH, sizeof(struct terminal_meta));
    int dfs_success = dfs(&arr_holder, program, strlen(program), &dfs_res, 0, init_state);
    // printf("*** return value %d *** \n", dfs_success);
    if (dfs_success) {
      parsed_res = constructArray(dfs_res, pda);
    }
    free(arr_holder->start);
    free(arr_holder);
    return parsed_res;
}

// return 0 if fails
// return 1 if succeeds
int add_element_to_symbols_arr(struct symbols_arr* symbols_arr, char* symbol, size_t symbol_len) {
  if (symbols_arr->len >= MAX_TERMINAL_NUMS || symbol_len >= MAX_TERMINAL_LENGTH) {
    return 0;
  }
  strncpy(symbols_arr->symbols_arr[symbols_arr->len], symbol, symbol_len);
  symbols_arr->len++;
  return 1;
}