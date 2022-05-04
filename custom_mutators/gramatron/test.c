/* This is the testing module for Gramatron
 */
#include "afl-fuzz.h"
#include "gramfuzz.h"

#define NUMINPUTS 50
#define MAX_PROGRAM_LENGTH 2000
#define MAX_PROGRAM_WALK_LENGTH 2000
#define MAX_TERMINAL_NUMS 1000
#define MAX_TERMINAL_LENGTH 100

// #define DEBUG

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
    printf("\nName:%d Trigger:%d", offset, trigger_len);

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

void SanityCheck(char *automaton_path) {

  state *        pda = create_pda(automaton_path);
  int            count = 0, state;
  Get_Dupes_Ret *getdupesret;
  IdxMap_new *   statemap;
  IdxMap_new *   statemap_ptr;
  terminal *     term_ptr;

  while (count < NUMINPUTS) {

    // Perform input generation
    Array *generated = gen_input(pda, NULL);
    print_repr(generated, "Gen");
    count += 1;

  }

}

// TODO: implement this
void find_automaton_walk(char *state_curr, state *pda) {

}

struct terminal_meta {

  int state_name;
  int trigger_idx;
  int dest;

} ;

struct terminal_arr {

  struct terminal_meta* start;
  size_t len;

} ;

struct symbols_arr {
  char** symbols_arr;
  size_t len;
} ; // essentially a 2d array of strings

// TODO: delete
void output_hashmap(any_t placeholder, any_t item) {
  struct terminal_meta* tmp = item;
  printf("%d\n", tmp->state_name);
}

int free_terminal_arr(any_t placeholder, any_t item) {
  struct terminal_arr* tmp = item;
  free(tmp->start);
  free(tmp);
  return MAP_OK;
}

void free_hashmap(map_t m, int (*f)(any_t, any_t)) {
  int r = hashmap_iterate(m, f, NULL);
  #ifdef DEBUG
  if (!r) printf("free hashmap items successfully!\n");
  else printf("free hashmap items failed");
  #endif
  hashmap_free(m);
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
        strncpy(symbols_arr->symbols_arr[symbols_arr->len], symbol_curr, symbol_len+1);
        symbols_arr->len++;
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

  // tryout hashmap
  // map_t m = hashmap_new();
  // char k[100] = "key";
  // struct terminal_meta* vptr = (struct terminal_meta *)malloc(sizeof(struct terminal_meta));
  // vptr->state_name = 9;
  // vptr->trigger_idx = 0;
  // any_t v = vptr;
  // struct terminal_meta* grptr;
  // int r = hashmap_put(m, k, v);
  // if (!r) {
  //   printf("add elements to hashmap succeed\n");
  //   int gr = hashmap_get(m, k, &grptr);
  //   // printf("%d\n", gr);
  //   hashmap_iterate(m, &output_hashmap, NULL);
  // }
  // else {printf("fail\n");}
  // free(vptr);

  // TODO: deallocate all the terminal arrays (not here!)
  // TODO: deallocate the hashmap (not here)
}

void print_terminal_arr(struct terminal_arr* ta) {
  size_t i;
  for (i = 0; i < ta->len; i++) {
    printf("state_name = %d, ", (ta->start + i)->state_name);
    printf("trigger_idx = %d, ", (ta->start + i)->trigger_idx);
    printf("dest = %d.\n", (ta->start + i)->dest);
  }
}

int test_get_hashmap(map_t m) {
  char k[100] = "continue";
  struct terminal_arr* ta;
  int r = hashmap_get(m, k, (void **)&ta);
  if (!r) {
    printf("------ In testing, the terminal is included in %zu edges ------\n", ta->len);
    size_t i;
    for (i = 0; i < ta->len; i++) {
      printf("state_name = %d\n", (ta->start + i)->state_name);
      printf("trigger_idx = %d\n", (ta->start + i)->trigger_idx);
      printf("dest = %d\n", (ta->start + i)->dest);
    }
  }
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

int free_array_of_chars(any_t placeholder, any_t item) {
  struct symbols_arr* arr = item;
  size_t i;
  for (i = 0; i < MAX_TERMINAL_NUMS; i++) {
    free(arr->symbols_arr[i]);
  }
  free(arr->symbols_arr);
  free(arr);
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

void print_symbols_arr(struct symbols_arr* arr) {
  size_t i;
  printf("(");
  for (i = 0; i < arr->len; i++) {
    printf("%s", arr->symbols_arr[i]);
    if (i != arr->len - 1) printf(",");
  }
  printf(")\n");
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
      strncpy(associated_symbols->symbols_arr[associated_symbols->len], symbol_curr, strlen(symbol_curr) + 1);
      associated_symbols->len++;
    }
    else {
      // start a new symbols_arr
      #ifdef DEBUG
      printf("****** First character %s is not in hashmap ******\n", first_character);
      #endif
      struct symbols_arr* new_associated_symbols = create_array_of_chars();
      strncpy(first_chars->symbols_arr[first_chars->len], first_character, 2); // 2 because one character plus the NULL byte
      strncpy(new_associated_symbols->symbols_arr[0], symbol_curr, strlen(symbol_curr) + 1);
      new_associated_symbols->len = 1;
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
  // testing
  // printf("****** Testing ******\n");
  // struct symbols_arr* tmp_arr;
  // char str[] = "i";
  // int t = hashmap_get(char_to_symbols, str, (any_t *)&tmp_arr);
  // if (!t)
  //   print_symbols_arr(tmp_arr);
  return char_to_symbols;
}


int dfs(const map_t pda_map, const map_t char_to_symbols, struct terminal_arr** tmp, const char* program, const size_t program_length, struct terminal_arr** res, size_t idx, int curr_state) {
  if (*res) return 1; // 1 means successfully found a path
  if (idx == program_length) {
    // test if the last terminal points to the final state
    if (curr_state != final_state) return 0;
    *res = *tmp;
    return 1;
  }
  char first_char[2];
  first_char[0] = program[idx]; // first character of program
  first_char[1] = '\0';
  int r;
  struct symbols_arr* matching_symbols;
  r = hashmap_get(char_to_symbols, first_char, (any_t *)&matching_symbols);
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
          if (dfs(pda_map, char_to_symbols, tmp, program, program_length, res, idx + strlen(matching_symbol), dest)) return 1;
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

void printArray(Array *arr) {
  printf("****** Start printing Array ****** \n");
  size_t i;
  for (i = 0; i < arr->used; i++) {
    printf("state_name = %d, trigger_idx = %d\n", arr->start[i].state,arr->start[i].trigger_idx);
  }
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

void free_pda(state* pda) {
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

bool if_terminal_equivalent(terminal* t1, terminal* t2) {
  if (t1->state != t2->state) {
    printf("t1->state = %d, t2->state = %d\n", t1->state, t2->state);
    return false;
  }
  if (t1->symbol_len != t2->symbol_len) {
    printf("t1->symbol_len = %d, t2->symbol_len = %d\n", t1->symbol_len, t2->symbol_len);
    return false;
  }
  if (t1->trigger_idx != t2->trigger_idx) {
    printf("t1->trigger_idx = %d, t2->trigger_idx = %d\n", t1->trigger_idx, t2->trigger_idx);
    return false;
  }
  if (!t1->symbol) {
    if (t2->symbol) return false;
    return true;
  }
  if (strcmp(t1->symbol, t2->symbol)) {
    printf("t1->symbol = %s, t2->symbol = %s\n", t1->symbol, t2->symbol);
    return false;
  }
  return true;
}

bool if_array_equivalent(Array* a1, Array* a2) {
  if (a1->used != a2->used) {
    printf("a1->used = %d, a2->used = %d\n", a1->used, a2->used);
    return false;
  }
  if (a1->size != a2->size) {
    printf("a1->size = %d, a2->size = %d\n", a1->size, a2->size);
    return false;
  }
  if (a1->inputlen != a2->inputlen) {
    printf("a1->inputlen = %d, a2->inputlen = %d\n", a1->inputlen, a2->inputlen);
    return false;
  }
  size_t i;
  for (i = 0; i < a1->size; i++) {
    terminal* t1 = a1->start + i;
    terminal* t2 = a2->start + i;
    if (!if_terminal_equivalent(t1, t2)) return false;
  }
  return true;

}

int main(int argc, char *argv[]) {

  char automaton_path[] = "/root/gramatron-artifact/grammars/gt_bugs/mruby-1/source_automata.json";
  state * pda = create_pda((u8 *)automaton_path);
  char program_path[] = "/root/gramatron-artifact/fuzzers/AFLplusplus/custom_mutators/gramatron/example";
  char program_aut_path[] = "/root/gramatron-artifact/fuzzers/AFLplusplus/custom_mutators/gramatron/example.aut";
  char program_aut_path_derived[] = "/root/gramatron-artifact/fuzzers/AFLplusplus/custom_mutators/gramatron/example_derived.aut";
  FILE* ptr;
  ptr = fopen(program_path, "r");
  if (NULL == ptr) {
    printf("file can't be opened \n");
  }
  char ch;
  char program[MAX_PROGRAM_LENGTH];
  int i = 0;
  do {
    ch = fgetc(ptr);
    program[i] = ch;
    printf("%c", ch);
    i ++;
  } while (ch != EOF);
  Array * res;
  // res = (Array *)calloc(1, sizeof(Array));

  // initArray(res, INIT_SIZE);
  struct symbols_arr* symbols = create_array_of_chars();
  map_t pda_map = create_pda_hashmap((struct state*)pda, symbols);
  res = read_input(pda, program_aut_path);
  printArray(res);
  // print all the symbols
  #ifdef DEBUG
  print_symbols_arr(symbols);
  #endif
  struct symbols_arr* first_chars = create_array_of_chars();
  map_t first_char_to_symbols_map = create_first_char_to_symbols_hashmap(symbols, first_chars);

  // testing
  // printf("****** Testing ******\n");
  // struct symbols_arr* tmp_arr;
  // char str[] = "c";
  // int t = hashmap_get(first_char_to_symbols_map, str, (any_t *)&tmp_arr);
  // if (!t)
  //   print_symbols_arr(tmp_arr);
  
  // testing
  struct terminal_arr* tmp;
  struct terminal_arr* dfs_res = NULL;
  tmp = (struct terminal_arr*)calloc(1, sizeof(struct terminal_arr));
  tmp->start = (struct terminal_meta*)calloc(MAX_PROGRAM_WALK_LENGTH, sizeof(struct terminal_meta));
  // char str[] = "return a\n";
  // size_t str_len = strlen(str);
  printf("*** return value %d *** \n", dfs(pda_map, first_char_to_symbols_map, &tmp, program, strlen(program), &dfs_res, 0, init_state));
  Array* parsed_res = constructArray(dfs_res, pda);
  printArray(parsed_res);
  write_input(parsed_res, program_aut_path_derived);
  printf("The two arrays are equivalent? %d\n", if_array_equivalent(res, parsed_res));

  Array* read_in_parsed = read_input(pda, program_aut_path_derived);
  printf("The two arrays are equivalent? %d\n", if_array_equivalent(res, read_in_parsed));

  free(read_in_parsed->start);
  free(read_in_parsed);

  free(parsed_res->start);
  free(parsed_res);
  free(tmp->start);
  free(tmp);
  free(res->start);
  free(res);
  free_hashmap(pda_map, &free_terminal_arr);
  free_hashmap(first_char_to_symbols_map, &free_array_of_chars);

  free_pda(pda);
  fclose(ptr);
  free_array_of_chars(NULL, symbols); // free the array of symbols
  free_array_of_chars(NULL, first_chars);
  return 0;
  // char *         mode;
  // char *         automaton_path;
  // char *         output_dir = NULL;
  // struct timeval tv;
  // struct timeval tz;
  // // gettimeofday(&tv, &tz);
  // srand(1337);
  // if (argc == 3) {

  //   mode = argv[1];
  //   automaton_path = strdup(argv[2]);
  //   printf("\nMode:%s Path:%s", mode, automaton_path);

  // } else {

  //   printf("\nUsage: ./test <mode> <automaton_path>");
  //   return -1;

  // }

  // if (!strcmp(mode, "SanityCheck")) {

  //   SanityCheck(automaton_path);

  // } else {

  //   printf("\nUnrecognized mode");
  //   return -1;

  // }

  // return 0;

}

