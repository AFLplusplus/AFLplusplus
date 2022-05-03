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
  size_t trigger_idx;
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

int test_get_hashmap(map_t m) {
  char k[100] = "continue";
  struct terminal_arr* ta;
  int r = hashmap_get(m, k, (void **)&ta);
  if (!r) {
    printf("------ In testing, the terminal is included in %zu edges ------\n", ta->len);
    size_t i;
    for (i = 0; i < ta->len; i++) {
      printf("state_name = %d\n", (ta->start + i)->state_name);
      printf("trigger_idx = %zu\n", (ta->start + i)->trigger_idx);
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


int dfs(map_t m, struct terminal_arr* ta, char* str, size_t str_size) {

}

int main(int argc, char *argv[]) {

  char automaton_path[] = "/root/gramatron-artifact/grammars/gt_bugs/mruby-1/source_automata.json";
  state * pda = create_pda((u8 *)automaton_path);
  // char program_path[] = "/root/gramatron-artifact/fuzzers/AFLplusplus/custom_mutators/gramatron/example";
  // FILE* ptr;
  // ptr = fopen(program_path, "r");
  // if (NULL == ptr) {
  //   printf("file can't be opened \n");
  // }
  // char ch;
  // char program[MAX_PROGRAM_LENGTH];
  // int i = 0;
  // do {
  //   ch = fgetc(ptr);
  //   program[i] = ch;
  //   printf("%c", ch);
  //   i ++;
  // } while (ch != EOF);
  Array * res;
  res = (Array *)calloc(1, sizeof(Array));
  initArray(res, INIT_SIZE);
  map_t char_to_symbol = hashmap_new();
  struct symbols_arr* symbols = create_array_of_chars();
  map_t pda_map = create_pda_hashmap((struct state*)pda, symbols);
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
  
  
  
  free_hashmap(pda_map, &free_terminal_arr);
  free_hashmap(first_char_to_symbols_map, &free_array_of_chars);
  free(pda);
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

