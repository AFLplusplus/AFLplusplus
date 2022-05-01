/* This is the testing module for Gramatron
 */
#include "afl-fuzz.h"
#include "gramfuzz.h"

#define NUMINPUTS 50
#define MAX_PROGRAM_LENGTH 2000
#define MAX_WALK_LENGTH 1000 // maximum length of terminals in a walk
#define MAX_TERMINAL_STATES 50

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

void free_hashmap(map_t m) {
  int r = hashmap_iterate(m, &free_terminal_arr, NULL);
  if (!r) printf("free hashmap items successfully!\n");
  else printf("free hashmap items failed");
  hashmap_free(m);
}

// map a symbol to a list of (state, trigger_idx)
map_t create_pda_hashmap(state* pda) {
  int state_idx, trigger_idx, r; // r is the return result for hashmap operation 
  map_t m = hashmap_new();
  // iterate over pda
  for (state_idx = 0; state_idx < numstates; state_idx++) {
    printf("------ The state idx is %d ------\n", state_idx);
    if (state_idx == final_state) continue;
    state* state_curr = pda + state_idx;
    for (trigger_idx = 0; trigger_idx < state_curr->trigger_len; trigger_idx++) {
      printf("------ The trigger idx is %d ------\n", trigger_idx);
      trigger* trigger_curr = state_curr->ptr + trigger_idx;
      char* symbol_curr = trigger_curr->term;
      struct terminal_arr* terminal_arr_curr;
      r = hashmap_get(m, symbol_curr, (any_t*)&terminal_arr_curr);
      if (r) {
        // the symbol is not in the map
        printf("Symbol %s is not in map\n", symbol_curr);
        struct terminal_arr* new_terminal_arr = (struct terminal_arr*)malloc(sizeof(struct terminal_arr));
        new_terminal_arr->start = (struct terminal_meta*)calloc(numstates, sizeof(struct terminal_meta));
        printf("allocate new memory address %p\n", new_terminal_arr->start);
        new_terminal_arr->start->state_name = state_idx;
        new_terminal_arr->start->dest = trigger_curr->dest;
        new_terminal_arr->start->trigger_idx = trigger_idx;
        new_terminal_arr->len = 1;
        printf("Symbol %s is included in %zu edges\n", symbol_curr, new_terminal_arr->len);
        r = hashmap_put(m, symbol_curr, new_terminal_arr);
        if (r) {
          printf("hashmap put failed\n");
        }
        else {
          printf("hashmap put succeeded\n");
        }
      }
      else {
        // the symbol is already in map
        // append to terminal array
        // no need to touch start
        printf("Symbol %s is in map\n", symbol_curr);
        struct terminal_meta* modify = terminal_arr_curr->start + terminal_arr_curr->len;
        modify->state_name = state_idx;
        modify->trigger_idx = trigger_idx;
        modify->dest = trigger_curr->dest;
        terminal_arr_curr->len++;
        printf("Symbol %s is included in %zu edges\n", symbol_curr, terminal_arr_curr->len);
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
  // Array * res;
  // res = (Array *)calloc(1, sizeof(Array));
  // initArray(res, INIT_SIZE);
  map_t m = create_pda_hashmap((struct state*)pda);
  free_hashmap(m);
  // free(res);
  free(pda);
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

