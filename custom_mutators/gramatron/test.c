/* This is the testing module for Gramatron
 */
#include "afl-fuzz.h"
#include "gramfuzz.h"

#define NUMINPUTS 50
#define MAX_PROGRAM_LENGTH 2000
#define MAX_WALK_LENGTH 1000 // maximum length of terminals in a walk

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

typedef struct {

  size_t t;

} test;

// TODO: generate a map
// map a symbol to (state, trigger_idx)
void create_pda_hashmap() {
  // tryout hashmap
  map_t m = hashmap_new();
  char k[100] = "key";
  test* vptr = (test *)malloc(sizeof(test));
  vptr->t = 9;
  any_t v = vptr;
  any_t grptr;
  int r = hashmap_put(m, k, v);
  if (!r) {
    printf("add elements to hashmap succeed\n");
    int gr = hashmap_get(m, k, vptr);
    printf("%d\n", gr);
  }
  else {printf("fail\n");}
  free(vptr);
}


int main(int argc, char *argv[]) {
  char automaton_path[] = "/root/gramatron-artifact/grammars/gt_bugs/mruby-1/source_automata.json";
  char * pda = create_pda(automaton_path);
  char program_path[] = "/root/gramatron-artifact/fuzzers/AFLplusplus/custom_mutators/gramatron/example";
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
  res = (Array *)calloc(1, sizeof(Array));
  initArray(res, INIT_SIZE);
  create_pda_hashmap();
  free(res);
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

