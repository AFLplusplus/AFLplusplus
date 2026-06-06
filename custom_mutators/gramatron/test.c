/* This is the testing module for Gramatron
 */
#include "afl-fuzz.h"
#include "gramfuzz.h"
#include "gramfuzz-rng.h"
#define NUMINPUTS 50
int gf_standalone_mode = 1;
state *create_pda(u8 *automaton_file) {

  cJSON              *parsed_json;
  state              *pda;
  cJSON              *source_obj, *attr;
  int                arraylen, ii, ii2, trigger_len, error;

  printf("\n[GF] Automaton file passed:%s", automaton_file);
  // parsed_json =
  // json_object_from_file("./gramfuzz/php_gnf_processed_full.json");
  parsed_json = load_json_file(automaton_file);

  // Getting final state
  source_obj = cJSON_GetObjectItem(parsed_json, "final_state");
  const char *final_state_obj = source_obj->valuestring;
  printf("\t\nFinal=%s\n",final_state_obj);
  final_state = atoi(final_state_obj);

  // Getting initial state
  source_obj = cJSON_GetObjectItem(parsed_json, "init_state");
  const char *init_state_obj = source_obj->valuestring;
  init_state = atoi(init_state_obj);
  printf("\tInit=%s\n", init_state_obj);

  // Getting number of states
  source_obj = cJSON_GetObjectItem(parsed_json, "numstates");
  numstates = source_obj->valueint + 1;
  printf("\tNumStates=%d\n", numstates);

  // Allocate state space for each pda state
  pda = (state *)calloc(numstates + 1,
                        sizeof(state));

  // Getting PDA representation
  source_obj = cJSON_GetObjectItem(parsed_json, "pda");
  cJSON * state_item;
  cJSON_ArrayForEach(state_item,source_obj) {

    state   *state_ptr;
    trigger *trigger_ptr;
    int      offset;

    // Get the correct offset into the pda to store state information
    state_ptr = pda;
    offset = atoi(state_item->string);
    state_ptr += offset;

    // Store state string
    state_ptr->state_name = offset;

    // Create trigger array of structs
    trigger_len = cJSON_GetArraySize(state_item);
    state_ptr->trigger_len = trigger_len;
    trigger_ptr = (trigger *)calloc(trigger_len, sizeof(trigger));
    state_ptr->ptr = trigger_ptr;
    printf("\nName:%d Trigger:%d", offset, trigger_len);

    for (ii = 0; ii < trigger_len; ii++) {

      cJSON *obj = cJSON_GetArrayItem(state_item, ii);
      // Get all the trigger trigger attributes
      attr = cJSON_GetArrayItem(obj, 0);
      (trigger_ptr)->id = strdup(attr->valuestring);

      attr = cJSON_GetArrayItem(obj, 1);
      trigger_ptr->dest = atoi(attr->valuestring);

      attr = cJSON_GetArrayItem(obj, 2);
      if (!strcmp("\\n", attr->valuestring)) {

        trigger_ptr->term = strdup("\n");

      } else {

        trigger_ptr->term = strdup(attr->valuestring);

      }

      trigger_ptr->term_len = strlen(trigger_ptr->term);
      trigger_ptr++;

    }

  }

  // Delete the JSON object
  cJSON_Delete(parsed_json);

  return pda;

}

void SanityCheck(char *automaton_path) {

  state         *pda = create_pda(automaton_path);
  int            count = 0, state;
  Get_Dupes_Ret *getdupesret;
  IdxMap_new    *statemap;
  IdxMap_new    *statemap_ptr;
  terminal      *term_ptr;

  while (count < NUMINPUTS) {

    // Perform input generation
    Array *generated = gen_input(pda, NULL);
    print_repr(generated, "Gen");
    count += 1;

  }

}

int main(int argc, char *argv[]) {
  char          *mode;
  char          *automaton_path;
  char          *output_dir = NULL;
  struct timeval tv;
  struct timeval tz;
  // gettimeofday(&tv, &tz);
  srand(1337);
  if (argc == 3) {

    mode = argv[1];
    automaton_path = strdup(argv[2]);
    printf("\nMode:%s Path:%s", mode, automaton_path);

  } else {

    printf("\nUsage: ./test <mode> <automaton_path>");
    return -1;

  }

  if (!strcmp(mode, "SanityCheck")) {

    SanityCheck(automaton_path);

  } else {

    printf("\nUnrecognized mode");
    return -1;

  }

  return 0;

}

