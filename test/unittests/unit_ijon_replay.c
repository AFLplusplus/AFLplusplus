#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "types.h"
#include "alloc-inl.h"
#include "afl-ijon-min.h"

int main(void) {

  int             result = 0;
  char            root[] = "/tmp/afl-ijon-unit.XXXXXX";
  char            dir[256] = {0};
  char            input_path[256] = {0};
  u8             *data = NULL;
  u8             *input = NULL;
  ijon_min_state *state = NULL;

  if (!mkdtemp(root)) { return 1; }
  if (snprintf(dir, sizeof(dir), "%s/max", root) < 0 ||
      snprintf(input_path, sizeof(input_path), "%s/3", dir) < 0) {

    result = 2;
    goto cleanup;

  }

  data = malloc(100000);
  if (!data) {

    result = 3;
    goto cleanup;

  }

  memset(data, 0xa5, 100000);
  state = new_ijon_min_state_with_limit(dir, 100000);
  ijon_store_max_input(state, 3, data, 100000);
  destroy_ijon_min_state(state);

  state = new_ijon_min_state_with_limit(dir, 100000);
  if (state->num_entries != 1) {

    result = 4;
    goto cleanup;

  }

  u64                     max_area[MAP_SIZE_IJON_ENTRIES] = {0};
  dynamic_shared_access_t shared = {.ijon_max_area = max_area};
  u8                      nominal = 0;
  max_area[3] = 32;
  ijon_update_max_dynamic(state, &shared, &nominal, 1);
  if (!state->persisted[3] || state->infos[3]->len != 100000) {

    result = 5;
    goto cleanup;

  }

  for (u32 i = 0; i < IJON_REPLAY_INTERVAL - 1; ++i) {

    if (ijon_should_schedule(state)) {

      result = 6;
      goto cleanup;

    }

  }

  if (!ijon_should_schedule(state)) {

    result = 7;
    goto cleanup;

  }

  ijon_input_info *info = ijon_get_input(state);
  if (!info || info->slot_id != 3 || state->persisted[3]) {

    result = 8;
    goto cleanup;

  }

  ijon_update_max_dynamic(state, &shared, &nominal, 1);
  if (state->infos[3]->len != 100000 || state->max_map[3] != 32) {

    result = 11;
    goto cleanup;

  }

  u32 len = 0;
  if (!ijon_read_input(state, info, &input, &len) || len != 100000 ||
      memcmp(input, data, 100000)) {

    result = 9;

  }

  if (!result) {

    unlink(input_path);
    ijon_load_existing_state(state);
    if (state->num_entries || state->max_map[3] || state->infos[3]->len ||
        state->persisted[3]) {

      result = 10;

    }

  }

cleanup:
  if (input) { afl_free(input); }
  if (state) { destroy_ijon_min_state(state); }
  free(data);
  unlink(input_path);
  rmdir(dir);
  rmdir(root);
  return result;

}

