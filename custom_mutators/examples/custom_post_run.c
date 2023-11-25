//
// This is an example on how to use afl_custom_post_run
// It executes custom code each time after AFL++ executes the target
//
// cc -O3 -fPIC -shared -g -o custom_post_run.so -I../../include custom_post_run.c
// cd ../..
// afl-cc -o test-instr test-instr.c
// AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/examples/custom_post_run.so \
//   afl-fuzz -i in -o out -- ./test-instr -f /tmp/foo
//


#include "afl-fuzz.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct my_mutator {

  afl_state_t *afl;

} my_mutator_t;

my_mutator_t *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  my_mutator_t *data = calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  data->afl = afl;

  return data;

}

void afl_custom_post_run(my_mutator_t *data) {

  printf("hello from afl_custom_post_run\n");
  return;
}


void afl_custom_deinit(my_mutator_t *data) {

  free(data);

}