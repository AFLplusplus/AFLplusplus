//
// This is an example on how to use afl_custom_send
// It writes each mutated data set to /tmp/foo
// You can modify this to send to IPC, shared memory, etc.
//
// cc -O3 -fPIC -shared -g -o custom_send.so -I../../include custom_send.c
// cd ../..
// afl-cc -o test-instr test-instr.c
// AFL_CUSTOM_MUTATOR_LIBRARY=custom_mutators/examples/custom_send.so \
//   afl-fuzz -i in -o out -- ./test-instr -f /tmp/foo
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "afl-fuzz.h"

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

void afl_custom_fuzz_send(my_mutator_t *data, uint8_t *buf, size_t buf_size) {

  int fd = open("/tmp/foo", O_CREAT | O_NOFOLLOW | O_TRUNC | O_RDWR, 0644);

  if (fd >= 0) {

    (void)write(fd, buf, buf_size);
    close(fd);

  }

  return;

}

void afl_custom_deinit(my_mutator_t *data) {

  free(data);

}

