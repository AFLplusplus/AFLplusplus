#include "custom_mutator_helpers.h"

typedef struct Angora{
    afl_t* afl;
}Angora;

Angora* afl_custom_init(afl_t* afl, unsigned int seed){
    Angora* data = calloc(1, sizeof(Angora));

    data->afl = afl;

    return data;
}

uint8_t afl_custom_queue_get(Angora *data, const uint8_t *filename) {

  return 0;

}

size_t afl_custom_fuzz(void *data, unsigned char *buf, size_t buf_size, unsigned char **out_buf, unsigned char *add_buf, size_t add_buf_size, size_t max_size){

    return 0;
}

void afl_custom_deinit(Angora* afl){
}