#include "mutator.h"
#include "cmp-functions.h"

#include <cmplog.h>

Angora* afl_custom_init(afl_state_t* afl, unsigned int seed){
    Angora* data = calloc(1, sizeof(Angora));

    data->afl = afl;

    return data;
}

uint8_t afl_custom_queue_get(Angora *data, const uint8_t *filename) {

  return 0;
}

size_t afl_custom_fuzz(void* udata, unsigned char *buf, size_t buf_size, unsigned char **out_buf, unsigned char *add_buf, size_t add_buf_size, size_t max_size){
  const int learningRate = 2;

  Angora* data = (Angora*)udata;
  afl_state_t* afl = data->afl;

  unsigned char* orig_buf = ck_alloc(buf_size);

  // The gradient of each dy/dx_i for every cmplog entry
  // TODO: Allocate globally for performance
  u8* gradients = ck_alloc(buf_size * sizeof(u8) * CMP_MAP_W);
  memset(gradients, 0, buf_size * sizeof(u8) * CMP_MAP_W);

  // Save the original map
  memcpy(afl->orig_cmp_map, afl->shm.cmp_map, sizeof(struct cmp_map));
  for (size_t i = 0; i < buf_size; i++){
    memset(afl->shm.cmp_map->headers, 0, sizeof(struct cmp_header) * CMP_MAP_W);

    buf[i] += 1;

    if (unlikely(common_fuzz_cmplog_stuff(afl, buf, buf_size))) {
      return 0;
    }

    // Check for deltas
    for(u32 k = 0; k < CMP_MAP_W; k++){
      if(!afl->shm.cmp_map->headers[k].hits) 
        continue;

      if(afl->shm.cmp_map->headers[k].id != afl->orig_cmp_map->headers[k].id) 
        continue;

      if(afl->shm.cmp_map->headers[k].type == CMP_TYPE_INS){
        // Angora the if statement
        unsigned attributes = afl->shm.cmp_map->headers[k].attribute;
        kale_function_info_t f = kale_get_function_from_type(attributes);
        
        u64 fprime = f.callback(afl->shm.cmp_map->log[k][0].v0, afl->shm.cmp_map->log[k][0].v1);
        u64 f0 = f.callback(afl->orig_cmp_map->log[k][0].v0, afl->orig_cmp_map->log[k][0].v1);

        gradients[k*CMP_MAP_W + i] = (fprime - f0) / 1;
      }

    }


    buf[i] -= 1; 
  }

  // Do gradient descent
  for(int i = 0; i < buf_size; i++){
    buf[i] -= learningRate * gradients[i];
  }

  memcpy(buf, orig_buf, buf_size);

  ck_free(gradients);
  ck_free(orig_buf);


  return 0;
}

void afl_custom_deinit(Angora* afl){
}