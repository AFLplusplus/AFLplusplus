#include "afl-fuzz.h"
#include "afl-framework.h"

void * executor_run () {
    //This function runs the exeutor (probably using the afl backend)
}


void * executor_init (afl_executor_t * afl_executor) {

    afl_executor->afl_state = ck_alloc(sizeof(afl_state_t));

    afl_state_init(afl_executor->afl_state, afl_executor->map_size);

}

