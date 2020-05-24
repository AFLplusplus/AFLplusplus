#include "afl-fuzz.h"
#include "list.h"

typedef struct afl_executor
{
    bool has_forkserver;
    bool has_fauxserver;
    afl_state_t * afl_state;
    u32 map_size;
} afl_executor_t;

typedef struct executors
{
    list_t executors_list;
    u8 number_of_executors;
    /* data */
} afl_executors;


