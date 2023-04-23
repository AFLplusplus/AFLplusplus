#include <afl-fuzz.h> 

typedef s64 (*fcallback_t) (u64, u64);
typedef u8 (*fconstraint_t)(s64);

typedef struct kale_function_info {
    fcallback_t callback;
    fconstraint_t constraint;
} kale_function_info_t;

kale_function_info_t kale_get_function_from_type(unsigned attributes); 