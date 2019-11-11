#include <inttypes.h>
#include <stddef.h>

extern void radamsa_init();

extern size_t radamsa_mutate(uint8_t *ptr, size_t len, uint8_t *target, size_t max, unsigned int seed);

extern size_t radamsa_mutate_inplace(uint8_t *ptr, size_t len, size_t max, unsigned int seed);


