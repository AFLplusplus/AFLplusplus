#include <inttypes.h>
#include <stddef.h>

void radamsa_init(void);

size_t radamsa(uint8_t *ptr, size_t len, uint8_t *target, size_t max,
               unsigned int seed);

size_t radamsa_inplace(uint8_t *ptr, size_t len, size_t max, unsigned int seed);

