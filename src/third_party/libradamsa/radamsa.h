#include <inttypes.h>
#include <stddef.h>

extern void radamsa_init();

extern size_t radamsa(uint8_t *ptr, size_t len, 
                      uint8_t *target, size_t max, 
                      unsigned int seed);

extern size_t radamsa_inplace(uint8_t *ptr, 
                              size_t len, 
                              size_t max, 
                              unsigned int seed);


