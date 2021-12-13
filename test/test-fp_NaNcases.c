/* test cases for floating point comparison transformations
 * compile with -DFLOAT_TYPE=float
 *          or  -DFLOAT_TYPE=double
 *          or  -DFLOAT_TYPE="long double"
 */

#include <assert.h>
#define _GNU_SOURCE
#include <math.h>                           /* for NaNs and infinity values */

int main() {

  volatile FLOAT_TYPE a, b;

  /* NaN */
#ifdef NAN
  a = (FLOAT_TYPE)NAN;                                      /* produces NaN */
#else
  a = 0.0 / 0.0;                                            /* produces NaN */
#endif
#ifdef INFINITY
  FLOAT_TYPE inf = (FLOAT_TYPE)INFINITY;
#else
  FLOAT_TYPE inf = 1.0 / 0.0;                          /* produces infinity */
#endif
  FLOAT_TYPE negZero = 1.0 / -inf;
  FLOAT_TYPE posZero = 0.0;
  b = a;

  assert(!(a < b));
  assert(!(a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  b = 0.0;
  assert(!(a < b));
  assert(!(a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  b = 1.0 / -(1.0 / 0.0);                                     /* negative 0 */
  assert(!(a < b));
  assert(!(a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  b = 42.0;
  assert(!(a < b));
  assert(!(a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  b = -42.0;
  assert(!(a < b));
  assert(!(a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  b = (1.0 / 0.0);                                     /* positive infinity */
  assert(!(a < b));
  assert(!(a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

  b = -(1.0 / 0.0);                                    /* negative infinity */
  assert(!(a < b));
  assert(!(a <= b));
  assert(!(a > b));
  assert(!(a >= b));
  assert((a != b));
  assert(!(a == b));

}

