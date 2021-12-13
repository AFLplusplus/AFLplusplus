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

  /* negative zero */
  a = 1.0 / -(1.0 / 0.0);                                     /* negative 0 */
  b = 0.0;                                                    /* positive 0 */
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

  a = 1.0 / -(1.0 / 0.0);                                     /* negative 0 */
  b = 1.0 / -(1.0 / 0.0);                                     /* negative 0 */
  assert(!(a < b));
  assert((a <= b));
  assert(!(a > b));
  assert((a >= b));
  assert(!(a != b));
  assert((a == b));

}

