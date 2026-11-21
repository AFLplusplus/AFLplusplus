/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* Persistent-state crash fixture. The first input is safe; after 100
   iterations any input crashes. VERIFY_CRASH_TEST_FRESH also makes inputs
   longer than one byte crash on their first execution. */
#include <stdlib.h>
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(void) {

  volatile unsigned int prior_input = 0;
  __AFL_INIT();
  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
  while (__AFL_LOOP(1000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;
    if (len > 0 && buf[0] == 'C') abort();
    if (getenv("VERIFY_CRASH_TEST_FRESH") && len >= 2) abort();
    if (!getenv("VERIFY_CRASH_TEST_FRESH") && prior_input >= 20) abort();
    prior_input++;

  }

  return 0;

}

