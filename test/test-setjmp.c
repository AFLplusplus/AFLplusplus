/*
   Test case for GCC plugin setjmp/returns_twice instrumentation fix.

   GCC 13+ requires returns_twice calls (like setjmp, sigsetjmp) to be the
   first instruction in their basic block. This test verifies that AFL++'s
   GCC plugin correctly handles this by creating trampoline blocks for
   instrumentation.

   See GitHub issue: https://github.com/AFLplusplus/AFLplusplus/issues/2541.
*/

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>

jmp_buf    env;
sigjmp_buf sigenv;
int        counter = 0;

void bar(void) {

}

void test_setjmp(void) {

  bar();
  if (setjmp(env) == 0) {

    /* First return from setjmp.  */
    counter++;
    if (counter < 2) { longjmp(env, 1); }

  } else {

    /* Returned from longjmp.  */
    counter++;

  }

}

void test_sigsetjmp(void) {

  bar();
  if (sigsetjmp(sigenv, 1) == 0) {

    /* First return from sigsetjmp.  */
    counter++;
    if (counter < 4) { siglongjmp(sigenv, 1); }

  } else {

    /* Returned from siglongjmp.  */
    counter++;

  }

}

int main(int argc, char **argv) {

  (void)argc;
  (void)argv;

  test_setjmp();
  test_sigsetjmp();

  /* Verify setjmp/longjmp worked correctly.  */
  if (counter != 4) {

    fprintf(stderr, "Error: counter=%d, expected 4\n", counter);
    return 1;

  }

  return 0;

}

