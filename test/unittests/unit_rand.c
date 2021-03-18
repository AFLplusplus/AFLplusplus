#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <assert.h>
#include <cmocka.h>
#include <sys/stat.h>
#include <fcntl.h>
/* cmocka < 1.0 didn't support these features we need */
#ifndef assert_ptr_equal
#define assert_ptr_equal(a, b) \
    _assert_int_equal(cast_ptr_to_largest_integral_type(a), \
                      cast_ptr_to_largest_integral_type(b), \
                      __FILE__, __LINE__)
#define CMUnitTest UnitTest
#define cmocka_unit_test unit_test
#define cmocka_run_group_tests(t, setup, teardown) run_tests(t)
#endif


extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);

#include "afl-fuzz.h"

/* remap exit -> assert, then use cmocka's mock_assert
    (compile with `--wrap=exit`) */
extern void exit(int status);
extern void __real_exit(int status);
//void __wrap_exit(int status);
void __wrap_exit(int status) {
    (void)status;
    assert(0);
}

/* ignore all printfs */
#undef printf
extern int printf(const char *format, ...);
extern int __real_printf(const char *format, ...);
int __wrap_printf(const char *format, ...);
int __wrap_printf(const char *format, ...) {
    (void)format;
    return 1;
}

/* Rand with 0 seed would broke in the past */
static void test_rand_0(void **state) {
    (void)state;

    afl_state_t afl = {0};
    rand_set_seed(&afl, 0);

    /* give this one chance to retry */
    assert_int_not_equal(
        (rand_next(&afl) != rand_next(&afl)
            || rand_next(&afl) != rand_next(&afl))
            , 0);

}

static void test_rand_below(void **state) {
    (void)state;

    afl_state_t afl = {0};
    rand_set_seed(&afl, 1337);

    afl.fsrv.dev_urandom_fd = open("/dev/urandom", O_RDONLY);

    assert(!(rand_below(&afl, 9000) > 9000));
    assert_int_equal(rand_below(&afl, 1), 0);

}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_rand_0),
        cmocka_unit_test(test_rand_below)
    };

    //return cmocka_run_group_tests (tests, setup, teardown);
    __real_exit( cmocka_run_group_tests (tests, NULL, NULL) );

    // fake return for dumb compilers
    return 0;
}
