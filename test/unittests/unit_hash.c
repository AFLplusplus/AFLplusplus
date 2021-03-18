#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <assert.h>
#include <cmocka.h>
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
#include "hash.h"

/* remap exit -> assert, then use cmocka's mock_assert
    (compile with `--wrap=exit`) */
extern void exit(int status);
extern void __real_exit(int status);
void __wrap_exit(int status);
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
static void test_hash(void **state) {
    (void)state;

    char bitmap[64] = {0};
    u64 hash0 = hash64(bitmap, sizeof(bitmap), 0xa5b35705);

    bitmap[10] = 1;
    u64 hash1 = hash64(bitmap, sizeof(bitmap), 0xa5b35705);

    assert_int_not_equal(hash0, hash1);

    bitmap[10] = 0;
    assert_int_equal(hash0, hash64(bitmap, sizeof(bitmap), 0xa5b35705));

    bitmap[10] = 1;
    assert_int_equal(hash1, hash64(bitmap, sizeof(bitmap), 0xa5b35705));

}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_hash)
    };

    //return cmocka_run_group_tests (tests, setup, teardown);
    __real_exit( cmocka_run_group_tests (tests, NULL, NULL) );

    // fake return for dumb compilers
    return 0;
}
