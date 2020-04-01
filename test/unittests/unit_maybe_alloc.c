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
#include "alloc-inl.h"

/* remap exit -> assert, then use cmocka's mock_assert
    (compile with `--wrap=exit`) */
extern void exit(int status);
extern void __real_exit(int status);
void __wrap_exit(int status) {
    assert(0);
}

/* ignore all printfs */
extern int printf(const char *format, ...);
extern int __real_printf(const char *format, ...);
int __wrap_printf(const char *format, ...) {
    return 1;
}

#define BUF_PARAMS (void **)&buf, &size

/*
static int setup(void **state) {

    return 0;

}
*/

static void test_null_allocs(void **state) {

    void *buf = NULL;
    size_t size = 0;
    void *ptr = ck_maybe_grow(BUF_PARAMS, 100);
    assert_true(buf == ptr);
    assert_true(size >= 100);
    ck_free(ptr);

}

static void test_nonpow2_size(void **state) {

    char *buf = ck_alloc(150);
    size_t size = 150;
    buf[140] = '5';
    char *ptr = ck_maybe_grow(BUF_PARAMS, 160);
    assert_ptr_equal(buf, ptr);
    assert_true(size >= 160);
    assert_true(buf[140] == '5');
    ck_free(ptr);

}

static void test_zero_size() {

    char *buf = NULL;
    size_t size = 0;
    assert_non_null(maybe_grow(BUF_PARAMS, 0));
    free(buf);
    buf = NULL;
    size = 0;

    char *ptr = ck_maybe_grow(BUF_PARAMS, 100);
    assert_non_null(ptr);
    assert_ptr_equal(buf, ptr);
    assert_true(size >= 100);

    expect_assert_failure(ck_maybe_grow(BUF_PARAMS, 0));

    ck_free(ptr);

}

static void test_unchanged_size(void **state) {

    void *buf = ck_alloc(100);
    size_t size = 100;
    void *buf_before = buf;
    void *buf_after = ck_maybe_grow(BUF_PARAMS, 100);
    assert_ptr_equal(buf, buf_after);
    assert_ptr_equal(buf_after, buf_before);
    ck_free(buf);

}

static void test_grow_multiple(void **state) {

    char *buf = NULL;
    size_t size = 0;

    char *ptr = ck_maybe_grow(BUF_PARAMS, 100);
    assert_ptr_equal(ptr, buf);
    assert_true(size >= 100);
    assert_int_equal(size, next_pow2(size));
    buf[50] = '5';

    ptr = (char *)ck_maybe_grow(BUF_PARAMS, 1000);
    assert_ptr_equal(ptr, buf);
    assert_true(size >= 100);
    assert_int_equal(size, next_pow2(size));
    buf[500] = '5';

    ptr = (char *)ck_maybe_grow(BUF_PARAMS, 10000);
    assert_ptr_equal(ptr, buf);
    assert_true(size >= 10000);
    assert_int_equal(size, next_pow2(size));
    buf[5000] = '5';

    assert_int_equal(buf[50], '5');
    assert_int_equal(buf[500], '5');
    assert_int_equal(buf[5000], '5');

    ck_free(buf);

}

/*
static int teardown(void **state) {

    return 0;

}
*/

int main(int argc, char **argv) {

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_null_allocs),
		cmocka_unit_test(test_nonpow2_size),
		cmocka_unit_test(test_zero_size),
        cmocka_unit_test(test_unchanged_size),
        cmocka_unit_test(test_grow_multiple),
	};

    //return cmocka_run_group_tests (tests, setup, teardown);
    return cmocka_run_group_tests (tests, NULL, NULL);

}
