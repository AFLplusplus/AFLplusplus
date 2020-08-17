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

void __wrap_exit(int status);
/* remap exit -> assert, then use cmocka's mock_assert
    (compile with `--wrap=exit`) */
extern void exit(int status);
extern void __real_exit(int status);
void __wrap_exit(int status) {
    (void) status;
    assert(0);
}

int __wrap_printf(const char *format, ...);
/* ignore all printfs */
#undef printf
extern int printf(const char *format, ...);
//extern int __real_printf(const char *format, ...);
int __wrap_printf(const char *format, ...) {
    (void)format;
    return 1;
}

#define VOID_BUF (void **)&buf

static void *create_fake_maybe_grow_of(size_t size) {

    size += AFL_ALLOC_SIZE_OFFSET;

    // fake a realloc buf
    
    struct afl_alloc_buf *buf = malloc(size);
    if (!buf) {
        perror("Could not allocate fake buf");
        return NULL;
    }
    buf->complete_size = size; // The size
    void *actual_buf = (void *)(buf->buf);
    return actual_buf;

}

/*
static int setup(void **state) {

    return 0;

}
*/

static void test_pow2(void **state) {
    (void)state;

    assert_int_equal(next_pow2(64), 64);
    assert_int_equal(next_pow2(63), 64);
    assert_int_not_equal(next_pow2(65), 65);
    assert_int_equal(next_pow2(0x100), 0x100);
    assert_int_equal(next_pow2(0x180), 0x200);
    assert_int_equal(next_pow2(108), 0x80);
    assert_int_equal(next_pow2(0), 0);
    assert_int_equal(next_pow2(1), 1);
    assert_int_equal(next_pow2(2), 2);
    assert_int_equal(next_pow2(3), 4);
    assert_int_equal(next_pow2(0xFFFFFF), 0x1000000);
    assert_int_equal(next_pow2(0xFFFFFFF), 0x10000000);
    assert_int_equal(next_pow2(0xFFFFFF0), 0x10000000);
    assert_int_equal(next_pow2(SIZE_MAX), 0);
    assert_int_equal(next_pow2(-1), 0);
    assert_int_equal(next_pow2(-2), 0);

}

static void test_null_allocs(void **state) {
    (void)state;

    void *buf = NULL;
    void *ptr = afl_realloc(VOID_BUF, 100);
    if (unlikely(!buf)) { PFATAL("alloc"); }
    size_t size = afl_alloc_bufsize(buf);
    assert_true(buf == ptr);
    assert_true(size >= 100);
    afl_free(ptr);

}

static void test_nonpow2_size(void **state) {
    (void)state;

    char *buf = create_fake_maybe_grow_of(150);

    buf[140] = '5';

    char *ptr = afl_realloc(VOID_BUF, 160);
    if (unlikely(!ptr)) { PFATAL("alloc"); }
    size_t size = afl_alloc_bufsize(buf);
    assert_ptr_equal(buf, ptr);
    assert_true(size >= 160);
    assert_true(buf[140] == '5');
    afl_free(ptr);

}

static void test_zero_size(void **state) {
    (void)state;

    char *buf = NULL;
    size_t size = 0;
    char *new_buf = afl_realloc(VOID_BUF, 0);
    assert_non_null(new_buf);
    assert_ptr_equal(buf, new_buf);
    afl_free(buf);
    buf = NULL;
    size = 0;

    char *ptr = afl_realloc(VOID_BUF, 100);
    if (unlikely(!ptr)) { PFATAL("alloc"); }
    size = afl_alloc_bufsize(buf);
    assert_non_null(ptr);
    assert_ptr_equal(buf, ptr);
    assert_true(size >= 100);

    afl_free(ptr);

}


static void test_unchanged_size(void **state) {
    (void)state;

    // fake a realloc buf
    void *actual_buf = create_fake_maybe_grow_of(100);

    void *buf_before = actual_buf;
    void *buf_after = afl_realloc(&actual_buf, 100);
    if (unlikely(!buf_after)) { PFATAL("alloc"); }
    assert_ptr_equal(actual_buf, buf_after);
    assert_ptr_equal(buf_after, buf_before);
    afl_free(buf_after);

}

static void test_grow_multiple(void **state) {
    (void)state;

    char *buf = NULL;
    size_t size = 0;

    char *ptr = afl_realloc(VOID_BUF, 100);
    if (unlikely(!ptr)) { PFATAL("alloc"); }
    size = afl_alloc_bufsize(ptr);
    assert_ptr_equal(ptr, buf);
    assert_true(size >= 100);
    assert_int_equal(size, next_pow2(size) - AFL_ALLOC_SIZE_OFFSET);
    buf[50] = '5';

    ptr = (char *)afl_realloc(VOID_BUF, 1000);
    if (unlikely(!ptr)) { PFATAL("alloc"); }
    size = afl_alloc_bufsize(ptr);
    assert_ptr_equal(ptr, buf);
    assert_true(size >= 100);
    assert_int_equal(size, next_pow2(size) - AFL_ALLOC_SIZE_OFFSET);
    buf[500] = '5';

    ptr = (char *)afl_realloc(VOID_BUF, 10000);
    if (unlikely(!ptr)) { PFATAL("alloc"); }
    size = afl_alloc_bufsize(ptr);
    assert_ptr_equal(ptr, buf);
    assert_true(size >= 10000);
    assert_int_equal(size, next_pow2(size) - AFL_ALLOC_SIZE_OFFSET);
    buf[5000] = '5';

    assert_int_equal(buf[50], '5');
    assert_int_equal(buf[500], '5');
    assert_int_equal(buf[5000], '5');

    afl_free(buf);

}

/*
static int teardown(void **state) {

    return 0;

}
*/

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_pow2),
		cmocka_unit_test(test_null_allocs),
		cmocka_unit_test(test_nonpow2_size),
		cmocka_unit_test(test_zero_size),
        cmocka_unit_test(test_unchanged_size),
        cmocka_unit_test(test_grow_multiple),
	};

    //return cmocka_run_group_tests (tests, setup, teardown);
    __real_exit( cmocka_run_group_tests (tests, NULL, NULL) );

    // fake return for dumb compilers
    return 0;
}
