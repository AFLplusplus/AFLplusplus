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

#include "afl-prealloc.h"

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

typedef struct prealloc_me
{
    PREALLOCABLE;

    u8 *content[128];

} prealloc_me_t;

#define PREALLOCED_BUF_SIZE (64)
prealloc_me_t prealloc_me_buf[PREALLOCED_BUF_SIZE];
size_t prealloc_me_size = 0;

static void test_alloc_free(void **state) {

    prealloc_me_t *prealloced = NULL;
    PRE_ALLOC(prealloced, prealloc_me_buf, PREALLOCED_BUF_SIZE, prealloc_me_size);
    assert_non_null(prealloced);
    PRE_FREE(prealloced, prealloc_me_size);

}

static void test_prealloc_overflow(void **state) {

    u32 i = 0;
    prealloc_me_t *prealloced[PREALLOCED_BUF_SIZE + 10];

    for (i = 0; i < PREALLOCED_BUF_SIZE + 10; i++) {

        PRE_ALLOC(prealloced[i], prealloc_me_buf, PREALLOCED_BUF_SIZE, prealloc_me_size);
        assert_non_null(prealloced[i]);

    }
    assert_int_equal(prealloced[0]->pre_status,  PRE_STATUS_USED);
    assert_int_equal(prealloced[PREALLOCED_BUF_SIZE]->pre_status,  PRE_STATUS_MALLOC);

    PRE_FREE(prealloced[20], prealloc_me_size);
    PRE_ALLOC(prealloced[20], prealloc_me_buf, PREALLOCED_BUF_SIZE, prealloc_me_size);
    assert_non_null(prealloced[20]);
    assert_int_equal(prealloced[20]->pre_status,  PRE_STATUS_USED);

    PRE_FREE(prealloced[PREALLOCED_BUF_SIZE], prealloc_me_size);
    PRE_FREE(prealloced[0], prealloc_me_size);
    PRE_ALLOC(prealloced[PREALLOCED_BUF_SIZE], prealloc_me_buf, PREALLOCED_BUF_SIZE, prealloc_me_size);
    assert_non_null(prealloced[PREALLOCED_BUF_SIZE]);
    /* there should be space now! */
    assert_int_equal(prealloced[PREALLOCED_BUF_SIZE]->pre_status,  PRE_STATUS_USED);

    PRE_ALLOC(prealloced[0], prealloc_me_buf, PREALLOCED_BUF_SIZE, prealloc_me_size);
    assert_non_null(prealloced[0]);
    /* no more space */
    assert_int_equal(prealloced[0]->pre_status,  PRE_STATUS_MALLOC);

    for (i = 0; i < PREALLOCED_BUF_SIZE + 10; i++) {

        PRE_FREE(prealloced[i], prealloc_me_size);

    }

}

int main(int argc, char **argv) {

	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_alloc_free),
		cmocka_unit_test(test_prealloc_overflow),
	};

    //return cmocka_run_group_tests (tests, setup, teardown);
    return cmocka_run_group_tests (tests, NULL, NULL);

}
