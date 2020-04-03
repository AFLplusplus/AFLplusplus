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

#include "list.h"

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

list_t testlist;

static void test_contains(void **state) {

    u32 one = 1;
    u32 two = 2;

    list_append(&testlist, &one);
    assert_true(list_contains(&testlist, &one));
    assert_false(list_contains(&testlist, &two));
    list_remove(&testlist, &one);
    assert_false(list_contains(&testlist, &one));
}

static void test_foreach(void **state) {

    u32 one = 1;
    u32 two = 2;
    u32 result = 0;

    list_append(&testlist, &one);
    list_append(&testlist, &two);
    list_append(&testlist, &one);

    /* The list is for pointers, so int doesn't work as type directly */
    LIST_FOREACH(&testlist, u32, {
        result += *el;
    });

    assert_int_equal(result, 4);

}

static void test_long_list(void **state) {

    u32 result1 = 0;
    u32 result2 = 0;
    u32 i;

    u32 vals[100];

    for (i = 0; i < 100; i++) {
        vals[i] = i;
    }

    LIST_FOREACH_CLEAR(&testlist, void, {});
    for (i = 0; i < 100; i++) {
        list_append(&testlist, &vals[i]);
    }
    LIST_FOREACH(&testlist, u32, {
        result1 += *el;
    });
    //printf("removing %d\n", vals[50]);
    list_remove(&testlist, &vals[50]);

    LIST_FOREACH(&testlist, u32, {
        // printf("var: %d\n", *el);
        result2 += *el;
    });
    assert_int_not_equal(result1, result2);
    assert_int_equal(result1, result2 + 50);

    result1 = 0;
    LIST_FOREACH_CLEAR(&testlist, u32, {
        result1 += *el;
    });
    assert_int_equal(result1, result2);

    result1 = 0;
    LIST_FOREACH(&testlist, u32, {
        result1 += *el;
    });
    assert_int_equal(result1, 0);

}

int main(int argc, char **argv) {

	const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_contains),
        cmocka_unit_test(test_foreach),
        cmocka_unit_test(test_long_list),
	};

    //return cmocka_run_group_tests (tests, setup, teardown);
    return cmocka_run_group_tests (tests, NULL, NULL);

}
