/*
 * <tested_file_path>src/utils/utils_refcnt.c</tested_file_path>
 * <tested_function>ocf_refcnt_register_zero_cb</tested_function>
 * <functions_to_leave>
 * ocf_refcnt_init
 * ocf_refcnt_inc
 * ocf_refcnt_dec
 * ocf_refcnt_freeze
* </functions_to_leave>
 */

#undef static

#undef inline


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

#include "../utils/utils_refcnt.h"

static void zero_cb(void *ctx)
{
	*(volatile int *)ctx = 1;
}

static void ocf_refcnt_register_zero_cb_test01(void **state)
{
	struct ocf_refcnt rc;
	int _cb_cnt = 0;
	volatile int *cb_cnt = &_cb_cnt;
	int val;

	print_test_description("Callback fires when counter drops to 0");

	ocf_refcnt_init(&rc);
	ocf_refcnt_inc(&rc);
	ocf_refcnt_inc(&rc);
	ocf_refcnt_freeze(&rc);

	ocf_refcnt_register_zero_cb(&rc, zero_cb, cb_cnt);

	assert_int_equal(0, *cb_cnt);

	ocf_refcnt_dec(&rc);
	assert_int_equal(0, *cb_cnt);
	val = env_atomic_read(&rc.callback);
	assert_int_equal(1, val);

	ocf_refcnt_dec(&rc);
	assert_int_equal(1, *cb_cnt);
	val = env_atomic_read(&rc.callback);
	assert_int_equal(0, val);
}

static void ocf_refcnt_register_zero_cb_test02(void **state)
{
	struct ocf_refcnt rc;
	int _cb_cnt = 0;
	volatile int *cb_cnt = &_cb_cnt;
	int val;

	print_test_description("Callback fires when counter is already 0");

	ocf_refcnt_init(&rc);
	ocf_refcnt_freeze(&rc);
	ocf_refcnt_register_zero_cb(&rc, zero_cb, cb_cnt);

	assert_int_equal(1, *cb_cnt);
	val = env_atomic_read(&rc.callback);
	assert_int_equal(0, val);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(ocf_refcnt_register_zero_cb_test01),
		cmocka_unit_test(ocf_refcnt_register_zero_cb_test02),
	};

	print_message("Unit test of src/utils/utils_refcnt.c");

	return cmocka_run_group_tests(tests, NULL, NULL);
}
