/*
 * <tested_file_path>src/eviction/lru.c</tested_file_path>
 * <files_to_link>
 *   src/utils/utils_journal.c
 * </files_to_link>
 * <tested_function>add_lru_head</tested_function>
 * <functions_to_leave>
 * 	update_lru_head
 * 	update_lru_tail
 * 	update_lru_head_tail
 *      _lru_init
 * 	add_lru_head_nobalance
 * 	add_lru_head
 * 	remove_lru_list_nobalance
 * 	remove_lru_list
 * 	remove_update_list
 * 	remove_update_ptrs
 * 	balance_lru_list
 * 	balance_update_last_hot
 * 	evp_lru_get_list
 * 	evp_lru_move
 * 	ocf_get_lru
 *	evp_get_cline_list
 *	evp_lru_init_evp
 *	next_phys_invalid
 *	ocf_lru_populate
 * 	ocf_lru_rollback_remove_dec_count
 *	ocf_lru_rollback_remove_clear_elem
 *	ocf_lru_rollback_balance_update_ctr
 *	ocf_lru_rollback_balance_update_last
 *	ocf_lru_rollback_balance_set_hot
 *	ocf_lru_rollback_insert_lru_head
 *	ocf_lru_rollback_move
 *	ocf_lru_rollback_set_hot
 *	ocf_lru_rollback_parent_get_list
 *	ocf_lru_rollback_balance_get_list
 *	ocf_journal_finish_op
 *      ocf_lru_rollback_remove_update_ptrs
 *      ocf_journal_get_next
 *      ocf_journal_start_op
 *      ocf_journal_op_get_parent
 * 	ocf_journal_recover
 * </functions_to_leave>
 */

#undef static

#undef inline


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

#include "eviction.h"
#include "lru.h"
#include "ops.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../utils/utils_journal.h"
#include "../concurrency/ocf_concurrency.h"
#include "../mngt/ocf_mngt_common.h"
#include "../engine/engine_zero.h"
#include "../ocf_request.h"

#include "eviction/lru.c/lru_journal_generated_wraps.c"

// explicit declarations for wrapped functions
ocf_jop_t __real_ocf_journal_start_op(ocf_jop_t op,
		enum ocf_journal_op_id op_id);
ocf_jop_t __real_ocf_journal_finish_op(ocf_jop_t op);

struct ocf_lru_list *evp_lru_get_list(struct ocf_part_runtime *part,
		uint32_t evp, bool clean);


#include "../utils/utils_journal.c"

#define TEST_CLINES_COUNT 8 * OCF_NUM_EVICTION_LISTS + 1
#define TEST_JOURNAL_SIZE 1024 * 1024

struct test_metadata_state {
	union eviction_policy_meta evp[TEST_CLINES_COUNT];
	ocf_part_id_t part_id[TEST_CLINES_COUNT];
	bool dirty[TEST_CLINES_COUNT];
	bool valid[TEST_CLINES_COUNT];
	struct ocf_part_runtime lru[OCF_IO_CLASS_MAX + 1];
	struct ocf_part_runtime free;
	char journal_buf[TEST_JOURNAL_SIZE];
};

struct test_metadata_state curr_state, state_snapshot;

struct ocf_cache _cache, *cache = &_cache;

static const unsigned end_marker = -1;

void test_state_init()
{
	unsigned i;

	memset(&curr_state, 0, sizeof(curr_state));

	for (i = 0; i <= OCF_IO_CLASS_MAX; i++) {
		cache->user_parts[i].runtime = &curr_state.lru[i];
		evp_lru_init_evp(cache, cache->user_parts[i].runtime);
	}

	for (i = 0; i < TEST_CLINES_COUNT; i++) {
		curr_state.evp[i].lru.next = end_marker;
		curr_state.evp[i].lru.prev = end_marker;
	}

	cache->free = &curr_state.free;
}

void __wrap___assert_fail (const char *__assertion, const char *__file,
      unsigned int __line, const char *__function)
{
       print_message("assertion failure %s in %s:%u %s\n",
               __assertion, __file, __line, __function);
       assert_int_equal(1, 0);
}

ocf_part_id_t __wrap_ocf_metadata_get_partition_id(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	return curr_state.part_id[line];
}

void __wrap_ocf_metadata_set_partition_id(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id)
{
	curr_state.part_id[line] = part_id;
}

bool __wrap_metadata_test_dirty(struct ocf_cache *cache, ocf_cache_line_t line)
{
	return curr_state.dirty[line];
}

bool __wrap_metadata_test_valid_any(struct ocf_cache *cache, ocf_cache_line_t line)
{
	return curr_state.valid[line];
}

ocf_cache_line_t __wrap_ocf_metadata_map_phy2lg(struct ocf_cache *cache, ocf_cache_line_t line)
{
	return line;
}

struct ocf_cache_line_concurrency *__wrap_ocf_cache_line_concurrency(ocf_cache_t cache)
{
	return NULL;
}

ocf_cache_line_t __wrap_ocf_metadata_collision_table_entries(struct ocf_cache *cache)
{
	return TEST_CLINES_COUNT;
}

union eviction_policy_meta*
__wrap_ocf_metadata_get_eviction_policy(ocf_cache_t cache, ocf_cache_line_t line)
{
	assert (line < TEST_CLINES_COUNT);
	return &curr_state.evp[line];
}

struct {
	bool taken;
	bool requested;
	int entry;
	int curr_entry;
} snapshot;

void request_snapshot(int entry)
{
	snapshot.taken = false;
	snapshot.requested = true;
	snapshot.entry = entry;
	snapshot.curr_entry = 0;
}

void metadata_snapshot()
{
	if (snapshot.curr_entry == snapshot.entry && snapshot.requested) {
		state_snapshot = curr_state;
		snapshot.taken = true;
		snapshot.requested = false;
	}

	snapshot.curr_entry++;
}

void metadata_restore_from_snapshot()
{
	curr_state = state_snapshot;
}

ocf_jop_t __wrap_ocf_journal_start_op(ocf_jop_t op,
		enum ocf_journal_op_id op_id)
{
	ocf_jop_t ret;

	metadata_snapshot();
	ret = __real_ocf_journal_start_op(op, op_id);
	metadata_snapshot();

	return ret;
}

ocf_jop_t __wrap_ocf_journal_finish_op(ocf_jop_t op)
{
	ocf_jop_t ret;

	metadata_snapshot();
	ret = __real_ocf_journal_finish_op(op);
	metadata_snapshot();

	return ret;
}

void *g_buf;
struct ocf_journal_schema *g_schema;

void test_schema_init()
{
	g_schema = calloc(sizeof(*g_schema), 1);
	assert(g_schema != NULL);
	ocf_journal_schema_init(g_schema);
}

ocf_journal_t test_prepare_journal()
{
	ocf_journal_t journal;
	int ret;

	ret = ocf_journal_init(cache, g_schema, curr_state.journal_buf,
			sizeof(curr_state.journal_buf), &journal);

	if (!ret) {
		ocf_journal_start(journal);
		return journal;
	} else {
		free(g_buf);
		return NULL;
	}
}

void test_cleanup_journal(ocf_journal_t journal)
{
	ocf_journal_deinit(journal);
	free(g_buf);
}


static void check_hot_elems(struct ocf_lru_list *list)
{
	unsigned i;
	unsigned curr = list->head;

	for (i = 0; i < list->num_hot; i++) {
		assert_int_equal(curr_state.evp[curr].lru.hot, 1);
		curr = curr_state.evp[curr].lru.next;
	}
	for (i = list->num_hot; i < list->num_nodes; i++) {
		assert_int_equal(curr_state.evp[curr].lru.hot, 0);
		curr = curr_state.evp[curr].lru.next;
	}
}

typedef void (* test_step_cb_t)(ocf_cache_t cache, int step, ocf_jop_t op);

void lru_journal_test_step(ocf_journal_t journal, enum ocf_journal_op_id op_id,
		int i, test_step_cb_t step)
{
	ocf_jop_t op;
	unsigned snapshot_step;
	int ret;
	bool recovered;
	struct test_metadata_state initial_state;

	initial_state = curr_state;

	snapshot_step = 0;
	do {
		recovered = false;

		/* request metadata snapshot at some moment during the
		 * transaction*/
		request_snapshot(snapshot_step);

		op = OCF_JOURNAL_OP_INIT_VAL();
		OCF_JOURNAL_TRANSACTION_START(journal, op_id);

		step(cache, i, op);

		if (snapshot.taken) {
			/* restore metadata (including journal) to the state at which
			 * snapshot was taken */
			metadata_restore_from_snapshot();

			/* now curr_state contains metadata and journal
			 * snapshot at step no 'snapshot_step'
			 */
			ret = ocf_journal_init(cache, g_schema, curr_state.journal_buf,
					sizeof(curr_state.journal_buf), &journal);
			assert_int_equal(ret, 0);

			/* only attempt to recover metadata from journal if the transaction is
			 * not finished (it would be finished when we take snapshot after all the steps)
			 */
			if (journal->ring.hdr->started_idx !=  journal->ring.hdr->finished_idx &&
					!is_finished(&journal->ring.buff[journal->ring.hdr->finished_idx])) {
				ocf_journal_recover(cache, journal);
				recovered = true;

				/* metadata should be restored to initial state
				 * except for the journal itself */
				ret = memcmp(&curr_state, &initial_state,
						sizeof(curr_state) - sizeof(curr_state.journal_buf));
				if (ret) {
					ret = memcmp(&curr_state.evp, &initial_state.evp, sizeof(curr_state.evp));
					assert_int_equal(ret, 0);
					ret = memcmp(&curr_state.lru, &initial_state.lru, sizeof(curr_state.lru));
					assert_int_equal(ret, 0);
				}

				assert_int_equal(ret, 0);
			}
		}
		snapshot_step++;
	} while (recovered);

	/* commit transaction and continue to next test iteration */
	OCF_JOURNAL_TRANSACTION_END(journal);
}

void add_head_test_step_do(ocf_cache_t cache, int step, ocf_jop_t op)
{
	ocf_part_id_t part_id = 0;
	struct ocf_part_runtime *part = cache->user_parts[part_id].runtime;
	ocf_cache_line_t cline = step * OCF_NUM_EVICTION_LISTS;
	struct ocf_lru_list *list = evp_lru_get_list(part, cline % OCF_NUM_EVICTION_LISTS, true);

	/* initiate transaction */
	add_lru_head(cache, list, part_id, true, cline, op);

	return op;
}

static void _lru_init_test02(void **state)
{
	ocf_journal_t journal;
	ocf_part_id_t part_id = 0;
	struct ocf_part_runtime *part;
	ocf_cache_line_t cline;
	struct ocf_lru_list *list;
	int i;

	test_state_init();
	//ocf_lru_populate(cache, TEST_CLINES_COUNT);
	journal = test_prepare_journal();
	assert_ptr_not_equal(journal, NULL);

	part = cache->user_parts[part_id].runtime;

	print_test_description("test add\n");

	for (i = 1; i <= 8; i++)
	{
		lru_journal_test_step(journal, ocf_journal_op_id_lru_add, i, add_head_test_step_do);

		cline = i * OCF_NUM_EVICTION_LISTS;
		list = evp_lru_get_list(part, cline % OCF_NUM_EVICTION_LISTS, true);

		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, cline);
		assert_int_equal(list->tail, 1 * OCF_NUM_EVICTION_LISTS);
		assert_int_equal(list->last_hot, i < 2 ? end_marker :
			(i - i / 2 + 1) * OCF_NUM_EVICTION_LISTS);
		check_hot_elems(list);
	}

	test_cleanup_journal(journal);
}

void remove_head_test_step_do(ocf_cache_t cache, int step, ocf_jop_t op)
{
	ocf_part_id_t part_id = 0;
	struct ocf_part_runtime *part = cache->user_parts[part_id].runtime;
	ocf_cache_line_t cline = step * OCF_NUM_EVICTION_LISTS;
	struct ocf_lru_list *list = evp_lru_get_list(part, cline % OCF_NUM_EVICTION_LISTS, true);

	/* initiate transaction */
	remove_lru_list(cache, list, part_id, true, cline, op);
}

static void _lru_init_test03(void **state)
{
	ocf_journal_t journal;
	ocf_part_id_t part_id = 0;
	struct ocf_part_runtime *part;
	ocf_cache_line_t cline;
	struct ocf_lru_list *list;
	int i;

	test_state_init();
	//ocf_lru_populate(cache, TEST_CLINES_COUNT);
	journal = test_prepare_journal();
	assert_ptr_not_equal(journal, NULL);

	part = cache->user_parts[part_id].runtime;

	print_test_description("remove head\n");

	for (i = 1; i <= 8; i++) {
		cline = i * OCF_NUM_EVICTION_LISTS;
		list = evp_lru_get_list(part, cline % OCF_NUM_EVICTION_LISTS, true);
		add_lru_head(cache, list, part_id, true, cline, NULL);
	}


	for (i = 8; i >= 1; i--) {
		cline = i * OCF_NUM_EVICTION_LISTS;
		list = evp_lru_get_list(part, cline % OCF_NUM_EVICTION_LISTS, true);

		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, i * OCF_NUM_EVICTION_LISTS);
		assert_int_equal(list->tail, OCF_NUM_EVICTION_LISTS);
		assert_int_equal(list->last_hot, i < 2 ? end_marker :
				(i - i / 2 + 1) * OCF_NUM_EVICTION_LISTS);
		check_hot_elems(list);

		lru_journal_test_step(journal, ocf_journal_op_id_lru_del, i, remove_head_test_step_do);

		remove_lru_list_nobalance(NULL, list, cline, NULL);
		balance_lru_list(NULL, list, NULL);
	}

	assert_int_equal(list->num_hot, 0);
	assert_int_equal(list->num_nodes, 0);
	assert_int_equal(list->head, end_marker);
	assert_int_equal(list->tail, end_marker);
	assert_int_equal(list->last_hot, end_marker);

	test_cleanup_journal(journal);
}

static void _lru_init_test04(void **state)
{
	struct ocf_lru_list *list;
	unsigned i;

	test_state_init();

	print_test_description("remove tail\n");

	_lru_init(list);

	for (i = 1; i <= 8; i++) {
		add_lru_head_nobalance(NULL, list, i, NULL);
		balance_lru_list(NULL, list, NULL);
	}

	for (i = 8; i >= 1; i--) {
		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, 8);
		assert_int_equal(list->tail, 9 - i);
		assert_int_equal(list->last_hot, i < 2 ? end_marker :
				8 - i / 2 + 1);
		check_hot_elems(list);

		remove_lru_list_nobalance(NULL, list, 9 - i, NULL);
		balance_lru_list(NULL, list, NULL);
	}

	assert_int_equal(list->num_hot, 0);
	assert_int_equal(list->num_nodes, 0);
	assert_int_equal(list->head, end_marker);
	assert_int_equal(list->tail, end_marker);
	assert_int_equal(list->last_hot, end_marker);
}

static void _lru_init_test05(void **state)
{
	struct ocf_lru_list *list;
	unsigned i, j;
	bool present[9];
	unsigned count;

	test_state_init();

	print_test_description("remove last hot\n");

	_lru_init(list);

	for (i = 1; i <= 8; i++) {
		add_lru_head_nobalance(NULL, list, i, NULL);
		balance_lru_list(NULL, list, NULL);
		present[i] = true;
	}

	for (i = 8; i >= 3; i--) {
		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, 8);
		assert_int_equal(list->tail, 1);

		count = 0;
		j = 8;
		while (count < i / 2) {
			if (present[j])
				++count;
			--j;
		}

		assert_int_equal(list->last_hot, j + 1);
		check_hot_elems(list);

		present[list->last_hot] = false;
		remove_lru_list_nobalance(NULL, list, list->last_hot, NULL);
		balance_lru_list(NULL, list, NULL);
	}

	assert_int_equal(list->num_hot, 1);
	assert_int_equal(list->num_nodes, 2);
	assert_int_equal(list->head, 2);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, 2);
}

static void _lru_init_test06(void **state)
{
	struct ocf_lru_list *list;
	unsigned i;
	unsigned count;

	test_state_init();

	print_test_description("remove middle hot\n");

	_lru_init(list);

	for (i = 1; i <= 8; i++) {
		add_lru_head_nobalance(NULL, list, i, NULL);
		balance_lru_list(NULL, list, NULL);
	}

	count = 8;

	remove_lru_list_nobalance(NULL, list, 7, NULL);
	balance_lru_list(NULL, list, NULL);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, 8);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, 5);

	remove_lru_list_nobalance(NULL, list, 6, NULL);
	balance_lru_list(NULL, list, NULL);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, 8);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, 4);

	remove_lru_list_nobalance(NULL, list, 5, NULL);
	balance_lru_list(NULL, list, NULL);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, 8);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, 4);

	remove_lru_list_nobalance(NULL, list, 4, NULL);
	balance_lru_list(NULL, list, NULL);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, 8);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, 3);

	remove_lru_list_nobalance(NULL, list, 3, NULL);
	balance_lru_list(NULL, list, NULL);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, 8);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, 8);

	remove_lru_list_nobalance(NULL, list, 8, NULL);
	balance_lru_list(NULL, list, NULL);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, 2);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, 2);

	remove_lru_list_nobalance(NULL, list, 2, NULL);
	balance_lru_list(NULL, list, NULL);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, 1);
	assert_int_equal(list->tail, 1);
	assert_int_equal(list->last_hot, end_marker);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(_lru_init_test02),
		cmocka_unit_test(_lru_init_test03),
		cmocka_unit_test(_lru_init_test04),
		cmocka_unit_test(_lru_init_test05),
		cmocka_unit_test(_lru_init_test06)
	};

	test_schema_init();

	return cmocka_run_group_tests(tests, NULL, NULL);
}
