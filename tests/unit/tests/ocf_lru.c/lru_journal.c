/*
 * <tested_file_path>src/ocf_lru.c</tested_file_path>
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
 * 	ocf_lru_get_list
 * 	ocf_lru_move
 * 	ocf_get_lru
 *	ocf_get_cline_list
 *	ocf_lru_init
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
 * 	is_started
 * 	clear_started
 * 	mark_started
 * 	is_finished
 * 	clear_finished
 * 	mark_finished
 * </functions_to_leave>
 */

#undef static

#undef inline


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "print_desc.h"

#include "ocf_space.h"
#include "ocf_lru.h"
#include "utils/utils_cleaner.h"
#include "utils/utils_cache_line.h"
#include "utils/utils_journal.h"
#include "concurrency/ocf_concurrency.h"
#include "mngt/ocf_mngt_common.h"
#include "engine/engine_zero.h"
#include "ocf_request.h"

#include "ocf_lru.c/lru_journal_generated_wraps.c"

// explicit declarations for wrapped functions
ocf_jop_t __real_ocf_journal_start_op(ocf_jop_t op,
		enum ocf_journal_op_id op_id);
ocf_jop_t __real_ocf_journal_finish_op(ocf_jop_t op);
void __real_mark_started(ocf_jop_t op);
void __real_clear_started(ocf_jop_t op);
bool __real_is_started(ocf_jop_t op);
void __real_mark_finished(ocf_jop_t op);
void __real_clear_finished(ocf_jop_t op);
bool __real_is_finished(ocf_jop_t op);

static struct ocf_lru_list *ocf_lru_get_list(struct ocf_part *part,
		uint32_t lru_idx, bool clean);

#define TEST_CLINES_COUNT 8 * OCF_NUM_LRU_LISTS + 1
#define TEST_JOURNAL_SIZE 1024 * 1024

struct test_metadata_state {
	struct ocf_lru_meta lru[TEST_CLINES_COUNT];
	ocf_part_id_t part_id[TEST_CLINES_COUNT];
	bool dirty[TEST_CLINES_COUNT];
	bool valid[TEST_CLINES_COUNT];
	struct ocf_part_runtime part_runtime[OCF_NUM_PARTITIONS];
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

	cache->free.id = PARTITION_FREELIST;
	cache->free.runtime = &curr_state.part_runtime[PARTITION_FREELIST];
	ocf_lru_init(cache, &cache->free);
	for (i = 0; i <= OCF_USER_IO_CLASS_MAX; i++) {
		cache->user_parts[i].part.id = i;
		cache->user_parts[i].part.runtime = &curr_state.part_runtime[i];
		ocf_lru_init(cache, &cache->user_parts[i].part);
	}

	for (i = 0; i < TEST_CLINES_COUNT; i++) {
		curr_state.lru[i].next = end_marker;
		curr_state.lru[i].prev = end_marker;
	}
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

struct ocf_lru_meta *
__wrap_ocf_metadata_get_lru(ocf_cache_t cache, ocf_cache_line_t line)
{
	assert (line < TEST_CLINES_COUNT);
	return &curr_state.lru[line];
}

struct {
	bool taken;
	bool requested;
	bool recovery;
	int step;
	int curr_step;
} snapshot;

void request_snapshot(int step, bool recovery)
{
	snapshot.taken = false;
	snapshot.requested = true;
	snapshot.recovery = recovery;
	snapshot.step = step;
	snapshot.curr_step = 0;
}

void request_runtime_snapshot(int step)
{
	request_snapshot(step, false);
}

void request_recovery_snapshot(int step)
{
	request_snapshot(step, true);
}

void clear_snapshot()
{
	snapshot.requested = false;
	snapshot.taken = false;
}

void try_snapshot(bool recovery)
{
	if (!snapshot.requested || snapshot.recovery != recovery)
		return;

	if (snapshot.curr_step == snapshot.step) {
		state_snapshot = curr_state;
		snapshot.taken = true;
		snapshot.requested = false;
	}

	snapshot.curr_step++;
}

void metadata_restore_from_snapshot(struct test_metadata_state *snapshot)
{
	curr_state = *snapshot;
}

int __ocf_ut_hook_status_op() { try_snapshot(true); }

ocf_jop_t __wrap_ocf_journal_start_op(ocf_jop_t op,
		enum ocf_journal_op_id op_id)
{
	ocf_jop_t ret;

	ret = __real_ocf_journal_start_op(op, op_id);
	try_snapshot(false);

	return ret;
}

ocf_jop_t __wrap_ocf_journal_finish_op(ocf_jop_t op)
{
	ocf_jop_t ret;

	try_snapshot(false);
	ret = __real_ocf_journal_finish_op(op);
	try_snapshot(false);

	return ret;
}

void __wrap_mark_started(ocf_jop_t op)
{
	try_snapshot(true);
	__real_mark_started(op);
	try_snapshot(true);
}

void __wrap_clear_started(ocf_jop_t op)
{
	try_snapshot(true);
	__real_clear_started(op);
	try_snapshot(true);
}

bool __wrap_is_started(ocf_jop_t op)
{
	bool ret;

	try_snapshot(true);
	ret = __real_is_started(op);
	try_snapshot(true);

	return ret;
}

void __wrap_mark_finished(ocf_jop_t op)
{
	try_snapshot(true);
	__real_mark_finished(op);
	try_snapshot(true);
}

void __wrap_clear_finished(ocf_jop_t op)
{
	try_snapshot(true);
	__real_clear_finished(op);
	try_snapshot(true);
}

bool __wrap_is_finished(ocf_jop_t op)
{
	bool ret;

	try_snapshot(true);
	ret = __real_is_finished(op);
	try_snapshot(true);

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
		assert_int_equal(curr_state.lru[curr].hot, 1);
		curr = curr_state.lru[curr].next;
	}
	for (i = list->num_hot; i < list->num_nodes; i++) {
		assert_int_equal(curr_state.lru[curr].hot, 0);
		curr = curr_state.lru[curr].next;
	}
}

typedef void (* test_step_cb_t)(ocf_cache_t cache, int step, ocf_jop_t op);

void verify_curr_metadata_state(struct test_metadata_state *snapshot)
{
	int ret;

	ret = memcmp(&curr_state, snapshot, sizeof(curr_state) -
			sizeof(curr_state.journal_buf));
	if (ret) {
		ret = memcmp(&curr_state.lru, &snapshot->lru, sizeof(curr_state.lru));
		assert_int_equal(ret, 0);
		ret = memcmp(&curr_state.part_runtime, &snapshot->part_runtime, sizeof(curr_state.part_runtime));
		assert_int_equal(ret, 0);
	}

	assert_int_equal(ret, 0);
}

/* attempt to recover from prev_crash_snapshot with simulated crash at various
 * points during recovery. After each recovery the state should be restored to
 * @initial_snashot. If num_crashes > 1 function will call itself recursively
 * to introduce more crashes and attempt to recover yet again */
void recover_with_crash(struct test_metadata_state *prev_crash_snapshot,
		struct test_metadata_state *initial_snapshot, int num_crashes)
{
	ocf_journal_t journal;
	unsigned recovery_crash_step = 0;
	bool recovery_interrupted;
	struct test_metadata_state _next_crash_state = {};
	struct test_metadata_state *next_crash_state = &_next_crash_state;
	bool snapshot_taken;
	int ret;
	unsigned cnt = 0;

	do {
		/* restore metadata (including journal) to the state at which
		 * previous simulated crash occured (during runtime transaction
		 * or recovery) */
		metadata_restore_from_snapshot(prev_crash_snapshot);

		/* now curr_state contains metadata and journal
		 * snapshot at step no 'runtime_crash_step'
		 */
		/* load journal */
		ret = ocf_journal_init(cache, g_schema, curr_state.journal_buf,
				sizeof(curr_state.journal_buf), &journal);
		assert_int_equal(ret, 0);

		if (num_crashes > 0) {
			/* capture metadat snapshot at some point during
			 * recovery to simulate interruptd recocery */
			request_recovery_snapshot(recovery_crash_step);
		} else {
			clear_snapshot();
		}

		/* rollback transaction */
		ocf_journal_recover(cache, journal);

		/* make sure journal is empty after recovery */
		assert_int_equal(journal->ring.hdr->started_idx, journal->ring.hdr->finished_idx);
		assert_int_equal(journal->ring.hdr->full, false);

		/* discard journal object */
		free(journal);

		/* metadata should be restored to initial state
		 * except for the journal itself */
		verify_curr_metadata_state(initial_snapshot);

		snapshot_taken = snapshot.taken;
		if (snapshot_taken) {
			/* only attempt recovery if the latest spapshot actually differs from the old one*/
			if (0 != memcmp(&state_snapshot, next_crash_state, sizeof(state_snapshot))) {
				cnt++;
				*next_crash_state = state_snapshot;

				/* attempt to continue interrupted recovery */
				recover_with_crash(next_crash_state, initial_snapshot, num_crashes - 1);
			}
		}

		++recovery_crash_step;
	} while(snapshot_taken);
}

void lru_journal_test_step(ocf_journal_t journal, enum ocf_journal_op_id op_id,
		int idx, test_step_cb_t step)
{
	ocf_jop_t op;
	unsigned runtime_crash_step;
	int ret;
	struct test_metadata_state initial_state;
	struct test_metadata_state runtime_crash_state = {};

	initial_state = curr_state;

	runtime_crash_step = 0;
	do {
		/* capture metadata snapshot at some moment during the
		 * transaction to simulate interrupted metadata transaction*/
		request_runtime_snapshot(runtime_crash_step);

		/* initiate transaction */
		op = OCF_JOURNAL_OP_INIT_VAL();
		OCF_JOURNAL_TRANSACTION_START(journal, op_id);

		/* execute journaled metadata operation, taking complete
		 * metadata snapshot at requested step */
		step(cache, idx, op);

		if (!snapshot.taken) {
			/* runtime_crash_step is greater than total number of steps
			 * within transactions - we're finished. */
			break;
		}

		/* only attempt recovery if the latest snapshot differs from the previous one */
		if (0 != memcmp(&state_snapshot, &runtime_crash_state, sizeof(state_snapshot))) {
			runtime_crash_state = state_snapshot;
			recover_with_crash(&runtime_crash_state, &initial_state, 2);
		}

		++runtime_crash_step;
	} while (true);

	/* commit transaction and continue to next test iteration */
	OCF_JOURNAL_TRANSACTION_END(journal);
}

void add_head_test_step_do(ocf_cache_t cache, int idx, ocf_jop_t op)
{
	ocf_part_id_t part_id = 0;
	unsigned lid = 0;
	struct ocf_part *part = &cache->user_parts[part_id].part;
	struct ocf_lru_list *list = ocf_lru_get_list(part, lid, true);

	/* initiate transaction */
	add_lru_head(cache, list, part_id, true, idx, op);

	return op;
}

#define CL(lid, idx) ((idx) * OCF_NUM_LRU_LISTS + (lid))
#define IDX(cline) ((cline) / OCF_NUM_LRU_LISTS)

static void _lru_journal_test01(void **state)
{
	ocf_journal_t journal;
	ocf_part_id_t part_id = 0;
	unsigned lid = 0;
	struct ocf_part *part;
	ocf_cache_line_t cline;
	struct ocf_lru_list *list;
	int i;

	test_state_init();
	//ocf_lru_populate(cache, TEST_CLINES_COUNT);
	journal = test_prepare_journal();
	assert_ptr_not_equal(journal, NULL);

	part = &cache->user_parts[part_id].part;
	list = ocf_lru_get_list(part, lid, true);

	print_test_description("test add\n");

	for (i = 1; i <= 8; i++)
	{
		cline = CL(0, i);

		lru_journal_test_step(journal, ocf_journal_op_id_lru_add,
				cline, add_head_test_step_do);

		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, cline);
		assert_int_equal(list->tail, CL(lid, 1));
		assert_int_equal(list->last_hot, i < 2 ? end_marker : CL(lid, i - i / 2 + 1));
		check_hot_elems(list);
	}

	test_cleanup_journal(journal);
}

void remove_test_do(ocf_cache_t cache, int idx, ocf_jop_t op)
{
	ocf_part_id_t part_id = 0;
	unsigned lid = 0;
	struct ocf_part *part = &cache->user_parts[part_id].part;
	struct ocf_lru_list *list = ocf_lru_get_list(part, lid, true);

	/* initiate transaction */
	remove_lru_list(cache, list, part_id, true, idx, op);
}

static void _lru_journal_test02(void **state)
{
	ocf_journal_t journal;
	ocf_part_id_t part_id = 0;
	unsigned lid = 0;
	struct ocf_part *part;
	ocf_cache_line_t cline;
	struct ocf_lru_list *list;
	int i;

	test_state_init();
	journal = test_prepare_journal();
	assert_ptr_not_equal(journal, NULL);

	part = &cache->user_parts[part_id].part;
	list = ocf_lru_get_list(part, lid, true);

	print_test_description("remove head\n");

	for (i = 1; i <= 8; i++) {
		cline = i * OCF_NUM_LRU_LISTS;
		add_lru_head(cache, list, part_id, true, cline, NULL);
	}


	for (i = 8; i >= 1; i--) {
		cline = CL(0, i);

		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, i * OCF_NUM_LRU_LISTS);
		assert_int_equal(list->tail, OCF_NUM_LRU_LISTS);
		assert_int_equal(list->last_hot, i < 2 ? end_marker :
				(i - i / 2 + 1) * OCF_NUM_LRU_LISTS);
		check_hot_elems(list);

		lru_journal_test_step(journal, ocf_journal_op_id_lru_del,
				CL(lid, i), remove_test_do);
	}

	assert_int_equal(list->num_hot, 0);
	assert_int_equal(list->num_nodes, 0);
	assert_int_equal(list->head, end_marker);
	assert_int_equal(list->tail, end_marker);
	assert_int_equal(list->last_hot, end_marker);

	test_cleanup_journal(journal);
}

static void _lru_journal_test03(void **state)
{
	ocf_journal_t journal;
	ocf_part_id_t part_id = 0;
	unsigned lid = 0;
	struct ocf_part *part;
	struct ocf_lru_list *list;
	int i;

	test_state_init();
	journal = test_prepare_journal();
	assert_ptr_not_equal(journal, NULL);

	part = &cache->user_parts[part_id].part;
	list = ocf_lru_get_list(part, lid, true);

	print_test_description("remove tail\n");

	for (i = 1; i <= 8; i++)
		add_lru_head(cache, list, part_id, true, CL(lid, i), NULL);

	for (i = 8; i >= 1; i--) {
		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, CL(lid, 8));
		assert_int_equal(list->tail, CL(lid, 9 - i));
		assert_int_equal(list->last_hot, i < 2 ? end_marker :
				CL(lid, 8 - i / 2 + 1));
		check_hot_elems(list);

		lru_journal_test_step(journal, ocf_journal_op_id_lru_del,
			       CL(lid, 9 - i), remove_test_do);
	}

	assert_int_equal(list->num_hot, 0);
	assert_int_equal(list->num_nodes, 0);
	assert_int_equal(list->head, end_marker);
	assert_int_equal(list->tail, end_marker);
	assert_int_equal(list->last_hot, end_marker);
}

static void _lru_journal_test04(void **state)
{
	ocf_journal_t journal;
	ocf_part_id_t part_id = 0;
	unsigned lid = 0;
	struct ocf_part *part;
	struct ocf_lru_list *list;
	unsigned i, j;
	bool present[9];
	unsigned count;

	test_state_init();
	journal = test_prepare_journal();
	assert_ptr_not_equal(journal, NULL);

	part = &cache->user_parts[part_id].part;
	list = ocf_lru_get_list(part, lid, true);

	print_test_description("remove last hot\n");

	for (i = 1; i <= 8; i++) {
		add_lru_head(cache, list, part_id, true, CL(lid, i), NULL);
		present[i] = true;
	}

	for (i = 8; i >= 3; i--) {
		assert_int_equal(list->num_hot, i / 2);
		assert_int_equal(list->num_nodes, i);
		assert_int_equal(list->head, CL(lid, 8));
		assert_int_equal(list->tail, CL(lid, 1));

		count = 0;
		j = 8;
		while (count < i / 2) {
			if (present[j])
				++count;
			--j;
		}

		assert_int_equal(list->last_hot, CL(lid, j + 1));
		check_hot_elems(list);

		present[IDX(list->last_hot)] = false;

		lru_journal_test_step(journal, ocf_journal_op_id_lru_del,
			       list->last_hot, remove_test_do);
	}

	assert_int_equal(list->num_hot, 1);
	assert_int_equal(list->num_nodes, 2);
	assert_int_equal(list->head, CL(lid, 2));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, CL(lid, 2));
}

static void _lru_journal_test05(void **state)
{
	ocf_journal_t journal;
	ocf_part_id_t part_id = 0;
	unsigned lid = 0;
	struct ocf_part *part;
	struct ocf_lru_list *list;
	int i;
	unsigned count;

	test_state_init();
	journal = test_prepare_journal();
	assert_ptr_not_equal(journal, NULL);

	part = &cache->user_parts[part_id].part;
	list = ocf_lru_get_list(part, lid, true);

	print_test_description("remove middle hot\n");

	for (i = 1; i <= 8; i++)
		add_lru_head(cache, list, part_id, true, CL(lid, i), NULL);

	count = 8;

	lru_journal_test_step(journal, ocf_journal_op_id_lru_del, CL(lid, 7), remove_test_do);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, CL(lid, 8));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, CL(lid, 5));

	lru_journal_test_step(journal, ocf_journal_op_id_lru_del, CL(lid, 6), remove_test_do);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, CL(lid, 8));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, CL(lid, 4));

	lru_journal_test_step(journal, ocf_journal_op_id_lru_del, CL(lid, 5), remove_test_do);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, CL(lid, 8));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, CL(lid, 4));

	lru_journal_test_step(journal, ocf_journal_op_id_lru_del, CL(lid, 4), remove_test_do);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, CL(lid, 8));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, CL(lid, 3));

	lru_journal_test_step(journal, ocf_journal_op_id_lru_del, CL(lid, 3), remove_test_do);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, CL(lid, 8));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, CL(lid, 8));

	lru_journal_test_step(journal, ocf_journal_op_id_lru_del, CL(lid, 8), remove_test_do);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, CL(lid, 2));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, CL(lid, 2));

	lru_journal_test_step(journal, ocf_journal_op_id_lru_del, CL(lid, 2), remove_test_do);
	--count;
	assert_int_equal(list->num_hot, count / 2);
	assert_int_equal(list->num_nodes, count);
	assert_int_equal(list->head, CL(lid, 1));
	assert_int_equal(list->tail, CL(lid, 1));
	assert_int_equal(list->last_hot, end_marker);
}

int main(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(_lru_journal_test01),
		cmocka_unit_test(_lru_journal_test02),
		cmocka_unit_test(_lru_journal_test03),
		cmocka_unit_test(_lru_journal_test04),
		cmocka_unit_test(_lru_journal_test05)
	};

	test_schema_init();

	return cmocka_run_group_tests(tests, NULL, NULL);
}
