/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "eviction.h"
#include "lru.h"
#include "ops.h"
#include "../utils/utils_cleaner.h"
#include "../utils/utils_cache_line.h"
#include "../concurrency/ocf_concurrency.h"
#include "../mngt/ocf_mngt_common.h"
#include "../engine/engine_zero.h"
#include "../ocf_request.h"
#include "../engine/engine_common.h"

#define OCF_EVICTION_MAX_SCAN 1024

/* -- Start of LRU functions --*/

/* Sets the given collision_index as the new _head_ of the LRU list. */
static inline void update_lru_head(struct ocf_lru_list *list,
		unsigned int collision_index)
{
	list->head = collision_index;
}

/* Sets the given collision_index as the new _tail_ of the LRU list. */
static inline void update_lru_tail(struct ocf_lru_list *list,
		unsigned int collision_index)
{
	list->tail = collision_index;
}

/* Sets the given collision_index as the new _head_ and _tail_ of
 * the LRU list.
 */
static inline void update_lru_head_tail(struct ocf_lru_list *list,
		unsigned int collision_index)
{
	update_lru_head(list, collision_index);
	update_lru_tail(list, collision_index);
}

/* Adds the given collision_index to the _head_ of the LRU list */
static void add_lru_head(ocf_cache_t cache,
		struct ocf_lru_list *list,
		unsigned int collision_index,
		unsigned int end_marker)

{
	struct lru_eviction_policy_meta *node;
	unsigned int curr_head_index;

	ENV_BUG_ON(collision_index >= end_marker);

	node = &ocf_metadata_hash_get_eviction_policy(cache, collision_index)
			->lru;

	/* First node to be added/ */
	if (!list->num_nodes)  {
		update_lru_head_tail(list, collision_index);

		node->next = end_marker;
		node->prev = end_marker;
		node->hot = false;

		list->num_nodes = 1;
	} else {
		struct lru_eviction_policy_meta *head;

		/* Not the first node to be added. */
		curr_head_index = list->head;

		ENV_BUG_ON(curr_head_index == end_marker);

		head = &ocf_metadata_hash_get_eviction_policy(cache,
				curr_head_index)->lru;

		node->next = curr_head_index;
		node->prev = end_marker;
		head->prev = collision_index;
		node->hot = true;
		if (!head->hot)
			list->last_hot = collision_index;
		++list->num_hot;

		update_lru_head(list, collision_index);

		++list->num_nodes;
	}
}

/* Deletes the node with the given collision_index from the lru list */
static void remove_lru_list(ocf_cache_t cache,
		struct ocf_lru_list *list,
		unsigned int collision_index,
		unsigned int end_marker)
{
	int is_head = 0, is_tail = 0;
	uint32_t prev_lru_node, next_lru_node;
	struct lru_eviction_policy_meta *node;

	ENV_BUG_ON(collision_index >= end_marker);

	node = &ocf_metadata_hash_get_eviction_policy(cache, collision_index)->lru;

	is_head = (list->head == collision_index);
	is_tail = (list->tail == collision_index);

	if (node->hot)
		--list->num_hot;

	/* Set prev and next (even if not existent) */
	next_lru_node = node->next;
	prev_lru_node = node->prev;

	/* Case 1: If we are head AND tail, there is only one node.
	 * So unlink node and set that there is no node left in the list.
	 */
	if (is_head && is_tail) {
		node->next = end_marker;
		node->prev = end_marker;

		update_lru_head_tail(list, end_marker);
		list->last_hot = end_marker;
		ENV_BUG_ON(list->num_hot != 0);
	}

	/* Case 2: else if this collision_index is LRU head, but not tail,
	 * update head and return
	 */
	else if (is_head) {
		struct lru_eviction_policy_meta *next_node;

		ENV_BUG_ON(next_lru_node >= end_marker);

		next_node = &ocf_metadata_hash_get_eviction_policy(cache,
				next_lru_node)->lru;

		/* unlikely */
		if (list->last_hot == collision_index) {
			ENV_BUG_ON(list->num_hot > 0); // already decremented
			list->last_hot = end_marker;
		}

		update_lru_head(list, next_lru_node);

		node->next = end_marker;
		next_node->prev = end_marker;
	}

	/* Case 3: else if this collision_index is LRU tail, but not head,
	 * update tail and return
	 */
	else if (is_tail) {
		struct lru_eviction_policy_meta *prev_node;

		ENV_BUG_ON(prev_lru_node >= end_marker);

		update_lru_tail(list, prev_lru_node);

		ENV_BUG_ON(node->hot);

		prev_node = &ocf_metadata_hash_get_eviction_policy(cache,
				prev_lru_node)->lru;

		node->prev = end_marker;
		prev_node->next = end_marker;
	}

	/* Case 4: else this collision_index is a middle node. There is no
	 * change to the head and the tail pointers.
	 */
	else {
		struct lru_eviction_policy_meta *prev_node;
		struct lru_eviction_policy_meta *next_node;

		ENV_BUG_ON(next_lru_node >= end_marker);
		ENV_BUG_ON(prev_lru_node >= end_marker);

		prev_node = &ocf_metadata_hash_get_eviction_policy(cache,
				prev_lru_node)->lru;
		next_node = &ocf_metadata_hash_get_eviction_policy(cache,
				next_lru_node)->lru;

		if (list->last_hot == collision_index) {
			ENV_BUG_ON(list->num_hot == 0);
			list->last_hot = prev_lru_node;
		}

		/* Update prev and next nodes */
		prev_node->next = node->next;
		next_node->prev = node->prev;

		/* Update the given node */
		node->next = end_marker;
		node->prev = end_marker;
	}

	--list->num_nodes;
}

/* assumptions:
 * called after (add || delete) ^ set_hot
 * add, delete and set hot make sure that:
 *  - only elements at the beginning of list are marked as hot
 *  - num_hot and last_hot are up to date
 */
static void balance_lru_list(ocf_cache_t cache,
		struct ocf_lru_list *list,
		unsigned int end_marker)
{
	unsigned target_hot_count = list->num_nodes / HOT_RATIO;
	struct lru_eviction_policy_meta *node;

	if (target_hot_count == list->num_hot)
		return;

	if (list->num_hot == 0) {
		node = &ocf_metadata_hash_get_eviction_policy(cache,
				list->head)->lru;
		list->last_hot = list->head;
		list->num_hot = 1;
		node->hot = 1;
		return;
	}

	ENV_BUG_ON(list->last_hot == end_marker);
	node = &ocf_metadata_hash_get_eviction_policy(cache,
			list->last_hot)->lru;

	if (target_hot_count > list->num_hot) {
		++list->num_hot;
		list->last_hot = node->next;
		node = &ocf_metadata_hash_get_eviction_policy(cache,
				node->next)->lru;
		node->hot = true;
	} else {
		if (list->last_hot == list->head) {
			node->hot = false;
			list->num_hot = 0;
			list->last_hot = end_marker;
		} else {
			ENV_BUG_ON(node->prev == end_marker);
			node->hot = false;
			--list->num_hot;
			list->last_hot = node->prev;
		}
	}
}


/*-- End of LRU functions*/

void evp_lru_init_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	struct lru_eviction_policy_meta *node;
	const uint32_t end_marker =
			cache->device->collision_table_entries;

	node = &ocf_metadata_hash_get_eviction_policy(cache, cline)->lru;

	node->hot = false;
	node->prev = end_marker;
	node->next = end_marker;
}


/* the caller must hold the metadata lock */
void evp_lru_rm_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_hash_get_partition_id(cache, cline);
	struct ocf_user_part *part = &cache->user_parts[part_id];
	int ev_part = (cline % cache->num_evps);
	struct ocf_lru_list *list;
	const unsigned int end_marker =
			cache->device->collision_table_entries;

	list = metadata_test_dirty(cache, cline) ? 
		&part->runtime->eviction[ev_part].policy.lru.dirty :
		&part->runtime->eviction[ev_part].policy.lru.clean;

	remove_lru_list(cache, list, cline, end_marker);
	balance_lru_list(cache, list, end_marker);
}

static inline void lru_iter_init(ocf_cache_t cache,
		ocf_part_id_t part_id,
		bool clean, bool lock_write,
		bool exclusive,
		_lru_hash_locked_pfn hash_locked, void *context,
		struct ocf_lru_iter_state *state)
{
	uint32_t i;
	struct ocf_user_part *part = &cache->user_parts[part_id];

	state->cache = cache;
	state->part_id = part_id;
	state->part = part;
	state->evp = env_atomic64_inc_return(&part->cleaning.next_lru) %
				cache->num_evps;
	state->end_marker = cache->device->collision_table_entries;
	state->empty_evps_no = 0;
	state->num_evps = cache->num_evps;
	state->clean = clean;
	state->exclusive = exclusive;
	state->lock_write = lock_write;
	state->hash_locked = hash_locked;
	state->context = context;

	for (i = 0; i < cache->num_evps; i++) {
		state->empty_evps[i] = false;
	}
}

static inline uint32_t _lru_next_evp(struct ocf_lru_iter_state *state)
{
	uint32_t curr_evp;

	do {
		curr_evp = state->evp;
		state->evp = (state->evp + 1) % state->num_evps;
	} while (state->empty_evps[curr_evp] &&
			state->empty_evps_no != state->num_evps);

	return curr_evp;
}

static bool inline _lru_trylock_cacheline(struct ocf_lru_iter_state *state,
		ocf_cache_line_t cline)
{
	if (state->lock_write)
		return ocf_cache_line_try_lock_wr(state->cache, cline);
	else {
		if (ocf_cache_line_try_lock_rd(state->cache, cline)) {
			return true;
		} else return false;
	}
}

static void inline _lru_unlock_cacheline(struct ocf_lru_iter_state *state,
		ocf_cache_line_t cline)
{
	if (state->lock_write)
		ocf_cache_line_unlock_wr(state->cache, cline);
	else
		ocf_cache_line_unlock_rd(state->cache, cline);
}

static bool inline _lru_trylock_hash(struct ocf_lru_iter_state *state,
		ocf_core_id_t core_id, uint64_t core_line)
{
	if (state->hash_locked != NULL && state->hash_locked(
				state->context,
				core_id, core_line)) {
		return true;
	}

	if (state->exclusive) {
		return _ocf_metadata_hash_trylock_wr(
				&state->cache->metadata.lock,
				core_id, core_line);
	} else {
		return _ocf_metadata_hash_trylock_rd(
				&state->cache->metadata.lock,
				core_id, core_line);
	}
}

static void inline _lru_unlock_hash(struct ocf_lru_iter_state *state,
		ocf_core_id_t core_id, uint64_t core_line)
{
	if (state->hash_locked != NULL && state->hash_locked(
				state->context,
				core_id, core_line)) {
		return;
	}

	if (state->exclusive) {
		_ocf_metadata_hash_unlock_wr(
				&state->cache->metadata.lock,
				core_id, core_line);
	} else {
		_ocf_metadata_hash_unlock_rd(
				&state->cache->metadata.lock,
				core_id, core_line);
	}
}

static bool inline _lru_lock(struct ocf_lru_iter_state *state,
		ocf_cache_line_t cache_line,
		ocf_core_id_t *core_id, uint64_t *core_line)

{
	if (!_lru_trylock_cacheline(state, cache_line))
		return false;

	ocf_metadata_hash_get_core_info(state->cache, cache_line,
		core_id, core_line);

	if (!_lru_trylock_hash(state, *core_id, *core_line)) {
		_lru_unlock_cacheline(state, cache_line);
		return false;
	}

	/* TODO: find a better name for what 'exclusive' means
	 * - it is used by eviction only, and drives two things:
	 *   1. requesting cacheline to be locked exlusively
	 *    (even for read - we can assure this under hash 
	 *    bucket write lock)
	 *   2. moves LRU item to head */
	if (!state->exclusive)
		return true;

	if (!ocf_cache_line_is_locked_exclusively(state->cache,
				cache_line)) {
		_lru_unlock_hash(state, *core_id, *core_line);
		_lru_unlock_cacheline(state, cache_line);
		return false;
	}

	return true;
}

static inline ocf_cache_line_t lru_iter_next(struct ocf_lru_iter_state *state,
		ocf_core_id_t *core_id, uint64_t *core_line)
{
	uint32_t curr_evp;
	ocf_cache_line_t  cline;
	ocf_cache_t cache = state->cache;
	struct ocf_user_part *part = state->part;
	struct ocf_lru_list *list;

	do {
		curr_evp = _lru_next_evp(state);

		_OCF_METADATA_EVICTION_LOCK(curr_evp);

		list = state->clean ?
			&part->runtime->eviction[curr_evp].policy.lru.clean :
			&part->runtime->eviction[curr_evp].policy.lru.dirty;

		cline = list->tail;

		while (cline != state->end_marker &&
				!_lru_lock(state, cline, core_id, core_line)) {
			cline = ocf_metadata_hash_get_eviction_policy(
					state->cache, cline)->lru.prev;
		}

		if (cline != state->end_marker && state->exclusive) {
			remove_lru_list(cache, list, cline, state->end_marker);
			add_lru_head(cache, list, cline, state->end_marker);
			balance_lru_list(cache, list, state->end_marker);
		}

		_OCF_METADATA_EVICTION_UNLOCK(curr_evp);

		if (cline == state->end_marker &&
				!state->empty_evps[curr_evp]) {
			state->empty_evps[curr_evp] = true;
			state->empty_evps_no++;
		}
	} while (cline == state->end_marker &&
			state->empty_evps_no < state->num_evps);

	return cline;
}


static void evp_lru_clean_end(void *private_data, int error)
{
	struct ocf_part_cleaning_ctx *ctx = private_data;
	struct ocf_lru_iter_state *lru_iter = &ctx->lru_iter;
	unsigned i;
	
	for (i = ctx->num_clines; i>=1; i--) {
		ocf_cache_line_unlock_rd(lru_iter->cache,
				ctx->clines[i - 1]);
	}

	env_atomic_set(&lru_iter->part->cleaning.state, 0);
	ocf_refcnt_dec(&lru_iter->cache->refcnt.cleaning[lru_iter->part_id]);

}


static int evp_lru_clean_get(ocf_cache_t cache, void *getter_context,
		uint32_t idx, struct flush_data *data)
{
	struct ocf_part_cleaning_ctx *ctx = getter_context;
	struct ocf_lru_iter_state *lru_iter = &ctx->lru_iter;
	ocf_cache_line_t cline;
	ocf_core_id_t core_id;
	uint64_t core_line;

	cline = lru_iter_next(lru_iter, &core_id, &core_line);

	if (cline == cache->device->collision_table_entries)
		return -1;
	
	ENV_BUG_ON(!metadata_test_dirty(cache, cline));

	lru_iter->part->cleaning.clines[idx] = cline;
	lru_iter->part->cleaning.num_clines = idx + 1;

	data->cache_line = cline;
	data->core_id = core_id;
	data->core_line = core_line;

	return 0;
}

static void evp_lru_clean_put(ocf_cache_t cache, void *getter_context,
		struct flush_data *data)
{
	struct ocf_part_cleaning_ctx *ctx = getter_context;
	struct ocf_lru_iter_state *lru_iter = &ctx->lru_iter; 

		
	_lru_unlock_hash(lru_iter, data->core_id, data->core_line);
}

static void evp_lru_clean(ocf_cache_t cache, ocf_queue_t io_queue,
		ocf_part_id_t part_id, uint32_t count)
{
	struct ocf_refcnt *counter = &cache->refcnt.cleaning[part_id];
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct ocf_cleaner_attribs attribs = {
		.cache_line_lock = false,
		.read_lock = false,
		.do_sort = true,

		.cmpl_context = &part->cleaning,
		.cmpl_fn = evp_lru_clean_end,

		.get = evp_lru_clean_get,
		.put = evp_lru_clean_put,
		.getter_context = &part->cleaning,

		.count = count > 32 ? 32 : count,

		.io_queue = io_queue
	};

	if (ocf_mngt_cache_is_locked(cache))
		return;

	if (!ocf_refcnt_inc(counter)) {
		/* cleaner disabled by management operation */
		return;
	}

	/* TODO: it seems that this doesn't serve any purpose -
	 * remove it */
	if (env_atomic_cmpxchg(&part->cleaning.state, 0, 1) == 1) {
		/* cleaning already running for this partition */
		ocf_refcnt_dec(counter);
		return;
	}

	part->cleaning.num_clines = 0;	
	lru_iter_init(cache, part_id, false, false, false, NULL, NULL,
			&part->cleaning.lru_iter);

	ocf_cleaner_fire(cache, &attribs);
}

static void evp_lru_zero_line_complete(struct ocf_request *ocf_req, int error)
{
	env_atomic_dec(&ocf_req->cache->pending_eviction_clines);
}

static void evp_lru_zero_line(ocf_cache_t cache, ocf_queue_t io_queue,
		ocf_cache_line_t line)
{
	struct ocf_request *req;
	ocf_core_id_t id;
	uint64_t addr, core_line;

	ocf_metadata_hash_get_core_info(cache, line, &id, &core_line);
	addr = core_line * ocf_line_size(cache);

	req = ocf_req_new(io_queue, &cache->core[id], addr,
			ocf_line_size(cache), OCF_WRITE);
	if (!req)
		return;

	if (req->d2c) {
		/* cache device is being detached */
		ocf_req_put(req);
		return;
	}

	req->info.internal = true;
	req->complete = evp_lru_zero_line_complete;

	env_atomic_inc(&cache->pending_eviction_clines);

	ocf_engine_zero_line(req);
}

bool evp_lru_can_evict(ocf_cache_t cache)
{
	if (env_atomic_read(&cache->pending_eviction_clines) >=
			OCF_PENDING_EVICTION_LIMIT) {
		return false;
	}

	return true;
}

static bool dirty_pages_present(ocf_cache_t cache, ocf_part_id_t part_id)
{
	uint32_t i;
	struct ocf_user_part *part = &cache->user_parts[part_id];


	for (i = 0; i < cache->num_evps; i++) {
		if (part->runtime->eviction[i].policy.lru.dirty.tail !=
				cache->device->collision_table_entries) {
			return true;
		}
	}

	return false;
}

static bool _evp_lru_evict_hash_locked(void *context,
		ocf_core_id_t core_id, uint64_t core_line)
{
	struct ocf_request *req = context;

	return  ocf_req_hash_in_range(req, core_id, core_line);
}

/* the caller must hold the metadata lock */
uint32_t evp_lru_req_clines(struct ocf_request *req,
		ocf_part_id_t part_id, uint32_t cline_no)
{
	struct ocf_lru_iter_state lru_iter;
	uint32_t i;
	ocf_cache_line_t cline;
	uint64_t core_line;
	ocf_core_id_t core_id;
	ocf_cache_t cache = req->cache;
	bool cacheline_write_lock = 
		(req->engine_cbs->get_lock_type(req) == 
		 		ocf_engine_lock_write);

	if (cline_no == 0)
		return 0;

	lru_iter_init(cache, part_id, true, cacheline_write_lock,
			true, _evp_lru_evict_hash_locked, req,		
			&lru_iter);

	i = 0;
	while (i < cline_no) {
		if (!evp_lru_can_evict(cache))
	 		break;

		cline = lru_iter_next(&lru_iter, &core_id, &core_line);

		if (cline == cache->device->collision_table_entries)
			break;

		ENV_BUG_ON(metadata_test_dirty(cache, cline));

		if (ocf_volume_is_atomic(&cache->device->volume)) {
			/* atomic cache, we have to trim cache lines before
			 * eviction
			 */
			/* TODO: evl_lru_zero_line probably expects:
			 * 1. to be called with global write lock
			 * 2. not to have cachelines locked */
			evp_lru_zero_line(cache, req->io_queue, cline);
			_ocf_metadata_hash_unlock_wr(&cache->metadata.lock,
					core_id, core_line);
			continue;
		}

		while (req->eviction_idx < req->core_line_count &&
				req->map[req->eviction_idx].status !=
						LOOKUP_MISS) {
			req->eviction_idx++;
		}

		ENV_BUG_ON(req->eviction_idx == req->core_line_count);

		/* TODO: squash unmap and map into one operation ?*/

		ocf_metadata_hash_start_collision_shared_access(
				cache, cline);
		set_cache_line_invalid_no_flush_no_freelist(cache, 0,
				ocf_line_end_sector(cache),
				cline);
		ocf_metadata_hash_end_collision_shared_access(
				cache, cline);

		_lru_unlock_hash(&lru_iter, core_id, core_line);

		// set partition id
		{
			ocf_part_id_t part_id;

			ocf_metadata_hash_get_partition_info(
					cache, cline, 
					&part_id, NULL, NULL);

			if (req->part_id != part_id) {
				ocf_metadata_remove_from_partition(
						cache, part_id, cline);
				ocf_metadata_add_to_partition(
						cache, req->part_id, cline);
			}

		}

		req->map[req->eviction_idx].status = LOOKUP_REPLACED;
		ocf_map_cache_line(req, req->eviction_idx, cline);
		ocf_engine_update_req_info(cache, req, req->eviction_idx);

		if (cacheline_write_lock)
			req->map[req->eviction_idx].wr_locked = true;
		else
			req->map[req->eviction_idx].rd_locked = true;

		req->eviction_idx++;

		++i;
	}
	
	if (i < cline_no && dirty_pages_present(cache, part_id)) {
		/* originally evp_lru_req_clines was called with 
		 * cline_no >= 128. since for now there is limitation
		 * to issue only one lru_cleaning request per 
		 * partition at a time, in order to maintain
		 * originall cleaning throughput I call evp_lru_clean
		 * with count = ~128  */
		evp_lru_clean(cache, req->io_queue, part_id, 128 - i);
	}

	/* Return number of clines that were really evicted */
	return i;
}

/* the caller must hold the metadata lock */
void evp_lru_hot_cline(ocf_cache_t cache, ocf_cache_line_t cline)
{
	ocf_part_id_t part_id = ocf_metadata_hash_get_partition_id(cache, cline);
	struct ocf_user_part *part = &cache->user_parts[part_id];
	int ev_part = (cline % cache->num_evps);
	uint32_t end_marker = cache->device->collision_table_entries;
	struct lru_eviction_policy_meta *node;

	int cline_dirty;
	struct ocf_lru_list *list;

	node = &ocf_metadata_hash_get_eviction_policy(cache, cline)->lru;

	if (node->hot)
		return;

	OCF_METADATA_EVICTION_LOCK(cline);

	cline_dirty = metadata_test_dirty(cache, cline);
	list = cline_dirty ? 
		&part->runtime->eviction[ev_part].policy.lru.dirty :
		&part->runtime->eviction[ev_part].policy.lru.clean;

	if (node->next != end_marker ||
			node->prev != end_marker ||
			list->head == cline || list->tail == cline) {
		remove_lru_list(cache, list, cline, end_marker);
	}

	/* Update LRU */
	add_lru_head(cache, list, cline, end_marker);
	balance_lru_list(cache, list, end_marker);

	OCF_METADATA_EVICTION_UNLOCK(cline);
}

static inline void _lru_init(struct ocf_lru_list *list, unsigned end_marker)
{
	list->num_nodes = 0;
	list->head = end_marker;
	list->tail = end_marker;
	list->num_hot = 0;
	list->last_hot = end_marker;
}

void evp_lru_init_evp(ocf_cache_t cache, ocf_part_id_t part_id,
		unsigned num_instances)
{
	unsigned int end_marker =
			cache->device->collision_table_entries;
	struct ocf_user_part *part = &cache->user_parts[part_id];
	struct ocf_lru_list *clean_list; 
	struct ocf_lru_list *dirty_list;

	unsigned i;

	for (i = 0; i < cache->num_evps; i++) {
		clean_list = &part->runtime->eviction[i].policy.lru.clean;
		dirty_list = &part->runtime->eviction[i].policy.lru.dirty;

		_lru_init(clean_list, end_marker);
		_lru_init(dirty_list, end_marker);
	}
}

void evp_lru_clean_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline)
{
	struct ocf_user_part *part = &cache->user_parts[part_id];
	const unsigned int end_marker =
			cache->device->collision_table_entries;
	int ev_part = (cline % cache->num_evps);
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;

	clean_list = &part->runtime->eviction[ev_part].policy.lru.clean;
	dirty_list = &part->runtime->eviction[ev_part].policy.lru.dirty;

	OCF_METADATA_EVICTION_LOCK(cline);
	remove_lru_list(cache, dirty_list, cline, end_marker);
	balance_lru_list(cache, dirty_list, end_marker);
	add_lru_head(cache, clean_list, cline, end_marker);
	balance_lru_list(cache, clean_list, end_marker);
	OCF_METADATA_EVICTION_UNLOCK(cline);
}

void evp_lru_dirty_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline)
{
	const unsigned int end_marker =
			cache->device->collision_table_entries;
	struct ocf_user_part *part = &cache->user_parts[part_id];
	int ev_part = (cline % cache->num_evps);
	struct ocf_lru_list *clean_list;
	struct ocf_lru_list *dirty_list;

	clean_list = &part->runtime->eviction[ev_part].policy.lru.clean;
	dirty_list = &part->runtime->eviction[ev_part].policy.lru.dirty;

	OCF_METADATA_EVICTION_LOCK(cline);
	remove_lru_list(cache, clean_list, cline, end_marker);
	balance_lru_list(cache, clean_list, end_marker);
	add_lru_head(cache, dirty_list, cline, end_marker);
	balance_lru_list(cache, dirty_list, end_marker);
	OCF_METADATA_EVICTION_UNLOCK(cline);
}

