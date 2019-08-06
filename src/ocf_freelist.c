/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata/metadata_partition.h"
#include "ocf_queue_priv.h"
#include "ocf_freelist.h"

static const int BACKUP_FREELIST_IDX = 0;

struct ocf_freelist {
	struct ocf_freelist_pool *pool;
	struct ocf_part part;
	env_spinlock lock;
	ocf_queue_t queue;
	bool deleted;
};

static void ocf_freelist_lock(struct ocf_freelist *freelist)
{
	env_spinlock_lock(&freelist->lock);
}

static void ocf_freelist_unlock(struct ocf_freelist *freelist)
{
	env_spinlock_unlock(&freelist->lock);
}

/* Sets the given collifsion_index as the new _head_ of the Partition list. */
static void _ocf_freelist_remove_cache_line(struct ocf_cache *cache,
		struct ocf_part *freelist, ocf_cache_line_t cline)
{
	int is_head, is_tail;
	ocf_part_id_t invalid_part_id = PARTITION_INVALID;
	ocf_cache_line_t prev, next;
	ocf_cache_line_t line_entries = cache->device->collision_table_entries;
	uint32_t free;

	ENV_BUG_ON(cline >= line_entries);

	/* Get Partition info */
	ocf_metadata_get_partition_info(cache, cline, NULL, &next, &prev);

	/* Find out if this node is Partition _head_ */
	is_head = (prev == line_entries);
	is_tail = (next == line_entries);

	free = env_atomic_read(&freelist->curr_size);

	/* Case 1: If we are head and there is only one node. So unlink node
	 * and set that there is no node left in the list.
	 */
	if (is_head && free == 1) {
		ocf_metadata_set_partition_info(cache, cline, invalid_part_id,
				line_entries, line_entries);
		freelist->head = line_entries;
		freelist->tail = line_entries;
	} else if (is_head) {
		/* Case 2: else if this collision_index is partition list head,
		 * but many nodes, update head and return
		 */
		ENV_BUG_ON(next >= line_entries);

		freelist->head = next;
		ocf_metadata_set_partition_prev(cache, next, line_entries);
		ocf_metadata_set_partition_next(cache, cline, line_entries);
	} else if (is_tail) {
		/* Case 3: else if this cline is partition list tail */
		ENV_BUG_ON(prev >= line_entries);

		freelist->tail = prev;
		ocf_metadata_set_partition_prev(cache, cline, line_entries);
		ocf_metadata_set_partition_next(cache, prev, line_entries);
	} else {
		/* Case 4: else this collision_index is a middle node.
		 * There is no change to the head and the tail pointers.
		 */

		ENV_BUG_ON(next >= line_entries || prev >= line_entries);

		/* Update prev and next nodes */
		ocf_metadata_set_partition_prev(cache, next, prev);
		ocf_metadata_set_partition_next(cache, prev, next);

		/* Update the given node */
		ocf_metadata_set_partition_info(cache, cline, invalid_part_id,
				line_entries, line_entries);
	}

	env_atomic_dec(&freelist->curr_size);
}

void ocf_freelist_remove_cache_line(struct ocf_freelist_pool *pool,
		ocf_cache_line_t cline)
{
	/* TODO: Need to find freelist for given cache line */
	_ocf_freelist_remove_cache_line(pool->cache, NULL, cline);
	env_atomic_dec(&pool->total_free);
}

static void ocf_freelist_add_cache_line(struct ocf_cache *cache,
		struct ocf_freelist *freelist, ocf_cache_line_t line)
{
	ocf_cache_line_t tail;
	ocf_cache_line_t line_entries = cache->device->collision_table_entries;
	ocf_part_id_t invalid_part_id = PARTITION_INVALID;

	ENV_BUG_ON(line >= line_entries);
	ENV_BUG_ON(!freelist || freelist->deleted);

	if (env_atomic_read(&freelist->part.curr_size) == 0) {
		freelist->part.head = line;
		freelist->part.tail = line;

		ocf_metadata_set_partition_info(cache, line, invalid_part_id,
				line_entries, line_entries);
	} else {
		tail = freelist->part.tail;

		ENV_BUG_ON(tail >= line_entries);

		ocf_metadata_set_partition_info(cache, line, invalid_part_id,
				line_entries, tail);
		ocf_metadata_set_partition_next(cache, tail, line);

		freelist->part.tail = line;
	}

	env_atomic_inc(&freelist->part.curr_size);
}

static int ocf_freelist_get_cache_line_fast(struct ocf_freelist *freelist,
		 ocf_cache_line_t *cline)
{
	ocf_cache_t cache = freelist->pool->cache;

	if (env_atomic_read(&freelist->part.curr_size) == 0)
		return -ENOSPC;

	ocf_freelist_lock(freelist);
	if (env_atomic_read(&freelist->part.curr_size) == 0) {
		ocf_freelist_unlock(freelist);
		return -ENOSPC;
	}

	*cline = freelist->part.head;
	_ocf_freelist_remove_cache_line(cache, &freelist->part, *cline);
	env_atomic_dec(&freelist->pool->total_free);

	ocf_freelist_unlock(freelist);

	return 0;
}

static inline unsigned ocf_freelist_get_next_idx(struct ocf_freelist_pool *pool)
{
	int idx;

	idx = env_atomic_read(&pool->last_used);
	env_atomic_set(&pool->last_used, (idx + 1) % pool->count);

	return idx;
}

#define _for_each_freelist(pool, i, idx, allow_deleted) \
	for (i = 0, idx = ocf_freelist_get_next_idx(pool); i < pool->count; \
			i++, idx = (i < pool->count) ? \
					ocf_freelist_get_next_idx(pool) : 0) \
		if (pool->freelist[idx] != NULL && (!pool->freelist[idx]->deleted || allow_deleted))

#define for_each_freelist_all(pool, i, idx) _for_each_freelist(pool, i, idx, true)
#define for_each_freelist(pool, i, idx) _for_each_freelist(pool, i, idx, false)

static int ocf_freelist_get_cache_line_slow(
		struct ocf_freelist_pool *pool, ocf_cache_line_t *cline)
{
	int victim_idx, i;
	struct ocf_freelist *victim;
	int ret = -ENOSPC;

	env_rwsem_down_read(&pool->list_sem);

	for_each_freelist_all(pool, victim_idx, i) {
		victim = pool->freelist[victim_idx];
		if (!ocf_freelist_get_cache_line_fast(victim, cline)) {
			ret = 0;
			break;
		}

	}

	env_rwsem_up_read(&pool->list_sem);

	return ret ?: victim_idx;
}

int ocf_freelist_get_cache_line(struct ocf_freelist_pool *pool, int idx,
		ocf_cache_line_t *cline)
{
	struct ocf_freelist *freelist = pool->freelist[idx];

	if (env_atomic_read(&freelist->pool->total_free) == 0)
		return -ENOSPC;

	if (!ocf_freelist_get_cache_line_fast(freelist, cline))
		return 0;

	return ocf_freelist_get_cache_line_slow(freelist->pool, cline);
}

/* idx == -1 means put the list at a freelist using round robin */
int ocf_freelist_put_cache_line(struct ocf_freelist_pool *pool, unsigned idx,
		ocf_cache_line_t cline)
{
	ocf_cache_t cache = pool->cache;
	struct ocf_freelist *freelist;
	int receiver, i;

	receiver = idx;
	if (receiver == UNSPECIFIED_FREELIST_IDX) {
		/* select first not deleted freelist in round-robin order */
		for_each_freelist(pool, i, idx) {
			receiver = idx;
			if (idx == BACKUP_FREELIST_IDX) {
				/* try not to put cacheline on the backup
 				 * freelist */
				continue;
			}
			break;
		}
	}

	/* there must be some not deleted freelist, at least the backup one */
	ENV_BUG_ON(receiver == UNSPECIFIED_FREELIST_IDX);

	freelist = pool->freelist[receiver];
	ocf_freelist_lock(freelist);
	ocf_freelist_add_cache_line(cache, freelist, cline);
	env_atomic_inc(&pool->total_free);
	ocf_freelist_unlock(freelist);

	return receiver;
}

int ocf_freelist_pool_init(struct ocf_freelist_pool *pool,
		struct ocf_cache *cache)
{
	int backup_freelist;

	pool->cache = cache;
	pool->count = 0;
	env_atomic_set(&pool->total_free, 0);
	env_atomic_set(&pool->total_free, 0);
	env_rwsem_init(&pool->list_sem);

	backup_freelist = ocf_freelist_new(pool, NULL);
	if (backup_freelist < 0) {
		ocf_freelist_pool_deinit(pool);
		return backup_freelist;
	}

	ENV_BUG_ON(backup_freelist != BACKUP_FREELIST_IDX);

	return 0;
}

static void _ocf_freelist_deinit(struct ocf_freelist *freelist)
{
	/* TODO: deinit spin lock */
	env_vfree(freelist);
}

void ocf_freelist_pool_deinit(struct ocf_freelist_pool *pool)
{
	int idx, i;

	for_each_freelist_all(pool, idx, i)
		_ocf_freelist_deinit(pool->freelist[idx]);
	/* TODO deinit semaphore etc */
}

int ocf_freelist_new(struct ocf_freelist_pool *pool, ocf_queue_t queue)
{
	struct ocf_freelist *freelist = env_vzalloc(sizeof(*freelist));
	struct ocf_freelist **new_array;
	int ret;

	if (!freelist)
		return -OCF_ERR_NO_MEM;

	freelist->pool = pool;
	freelist->queue = queue;
	env_spinlock_init(&freelist->lock);

	env_rwsem_down_write(&pool->list_sem);
	new_array = env_realloc(pool->freelist,
			(pool->count + 1) * sizeof(pool->freelist[0]),
			ENV_MEM_NORMAL);
	if (!new_array) {
		_ocf_freelist_deinit(freelist);
		ret = -OCF_ERR_NO_MEM;
		goto unlock;
	}

	pool->freelist = new_array;
	pool->freelist[pool->count] = freelist;
	ret = pool->count++;

unlock:
	env_rwsem_up_write(&pool->list_sem);

	return ret;
}

static void _ocf_freelist_remove(struct ocf_freelist_pool *pool, int id)
{
	_ocf_freelist_deinit(pool->freelist[id]);
	pool->freelist[id] = NULL;
}

void ocf_freelist_del(struct ocf_freelist_pool *pool, int id)
{
	struct ocf_freelist *freelist;

	env_rwsem_down_write(&pool->list_sem);

	ENV_BUG_ON(id >= pool->count);

	freelist = pool->freelist[id];

	ENV_BUG_ON(!freelist);
	ENV_BUG_ON(freelist->deleted);

	if (env_atomic_read(&freelist->part.curr_size) == 0)
		_ocf_freelist_remove(pool, id);
	else
		freelist->deleted = true;

	env_rwsem_up_write(&pool->list_sem);
}

void ocf_freelist_attach(struct ocf_freelist_pool *pool,
		ocf_cache_line_t collision_table_entries)
{
	unsigned i;

	ocf_freelist_detach(pool);

	env_rwsem_down_read(&pool->list_sem);

	for (i = 0; i < pool->count; i++) {
		pool->freelist[i]->part.head = collision_table_entries;
		pool->freelist[i]->part.tail = collision_table_entries;
		env_atomic_set(&pool->freelist[i]->part.curr_size, 0);
	}

	env_rwsem_up_read(&pool->list_sem);
}

/* Actually deallocate and remove deleted freelists from the pool - if there are
 * elements on the removed freelists, freelist_balance must be performed after
 * this to make sure cachelines from removed freelist are re-used */
void ocf_freelist_detach(struct ocf_freelist_pool *pool)
{
	struct ocf_freelist *freelist;
	unsigned deleted, i;

	env_rwsem_down_write(&pool->list_sem);

	/* Dealloc deleted freelist and move those remaining to the beginning
 	 * of array */
	deleted = 0;
	for (i = 0; i < pool->count; i++) {
		freelist = pool->freelist[i];
		if (freelist == NULL || freelist->deleted) {
			_ocf_freelist_remove(pool, i);
			deleted++;
		} else {
			pool->freelist[i - deleted] = freelist;

			/* only the first freelist (backup) is expected not to
			 * have an associated queue */
			ENV_BUG_ON(deleted && !freelist->queue);

			if (freelist->queue) {
				ocf_queue_set_freelist(freelist->queue,
				i - deleted);
			}
		}
	}
	pool->count -= deleted;
	env_atomic_set(&pool->last_used, 0);
	pool->freelist = env_realloc(pool->freelist, pool->count *
			sizeof(pool->freelist[0]), ENV_MEM_NORMAL);

	/* realloc shouldn't fail when downsizing the allocation */
	ENV_BUG_ON(!pool->freelist);

	env_rwsem_up_write(&pool->list_sem);
}

/* TODO: add freelist balancing , special case for BACKUP_FREELIST_IDX freelist*/
