/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata/metadata.h"
#include "metadata/metadata_partition.h"

struct ocf_freelist {
	struct ocf_cache *cache;
	struct ocf_part *part;
	uint32_t count;
	env_atomic last_used;
	env_atomic64 total_free;
	env_spinlock *lock;
};

static void ocf_freelist_lock(ocf_freelist_t freelist, uint32_t ctx)
{
	env_spinlock_lock(&freelist->lock[ctx]);
}

static void ocf_freelist_unlock(ocf_freelist_t freelist, uint32_t ctx)
{
	env_spinlock_unlock(&freelist->lock[ctx]);
}

/* Sets the given collision_index as the new _head_ of the Partition list. */
static void _ocf_freelist_remove_cache_line(ocf_freelist_t freelist,
		uint32_t ctx, ocf_cache_line_t cline)
{
	struct ocf_cache *cache = freelist->cache;
	struct ocf_part *freelist_part = &freelist->part[ctx];
	int is_head, is_tail;
	ocf_part_id_t invalid_part_id = PARTITION_INVALID;
	ocf_cache_line_t prev, next;
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
							freelist->cache);
	uint32_t free;

	ENV_BUG_ON(cline >= line_entries);

	/* Get Partition info */
	ocf_metadata_get_partition_info(cache, cline, NULL, &next, &prev);

	/* Find out if this node is Partition _head_ */
	is_head = (prev == line_entries);
	is_tail = (next == line_entries);

	free = env_atomic64_read(&freelist_part->curr_size);

	/* Case 1: If we are head and there is only one node. So unlink node
	 * and set that there is no node left in the list.
	 */
	if (is_head && free == 1) {
		ocf_metadata_set_partition_info(cache, cline, invalid_part_id,
				line_entries, line_entries);
		freelist_part->head = line_entries;
		freelist_part->tail = line_entries;
	} else if (is_head) {
		/* Case 2: else if this collision_index is partition list head,
		 * but many nodes, update head and return
		 */
		ENV_BUG_ON(next >= line_entries);

		freelist_part->head = next;
		ocf_metadata_set_partition_prev(cache, next, line_entries);
		ocf_metadata_set_partition_next(cache, cline, line_entries);
	} else if (is_tail) {
		/* Case 3: else if this cline is partition list tail */
		ENV_BUG_ON(prev >= line_entries);

		freelist_part->tail = prev;
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

	env_atomic64_dec(&freelist_part->curr_size);
	env_atomic64_dec(&freelist->total_free);
}

static ocf_cache_line_t next_phys_invalid(ocf_cache_t cache,
		ocf_cache_line_t phys)
{
	ocf_cache_line_t lg;
	ocf_cache_line_t collision_table_entries =
			cache->device->collision_table_entries;

	if (phys == collision_table_entries)
		return collision_table_entries;

	lg = ocf_metadata_map_phy2lg(cache, phys);
	while (metadata_test_valid(cache, lg)) {
		++phys;

		if (phys == collision_table_entries)
			break;

		lg = ocf_metadata_map_phy2lg(cache, phys);
	}

	return phys;
}

void ocf_freelist_part_init(ocf_freelist_t freelist,
		ocf_cache_line_t num_free_clines)
{
	unsigned step = 0;
	ocf_cache_t cache = freelist->cache;
	unsigned num_freelists = freelist->count;
	ocf_cache_line_t prev, next, idx;
	ocf_cache_line_t phys;
	ocf_cache_line_t collision_table_entries =
			cache->device->collision_table_entries;
	unsigned freelist_idx;
	uint64_t size;

	phys = 0;
	for (freelist_idx = 0; freelist_idx < num_freelists; freelist_idx++)
	{
		/* calculate freelist size */
		size = num_free_clines / num_freelists;
		if (freelist_idx < (num_free_clines % num_freelists))
			++size;

		env_atomic64_set(&freelist->part[freelist_idx].curr_size, size);

		if (!size) {
			freelist->part[freelist_idx].head =
					collision_table_entries;
			freelist->part[freelist_idx].tail =
					collision_table_entries;
			continue;
		}

		phys = next_phys_invalid(cache, phys);
		ENV_BUG_ON(phys == collision_table_entries);
		idx = ocf_metadata_map_phy2lg(cache, phys);
		++phys;

		freelist->part[freelist_idx].head = idx;

		prev = collision_table_entries;
		while (--size) {
			phys = next_phys_invalid(cache, phys);
			ENV_BUG_ON(phys == collision_table_entries);
			next = ocf_metadata_map_phy2lg(cache, phys);
			++phys;

			ocf_metadata_set_partition_info(cache, idx,
					PARTITION_INVALID, next, prev);

			prev = idx;
			idx = next;

			OCF_COND_RESCHED_DEFAULT(step);
		}

		ocf_metadata_set_partition_info(cache, idx, PARTITION_INVALID,
			collision_table_entries, prev);

		freelist->part[freelist_idx].tail = idx;
	}

	/* we should have reached the last invalid cache line */
	phys = next_phys_invalid(cache, phys);
	ENV_BUG_ON(phys != collision_table_entries);

	env_atomic64_set(&freelist->total_free, num_free_clines);
}

static void ocf_freelist_add_cache_line(ocf_freelist_t freelist,
		uint32_t ctx, ocf_cache_line_t line)
{
	struct ocf_cache *cache = freelist->cache;
	struct ocf_part *freelist_part = &freelist->part[ctx];
	ocf_cache_line_t tail;
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
							freelist->cache);
	ocf_part_id_t invalid_part_id = PARTITION_INVALID;

	ENV_BUG_ON(line >= line_entries);

	if (env_atomic64_read(&freelist_part->curr_size) == 0) {
		freelist_part->head = line;
		freelist_part->tail = line;

		ocf_metadata_set_partition_info(cache, line, invalid_part_id,
				line_entries, line_entries);
	} else {
		tail = freelist_part->tail;

		ENV_BUG_ON(tail >= line_entries);

		ocf_metadata_set_partition_info(cache, line, invalid_part_id,
				line_entries, tail);
		ocf_metadata_set_partition_next(cache, tail, line);

		freelist_part->tail = line;
	}

	env_atomic64_inc(&freelist_part->curr_size);
	env_atomic64_inc(&freelist->total_free);
}

static int ocf_freelist_get_cache_line_ctx(ocf_freelist_t freelist,
		uint32_t ctx, ocf_cache_line_t *cline)
{
	if (env_atomic64_read(&freelist->part[ctx].curr_size) == 0)
		return -ENOSPC;

	ocf_freelist_lock(freelist, ctx);
	if (env_atomic64_read(&freelist->part[ctx].curr_size) == 0) {
		ocf_freelist_unlock(freelist, ctx);
		return -ENOSPC;
	}

	*cline = freelist->part[ctx].head;
	_ocf_freelist_remove_cache_line(freelist, ctx, *cline);

	ocf_freelist_unlock(freelist, ctx);

	return 0;
}

static int get_next_freelist(ocf_freelist_t freelist)
{
	int ctx, next;

	do {
		ctx = env_atomic_read(&freelist->last_used);
		next = (ctx + 1) % freelist->count;
	} while (ctx != env_atomic_cmpxchg(&freelist->last_used, ctx,
			next));

	return ctx;
}

static int ocf_freelist_get_cache_line_slow(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	int i, ctx;

	for (i = 0; i < freelist->count; i++) {
		ctx = get_next_freelist(freelist);
		if (!ocf_freelist_get_cache_line_ctx(freelist, ctx, cline))
			return 0;
	}

	return -ENOSPC;
}

static int ocf_freelist_get_cache_line_fast(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	int res;
	uint32_t ctx = env_get_execution_context();

	res = ocf_freelist_get_cache_line_ctx(freelist, ctx, cline);

	env_put_execution_context();

	return res;
}

int ocf_freelist_get_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{

	if (env_atomic64_read(&freelist->total_free) == 0)
		return -ENOSPC;

	if (ocf_freelist_get_cache_line_fast(freelist, cline))
		return ocf_freelist_get_cache_line_slow(freelist, cline);

	return 0;
}

void ocf_freelist_put_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t cline)
{
	uint32_t ctx = env_get_execution_context();
	ocf_freelist_lock(freelist, ctx);
	ocf_freelist_add_cache_line(freelist, ctx, cline);
	ocf_freelist_unlock(freelist, ctx);
	env_put_execution_context();
}

ocf_freelist_t ocf_freelist_init(struct ocf_cache *cache)
{
	uint32_t num;
	int i;
	ocf_freelist_t freelist;
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
						cache);

	freelist = env_vzalloc(sizeof(*freelist));
	if (!freelist)
		return NULL;

	num = env_get_execution_context_count();

	freelist->cache = cache;
	freelist->count = num;
	freelist->lock = env_vzalloc(sizeof(freelist->lock[0]) * num);
	freelist->part = env_vzalloc(sizeof(freelist->part[0]) * num);

	if (!freelist->lock || !freelist->part) {
		env_vfree(freelist->lock);
		env_vfree(freelist->part);
		env_vfree(freelist);
		return NULL;
	}

	for (i = 0; i < num; i++) {
		env_spinlock_init(&freelist->lock[i]);
		freelist->part[i].head = line_entries;
		freelist->part[i].tail = line_entries;
		env_atomic64_set(&freelist->part[i].curr_size, 0);
	}

	return freelist;
}

void ocf_freelist_deinit(ocf_freelist_t freelist)
{
	// TODO: deinit locks
	env_vfree(freelist->lock);
	env_vfree(freelist->part);
	env_vfree(freelist);
}


unsigned ocf_freelist_get_count(ocf_freelist_t freelist)
{
	return freelist->count;
}
