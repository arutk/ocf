/*
 * Copyright(c) 2019-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata/metadata.h"

struct ocf_freelist {
	/* parent cache */
	struct ocf_cache *cache;

	/* freelist partition list heads */
	struct list_head *part;

	/* freelist lock array */
	env_spinlock *lock;

	/* cacheline indexed array of partition list elements */
	struct list_head *elem;

	/* number of free lists */
	uint32_t count;

	/* next slowpath victim idx */
	env_atomic slowpath_victim_idx;

	/* total number of free lines */
	env_atomic64 total_free;
};

static void ocf_freelist_lock(ocf_freelist_t freelist, uint32_t ctx)
{
	env_spinlock_lock(&freelist->lock[ctx]);
}

static int ocf_freelist_trylock(ocf_freelist_t freelist, uint32_t ctx)
{
	return env_spinlock_trylock(&freelist->lock[ctx]);
}

static void ocf_freelist_unlock(ocf_freelist_t freelist, uint32_t ctx)
{
	env_spinlock_unlock(&freelist->lock[ctx]);
}

static ocf_cache_line_t next_phys_invalid(ocf_cache_t cache,
		ocf_cache_line_t phys)
{
	ocf_cache_line_t lg;
	ocf_cache_line_t collision_table_entries =
			ocf_metadata_collision_table_entries(cache);

	if (phys == collision_table_entries)
		return collision_table_entries;

	lg = ocf_metadata_map_phy2lg(cache, phys);
	while (metadata_test_valid_any(cache, lg)) {
		++phys;

		if (phys == collision_table_entries)
			break;

		lg = ocf_metadata_map_phy2lg(cache, phys);
	}

	return phys;
}

/* Assign unused cachelines to freelist */
void ocf_freelist_populate(ocf_freelist_t freelist,
		ocf_cache_line_t num_free_clines)
{
	unsigned step = 0;
	ocf_cache_t cache = freelist->cache;
	unsigned num_freelists = freelist->count;
	ocf_cache_line_t phys, coll_idx;
	ocf_cache_line_t collision_table_entries =
			ocf_metadata_collision_table_entries(cache);
	unsigned freelist_idx;
	uint64_t freelist_size;

	phys = 0;
	for (freelist_idx = 0; freelist_idx < num_freelists; freelist_idx++)
	{
		struct list_head *head = &freelist->part[freelist_idx];

		/* calculate current freelist pattition size */
		freelist_size = num_free_clines / num_freelists;
		if (freelist_idx < (num_free_clines % num_freelists))
			++freelist_size;


		if (!freelist_size)
			continue;

		/* populate freelist partition */
		while (freelist_size--) {
			phys = next_phys_invalid(cache, phys);
			ENV_BUG_ON(phys == collision_table_entries);
			coll_idx = ocf_metadata_map_phy2lg(cache, phys);
			++phys;

			list_add_tail(&freelist->elem[coll_idx], head);

			OCF_COND_RESCHED_DEFAULT(step);
		}
	}

	/* we should have reached the last invalid cache line */
	phys = next_phys_invalid(cache, phys);
	ENV_BUG_ON(phys != collision_table_entries);

	env_atomic64_set(&freelist->total_free, num_free_clines);
}

static void ocf_freelist_add_cache_line(ocf_freelist_t freelist,
		uint32_t ctx, ocf_cache_line_t line)
{
	ocf_cache_line_t line_entries = ocf_metadata_collision_table_entries(
							freelist->cache);

	ENV_BUG_ON(line >= line_entries);

	list_add_tail(&freelist->elem[line], &freelist->part[ctx]);

	env_atomic64_inc(&freelist->total_free);
}

typedef enum {
	OCF_FREELIST_ERR_NOLOCK = 1,
	OCF_FREELIST_ERR_LIST_EMPTY,
} ocf_freelist_get_err_t;

static ocf_freelist_get_err_t ocf_freelist_get_cache_line_ctx(
		ocf_freelist_t freelist, uint32_t ctx, bool can_wait,
		ocf_cache_line_t *cline)
{
	struct list_head *elem;

	if (list_empty(&freelist->part[ctx]))
		return -OCF_FREELIST_ERR_LIST_EMPTY;

	if (!can_wait && ocf_freelist_trylock(freelist, ctx))
		return -OCF_FREELIST_ERR_NOLOCK;

	if (can_wait)
		ocf_freelist_lock(freelist, ctx);

	if (list_empty(&freelist->part[ctx])) {
		ocf_freelist_unlock(freelist, ctx);
		return -OCF_FREELIST_ERR_LIST_EMPTY;
	}

	elem = freelist->part[ctx].next;
	list_del(elem);

	ocf_freelist_unlock(freelist, ctx);

	*cline = (ocf_cache_line_t)(elem - freelist->elem);

	return 0;
}

static int get_next_victim_freelist(ocf_freelist_t freelist)
{
	int ctx, next;

	do {
		ctx = env_atomic_read(&freelist->slowpath_victim_idx);
		next = (ctx + 1) % freelist->count;
	} while (ctx != env_atomic_cmpxchg(&freelist->slowpath_victim_idx, ctx,
			next));

	return ctx;
}

static bool ocf_freelist_get_cache_line_slow(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	int i, ctx;
	int err;
	bool lock_err;

	/* try slowpath without waiting on lock */
	lock_err = false;
	for (i = 0; i < freelist->count; i++) {
		ctx = get_next_victim_freelist(freelist);
		err = ocf_freelist_get_cache_line_ctx(freelist, ctx, false,
				cline);
		if (!err)
			return true;
		if (err == -OCF_FREELIST_ERR_NOLOCK)
			lock_err = true;
	}

	if (!lock_err) {
		/* Slowpath failed due to empty freelists - no point in
		 * iterating through contexts to attempt slowpath with full
		 * lock */
		return false;
	}

	/* slow path with waiting on lock */
	for (i = 0; i < freelist->count; i++) {
		ctx = get_next_victim_freelist(freelist);
		if (!ocf_freelist_get_cache_line_ctx(freelist, ctx, true,
				cline)) {
			return true;
		}
	}

	return false;
}

static bool ocf_freelist_get_cache_line_fast(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	bool ret;
	uint32_t ctx = env_get_execution_context();

	ret = !ocf_freelist_get_cache_line_ctx(freelist, ctx, false, cline);

	env_put_execution_context(ctx);

	return ret;
}

bool ocf_freelist_get_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t *cline)
{
	if (env_atomic64_read(&freelist->total_free) == 0)
		return false;

	if (!ocf_freelist_get_cache_line_fast(freelist, cline))
		return ocf_freelist_get_cache_line_slow(freelist, cline);

	return true;
}

void ocf_freelist_put_cache_line(ocf_freelist_t freelist,
		ocf_cache_line_t cline)
{
	uint32_t ctx = env_get_execution_context();

	ocf_freelist_lock(freelist, ctx);
	ocf_freelist_add_cache_line(freelist, ctx, cline);
	ocf_freelist_unlock(freelist, ctx);
	env_put_execution_context(ctx);
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
	env_atomic64_set(&freelist->total_free, 0);
	freelist->lock = env_vzalloc(sizeof(freelist->lock[0]) * num);
	freelist->part = env_vzalloc(sizeof(freelist->part[0]) * num);
	freelist->elem = env_vzalloc(sizeof(freelist->elem[0]) * line_entries);

	if (!freelist->lock || !freelist->part || !freelist->elem)
		goto free_allocs;

	for (i = 0; i < num; i++) {
		if (env_spinlock_init(&freelist->lock[i]))
			goto spinlock_err;

		INIT_LIST_HEAD(&freelist->part[i]);
	}

	return freelist;

spinlock_err:
	while (i--)
		env_spinlock_destroy(&freelist->lock[i]);
free_allocs:
	env_vfree(freelist->lock);
	env_vfree(freelist->part);
	env_vfree(freelist->elem);
	env_vfree(freelist);
	return NULL;
}

void ocf_freelist_deinit(ocf_freelist_t freelist)
{
	int i;

	for (i = 0; i < freelist->count; i++)
		env_spinlock_destroy(&freelist->lock[i]);
	env_vfree(freelist->lock);
	env_vfree(freelist->part);
	env_vfree(freelist);
}

ocf_cache_line_t ocf_freelist_num_free(ocf_freelist_t freelist)
{
	return env_atomic64_read(&freelist->total_free);
}

