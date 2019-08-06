/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_FREELIST_H__
#define __OCF_FREELIST_H__

#include "ocf_cache_priv.h"

struct ocf_freelist;

struct ocf_freelist_pool {
	struct ocf_cache *cache;
	uint32_t count;
	env_atomic last_used;
	env_atomic total_free;
	env_rwsem list_sem;
	struct ocf_freelist **freelist;
};

#define UNSPECIFIED_FREELIST_IDX -1

int ocf_freelist_pool_init(struct ocf_freelist_pool *pool,
		struct ocf_cache *cache);
void ocf_freelist_pool_deinit(struct ocf_freelist_pool *pool);

int ocf_freelist_new(struct ocf_freelist_pool *pool, ocf_queue_t queue);
void ocf_freelist_del(struct ocf_freelist_pool *pool, int freelist);

void ocf_freelist_attach(struct ocf_freelist_pool *pool,
		ocf_cache_line_t collision_table_entries);
void ocf_freelist_detach(struct ocf_freelist_pool *pool);

int ocf_freelist_get_cache_line(struct ocf_freelist_pool *pool, int idx,
		ocf_cache_line_t *cline);
int ocf_freelist_put_cache_line(struct ocf_freelist_pool *pool, unsigned idx,
		ocf_cache_line_t cline);

void ocf_freelist_remove_cache_line(struct ocf_freelist_pool *pool,
		ocf_cache_line_t cline);

static inline int ocf_freelist_get_count(struct ocf_freelist_pool *pool)
{
	return pool->count;
}

static inline int ocf_freelist_get_free_count(struct ocf_freelist_pool *pool)
{
	return env_atomic_read(&pool->total_free);
}

#endif /* __OCF_FREELIST_H__ */
