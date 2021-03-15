/*
 * Copyright(c) 2012-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef LAYER_EVICTION_POLICY_OPS_H_
#define LAYER_EVICTION_POLICY_OPS_H_

#include "eviction.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_metadata_concurrency.h"

/**
 * @brief Initialize cache line before adding it into eviction
 *
 * @note This operation is called under WR metadata lock
 */
static inline void ocf_eviction_init_cache_line(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	evp_lru_init_cline(cache, line);
}

static inline void ocf_eviction_purge_cache_line(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	evp_lru_rm_cline(cache, line);
}

static inline bool ocf_eviction_can_evict(struct ocf_cache *cache)
{
	return evp_lru_can_evict(cache);
}

static inline uint32_t ocf_eviction_need_space(ocf_cache_t cache,
		struct ocf_request *req, struct ocf_user_part *part,
		uint32_t clines)
{
	return evp_lru_req_clines(req, part, clines);
}

static inline void ocf_eviction_set_hot_cache_line(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	evp_lru_hot_cline(cache, line);
}

static inline void ocf_eviction_initialize(struct ocf_cache *cache,
		struct ocf_user_part *part)
{
	evp_lru_init_evp(cache, part);
}

static inline void ocf_eviction_flush_dirty(ocf_cache_t cache,
		struct ocf_user_part *part, ocf_queue_t io_queue,
		uint32_t count)
{
	evp_lru_clean(cache, part, io_queue, count);
}

#endif /* LAYER_EVICTION_POLICY_OPS_H_ */
