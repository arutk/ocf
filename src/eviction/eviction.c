/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "eviction.h"
#include "ops.h"
#include "../utils/utils_part.h"
#include "../engine/engine_common.h"

static uint32_t ocf_evict_calculate(struct ocf_user_part *part,
		uint32_t to_evict)
{
	if (part->runtime->curr_size <= part->config->min_size) {
		/*
		 * Cannot evict from this partition because current size
		 * is less than minimum size
		 */
		return 0;
	}

	if (to_evict < OCF_TO_EVICTION_MIN)
		to_evict = OCF_TO_EVICTION_MIN;

	if (to_evict > (part->runtime->curr_size - part->config->min_size))
		to_evict = part->runtime->curr_size - part->config->min_size;

	return to_evict;
}

static inline uint32_t ocf_evict_do(struct ocf_request *req)
{
	uint32_t to_evict = 0, evicted = 0;
	struct ocf_user_part *part;
	ocf_part_id_t target_part_id = req->part_id;
	ocf_cache_t cache = req->cache;
	uint32_t evict_cline_no = ocf_engine_unmapped_count(req);
	struct ocf_user_part *target_part = &cache->user_parts[target_part_id];
	ocf_part_id_t part_id;

	/* For each partition from the lowest priority to highest one */
	for_each_part(cache, part, part_id) {
		/*
		 * Check stop and continue conditions
		 */
		if (target_part->config->priority > part->config->priority) {
			/*
			 * iterate partition have higher priority, do not evict
			 */
			break;
		}
		if (!part->config->flags.eviction) {
			/* It seams that no more partition for eviction */
			break;
		}
		if (part_id == target_part_id) {
			/* Omit targeted, evict from different first */
			continue;
		}
		if (evicted >= evict_cline_no) {
			/* Evicted requested number of cache line, stop */
			goto out;
		}

		to_evict = ocf_evict_calculate(part, evict_cline_no);
		if (to_evict == 0) {
			/* No cache lines to evict for this partition */
			continue;
		}

		evicted += evp_lru_req_clines(req,
				part_id, to_evict);
	}

	if (evicted < evict_cline_no) {
		/* Now we can evict form targeted partition */
		to_evict = ocf_evict_calculate(target_part, evict_cline_no);
		if (to_evict) {
			evicted += evp_lru_req_clines(req,
					target_part_id, to_evict);
		}
	}

out:
	return evicted;
}

int space_managment_evict_do(struct ocf_request *req)
{
	uint32_t needed = ocf_engine_unmapped_count(req);
	uint32_t evicted;

	evicted = ocf_evict_do(req);

	if (needed <= evicted)
		return LOOKUP_MAPPED;

	req->info.mapping_error |= true;
	return LOOKUP_MISS;
}
