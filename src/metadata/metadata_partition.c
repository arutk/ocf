/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata.h"
#include "../utils/utils_part.h"


void ocf_metadata_add_to_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line)
{
	struct ocf_user_part *part = &cache->user_parts[part_id];


	ocf_metadata_hash_set_partition_id(cache, line, part_id);

	ocf_metadata_partition_lock(&cache->metadata.lock, part_id);
	part->runtime->curr_size++;
	ocf_metadata_partition_unlock(&cache->metadata.lock, part_id);
}

void ocf_metadata_remove_from_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line)
{
	struct ocf_user_part *part = &cache->user_parts[part_id];

	ocf_metadata_partition_lock(&cache->metadata.lock, part_id);
	part->runtime->curr_size--;
	ocf_metadata_partition_unlock(&cache->metadata.lock, part_id);

}
