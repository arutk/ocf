/*
 * Copyright(c) 2012-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf/ocf.h"
#include "metadata.h"
#include "metadata_internal.h"
#include "../utils/utils_part.h"

ocf_part_id_t ocf_metadata_get_partition_id(struct ocf_cache *cache,
		ocf_cache_line_t line)
{
	const struct ocf_metadata_list_info *info;
	struct ocf_metadata_ctrl *ctrl =
		(struct ocf_metadata_ctrl *) cache->metadata.priv;

	info = ocf_metadata_raw_rd_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line);

	if (info) {
		return info->partition_id;
	} else {
		ocf_metadata_error(cache);
		return PARTITION_DEFAULT;
	}
}

static void ocf_metadata_set_partition_id(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id)
{
	struct ocf_metadata_list_info *info;
	struct ocf_metadata_ctrl *ctrl =
		(struct ocf_metadata_ctrl *) cache->metadata.priv;

	info = ocf_metadata_raw_wr_access(cache,
			&(ctrl->raw_desc[metadata_segment_list_info]), line);

	if (info)
		info->partition_id = part_id;
	else
		ocf_metadata_error(cache);
}


/* Adds the given collision_index to the _head_ of the Partition list */
void ocf_metadata_add_to_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line)
{
	ocf_cache_line_t line_entries = cache->device->collision_table_entries;
	struct ocf_user_part *part = &cache->user_parts[part_id];

	ENV_BUG_ON(!(line < line_entries));

	ocf_metadata_partition_lock(&cache->metadata.lock, part_id);

	ocf_metadata_set_partition_id(cache, line, part_id);

	/* First node to added/ */
	if (!part->runtime->curr_size) {
		if (!ocf_part_is_valid(part)) {
			/* Partition becomes empty, and is not valid
			 * update list of partitions
			 */
			ocf_part_sort(cache);
		}

	}

	part->runtime->curr_size++;

	ocf_metadata_partition_unlock(&cache->metadata.lock, part_id);
}

/* Deletes the node with the given collision_index from the Partition list */
void ocf_metadata_remove_from_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line)
{
	uint32_t line_entries = cache->device->collision_table_entries;
	struct ocf_user_part *part = &cache->user_parts[part_id];

	ENV_BUG_ON(!(line < line_entries));

	ocf_metadata_partition_lock(&cache->metadata.lock, part_id);

	if (part->runtime->curr_size == 1) {
		if (!ocf_part_is_valid(part)) {
			/* Partition becomes not empty, and is not valid
			 * update list of partitions
			 */
			ocf_part_sort(cache);
		}

	}

	part->runtime->curr_size--;

	ocf_metadata_partition_unlock(&cache->metadata.lock, part_id);
}
