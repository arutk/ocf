/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_COLLISION_H__
#define __METADATA_COLLISION_H__

/**
 * @brief Metadata map structure
 */
struct ocf_metadata_partition_list_info {
	/*!<  Next cache line in collision list*/
	ocf_cache_line_t partition_prev;
	/*!<  Previous cache line in the same partition*/
	ocf_cache_line_t partition_next;
	/*!<  Next cache line in the same partition*/
};


struct ocf_metadata_list_info {
	ocf_cache_line_t prev_col;
		/*!<  Previous cache line in collision list */
	ocf_cache_line_t next_col;
};

/**
 * @brief Metadata map structure
 */

struct ocf_metadata_cacheline {
	uint64_t core_line; // 8
		/*!<  Core line addres on cache mapped by this strcture */

	uint16_t core_id; // 2
		/*!<  ID of core where is assigned this cache line*/

	/*!<  ID of partition where is assigned this cache line*/
	uint8_t partition_id;
	ocf_cache_line_t hash; // 4
	struct ocf_metadata_list_info list; // 8
	struct cleaning_policy_meta cleaning; // 12
	union eviction_policy_meta eviction;  // 12
};


static inline ocf_cache_line_t ocf_metadata_map_lg2phy(
		struct ocf_cache *cache, ocf_cache_line_t coll_idx)
{
	 return cache->metadata.iface.layout_iface->lg2phy(cache,
			coll_idx);
}

static inline ocf_cache_line_t ocf_metadata_map_phy2lg(
		struct ocf_cache *cache, ocf_cache_line_t cache_line)
{
	 return cache->metadata.iface.layout_iface->phy2lg(cache,
			cache_line);
}

void ocf_metadata_hash_set_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next, ocf_cache_line_t prev);

void ocf_metadata_hash_set_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t next);

void ocf_metadata_hash_set_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t prev);

 void ocf_metadata_hash_get_collision_info(
		struct ocf_cache *cache, ocf_cache_line_t line,
		ocf_cache_line_t *next, ocf_cache_line_t *prev);

static inline ocf_cache_line_t ocf_metadata_hash_get_collision_next(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t next;

	ocf_metadata_hash_get_collision_info(cache, line, &next, NULL);
	return next;
}

static inline ocf_cache_line_t ocf_metadata_hash_get_collision_prev(
		struct ocf_cache *cache, ocf_cache_line_t line)
{
	ocf_cache_line_t prev;

	ocf_metadata_hash_get_collision_info(cache, line, NULL, &prev);
	return prev;
}

void ocf_metadata_add_to_collision(struct ocf_cache *cache,
		ocf_core_id_t core_id, uint64_t core_line,
		ocf_cache_line_t hash, ocf_cache_line_t cache_line);

void ocf_metadata_remove_from_collision(struct ocf_cache *cache,
		ocf_cache_line_t line, ocf_part_id_t part_id);

 void ocf_metadata_hash_start_collision_shared_access(
		struct ocf_cache *cache, ocf_cache_line_t line);

 void ocf_metadata_hash_end_collision_shared_access(
		struct ocf_cache *cache, ocf_cache_line_t line);


#endif /* METADATA_COLLISION_H_ */
