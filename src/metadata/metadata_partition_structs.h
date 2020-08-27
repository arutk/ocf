/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_PARTITION_STRUCTS_H__
#define __METADATA_PARTITION_STRUCTS_H__

#include "../utils/utils_list.h"
#include "../cleaning/cleaning.h"
#include "../eviction/eviction.h"

struct ocf_user_part_config {
        uint32_t min_size;
        uint32_t max_size;
        int16_t priority;
        ocf_cache_mode_t cache_mode;
        struct {
                uint8_t valid : 1;
                uint8_t added : 1;
                uint8_t eviction : 1;
                        /*!< This bits is setting during partition sorting,
                         * and means that can evict from this partition
                         */
        } flags;

        char name[OCF_IO_CLASS_NAME_MAX];
} __attribute__ ((aligned (64)));;

struct ocf_user_part_runtime {
        uint32_t curr_size;
        uint32_t head;
        struct cleaning_policy cleaning;
} __attribute__ ((aligned (64)));

typedef bool ( *_lru_hash_locked_pfn)(void *context,
		ocf_core_id_t core_id, uint64_t core_line);


struct ocf_lru_iter_state
{
	ocf_cache_t cache;
	ocf_part_id_t part_id;
	struct ocf_user_part *part;
	ocf_cache_line_t end_marker;
	uint32_t empty_evps_no;
	uint32_t evp;
	uint32_t num_evps;
	_lru_hash_locked_pfn hash_locked;
	void *context;
	bool empty_evps[EVICTION_MAX_PARTS];
	bool clean : 1;
	bool lock_write : 1;
	bool exclusive: 1;
};

struct ocf_part_cleaning_ctx {
	env_atomic state;
	struct ocf_lru_iter_state lru_iter;
	env_atomic64  next_lru;
	ocf_cache_line_t clines[32];
	unsigned num_clines;
} __attribute__ ((aligned (64)));;

struct ocf_user_part {
        struct ocf_user_part_config *config;
        struct ocf_user_part_runtime *runtime;
        struct ocf_lst_entry lst_valid;
	struct ocf_part_cleaning_ctx cleaning;
	struct eviction_policy *eviction[EVICTION_MAX_PARTS];
} __attribute__ ((aligned (64)));

#endif /* __METADATA_PARTITION_STRUCTS_H__ */
