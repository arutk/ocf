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
        char name[OCF_IO_CLASS_NAME_MAX];
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
};

struct ocf_user_part_runtime {
        uint32_t curr_size;
        uint32_t head;
        struct eviction_policy eviction[EVICTION_MAX_PARTS];
        struct cleaning_policy cleaning;
};

struct ocf_lru_iter_state
{
	ocf_cache_t cache;
	ocf_part_id_t part_id;
	struct ocf_user_part *part;
	ocf_cache_line_t curr_cline[EVICTION_MAX_PARTS];
	bool empty_evps[EVICTION_MAX_PARTS];
	ocf_cache_line_t end_marker;
	uint32_t empty_evps_no;
	uint32_t evp;
	uint32_t num_evps;
};

struct ocf_user_part {
        struct ocf_user_part_config *config;
        struct ocf_user_part_runtime *runtime;

	env_atomic cleaning;
	struct ocf_lru_iter_state eviction_clean_iter;
	uint32_t next_evp;
        struct ocf_lst_entry lst_valid;
};


#endif /* __METADATA_PARTITION_STRUCTS_H__ */
