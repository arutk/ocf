/*
 * Copyright(c) 2012-2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_PARTITION_H__
#define __METADATA_PARTITION_H__

#include "metadata_partition_structs.h"
#include "../ocf_cache_priv.h"

#define PARTITION_DEFAULT		0
#define PARTITION_INVALID		((ocf_part_id_t)-1)
#define PARTITION_SIZE_MAX		((ocf_cache_line_t)-1)

ocf_part_id_t ocf_metadata_get_partition_id(struct ocf_cache *cache,
		ocf_cache_line_t line);

void ocf_metadata_add_to_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line);

void ocf_metadata_remove_from_partition(struct ocf_cache *cache,
		ocf_part_id_t part_id, ocf_cache_line_t line);

#endif /* __METADATA_PARTITION_H__ */
