/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_HASH_H__
#define __METADATA_HASH_H__

/**
 * @file metadata_.h
 * @brief Metadata Service - Hash Implementation
 */

#include "../ocf_request.h"
/**
 * @brief Metada hash elements type
 */
enum ocf_metadata_segment {
	metadata_segment_sb_config = 0,	/*!< Super block conf */
	metadata_segment_sb_runtime,	/*!< Super block runtime */
	metadata_segment_reserved,	/*!< Reserved space on disk */
	metadata_segment_part_config,	/*!< Part Config Metadata */
	metadata_segment_part_runtime,	/*!< Part Runtime Metadata */
	metadata_segment_core_config,	/*!< Core Config Metadata */
	metadata_segment_core_runtime,	/*!< Core Runtime Metadata */
	metadata_segment_core_uuid,	/*!< Core UUID */
	metadata_segment_eviction_runtime,
	/* .... new fixed size sections go here */

	metadata_segment_fixed_size_max,
	metadata_segment_variable_size_start = metadata_segment_fixed_size_max,

	/* sections with size dependent on cache device size go here: */
	metadata_segment_cacheline =	/*!< Cleaning policy */
			metadata_segment_variable_size_start,

	metadata_segment_hash,		/*!< Hash */
	/* .... new variable size sections go here */

	/* moving this to a separate segment as this is
	 * practically obsolete, just need to fully get
	 * rid of partition list and freelist (all
	 * needed info is on lru list */
	metadata_segment_partition_list,

	metadata_segment_max,		/*!< MAX */
};

/**
 * @brief Get metadata interface implementation
 *
 * @return metadata interface
 */
const struct ocf_metadata_iface *metadata_hash_get_iface(void);

#endif /* METADATA_HASH_H_ */
