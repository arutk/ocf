/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_EVICTION_H__
#define __METADATA_EVICTION_H__

union eviction_policy_meta *
ocf_metadata_hash_get_eviction_policy(
		struct ocf_cache *cache, ocf_cache_line_t line);

#endif /* METADATA_EVICTION_H_ */
