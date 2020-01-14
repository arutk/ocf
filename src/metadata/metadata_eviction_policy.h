/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_EVICTION_H__
#define __METADATA_EVICTION_H__

void ocf_metadata_hash_get_eviction_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		union eviction_policy_meta *eviction);
/*
 * SET
 */
void ocf_metadata_hash_set_eviction_policy(
		struct ocf_cache *cache, ocf_cache_line_t line,
		union eviction_policy_meta *eviction);

#endif /* METADATA_EVICTION_H_ */
