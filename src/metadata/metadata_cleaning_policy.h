/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __METADATA_CLEANING_POLICY_H__
#define __METADATA_CLEANING_POLICY_H__

/*
 * GET
 */
void
ocf_metadata_hash_get_cleaning_policy(struct ocf_cache *cache,
		ocf_cache_line_t line, struct cleaning_policy_meta *policy);

/*
 * SET
 */
void
ocf_metadata_hash_set_cleaning_policy(struct ocf_cache *cache,
		ocf_cache_line_t line, struct cleaning_policy_meta *policy);

#endif /* METADATA_CLEANING_POLICY_H_ */
