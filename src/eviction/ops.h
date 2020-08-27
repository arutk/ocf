/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef LAYER_EVICTION_POLICY_OPS_H_
#define LAYER_EVICTION_POLICY_OPS_H_

#include "eviction.h"
#include "../metadata/metadata.h"
#include "../concurrency/ocf_metadata_concurrency.h"

/**
 * @brief Initialize cache line before adding it into eviction
 *
 * @note This operation is called under WR metadata lock
 */

void evp_lru_init_cline(ocf_cache_t cache, ocf_cache_line_t cline);
void evp_lru_rm_cline(ocf_cache_t cache, ocf_cache_line_t cline);
uint32_t evp_lru_req_clines(struct ocf_request *req,
		ocf_part_id_t part_id, uint32_t cline_no);
void evp_lru_hot_cline(ocf_cache_t cache, ocf_cache_line_t cline);
void evp_lru_init_evp(ocf_cache_t cache, ocf_part_id_t part_id,
		unsigned num_instances);
void evp_lru_clean_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline);
void evp_lru_dirty_cline(ocf_cache_t cache, ocf_part_id_t part_id,
		uint32_t cline);

#endif /* LAYER_EVICTION_POLICY_OPS_H_ */
