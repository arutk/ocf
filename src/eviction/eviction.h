/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __LAYER_EVICTION_POLICY_H__
#define __LAYER_EVICTION_POLICY_H__

#include "ocf/ocf.h"
#include "lru.h"
#include "lru_structs.h"
#include "../ocf_request.h"

#define OCF_TO_EVICTION_MIN 0UL
#define OCF_PENDING_EVICTION_LIMIT 512UL

#define EVICTION_MAX_PARTS 128U

struct eviction_policy {
	union {
		struct lru_eviction_policy lru;
	} policy;
} __attribute__ ((aligned (64)));

/* Eviction policy metadata per cache line */
union eviction_policy_meta {
	struct lru_eviction_policy_meta lru;
};

/*
 * Deallocates space from low priority partitions.
 *
 * Returns -1 on error
 * or the destination partition ID for the free buffers
 * (it matches label and is part of the object (#core_id) IO group)
 */
int space_managment_evict_do(struct ocf_request *req);

int space_management_free(ocf_cache_t cache, uint32_t count);

#endif
