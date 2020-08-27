/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#ifndef __EVICTION_LRU_STRUCTS_H__

#define __EVICTION_LRU_STRUCTS_H__

struct lru_eviction_policy_meta {
	/* LRU pointers 3*4=12 bytes */
	uint32_t prev;
	uint32_t next;
	uint32_t hot;
};

struct ocf_lru_list {
	uint32_t num_nodes;
	uint32_t head;
	uint32_t tail;
	uint32_t num_hot;
	uint32_t last_hot;
} __attribute__ ((aligned (64)));;

struct lru_eviction_policy {
	struct ocf_lru_list clean;
	struct ocf_lru_list dirty;
};

// TODO: configurable ?
#define HOT_RATIO 2

#endif
