/*
 * Copyright(c) 2012-2018 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_FREELIST_H__
#define __OCF_FREELIST_H__

#include "ocf_cache_priv.h"

struct ocf_freelist;

struct ocf_freelist *ocf_freelist_init(struct ocf_cache *cache);
void ocf_freelist_deinit(struct ocf_freelist *freelist);

int ocf_freelist_get_cache_line(struct ocf_cache *cache, ocf_cache_line_t *cline);
void ocf_freelist_put_cache_line(struct ocf_cache *cache, ocf_cache_line_t cline);
void ocf_freelist_remove_cache_line(struct ocf_cache *cache, ocf_cache_line_t cline);

#endif /* __OCF_FREELIST_H__ */
