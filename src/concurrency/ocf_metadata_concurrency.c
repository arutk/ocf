/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_metadata_concurrency.h"

void ocf_metadata_concurrency_init(struct ocf_cache *cache)
{
	env_spinlock_init(&cache->metadata.lock.eviction);
	env_rwlock_init(&cache->metadata.lock.status);
	env_rwsem_init(&cache->metadata.lock.global);
}

int ocf_metadata_concurrency_attached_init(struct ocf_cache *cache)
{
	int i;

	cache->metadata.lock.hash = env_vzalloc(sizeof(env_rwsem) *
			cache->device->hash_table_entries);
	if (!cache->metadata.lock.hash)
		return -OCF_ERR_NO_MEM;
	for (i = 0; i < cache->device->hash_table_entries; i++) {
		env_rwsem_init(&cache->metadata.lock.hash[i]);
	}

	return 0;
}

void ocf_metadata_start_exclusive_access(struct ocf_cache *cache)
{
        env_rwsem_down_write(&cache->metadata.lock.global);
}

int ocf_metadata_try_start_exclusive_access(struct ocf_cache *cache)
{
	return env_rwsem_down_write_trylock(&cache->metadata.lock.global);
}

void ocf_metadata_end_exclusive_access(struct ocf_cache *cache)
{
        env_rwsem_up_write(&cache->metadata.lock.global);
}

void ocf_metadata_start_shared_access(struct ocf_cache *cache)
{
        env_rwsem_down_read(&cache->metadata.lock.global);
}

int ocf_metadata_try_start_shared_access(struct ocf_cache *cache)
{
	return env_rwsem_down_read_trylock(&cache->metadata.lock.global);
}

void ocf_metadata_end_shared_access(struct ocf_cache *cache)
{
        env_rwsem_up_read(&cache->metadata.lock.global);
}

void ocf_metadata_hash_lock(struct ocf_cache *cache,
		ocf_cache_line_t hash, int rw)
{
	ENV_BUG_ON(hash >= cache->device->hash_table_entries);

	if (rw == OCF_METADATA_WR)
		env_rwsem_down_write(&cache->metadata.lock.hash[hash]);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_down_read(&cache->metadata.lock.hash[hash]);
	else
		ENV_BUG();
}

void ocf_metadata_hash_unlock(struct ocf_cache *cache,
		ocf_cache_line_t hash, int rw)
{
	ENV_BUG_ON(hash >= cache->device->hash_table_entries);

	if (rw == OCF_METADATA_WR)
		env_rwsem_up_write(&cache->metadata.lock.hash[hash]);
	else if (rw == OCF_METADATA_RD)
		env_rwsem_up_read(&cache->metadata.lock.hash[hash]);
	else
		ENV_BUG();
}

int ocf_metadata_hash_try_lock(struct ocf_cache *cache,
		ocf_cache_line_t hash, int rw)
{
	int result = -1;

	ENV_BUG_ON(hash >= cache->device->hash_table_entries);

	if (rw == OCF_METADATA_WR) {
		result = env_rwsem_down_write_trylock(
				&cache->metadata.lock.hash[hash]);
	} else if (rw == OCF_METADATA_RD) {
		result = env_rwsem_down_read_trylock(
				&cache->metadata.lock.hash[hash]);
	} else {
		ENV_BUG();
	}

	if (!result)
		return -1;

	return 0;
}

/* Iterate over hash buckets for all core lines in the request. Each hash bucket
 * is visited only once. The order in which iterator visits hash buckets is
 * strict - for all requests with core lines belonging to hash buckets no A and
 * B, the iterator always visits either A or B first.
 */
#define for_each_req_hash_strict(req, i, pos) \
	for (pos = req->first_hash_bucket, i = 0; \
		i < min(req->core_line_count, \
				req->cache->device->hash_table_entries); \
		i++, pos = (pos + 1) % req->core_line_count)

void ocf_req_hash_lock_rd(struct ocf_request *req)
{
	unsigned i, entry;

	ocf_metadata_start_shared_access(req->cache);
	for_each_req_hash_strict(req, i, entry) {
		ocf_metadata_hash_lock(req->cache, req->map[entry].hash,
				OCF_METADATA_RD);
	}
}

void ocf_req_hash_unlock_rd(struct ocf_request *req)
{
	unsigned i, entry;

	for_each_req_hash_strict(req, i, entry) {
		ocf_metadata_hash_unlock(req->cache, req->map[entry].hash,
				OCF_METADATA_RD);
	}
	ocf_metadata_end_shared_access(req->cache);
}

void ocf_req_hash_lock_wr(struct ocf_request *req)
{
	unsigned i, entry;

	ocf_metadata_start_shared_access(req->cache);
	for_each_req_hash_strict(req, i, entry) {
		ocf_metadata_hash_lock(req->cache, req->map[entry].hash,
				OCF_METADATA_WR);
	}
}

void ocf_req_hash_lock_upgrade(struct ocf_request *req)
{
	unsigned i, entry;

	for_each_req_hash_strict(req, i, entry) {
		ocf_metadata_hash_unlock(req->cache, req->map[entry].hash,
				OCF_METADATA_RD);
		ocf_metadata_hash_lock(req->cache, req->map[entry].hash,
				OCF_METADATA_WR);
	}
}

void ocf_req_hash_unlock_wr(struct ocf_request *req)
{
	unsigned i, entry;

	for_each_req_hash_strict(req, i, entry) {
		ocf_metadata_hash_unlock(req->cache, req->map[entry].hash,
				OCF_METADATA_WR);
	}
	ocf_metadata_end_shared_access(req->cache);
}
