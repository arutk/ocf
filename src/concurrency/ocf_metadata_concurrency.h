/*
 * Copyright(c) 2019-2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */
#include "../ocf_cache_priv.h"

#ifndef __OCF_METADATA_CONCURRENCY_H__
#define __OCF_METADATA_CONCURRENCY_H__

#define OCF_METADATA_RD 0
#define OCF_METADATA_WR 1

int ocf_metadata_concurrency_init(struct ocf_metadata_lock *metadata_lock,
		unsigned num_evps);

void ocf_metadata_concurrency_deinit(struct ocf_metadata_lock *metadata_lock);

int ocf_metadata_concurrency_attached_init(
		struct ocf_metadata_lock *metadata_lock, ocf_cache_t cache,
		uint32_t hash_table_entries, uint32_t colision_table_pages);

void ocf_metadata_concurrency_attached_deinit(
		struct ocf_metadata_lock *metadata_lock);

static inline void ocf_metadata_eviction_lock(
		struct ocf_metadata_lock *metadata_lock, unsigned sublock)
{
	env_spinlock_lock(&metadata_lock->eviction[sublock]);
}

static inline void ocf_metadata_eviction_unlock(
		struct ocf_metadata_lock *metadata_lock, unsigned sublock)
{
	env_spinlock_unlock(&metadata_lock->eviction[sublock]);
}

static inline void ocf_metadata_eviction_lock_all(
		struct ocf_metadata_lock *metadata_lock)
{
	int i;
	for (i = 0; i < metadata_lock->num_evps; i++)
		ocf_metadata_eviction_lock(metadata_lock, i);
}

static inline void ocf_metadata_eviction_unlock_all(
		struct ocf_metadata_lock *metadata_lock)
{
	int i;
	for (i = 0; i < metadata_lock->num_evps; i++)
		ocf_metadata_eviction_unlock(metadata_lock, i);
}

#define _OCF_METADATA_EVICTION_LOCK(list_no) \
	ocf_metadata_eviction_lock(&cache->metadata.lock, list_no)

#define _OCF_METADATA_EVICTION_UNLOCK(list_no) \
	ocf_metadata_eviction_unlock(&cache->metadata.lock, list_no)

#define OCF_METADATA_EVICTION_NUM_LOCKS \
		(cache->num_evps)

#define OCF_METADATA_EVICTION_LOCK(cline) \
	_OCF_METADATA_EVICTION_LOCK(cline % OCF_METADATA_EVICTION_NUM_LOCKS)

#define OCF_METADATA_EVICTION_UNLOCK(cline) \
	_OCF_METADATA_EVICTION_UNLOCK(cline % OCF_METADATA_EVICTION_NUM_LOCKS)

#define OCF_METADATA_EVICTION_LOCK_ALL() \
	ocf_metadata_eviction_lock_all(&cache->metadata.lock)

#define OCF_METADATA_EVICTION_UNLOCK_ALL() \
	ocf_metadata_eviction_unlock_all(&cache->metadata.lock)

static inline void ocf_metadata_partition_lock(
		struct ocf_metadata_lock *metadata_lock,
		ocf_part_id_t part_id)
{
	env_spinlock_lock(&metadata_lock->partition[part_id]);
}

static inline void ocf_metadata_partition_unlock(
		struct ocf_metadata_lock *metadata_lock,
		ocf_part_id_t part_id)
{
	env_spinlock_unlock(&metadata_lock->partition[part_id]);
}

void ocf_metadata_start_exclusive_access(
		struct ocf_metadata_lock *metadata_lock);

int ocf_metadata_try_start_exclusive_access(
		struct ocf_metadata_lock *metadata_lock);

void ocf_metadata_end_exclusive_access(
		struct ocf_metadata_lock *metadata_lock);

int ocf_metadata_try_start_shared_access(
		struct ocf_metadata_lock *metadata_lock,
		uint64_t core_line);

void ocf_metadata_start_shared_access(
		struct ocf_metadata_lock *metadata_lock,
		uint64_t core_line);

void ocf_metadata_end_shared_access(
		struct ocf_metadata_lock *metadata_lock,
		uint64_t core_line);

static inline void ocf_metadata_status_bits_lock(
		struct ocf_metadata_lock *metadata_lock, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_lock(&metadata_lock->status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_lock(&metadata_lock->status);
	else
		ENV_BUG();
}

static inline void ocf_metadata_status_bits_unlock(
		struct ocf_metadata_lock *metadata_lock, int rw)
{
	if (rw == OCF_METADATA_WR)
		env_rwlock_write_unlock(&metadata_lock->status);
	else if (rw == OCF_METADATA_RD)
		env_rwlock_read_unlock(&metadata_lock->status);
	else
		ENV_BUG();
}

#define OCF_METADATA_BITS_LOCK_RD() 

#define OCF_METADATA_BITS_UNLOCK_RD()

#define OCF_METADATA_BITS_LOCK_WR() 

#define OCF_METADATA_BITS_UNLOCK_WR() 

void ocf_metadata_hash_lock_rd(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);
void ocf_metadata_hash_unlock_rd(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);

/* caller must hold global metadata read lock */
bool _ocf_metadata_hash_trylock_rd(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);
void _ocf_metadata_hash_unlock_rd(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);

void ocf_metadata_hash_lock_wr(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);
void ocf_metadata_hash_unlock_wr(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);

/* caller must hold global metadata read lock */
bool _ocf_metadata_hash_trylock_wr(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);
void _ocf_metadata_hash_unlock_wr(struct ocf_metadata_lock *metadata_lock,
		uint32_t core_id, uint64_t core_line);

/* TODO: find better place for this */
bool ocf_req_hash_in_range(struct ocf_request *req,
		ocf_core_id_t core_id, uint64_t core_line);

/* lock entire request in deadlock-free manner */
void ocf_req_hash_lock_rd(struct ocf_request *req);
void ocf_req_hash_unlock_rd(struct ocf_request *req);
void ocf_req_hash_lock_wr(struct ocf_request *req);
void ocf_req_hash_unlock_wr(struct ocf_request *req);
void ocf_req_hash_lock_upgrade(struct ocf_request *req);

/* collision table page lock interface */
void ocf_collision_start_shared_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page);
void ocf_collision_end_shared_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page);
void ocf_collision_start_exclusive_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page);
void ocf_collision_end_exclusive_access(struct ocf_metadata_lock *metadata_lock,
		uint32_t page);
#endif
