/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "../utils/utils_refcnt.h"

int ocf_refcnt_init(struct ocf_refcnt *rc, const char *name, size_t name_len)
{
	int cpu;

	env_memset(rc, sizeof(*rc), 0);

	env_strncpy(rc->name, sizeof(rc->name), name, name_len);

	rc->pcpu = alloc_percpu(struct ocf_refcnt_pcpu);
	if (!rc->pcpu)
		return -OCF_ERR_NO_MEM;
	ENV_BUG_ON(!rc->pcpu);

	for_each_online_cpu(cpu) {
		per_cpu_ptr(rc->pcpu, cpu)->freeze = false;
		env_atomic64_set(&per_cpu_ptr(rc->pcpu, cpu)->counter, 0);
	}

	env_spinlock_init(&rc->freeze.lock);
	rc->callback.pfn = NULL;
	rc->callback.priv = NULL;

	return 0;
}

void ocf_refcnt_deinit(struct ocf_refcnt *rc)
{
	free_percpu(rc->pcpu);
	rc->pcpu = NULL;
}

static inline void _ocf_refcnt_call_freeze_cb(struct ocf_refcnt *rc)
{
	bool fire;

	fire = (env_atomic_cmpxchg(&rc->callback.armed, 1, 0) == 1);
	smp_mb();
	if (fire)
		rc->callback.pfn(rc->callback.priv);
}

void ocf_refcnt_dec(struct ocf_refcnt *rc)
{
	struct ocf_refcnt_pcpu *pcpu;
	bool freeze;
	int64_t countdown = 0;
	bool callback;

	pcpu = get_cpu_ptr(rc->pcpu);

	freeze = pcpu->freeze;

	if (!freeze)
		env_atomic64_dec(&pcpu->counter);

	put_cpu_ptr(pcpu);

	if (freeze) {
		env_spinlock_lock(&rc->freeze.lock);
		countdown = --(rc->freeze.countdown);
		callback = !rc->freeze.initializing && countdown == 0;
		env_spinlock_unlock(&rc->freeze.lock);

		if (callback)
			_ocf_refcnt_call_freeze_cb(rc);
	}
}

bool ocf_refcnt_inc(struct ocf_refcnt  *rc)
{
	struct ocf_refcnt_pcpu *pcpu;
	bool freeze;

	pcpu = get_cpu_ptr(rc->pcpu);

	freeze = pcpu->freeze;

	if (!freeze) {
		env_atomic64_inc(&pcpu->counter);
	}
		
	put_cpu_ptr(pcpu);

	return !freeze;
}

struct ocf_refcnt_freeze_ctx
{
	struct ocf_refcnt *rc;
	env_atomic64 sum;
};

static void _ocf_refcnt_freeze_pcpu(void *_ctx)
{
	struct ocf_refcnt_freeze_ctx *ctx = _ctx;
	struct ocf_refcnt_pcpu *pcpu = this_cpu_ptr(ctx->rc->pcpu);

	pcpu->freeze = true;
	env_atomic64_add(env_atomic64_read(&pcpu->counter),
			&ctx->sum);
}

void ocf_refcnt_freeze(struct ocf_refcnt *rc)
{
	struct ocf_refcnt_freeze_ctx ctx;
	int freeze_cnt;
	bool callback;

	ctx.rc = rc;
	env_atomic64_set(&ctx.sum, 0);

	/* initiate freeze */
	env_spinlock_lock(&rc->freeze.lock);
	freeze_cnt = ++(rc->freeze.counter);
	if (freeze_cnt > 1) {
		env_spinlock_unlock(&rc->freeze.lock);
		return;
	}
	rc->freeze.initializing = true;
	rc->freeze.countdown = 0;
	env_spinlock_unlock(&rc->freeze.lock);

	/* notify CPUs about freeze */
	on_each_cpu(_ocf_refcnt_freeze_pcpu, &ctx, true);

	/* update countdown */
	env_spinlock_lock(&rc->freeze.lock);
	rc->freeze.countdown += env_atomic64_read(&ctx.sum);
	rc->freeze.initializing = false;
	callback = (rc->freeze.countdown == 0);
	env_spinlock_unlock(&rc->freeze.lock);

	/* if countdown finished tigger callback */
	if (callback)
		_ocf_refcnt_call_freeze_cb(rc);
}


void ocf_refcnt_register_zero_cb(struct ocf_refcnt *rc, ocf_refcnt_cb_t cb,
		void *priv)
{
	bool callback;

	ENV_BUG_ON(env_atomic_read(&rc->callback.armed));

	/* arm callback */
	rc->callback.pfn = cb;
	rc->callback.priv = priv;
	smp_wmb();
	env_atomic_set(&rc->callback.armed, 1);

	/* fire callback in case countdown finished */
	env_spinlock_lock(&rc->freeze.lock);
	callback = (rc->freeze.countdown == 0 && !rc->freeze.initializing);
	env_spinlock_unlock(&rc->freeze.lock);

	if (callback)
		_ocf_refcnt_call_freeze_cb(rc);
}

static void _ocf_refcnt_unfreeze_pcpu(void *_ctx)
{
	struct ocf_refcnt_freeze_ctx *ctx = _ctx;
	struct ocf_refcnt_pcpu *pcpu = this_cpu_ptr(ctx->rc->pcpu);

	env_atomic64_set(&pcpu->counter, 0);
	pcpu->freeze = false;
}

void ocf_refcnt_unfreeze(struct ocf_refcnt *rc)
{
	struct ocf_refcnt_freeze_ctx ctx;
	int freeze_cnt;

	env_spinlock_lock(&rc->freeze.lock);
	freeze_cnt = --(rc->freeze.counter);
	env_spinlock_unlock(&rc->freeze.lock);

	ENV_BUG_ON(freeze_cnt < 0);
	if (freeze_cnt > 0)
		return;

	/* disarm callback */
	env_atomic_set(&rc->callback.armed, 0);
	smp_wmb();

	/* notify CPUs about unfreeze */
	ctx.rc = rc;
	on_each_cpu(_ocf_refcnt_unfreeze_pcpu, &ctx, true);

	/* cleanup, technically not necessary */
	rc->freeze.countdown = 0;
}

bool ocf_refcnt_frozen(struct ocf_refcnt *rc)
{
	bool frozen;

	env_spinlock_lock(&rc->freeze.lock);
	frozen =  !!rc->freeze.counter;
	env_spinlock_unlock(&rc->freeze.lock);

	return frozen;
}

bool ocf_refcnt_is_zero(struct ocf_refcnt *rc)
{
	struct ocf_refcnt_pcpu *pcpu;
	int cpu;
	uint64_t sum = 0;

	for_each_online_cpu(cpu) {
		pcpu = per_cpu_ptr(rc->pcpu, cpu);
		sum += env_atomic64_read(&pcpu->counter);
	}


	return (sum == 0);
}
