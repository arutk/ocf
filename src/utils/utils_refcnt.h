/*
 * Copyright(c) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef __OCF_REFCNT_H__
#define __OCF_REFCNT_H__

#include "ocf_env.h"

typedef void (*ocf_refcnt_cb_t)(void *priv);

struct ocf_refcnt_pcpu
{
	env_atomic64 counter;
	bool freeze;
};

struct ocf_refcnt
{
	struct ocf_refcnt_pcpu /* __percpu */ *pcpu;

	struct {
		/* freeze counter */
		uint32_t counter;

		/* global counter used instead of per-CPU ones after
		 * freeze */
		int64_t countdown;

		/* freeze initializing - freeze was requested but not all
		 * CPUs were notified. */
		bool initializing;

		env_spinlock lock;
	} freeze;

	struct {
		env_atomic armed;
		ocf_refcnt_cb_t pfn;
		void *priv;
	} callback;

	char name[32];
};

/* Initialize reference counter */
int ocf_refcnt_init(struct ocf_refcnt *rc, const char *name, size_t name_len);

void ocf_refcnt_deinit(struct ocf_refcnt *rc);

/* Try to increment counter. Returns counter value (> 0) if successfull, 0
 * if counter is frozen */
bool ocf_refcnt_inc(struct ocf_refcnt  *rc);

/* Decrement reference counter */
void ocf_refcnt_dec(struct ocf_refcnt *rc);

/* Disallow incrementing of underlying counter - attempts to increment counter
 * will be failing until ocf_refcnt_unfreeze is calleed.
 * It's ok to call freeze multiple times, in which case counter is frozen
 * until all freeze calls are offset by a corresponding unfreeze.*/
void ocf_refcnt_freeze(struct ocf_refcnt *rc);

/* Cancel the effect of single ocf_refcnt_freeze call */
void ocf_refcnt_unfreeze(struct ocf_refcnt *rc);

bool ocf_refcnt_frozen(struct ocf_refcnt *rc);

/* Register callback to be called when reference counter drops to 0.
 * Must be called after counter is frozen.
 * Cannot be called until previously regsitered callback had fired. */
void ocf_refcnt_register_zero_cb(struct ocf_refcnt *rc, ocf_refcnt_cb_t cb,
		void *priv);

bool ocf_refcnt_is_zero(struct ocf_refcnt *rc);

#endif // __OCF_REFCNT_H__
