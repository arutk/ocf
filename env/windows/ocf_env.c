/*
 * Copyright(c) 2019-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "ocf_env.h"
#include <Windows.h>
#include <windef.h>
#include <sched.h>
#include <dbghelp.h>

/* ALLOCATOR */
struct _env_allocator {
	/*!< Memory pool ID unique name */
	char *name;

	/*!< Size of specific item of memory pool */
	uint32_t item_size;

	/*!< Number of currently allocated items in pool */
	env_atomic count;
};

static inline size_t env_allocator_align(size_t size)
{
	if (size <= 2)
		return size;
	return (1ULL << 32) >> __builtin_clz(size - 1);
}

struct _env_allocator_item {
	uint32_t flags;
	uint32_t cpu;
	char data[];
};

void *env_allocator_new(env_allocator *allocator)
{
	struct _env_allocator_item *item = NULL;

	item = calloc(1, allocator->item_size);

	if (item) {
		item->cpu = 0;
		env_atomic_inc(&allocator->count);
	}

	return &item->data;
}

env_allocator *env_allocator_create(uint32_t size, const char *fmt_name, ...)
{
	char name[OCF_ALLOCATOR_NAME_MAX] = { '\0' };
	int result, error = -1;
	va_list args;

	env_allocator *allocator = calloc(1, sizeof(*allocator));
	if (!allocator) {
		error = __LINE__;
		goto err;
	}

	allocator->item_size = size + sizeof(struct _env_allocator_item);

	/* Format allocator name */
	va_start(args, fmt_name);
	result = vsnprintf(name, sizeof(name), fmt_name, args);
	va_end(args);

	if ((result > 0) && (result < sizeof(name))) {
		allocator->name = strdup(name);

		if (!allocator->name) {
			error = __LINE__;
			goto err;
		}
	} else {
		/* Formated string name exceed max allowed size of name */
		error = __LINE__;
		goto err;
	}

	return allocator;

err:
	printf("Cannot create memory allocator, ERROR %d", error);
	env_allocator_destroy(allocator);

	return NULL;
}

void env_allocator_del(env_allocator *allocator, void *obj)
{
	struct _env_allocator_item *item =
		container_of(obj, struct _env_allocator_item, data);

	env_atomic_dec(&allocator->count);

	free(item);
}

void env_allocator_destroy(env_allocator *allocator)
{
	if (allocator) {
		if (env_atomic_read(&allocator->count)) {
			printf("Not all objects deallocated\n");
			ENV_WARN(true, OCF_PREFIX_SHORT" Cleanup problem\n");
		}

		free(allocator->name);
		free(allocator);
	}
}

/* DEBUGING */
#define ENV_TRACE_DEPTH	16

void env_stack_trace(void)
{
	HANDLE curr_proc = GetCurrentProcess();
	PVOID *backtrace = malloc(USHRT_MAX * sizeof(PVOID));
	USHORT num_frames = CaptureStackBackTrace(0, USHRT_MAX, backtrace, NULL);
	const unsigned symbol_name_buff_size = 512;
	SYMBOL_INFO *info = malloc(sizeof(SYMBOL_INFO) + symbol_name_buff_size);
	DWORD64 displacement;
	unsigned i;
	bool ret;

	info->MaxNameLen = symbol_name_buff_size;

	printf("[stack trace]>>>\n");
	for (i = 0; i < num_frames; i++) {
		ret = SymFromAddr(curr_proc, (DWORD64)backtrace[i], &displacement, info);
		assert(ret);
		printf("%s+%llx\n", info->Name, displacement);
	}
	printf("<<<[stack trace]\n");

	free(info);
	free(backtrace);
}

/* CRC */
uint32_t env_crc32(uint32_t crc, uint8_t const *data, size_t len)
{
	return crc32(crc, data, len);
}

/* EXECUTION CONTEXTS */
pthread_mutex_t *exec_context_mutex;

static void __attribute__((constructor)) init_execution_context(void)
{
	unsigned count = env_get_execution_context_count();
	unsigned i;

	ENV_BUG_ON(count == 0);
	exec_context_mutex = malloc(count * sizeof(exec_context_mutex[0]));
	ENV_BUG_ON(exec_context_mutex == NULL);
	for (i = 0; i < count; i++)
		ENV_BUG_ON(pthread_mutex_init(&exec_context_mutex[i], NULL));
}

static void __attribute__((destructor)) deinit_execution_context(void)
{
	unsigned count = env_get_execution_context_count();
	unsigned i;

	ENV_BUG_ON(count == 0);
	ENV_BUG_ON(exec_context_mutex == NULL);

	for (i = 0; i < count; i++)
		ENV_BUG_ON(pthread_mutex_destroy(&exec_context_mutex[i]));
	free(exec_context_mutex);
}

/* get_execuction_context must assure that after the call finishes, the caller
 * will not get preempted from current execution context. For userspace env
 * we simulate this behavior by acquiring per execution context mutex. As a
 * result the caller might actually get preempted, but no other thread will
 * execute in this context by the time the caller puts current execution ctx. */
unsigned env_get_execution_context(void)
{
	unsigned cpu;

	cpu = GetCurrentProcessorNumber();
	cpu = (cpu == -1) ?  0 : cpu;

	ENV_BUG_ON(pthread_mutex_lock(&exec_context_mutex[cpu]));

	return cpu;
}

void env_put_execution_context(unsigned ctx)
{
	pthread_mutex_unlock(&exec_context_mutex[ctx]);
}

unsigned env_get_execution_context_count(void)
{
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	return sysinfo.dwNumberOfProcessors;
}
