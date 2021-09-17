/*
 * Copyright(c) 2021-2021 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>

extern "C" {
#include <ocf/ocf.h>
}

#include "queue_thread.h"

/* queue thread main function */
static void run(struct ocf_queue *q, struct queue_thread &qt);

/* helper class to store all synchronization related objects */
struct queue_thread
{
	/* thread running the queue */
	std::thread thread;
	/* incremented in kick callback to request the thread to call ocf_queue_run */
	unsigned kick_cnt;
	/* request thread to exit */
	bool stop;
	/* synchronization primitive to notify about kick_cnt or stop value changes */
	std::condition_variable cv;
	/* condition variable mutex */
	std::mutex mutex;

	queue_thread(struct ocf_queue *q) : thread(run, q, std::ref(*this)) {}
};

/* queue thread main function */
static void run(struct ocf_queue *q, struct queue_thread &qt)
{
	unsigned last_kick_cnt = 0;
	bool stopped;

	do {
		/* wait for kick_cnt or stop value change */
		{
			std::unique_lock<std::mutex> l(qt.mutex);
			qt.cv.wait(l, [&qt, &last_kick_cnt] {return qt.kick_cnt != last_kick_cnt || qt.stop;});
			last_kick_cnt = qt.kick_cnt;
			stopped = qt.stop;
		}

		/* execute items on the queue */
		ocf_queue_run(q);

	} while (!stopped);
}

/* initialize I/O queue and management queue thread */
extern "C"
int initialize_threads(struct ocf_queue *mngt_queue, struct ocf_queue *io_queue)
{
	int ret = 0;

	try {
		struct queue_thread* mngt_queue_thread = new queue_thread(mngt_queue);
		struct queue_thread* io_queue_thread = new queue_thread(io_queue);

		ocf_queue_set_priv(mngt_queue, mngt_queue_thread);
		ocf_queue_set_priv(io_queue, io_queue_thread);
	} catch(...) {
		ret = 1;
	}

	return ret;
}

/* callback for OCF to kick the queue thread */
extern "C" void queue_thread_kick(ocf_queue_t q)
{
	struct queue_thread *qt = static_cast<struct queue_thread *>(ocf_queue_get_priv(q));

	{
		std::unique_lock<std::mutex> l(qt->mutex);
		++qt->kick_cnt;
	}

	qt->cv.notify_one();
}

/* callback for OCF to stop the queue thread */
extern "C" void queue_thread_stop(ocf_queue_t q)
{
	struct queue_thread *qt = static_cast<struct queue_thread *>(ocf_queue_get_priv(q));

	{
		std::unique_lock<std::mutex> l(qt->mutex);
		qt->stop = true;
	}

	qt->cv.notify_one();
	qt->thread.join();
	delete qt;
}
