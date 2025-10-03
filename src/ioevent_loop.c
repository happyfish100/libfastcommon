/*
 * Copyright (c) 2020 YuQing <384681@qq.com>
 *
 * This program is free software: you can use, redistribute, and/or modify
 * it under the terms of the Lesser GNU General Public License, version 3
 * or later ("LGPL"), as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.
 *
 * You should have received a copy of the Lesser GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "sched_thread.h"
#include "logger.h"
#include "ioevent_loop.h"

#if IOEVENT_USE_URING
static int ioevent_process(IOEventPoller *ioevent)
{
    int result;
    unsigned head;
    unsigned count = 0;
	IOEventEntry *pEntry;

    result = io_uring_wait_cqe_timeout(&ioevent->ring,
            &ioevent->cqe, &ioevent->timeout);
    switch (result) {
        case 0:
            break;
        case -ETIME:
        case -EINTR:
            return 0;
        default:
            result *= -1;
            logError("file: "__FILE__", line: %d, "
                    "io_uring_wait_cqe fail, errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
    }

    io_uring_for_each_cqe(&ioevent->ring, head, ioevent->cqe) {
        count++;
        pEntry = (IOEventEntry *)ioevent->cqe->user_data;
        if (pEntry != NULL) {
            if (ioevent->cqe->flags & IORING_CQE_F_NOTIF) {
#ifdef IORING_NOTIF_USAGE_ZC_COPIED
                if (!ioevent->send_zc_logged) {
                    ioevent->send_zc_logged = true;
                    if (ioevent->cqe->res & IORING_NOTIF_USAGE_ZC_COPIED) {
                        logWarning("file: "__FILE__", line: %d, "
                                "io_uring send_zc: memory copy "
                                "instead of zero copy!", __LINE__);
                    } else {
                        logInfo("file: "__FILE__", line: %d, "
                                "io_uring send_zc: zero copy OK.", __LINE__);
                    }
                }
#endif
            } else {
                pEntry->res = ioevent->cqe->res;
                pEntry->callback(pEntry->fd, 0, pEntry);
            }
        } else {
            logWarning("file: "__FILE__", line: %d, "
                    "unexpected flags: %d, result: %u", __LINE__,
                    ioevent->cqe->flags, ioevent->cqe->res);
        }
    }

    io_uring_cq_advance(&ioevent->ring, count);
    return 0;
}

#else

static void deal_ioevents(IOEventPoller *ioevent)
{
	int event;
	IOEventEntry *pEntry;

	for (ioevent->iterator.index=0; ioevent->iterator.index < ioevent->
            iterator.count; ioevent->iterator.index++)
	{
		event = IOEVENT_GET_EVENTS(ioevent, ioevent->iterator.index);
		pEntry = (IOEventEntry *)IOEVENT_GET_DATA(ioevent,
                ioevent->iterator.index);
        if (pEntry != NULL) {
            pEntry->callback(pEntry->fd, event, pEntry);
        }
        else {
            logDebug("file: "__FILE__", line: %d, "
                    "ignore ioevent : %d, index: %d",
                    __LINE__, event, ioevent->iterator.index);
        }
	}
}

static int ioevent_process(IOEventPoller *ioevent)
{
    int result;

    ioevent->iterator.count = ioevent_poll(ioevent);
    if (ioevent->iterator.count > 0) {
        deal_ioevents(ioevent);
    }
    else if (ioevent->iterator.count < 0) {
        result = errno != 0 ? errno : EINVAL;
        if (result != EINTR) {
            logError("file: "__FILE__", line: %d, "
                    "ioevent_poll fail, errno: %d, error info: %s",
                    __LINE__, result, STRERROR(result));
            return result;
        }
    }

    return 0;
}

#endif

static void deal_timeouts(FastTimerEntry *head)
{
	FastTimerEntry *entry;
	FastTimerEntry *current;
	IOEventEntry *pEventEntry;

	entry = head->next;
	while (entry != NULL)
	{
		current = entry;
		entry = entry->next;

        /* must set NULL because NOT in time wheel */
        current->prev = current->next = NULL;
		pEventEntry = (IOEventEntry *)current;
		if (pEventEntry != NULL)
		{
			pEventEntry->callback(pEventEntry->fd, IOEVENT_TIMEOUT, current);
		}
	}
}

int ioevent_loop(struct nio_thread_data *thread_data,
	IOEventCallback recv_notify_callback, TaskCleanUpCallback
	clean_up_callback, volatile bool *continue_flag)
{
	int result;
	struct ioevent_notify_entry ev_notify;
	FastTimerEntry head;
	struct fast_task_info *task;
	time_t last_check_time;
    int save_extra_events;
	int count;
#ifdef OS_LINUX
    uint32_t sched_counter;
#endif
    bool sched_pull;

	memset(&ev_notify, 0, sizeof(ev_notify));
	ev_notify.event.fd = FC_NOTIFY_READ_FD(thread_data);
	ev_notify.event.callback = recv_notify_callback;
	ev_notify.thread_data = thread_data;

    save_extra_events = thread_data->ev_puller.extra_events;
    thread_data->ev_puller.extra_events = 0; //disable edge trigger temporarily
	if (ioevent_attach(&thread_data->ev_puller, ev_notify.
                event.fd, IOEVENT_READ, &ev_notify) != 0)
	{
		result = errno != 0 ? errno : ENOMEM;
		logCrit("file: "__FILE__", line: %d, "
			"ioevent_attach fail, errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}
    thread_data->ev_puller.extra_events = save_extra_events; //restore

#ifdef OS_LINUX
    sched_counter = 0;
#endif

    thread_data->deleted_list = NULL;
	last_check_time = g_current_time;
	while (*continue_flag) {
#ifdef OS_LINUX
        if (thread_data->ev_puller.zero_timeout) {
            sched_pull = (sched_counter++ & 8) != 0;
        } else {
            sched_pull = true;
        }
#else
        sched_pull = true;
#endif

        if (sched_pull) {
            if ((result=ioevent_process(&thread_data->ev_puller)) != 0) {
                return result;
            }
        }

        if (thread_data->busy_polling_callback != NULL) {
            thread_data->busy_polling_callback(thread_data);
        }

		if (thread_data->deleted_list != NULL) {
			count = 0;
			while (thread_data->deleted_list != NULL) {
				task = thread_data->deleted_list;
				thread_data->deleted_list = task->next;

                if (task->polling.in_queue) {
                    fc_list_del_init(&task->polling.dlink);
                    task->polling.in_queue = false;
                    if (fc_list_empty(&task->thread_data->polling_queue)) {
                        ioevent_set_timeout(&task->thread_data->ev_puller,
                                task->thread_data->timeout_ms);
                    }
                }
				clean_up_callback(task);
				count++;
			}
			//logInfo("cleanup task count: %d", count);
		}

		if (g_current_time - last_check_time > 0) {
			last_check_time = g_current_time;
			count = fast_timer_timeouts_get(
				&thread_data->timer, g_current_time, &head);
			if (count > 0)
			{
				deal_timeouts(&head);
			}
		}

        if (thread_data->notify.enabled) {
            int64_t n;
            if ((n=__sync_fetch_and_add(&thread_data->notify.counter, 0)) != 0)
            {
                __sync_fetch_and_sub(&thread_data->notify.counter, n);
                /*
                logInfo("file: "__FILE__", line: %d, "
                        "n ==== %"PRId64", now: %"PRId64,
                        __LINE__, n, __sync_fetch_and_add(
                            &thread_data->notify.counter, 0));
                            */
            }
        }

        if (thread_data->thread_loop_callback != NULL) {
            thread_data->thread_loop_callback(thread_data);
        }

#if IOEVENT_USE_URING
        if (thread_data->ev_puller.submit_count > 0) {
            if ((result=ioevent_uring_submit(&thread_data->ev_puller)) != 0) {
                logError("file: "__FILE__", line: %d, "
                        "io_uring_submit fail, errno: %d, error info: %s",
                        __LINE__, result, STRERROR(result));
                return result;
            }
        }
#endif
	}

	return 0;
}

int ioevent_set(struct fast_task_info *task, struct nio_thread_data *pThread,
        int sock, short event, IOEventCallback callback,
        const int timeout, const bool use_iouring)
{
	int result;

	task->thread_data = pThread;
	task->event.fd = sock;
	task->event.callback = callback;
#if IOEVENT_USE_URING
    if (use_iouring) {
        if (FC_URING_OP_TYPE(task) == IORING_OP_NOP) {
            if ((result=uring_prep_first_recv(task)) != 0) {
                logError("file: "__FILE__", line: %d, "
                        "uring_prep_recv fail, fd: %d, "
                        "errno: %d, error info: %s",
                        __LINE__, sock, result, STRERROR(result));
                return result;
            }
        } else {
            logInfo("file: "__FILE__", line: %d, "
                    "skip uring_prep_recv, fd: %d, port: %d, in progress op type: %d, timeout: %"PRId64,
                    __LINE__, sock, task->port, FC_URING_OP_TYPE(task), task->event.timer.expires);
        }
    } else {
#endif
        if (ioevent_attach(&pThread->ev_puller, sock, event, task) < 0) {
            result = errno != 0 ? errno : ENOENT;
            logError("file: "__FILE__", line: %d, "
                    "ioevent_attach fail, fd: %d, "
                    "errno: %d, error info: %s",
                    __LINE__, sock, result, STRERROR(result));
            return result;
        }
#if IOEVENT_USE_URING
    }
#endif

	task->event.timer.expires = g_current_time + timeout;
	fast_timer_add(&pThread->timer, &task->event.timer);
	return 0;
}
