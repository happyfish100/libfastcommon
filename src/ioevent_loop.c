#include "sched_thread.h"
#include "logger.h"
#include "ioevent_loop.h"

static void deal_ioevents(IOEventPoller *ioevent)
{
	int event;
	IOEventEntry *pEntry;

	for (ioevent->iterator.index=0; ioevent->iterator.index < ioevent->iterator.
            count; ioevent->iterator.index++)
	{
		event = IOEVENT_GET_EVENTS(ioevent, ioevent->iterator.index);
		pEntry = (IOEventEntry *)IOEVENT_GET_DATA(ioevent,
                ioevent->iterator.index);
        if (pEntry != NULL) {
            pEntry->callback(pEntry->fd, event, pEntry->timer.data);
        }
	}
}

int ioevent_remove(IOEventPoller *ioevent, void *data)
{
	IOEventEntry *pEntry;
    int index;

    if (ioevent->iterator.index >= ioevent->iterator.count)
    {
        return ENOENT;
    }

    pEntry = (IOEventEntry *)IOEVENT_GET_DATA(ioevent,
            ioevent->iterator.index);
    if (pEntry != NULL && pEntry->timer.data == data) {
        return 0;  //do NOT clear current entry
    }

    for (index=ioevent->iterator.index + 1; index < ioevent->iterator.count;
            index++)
    {
        pEntry = (IOEventEntry *)IOEVENT_GET_DATA(ioevent, index);
        if (pEntry != NULL && pEntry->timer.data == data) {
            IOEVENT_CLEAR_DATA(ioevent, index);
            return 0;
        }
    }

    return ENOENT;
}

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

        current->prev = current->next = NULL; //must set NULL because NOT in time wheel
		pEventEntry = (IOEventEntry *)current->data;
		if (pEventEntry != NULL)
		{
			pEventEntry->callback(pEventEntry->fd, IOEVENT_TIMEOUT,
						current->data);
		}
	}
}

int ioevent_loop(struct nio_thread_data *pThreadData,
	IOEventCallback recv_notify_callback, TaskCleanUpCallback
	clean_up_callback, volatile bool *continue_flag)
{
	int result;
	IOEventEntry ev_notify;
	FastTimerEntry head;
	struct fast_task_info *pTask;
	time_t last_check_time;
	int count;

	memset(&ev_notify, 0, sizeof(ev_notify));
	ev_notify.fd = pThreadData->pipe_fds[0];
	ev_notify.callback = recv_notify_callback;
	if (ioevent_attach(&pThreadData->ev_puller,
		pThreadData->pipe_fds[0], IOEVENT_READ,
		&ev_notify) != 0)
	{
		result = errno != 0 ? errno : ENOMEM;
		logCrit("file: "__FILE__", line: %d, " \
			"ioevent_attach fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

	last_check_time = g_current_time;
	while (*continue_flag)
	{
		pThreadData->deleted_list = NULL;
		pThreadData->ev_puller.iterator.count = ioevent_poll(&pThreadData->ev_puller);
		if (pThreadData->ev_puller.iterator.count > 0)
		{
			deal_ioevents(&pThreadData->ev_puller);
		}
		else if (pThreadData->ev_puller.iterator.count < 0)
		{
			result = errno != 0 ? errno : EINVAL;
			if (result != EINTR)
			{
				logError("file: "__FILE__", line: %d, " \
					"ioevent_poll fail, " \
					"errno: %d, error info: %s", \
					__LINE__, result, STRERROR(result));
				return result;
			}
		}

		if (pThreadData->deleted_list != NULL)
		{
			count = 0;
			while (pThreadData->deleted_list != NULL)
			{
				pTask = pThreadData->deleted_list;
				pThreadData->deleted_list = pTask->next;

				clean_up_callback(pTask);
				count++;
			}
			logDebug("cleanup task count: %d", count);
		}

		if (g_current_time - last_check_time > 0)
		{
			last_check_time = g_current_time;
			count = fast_timer_timeouts_get(
				&pThreadData->timer, g_current_time, &head);
			if (count > 0)
			{
				deal_timeouts(&head);
			}
		}

        if (pThreadData->thread_loop_callback != NULL) {
            pThreadData->thread_loop_callback(pThreadData);
        }
	}

	return 0;
}

int ioevent_set(struct fast_task_info *pTask, struct nio_thread_data *pThread,
	int sock, short event, IOEventCallback callback, const int timeout)
{
	int result;

	pTask->thread_data = pThread;
	pTask->event.fd = sock;
	pTask->event.callback = callback;
	if (ioevent_attach(&pThread->ev_puller,
		sock, event, pTask) < 0)
	{
		result = errno != 0 ? errno : ENOENT;
		logError("file: "__FILE__", line: %d, " \
			"ioevent_attach fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

	pTask->event.timer.data = pTask;
	pTask->event.timer.expires = g_current_time + timeout;
	result = fast_timer_add(&pThread->timer, &pTask->event.timer);
	if (result != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"fast_timer_add fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

	return 0;
}

