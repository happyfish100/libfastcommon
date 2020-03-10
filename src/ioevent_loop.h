#ifndef _IOEVENT_LOOP_H
#define _IOEVENT_LOOP_H

#include "fast_task_queue.h"

#ifdef __cplusplus
extern "C" {
#endif

int ioevent_loop(struct nio_thread_data *pThreadData,
	IOEventCallback recv_notify_callback, TaskCleanUpCallback
	clean_up_callback, volatile bool *continue_flag);

//remove entry from ready list
int ioevent_remove(IOEventPoller *ioevent, void *data);

int ioevent_set(struct fast_task_info *pTask, struct nio_thread_data *pThread,
	int sock, short event, IOEventCallback callback, const int timeout);

static inline void iovent_add_to_deleted_list(struct fast_task_info *task)
{
    if (task->thread_data == NULL)
    {
        return;
    }

    if (task->canceled) {
        logError("file: "__FILE__", line: %d, "
                "task %p already canceled", __LINE__, task);
        return;
    }

    task->canceled = true;
    task->next = task->thread_data->deleted_list;
    task->thread_data->deleted_list = task;
}

static inline int iovent_notify_thread(struct nio_thread_data *thread_data)
{
    int64_t n;
    int result;

    if (__sync_fetch_and_add(&thread_data->notify.counter, 1) == 0)
    {
        n = 1;
        if (write(FC_NOTIFY_WRITE_FD(thread_data), &n, sizeof(n)) != sizeof(n))
        {
            result = errno != 0 ? errno : EIO;
            logError("file: "__FILE__", line: %d, "
                    "write to fd %d fail, errno: %d, error info: %s",
                    __LINE__, FC_NOTIFY_WRITE_FD(thread_data),
                    result, STRERROR(result));
            return result;
        }
    }

    return 0;
}

#ifdef __cplusplus
}
#endif

#endif

