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

static inline bool ioevent_is_canceled(struct fast_task_info *task)
{
    return __sync_fetch_and_add(&task->canceled, 0) != 0;
}

//only called by the nio thread
static inline void ioevent_add_to_deleted_list(struct fast_task_info *task)
{
    if (!__sync_bool_compare_and_swap(&task->canceled, 0, 1))
    {
        logWarning("file: "__FILE__", line: %d, "
                "task %p already canceled", __LINE__, task);
        return;
    }

    task->next = task->thread_data->deleted_list;
    task->thread_data->deleted_list = task;
}

static inline int ioevent_notify_thread(struct nio_thread_data *thread_data)
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

