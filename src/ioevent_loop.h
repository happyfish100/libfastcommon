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

int ioevent_loop(struct nio_thread_data *thread_data,
	IOEventCallback recv_notify_callback, TaskCleanUpCallback
	clean_up_callback, volatile bool *continue_flag);

int ioevent_set(struct fast_task_info *task, struct nio_thread_data *pThread,
        int sock, short event, IOEventCallback callback,
        const int timeout, const bool use_iouring);

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

#if IOEVENT_USE_URING
static inline int uring_prep_recv_data(struct fast_task_info *task,
        char *buff, const int len)
{
    FC_URING_OP_TYPE(task) = IORING_OP_RECV;
    return ioevent_uring_prep_recv(&task->thread_data->ev_puller,
            task->event.fd, buff, len, task);
}

static inline int uring_prep_first_recv(struct fast_task_info *task)
{
    FC_URING_OP_TYPE(task) = IORING_OP_RECV;
    return ioevent_uring_prep_recv(&task->thread_data->ev_puller,
            task->event.fd, task->recv.ptr->data,
            task->recv.ptr->size, task);
}

static inline int uring_prep_next_recv(struct fast_task_info *task)
{
    FC_URING_OP_TYPE(task) = IORING_OP_RECV;
    return ioevent_uring_prep_recv(&task->thread_data->ev_puller,
            task->event.fd, task->recv.ptr->data + task->recv.ptr->offset,
            task->recv.ptr->length - task->recv.ptr->offset, task);
}

static inline int uring_prep_first_send(struct fast_task_info *task)
{
    FC_URING_OP_TYPE(task) = IORING_OP_SEND;
    if (task->iovec_array.iovs != NULL) {
        return ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        return ioevent_uring_prep_send(&task->thread_data->ev_puller,
                task->event.fd, task->send.ptr->data,
                task->send.ptr->length, task);
    }
}

static inline int uring_prep_next_send(struct fast_task_info *task)
{
    FC_URING_OP_TYPE(task) = IORING_OP_SEND;
    if (task->iovec_array.iovs != NULL) {
        return ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        return ioevent_uring_prep_send(&task->thread_data->ev_puller,
                task->event.fd, task->send.ptr->data + task->send.ptr->offset,
                task->send.ptr->length - task->send.ptr->offset, task);
    }
}

static inline int uring_prep_first_send_zc(struct fast_task_info *task)
{
    FC_URING_OP_TYPE(task) = IORING_OP_SEND;
    if (task->iovec_array.iovs != NULL) {
        return ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        return ioevent_uring_prep_send_zc(&task->thread_data->ev_puller,
                task->event.fd, task->send.ptr->data,
                task->send.ptr->length, task);
    }
}

static inline int uring_prep_next_send_zc(struct fast_task_info *task)
{
    FC_URING_OP_TYPE(task) = IORING_OP_SEND;
    if (task->iovec_array.iovs != NULL) {
        return ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        return ioevent_uring_prep_send_zc(&task->thread_data->ev_puller,
                task->event.fd, task->send.ptr->data + task->send.ptr->offset,
                task->send.ptr->length - task->send.ptr->offset, task);
    }
}

static inline int uring_prep_close_fd(struct fast_task_info *task)
{
    FC_URING_OP_TYPE(task) = IORING_OP_CLOSE;
    return ioevent_uring_prep_close(&task->thread_data->
            ev_puller, task->event.fd);
}
#endif

#ifdef __cplusplus
}
#endif

#endif
