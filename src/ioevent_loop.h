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
#if IOEVENT_USE_URING
#include "sockopt.h"
#endif

#define fc_hold_task_ex(task, inc_count) __sync_add_and_fetch( \
        &task->reffer_count, inc_count)
#define fc_hold_task(task)  fc_hold_task_ex(task, 1)

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

#define SET_OP_TYPE_AND_HOLD_TASK(task, _op_type) \
    struct io_uring_sqe *sqe; \
    if ((sqe=ioevent_uring_get_sqe(&task->thread_data->ev_puller)) == NULL) { \
        return ENOSPC; \
    } \
    FC_URING_OP_TYPE(task) = _op_type; \
    fc_hold_task(task)

static inline int uring_prep_recv_data(struct fast_task_info *task,
        char *buff, const int len)
{
    SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_RECV);
    ioevent_uring_prep_recv(&task->thread_data->ev_puller,
            sqe, task->event.fd, buff, len, task);
    return 0;
}

static inline int uring_prep_first_recv(struct fast_task_info *task)
{
    SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_RECV);
    ioevent_uring_prep_recv(&task->thread_data->ev_puller,
            sqe, task->event.fd, task->recv.ptr->data,
            task->recv.ptr->size, task);
    return 0;
}

static inline int uring_prep_next_recv(struct fast_task_info *task)
{
    SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_RECV);
    ioevent_uring_prep_recv(&task->thread_data->ev_puller, sqe,
            task->event.fd, task->recv.ptr->data + task->recv.ptr->offset,
            task->recv.ptr->length - task->recv.ptr->offset, task);
    return 0;
}

static inline int uring_prep_first_send(struct fast_task_info *task)
{
    if (task->iovec_array.iovs != NULL) {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_WRITEV);
        ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                sqe, task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_SEND);
        ioevent_uring_prep_send(&task->thread_data->ev_puller,
                sqe, task->event.fd, task->send.ptr->data,
                task->send.ptr->length, task);
    }
    return 0;
}

static inline int uring_prep_next_send(struct fast_task_info *task)
{
    if (task->iovec_array.iovs != NULL) {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_WRITEV);
        ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                sqe, task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_SEND);
        ioevent_uring_prep_send(&task->thread_data->ev_puller, sqe,
                task->event.fd, task->send.ptr->data + task->send.ptr->offset,
                task->send.ptr->length - task->send.ptr->offset, task);
    }
    return 0;
}

static inline int uring_prep_first_send_zc(struct fast_task_info *task)
{
    if (task->iovec_array.iovs != NULL) {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_WRITEV);
        ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                sqe, task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_SEND_ZC);
        ioevent_uring_prep_send_zc(&task->thread_data->ev_puller,
                sqe, task->event.fd, task->send.ptr->data,
                task->send.ptr->length, task);
    }
    return 0;
}

static inline int uring_prep_next_send_zc(struct fast_task_info *task)
{
    if (task->iovec_array.iovs != NULL) {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_WRITEV);
        ioevent_uring_prep_writev(&task->thread_data->ev_puller,
                sqe, task->event.fd, task->iovec_array.iovs,
                FC_MIN(task->iovec_array.count, IOV_MAX),
                task);
    } else {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_SEND_ZC);
        ioevent_uring_prep_send_zc(&task->thread_data->ev_puller, sqe,
                task->event.fd, task->send.ptr->data + task->send.ptr->offset,
                task->send.ptr->length - task->send.ptr->offset, task);
    }
    return 0;
}

static inline int uring_prep_close_fd(struct fast_task_info *task)
{
    struct io_uring_sqe *sqe;

    if ((sqe=ioevent_uring_get_sqe(&task->thread_data->ev_puller)) == NULL) {
        return ENOSPC;
    }

    /* do NOT need callback */
    ioevent_uring_prep_close(&task->thread_data->
            ev_puller, sqe, task->event.fd, NULL);
    return 0;
}

static inline int uring_prep_cancel(struct fast_task_info *task)
{
    SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_ASYNC_CANCEL);
    ioevent_uring_prep_cancel(&task->thread_data->ev_puller, sqe, task);
    return 0;
}

static inline int uring_prep_connect(struct fast_task_info *task)
{
    int result;
    sockaddr_convert_t *convert;

    if ((task->event.fd=socketCreateEx2(AF_UNSPEC, task->server_ip,
                    O_NONBLOCK, NULL, &result)) < 0)
    {
        return result;
    }

    convert = (sockaddr_convert_t *)(task->send.ptr->data +
            task->send.ptr->size - 2 * sizeof(sockaddr_convert_t));
    if ((result=setsockaddrbyip(task->server_ip, task->port, convert)) != 0) {
        return result;
    }

    do {
        SET_OP_TYPE_AND_HOLD_TASK(task, IORING_OP_CONNECT);
        ioevent_uring_prep_connect(&task->thread_data->ev_puller, sqe,
                task->event.fd, &convert->sa.addr, convert->len, task);
    } while (0);
    return 0;
}
#endif

#ifdef __cplusplus
}
#endif

#endif
