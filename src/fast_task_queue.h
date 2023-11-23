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

//fast_task_queue.h

#ifndef _FAST_TASK_QUEUE_H
#define _FAST_TASK_QUEUE_H 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common_define.h"
#include "fc_list.h"
#include "ioevent.h"
#include "fast_timer.h"
#include "fast_mblock.h"

#define FC_NOTIFY_READ_FD(tdata)  (tdata)->pipe_fds[0]
#define FC_NOTIFY_WRITE_FD(tdata) (tdata)->pipe_fds[1]

#define ALIGNED_TASK_INFO_SIZE  MEM_ALIGN(sizeof(struct fast_task_info))

struct nio_thread_data;
struct fast_task_info;

typedef int (*ThreadLoopCallback) (struct nio_thread_data *pThreadData);
typedef int (*TaskFinishCallback) (struct fast_task_info *task);
typedef void (*TaskCleanUpCallback) (struct fast_task_info *task);
typedef int (*TaskInitCallback)(struct fast_task_info *task);
typedef void (*TaskReleaseCallback)(struct fast_task_info *task);

typedef void (*IOEventCallback) (int sock, short event, void *arg);
typedef int (*TaskContinueCallback)(struct fast_task_info *task);

struct sf_network_handler;
struct fast_task_info;

typedef struct ioevent_entry
{
    FastTimerEntry timer; //must first
    int fd;
    IOEventCallback callback;
} IOEventEntry;

struct nio_thread_data
{
	struct ioevent_puller ev_puller;
	struct fast_timer timer;
	int pipe_fds[2];   //for notify
	struct fast_task_info *deleted_list;   //tasks for cleanup
	ThreadLoopCallback thread_loop_callback;
	ThreadLoopCallback busy_polling_callback;
	void *arg;   //extra argument pointer
    struct {
        struct fast_task_info *head;
        struct fast_task_info *tail;
        pthread_mutex_t lock;
    } waiting_queue;  //task queue

    struct {
        bool enabled;
        volatile int64_t counter;
    } notify;  //for thread notify

    int timeout_ms;   //for restore
    struct fc_list_head polling_queue;  //for RDMA busy polling
};

struct ioevent_notify_entry
{
    IOEventEntry event;  //must first
    struct nio_thread_data *thread_data;
};

struct fast_net_buffer
{
    int size;      //alloc size
    int length;    //data length
    int offset;    //current offset
    char *data;    //buffer for write or read
};

struct fast_net_buffer_wrapper
{
    struct fast_net_buffer holder;
    struct fast_net_buffer *ptr;
};

struct fast_task_queue;
struct fast_task_info
{
    IOEventEntry event;  //must first
    union {
        char server_ip[IP_ADDRESS_SIZE];
        char client_ip[IP_ADDRESS_SIZE];
    };
    void *arg;        //extra argument pointer
    char *recv_body;  //for extra (dynamic) recv buffer

    struct {
        struct iovec *iovs;
        int count;
    } iovec_array; //for writev

    struct fast_net_buffer_wrapper send;  //send buffer
    struct fast_net_buffer_wrapper recv;  //recv buffer

    uint16_t port; //peer port
    struct {
        uint8_t current;
        volatile uint8_t notify;
    } nio_stages; //stages for network IO
    volatile int8_t reffer_count;
    volatile int8_t canceled;  //if task canceled
    short connect_timeout;     //for client side
    short network_timeout;
    int pending_send_count;
    int64_t req_count; //request count
    struct {
        int64_t  last_req_count;
        uint32_t last_calc_time;
        uint16_t continuous_count;
        bool in_queue;
        struct fc_list_head dlink;  //for polling queue
    } polling;  //for RDMA busy polling
    TaskContinueCallback continue_callback; //for continue stage
    TaskFinishCallback finish_callback;
    struct nio_thread_data *thread_data;
    struct sf_network_handler *handler; //network handler for libserverframe nio
    struct fast_task_info *next;        //for free queue and deleted list
    struct fast_task_info *notify_next; //for nio notify queue
    struct fast_task_queue *free_queue; //task allocator
    char conn[0];    //for RDMA connection
};

struct fast_task_queue
{
    int min_buff_size;
    int max_buff_size;
    int padding_size;   //for last field: conn[0]
    int arg_size;       //for arg pointer
    int block_size;
    bool malloc_whole_block;
    bool double_buffers;  //if send buffer and recv buffer are independent
    struct fast_mblock_man allocator;
    TaskInitCallback init_callback;
    TaskReleaseCallback release_callback;
};

#ifdef __cplusplus
extern "C" {
#endif

int free_queue_init_ex2(struct fast_task_queue *queue, const char *name,
        const bool double_buffers, const int max_connections,
        const int alloc_task_once, const int min_buff_size,
        const int max_buff_size, const int padding_size,
        const int arg_size, TaskInitCallback init_callback);

static inline int free_queue_init_ex(struct fast_task_queue *queue,
        const char *name, const bool double_buffers,
        const int max_connections, const int alloc_task_once,
        const int min_buff_size, const int max_buff_size,
        const int arg_size)
{
    const int padding_size = 0;
    return free_queue_init_ex2(queue, name, double_buffers, max_connections,
            alloc_task_once, min_buff_size, max_buff_size, padding_size,
            arg_size, NULL);
}

static inline int free_queue_init(struct fast_task_queue *queue,
        const int max_connections, const int alloc_task_once,
        const int min_buff_size, const int max_buff_size)
{
    const char *name = "";
    const bool double_buffers = false;
    const int arg_size = 0;
    return free_queue_init_ex(queue, name, double_buffers, max_connections,
            alloc_task_once, min_buff_size, max_buff_size, arg_size);
}

static inline void free_queue_set_release_callback(
        struct fast_task_queue *queue,
        TaskReleaseCallback callback)
{
    queue->release_callback = callback;
}

void free_queue_destroy(struct fast_task_queue *queue);

static inline struct fast_task_info *free_queue_pop(
        struct fast_task_queue *queue)
{
    return fast_mblock_alloc_object(&queue->allocator);
}

void free_queue_push(struct fast_task_info *task);

static inline int free_queue_count(struct fast_task_queue *queue)
{
    return queue->allocator.info.element_total_count -
        queue->allocator.info.element_used_count;
}

static inline int free_queue_alloc_connections(struct fast_task_queue *queue)
{
    return queue->allocator.info.element_total_count;
}

int free_queue_get_new_buffer_size(const int min_buff_size,
        const int max_buff_size, const int expect_size, int *new_size);

int free_queue_set_buffer_size(struct fast_task_info *task,
        struct fast_net_buffer *buffer, const int expect_size);

static inline int free_queue_set_max_buffer_size(
        struct fast_task_info *task,
        struct fast_net_buffer *buffer)
{
    return free_queue_set_buffer_size(task, buffer,
            task->free_queue->max_buff_size);
}

int free_queue_realloc_buffer(struct fast_task_info *task,
        struct fast_net_buffer *buffer, const int expect_size);

static inline int free_queue_realloc_max_buffer(
        struct fast_task_info *task,
        struct fast_net_buffer *buffer)
{
    return free_queue_realloc_buffer(task, buffer,
            task->free_queue->max_buff_size);
}

/* send and recv buffer operations */
static inline int free_queue_set_send_buffer_size(
        struct fast_task_info *task, const int expect_size)
{
    return free_queue_set_buffer_size(task, task->send.ptr, expect_size);
}

static inline int free_queue_set_recv_buffer_size(
        struct fast_task_info *task, const int expect_size)
{
    return free_queue_set_buffer_size(task, task->recv.ptr, expect_size);
}

static inline int free_queue_set_send_max_buffer_size(
        struct fast_task_info *task)
{
    return free_queue_set_max_buffer_size(task, task->send.ptr);
}

static inline int free_queue_set_recv_max_buffer_size(
        struct fast_task_info *task)
{
    return free_queue_set_max_buffer_size(task, task->recv.ptr);
}

static inline int free_queue_realloc_send_buffer(
        struct fast_task_info *task, const int expect_size)
{
    return free_queue_realloc_buffer(task, task->send.ptr, expect_size);
}

static inline int free_queue_realloc_recv_buffer(
        struct fast_task_info *task, const int expect_size)
{
    return free_queue_realloc_buffer(task, task->recv.ptr, expect_size);
}

static inline int free_queue_realloc_send_max_buffer(
        struct fast_task_info *task)
{
    return free_queue_realloc_max_buffer(task, task->send.ptr);
}

static inline int free_queue_realloc_recv_max_buffer(
        struct fast_task_info *task)
{
    return free_queue_realloc_max_buffer(task, task->recv.ptr);
}

#ifdef __cplusplus
}
#endif

#endif

