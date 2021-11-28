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
#include "ioevent.h"
#include "fast_timer.h"

#define FC_NOTIFY_READ_FD(tdata)  (tdata)->pipe_fds[0]
#define FC_NOTIFY_WRITE_FD(tdata) (tdata)->pipe_fds[1]

#define ALIGNED_TASK_INFO_SIZE  MEM_ALIGN(sizeof(struct fast_task_info))

struct nio_thread_data;
struct fast_task_info;

typedef int (*ThreadLoopCallback) (struct nio_thread_data *pThreadData);
typedef int (*TaskFinishCallback) (struct fast_task_info *pTask);
typedef void (*TaskCleanUpCallback) (struct fast_task_info *pTask);
typedef int (*TaskInitCallback)(struct fast_task_info *pTask);

typedef void (*IOEventCallback) (int sock, short event, void *arg);
typedef int (*TaskContinueCallback)(struct fast_task_info *task);

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
};

struct ioevent_notify_entry
{
    IOEventEntry event;  //must first
    struct nio_thread_data *thread_data;
};

struct fast_task_info
{
	IOEventEntry event;  //must first
    union {
        char server_ip[IP_ADDRESS_SIZE];
        char client_ip[IP_ADDRESS_SIZE];
    };
	void *arg;  //extra argument pointer
	char *data; //buffer for write or read

    struct {
        struct iovec *iovs;
        int count;
    } iovec_array; //for writev

	int size;   //alloc size
	int length; //data length
	int offset; //current offset
    uint16_t port; //peer port
    struct {
        uint8_t current;
        volatile uint8_t notify;
    } nio_stages; //stages for network IO
    TaskContinueCallback continue_callback; //for continue stage
    volatile int8_t reffer_count;
    volatile int8_t canceled;  //if task canceled
    short connect_timeout;     //for client side
    short network_timeout;
	int64_t req_count; //request count
	TaskFinishCallback finish_callback;
	struct nio_thread_data *thread_data;
	void *ctx;  //context pointer for libserverframe nio
	struct fast_task_info *next;
};

struct fast_task_queue
{
	struct fast_task_info *head;
	struct fast_task_info *tail;
	pthread_mutex_t lock;
	int max_connections;
	int alloc_connections;
	int alloc_task_once;
	int min_buff_size;
	int max_buff_size;
	int arg_size;
	int block_size;
	bool malloc_whole_block;
    TaskInitCallback init_callback;
};

#ifdef __cplusplus
extern "C" {
#endif

int free_queue_init_ex2(const int max_connections, const int init_connections,
        const int alloc_task_once, const int min_buff_size,
        const int max_buff_size, const int arg_size,
        TaskInitCallback init_callback);

static inline int free_queue_init_ex(const int max_connections,
        const int init_connections, const int alloc_task_once,
        const int min_buff_size, const int max_buff_size, const int arg_size)
{
    return free_queue_init_ex2(max_connections, init_connections,
            alloc_task_once, min_buff_size, max_buff_size, arg_size, NULL);
}

static inline int free_queue_init(const int max_connections,
        const int min_buff_size, const int max_buff_size, const int arg_size)
{
    return free_queue_init_ex2(max_connections, max_connections,
            0, min_buff_size, max_buff_size, arg_size, NULL);
}

void free_queue_destroy();

int free_queue_push(struct fast_task_info *pTask);
struct fast_task_info *free_queue_pop();
int free_queue_count();
int free_queue_alloc_connections();
int free_queue_set_buffer_size(struct fast_task_info *pTask,
        const int expect_size);
int free_queue_realloc_buffer(struct fast_task_info *pTask,
        const int expect_size);

int free_queue_set_max_buffer_size(struct fast_task_info *pTask);

int free_queue_realloc_max_buffer(struct fast_task_info *pTask);

int task_queue_init(struct fast_task_queue *pQueue);
int task_queue_push(struct fast_task_queue *pQueue, \
		struct fast_task_info *pTask);
struct fast_task_info *task_queue_pop(struct fast_task_queue *pQueue);
int task_queue_count(struct fast_task_queue *pQueue);
int task_queue_set_buffer_size(struct fast_task_queue *pQueue,
        struct fast_task_info *pTask, const int expect_size);
int task_queue_realloc_buffer(struct fast_task_queue *pQueue,
        struct fast_task_info *pTask, const int expect_size);

int task_queue_get_new_buffer_size(const int min_buff_size,
        const int max_buff_size, const int expect_size, int *new_size);

#ifdef __cplusplus
}
#endif

#endif

