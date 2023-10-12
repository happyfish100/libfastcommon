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

//fast_task_queue.c

#include <errno.h>
#include <sys/resource.h>
#include <pthread.h>
#include <inttypes.h>
#include "logger.h"
#include "shared_func.h"
#include "pthread_func.h"
#include "fc_memory.h"
#include "fast_task_queue.h"

static int task_alloc_init(struct fast_task_info *task,
        struct fast_task_queue *queue)
{
    task->arg = (char *)task + ALIGNED_TASK_INFO_SIZE + queue->padding_size;
    task->send.ptr = &task->send.holder;
    task->send.ptr->size = queue->min_buff_size;
    if (queue->malloc_whole_block) {
        task->send.ptr->data = (char *)task->arg + queue->arg_size;
    } else {
        task->send.ptr->data = (char *)fc_malloc(task->send.ptr->size);
        if (task->send.ptr->data == NULL) {
            return ENOMEM;
        }
    }

    if (queue->double_buffers) {
        task->recv.ptr = &task->recv.holder;
        task->recv.ptr->size = queue->min_buff_size;
        task->recv.ptr->data = (char *)fc_malloc(task->recv.ptr->size);
        if (task->recv.ptr->data == NULL) {
            return ENOMEM;
        }
    } else {
        task->recv.ptr = &task->send.holder;
    }

    task->free_queue = queue;
    if (queue->init_callback != NULL) {
        return queue->init_callback(task);
    }
    return 0;
}

int free_queue_init_ex2(struct fast_task_queue *queue, const char *name,
        const bool double_buffers, const int max_connections,
        const int alloc_task_once, const int min_buff_size,
        const int max_buff_size, const int padding_size,
        const int arg_size, TaskInitCallback init_callback)
{
#define MAX_DATA_SIZE  (256 * 1024 * 1024)
    int alloc_once;
	int aligned_min_size;
	int aligned_max_size;
	int aligned_padding_size;
	int aligned_arg_size;
	rlim_t max_data_size;
    char aname[64];

	aligned_min_size = MEM_ALIGN(min_buff_size);
	aligned_max_size = MEM_ALIGN(max_buff_size);
    aligned_padding_size = MEM_ALIGN(padding_size);
	aligned_arg_size = MEM_ALIGN(arg_size);
	queue->block_size = ALIGNED_TASK_INFO_SIZE +
        aligned_padding_size + aligned_arg_size;
    if (alloc_task_once <= 0) {
        alloc_once = FC_MIN(MAX_DATA_SIZE / queue->block_size, 256);
        if (alloc_once == 0) {
            alloc_once = 1;
        }
    } else {
        alloc_once = alloc_task_once;
    }

	if (aligned_max_size > aligned_min_size) {
		queue->malloc_whole_block = false;
		max_data_size = 0;
    } else {
        struct rlimit rlimit_data;

        if (getrlimit(RLIMIT_DATA, &rlimit_data) < 0) {
            logError("file: "__FILE__", line: %d, "
                    "call getrlimit fail, "
                    "errno: %d, error info: %s",
                    __LINE__, errno, STRERROR(errno));
            return errno != 0 ? errno : EPERM;
        }
        if (rlimit_data.rlim_cur == RLIM_INFINITY) {
            max_data_size = MAX_DATA_SIZE;
        } else {
            max_data_size = rlimit_data.rlim_cur;
            if (max_data_size > MAX_DATA_SIZE) {
                max_data_size = MAX_DATA_SIZE;
            }
        }

        if (max_data_size >= (int64_t)(queue->block_size +
                    aligned_min_size) * (int64_t)alloc_once)
        {
            queue->malloc_whole_block = true;
            queue->block_size += aligned_min_size;
        } else {
            queue->malloc_whole_block = false;
            max_data_size = 0;
        }
    }

    queue->double_buffers = double_buffers;
	queue->min_buff_size = aligned_min_size;
	queue->max_buff_size = aligned_max_size;
	queue->padding_size = aligned_padding_size;
	queue->arg_size = aligned_arg_size;
	queue->init_callback = init_callback;
    queue->release_callback = NULL;

    /*
	logInfo("file: "__FILE__", line: %d, [%s] double_buffers: %d, "
		"max_connections: %d, alloc_once: %d, malloc_whole_block: %d, "
        "min_buff_size: %d, max_buff_size: %d, block_size: %d, "
        "padding_size: %d, arg_size: %d, max_data_size: %"PRId64,
        __LINE__, name, double_buffers, max_connections, alloc_once,
        queue->malloc_whole_block, aligned_min_size, aligned_max_size,
        queue->block_size, aligned_padding_size, aligned_arg_size,
        (int64_t)max_data_size);
        */

    snprintf(aname, sizeof(aname), "%s-task", name);
	return fast_mblock_init_ex1(&queue->allocator, aname,
            queue->block_size, alloc_once, max_connections,
            (fast_mblock_object_init_func)task_alloc_init,
            queue, true);
}

void free_queue_destroy(struct fast_task_queue *queue)
{
    fast_mblock_destroy(&queue->allocator);
}

static int _realloc_buffer(struct fast_net_buffer *buffer,
        const int new_size, const bool copy_data)
{
	char *new_buff;

    new_buff = (char *)fc_malloc(new_size);
    if (new_buff == NULL) {
        return ENOMEM;
    }

    if (copy_data && buffer->offset > 0) {
        memcpy(new_buff, buffer->data, buffer->offset);
    }
    free(buffer->data);
    buffer->size = new_size;
    buffer->data = new_buff;
    return 0;
}

void free_queue_push(struct fast_task_info *task)
{
    if (task->free_queue->release_callback != NULL) {
        task->free_queue->release_callback(task);
    }

    *(task->client_ip) = '\0';
    task->send.ptr->length = 0;
    task->send.ptr->offset = 0;
    task->req_count = 0;
    if (task->send.ptr->size > task->free_queue->min_buff_size) {//need thrink
        _realloc_buffer(task->send.ptr, task->free_queue->min_buff_size, false);
    }

    if (task->free_queue->double_buffers) {
        task->recv.ptr->length = 0;
        task->recv.ptr->offset = 0;
        if (task->recv.ptr->size > task->free_queue->min_buff_size) {
            _realloc_buffer(task->recv.ptr, task->free_queue->
                    min_buff_size, false);
        }
    }

    fast_mblock_free_object(&task->free_queue->allocator, task);
}

int free_queue_get_new_buffer_size(const int min_buff_size,
        const int max_buff_size, const int expect_size, int *new_size)
{
    if (min_buff_size == max_buff_size) {
        logError("file: "__FILE__", line: %d, "
                "can't change buffer size because NOT supported", __LINE__);
        return EOPNOTSUPP;
    }

    if (expect_size > max_buff_size) {
        logError("file: "__FILE__", line: %d, "
                "can't change buffer size because expect buffer size: %d "
                "exceeds max buffer size: %d", __LINE__, expect_size,
                max_buff_size);
        return EOVERFLOW;
    }

    *new_size = min_buff_size;
    if (expect_size > min_buff_size) {
        while (*new_size < expect_size) {
            *new_size *= 2;
        }
        if (*new_size > max_buff_size) {
            *new_size = max_buff_size;
        }
    }

    return 0;
}

#define  _get_new_buffer_size(queue, expect_size, new_size) \
    free_queue_get_new_buffer_size(queue->min_buff_size, \
            queue->max_buff_size, expect_size, new_size)

int free_queue_set_buffer_size(struct fast_task_info *task,
        struct fast_net_buffer *buffer, const int expect_size)
{
    int result;
    int new_size;

    if ((result=_get_new_buffer_size(task->free_queue,
                    expect_size, &new_size)) != 0)
    {
        return result;
    }
    if (buffer->size == new_size) { //do NOT need change buffer size
        return 0;
    }

    return _realloc_buffer(buffer, new_size, false);
}

int free_queue_realloc_buffer(struct fast_task_info *task,
        struct fast_net_buffer *buffer, const int expect_size)
{
    int result;
    int new_size;

    if (buffer->size >= expect_size) {  //do NOT need change buffer size
        return 0;
    }

    if ((result=_get_new_buffer_size(task->free_queue,
                    expect_size, &new_size)) != 0)
    {
        return result;
    }

    return _realloc_buffer(buffer, new_size, true);
}
