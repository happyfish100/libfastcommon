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

//fast_blocked_queue.h

#ifndef _FAST_BLOCKED_QUEUE_H
#define _FAST_BLOCKED_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common_define.h"
#include "fast_task_queue.h"

struct fast_blocked_queue
{
	struct fast_task_info *head;
	struct fast_task_info *tail;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

#ifdef __cplusplus
extern "C" {
#endif

int blocked_queue_init(struct fast_blocked_queue *pQueue);
void blocked_queue_destroy(struct fast_blocked_queue *pQueue);

static inline void blocked_queue_terminate(struct fast_blocked_queue *pQueue)
{
     pthread_cond_signal(&(pQueue->cond));
}

static inline void blocked_queue_terminate_all(struct fast_blocked_queue *pQueue,
        const int count)
{
    int i;
    for (i=0; i<count; i++)
    {
        pthread_cond_signal(&(pQueue->cond));
    }
}

int blocked_queue_push(struct fast_blocked_queue *pQueue,
		struct fast_task_info *pTask);

struct fast_task_info *blocked_queue_pop(struct fast_blocked_queue *pQueue);

#ifdef __cplusplus
}
#endif

#endif

