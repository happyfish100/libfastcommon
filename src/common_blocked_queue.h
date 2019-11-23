/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.fastken.com/ for more detail.
**/

//common_blocked_queue.h

#ifndef _COMMON_BLOCKED_QUEUE_H
#define _COMMON_BLOCKED_QUEUE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common_define.h"
#include "fast_mblock.h"

struct common_blocked_node
{
    void *data;
    struct common_blocked_node *next;
};

struct common_blocked_queue
{
	struct common_blocked_node *head;
	struct common_blocked_node *tail;
    struct fast_mblock_man mblock;
	pthread_mutex_t lock;
	pthread_cond_t cond;
};

#ifdef __cplusplus
extern "C" {
#endif

int common_blocked_queue_init_ex(struct common_blocked_queue *queue,
        const int alloc_elements_once);

#define common_blocked_queue_init(queue)  \
        common_blocked_queue_init_ex(queue, 1024)

void common_blocked_queue_destroy(struct common_blocked_queue *queue);

static inline void common_blocked_queue_terminate(struct common_blocked_queue *queue)
{
    pthread_cond_signal(&(queue->cond));
}

static inline void common_blocked_queue_terminate_all(
        struct common_blocked_queue *queue, const int count)
{
    int i;
    for (i=0; i<count; i++)
    {
        pthread_cond_signal(&(queue->cond));
    }
}

int common_blocked_queue_push(struct common_blocked_queue *queue, void *data);

void *common_blocked_queue_pop_ex(struct common_blocked_queue *queue,
        const bool blocked);

static inline void *common_blocked_queue_pop(struct common_blocked_queue *queue)
{
    return common_blocked_queue_pop_ex(queue, true);
}

static inline void *common_blocked_queue_try_pop(struct common_blocked_queue *queue)
{
    return common_blocked_queue_pop_ex(queue, false);
}

#ifdef __cplusplus
}
#endif

#endif
