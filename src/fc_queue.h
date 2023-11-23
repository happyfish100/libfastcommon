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

//fc_queue.h

#ifndef _FC_QUEUE_H
#define _FC_QUEUE_H

#include "common_define.h"
#include "fast_mblock.h"

struct fc_queue_info
{
    void *head;
    void *tail;
};

struct fc_queue
{
	void *head;
	void *tail;
    pthread_lock_cond_pair_t lcp;
    int next_ptr_offset;
};


#define FC_QUEUE_NEXT_PTR(queue, data) \
    *((void **)(((char *)data) + (queue)->next_ptr_offset))

#ifdef __cplusplus
extern "C" {
#endif

int fc_queue_init(struct fc_queue *queue, const int next_ptr_offset);

void fc_queue_destroy(struct fc_queue *queue);

static inline void fc_queue_terminate(struct fc_queue *queue)
{
    pthread_cond_signal(&queue->lcp.cond);
}

static inline void fc_queue_terminate_all(
        struct fc_queue *queue, const int count)
{
    int i;
    for (i=0; i<count; i++) {
        pthread_cond_signal(&(queue->lcp.cond));
    }
}

#define fc_queue_notify(queue) fc_queue_terminate(queue)

#define fc_queue_notify_all(queue, count) \
    fc_queue_terminate_all(queue, count)

//notify by the caller
void fc_queue_push_ex(struct fc_queue *queue, void *data, bool *notify);
int fc_queue_push_with_check_ex(struct fc_queue *queue,
        void *data, bool *notify);

static inline void fc_queue_push(struct fc_queue *queue, void *data)
{
    bool notify;

    fc_queue_push_ex(queue, data, &notify);
    if (notify) {
        pthread_cond_signal(&(queue->lcp.cond));
    }
}

static inline int fc_queue_push_with_check(struct fc_queue *queue, void *data)
{
    int result;
    bool notify;

    result = fc_queue_push_with_check_ex(queue, data, &notify);
    if (notify) {
        pthread_cond_signal(&(queue->lcp.cond));
    }

    return result;
}

static inline void fc_queue_push_silence(struct fc_queue *queue, void *data)
{
    bool notify;
    fc_queue_push_ex(queue, data, &notify);
}

void fc_queue_push_queue_to_head_ex(struct fc_queue *queue,
        struct fc_queue_info *qinfo, bool *notify);

static inline void fc_queue_push_queue_to_head(struct fc_queue *queue,
        struct fc_queue_info *qinfo)
{
    bool notify;

    fc_queue_push_queue_to_head_ex(queue, qinfo, &notify);
    if (notify) {
        pthread_cond_signal(&(queue->lcp.cond));
    }
}

static inline void fc_queue_push_queue_to_head_silence(
        struct fc_queue *queue, struct fc_queue_info *qinfo)
{
    bool notify;
    fc_queue_push_queue_to_head_ex(queue, qinfo, &notify);
}

void fc_queue_push_queue_to_tail_ex(struct fc_queue *queue,
        struct fc_queue_info *qinfo, bool *notify);

static inline void fc_queue_push_queue_to_tail(struct fc_queue *queue,
        struct fc_queue_info *qinfo)
{
    bool notify;

    fc_queue_push_queue_to_tail_ex(queue, qinfo, &notify);
    if (notify) {
        pthread_cond_signal(&(queue->lcp.cond));
    }
}

static inline void fc_queue_push_queue_to_tail_silence(
        struct fc_queue *queue, struct fc_queue_info *qinfo)
{
    bool notify;
    fc_queue_push_queue_to_tail_ex(queue, qinfo, &notify);
}

void *fc_queue_pop_ex(struct fc_queue *queue, const bool blocked);
#define fc_queue_pop(queue) fc_queue_pop_ex(queue, true)
#define fc_queue_try_pop(queue) fc_queue_pop_ex(queue, false)

void *fc_queue_pop_all_ex(struct fc_queue *queue, const bool blocked);
#define fc_queue_pop_all(queue) fc_queue_pop_all_ex(queue, true)
#define fc_queue_try_pop_all(queue) fc_queue_pop_all_ex(queue, false)

void fc_queue_pop_to_queue_ex(struct fc_queue *queue,
        struct fc_queue_info *qinfo, const bool blocked);

#define fc_queue_pop_to_queue(queue, qinfo) \
    fc_queue_pop_to_queue_ex(queue, qinfo, true)

#define fc_queue_try_pop_to_queue(queue, qinfo) \
    fc_queue_pop_to_queue_ex(queue, qinfo, false)

static inline bool fc_queue_empty(struct fc_queue *queue)
{
    bool empty;

    pthread_mutex_lock(&queue->lcp.lock);
    empty = (queue->head == NULL);
    pthread_mutex_unlock(&queue->lcp.lock);
    return empty;
}

static inline int fc_queue_count(struct fc_queue *queue)
{
    int count;
    void *data;

    count = 0;
    pthread_mutex_lock(&queue->lcp.lock);
    data = queue->head;
    while (data != NULL)
    {
        ++count;
        data = FC_QUEUE_NEXT_PTR(queue, data);
    }
    pthread_mutex_unlock(&queue->lcp.lock);
    return count;
}

static inline void *fc_queue_peek(struct fc_queue *queue)
{
    void *data;

    pthread_mutex_lock(&queue->lcp.lock);
    data = queue->head;
    pthread_mutex_unlock(&queue->lcp.lock);
    return data;
}

void *fc_queue_timedpop(struct fc_queue *queue,
        const int timeout, const int time_unit);

#define fc_queue_timedpop_sec(queue, timeout) \
    fc_queue_timedpop(queue, timeout, FC_TIME_UNIT_SECOND)

#define fc_queue_timedpop_ms(queue, timeout_ms) \
    fc_queue_timedpop(queue, timeout_ms, FC_TIME_UNIT_MSECOND)

#define fc_queue_timedpop_us(queue, timeout_us) \
    fc_queue_timedpop(queue, timeout_us, FC_TIME_UNIT_USECOND)

void *fc_queue_timedpeek(struct fc_queue *queue,
        const int timeout, const int time_unit);

#define fc_queue_timedpeek_sec(queue, timeout) \
    fc_queue_timedpeek(queue, timeout, FC_TIME_UNIT_SECOND)

#define fc_queue_timedpeek_ms(queue, timeout_ms) \
    fc_queue_timedpeek(queue, timeout_ms, FC_TIME_UNIT_MSECOND)

#define fc_queue_timedpeek_us(queue, timeout_us) \
    fc_queue_timedpeek(queue, timeout_us, FC_TIME_UNIT_USECOND)

int fc_queue_alloc_chain(struct fc_queue *queue, struct fast_mblock_man
        *mblock, const int count, struct fc_queue_info *chain);

int fc_queue_free_chain(struct fc_queue *queue, struct fast_mblock_man
        *mblock, struct fc_queue_info *qinfo);

#ifdef __cplusplus
}
#endif

#endif
