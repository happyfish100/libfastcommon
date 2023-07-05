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

//sorted_queue.h

#ifndef _FC_SORTED_QUEUE_H
#define _FC_SORTED_QUEUE_H

#include "fast_mblock.h"
#include "fc_list.h"
#include "pthread_func.h"

struct sorted_queue
{
    struct fc_list_head head;
    pthread_lock_cond_pair_t lcp;
    int dlink_offset;
    void *arg;
    int (*push_compare_func)(const void *data1, const void *data2);
    int (*pop_compare_func)(const void *data,
            const void *less_equal, void *arg);
};

#define FC_SORTED_QUEUE_DLINK_PTR(sq, data) \
    ((void *)(((char *)data) + (sq)->dlink_offset))

#define FC_SORTED_QUEUE_DATA_PTR(sq, dlink) \
    ((void *)((char *)(dlink) - (sq)->dlink_offset))

#ifdef __cplusplus
extern "C" {
#endif

int sorted_queue_init(struct sorted_queue *sq, const int dlink_offset,
        int (*push_compare_func)(const void *data1, const void *data2),
        int (*pop_compare_func)(const void *data, const
            void *less_equal, void *arg), void *arg);

void sorted_queue_destroy(struct sorted_queue *sq);

static inline void sorted_queue_terminate(struct sorted_queue *sq)
{
    pthread_cond_signal(&sq->lcp.cond);
}

static inline void sorted_queue_terminate_all(
        struct sorted_queue *sq, const int count)
{
    int i;
    for (i=0; i<count; i++) {
        pthread_cond_signal(&(sq->lcp.cond));
    }
}

//notify by the caller
void sorted_queue_push_ex(struct sorted_queue *sq, void *data, bool *notify);

static inline void sorted_queue_push(struct sorted_queue *sq, void *data)
{
    bool notify;

    sorted_queue_push_ex(sq, data, &notify);
    if (notify) {
        pthread_cond_signal(&(sq->lcp.cond));
    }
}

static inline void sorted_queue_push_silence(
        struct sorted_queue *sq, void *data)
{
    bool notify;
    sorted_queue_push_ex(sq, data, &notify);
}

void *sorted_queue_pop_ex(struct sorted_queue *sq,
        void *less_equal, const bool blocked);

#define sorted_queue_pop(sq, less_equal) \
    sorted_queue_pop_ex(sq, less_equal, true)

#define sorted_queue_try_pop(sq, less_equal) \
    sorted_queue_pop_ex(sq, less_equal, false)

void sorted_queue_pop_to_chain_ex(struct sorted_queue *sq,
        void *less_equal, struct fc_list_head *head,
        const bool blocked);

#define sorted_queue_pop_to_chain(sq, less_equal, head) \
    sorted_queue_pop_to_chain_ex(sq, less_equal, head, true)

#define sorted_queue_try_pop_to_chain(sq, less_equal, head) \
    sorted_queue_pop_to_chain_ex(sq, less_equal, head, false)

static inline bool sorted_queue_empty(struct sorted_queue *sq)
{
    return fc_list_empty(&sq->head);
}

int sorted_queue_free_chain(struct sorted_queue *sq,
        struct fast_mblock_man *mblock, struct fc_list_head *head);

static inline void sorted_queue_lock(struct sorted_queue *sq)
{
    PTHREAD_MUTEX_LOCK(&sq->lcp.lock);
}

static inline void sorted_queue_unlock(struct sorted_queue *sq)
{
    PTHREAD_MUTEX_UNLOCK(&sq->lcp.lock);
}

#ifdef __cplusplus
}
#endif

#endif
