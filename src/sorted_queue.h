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

#include "fc_queue.h"

struct sorted_queue
{
    struct fc_queue queue;
    int (*compare_func)(const void *, const void *);
};

#ifdef __cplusplus
extern "C" {
#endif

int sorted_queue_init(struct sorted_queue *sq, const int next_ptr_offset,
        int (*compare_func)(const void *, const void *));

void sorted_queue_destroy(struct sorted_queue *sq);

static inline void sorted_queue_terminate(struct sorted_queue *sq)
{
    fc_queue_terminate(&sq->queue);
}

static inline void sorted_queue_terminate_all(
        struct sorted_queue *sq, const int count)
{
    fc_queue_terminate_all(&sq->queue, count);
}

//notify by the caller
void sorted_queue_push_ex(struct sorted_queue *sq, void *data, bool *notify);

static inline void sorted_queue_push(struct sorted_queue *sq, void *data)
{
    bool notify;

    sorted_queue_push_ex(sq, data, &notify);
    if (notify) {
        pthread_cond_signal(&(sq->queue.lc_pair.cond));
    }
}

static inline void sorted_queue_push_silence(struct sorted_queue *sq, void *data)
{
    bool notify;
    sorted_queue_push_ex(sq, data, &notify);
}

void *sorted_queue_pop_ex(struct sorted_queue *sq,
        void *less_equal, const bool blocked);

#define sorted_queue_pop(sq, less_equal)  \
    sorted_queue_pop_ex(sq, less_equal, true)

#define sorted_queue_try_pop(sq, less_equal) \
    sorted_queue_pop_ex(sq, less_equal, false)


void sorted_queue_pop_to_queue_ex(struct sorted_queue *sq,
        void *less_equal, struct fc_queue_info *qinfo,
        const bool blocked);

#define sorted_queue_pop_to_queue(sq, less_equal, qinfo) \
    sorted_queue_pop_to_queue_ex(sq, less_equal, qinfo, true)

#define sorted_queue_try_pop_to_queue(sq, less_equal, qinfo) \
    sorted_queue_pop_to_queue_ex(sq, less_equal, qinfo, false)


static inline void *sorted_queue_pop_all_ex(struct sorted_queue *sq,
        void *less_equal, const bool blocked)
{
    struct fc_queue_info chain;
    sorted_queue_pop_to_queue_ex(sq, less_equal, &chain, blocked);
    return chain.head;
}

#define sorted_queue_pop_all(sq, less_equal)  \
    sorted_queue_pop_all_ex(sq, less_equal, true)

#define sorted_queue_try_pop_all(sq, less_equal) \
    sorted_queue_pop_all_ex(sq, less_equal, false)

static inline bool sorted_queue_empty(struct sorted_queue *sq)
{
    return fc_queue_empty(&sq->queue);
}

static inline void *sorted_queue_timedpeek(struct sorted_queue *sq,
        const int timeout, const int time_unit)
{
    return fc_queue_timedpeek(&sq->queue, timeout, time_unit);
}

#define sorted_queue_timedpeek_sec(sq, timeout) \
    sorted_queue_timedpeek(sq, timeout, FC_TIME_UNIT_SECOND)

#define sorted_queue_timedpeek_ms(sq, timeout_ms) \
    sorted_queue_timedpeek(sq, timeout_ms, FC_TIME_UNIT_MSECOND)

#define sorted_queue_timedpeek_us(sq, timeout_us) \
    sorted_queue_timedpeek(sq, timeout_us, FC_TIME_UNIT_USECOND)

static inline int sorted_queue_free_chain(struct sorted_queue *sq,
        struct fast_mblock_man *mblock, struct fc_queue_info *qinfo)
{
    return fc_queue_free_chain(&sq->queue, mblock, qinfo);
}

#ifdef __cplusplus
}
#endif

#endif
