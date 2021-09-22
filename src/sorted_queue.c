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

//sorted_queue.c

#include "pthread_func.h"
#include "sorted_queue.h"

int sorted_queue_init(struct sorted_queue *sq, const int next_ptr_offset,
        int (*compare_func)(const void *, const void *))
{
    sq->compare_func = compare_func;
	return fc_queue_init(&sq->queue, next_ptr_offset);
}

void sorted_queue_destroy(struct sorted_queue *sq)
{
    fc_queue_destroy(&sq->queue);
}

void sorted_queue_push_ex(struct sorted_queue *sq, void *data, bool *notify)
{
    void *previous;
    void *current;

    PTHREAD_MUTEX_LOCK(&sq->queue.lc_pair.lock);
    if (sq->queue.tail == NULL) {
        FC_QUEUE_NEXT_PTR(&sq->queue, data) = NULL;
        sq->queue.head = sq->queue.tail = data;
        *notify = true;
    } else {
        if (sq->compare_func(data, sq->queue.tail) >= 0) {
            FC_QUEUE_NEXT_PTR(&sq->queue, data) = NULL;
            FC_QUEUE_NEXT_PTR(&sq->queue, sq->queue.tail) = data;
            sq->queue.tail = data;
            *notify = false;
        } else if (sq->compare_func(data, sq->queue.head) < 0) {
            FC_QUEUE_NEXT_PTR(&sq->queue, data) = sq->queue.head;
            sq->queue.head = data;
            *notify = true;
        } else {
            previous = sq->queue.head;
            current = FC_QUEUE_NEXT_PTR(&sq->queue, previous);
            while (sq->compare_func(data, current) >= 0) {
                previous = current;
                current = FC_QUEUE_NEXT_PTR(&sq->queue, previous);
            }

            FC_QUEUE_NEXT_PTR(&sq->queue, data) = FC_QUEUE_NEXT_PTR(
                    &sq->queue, previous);
            FC_QUEUE_NEXT_PTR(&sq->queue, previous) = data;
            *notify = false;
        }
    }

    PTHREAD_MUTEX_UNLOCK(&sq->queue.lc_pair.lock);
}

void *sorted_queue_pop_ex(struct sorted_queue *sq,
        void *less_equal, const bool blocked)
{
	void *data;

    PTHREAD_MUTEX_LOCK(&sq->queue.lc_pair.lock);
    do {
        if (sq->queue.head == NULL || sq->compare_func(
                    sq->queue.head, less_equal) > 0)
        {
            if (!blocked) {
                data = NULL;
                break;
            }

            pthread_cond_wait(&sq->queue.lc_pair.cond,
                    &sq->queue.lc_pair.lock);
        }

        if (sq->queue.head == NULL) {
            data = NULL;
        } else {
            if (sq->compare_func(sq->queue.head, less_equal) <= 0) {
                data = sq->queue.head;
                sq->queue.head = FC_QUEUE_NEXT_PTR(&sq->queue, data);
                if (sq->queue.head == NULL) {
                    sq->queue.tail = NULL;
                }
            } else {
                data = NULL;
            }
        }
    } while (0);

    PTHREAD_MUTEX_UNLOCK(&sq->queue.lc_pair.lock);
	return data;
}

void sorted_queue_pop_to_queue_ex(struct sorted_queue *sq,
        void *less_equal, struct fc_queue_info *qinfo,
        const bool blocked)
{
    PTHREAD_MUTEX_LOCK(&sq->queue.lc_pair.lock);
    do {
        if (sq->queue.head == NULL) {
            if (!blocked) {
                qinfo->head = qinfo->tail = NULL;
                break;
            }

            pthread_cond_wait(&sq->queue.lc_pair.cond,
                    &sq->queue.lc_pair.lock);
        }

        if (sq->queue.head == NULL) {
            qinfo->head = qinfo->tail = NULL;
        } else {
            if (sq->compare_func(sq->queue.head, less_equal) <= 0) {
                qinfo->head = qinfo->tail = sq->queue.head;
                sq->queue.head = FC_QUEUE_NEXT_PTR(&sq->queue,
                        sq->queue.head);
                while (sq->queue.head != NULL && sq->compare_func(
                            sq->queue.head, less_equal) <= 0)
                {
                    qinfo->tail = sq->queue.head;
                    sq->queue.head = FC_QUEUE_NEXT_PTR(
                            &sq->queue, sq->queue.head);
                }

                if (sq->queue.head == NULL) {
                    sq->queue.tail = NULL;
                } else {
                    FC_QUEUE_NEXT_PTR(&sq->queue, qinfo->tail) = NULL;
                }
            } else {
                qinfo->head = qinfo->tail = NULL;
            }
        }
    } while (0);

    PTHREAD_MUTEX_UNLOCK(&sq->queue.lc_pair.lock);
}
