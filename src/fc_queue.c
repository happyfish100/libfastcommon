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

//fc_queue.c

#include "pthread_func.h"
#include "fc_queue.h"

int fc_queue_init(struct fc_queue *queue, const int next_ptr_offset)
{
	int result;

	if ((result=init_pthread_lock_cond_pair(&queue->lc_pair)) != 0)
	{
		return result;
	}

	queue->head = NULL;
	queue->tail = NULL;
    queue->next_ptr_offset = next_ptr_offset;
	return 0;
}

void fc_queue_destroy(struct fc_queue *queue)
{
    destroy_pthread_lock_cond_pair(&queue->lc_pair);
}

void fc_queue_push_ex(struct fc_queue *queue, void *data, bool *notify)
{
    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
	FC_QUEUE_NEXT_PTR(queue, data) = NULL;
	if (queue->tail == NULL) {
		queue->head = data;
        *notify = true;
	} else {
		FC_QUEUE_NEXT_PTR(queue, queue->tail) = data;
        *notify = false;
	}
	queue->tail = data;

    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);
}

void *fc_queue_pop_ex(struct fc_queue *queue, const bool blocked)
{
	void *data;

    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
    do {
        data = queue->head;
        if (data == NULL) {
            if (!blocked) {
                break;
            }

            pthread_cond_wait(&queue->lc_pair.cond, &queue->lc_pair.lock);
            data = queue->head;
        }

        if (data != NULL) {
            queue->head = FC_QUEUE_NEXT_PTR(queue, data);
            if (queue->head == NULL) {
                queue->tail = NULL;
            }
        }
    } while (0);

    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);
	return data;
}

void *fc_queue_pop_all_ex(struct fc_queue *queue, const bool blocked)
{
	void *data;

    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
    do {
        data = queue->head;
        if (data == NULL) {
            if (!blocked) {
                break;
            }

            pthread_cond_wait(&queue->lc_pair.cond, &queue->lc_pair.lock);
            data = queue->head;
        }

        if (data != NULL) {
            queue->head = queue->tail = NULL;
        }
    } while (0);

    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);
	return data;
}

void fc_queue_push_queue_to_head_ex(struct fc_queue *queue,
        struct fc_queue_info *qinfo, bool *notify)
{
    if (qinfo->head == NULL) {
        *notify = false;
        return;
    }

    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
    FC_QUEUE_NEXT_PTR(queue, qinfo->tail) = queue->head;
    queue->head = qinfo->head;
    if (queue->tail == NULL) {
        queue->tail = qinfo->tail;
        *notify = true;
    } else {
        *notify = false;
    }
    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);
}

void fc_queue_push_queue_to_tail_ex(struct fc_queue *queue,
        struct fc_queue_info *qinfo, bool *notify)
{
    if (qinfo->head == NULL) {
        *notify = false;
        return;
    }

    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
    if (queue->head == NULL) {
        queue->head = qinfo->head;
        *notify = true;
    } else {
        FC_QUEUE_NEXT_PTR(queue, queue->tail) = qinfo->head;
        *notify = false;
    }
    queue->tail = qinfo->tail;
    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);
}

void fc_queue_pop_to_queue_ex(struct fc_queue *queue,
        struct fc_queue_info *qinfo, const bool blocked)
{
    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
    if (queue->head == NULL) {
        if (blocked) {
            pthread_cond_wait(&queue->lc_pair.cond, &queue->lc_pair.lock);
        }
    }

    if (queue->head != NULL) {
        qinfo->head = queue->head;
        qinfo->tail = queue->tail;
        queue->head = queue->tail = NULL;
    } else {
        qinfo->head = qinfo->tail = NULL;
    }
    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);
}

void *fc_queue_timedpop(struct fc_queue *queue,
        const int timeout, const int time_unit)
{
	void *data;

    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
    data = queue->head;
    if (data == NULL) {
        fc_cond_timedwait(&queue->lc_pair, timeout, time_unit);
        data = queue->head;
    }

    if (data != NULL) {
        queue->head = FC_QUEUE_NEXT_PTR(queue, data);
        if (queue->head == NULL) {
            queue->tail = NULL;
        }
    }
    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);

	return data;
}

void *fc_queue_timedpeek(struct fc_queue *queue,
        const int timeout, const int time_unit)
{
    void *data;

    PTHREAD_MUTEX_LOCK(&queue->lc_pair.lock);
    data = queue->head;
    if (data == NULL) {
        fc_cond_timedwait(&queue->lc_pair, timeout, time_unit);
        data = queue->head;
    }
    PTHREAD_MUTEX_UNLOCK(&queue->lc_pair.lock);

    return data;
}

int fc_queue_alloc_chain(struct fc_queue *queue, struct fast_mblock_man
        *mblock, const int count, struct fc_queue_info *chain)
{
    struct fast_mblock_node *node;

    if ((node=fast_mblock_batch_alloc1(mblock, count)) == NULL) {
        chain->head = chain->tail = NULL;
        return ENOMEM;
    }

    chain->head = chain->tail = node->data;
    while ((node=node->next) != NULL) {
        FC_QUEUE_NEXT_PTR(queue, chain->tail) = node->data;
        chain->tail = node->data;
    }
    FC_QUEUE_NEXT_PTR(queue, chain->tail) = NULL;

    return 0;
}

int fc_queue_free_chain(struct fc_queue *queue, struct fast_mblock_man
        *mblock, struct fc_queue_info *qinfo)
{
    struct fast_mblock_node *previous;
    struct fast_mblock_node *current;
    struct fast_mblock_chain chain;
    void *data;

    if (qinfo->head == NULL) {
        return 0;
    }

    chain.head = previous = fast_mblock_to_node_ptr(qinfo->head);
    data = FC_QUEUE_NEXT_PTR(queue, qinfo->head);
    while (data != NULL) {
        current = fast_mblock_to_node_ptr(data);
        previous->next = current;

        previous = current;
        data = FC_QUEUE_NEXT_PTR(queue, data);
    }

    previous->next = NULL;
    chain.tail = previous;
    return fast_mblock_batch_free(mblock, &chain);
}
