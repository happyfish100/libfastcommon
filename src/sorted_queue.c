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

int sorted_queue_init(struct sorted_queue *sq, const int dlink_offset,
        int (*push_compare_func)(const void *data1, const void *data2),
        int (*pop_compare_func)(const void *data, const
            void *less_equal, void *arg), void *arg)
{
    int result;

    if ((result=init_pthread_lock_cond_pair(&sq->lcp)) != 0) {
        return result;
    }

    FC_INIT_LIST_HEAD(&sq->head);
    sq->dlink_offset = dlink_offset;
    sq->arg = arg;
    sq->push_compare_func = push_compare_func;
    sq->pop_compare_func = pop_compare_func;
    return 0;
}

void sorted_queue_destroy(struct sorted_queue *sq)
{
    destroy_pthread_lock_cond_pair(&sq->lcp);
}

void sorted_queue_push_ex(struct sorted_queue *sq, void *data, bool *notify)
{
    struct fc_list_head *dlink;
    struct fc_list_head *current;

    dlink = FC_SORTED_QUEUE_DLINK_PTR(sq, data);
    PTHREAD_MUTEX_LOCK(&sq->lcp.lock);
    if (fc_list_empty(&sq->head)) {
        fc_list_add(dlink, &sq->head);
        *notify = true;
    } else {
        if (sq->push_compare_func(data, FC_SORTED_QUEUE_DATA_PTR(
                        sq, sq->head.prev)) >= 0)
        {
            fc_list_add_tail(dlink, &sq->head);
            *notify = false;
        } else if (sq->push_compare_func(data, FC_SORTED_QUEUE_DATA_PTR(
                        sq, sq->head.next)) < 0)
        {
            fc_list_add(dlink, &sq->head);
            *notify = true;
        } else {
            current = sq->head.prev->prev;
            while (sq->push_compare_func(data, FC_SORTED_QUEUE_DATA_PTR(
                        sq, current)) < 0)
            {
                current = current->prev;
            }
            fc_list_add_after(dlink, current);
            *notify = false;
        }
    }

    PTHREAD_MUTEX_UNLOCK(&sq->lcp.lock);
}

void *sorted_queue_pop_ex(struct sorted_queue *sq,
        void *less_equal, const bool blocked)
{
    void *data;
    struct fc_list_head *current;

    PTHREAD_MUTEX_LOCK(&sq->lcp.lock);
    do {
        if (fc_list_empty(&sq->head)) {
            if (!blocked) {
                data = NULL;
                break;
            }

            pthread_cond_wait(&sq->lcp.cond,
                    &sq->lcp.lock);
            if (fc_list_empty(&sq->head)) {
                data = NULL;
                break;
            }
        }

        current = sq->head.next;
        data = FC_SORTED_QUEUE_DATA_PTR(sq, current);
        if (sq->pop_compare_func(data, less_equal, sq->arg) <= 0) {
            fc_list_del_init(current);
        } else {
            data = NULL;
        }
    } while (0);
    PTHREAD_MUTEX_UNLOCK(&sq->lcp.lock);

    return data;
}

void sorted_queue_pop_to_chain_ex(struct sorted_queue *sq,
        void *less_equal, struct fc_list_head *head,
        const bool blocked)
{
    struct fc_list_head *current;

    PTHREAD_MUTEX_LOCK(&sq->lcp.lock);
    do {
        if (fc_list_empty(&sq->head)) {
            if (!blocked) {
                FC_INIT_LIST_HEAD(head);
                break;
            }

            pthread_cond_wait(&sq->lcp.cond,
                    &sq->lcp.lock);
        }

        if (fc_list_empty(&sq->head)) {
            FC_INIT_LIST_HEAD(head);
        } else {
            current = sq->head.next;
            if (sq->pop_compare_func(FC_SORTED_QUEUE_DATA_PTR(
                        sq, current), less_equal, sq->arg) <= 0)
            {
                head->next = current;
                current->prev = head;
                current = current->next;
                while (current != &sq->head && sq->pop_compare_func(
                            FC_SORTED_QUEUE_DATA_PTR(sq, current),
                            less_equal, sq->arg) <= 0)
                {
                    current = current->next;
                }

                head->prev = current->prev;
                current->prev->next = head;
                if (current == &sq->head) {
                    FC_INIT_LIST_HEAD(&sq->head);
                } else {
                    sq->head.next = current;
                    current->prev = &sq->head;
                }
            } else {
                FC_INIT_LIST_HEAD(head);
            }
        }
    } while (0);

    PTHREAD_MUTEX_UNLOCK(&sq->lcp.lock);
}

int sorted_queue_free_chain(struct sorted_queue *sq,
        struct fast_mblock_man *mblock, struct fc_list_head *head)
{
    struct fast_mblock_node *previous;
    struct fast_mblock_node *current;
    struct fast_mblock_chain chain;
    struct fc_list_head *node;

    if (fc_list_empty(&sq->head)) {
        return 0;
    }

    node = head->next;
    chain.head = previous = fast_mblock_to_node_ptr(
            FC_SORTED_QUEUE_DATA_PTR(sq, node));
    node = node->next;
    while (node != head) {
        current = fast_mblock_to_node_ptr(FC_SORTED_QUEUE_DATA_PTR(sq, node));
        previous->next = current;
        previous = current;
        node = node->next;
    }

    previous->next = NULL;
    chain.tail = previous;
    return fast_mblock_batch_free(mblock, &chain);
}
