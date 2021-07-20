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

//common_blocked_queue.c

#include <errno.h>
#include <pthread.h>
#include <inttypes.h>
#include "logger.h"
#include "shared_func.h"
#include "pthread_func.h"
#include "common_blocked_queue.h"

int common_blocked_queue_init_ex(struct common_blocked_queue *queue,
        const int alloc_elements_once)
{
    const int64_t alloc_elements_limit = 0;
	int result;

	if ((result=init_pthread_lock_cond_pair(&queue->lc_pair)) != 0)
	{
		return result;
	}

    if ((result=fast_mblock_init_ex1(&queue->mblock, "queue-node",
                    sizeof(struct common_blocked_node),
                    alloc_elements_once, alloc_elements_limit,
                    NULL, NULL, false)) != 0)
    {
        return result;
    }

	queue->head = NULL;
	queue->tail = NULL;

	return 0;
}

void common_blocked_queue_destroy(struct common_blocked_queue *queue)
{
    destroy_pthread_lock_cond_pair(&queue->lc_pair);
    fast_mblock_destroy(&queue->mblock);
}

int common_blocked_queue_push_ex(struct common_blocked_queue *queue,
        void *data, bool *notify)
{
	int result;
    struct common_blocked_node *node;

	if ((result=pthread_mutex_lock(&(queue->lc_pair.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

    node = (struct common_blocked_node *)fast_mblock_alloc_object(
            &queue->mblock);
    if (node == NULL)
    {
        pthread_mutex_unlock(&(queue->lc_pair.lock));
		return ENOMEM;
    }

	node->data = data;
	node->next = NULL;
	if (queue->tail == NULL)
	{
		queue->head = node;
        *notify = true;
	}
	else
	{
		queue->tail->next = node;
        *notify = false;
	}
	queue->tail = node;

	if ((result=pthread_mutex_unlock(&(queue->lc_pair.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return 0;
}

void common_blocked_queue_return_nodes(struct common_blocked_queue *queue,
        struct common_blocked_node *node)
{
    struct common_blocked_node *last;

    if (node == NULL)
    {
        return;
    }

    last = node;
    while (last->next != NULL) {
        last = last->next;
    }

    pthread_mutex_lock(&(queue->lc_pair.lock));
    last->next = queue->head;
    queue->head = node;
    if (queue->tail == NULL)
    {
        queue->tail = last;
    }
    pthread_mutex_unlock(&(queue->lc_pair.lock));
}

void *common_blocked_queue_pop_ex(struct common_blocked_queue *queue,
        const bool blocked)
{
    struct common_blocked_node *node;
	void *data;
	int result;

	if ((result=pthread_mutex_lock(&(queue->lc_pair.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return NULL;
	}

    do {
        node = queue->head;
        if (node == NULL)
        {
            if (!blocked)
            {
                data = NULL;
                break;
            }

            pthread_cond_wait(&(queue->lc_pair.cond), &(queue->lc_pair.lock));
            node = queue->head;
        }

        if (node != NULL)
        {
            queue->head = node->next;
            if (queue->head == NULL)
            {
                queue->tail = NULL;
            }

            data = node->data;
            fast_mblock_free_object(&queue->mblock, node);
        }
        else
        {
            data = NULL;
        }
    } while (0);

	if ((result=pthread_mutex_unlock(&(queue->lc_pair.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return data;
}

void *common_blocked_queue_timedpop(struct common_blocked_queue *queue,
        const int timeout, const int time_unit)
{
    struct common_blocked_node *node;
    void *data;
    int result;

    if ((result=pthread_mutex_lock(&(queue->lc_pair.lock))) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "call pthread_mutex_lock fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return NULL;
    }

    do {
        node = queue->head;
        if (node == NULL)
        {
            fc_cond_timedwait(&queue->lc_pair, timeout, time_unit);
            node = queue->head;
        }

        if (node != NULL)
        {
            queue->head = node->next;
            if (queue->head == NULL)
            {
                queue->tail = NULL;
            }

            data = node->data;
            fast_mblock_free_object(&queue->mblock, node);
        }
        else
        {
            data = NULL;
        }
    } while (0);

    if ((result=pthread_mutex_unlock(&(queue->lc_pair.lock))) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "call pthread_mutex_unlock fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
    }

    return data;
}

struct common_blocked_node *common_blocked_queue_pop_all_nodes_ex(
        struct common_blocked_queue *queue, const bool blocked)
{
    struct common_blocked_node *node;
	int result;

	if ((result=pthread_mutex_lock(&(queue->lc_pair.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"call pthread_mutex_lock fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return NULL;
	}

    if (queue->head == NULL)
    {
        if (blocked)
        {
            pthread_cond_wait(&(queue->lc_pair.cond), &(queue->lc_pair.lock));
        }
    }

    node = queue->head;
    queue->head = queue->tail = NULL;
	if ((result=pthread_mutex_unlock(&(queue->lc_pair.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"call pthread_mutex_unlock fail, "
			"errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
	}

	return node;
}

void common_blocked_queue_free_all_nodes(struct common_blocked_queue *queue,
        struct common_blocked_node *node)
{
    struct common_blocked_node *deleted;

    pthread_mutex_lock(&(queue->lc_pair.lock));
    while (node != NULL) {
        deleted = node;
        node = node->next;
        fast_mblock_free_object(&queue->mblock, deleted);
    }
    pthread_mutex_unlock(&(queue->lc_pair.lock));
}
