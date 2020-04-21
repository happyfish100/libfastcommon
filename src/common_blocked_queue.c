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
	int result;

	if ((result=init_pthread_lock(&queue->lock)) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"init_pthread_lock fail, errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

    if ((result=pthread_cond_init(&queue->cond, NULL)) != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "pthread_cond_init fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    if ((result=fast_mblock_init_ex2(&queue->mblock,
                    "queue_node", sizeof(struct common_blocked_node),
                    alloc_elements_once, NULL, NULL, false,
                    NULL, NULL, NULL)) != 0)
    {
        return result;
    }

	queue->head = NULL;
	queue->tail = NULL;

	return 0;
}

void common_blocked_queue_destroy(struct common_blocked_queue *queue)
{
    pthread_cond_destroy(&queue->cond);
    pthread_mutex_destroy(&queue->lock);
    fast_mblock_destroy(&queue->mblock);
}

int common_blocked_queue_push_ex(struct common_blocked_queue *queue,
        void *data, bool *notify)
{
	int result;
    struct common_blocked_node *node;

	if ((result=pthread_mutex_lock(&(queue->lock))) != 0)
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
        pthread_mutex_unlock(&(queue->lock));
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

	if ((result=pthread_mutex_unlock(&(queue->lock))) != 0)
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

    pthread_mutex_lock(&(queue->lock));
    last->next = queue->head;
    queue->head = node;
    if (queue->tail == NULL)
    {
        queue->tail = last;
    }
    pthread_mutex_unlock(&(queue->lock));
}

void *common_blocked_queue_pop_ex(struct common_blocked_queue *queue,
        const bool blocked)
{
    struct common_blocked_node *node;
	void *data;
	int result;

	if ((result=pthread_mutex_lock(&(queue->lock))) != 0)
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

            pthread_cond_wait(&(queue->cond), &(queue->lock));
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

	if ((result=pthread_mutex_unlock(&(queue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return data;
}

struct common_blocked_node *common_blocked_queue_pop_all_nodes_ex(
        struct common_blocked_queue *queue, const bool blocked)
{
    struct common_blocked_node *node;
	int result;

	if ((result=pthread_mutex_lock(&(queue->lock))) != 0)
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
            pthread_cond_wait(&(queue->cond), &(queue->lock));
        }
    }

    node = queue->head;
    queue->head = queue->tail = NULL;
	if ((result=pthread_mutex_unlock(&(queue->lock))) != 0)
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

    pthread_mutex_lock(&(queue->lock));
    while (node != NULL) {
        deleted = node;
        node = node->next;
        fast_mblock_free_object(&queue->mblock, deleted);
    }
    pthread_mutex_unlock(&(queue->lock));
}
