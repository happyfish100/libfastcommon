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

	if ((result=init_pthread_lock(&(queue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"init_pthread_lock fail, errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

    result = pthread_cond_init(&(queue->cond), NULL);
    if (result != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "pthread_cond_init fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

    if ((result=fast_mblock_init_ex(&queue->mblock,
                    sizeof(struct common_blocked_node),
                    alloc_elements_once, NULL, NULL, false)) != 0)
    {
        return result;
    }

	queue->head = NULL;
	queue->tail = NULL;

	return 0;
}

void common_blocked_queue_destroy(struct common_blocked_queue *queue)
{
    pthread_cond_destroy(&(queue->cond));
    pthread_mutex_destroy(&(queue->lock));
}

int common_blocked_queue_push(struct common_blocked_queue *queue, void *data)
{
	int result;
    struct common_blocked_node *node;
    bool notify;

	if ((result=pthread_mutex_lock(&(queue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

    node = (struct common_blocked_node *)fast_mblock_alloc_object(&queue->mblock);
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
        notify = true;
	}
	else
	{
		queue->tail->next = node;
        notify = false;
	}
	queue->tail = node;

	if ((result=pthread_mutex_unlock(&(queue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

    if (notify)
    {
        pthread_cond_signal(&(queue->cond));
    }

	return 0;
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

