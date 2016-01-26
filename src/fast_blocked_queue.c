//fast_blocked_queue.c

#include <errno.h>
#include <pthread.h>
#include <inttypes.h>
#include "logger.h"
#include "shared_func.h"
#include "pthread_func.h"
#include "fast_blocked_queue.h"

int blocked_queue_init(struct fast_blocked_queue *pQueue)
{
	int result;

	if ((result=init_pthread_lock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, "
			"init_pthread_lock fail, errno: %d, error info: %s",
			__LINE__, result, STRERROR(result));
		return result;
	}

    result = pthread_cond_init(&(pQueue->cond), NULL);
    if (result != 0)
    {
        logError("file: "__FILE__", line: %d, "
                "pthread_cond_init fail, "
                "errno: %d, error info: %s",
                __LINE__, result, STRERROR(result));
        return result;
    }

	pQueue->head = NULL;
	pQueue->tail = NULL;

	return 0;
}

void blocked_queue_destroy(struct fast_blocked_queue *pQueue)
{
    pthread_cond_destroy(&(pQueue->cond));
    pthread_mutex_destroy(&(pQueue->lock));
}

int blocked_queue_push(struct fast_blocked_queue *pQueue,
		struct fast_task_info *pTask)
{
	int result;
    bool notify;

	if ((result=pthread_mutex_lock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

	pTask->next = NULL;
	if (pQueue->tail == NULL)
	{
		pQueue->head = pTask;
        notify = true;
	}
	else
	{
		pQueue->tail->next = pTask;
        notify = false;
	}
	pQueue->tail = pTask;

	if ((result=pthread_mutex_unlock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

    if (notify)
    {
        pthread_cond_signal(&(pQueue->cond));
    }

	return 0;
}

struct fast_task_info *blocked_queue_pop(struct fast_blocked_queue *pQueue)
{
	struct fast_task_info *pTask;
	int result;

	if ((result=pthread_mutex_lock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return NULL;
	}

	pTask = pQueue->head;
	if (pTask == NULL)
	{
        pthread_cond_wait(&(pQueue->cond), &(pQueue->lock));
        pTask = pQueue->head;
    }

	if (pTask != NULL)
    {
		pQueue->head = pTask->next;
		if (pQueue->head == NULL)
		{
			pQueue->tail = NULL;
		}
	}

	if ((result=pthread_mutex_unlock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return pTask;
}

