//fast_task_queue.c

#include <errno.h>
#include <sys/resource.h>
#include <pthread.h>
#include <inttypes.h>
#include "fast_task_queue.h"
#include "logger.h"
#include "shared_func.h"
#include "pthread_func.h"

static struct fast_task_queue g_free_queue;

struct mpool_node {
	struct fast_task_info *blocks;
	struct fast_task_info *last_block;   //last block
	struct mpool_node *next;
};

struct mpool_chain {
    struct mpool_node *head;
    struct mpool_node *tail;
};

static struct mpool_chain g_mpool = {NULL, NULL};

#define ALIGNED_TASK_INFO_SIZE  MEM_ALIGN(sizeof(struct fast_task_info))

int task_queue_init(struct fast_task_queue *pQueue)
{
	int result;

	if ((result=init_pthread_lock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"init_pthread_lock fail, errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

	pQueue->head = NULL;
	pQueue->tail = NULL;

	return 0;
}

static struct mpool_node *malloc_mpool(const int total_alloc_size)
{
	struct fast_task_info *pTask;
	char *p;
	char *pCharEnd;
	struct mpool_node *mpool;

	mpool = (struct mpool_node *)malloc(sizeof(struct mpool_node));
	if (mpool == NULL)
	{
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes fail, " \
			"errno: %d, error info: %s", \
			__LINE__, (int)sizeof(struct mpool_node), \
			errno, STRERROR(errno));
		return NULL;
	}

	mpool->next = NULL;
	mpool->blocks = (struct fast_task_info *)malloc(total_alloc_size);
	if (mpool->blocks == NULL)
	{
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes fail, " \
			"errno: %d, error info: %s", \
			__LINE__, total_alloc_size, \
			errno, STRERROR(errno));
		free(mpool);
		return NULL;
	}
	memset(mpool->blocks, 0, total_alloc_size);

	pCharEnd = ((char *)mpool->blocks) + total_alloc_size;
	for (p=(char *)mpool->blocks; p<pCharEnd; p += g_free_queue.block_size)
	{
		pTask = (struct fast_task_info *)p;
		pTask->size = g_free_queue.min_buff_size;

		pTask->arg = p + ALIGNED_TASK_INFO_SIZE;
		if (g_free_queue.malloc_whole_block)
		{
			pTask->data = (char *)pTask->arg + \
					g_free_queue.arg_size;
		}
		else
		{
			pTask->data = (char *)malloc(pTask->size);
			if (pTask->data == NULL)
			{
				char *pt;

				logError("file: "__FILE__", line: %d, " \
					"malloc %d bytes fail, " \
					"errno: %d, error info: %s", \
					__LINE__, pTask->size, \
					errno, STRERROR(errno));

				for (pt=(char *)mpool->blocks; pt < p; \
					pt += g_free_queue.block_size)
				{
					free(((struct fast_task_info *)pt)->data);
				}

				free(mpool->blocks);
				free(mpool);
				return NULL;
			}
		}
	}

	mpool->last_block = (struct fast_task_info *)(pCharEnd - g_free_queue.block_size);
	for (p=(char *)mpool->blocks; p<(char *)mpool->last_block; p += g_free_queue.block_size)
	{
		pTask = (struct fast_task_info *)p;
		pTask->next = (struct fast_task_info *)(p + g_free_queue.block_size);
	}
	mpool->last_block->next = NULL;

	return mpool;
}

int free_queue_init_ex(const int max_connections, const int init_connections,
        const int alloc_task_once, const int min_buff_size,
        const int max_buff_size, const int arg_size)
{
#define MAX_DATA_SIZE  (256 * 1024 * 1024)
	int64_t total_size;
	struct mpool_node *mpool;
	int alloc_size;
    int alloc_once;
	int result;
	int loop_count;
	int aligned_min_size;
	int aligned_max_size;
	int aligned_arg_size;
	rlim_t max_data_size;

	if ((result=init_pthread_lock(&(g_free_queue.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"init_pthread_lock fail, errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

	aligned_min_size = MEM_ALIGN(min_buff_size);
	aligned_max_size = MEM_ALIGN(max_buff_size);
	aligned_arg_size = MEM_ALIGN(arg_size);
	g_free_queue.block_size = ALIGNED_TASK_INFO_SIZE + aligned_arg_size;
	alloc_size = g_free_queue.block_size * init_connections;
	if (aligned_max_size > aligned_min_size)
	{
		total_size = alloc_size;
		g_free_queue.malloc_whole_block = false;
		max_data_size = 0;
	}
	else
	{
		struct rlimit rlimit_data;

		if (getrlimit(RLIMIT_DATA, &rlimit_data) < 0)
		{
			logError("file: "__FILE__", line: %d, " \
				"call getrlimit fail, " \
				"errno: %d, error info: %s", \
				__LINE__, errno, STRERROR(errno));
			return errno != 0 ? errno : EPERM;
		}
		if (rlimit_data.rlim_cur == RLIM_INFINITY)
		{
			max_data_size = MAX_DATA_SIZE;
		}
		else
		{
			max_data_size = rlimit_data.rlim_cur;
			if (max_data_size > MAX_DATA_SIZE)
			{
				max_data_size = MAX_DATA_SIZE;
			}
		}

		if (max_data_size >= (int64_t)(g_free_queue.block_size + aligned_min_size) *
			(int64_t)init_connections)
		{
			total_size = alloc_size + (int64_t)aligned_min_size *
					init_connections;
			g_free_queue.malloc_whole_block = true;
			g_free_queue.block_size += aligned_min_size;
		}
		else
		{
			total_size = alloc_size;
			g_free_queue.malloc_whole_block = false;
			max_data_size = 0;
		}
	}

	g_free_queue.max_connections = max_connections;
	g_free_queue.alloc_connections = init_connections;
    if (alloc_task_once <= 0)
    {
        g_free_queue.alloc_task_once = 256;
		alloc_once = MAX_DATA_SIZE / g_free_queue.block_size;
        if (g_free_queue.alloc_task_once > alloc_once)
        {
            g_free_queue.alloc_task_once = alloc_once;
        }
    }
    else
    {
        g_free_queue.alloc_task_once = alloc_task_once;
    }
	g_free_queue.min_buff_size = aligned_min_size;
	g_free_queue.max_buff_size = aligned_max_size;
	g_free_queue.arg_size = aligned_arg_size;

	logDebug("file: "__FILE__", line: %d, "
		"max_connections: %d, init_connections: %d, alloc_task_once: %d, "
        "min_buff_size: %d, max_buff_size: %d, block_size: %d, "
        "arg_size: %d, max_data_size: %d, total_size: %"PRId64,
        __LINE__, max_connections, init_connections,
        g_free_queue.alloc_task_once, aligned_min_size, aligned_max_size,
        g_free_queue.block_size, aligned_arg_size, (int)max_data_size, total_size);

	if ((!g_free_queue.malloc_whole_block) || (total_size <= max_data_size))
	{
		loop_count = 1;
		mpool = malloc_mpool(total_size);
		if (mpool == NULL)
		{
			return errno != 0 ? errno : ENOMEM;
		}
		g_mpool.head = mpool;
		g_mpool.tail = mpool;
	}
	else
	{
		int remain_count;
		int alloc_count;
		int current_alloc_size;

		loop_count = 0;
		remain_count = init_connections;
		alloc_once = max_data_size / g_free_queue.block_size;
		while (remain_count > 0)
		{
			alloc_count = (remain_count > alloc_once) ?
					alloc_once : remain_count;
			current_alloc_size = g_free_queue.block_size * alloc_count;
			mpool = malloc_mpool(current_alloc_size);
			if (mpool == NULL)
			{
				free_queue_destroy();
				return errno != 0 ? errno : ENOMEM;
			}

			if (g_mpool.tail == NULL)
			{
				g_mpool.head = mpool;
			}
			else
			{
				g_mpool.tail->next = mpool;
				g_mpool.tail->last_block->next = mpool->blocks;  //link previous mpool to current
			}
            g_mpool.tail = mpool;

			remain_count -= alloc_count;
			loop_count++;
		}

		logDebug("file: "__FILE__", line: %d, " \
			"alloc_once: %d", __LINE__, alloc_once);
	}

	logDebug("file: "__FILE__", line: %d, " \
		"malloc task info as whole: %d, malloc loop count: %d", \
		__LINE__, g_free_queue.malloc_whole_block, loop_count);

	if (g_mpool.head != NULL)
	{
		g_free_queue.head = g_mpool.head->blocks;
		g_free_queue.tail = g_mpool.tail->last_block;
	}

	return 0;
}

int free_queue_init(const int max_connections, const int min_buff_size,
		const int max_buff_size, const int arg_size)
{
    return free_queue_init_ex(max_connections, max_connections,
        0, min_buff_size, max_buff_size, arg_size);
}

void free_queue_destroy()
{
	struct mpool_node *mpool;
	struct mpool_node *mp;

	if (g_mpool.head == NULL)
	{
		return;
	}

	if (!g_free_queue.malloc_whole_block)
	{
		char *p;
		char *pCharEnd;
		struct fast_task_info *pTask;

        mpool = g_mpool.head;
        while (mpool != NULL)
        {
            pCharEnd = (char *)mpool->last_block + g_free_queue.block_size;
            for (p=(char *)mpool->blocks; p<pCharEnd; p += g_free_queue.block_size)
            {
                pTask = (struct fast_task_info *)p;
                if (pTask->data != NULL)
                {
                    free(pTask->data);
                    pTask->data = NULL;
                }
            }
            mpool = mpool->next;
        }
	}

	mpool = g_mpool.head;
	while (mpool != NULL)
	{
		mp = mpool;
		mpool = mpool->next;

		free(mp->blocks);
		free(mp);
	}
	g_mpool.head = g_mpool.tail = NULL;

	pthread_mutex_destroy(&(g_free_queue.lock));
}

static int free_queue_realloc()
{
	struct mpool_node *mpool;
	struct fast_task_info *head;
	struct fast_task_info *tail;
	int remain_count;
	int alloc_count;
	int current_alloc_size;

    head = tail = NULL;
	remain_count = g_free_queue.max_connections -
        g_free_queue.alloc_connections;
    alloc_count = (remain_count > g_free_queue.alloc_task_once) ?
        g_free_queue.alloc_task_once : remain_count;
    if (alloc_count > 0)
	{
		current_alloc_size = g_free_queue.block_size * alloc_count;
		mpool = malloc_mpool(current_alloc_size);
		if (mpool == NULL)
		{
            return ENOMEM;
		}

		if (g_mpool.tail == NULL)
		{
			g_mpool.head = mpool;
		}
		else
		{
			g_mpool.tail->next = mpool;
		}
        g_mpool.tail = mpool;

        head = mpool->blocks;
        tail = mpool->last_block;

		remain_count -= alloc_count;
	}
    else {
        return ENOSPC;
    }

    if (g_free_queue.head == NULL)
    {
        g_free_queue.head = head;
    }
    if (g_free_queue.tail != NULL)
    {
        g_free_queue.tail->next = head;
    }
    g_free_queue.tail = tail;

    g_free_queue.alloc_connections += alloc_count;

	logDebug("file: "__FILE__", line: %d, "
		"alloc_connections: %d, realloc %d elements", __LINE__,
        g_free_queue.alloc_connections, alloc_count);

    return 0;
}

struct fast_task_info *free_queue_pop()
{
    struct fast_task_info *pTask;
	if ((pTask=task_queue_pop(&g_free_queue)) != NULL)
    {
        return pTask;
    }

    if (g_free_queue.alloc_connections >= g_free_queue.max_connections)
    {
        return NULL;
    }

	pthread_mutex_lock(&g_free_queue.lock);
    if (g_free_queue.alloc_connections >= g_free_queue.max_connections)
    {
        if (g_free_queue.head == NULL)
        {
            pthread_mutex_unlock(&g_free_queue.lock);
            return NULL;
        }
    }
    else
    {
        if (free_queue_realloc() != 0)
        {
            pthread_mutex_unlock(&g_free_queue.lock);
            return NULL;
        }
    }
	pthread_mutex_unlock(&g_free_queue.lock);

    return task_queue_pop(&g_free_queue);
}

static int _realloc_buffer(struct fast_task_info *pTask, const int new_size,
        const bool copy_data)
{
	char *new_buff;
    new_buff = (char *)malloc(new_size);
    if (new_buff == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "malloc %d bytes fail, "
                "errno: %d, error info: %s",
                __LINE__, new_size,
                errno, STRERROR(errno));
        return errno != 0 ? errno : ENOMEM;
    }
    else
    {
        if (copy_data && pTask->offset > 0) {
            memcpy(new_buff, pTask->data, pTask->offset);
        }
        free(pTask->data);
        pTask->size = new_size;
        pTask->data = new_buff;
        return 0;
    }
}

int free_queue_push(struct fast_task_info *pTask)
{
	int result;

	*(pTask->client_ip) = '\0';
	pTask->length = 0;
	pTask->offset = 0;
	pTask->req_count = 0;

	if (pTask->size > g_free_queue.min_buff_size) //need thrink
	{
        _realloc_buffer(pTask, g_free_queue.min_buff_size, false);
	}

	if ((result=pthread_mutex_lock(&g_free_queue.lock)) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	pTask->next = g_free_queue.head;
	g_free_queue.head = pTask;
	if (g_free_queue.tail == NULL)
	{
		g_free_queue.tail = pTask;
	}

	if ((result=pthread_mutex_unlock(&g_free_queue.lock)) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return result;
}

int free_queue_count()
{
	return task_queue_count(&g_free_queue);
}

int free_queue_alloc_connections()
{
    return g_free_queue.alloc_connections;
}

int free_queue_set_buffer_size(struct fast_task_info *pTask,
        const int expect_size)
{
    return task_queue_set_buffer_size(&g_free_queue, pTask, expect_size);
}

int free_queue_realloc_buffer(struct fast_task_info *pTask,
        const int expect_size)
{
    return task_queue_realloc_buffer(&g_free_queue, pTask, expect_size);
}

int task_queue_push(struct fast_task_queue *pQueue, \
		struct fast_task_info *pTask)
{
	int result;

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
	}
	else
	{
		pQueue->tail->next = pTask;
	}
	pQueue->tail = pTask;

	if ((result=pthread_mutex_unlock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return 0;
}

struct fast_task_info *task_queue_pop(struct fast_task_queue *pQueue)
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

int task_queue_count(struct fast_task_queue *pQueue)
{
	struct fast_task_info *pTask;
	int count;
	int result;

	if ((result=pthread_mutex_lock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return 0;
	}

	count = 0;
	pTask = pQueue->head;
	while (pTask != NULL)
	{
		pTask = pTask->next;
		count++;
	}

	if ((result=pthread_mutex_unlock(&(pQueue->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return count;
}

int task_queue_get_new_buffer_size(const int min_buff_size,
        const int max_buff_size, const int expect_size, int *new_size)
{
    if (min_buff_size == max_buff_size)
    {
        logError("file: "__FILE__", line: %d, "
                "can't change buffer size because NOT supported", __LINE__);
        return EOPNOTSUPP;
    }

    if (expect_size > max_buff_size)
    {
        logError("file: "__FILE__", line: %d, "
                "can't change buffer size because expect buffer size: %d "
                "exceeds max buffer size: %d", __LINE__, expect_size,
                max_buff_size);
        return EOVERFLOW;
    }

    *new_size = min_buff_size;
    if (expect_size > min_buff_size)
    {
        while (*new_size < expect_size)
        {
            *new_size *= 2;
        }
        if (*new_size > max_buff_size)
        {
            *new_size = max_buff_size;
        }
    }

    return 0;
}

#define  _get_new_buffer_size(pQueue, expect_size, new_size) \
    task_queue_get_new_buffer_size(pQueue->min_buff_size, \
            pQueue->max_buff_size, expect_size, new_size)

int task_queue_set_buffer_size(struct fast_task_queue *pQueue,
        struct fast_task_info *pTask, const int expect_size)
{
    int result;
    int new_size;

    if ((result=_get_new_buffer_size(pQueue, expect_size, &new_size)) != 0) {
        return result;
    }
    if (pTask->size == new_size)  //do NOT need change buffer size
    {
        return 0;
    }

    return _realloc_buffer(pTask, new_size, false);
}

int task_queue_realloc_buffer(struct fast_task_queue *pQueue,
        struct fast_task_info *pTask, const int expect_size)
{
    int result;
    int new_size;

    if (pTask->size >= expect_size)  //do NOT need change buffer size
    {
        return 0;
    }

    if ((result=_get_new_buffer_size(pQueue, expect_size, &new_size)) != 0) {
        return result;
    }

    return _realloc_buffer(pTask, new_size, true);
}

