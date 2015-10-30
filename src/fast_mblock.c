//fast_mblock.c

#include <errno.h>
#include <sys/resource.h>
#include <pthread.h>
#include <assert.h>
#include "logger.h"
#include "shared_func.h"
#include "pthread_func.h"
#include "sched_thread.h"
#include "fast_mblock.h"

struct _fast_mblock_manager
{
    bool initialized;
    struct fast_mblock_man head;
	pthread_mutex_t lock;
};

#define INIT_HEAD(head) (head)->next = (head)->prev = head
#define IS_EMPTY(head) ((head)->next == head)

static struct _fast_mblock_manager mblock_manager = {false};

int fast_mblock_manager_init()
{
    int result;
	if ((result=init_pthread_lock(&(mblock_manager.lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"init_pthread_lock fail, errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}
    INIT_HEAD(&mblock_manager.head);
    mblock_manager.initialized = true;

    return 0;
}

static int cmp_mblock_info(struct fast_mblock_man *mb1, struct fast_mblock_man *mb2)
{
    int result;
    result = strcmp(mb1->info.name, mb2->info.name);
    if (result != 0)
    {
        return result;
    }

    return mb1->info.element_size - mb2->info.element_size;
}

static void add_to_mblock_list(struct fast_mblock_man *mblock)
{
    struct fast_mblock_man *current;
    if (!mblock_manager.initialized)
    {
        return;
    }

    if (*mblock->info.name == '\0')
    {
        snprintf(mblock->info.name, sizeof(mblock->info.name),
                "size-%d", mblock->info.element_size);
    }
    pthread_mutex_lock(&(mblock_manager.lock));
    current = mblock_manager.head.next;
    while (current != &mblock_manager.head)
    {
        if (cmp_mblock_info(mblock, current) <= 0)
        {
            break;
        }
        current = current->next;
    }

    mblock->next = current;
    mblock->prev = current->prev;
    current->prev->next = mblock;
    current->prev = mblock;

    pthread_mutex_unlock(&(mblock_manager.lock));
}

static void delete_from_mblock_list(struct fast_mblock_man *mblock)
{
    if (!mblock_manager.initialized)
    {
        return;
    }

    pthread_mutex_lock(&(mblock_manager.lock));
    mblock->prev->next = mblock->next;
    mblock->next->prev = mblock->prev;
    pthread_mutex_unlock(&(mblock_manager.lock));

    INIT_HEAD(mblock);
}

#define STAT_DUP(pStat, current, copy_name) \
    do { \
        if (copy_name) { \
            strcpy(pStat->name, current->info.name); \
            pStat->element_size = current->info.element_size; \
        } \
        pStat->total_count += current->info.total_count;  \
        pStat->used_count += current->info.used_count;    \
        pStat->instance_count += current->info.instance_count;  \
        /* logInfo("name: %s, element_size: %d, total_count: %d, used_count: %d", */ \
        /* pStat->name, pStat->element_size, pStat->total_count, pStat->used_count); */\
    } while (0)

int fast_mblock_manager_stat(struct fast_mblock_info *stats,
        const int size, int *count)
{
    int result;
    struct fast_mblock_man *current;
    struct fast_mblock_info *pStat;

    if (!mblock_manager.initialized)
    {
        *count = 0;
        return EFAULT;
    }

    if (size <= 0)
    {
        *count = 0;
        return EOVERFLOW;
    }

    result = 0;
    pStat = stats;
    memset(stats, 0, sizeof(struct fast_mblock_info) * size);
    pthread_mutex_lock(&(mblock_manager.lock));
    current = mblock_manager.head.next;
    while (current != &mblock_manager.head)
    {
        if (current->prev != &mblock_manager.head)
        {
            if (cmp_mblock_info(current, current->prev) != 0)
            {
                if (size <= (int)(pStat - stats))
                {
                    result = EOVERFLOW;
                    break;
                }
                STAT_DUP(pStat, current->prev, true);
                pStat++;
            }
            else
            {
                STAT_DUP(pStat, current->prev, false);
            }
        }
        current = current->next;
    }

    if (!IS_EMPTY(&mblock_manager.head))
    {
        if (size <= (int)(pStat - stats))
        {
            result = EOVERFLOW;
        }
        else
        {
            STAT_DUP(pStat, current->prev, true);
            pStat++;
        }
    }
    pthread_mutex_unlock(&(mblock_manager.lock));

    *count = (int)(pStat - stats);
    return result;
}

int fast_mblock_manager_stat_print()
{
    int result;
    int count;
    int alloc_size;
    struct fast_mblock_info *stats;
    struct fast_mblock_info *pStat;
    struct fast_mblock_info *stat_end;

    stats = NULL;
    count = 0;
    alloc_size = 128;
    result = EOVERFLOW;
    while (result == EOVERFLOW)
    {
        alloc_size *= 2;
        stats = realloc(stats, sizeof(struct fast_mblock_info) * alloc_size);
        if (stats == NULL)
        {
            return ENOMEM;
        }
        result = fast_mblock_manager_stat(stats,
                alloc_size, &count);
    }

    if (result == 0)
    {
        logInfo("mblock stat count: %d", count);
        logInfo("%32s %12s %16s %12s %12s %12s", "name", "element_size",
                "instance_count", "alloc_count", "used_count", "used_ratio");
        stat_end = stats + count;
        for (pStat=stats; pStat<stat_end; pStat++)
        {
            logInfo("%32s %12d %16d %12d %12d %12.4f", pStat->name,
                    pStat->element_size, pStat->instance_count,
                    pStat->total_count, pStat->used_count,
                    pStat->total_count > 0 ? (double)pStat->used_count /
                    (double)pStat->total_count : 0.00);
        }
    }

    if (stats != NULL) free(stats);
    return 0;
}

int fast_mblock_init_ex(struct fast_mblock_man *mblock,
        const int element_size, const int alloc_elements_once,
        fast_mblock_alloc_init_func init_func, const bool need_lock)
{
    return fast_mblock_init_ex2(mblock, NULL, element_size,
            alloc_elements_once, init_func, need_lock);
}

int fast_mblock_init_ex2(struct fast_mblock_man *mblock, const char *name,
        const int element_size, const int alloc_elements_once,
        fast_mblock_alloc_init_func init_func, const bool need_lock)
{
	int result;

	if (element_size <= 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"invalid block size: %d", \
			__LINE__, element_size);
		return EINVAL;
	}

	mblock->info.element_size = MEM_ALIGN(element_size);
	if (alloc_elements_once > 0)
	{
		mblock->alloc_elements_once = alloc_elements_once;
	}
	else
	{
		int block_size;
		block_size = MEM_ALIGN(sizeof(struct fast_mblock_node) \
			+ mblock->info.element_size);
		mblock->alloc_elements_once = (1024 * 1024) / block_size;
	}

	if (need_lock && (result=init_pthread_lock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"init_pthread_lock fail, errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

    mblock->alloc_init_func = init_func;
	mblock->malloc_chain_head = NULL;
	mblock->free_chain_head = NULL;
	mblock->delay_free_chain.head = NULL;
	mblock->delay_free_chain.tail = NULL;
    mblock->info.total_count = 0;
    mblock->info.used_count = 0;
    mblock->info.instance_count = 1;
    mblock->need_lock = need_lock;

    if (name != NULL)
    {
        snprintf(mblock->info.name, sizeof(mblock->info.name), "%s", name);
    }
    else
    {
        *mblock->info.name = '\0';
    }
    add_to_mblock_list(mblock);

	return 0;
}

static int fast_mblock_prealloc(struct fast_mblock_man *mblock)
{
	struct fast_mblock_node *pNode;
	struct fast_mblock_malloc *pMallocNode;
	char *pNew;
	char *pTrunkStart;
	char *p;
	char *pLast;
    int result;
	int block_size;
	int alloc_size;

	block_size = MEM_ALIGN(sizeof(struct fast_mblock_node) + \
			mblock->info.element_size);
	alloc_size = sizeof(struct fast_mblock_malloc) + block_size * \
			mblock->alloc_elements_once;

	pNew = (char *)malloc(alloc_size);
	if (pNew == NULL)
	{
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes fail, " \
			"errno: %d, error info: %s", \
			__LINE__, alloc_size, errno, STRERROR(errno));
		return errno != 0 ? errno : ENOMEM;
	}
	memset(pNew, 0, alloc_size);

	pMallocNode = (struct fast_mblock_malloc *)pNew;

	pTrunkStart = pNew + sizeof(struct fast_mblock_malloc);
	pLast = pNew + (alloc_size - block_size);
	for (p=pTrunkStart; p<pLast; p += block_size)
	{
		pNode = (struct fast_mblock_node *)p;

        if (mblock->alloc_init_func != NULL)
        {
            if ((result=mblock->alloc_init_func(pNode->data)) != 0)
            {
                free(pNew);
                return result;
            }
        }
		pNode->next = (struct fast_mblock_node *)(p + block_size);
	}

    if (mblock->alloc_init_func != NULL)
    {
        if ((result=mblock->alloc_init_func(((struct fast_mblock_node *)
                            pLast)->data)) != 0)
        {
            free(pNew);
            return result;
        }
    }
    ((struct fast_mblock_node *)pLast)->next = NULL;
	mblock->free_chain_head = (struct fast_mblock_node *)pTrunkStart;

	pMallocNode->next = mblock->malloc_chain_head;
	mblock->malloc_chain_head = pMallocNode;
    mblock->info.total_count += mblock->alloc_elements_once;

	return 0;
}

void fast_mblock_destroy(struct fast_mblock_man *mblock)
{
	struct fast_mblock_malloc *pMallocNode;
	struct fast_mblock_malloc *pMallocTmp;

	if (mblock->malloc_chain_head == NULL)
	{
		return;
	}

	pMallocNode = mblock->malloc_chain_head;
	while (pMallocNode != NULL)
	{
		pMallocTmp = pMallocNode;
		pMallocNode = pMallocNode->next;

		free(pMallocTmp);
	}
	mblock->malloc_chain_head = NULL;
	mblock->free_chain_head = NULL;
    mblock->info.used_count = 0;
    mblock->info.total_count = 0;

    if (mblock->need_lock) pthread_mutex_destroy(&(mblock->lock));
    delete_from_mblock_list(mblock);
}

struct fast_mblock_node *fast_mblock_alloc(struct fast_mblock_man *mblock)
{
	struct fast_mblock_node *pNode;
	int result;

	if (mblock->need_lock && (result=pthread_mutex_lock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return NULL;
	}

	if (mblock->free_chain_head != NULL)
	{
		pNode = mblock->free_chain_head;
		mblock->free_chain_head = pNode->next;
        mblock->info.used_count++;
	}
	else
	{
        if (mblock->delay_free_chain.head != NULL &&
                mblock->delay_free_chain.head->recycle_timestamp <= get_current_time())
        {
            pNode = mblock->delay_free_chain.head;
            mblock->delay_free_chain.head = pNode->next;
            if (mblock->delay_free_chain.tail == pNode)
            {
                mblock->delay_free_chain.tail = NULL;
            }
        }
        else if ((result=fast_mblock_prealloc(mblock)) == 0)
		{
			pNode = mblock->free_chain_head;
			mblock->free_chain_head = pNode->next;
            mblock->info.used_count++;
		}
		else
		{
			pNode = NULL;
		}
	}

	if (mblock->need_lock && (result=pthread_mutex_unlock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return pNode;
}

int fast_mblock_free(struct fast_mblock_man *mblock, \
		     struct fast_mblock_node *pNode)
{
	int result;

	if (mblock->need_lock && (result=pthread_mutex_lock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

	pNode->next = mblock->free_chain_head;
	mblock->free_chain_head = pNode;
    mblock->info.used_count--;

	if (mblock->need_lock && (result=pthread_mutex_unlock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return 0;
}

int fast_mblock_delay_free(struct fast_mblock_man *mblock,
		     struct fast_mblock_node *pNode, const int deley)
{
	int result;

	if (mblock->need_lock && (result=pthread_mutex_lock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return result;
	}

    pNode->recycle_timestamp = get_current_time() + deley;
	if (mblock->delay_free_chain.head == NULL)
    {
        mblock->delay_free_chain.head = pNode;
    }
    else
    {
        mblock->delay_free_chain.tail->next = pNode;
    }
    mblock->delay_free_chain.tail = pNode;
    pNode->next = NULL;

	if (mblock->need_lock && (result=pthread_mutex_unlock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return 0;
}

static int fast_mblock_chain_count(struct fast_mblock_man *mblock,
        struct fast_mblock_node *head)
{
	struct fast_mblock_node *pNode;
	int count;
	int result;

	if (mblock->need_lock && (result=pthread_mutex_lock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_lock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
		return -1;
	}

	count = 0;
	pNode = head;
	while (pNode != NULL)
	{
		pNode = pNode->next;
		count++;
	}

	if (mblock->need_lock && (result=pthread_mutex_unlock(&(mblock->lock))) != 0)
	{
		logError("file: "__FILE__", line: %d, " \
			"call pthread_mutex_unlock fail, " \
			"errno: %d, error info: %s", \
			__LINE__, result, STRERROR(result));
	}

	return count;
}

int fast_mblock_free_count(struct fast_mblock_man *mblock)
{
    return fast_mblock_chain_count(mblock, mblock->free_chain_head);
}

int fast_mblock_delay_free_count(struct fast_mblock_man *mblock)
{
    return fast_mblock_chain_count(mblock, mblock->delay_free_chain.head);
}

