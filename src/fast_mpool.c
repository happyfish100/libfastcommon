//fast_mpool.c

#include <errno.h>
#include <sys/resource.h>
#include <pthread.h>
#include <assert.h>
#include "fast_mpool.h"
#include "logger.h"
#include "shared_func.h"
#include "pthread_func.h"
#include "sched_thread.h"

int fast_mpool_init(struct fast_mpool_man *mpool,
		const int alloc_size_once, const int discard_size)
{
	if (alloc_size_once > 0)
	{
		mpool->alloc_size_once = alloc_size_once;
	}
	else
	{
		mpool->alloc_size_once = 1024 * 1024;
	}

    if (discard_size > 0)
    {
		mpool->discard_size = discard_size;
    }
    else
    {
		mpool->discard_size = 64;
    }

	mpool->malloc_chain_head = NULL;
	mpool->free_chain_head = NULL;

	return 0;
}

static int fast_mpool_prealloc(struct fast_mpool_man *mpool,
	const int alloc_size)
{
	struct fast_mpool_malloc *pMallocNode;
    int bytes;

    bytes = sizeof(struct fast_mpool_malloc) + alloc_size;
	pMallocNode = (struct fast_mpool_malloc *)malloc(bytes);
	if (pMallocNode == NULL)
	{
		logError("file: "__FILE__", line: %d, " \
			"malloc %d bytes fail, " \
			"errno: %d, error info: %s", \
			__LINE__, bytes, errno, STRERROR(errno));
		return errno != 0 ? errno : ENOMEM;
	}

    pMallocNode->alloc_size = alloc_size;
    pMallocNode->base_ptr = (char *)(pMallocNode + 1);
    pMallocNode->end_ptr = pMallocNode->base_ptr + alloc_size;
    pMallocNode->free_ptr = pMallocNode->base_ptr;

	pMallocNode->free_next = mpool->free_chain_head;
	mpool->free_chain_head = pMallocNode;

	pMallocNode->malloc_next = mpool->malloc_chain_head;
	mpool->malloc_chain_head = pMallocNode;

	return 0;
}

void fast_mpool_destroy(struct fast_mpool_man *mpool)
{
	struct fast_mpool_malloc *pMallocNode;
	struct fast_mpool_malloc *pMallocTmp;

	if (mpool->malloc_chain_head == NULL)
	{
		return;
	}

	pMallocNode = mpool->malloc_chain_head;
	while (pMallocNode != NULL)
	{
		pMallocTmp = pMallocNode;
		pMallocNode = pMallocNode->malloc_next;

		free(pMallocTmp);
	}
	mpool->malloc_chain_head = NULL;
	mpool->free_chain_head = NULL;
}

static void fast_mpool_remove_free_node(struct fast_mpool_man *mpool,
        struct fast_mpool_malloc *pMallocNode)
{
	struct fast_mpool_malloc *previous;

    if (mpool->free_chain_head == pMallocNode)
    {
        mpool->free_chain_head = pMallocNode->free_next;
        return;
    }

    previous = mpool->free_chain_head;
    while (previous->free_next != NULL)
    {
        if (previous->free_next == pMallocNode)
        {
            previous->free_next = pMallocNode->free_next;
            return;
        }
        previous = previous->free_next;
    }
}

static inline void *fast_mpool_do_alloc(struct fast_mpool_man *mpool,
        struct fast_mpool_malloc *pMallocNode, const int size)
{
    void *ptr;
    if ((int)(pMallocNode->end_ptr - pMallocNode->free_ptr) >= size)
    {
        ptr = pMallocNode->free_ptr;
        pMallocNode->free_ptr += size;
        if ((int)(pMallocNode->end_ptr - pMallocNode->free_ptr) <=
                mpool->discard_size)
        {
            fast_mpool_remove_free_node(mpool, pMallocNode);
        }

        return ptr;
    }
    return NULL;
}

void *fast_mpool_alloc(struct fast_mpool_man *mpool, const int size)
{
	struct fast_mpool_malloc *pMallocNode;
    void *ptr;
	int result;
    int alloc_size;

    pMallocNode = mpool->free_chain_head;
    while (pMallocNode != NULL)
    {
        if ((ptr=fast_mpool_do_alloc(mpool, pMallocNode, size)) != NULL)
        {
            return ptr;
        }
        pMallocNode  = pMallocNode->free_next;
    }

    if (size < mpool->alloc_size_once)
    {
        alloc_size = mpool->alloc_size_once;
    }
    else
    {
        alloc_size = size;
    }
    if ((result=fast_mpool_prealloc(mpool, alloc_size)) == 0)
	{
        return fast_mpool_do_alloc(mpool, mpool->free_chain_head, size);
	}

	return NULL;
}

void fast_mpool_reset(struct fast_mpool_man *mpool)
{
	struct fast_mpool_malloc *pMallocNode;

	mpool->free_chain_head = NULL;
	pMallocNode = mpool->malloc_chain_head;
	while (pMallocNode != NULL)
	{
        pMallocNode->free_ptr = pMallocNode->base_ptr;

        pMallocNode->free_next = mpool->free_chain_head;
        mpool->free_chain_head = pMallocNode;

		pMallocNode = pMallocNode->malloc_next;
	}
}

void fast_mpool_stats(struct fast_mpool_man *mpool, struct fast_mpool_stats *stats)
{
	struct fast_mpool_malloc *pMallocNode;

    stats->total_bytes = 0;
    stats->free_bytes = 0;
    stats->total_trunk_count = 0;
    stats->free_trunk_count = 0;

	pMallocNode = mpool->malloc_chain_head;
	while (pMallocNode != NULL)
	{
        stats->total_bytes += pMallocNode->alloc_size;
        stats->free_bytes += (int)(pMallocNode->end_ptr - pMallocNode->free_ptr);
        stats->total_trunk_count++;

		pMallocNode = pMallocNode->malloc_next;
	}

	pMallocNode = mpool->free_chain_head;
	while (pMallocNode != NULL)
	{
        stats->free_trunk_count++;
		pMallocNode = pMallocNode->free_next;
	}
}

