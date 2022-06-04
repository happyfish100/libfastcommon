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
	mpool->alloc_count = 0;
	mpool->alloc_bytes = 0;
	mpool->reset.count = 0;
	mpool->reset.last_alloc_count = 0;

	return 0;
}

static int fast_mpool_prealloc(struct fast_mpool_man *mpool,
	const int alloc_size)
{
	struct fast_mpool_malloc *pMallocNode;
    int bytes;

    bytes = sizeof(struct fast_mpool_malloc) + alloc_size;
	pMallocNode = (struct fast_mpool_malloc *)fc_malloc(bytes);
	if (pMallocNode == NULL)
	{
		return ENOMEM;
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

        mpool->alloc_count++;
        mpool->alloc_bytes += size;
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

void *fast_mpool_memdup(struct fast_mpool_man *mpool,
        const void *src, const int len)
{
    void *dest;
    dest = (char *)fast_mpool_alloc(mpool, len);
    if (dest == NULL)
    {
        logError("file: "__FILE__", line: %d, "
                "alloc %d bytes from mpool fail", __LINE__, len);
        return NULL;
    }

    if (len > 0) {
        memcpy(dest, src, len);
    }
    return dest;
}

void fast_mpool_reset(struct fast_mpool_man *mpool)
{
    struct fast_mpool_malloc *pMallocNode;

    mpool->reset.count++;
	if (mpool->reset.last_alloc_count == mpool->alloc_count)
    {
        return;
    }

    mpool->reset.last_alloc_count = mpool->alloc_count;
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

void fast_mpool_stats(struct fast_mpool_man *mpool,
        struct fast_mpool_stats *stats)
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
        stats->free_bytes += (int)(pMallocNode->end_ptr -
                pMallocNode->free_ptr);
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

void fast_mpool_log_stats(struct fast_mpool_man *mpool)
{
    struct fast_mpool_stats stats;
    char sz_total_bytes[32];
    char sz_free_bytes[32];
    char sz_alloc_bytes[32];

    fast_mpool_stats(mpool, &stats);

    long_to_comma_str(stats.total_bytes, sz_total_bytes);
    long_to_comma_str(stats.free_bytes, sz_free_bytes);
    long_to_comma_str(mpool->alloc_bytes, sz_alloc_bytes);
    logInfo("alloc_size_once: %d, discard_size: %d, "
            "bytes: {total: %s, free: %s}, "
            "trunk_count: {total: %d, free: %d}, "
            "alloc_count: %"PRId64", alloc_bytes: %s, "
            "reset_count: %"PRId64, mpool->alloc_size_once,
            mpool->discard_size, sz_total_bytes,
            sz_free_bytes, stats.total_trunk_count,
            stats.free_trunk_count, mpool->alloc_count,
            sz_alloc_bytes, mpool->reset.count);
}
