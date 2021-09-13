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

//fast_allocator.h

#ifndef _FAST_ALLOCATOR_H
#define _FAST_ALLOCATOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "common_define.h"
#include "fast_mblock.h"

struct fast_allocator_info
{
	int index;
	short magic_number;
	bool pooled;
	struct fast_mblock_man mblock;
};

struct fast_region_info
{
	int start;  //exclude
	int end;    //include
	int step;
	int alloc_elements_once;
	int pad_mask;  //for internal use
    int count;
	struct fast_allocator_info *allocators;
};

struct fast_allocator_array
{
	int count;
	int alloc;
	int reclaim_interval;   //< 0 for never reclaim
	int last_reclaim_time;
	volatile int64_t malloc_bytes;   //total alloc bytes
	int64_t malloc_bytes_limit;      //water mark bytes for malloc
	double expect_usage_ratio;
	struct fast_allocator_info **allocators;
};

struct fast_allocator_context
{
	struct fast_region_info *regions;
	int region_count;

	struct fast_allocator_array allocator_array;

	int64_t alloc_bytes_limit;       //water mark bytes for alloc
	volatile int64_t alloc_bytes;    //total alloc bytes
	bool need_lock;     //if need mutex lock for acontext
};

#define FAST_ALLOCATOR_INIT_REGION(region, _start, _end, _step, _alloc_once) \
	do { \
		(region).start = _start; \
		(region).end = _end;     \
		(region).step = _step;   \
		(region).alloc_elements_once = _alloc_once;   \
	} while(0)

#ifdef __cplusplus
extern "C" {
#endif

/**
allocator init by default region allocators
parameters:
	acontext: the context pointer
    mblock_name_prefix: the name prefix of mblock
    alloc_bytes_limit: the alloc limit, 0 for no limit
	expect_usage_ratio: the trunk usage ratio
	reclaim_interval: reclaim interval in second, < 0 for never reclaim
	need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
int fast_allocator_init(struct fast_allocator_context *acontext,
        const char *mblock_name_prefix, const int64_t alloc_bytes_limit,
        const double expect_usage_ratio, const int reclaim_interval,
        const bool need_lock);

/**
allocator init
parameters:
	acontext: the context pointer
	regions: the region array
	region_count: the region count
        alloc_bytes_limit: the alloc limit, 0 for no limit
	expect_usage_ratio: the trunk usage ratio
	reclaim_interval: reclaim interval in second, < 0 for never reclaim
	need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
int fast_allocator_init_ex(struct fast_allocator_context *acontext,
        const char *mblock_name_prefix, struct fast_region_info *regions,
        const int region_count, const int64_t alloc_bytes_limit,
        const double expect_usage_ratio, const int reclaim_interval,
        const bool need_lock);

/**
allocator destroy
parameters:
	acontext: the context pointer
*/
void fast_allocator_destroy(struct fast_allocator_context *acontext);

/**
alloc memory from the context
parameters:
	acontext: the context pointer
	bytes: alloc bytes
return the alloced pointer, return NULL if fail
*/
void* fast_allocator_alloc(struct fast_allocator_context *acontext,
	const int bytes);

/**
free a node (put a node to the context)
parameters:
	acontext: the context pointer
	ptr: the pointer to free
return none
*/
void fast_allocator_free(struct fast_allocator_context *acontext, void *ptr);

/**
retry reclaim free trunks
parameters:
	acontext: the context pointer
	total_reclaim_bytes: return total reclaim bytes
return error no, 0 for success, != 0 fail
*/
int fast_allocator_retry_reclaim(struct fast_allocator_context *acontext,
	int64_t *total_reclaim_bytes);

char *fast_allocator_memdup(struct fast_allocator_context *acontext,
        const char *src, const int len);

static inline char *fast_allocator_strdup_ex(struct fast_allocator_context *
        acontext, const char *src, const int len)
{
    return fast_allocator_memdup(acontext, src, len + 1);
}

static inline char *fast_allocator_strdup(struct fast_allocator_context *
        acontext, const char *src)
{
    return fast_allocator_memdup(acontext, src, strlen(src) + 1);
}

static inline int fast_allocator_alloc_string_ex(struct fast_allocator_context
        *acontext, string_t *dest, const char *src, const int len)
{
    dest->str = fast_allocator_memdup(acontext, src, len);
    dest->len = len;
    return dest->str != NULL ? 0 : ENOMEM;
}

static inline int fast_allocator_alloc_string(struct fast_allocator_context
        *acontext, string_t *dest, const string_t *src)
{
    return fast_allocator_alloc_string_ex(acontext, dest, src->str, src->len);
}

static inline int64_t fast_allocator_avail_memory(
        struct fast_allocator_context *acontext)
{
    if (acontext->alloc_bytes_limit == 0) {
        return INT64_MIN;
    }

    return acontext->alloc_bytes_limit - __sync_add_and_fetch(
            &acontext->allocator_array.malloc_bytes, 0);
}

#ifdef __cplusplus
}
#endif

#endif
