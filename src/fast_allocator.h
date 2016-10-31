/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

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
	int start;
	int end;
	int step;
	int alloc_elements_once;
	int pad_mask;  //for internal use
	struct fast_allocator_info *allocators;
};

struct fast_allocator_array
{
	int count;
	int alloc;
	int reclaim_interval;   //<= 0 for never reclaim
	int last_reclaim_time;
	volatile int64_t malloc_bytes;   //total alloc bytes
	int64_t malloc_bytes_limit;       //water mark bytes for malloc
	double expect_usage_ratio;
	struct fast_allocator_info **allocators;
};

struct fast_allocator_context
{
	struct fast_region_info *regions;
	int region_count;

	struct fast_allocator_array allocator_array;

	int64_t alloc_bytes_limit;       //mater mark bytes for alloc
	volatile int64_t alloc_bytes;    //total alloc bytes
	bool need_lock;     //if need mutex lock for acontext
};

#ifdef __cplusplus
extern "C" {
#endif

/**
allocator init by default region allocators
parameters:
	acontext: the context pointer
        alloc_bytes_limit: the alloc limit, 0 for no limit
	expect_usage_ratio: the trunk usage ratio
	reclaim_interval: reclaim interval in second, 0 for never reclaim
	need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
int fast_allocator_init(struct fast_allocator_context *acontext,
        const int64_t alloc_bytes_limit, const double expect_usage_ratio,
	const int reclaim_interval, const bool need_lock);

/**
allocator init
parameters:
	acontext: the context pointer
	regions: the region array
	region_count: the region count
        alloc_bytes_limit: the alloc limit, 0 for no limit
	expect_usage_ratio: the trunk usage ratio
	reclaim_interval: reclaim interval in second, 0 for never reclaim
	need_lock: if need lock
return error no, 0 for success, != 0 fail
*/
int fast_allocator_init_ex(struct fast_allocator_context *acontext,
        struct fast_region_info *regions, const int region_count,
        const int64_t alloc_bytes_limit, const double expect_usage_ratio,
	const int reclaim_interval, const bool need_lock);

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

#ifdef __cplusplus
}
#endif

#endif

